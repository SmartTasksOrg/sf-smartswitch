package smartswitch

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Halted is returned by Agent.Checkpoint when the agent may not run.
type Halted struct{ Code string }

func (h *Halted) Error() string { return "SmartSwitch: this agent may not run (" + h.Code + ")" }

// HTTPError is an error answer from the coordinator.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %.300s", e.Status, e.Body) }

var clockStart = time.Now()

// MonoMs is a monotonic clock in milliseconds (Go's time.Since uses the monotonic reading).
func MonoMs() int64 { return int64(time.Since(clockStart) / time.Millisecond) }

// LoadFleet reads and validates a fleet document file.
func LoadFleet(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := DecodeJSON(b)
	if err != nil {
		return nil, err
	}
	return ValidateFleet(v)
}

// AgentConfig configures NewAgent. Fleet is a fleet document (a value from DecodeJSON) or, when
// FleetFile is set, read from that file. InstanceID defaults to 16 random hex characters, PollInterval
// to 1 s and Timeout (per HTTP request) to 2 s.
type AgentConfig struct {
	URL, Token          string
	Fleet               any
	FleetFile           string
	AgentID, InstanceID string
	PollInterval        time.Duration
	Timeout             time.Duration
	OnChange            func(Status)
	Clock               func() int64 // monotonic ms for heartbeats and status; default MonoMs
	WallClock           func() int64 // wall-clock ms for Deliver; default time.Now().UnixMilli()
}

// Agent asks the coordinator for a signed heartbeat every PollInterval, verifies everything with an
// AgentView, and stops when told or when cut off. Network errors change nothing: without a valid
// heartbeat for the fleet's offline_timeout_ms the status becomes SW-OFFLINE by itself.
// Safe for concurrent use.
type Agent struct {
	cfg       AgentConfig
	url       string
	http      *http.Client
	mu        sync.Mutex
	view      *AgentView
	last      *Status
	lastError string
	stop      chan struct{}
	done      chan struct{}
}

// NewAgent returns an agent; call Start for the background loop, or PollOnce yourself.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if !strings.HasPrefix(cfg.URL, "http://") && !strings.HasPrefix(cfg.URL, "https://") {
		return nil, errors.New("the coordinator URL must start with http:// or https://")
	}
	fleet := cfg.Fleet
	if cfg.FleetFile != "" {
		f, err := LoadFleet(cfg.FleetFile)
		if err != nil {
			return nil, err
		}
		fleet = f
	}
	if cfg.InstanceID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		cfg.InstanceID = hex.EncodeToString(b)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = MonoMs
	}
	if cfg.WallClock == nil {
		cfg.WallClock = func() int64 { return time.Now().UnixMilli() }
	}
	view, err := NewAgentView(fleet, cfg.AgentID, cfg.InstanceID)
	if err != nil {
		return nil, err
	}
	// One connection per request (no keep-alive), as the Python reference client does: an answer
	// always comes from a coordinator that is accepting connections now.
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}
	return &Agent{cfg: cfg, url: strings.TrimRight(cfg.URL, "/"), view: view,
		http: &http.Client{Timeout: cfg.Timeout, Transport: tr}}, nil
}

// AgentID and InstanceID identify this agent instance.
func (a *Agent) AgentID() string    { return a.cfg.AgentID }
func (a *Agent) InstanceID() string { return a.cfg.InstanceID }

// LastError is the last heartbeat failure ("" after a valid heartbeat).
func (a *Agent) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastError
}

func (a *Agent) get(path string, q url.Values) (any, error) {
	req, err := http.NewRequest("GET", a.url+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	res, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &HTTPError{res.StatusCode, string(data)}
	}
	return DecodeJSON(data)
}

// PollOnce does one round: a heartbeat with a fresh random nonce; on SW-BEHIND it fetches the log
// pages it lacks and checks the same heartbeat again. It returns the status afterwards. Any error
// (network, HTTP, a malformed or cut-off answer, a parser limit, even a panic) changes nothing.
func (a *Agent) PollOnce() Status {
	a.round()
	return a.Status()
}

func (a *Agent) round() {
	defer func() {
		if p := recover(); p != nil {
			a.locked(func() { a.lastError = fmt.Sprintf("panic: %v", p) })
		}
	}()
	nb := make([]byte, 16)
	errMsg := ""
	if _, err := rand.Read(nb); err != nil {
		errMsg = "random: " + err.Error()
	} else {
		nonce := hex.EncodeToString(nb)
		sent := a.cfg.Clock()
		hb, err := a.get("/v1/heartbeat", url.Values{"agent_id": {a.cfg.AgentID}, "instance_id": {a.cfg.InstanceID}, "nonce": {nonce}})
		if err == nil {
			var r Result
			a.locked(func() { r = a.view.Heartbeat(hb, nonce, sent) })
			if r.Code == "SW-BEHIND" {
				size, _ := AsInt(hb.(map[string]any)["log_size"], 1, MaxInt)
				err = a.catchUp(int(size))
				if err == nil {
					a.locked(func() { r = a.view.Heartbeat(hb, nonce, sent) })
				}
			}
			if err == nil && !r.OK {
				errMsg = r.Code
			}
		}
		if err != nil {
			errMsg = err.Error()
		}
	}
	a.locked(func() { a.lastError = errMsg })
}

// locked runs f with the lock held and releases it even if f panics.
func (a *Agent) locked(f func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f()
}

func (a *Agent) catchUp(size int) error {
	for {
		var have int
		a.locked(func() { have = a.view.Replica.Size })
		if have >= size {
			return nil
		}
		q := url.Values{"from": {strconv.Itoa(have)}, "limit": {"1000"}, "agent_id": {a.cfg.AgentID}, "instance_id": {a.cfg.InstanceID}}
		page, err := a.get("/v1/log", q)
		if err != nil {
			return err
		}
		pm, _ := page.(map[string]any)
		entries, _ := pm["entries"].([]any)
		if len(entries) == 0 { // not a list, or empty: try again next round
			return nil
		}
		var r LogResult
		a.locked(func() { r = a.view.Log(entries) })
		if !r.OK {
			return fmt.Errorf("the coordinator log does not verify (%s at entry %d)", r.Code, r.Size)
		}
	}
}

// Deliver takes a certificate that reached this agent some other way than the coordinator. It is
// checked at wall-clock time (WallClock), because it is compared with expires_ms.
func (a *Agent) Deliver(cert any) Result {
	var r Result
	a.locked(func() { r = a.view.Certificate(cert, a.cfg.WallClock()) })
	a.Status()
	return r
}

// Status is whether the agent may run now, and why.
func (a *Agent) Status() Status {
	a.mu.Lock()
	s := a.view.Status(a.cfg.Clock())
	changed := a.last == nil || *a.last != s
	if changed {
		a.last = &s
	}
	cb := a.cfg.OnChange
	a.mu.Unlock()
	if changed && cb != nil {
		cb(s)
	}
	return s
}

// MayRun reports whether the agent may run now.
func (a *Agent) MayRun() bool { return a.Status().Run }

// Checkpoint returns *Halted when the agent may not run.
func (a *Agent) Checkpoint() error {
	if s := a.Status(); !s.Run {
		return &Halted{s.Code}
	}
	return nil
}

// Start polls in a background goroutine until Stop.
func (a *Agent) Start() *Agent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stop != nil {
		return a
	}
	a.stop, a.done = make(chan struct{}), make(chan struct{})
	go func(stop, done chan struct{}) {
		defer close(done)
		for {
			a.PollOnce()
			select {
			case <-stop:
				return
			case <-time.After(a.cfg.PollInterval):
			}
		}
	}(a.stop, a.done)
	return a
}

// Stop ends the background loop and waits for it.
func (a *Agent) Stop() {
	a.mu.Lock()
	stop, done := a.stop, a.done
	a.stop, a.done = nil, nil
	a.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}
