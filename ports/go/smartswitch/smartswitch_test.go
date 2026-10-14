package smartswitch

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConformance runs the shared vectors (spec/conformance at the repository root).
func TestConformance(t *testing.T) {
	total, fails, err := RunConformance(filepath.Join("..", "..", "..", "spec", "conformance"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fails {
		t.Error(f)
	}
	if total != 302 {
		t.Errorf("%d vectors, want 302 (the Python count)", total)
	}
}

func TestGroupOrder(t *testing.T) {
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if l.Add(l, c).Cmp(groupOrderL) != 0 {
		t.Fatal("L is wrong")
	}
}

func TestCanonicalDoesNotEscapeHTML(t *testing.T) {
	v, err := DecodeJSON([]byte(`{"b":"<>&  \u007f\u0001","a":-0,"B":[1,true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"B\":[1,true,null],\"a\":0,\"b\":\"<>&  \u007f\\u0001\"}"
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := Canonical(json.Number("2.5")); err == nil {
		t.Fatal("2.5 must not encode")
	}
}

// ---------------------------------------------------------------- the networked agent

type keypair struct {
	pub  string
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) keypair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keypair{hex.EncodeToString(pub), priv}
}

func sign(k keypair, msg []byte) string { return hex.EncodeToString(ed25519.Sign(k.priv, msg)) }

func mustJSON(t *testing.T, s string) any {
	v, err := DecodeJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// fakeCoordinator serves /v1/heartbeat and /v1/log like the Python coordinator, signing heartbeats.
type fakeCoordinator struct {
	t       *testing.T
	mu      sync.Mutex
	key     keypair
	fleetH  string
	entries []any
	token   string
	served  atomic.Int32
	hostile func(w http.ResponseWriter, r *http.Request) bool // when set and true, it has answered
}

func (f *fakeCoordinator) add(kind string, body any, ts int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := GenesisPrev
	if n := len(f.entries); n > 0 {
		prev = f.entries[n-1].(map[string]any)["hash"].(string)
	}
	e := map[string]any{"n": len(f.entries), "ts_ms": ts, "kind": kind, "body": body, "prev": prev}
	h, err := EntryHash(e)
	if err != nil {
		f.t.Fatal(err)
	}
	e["hash"] = h
	// round-trip through JSON so the entry holds the types the agent will see
	b, _ := json.Marshal(e)
	f.entries = append(f.entries, mustJSON(f.t, string(b)))
}

func (f *fakeCoordinator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.served.Add(1)
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	if f.hostile != nil && f.hostile(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	var out any
	switch r.URL.Path {
	case "/v1/heartbeat":
		hb := map[string]any{"type": "smartswitch.heartbeat", "fleet_hash": f.fleetH, "agent_id": q.Get("agent_id"),
			"instance_id": q.Get("instance_id"), "nonce": q.Get("nonce"), "log_size": len(f.entries),
			"head": f.entries[len(f.entries)-1].(map[string]any)["hash"], "issued_ms": 1}
		msg, err := HeartbeatMessage(hb)
		if err != nil {
			f.t.Error(err)
		}
		hb["sig"] = sign(f.key, msg)
		out = hb
	case "/v1/log":
		from, _ := strconv.Atoi(q.Get("from"))
		end := from + 1 // one entry per page, to exercise paging
		if end > len(f.entries) {
			end = len(f.entries)
		}
		out = map[string]any{"from": from, "entries": f.entries[from:end], "log_size": len(f.entries)}
	default:
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

func TestAgentAgainstFakeCoordinator(t *testing.T) {
	alice, bob, carol, coord := newKey(t), newKey(t), newKey(t), newKey(t)
	fleet := mustJSON(t, `{"type":"smartswitch.fleet","version":1,"fleet_id":"test","keyholders":[`+
		`{"id":"alice","public_key":"`+alice.pub+`"},{"id":"bob","public_key":"`+bob.pub+`"},{"id":"carol","public_key":"`+carol.pub+`"}],`+
		`"threshold":null,"coordinator_key":"`+coord.pub+`","offline_timeout_ms":2000,"proposal_max_ttl_ms":600000,"agents":null}`)
	fh, _ := DocHash(fleet)
	fc := &fakeCoordinator{t: t, key: coord, fleetH: fh, token: "secret"}
	fc.add("genesis", fleet, 1000)
	fc.add("event", map[string]any{"kind": "note"}, 1001)
	srv := httptest.NewServer(fc)
	defer srv.Close()

	var now atomic.Int64
	now.Store(10_000)
	var changes []string
	ag, err := NewAgent(AgentConfig{URL: srv.URL, Token: "secret", Fleet: fleet, AgentID: "a1", InstanceID: "i1",
		Clock: now.Load, OnChange: func(s Status) { changes = append(changes, s.Code) }})
	if err != nil {
		t.Fatal(err)
	}
	if s := ag.Status(); s.Code != "SW-NO-HEARTBEAT" {
		t.Fatalf("start: %v", s)
	}
	if s := ag.PollOnce(); s.Code != "SW-RUN" {
		t.Fatalf("after the first poll: %v (%s)", s, ag.LastError())
	}

	// a halt of the fleet, signed by alice and bob; times are wall-clock ms
	makeCert := func(created, expires int64) any {
		prop := map[string]any{"type": "smartswitch.proposal", "fleet_id": "test", "fleet_hash": fh, "seq": 1, "epoch": 0,
			"action": "halt", "target": "*", "new_public_key": nil, "reason": "test", "created_ms": created, "expires_ms": expires}
		ph, _ := DocHash(prop)
		cert := map[string]any{"type": "smartswitch.certificate", "proposal": prop, "votes": []any{
			map[string]any{"keyholder": "alice", "sig": sign(alice, VoteMessage(ph))},
			map[string]any{"keyholder": "bob", "sig": sign(bob, VoteMessage(ph))}}}
		b, _ := json.Marshal(cert)
		return mustJSON(t, string(b))
	}
	// valid by the monotonic clock (10 000) but long expired by the wall clock: Deliver must use the wall clock
	if r := ag.Deliver(makeCert(5000, 65000)); r.Code != "SW-EXPIRED" {
		t.Fatalf("deliver of an expired certificate: %v", r)
	}
	wall := time.Now().UnixMilli()
	certJSON := makeCert(wall-1000, wall+60000)

	// delivered directly first: a provisional halt until the log reaches it
	if r := ag.Deliver(certJSON); r.Code != "SW-PROVISIONAL-HALT" {
		t.Fatalf("deliver: %v", r)
	}
	fc.add("certificate", certJSON, wall)
	if s := ag.PollOnce(); s.Code != "SW-HALTED-FLEET" {
		t.Fatalf("after the halt: %v (%s)", s, ag.LastError())
	}
	if err := ag.Checkpoint(); err == nil {
		t.Fatal("checkpoint must fail when halted")
	}

	// a wrong token: an HTTP error changes nothing
	ag.cfg.Token = "wrong"
	if s := ag.PollOnce(); s.Code != "SW-HALTED-FLEET" || ag.LastError() == "" {
		t.Fatalf("with a wrong token: %v (%s)", s, ag.LastError())
	}
	want := []string{"SW-NO-HEARTBEAT", "SW-RUN", "SW-PROVISIONAL-HALT", "SW-HALTED-FLEET"}
	if len(changes) != len(want) {
		t.Fatalf("changes %v, want %v", changes, want)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Fatalf("changes %v, want %v", changes, want)
		}
	}
}

func TestAgentGoesOfflineWithoutCoordinator(t *testing.T) {
	alice, bob, carol, coord := newKey(t), newKey(t), newKey(t), newKey(t)
	fleet := mustJSON(t, `{"type":"smartswitch.fleet","version":1,"fleet_id":"test","keyholders":[`+
		`{"id":"alice","public_key":"`+alice.pub+`"},{"id":"bob","public_key":"`+bob.pub+`"},{"id":"carol","public_key":"`+carol.pub+`"}],`+
		`"threshold":null,"coordinator_key":"`+coord.pub+`","offline_timeout_ms":1000,"proposal_max_ttl_ms":600000,"agents":null}`)
	fh, _ := DocHash(fleet)
	fc := &fakeCoordinator{t: t, key: coord, fleetH: fh, token: "t"}
	fc.add("genesis", fleet, 1000)
	srv := httptest.NewServer(fc)
	var now atomic.Int64
	ag, err := NewAgent(AgentConfig{URL: srv.URL, Token: "t", Fleet: fleet, AgentID: "a1", PollInterval: 10 * time.Millisecond, Clock: now.Load})
	if err != nil {
		t.Fatal(err)
	}
	ag.Start()
	defer ag.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for !ag.MayRun() {
		if time.Now().After(deadline) {
			t.Fatalf("never ran: %v (%s)", ag.Status(), ag.LastError())
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.Close()
	n := fc.served.Load()
	time.Sleep(50 * time.Millisecond)
	now.Store(999)
	if !ag.MayRun() {
		t.Fatalf("stopped before the offline timeout: %v", ag.Status())
	}
	now.Store(1000)
	if s := ag.Status(); s.Code != "SW-OFFLINE" {
		t.Fatalf("after the offline timeout: %v", s)
	}
	if fc.served.Load() != n {
		t.Fatal("the closed coordinator answered")
	}
}

// TestPollSurvivesMalformedAnswers: whatever the coordinator answers, a poll changes nothing.
func TestPollSurvivesMalformedAnswers(t *testing.T) {
	alice, bob, carol, coord := newKey(t), newKey(t), newKey(t), newKey(t)
	fleet := mustJSON(t, `{"type":"smartswitch.fleet","version":1,"fleet_id":"test","keyholders":[`+
		`{"id":"alice","public_key":"`+alice.pub+`"},{"id":"bob","public_key":"`+bob.pub+`"},{"id":"carol","public_key":"`+carol.pub+`"}],`+
		`"threshold":null,"coordinator_key":"`+coord.pub+`","offline_timeout_ms":1000,"proposal_max_ttl_ms":600000,"agents":null}`)
	fh, _ := DocHash(fleet)
	fc := &fakeCoordinator{t: t, key: coord, fleetH: fh, token: "t"}
	fc.add("genesis", fleet, 1000)
	srv := httptest.NewServer(fc)
	defer srv.Close()
	ag, err := NewAgent(AgentConfig{URL: srv.URL, Token: "t", Fleet: fleet, AgentID: "a1", Clock: func() int64 { return 0 },
		Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if s := ag.PollOnce(); s.Code != "SW-RUN" {
		t.Fatalf("start: %v (%s)", s, ag.LastError())
	}

	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	// a correctly signed heartbeat claiming a longer log, so the agent fetches /v1/log
	behind := func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		hb := map[string]any{"type": "smartswitch.heartbeat", "fleet_hash": fh, "agent_id": q.Get("agent_id"),
			"instance_id": q.Get("instance_id"), "nonce": q.Get("nonce"), "log_size": 3, "head": strings.Repeat("ab", 32), "issued_ms": 1}
		msg, _ := HeartbeatMessage(hb)
		hb["sig"] = sign(coord, msg)
		_ = json.NewEncoder(w).Encode(hb)
	}
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"200 000 nested arrays": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(deep(200000))) },
		"truncated body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte(`{"type":"smartswitch.heart`))
		},
		"not JSON":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"HTTP 500":  func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) },
		"JSON null": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("null")) },
		"nested heartbeat field": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"type":"smartswitch.heartbeat","fleet_hash":"` + fh + `","agent_id":"a1","instance_id":"x","nonce":` +
				deep(9000) + `,"log_size":1,"head":"` + strings.Repeat("ab", 32) + `","issued_ms":1,"sig":"00"}`))
		},
		"log page not a list": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/heartbeat" {
				behind(w, r)
			} else {
				_, _ = w.Write([]byte(`{"entries":{"0":1}}`))
			}
		},
		"log entry nested deeply": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/heartbeat" {
				behind(w, r)
			} else {
				_, _ = w.Write([]byte(`{"entries":[{"n":1,"ts_ms":1,"kind":"event","body":{"x":` + deep(9000) + `},"prev":"` +
					fc.entries[0].(map[string]any)["hash"].(string) + `","hash":"00"}]}`))
			}
		},
		"log page truncated": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/heartbeat" {
				behind(w, r)
			} else {
				w.Header().Set("Content-Length", "1000")
				_, _ = w.Write([]byte(`{"entries":[{"n":1`))
			}
		},
	}
	for name, h := range cases {
		fc.hostile = func(w http.ResponseWriter, r *http.Request) bool { h(w, r); return true }
		s := ag.PollOnce()
		if s.Code != "SW-RUN" || ag.LastError() == "" {
			t.Errorf("%s: %v, last error %q", name, s, ag.LastError())
		}
		if strings.HasPrefix(ag.LastError(), "panic") {
			t.Errorf("%s: %s", name, ag.LastError())
		}
	}
	fc.hostile = nil
	if s := ag.PollOnce(); s.Code != "SW-RUN" || ag.LastError() != "" || ag.view.Replica.Size != 1 {
		t.Fatalf("after: %v (%s), replica size %d", s, ag.LastError(), ag.view.Replica.Size)
	}
}
