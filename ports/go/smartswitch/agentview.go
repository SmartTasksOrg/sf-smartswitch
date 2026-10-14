package smartswitch

import "errors"

// LogResult is the answer of AgentView.Log: {ok, size} or {ok, code, size}.
type LogResult struct {
	OK   bool
	Code string
	Size int
}

// Map is the result as the vectors write it.
func (r LogResult) Map() map[string]any {
	if r.OK {
		return map[string]any{"ok": true, "size": r.Size}
	}
	return map[string]any{"ok": false, "code": r.Code, "size": r.Size}
}

// Result is the answer of AgentView.Heartbeat and AgentView.Certificate: {ok, code}.
type Result struct {
	OK   bool
	Code string
}

// Map is the result as the vectors write it.
func (r Result) Map() map[string]any { return map[string]any{"ok": r.OK, "code": r.Code} }

// Status is whether the agent may run, and why: {run, code}.
type Status struct {
	Run  bool
	Code string
}

// Map is the status as the vectors write it.
func (s Status) Map() map[string]any { return map[string]any{"run": s.Run, "code": s.Code} }

var heartbeatFields = []string{"agent_id", "fleet_hash", "head", "instance_id", "issued_ms", "log_size", "nonce", "sig", "type"}

// HeartbeatMessage is the coordinator's signed message: "smartswitch-heartbeat-v1:" +
// doc_hash(heartbeat without "sig").
func HeartbeatMessage(hb map[string]any) ([]byte, error) {
	body := make(map[string]any, len(hb))
	for k, v := range hb {
		if k != "sig" {
			body[k] = v
		}
	}
	h, err := DocHash(body)
	if err != nil {
		return nil, err
	}
	return []byte(HeartbeatPrefix + h), nil
}

// AgentView is what an agent believes and whether it may run: the agent-side rules of
// spec/SEMANTICS.md, "Agent", without any I/O. Times for Heartbeat and Status are the agent's own
// monotonic milliseconds; the time for Certificate is wall-clock milliseconds (compared with expires_ms).
// It is not safe for concurrent use (Agent adds the locking).
type AgentView struct {
	Fleet       map[string]any
	FleetHash   string
	AgentID     string
	InstanceID  string
	Replica     *Replica
	lastOK      int64
	hasLastOK   bool
	provisional map[string]int64 // proposal hash -> seq of directly delivered halts
	Fork        bool
}

// NewAgentView returns the view of a new agent for a valid fleet document.
func NewAgentView(fleet any, agentID, instanceID string) (*AgentView, error) {
	if !IsID(agentID) || !IsID(instanceID) {
		return nil, errors.New("agent id and instance id must match [A-Za-z0-9._-]{1,64}")
	}
	m, err := ValidateFleet(fleet)
	if err != nil {
		return nil, err
	}
	h, err := DocHash(m)
	if err != nil {
		return nil, err
	}
	return &AgentView{Fleet: m, FleetHash: h, AgentID: agentID, InstanceID: instanceID, Replica: NewReplica(h),
		provisional: map[string]int64{}}, nil
}

// Log appends entries that continue the local copy (fetched from the coordinator), one at a time.
// entries must be a JSON array ([]any). A provisional halt ends when the log applies that same proposal,
// or a later resume of "*" or of this agent; another certificate taking its seq does not end it.
func (v *AgentView) Log(entries any) LogResult {
	list, ok := entries.([]any)
	if !ok {
		return LogResult{false, "SW-BAD-ENTRY", v.Replica.Size}
	}
	for _, e := range list {
		if err := v.Replica.Extend([]any{e}); err != nil {
			code := "SW-BAD-ENTRY"
			if se, ok := err.(*SwitchError); ok {
				code = se.Code
			}
			return LogResult{false, code, v.Replica.Size}
		}
		em := e.(map[string]any) // a verified entry
		if len(v.provisional) == 0 || em["kind"] != "certificate" {
			continue
		}
		p, err := CheckProposalFormat(em["body"].(map[string]any)["proposal"])
		if err != nil { // cannot happen: the certificate was applied
			continue
		}
		if ph, err := DocHash(p.Raw); err == nil {
			delete(v.provisional, ph)
		}
		if p.Action == "resume" && (p.Target == "*" || p.Target == v.AgentID) {
			for h, seq := range v.provisional {
				if seq < p.Seq {
					delete(v.provisional, h)
				}
			}
		}
	}
	return LogResult{true, "", v.Replica.Size}
}

// Heartbeat checks a heartbeat answering nonce, which the agent sent at atMs.
func (v *AgentView) Heartbeat(hb any, nonce string, atMs int64) Result {
	m, code := v.checkHeartbeat(hb, nonce)
	if code == "" {
		size, _ := AsInt(m["log_size"], 1, MaxInt)
		if int64(v.Replica.Size) >= size {
			if !isString(m["head"], v.Replica.Hashes[size-1]) {
				v.Fork = true
				code = "SW-FORK"
			}
		} else {
			code = "SW-BEHIND"
		}
	}
	if code != "" {
		return Result{false, code}
	}
	if !v.hasLastOK || atMs > v.lastOK {
		v.lastOK = atMs
	}
	v.hasLastOK = true
	return Result{true, "SW-OK"}
}

func (v *AgentView) checkHeartbeat(hb any, nonce string) (map[string]any, string) {
	m, ok := exactFields(hb, heartbeatFields...)
	if !ok || !isString(m["type"], "smartswitch.heartbeat") || !IsKeyHex(m["head"]) {
		return nil, "SW-BAD-HEARTBEAT"
	}
	if _, ok := AsInt(m["log_size"], 1, MaxInt); !ok {
		return nil, "SW-BAD-HEARTBEAT"
	}
	if _, ok := AsInt(m["issued_ms"], 0, MaxInt); !ok {
		return nil, "SW-BAD-HEARTBEAT"
	}
	msg, err := HeartbeatMessage(m)
	if err != nil || !Verify(v.Fleet["coordinator_key"], msg, m["sig"]) {
		return nil, "SW-BAD-HEARTBEAT"
	}
	if !isString(m["fleet_hash"], v.FleetHash) {
		return nil, "SW-WRONG-FLEET"
	}
	if !isString(m["agent_id"], v.AgentID) || !isString(m["instance_id"], v.InstanceID) {
		return nil, "SW-WRONG-AGENT"
	}
	if !nonceRe.MatchString(nonce) || !isString(m["nonce"], nonce) {
		return nil, "SW-NONCE"
	}
	return m, ""
}

// Certificate takes a certificate delivered directly (not through the log), checked at WALL-CLOCK time
// atMs (it is compared with expires_ms). Only a valid halt of this agent or of the whole fleet, newer
// than the local state, has an effect: a provisional halt (see Log for when it ends).
func (v *AgentView) Certificate(cert any, atMs int64) Result {
	st := v.Replica.State
	if st == nil {
		return Result{false, "SW-NO-STATE"}
	}
	p, err := VerifyCertificate(st, cert, atMs, true)
	if err != nil {
		return Result{false, err.(*SwitchError).Code}
	}
	if p.Action != "halt" || (p.Target != "*" && p.Target != v.AgentID) {
		return Result{false, "SW-NOT-APPLICABLE"}
	}
	ph, err := DocHash(p.Raw)
	if err != nil { // cannot happen after the certificate checks
		return Result{false, "SW-BAD-PROPOSAL"}
	}
	v.provisional[ph] = p.Seq
	return Result{true, "SW-PROVISIONAL-HALT"}
}

// Status answers whether the agent may run at atMs; the first matching reason wins.
func (v *AgentView) Status(atMs int64) Status {
	st := v.Replica.State
	switch {
	case v.Fork:
		return Status{false, "SW-FORK"}
	case st != nil && st.HaltedAll:
		return Status{false, "SW-HALTED-FLEET"}
	case st != nil && st.Halted[v.AgentID]:
		return Status{false, "SW-HALTED-AGENT"}
	case len(v.provisional) > 0:
		return Status{false, "SW-PROVISIONAL-HALT"}
	case !v.hasLastOK || st == nil:
		return Status{false, "SW-NO-HEARTBEAT"}
	case atMs-v.lastOK >= st.OfflineTimeoutMs:
		return Status{false, "SW-OFFLINE"}
	}
	return Status{true, "SW-RUN"}
}
