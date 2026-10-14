package smartswitch

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Limits and prefixes from spec/SEMANTICS.md.
const (
	MaxKeyholders   = 64
	MaxAgents       = 100000
	MaxReasonBytes  = 1000
	MaxInt          = 1<<53 - 1
	VotePrefix      = "smartswitch-vote-v1:"
	HeartbeatPrefix = "smartswitch-heartbeat-v1:"
)

var (
	idRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	nonceRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	actions = []string{"halt", "resume", "suspend", "reinstate"}

	fleetFields    = []string{"agents", "coordinator_key", "fleet_id", "keyholders", "offline_timeout_ms", "proposal_max_ttl_ms", "threshold", "type", "version"}
	proposalFields = []string{"action", "created_ms", "epoch", "expires_ms", "fleet_hash", "fleet_id", "new_public_key", "reason", "seq", "target", "type"}
)

// SwitchError is a broken rule; Code is the stable SW-* code from spec/SEMANTICS.md.
type SwitchError struct {
	Code    string
	Message string
}

func (e *SwitchError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func swErr(code, format string, a ...any) *SwitchError {
	return &SwitchError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// IsID reports whether v is an id: 1 to 64 characters from A-Z a-z 0-9 . _ -
func IsID(v any) bool {
	s, ok := v.(string)
	return ok && idRe.MatchString(s)
}

// AsInt returns v as an integer when it is a JSON integer (not a float like 2.5, not a bool, not a
// string) within [lo, hi].
func AsInt(v any, lo, hi int64) (int64, bool) {
	var n int64
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return 0, false
		}
		var err error
		if n, err = strconv.ParseInt(s, 10, 64); err != nil {
			return 0, false
		}
	case int:
		n = int64(x)
	case int64:
		n = x
	default:
		return 0, false
	}
	return n, n >= lo && n <= hi
}

func isString(v any, want string) bool {
	s, ok := v.(string)
	return ok && s == want
}

// exactFields returns v as an object when its keys are exactly fields (given sorted).
func exactFields(v any, fields ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(fields) {
		return nil, false
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return nil, false
		}
	}
	return m, true
}

// ---------------------------------------------------------------- fleet

// DefaultThreshold is 2 for up to five keyholders, floor(n/2) + 1 above five.
func DefaultThreshold(n int) int {
	if n <= 5 {
		return 2
	}
	return n/2 + 1
}

// ValidateFleet returns the fleet document as an object, or SW-BAD-FLEET.
func ValidateFleet(doc any) (map[string]any, error) {
	bad := func(msg string) (map[string]any, error) { return nil, &SwitchError{"SW-BAD-FLEET", msg} }
	m, ok := exactFields(doc, fleetFields...)
	if !ok {
		return bad("the fleet document must have exactly the fields " + strings.Join(fleetFields, ", "))
	}
	if !isString(m["type"], "smartswitch.fleet") {
		return bad(`type must be "smartswitch.fleet" and version 1`)
	}
	if _, ok := AsInt(m["version"], 1, 1); !ok {
		return bad(`type must be "smartswitch.fleet" and version 1`)
	}
	if !IsID(m["fleet_id"]) {
		return bad("fleet_id must match [A-Za-z0-9._-]{1,64}")
	}
	khs, ok := m["keyholders"].([]any)
	if !ok || len(khs) < 3 || len(khs) > MaxKeyholders {
		return bad(fmt.Sprintf("keyholders must be a list of 3 to %d", MaxKeyholders))
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, khv := range khs {
		kh, ok := exactFields(khv, "id", "public_key")
		if !ok {
			return bad(`each keyholder must be {"id", "public_key"}`)
		}
		if !IsID(kh["id"]) || !IsKeyHex(kh["public_key"]) {
			return bad("keyholder id must be an id and public_key 64 lower-case hex")
		}
		id, pk := kh["id"].(string), kh["public_key"].(string)
		if ids[id] || keys[pk] {
			return bad("keyholder ids and public keys must be unique")
		}
		ids[id], keys[pk] = true, true
	}
	n := int64(len(khs))
	if m["threshold"] != nil {
		if _, ok := AsInt(m["threshold"], 2, n-1); !ok {
			return bad(fmt.Sprintf("threshold must be null or an integer from 2 to %d", n-1))
		}
	}
	if !IsKeyHex(m["coordinator_key"]) || keys[m["coordinator_key"].(string)] {
		return bad("coordinator_key must be 64 lower-case hex and differ from every keyholder key")
	}
	if _, ok := AsInt(m["offline_timeout_ms"], 1000, 3600000); !ok {
		return bad("offline_timeout_ms must be an integer from 1000 to 3600000")
	}
	if _, ok := AsInt(m["proposal_max_ttl_ms"], 1000, 86400000); !ok {
		return bad("proposal_max_ttl_ms must be an integer from 1000 to 86400000")
	}
	if m["agents"] != nil {
		agents, ok := m["agents"].([]any)
		if !ok || len(agents) > MaxAgents {
			return bad(fmt.Sprintf("agents must be null or a list of at most %d", MaxAgents))
		}
		seen := map[string]bool{}
		for _, av := range agents {
			a, ok := exactFields(av, "id", "max_instances")
			if !ok {
				return bad(`each agent must be {"id", "max_instances"}`)
			}
			_, okN := AsInt(a["max_instances"], 1, 1000)
			if !IsID(a["id"]) || !okN || seen[a["id"].(string)] {
				return bad("agent id must be a unique id and max_instances 1 to 1000")
			}
			seen[a["id"].(string)] = true
		}
	}
	return m, nil
}

// ---------------------------------------------------------------- proposals and certificates

// Proposal is a proposal that passed the format check; Raw is the document that is hashed.
type Proposal struct {
	Raw                                        map[string]any
	FleetID, FleetHash, Action, Target, Reason string
	NewPublicKey                               string // "" unless the action is reinstate
	Seq, Epoch, CreatedMs, ExpiresMs           int64
}

// CheckProposalFormat checks a proposal's fields; the error is SW-BAD-PROPOSAL.
func CheckProposalFormat(v any) (*Proposal, error) {
	bad := func(msg string) (*Proposal, error) { return nil, &SwitchError{"SW-BAD-PROPOSAL", msg} }
	m, ok := exactFields(v, proposalFields...)
	if !ok {
		return bad("a proposal must have exactly the fields " + strings.Join(proposalFields, ", "))
	}
	if !isString(m["type"], "smartswitch.proposal") {
		return bad(`type must be "smartswitch.proposal"`)
	}
	if !IsID(m["fleet_id"]) || !IsKeyHex(m["fleet_hash"]) {
		return bad("fleet_id or fleet_hash is malformed")
	}
	p := &Proposal{Raw: m, FleetID: m["fleet_id"].(string), FleetHash: m["fleet_hash"].(string)}
	var okS, okE bool
	p.Seq, okS = AsInt(m["seq"], 1, MaxInt)
	p.Epoch, okE = AsInt(m["epoch"], 0, MaxInt)
	if !okS || !okE {
		return bad("seq must be an integer >= 1 and epoch >= 0")
	}
	action, _ := m["action"].(string)
	known := false
	for _, a := range actions {
		known = known || a == action
	}
	if !known {
		return bad("action must be one of " + strings.Join(actions, ", "))
	}
	p.Action = action
	if p.Target, ok = m["target"].(string); !ok {
		return bad("target must be a string")
	}
	if action == "reinstate" {
		if !IsKeyHex(m["new_public_key"]) {
			return bad("reinstate needs new_public_key (64 lower-case hex)")
		}
		p.NewPublicKey = m["new_public_key"].(string)
	} else if m["new_public_key"] != nil {
		return bad("new_public_key must be null unless the action is reinstate")
	}
	// len of a Go string is its length in UTF-8 bytes
	if p.Reason, ok = m["reason"].(string); !ok || len(p.Reason) > MaxReasonBytes {
		return bad(fmt.Sprintf("reason must be a string of at most %d UTF-8 bytes", MaxReasonBytes))
	}
	var okC, okX bool
	p.CreatedMs, okC = AsInt(m["created_ms"], 0, MaxInt)
	p.ExpiresMs, okX = AsInt(m["expires_ms"], 0, MaxInt)
	if !okC || !okX {
		return bad("created_ms and expires_ms must be integers >= 0")
	}
	if p.ExpiresMs <= p.CreatedMs {
		return bad("expires_ms must be after created_ms")
	}
	return p, nil
}

// VoteMessage is the signed message of a vote: "smartswitch-vote-v1:" + proposal hash.
func VoteMessage(proposalHash string) []byte { return []byte(VotePrefix + proposalHash) }

type vote struct{ keyholder, sig string }

// CheckCertificateFormat checks the certificate's shape; the error is SW-BAD-CERTIFICATE.
func CheckCertificateFormat(v any) (map[string]any, []vote, error) {
	bad := func(msg string) (map[string]any, []vote, error) {
		return nil, nil, &SwitchError{"SW-BAD-CERTIFICATE", msg}
	}
	m, ok := exactFields(v, "proposal", "type", "votes")
	if !ok {
		return bad(`a certificate must be {"type", "proposal", "votes"}`)
	}
	if !isString(m["type"], "smartswitch.certificate") {
		return bad(`type must be "smartswitch.certificate"`)
	}
	vs, ok := m["votes"].([]any)
	if !ok || len(vs) < 1 || len(vs) > MaxKeyholders {
		return bad(fmt.Sprintf("votes must be a list of 1 to %d", MaxKeyholders))
	}
	out := make([]vote, 0, len(vs))
	for _, vv := range vs {
		vm, ok := exactFields(vv, "keyholder", "sig")
		kh, ok1 := vm["keyholder"].(string)
		sg, ok2 := vm["sig"].(string)
		if !ok || !ok1 || !ok2 {
			return bad(`each vote must be {"keyholder": string, "sig": string}`)
		}
		out = append(out, vote{kh, sg})
	}
	return m, out, nil
}

// ---------------------------------------------------------------- state

// State is derived from the fleet document and the certificates applied so far. Treat it as
// immutable: Apply returns a new State.
type State struct {
	FleetID, FleetHash, CoordinatorKey string
	N, Threshold                       int
	MaxTTLMs, OfflineTimeoutMs         int64
	Keys                               map[string]string // keyholder id -> current public key
	Suspended                          map[string]bool
	Seq, Epoch                         int64
	HaltedAll                          bool
	Halted                             map[string]bool
	Roster                             map[string]int // agent id -> max_instances; nil: no roster
}

// Genesis returns the state of a valid fleet document.
func Genesis(doc any) (*State, error) {
	m, err := ValidateFleet(doc)
	if err != nil {
		return nil, err
	}
	h, err := DocHash(m)
	if err != nil {
		return nil, &SwitchError{"SW-BAD-FLEET", err.Error()}
	}
	khs := m["keyholders"].([]any)
	st := &State{FleetID: m["fleet_id"].(string), FleetHash: h, CoordinatorKey: m["coordinator_key"].(string),
		N: len(khs), Keys: map[string]string{}, Suspended: map[string]bool{}, Halted: map[string]bool{}}
	st.Threshold = DefaultThreshold(len(khs))
	if m["threshold"] != nil {
		k, _ := AsInt(m["threshold"], 2, int64(len(khs)-1))
		st.Threshold = int(k)
	}
	st.MaxTTLMs, _ = AsInt(m["proposal_max_ttl_ms"], 1000, 86400000)
	st.OfflineTimeoutMs, _ = AsInt(m["offline_timeout_ms"], 1000, 3600000)
	for _, kv := range khs {
		kh := kv.(map[string]any)
		st.Keys[kh["id"].(string)] = kh["public_key"].(string)
	}
	if m["agents"] != nil {
		st.Roster = map[string]int{}
		for _, av := range m["agents"].([]any) {
			a := av.(map[string]any)
			n, _ := AsInt(a["max_instances"], 1, 1000)
			st.Roster[a["id"].(string)] = int(n)
		}
	}
	return st, nil
}

// Active is the sorted list of keyholder ids that are not suspended.
func (st *State) Active() []string {
	out := []string{}
	for k := range st.Keys {
		if !st.Suspended[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// MayRun reports whether the state lets agentID run.
func (st *State) MayRun(agentID string) bool { return !st.HaltedAll && !st.Halted[agentID] }

func sortedSet(s map[string]bool) []string {
	out := []string{}
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summary is the state as the vectors compare it.
func (st *State) Summary() map[string]any {
	keys := map[string]any{}
	for k, v := range st.Keys {
		keys[k] = v
	}
	return map[string]any{"seq": st.Seq, "epoch": st.Epoch, "threshold": st.Threshold, "halted_all": st.HaltedAll,
		"halted": sortedSet(st.Halted), "active": st.Active(), "suspended": sortedSet(st.Suspended), "keys": keys}
}

func (st *State) clone() *State {
	c := *st
	c.Keys = make(map[string]string, len(st.Keys))
	for k, v := range st.Keys {
		c.Keys[k] = v
	}
	c.Suspended = map[string]bool{}
	for k := range st.Suspended {
		c.Suspended[k] = true
	}
	c.Halted = map[string]bool{}
	for k := range st.Halted {
		c.Halted[k] = true
	}
	return &c
}

func checkTarget(st *State, p *Proposal) error {
	t := p.Target
	switch p.Action {
	case "halt", "resume":
		if t != "*" && !IsID(t) {
			return swErr("SW-BAD-TARGET", `target must be "*" or an agent id`)
		}
	case "suspend":
		if _, ok := st.Keys[t]; !ok || st.Suspended[t] {
			return swErr("SW-BAD-TARGET", "target must be an active keyholder")
		}
		if len(st.Active())-1 < st.Threshold {
			return swErr("SW-QUORUM-IMPOSSIBLE", "suspending this keyholder would leave fewer active keyholders than the threshold %d", st.Threshold)
		}
	default: // reinstate
		if !st.Suspended[t] {
			return swErr("SW-BAD-TARGET", "target must be a suspended keyholder")
		}
		k := p.NewPublicKey
		used := k == st.CoordinatorKey
		for _, v := range st.Keys {
			used = used || v == k
		}
		if used {
			return swErr("SW-BAD-TARGET", "new_public_key must be a key not used in this fleet")
		}
	}
	return nil
}

// VerifyCertificate checks cert against st at atMs in the order of spec/SEMANTICS.md, "Certificate
// checks", and returns its proposal. ahead: any seq above st.Seq is accepted (a certificate delivered
// directly to an agent); otherwise the seq must be st.Seq + 1.
func VerifyCertificate(st *State, cert any, atMs int64, ahead bool) (*Proposal, error) {
	c, votes, err := CheckCertificateFormat(cert)
	if err != nil {
		return nil, err
	}
	p, err := CheckProposalFormat(c["proposal"])
	if err != nil {
		return nil, err
	}
	if p.FleetID != st.FleetID || p.FleetHash != st.FleetHash {
		return nil, swErr("SW-WRONG-FLEET", "the proposal is for another fleet")
	}
	if p.Seq <= st.Seq {
		return nil, swErr("SW-STALE-SEQ", "seq %d is not after the current seq %d", p.Seq, st.Seq)
	}
	if !ahead && p.Seq != st.Seq+1 {
		return nil, swErr("SW-SEQ-GAP", "seq %d is not the next seq %d", p.Seq, st.Seq+1)
	}
	if p.Epoch != st.Epoch {
		return nil, swErr("SW-WRONG-EPOCH", "epoch %d is not the current epoch %d", p.Epoch, st.Epoch)
	}
	if p.ExpiresMs-p.CreatedMs > st.MaxTTLMs {
		return nil, swErr("SW-BAD-PROPOSAL", "the proposal is valid for longer than %d ms", st.MaxTTLMs)
	}
	if atMs >= p.ExpiresMs {
		return nil, swErr("SW-EXPIRED", "the proposal has expired")
	}
	if err := checkTarget(st, p); err != nil {
		return nil, err
	}
	ph, err := DocHash(p.Raw)
	if err != nil { // cannot happen after the format check
		return nil, swErr("SW-BAD-PROPOSAL", "%v", err)
	}
	msg := VoteMessage(ph)
	seen := map[string]bool{}
	for _, v := range votes {
		kh := v.keyholder
		key, ok := st.Keys[kh]
		if !ok {
			return nil, swErr("SW-UNKNOWN-KEYHOLDER", "%q is not a keyholder of this fleet", kh)
		}
		if seen[kh] {
			return nil, swErr("SW-DUPLICATE-VOTE", "%q voted twice", kh)
		}
		seen[kh] = true
		if st.Suspended[kh] {
			return nil, swErr("SW-SUSPENDED-KEYHOLDER", "%q is suspended", kh)
		}
		if p.Action == "suspend" && kh == p.Target {
			return nil, swErr("SW-TARGET-VOTE", "a keyholder cannot vote on its own suspension")
		}
		if !Verify(key, msg, v.sig) {
			return nil, swErr("SW-BAD-SIGNATURE", "the signature of %q does not verify", kh)
		}
	}
	if len(seen) < st.Threshold {
		return nil, swErr("SW-NO-QUORUM", "%d valid votes, %d needed", len(seen), st.Threshold)
	}
	return p, nil
}

// Apply verifies cert (seq must be st.Seq + 1) and returns the next state; st is not changed.
func Apply(st *State, cert any, atMs int64) (*State, error) {
	p, err := VerifyCertificate(st, cert, atMs, false)
	if err != nil {
		return nil, err
	}
	nx := st.clone()
	nx.Seq = st.Seq + 1
	t := p.Target
	switch p.Action {
	case "halt":
		if t == "*" {
			nx.HaltedAll = true
		} else {
			nx.Halted[t] = true
		}
	case "resume":
		if t == "*" {
			nx.HaltedAll = false
			nx.Halted = map[string]bool{}
		} else {
			delete(nx.Halted, t)
		}
	case "suspend":
		nx.Epoch++
		nx.Suspended[t] = true
	default:
		nx.Epoch++
		delete(nx.Suspended, t)
		nx.Keys[t] = p.NewPublicKey
	}
	return nx, nil
}
