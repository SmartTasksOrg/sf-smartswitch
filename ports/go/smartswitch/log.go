package smartswitch

import (
	"encoding/json"
	"math"
	"math/big"
	"strings"
)

// GenesisPrev is the prev of entry 0: 64 zeros.
var GenesisPrev = strings.Repeat("0", 64)

// EntryHash is doc_hash(entry without "hash").
func EntryHash(e map[string]any) (string, error) {
	rest := make(map[string]any, len(e))
	for k, v := range e {
		if k != "hash" {
			rest[k] = v
		}
	}
	return DocHash(rest)
}

// Replica is a verified copy of a log. Extend checks entries one by one and applies certificates; on
// the first bad entry it returns a *SwitchError and keeps everything before it.
type Replica struct {
	Pinned string // "" accepts any genesis
	State  *State
	Size   int
	Head   string
	Hashes []string
}

// NewReplica returns an empty replica pinned to fleetHash ("" for no pin).
func NewReplica(fleetHash string) *Replica {
	return &Replica{Pinned: fleetHash, Head: GenesisPrev}
}

// Extend appends entries; it returns the first entry's error, if any.
func (r *Replica) Extend(entries []any) error {
	for _, e := range entries {
		if err := r.one(e); err != nil {
			return err
		}
	}
	return nil
}

func (r *Replica) one(ev any) error {
	e, ok := exactFields(ev, "body", "hash", "kind", "n", "prev", "ts_ms")
	var kind string
	if ok {
		kind, _ = e["kind"].(string)
	}
	_, isBody := e["body"].(map[string]any)
	n, okN := saturatingInt(e["n"])
	ts, okT := saturatingInt(e["ts_ms"])
	if !ok || (kind != "genesis" && kind != "certificate" && kind != "event") || !isBody || !okN || !okT || ts < 0 {
		return swErr("SW-BAD-ENTRY", "entry %d is malformed", r.Size)
	}
	// ts_ms need not increase (spec/SEMANTICS.md, "Log" step 2): only n is checked.
	if n != int64(r.Size) {
		return swErr("SW-LOG-ORDER", "entry %d: n is %d", r.Size, n)
	}
	hash, _ := e["hash"].(string)
	if !isString(e["prev"], r.Head) {
		return swErr("SW-LOG-CHAIN", "entry %d: the hash chain is broken", r.Size)
	}
	if h, err := EntryHash(e); err != nil || !isString(e["hash"], h) {
		return swErr("SW-LOG-CHAIN", "entry %d: the hash chain is broken", r.Size)
	}
	if r.Size == 0 {
		if kind != "genesis" {
			return swErr("SW-BAD-ENTRY", "entry 0 must be the genesis")
		}
		if _, err := ValidateFleet(e["body"]); err != nil {
			return &SwitchError{"SW-BAD-FLEET", "entry 0: " + err.(*SwitchError).Message}
		}
		if r.Pinned != "" {
			if h, err := DocHash(e["body"]); err != nil || h != r.Pinned {
				return swErr("SW-WRONG-FLEET", "entry 0 is not the pinned fleet")
			}
		}
		st, err := Genesis(e["body"])
		if err != nil {
			return err
		}
		r.State = st
	} else if kind == "genesis" {
		return swErr("SW-BAD-ENTRY", "entry %d: only entry 0 can be a genesis", r.Size)
	} else if kind == "certificate" {
		st, err := Apply(r.State, e["body"], ts)
		if err != nil {
			return err
		}
		r.State = st
	}
	r.Size++
	r.Head = hash
	r.Hashes = append(r.Hashes, hash)
	return nil
}

// Replay verifies a whole log: {"ok": true, "size", "head", "state"} or {"ok": false, "index", "code"}.
// fleetHash "" means no pin.
func Replay(entries []any, fleetHash string) map[string]any {
	r := NewReplica(fleetHash)
	if err := r.Extend(entries); err != nil {
		code := "SW-BAD-ENTRY"
		if se, ok := err.(*SwitchError); ok {
			code = se.Code
		}
		return map[string]any{"ok": false, "index": r.Size, "code": code}
	}
	if r.Size == 0 {
		return map[string]any{"ok": false, "index": 0, "code": "SW-BAD-ENTRY"}
	}
	return map[string]any{"ok": true, "size": r.Size, "head": r.Head, "state": r.State.Summary()}
}

// saturatingInt returns v as an integer when it is a JSON integer of any size, clamped to the int64
// range (n and ts_ms have no upper bound in the spec; clamping keeps every comparison the same).
func saturatingInt(v any) (int64, bool) {
	if num, ok := v.(json.Number); ok && !strings.ContainsAny(string(num), ".eE") {
		b, ok := new(big.Int).SetString(string(num), 10)
		if !ok {
			return 0, false
		}
		if b.IsInt64() {
			return b.Int64(), true
		}
		if b.Sign() < 0 {
			return math.MinInt64, true
		}
		return math.MaxInt64, true
	}
	return AsInt(v, math.MinInt64, math.MaxInt64)
}
