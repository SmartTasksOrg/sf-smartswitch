package smartswitch

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RunConformance runs the shared vectors in dir (spec/conformance), check for check as the Python
// runner (src/sf_smartswitch/conformance.py) does. It returns the number of checks and the failures.
func RunConformance(dir string) (total int, fails []string, err error) {
	files := map[string]map[string]any{}
	for _, n := range []string{"canonical.json", "ed25519.json", "fleets.json", "certificates.json", "logs.json", "agent.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return 0, nil, err
		}
		v, err := DecodeJSON(b)
		if err != nil {
			return 0, nil, fmt.Errorf("%s: %v", n, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return 0, nil, fmt.Errorf("%s: not an object", n)
		}
		files[n] = m
	}
	check := func(name string, got, want any) {
		total++
		g, w := show(got), show(want)
		if g != w {
			fails = append(fails, fmt.Sprintf("%s: got %.300s, want %.300s", name, g, w))
		}
	}
	cases := func(f string) []map[string]any {
		var out []map[string]any
		for _, c := range files[f]["cases"].([]any) {
			out = append(out, c.(map[string]any))
		}
		return out
	}

	for _, c := range cases("canonical.json") {
		text, err := Canonical(c["input"])
		if err != nil {
			check("canonical/"+str(c["name"]), "error: "+err.Error(), []any{c["canonical"], c["sha256"]})
			continue
		}
		check("canonical/"+str(c["name"]), []any{string(text), SHA256Hex(text)}, []any{c["canonical"], c["sha256"]})
	}

	for _, c := range cases("ed25519.json") {
		msg, err := hex.DecodeString(str(c["message_hex"]))
		if err != nil {
			return 0, nil, fmt.Errorf("ed25519/%s: message_hex: %v", str(c["name"]), err)
		}
		check("ed25519/"+str(c["name"]), Verify(c["public_key"], msg, c["sig"]), c["valid"])
	}

	for _, tv := range files["fleets.json"]["default_thresholds"].([]any) {
		t := tv.(map[string]any)
		n, _ := AsInt(t["n"], 0, MaxInt)
		check(fmt.Sprintf("fleets/default threshold n=%d", n), DefaultThreshold(int(n)), t["k"])
	}
	for _, c := range cases("fleets.json") {
		var got map[string]any
		if st, err := Genesis(c["fleet"]); err != nil {
			got = errResult(err)
		} else {
			got = map[string]any{"ok": true, "fleet_hash": st.FleetHash, "threshold": st.Threshold}
		}
		check("fleets/"+str(c["name"]), got, pick(c, "ok", "fleet_hash", "threshold", "code"))
	}

	certs := files["certificates.json"]
	fleets := certs["fleets"].(map[string]any)
	for _, c := range cases("certificates.json") {
		name := str(c["name"])
		st, err := Genesis(fleets[str(c["fleet"])])
		if err != nil {
			return 0, nil, fmt.Errorf("certificates/%s: fleet: %v", name, err)
		}
		for _, sv := range c["setup"].([]any) {
			s := sv.(map[string]any)
			at, _ := AsInt(s["at_ms"], -1<<63, 1<<63-1)
			if st, err = Apply(st, s["certificate"], at); err != nil {
				return 0, nil, fmt.Errorf("certificates/%s: setup: %v", name, err)
			}
		}
		var ph any
		if cm, ok := c["certificate"].(map[string]any); ok {
			if p, ok := cm["proposal"]; ok {
				if h, err := DocHash(p); err == nil {
					ph = h
				}
			}
		}
		check("certificates/"+name+" (proposal hash)", ph, c["proposal_hash"])
		at, _ := AsInt(c["at_ms"], -1<<63, 1<<63-1)
		var got map[string]any
		if c["ahead"] == true {
			if _, err := VerifyCertificate(st, c["certificate"], at, true); err != nil {
				got = errResult(err)
			} else {
				got = map[string]any{"ok": true, "state": nil}
			}
		} else if nx, err := Apply(st, c["certificate"], at); err != nil {
			got = errResult(err)
		} else {
			got = map[string]any{"ok": true, "state": nx.Summary()}
		}
		check("certificates/"+name, got, pick(c, "ok", "state", "code"))
	}

	for _, c := range cases("logs.json") {
		pinned, _ := c["pinned"].(string)
		entries, _ := c["entries"].([]any)
		check("logs/"+str(c["name"]), Replay(entries, pinned), c["result"])
	}

	agent := files["agent.json"]
	for _, c := range cases("agent.json") {
		view, err := NewAgentView(agent["fleet"], str(c["agent_id"]), str(c["instance_id"]))
		if err != nil {
			return 0, nil, fmt.Errorf("agent/%s: %v", str(c["name"]), err)
		}
		for i, sv := range c["steps"].([]any) {
			s := sv.(map[string]any)
			op := str(s["op"])
			at, _ := AsInt(s["at_ms"], -1<<63, 1<<63-1)
			var got map[string]any
			switch op {
			case "log":
				got = view.Log(s["entries"]).Map()
			case "heartbeat":
				got = view.Heartbeat(s["heartbeat"], str(s["nonce"]), at).Map()
			case "certificate":
				got = view.Certificate(s["certificate"], at).Map()
			default:
				got = view.Status(at).Map()
			}
			check(fmt.Sprintf("agent/%s step %d (%s)", str(c["name"]), i, op), got, s["expect"])
		}
	}
	return total, fails, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func errResult(err error) map[string]any {
	if se, ok := err.(*SwitchError); ok {
		return map[string]any{"ok": false, "code": se.Code}
	}
	return map[string]any{"ok": false, "error": err.Error()}
}

func pick(c map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := c[k]; ok {
			out[k] = v
		}
	}
	return out
}

// show is the canonical text of a JSON value, so that comparison ignores key order and integer types.
func show(v any) string {
	b, err := Canonical(v)
	if err != nil {
		j, _ := json.Marshal(v)
		return "non-canonical:" + string(j)
	}
	return string(b)
}
