# SmartSwitch for Go (agent side)

This is the agent side of SmartSwitch in Go. It verifies the fleet log, quorum certificates and the
coordinator's signed heartbeats, and decides whether an agent may run. It follows `spec/SEMANTICS.md`.
The shared vectors in `spec/conformance` test it. Signing (keyholders) and the coordinator stay in the
Python reference.

It uses only the Go standard library and has no dependencies:

- `crypto/ed25519` for Ed25519, with the port's own pre-checks first (lower-case hex, lengths, S < L)
- `crypto/sha256`, and `crypto/rand` for nonces
- `encoding/json` with `UseNumber` for parsing, so `2.5`, `true` and `"1"` are rejected where an
  integer is required

Canonical JSON uses the port's own encoder, because `json.Marshal` escapes `<`, `>`, `&`, U+2028 and
U+2029. It was tested with Go 1.24. The module declares `go 1.22`.

Module path: `github.com/SmartTasksOrg/sf-smartswitch/ports/go`, package `smartswitch`. It is not
published on any registry or module proxy. Use it from a clone, for example with a `replace` directive
that points at `ports/go`.

## Layout

| Path | What |
|---|---|
| `smartswitch/canonical.go` | `DecodeJSON`, `Canonical`, `DocHash` |
| `smartswitch/ed25519.go` | `Verify` with the pre-checks |
| `smartswitch/protocol.go` | `ValidateFleet`, `CheckProposalFormat`, `VerifyCertificate`, `State`, `Apply` |
| `smartswitch/log.go` | `Replica`, `Replay` |
| `smartswitch/agentview.go` | `AgentView`: Log / Heartbeat / Certificate / Status, without I/O |
| `smartswitch/agent.go` | `Agent`: the networked agent |
| `smartswitch/conformance.go` | `RunConformance`, shared by the runner and the tests |
| `cmd/conformance` | the vector runner |
| `cmd/interop` | the interop agent for `ports/conformance/interop.py` |

## Conformance, tests and interop

```sh
cd ports/go
go vet ./... && go run ./cmd/conformance ../../spec/conformance   # last line: go: 302/302 vectors passed
go test ./...        # the vectors, plus the networked agent against an in-process fake coordinator
                     # (including malformed, deeply nested and truncated answers)
cd ../..
ports/conformance/run.sh go
ports/conformance/interop.sh go   # builds /tmp/smartswitch-go-interop, runs it against the Python coordinator
```

The interop test needs Python 3 and the Python reference's dependencies.

## Using the agent

```go
import ss "github.com/SmartTasksOrg/sf-smartswitch/ports/go/smartswitch"

ag, err := ss.NewAgent(ss.AgentConfig{
	URL:       "https://switch.example:8720",
	Token:     os.Getenv("SMARTSWITCH_AGENT_TOKEN"),
	FleetFile: "fleet.json", // or Fleet: a value from ss.DecodeJSON
	AgentID:   "planner-1",
	OnChange:  func(s ss.Status) { log.Println("smartswitch:", s.Code) },
})
if err != nil {
	log.Fatal(err)
}
ag.Start() // polls every PollInterval (1 s by default) in a goroutine
defer ag.Stop()

for ag.MayRun() {
	doOneStep()
	if err := ag.Checkpoint(); err != nil { // *ss.Halted with the code
		break
	}
}
```

- `Status()` returns `{Run, Code}`. `Code` is one of `SW-RUN`, `SW-FORK`, `SW-HALTED-FLEET`,
  `SW-HALTED-AGENT`, `SW-PROVISIONAL-HALT`, `SW-NO-HEARTBEAT` or `SW-OFFLINE`.
- `PollOnce()` runs one round. It sends a heartbeat request with a fresh 16-byte random nonce. On
  `SW-BEHIND` it fetches the missing `/v1/log` pages and checks the same heartbeat again.
- `Deliver(certificate)` takes a certificate that reached the agent some other way. It is checked at
  wall-clock time (`time.Now().UnixMilli()`, or `WallClock`), because it is compared with the
  proposal's `expires_ms`. Heartbeats and status use the monotonic clock (`Clock`). A valid halt of this
  agent or of the fleet halts it provisionally. The provisional halt ends when the log applies that same
  proposal, or a later resume of `*` or of this agent.
- Errors change nothing: network and HTTP errors, malformed or cut-off answers, parser limits, and
  even a panic, which `PollOnce` recovers from. The error is kept in `LastError()`. Without a valid heartbeat
  for the fleet's `offline_timeout_ms`, the status becomes `SW-OFFLINE`.
- Each request uses its own connection (no keep-alive), as the Python reference client does.
- `Agent` is safe for concurrent use. `AgentView` is not.
