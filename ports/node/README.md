# SmartSwitch for Node.js (agent side)

This is the agent side of SmartSwitch in JavaScript for Node.js. It verifies the fleet log, quorum
certificates and the coordinator's signed heartbeats, and decides whether an agent may run. It follows
`spec/SEMANTICS.md`. The shared vectors in `spec/conformance` test it. Signing (keyholders) and the
coordinator stay in the Python reference.

It uses only the Node.js standard library (`crypto`, `http`, `https`, `fs`) and has no dependencies.
Ed25519 verification goes through Node's `crypto` (OpenSSL). Before the library call, the port checks
the key and signature itself: lower-case hex, the right lengths, and S < L. It was tested with Node 22.

It is not published on npm or any other registry. Use it from a clone of this repository.

## Layout

| Path | What |
|---|---|
| `src/canonical.js` | canonical JSON, SHA-256, `docHash` |
| `src/ed25519.js` | `verify` with the pre-checks |
| `src/protocol.js` | fleet validation, proposal and certificate checks, `State`, `apply` |
| `src/log.js` | `Replica` and `replay` (the hash-chained log) |
| `src/agentview.js` | `AgentView`: log / heartbeat / certificate / status, without I/O |
| `src/agent.js` | `Agent`: the networked agent (poll loop, catch-up, dead-man rule) |
| `test/conformance.js` | the vector runner |
| `bin/interop.js` | the interop agent for `ports/conformance/interop.py` |

## Conformance and interop

From the repository root:

```sh
node ports/node/test/conformance.js spec/conformance   # last line: node: 302/302 vectors passed
ports/conformance/run.sh node                          # the same through the shared harness
ports/conformance/interop.sh node                      # this agent against the Python coordinator
```

The interop test needs Python 3 and the Python reference's dependencies. It starts the Python
coordinator and runs `node ports/node/bin/interop.js URL FLEET_FILE AGENT_ID INSTANCE_ID`.

## Using the agent

```js
const { Agent, Halted } = require('./ports/node/src');

const agent = new Agent({
  url: 'https://switch.example:8720',
  token: process.env.SMARTSWITCH_AGENT_TOKEN,
  fleet: 'fleet.json',          // a path, or the parsed fleet document
  agentId: 'planner-1',
  pollMs: 1000,                 // the default
  onChange: (s) => console.error('smartswitch:', s.code),
}).start();                     // polls in the background; the timer does not keep the process alive

async function work() {
  while (agent.mayRun()) {
    await doOneStep();
    agent.checkpoint();         // throws Halted (e.code) when the agent may no longer run
  }
}
```

- `status()` returns `{run, code}`. `code` is one of `SW-RUN`, `SW-FORK`, `SW-HALTED-FLEET`,
  `SW-HALTED-AGENT`, `SW-PROVISIONAL-HALT`, `SW-NO-HEARTBEAT` or `SW-OFFLINE`.
- `pollOnce()` runs one round and resolves to the status. It sends a heartbeat request with a fresh
  16-byte random nonce. On `SW-BEHIND` it fetches the missing `/v1/log` pages and checks the same
  heartbeat again.
- `deliver(certificate)` takes a certificate that reached the agent some other way. It is checked at
  wall-clock time (`Date.now()`, or the `wallClock` option), because it is compared with the proposal's
  `expires_ms`. Heartbeats and status use the monotonic clock (`clock`). A valid halt of this agent or of
  the fleet halts it provisionally. The provisional halt ends when the log applies that same proposal,
  or a later resume of `*` or of this agent.
- `stop()` ends the background loop.
- Errors change nothing: network and HTTP errors, malformed or cut-off answers, and parser limits.
  `pollOnce()` never throws. One deadline (`timeoutMs`) covers each whole request, body included. The
  error is kept in `lastError`. Without a valid heartbeat
  for the fleet's `offline_timeout_ms`, the status becomes `SW-OFFLINE`.
- Each request uses its own connection (no keep-alive), as the Python reference client does.

The building blocks (`AgentView`, `replay`, `verifyCertificate`, `apply`, `validateFleet`, `dumps`,
`verify`) are exported from `src/index.js` too.

## Numbers

JSON is parsed with `JSON.parse`. A parsed `2.5`, `true` or `"1"` is rejected where an integer is
required. `1.0` cannot be told apart from `1` after parsing; the documents use integers only.
Integers above 2^53 − 1 are outside the spec.
