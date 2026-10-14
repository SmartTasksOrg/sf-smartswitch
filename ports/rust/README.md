# SmartSwitch for Rust

The agent side of SmartSwitch in Rust: canonical JSON, fleet validation, certificate checks, log replay,
the agent rules (`spec/SEMANTICS.md`) and a networked agent that talks to the Python coordinator. Signing
and the coordinator stay in Python (`spec/PORTING.md`).

The crate (`sf-smartswitch`, library name `smartswitch`) has no dependencies and builds with `--offline`.
It is not published on crates.io (`publish = false`); use it from a clone.

## Ed25519

Rust's standard library has no Ed25519, so this crate carries its own verify-only implementation
(`src/ed25519.rs`, with SHA-512 in `src/sha512.rs` and SHA-256 in `src/sha256.rs`). It was written for this
port. It passes the RFC 8032 test vectors (section 7.1, tests 1 to 3) and the shared vectors in
`spec/conformance/ed25519.json`. **It has not been independently audited.**

Before the curve check it applies the pre-checks of `spec/SEMANTICS.md` ("Signatures"): lower-case hex,
64 characters for a key and 128 for a signature, and S < L. It then rejects a non-canonical y (y >= p) and
points that are not on the curve, and checks the cofactorless equation [S]B == R + [k]A. Any failure is
`false`. It verifies public data and makes no attempt at constant time. One verify takes about 0.3 ms in a
release build on the machine it was tested on.

## Tests

    cd ports/rust
    cargo test --offline                                        # unit tests, including RFC 8032
    cargo run --quiet --offline --release --bin conformance ../../spec/conformance
    # rust: 302/302 vectors passed

From the repository root, `ports/conformance/run.sh rust` runs the vectors and
`ports/conformance/interop.sh rust` runs the interop agent (`src/bin/interop.rs`) against the Python
coordinator: halt and resume of the fleet and of one agent, suspension and reinstatement with a new key, a
refused second instance and the dead-man rule.

## Usage

Add the crate from a clone as a path dependency:

    [dependencies]
    sf-smartswitch = { path = "../sf-smartswitch/ports/rust" }

```rust
use smartswitch::Agent;
use std::sync::Arc;

let fleet = Agent::load_fleet("fleet.json")?;                   // validated fleet document
let token = std::env::var("SMARTSWITCH_AGENT_TOKEN").ok();
let agent = Arc::new(Agent::new("http://10.0.0.5:8720", token.as_deref(), &fleet, "planner-1", "i-1")?);
agent.start();                                                  // heartbeat every poll_ms (1 s)
while agent.may_run() {
    do_one_step();
    agent.checkpoint()?;                                        // Err(Halted { code }) once stopped
}
```

`Agent::status()` returns the status code (`SW-RUN`, `SW-HALTED-FLEET`, `SW-OFFLINE`, ...). A halt
certificate received another way can be given to `Agent::deliver`, which checks it at wall-clock time
(it is compared with the proposal's `expires_ms`); heartbeats and status use a monotonic clock. The rules without I/O are in
`AgentView` (`src/agentview.rs`), which is what the vectors test.

## Limits of the networked agent

- The HTTP client speaks **plain HTTP only** (HTTP/1.1 over `std::net::TcpStream`, one connection per
  request with `Connection: close`). There is no TLS: run the agent on a private network or next to a
  local TLS-terminating proxy. Every heartbeat is signed by the coordinator key and checked against the
  fleet document, so a network attacker cannot fake a heartbeat or a certificate, but can read the token.
- Nonces are read from `/dev/urandom`, so the networked agent works on Unix systems only. The verification
  code itself is portable.
