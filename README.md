# SmartSwitch

**A quorum kill switch for fleets of AI agents.** No single person can halt the fleet, and no single
person can stop a halt. Halting, resuming and replacing a keyholder each need signatures from a quorum
of keyholders (2 of 3 by default). Every agent checks those signatures itself and stops on its own when
it can no longer reach the coordinator.

- **Quorum:** k-of-n Ed25519 signatures over one proposal. The default is 2 of up to 5 keyholders and a
  strict majority above 5 (4 of 7). The quorum is always at least 2 and at most n − 1, so one keyholder
  can neither trigger an action nor block one.
- **Verified at the edge:** each agent is deployed with the fleet document and replays the log from
  it. A coordinator or a network attacker cannot forge a halt or a resume.
- **Dead-man rule:** an agent that gets no valid, nonce-bound heartbeat for `offline_timeout_ms`
  (30 s by default) stops by itself. Halts signed by a quorum also reach agents directly (a file, any
  channel), even when the coordinator withholds them.
- **Replication detection:** a roster says how many instances of each agent may run. The coordinator
  refuses extra or unknown instances and logs an alert. Refused instances get no heartbeat, so they
  stop.
- **Evidence:** every certificate and alert is an entry in a SHA-256 hash-chained log, optionally
  mirrored to a second file and compared every 30 s. `sf-smartswitch log verify` checks it from the
  first entry, and `log export` writes one JSON line per vote (timestamp, vote hash, signature).
  Signatures protect the certificates. For the rest (timestamps, alerts), keep the mirror on another
  disk and record the head hash elsewhere ([docs/threat-model.md](docs/threat-model.md)).
- **Watchdog:** aggregation is the time from the quorum-completing vote to the certificate being
  written. Above 200 ms (plus a 10 % jitter tolerance) the coordinator raises an alert; above 300 ms it
  always raises one. Prometheus metrics, alert rules and a Grafana dashboard are included.

```bash
sf-smartswitch --demo         # a whole fleet on this machine in a few seconds, no files written
```

## Install

```bash
python -m pip install sf-smartswitch
sf-smartswitch --demo
```

Every file of `sf-smartswitch` on PyPI is built and published by this repository's release workflow
(`.github/workflows/release.yml`, PyPI trusted publishing). Each carries a provenance attestation that
names this repository and that workflow; PyPI shows it under "Verified details". The same workflow
records a GitHub attestation, which you can check with
`gh attestation verify <file> --repo SmartTasksOrg/sf-smartswitch`. A release file without that
provenance is not ours, and neither is a package called `smartswitch` (without `sf-`) on any registry.

Version 0.1.0 is the first release under this name. If pip cannot find it yet, that release has not
finished. Install from a clone instead (Python 3.10 or later):

```bash
git clone https://github.com/SmartTasksOrg/sf-smartswitch
cd sf-smartswitch
python -m venv .venv
. .venv/bin/activate          # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install .
sf-smartswitch --demo
```

The only runtime dependency is [`cryptography`](https://pypi.org/project/cryptography/), which
provides Ed25519 through OpenSSL.

## Set up a fleet

```bash
# each keyholder, on their own device (the .key file never leaves it)
sf-smartswitch keygen --name alice --out alice.key          # prints alice's public key

# the operator: the coordinator's key, then the fleet document from the keyholders' public keys
sf-smartswitch keygen --name coordinator --out coordinator.key
sf-smartswitch fleet init --fleet-id prod --coordinator-key coordinator.key \
    --keyholder alice=<alice's public key> --keyholder bob=<...> --keyholder carol=<...> \
    --agent planner --agent worker:4 --out fleet.json         # prints the quorum and the fleet hash

# the coordinator (behind a TLS proxy; tokens: python -c "import secrets; print(secrets.token_urlsafe(32))")
export SMARTSWITCH_AGENT_TOKEN=... SMARTSWITCH_OPERATOR_TOKEN=...
sf-smartswitch serve --fleet fleet.json --key coordinator.key --log switch.jsonl --mirror /other-disk/switch.jsonl

# each agent: wrap the program (any language) so that it is stopped when the switch says so
export SMARTSWITCH_AGENT_TOKEN=...
sf-smartswitch agent --url https://switch.internal --fleet fleet.json --agent-id planner -- python planner.py
```

Halting is two commands by two different people:

```bash
export SMARTSWITCH_OPERATOR_TOKEN=...
sf-smartswitch propose --url https://switch.internal --key alice.key --action halt --target '*' --reason "runaway spend"
sf-smartswitch sign    --url https://switch.internal --key bob.key --hash <proposal hash printed above>
```

`--target` is `*` for the whole fleet or an agent id. `resume` works the same way. `suspend` takes a
keyholder out (a lost laptop, a person who left), and `reinstate` brings one back with a new key. Both
need the quorum, without the votes of the keyholder in question. Without a coordinator, `propose
--offline`, `sign --proposal` and `assemble` produce a certificate file that any agent accepts as a halt
(`--cert-dir`). The walkthrough is in [docs/operations.md](docs/operations.md).

## Inside a Python agent

```python
from sf_smartswitch import Agent, Halted

agent = Agent("https://switch.internal", token, "fleet.json", "planner").start()   # polls every second
while agent.may_run():
    plan_next_step()
    agent.checkpoint()        # raises Halted("SW-HALTED-FLEET" | "SW-OFFLINE" | ...) between steps
```

The process wrapper (`sf-smartswitch agent ... -- program`) is the stronger choice. The program runs in
its own process group. The wrapper terminates the whole group, then kills it after a grace period,
without relying on the program's cooperation. It does the same when the wrapper itself gets SIGTERM or
SIGINT. A program that deliberately leaves its process group escapes it; run agents in a container
whose lifetime is the wrapper's.
[docs/integration.md](docs/integration.md) covers both, plus containers and the ports.

## What an agent checks

| Status | Meaning |
|---|---|
| `SW-RUN` | a valid heartbeat answered one of its nonces within `offline_timeout_ms`, and nothing halts it |
| `SW-HALTED-FLEET` / `SW-HALTED-AGENT` | a quorum-signed certificate in the verified log halts the fleet or this agent |
| `SW-PROVISIONAL-HALT` | a quorum-signed halt reached it directly, ahead of the log |
| `SW-OFFLINE` | no valid heartbeat for `offline_timeout_ms` (the dead-man rule) |
| `SW-NO-HEARTBEAT` | not yet heard from the coordinator: it does not start |
| `SW-FORK` | the coordinator showed a history that contradicts the verified one; it stays stopped until restarted |

The exact rules are in [spec/SEMANTICS.md](spec/SEMANTICS.md). The vectors in `spec/conformance` (302
checks) test them in every engine.

## Coordinator API

| Endpoint | Token | Purpose |
|---|---|---|
| `GET /v1/heartbeat?agent_id=&instance_id=&nonce=` | agent | signed heartbeat bound to the agent's nonce; 403/409 for instances the roster refuses |
| `GET /v1/log?from=&limit=` | agent | log entries (at most 1000 per page) |
| `GET /v1/fleet`, `GET /v1/state` | agent | the fleet document; seq, epoch, halts, keyholders, log size and head |
| `POST /v1/votes` | operator | one signed vote on a proposal; applied when the quorum is reached |
| `POST /v1/certificates` | operator | a complete certificate (assembled offline) |
| `GET /v1/proposals`, `GET /v1/instances` | operator | pending proposals; agent instances seen |
| `GET /ui` | operator (HTTP Basic, the token as password) | read-only status page, no script, refreshes every 5 s |
| `GET /metrics`, `GET /healthz` | none | Prometheus metrics, liveness |

Full contract: [spec/openapi.yaml](spec/openapi.yaml). A token only opens the door. No request halts or
resumes anything without the quorum's signatures.

Operator endpoints check:
1. the source address against `SMARTSWITCH_OPERATOR_ALLOW` (addresses or CIDRs), when set;
2. the token;
3. a rate limit per address (60 per minute). An address with more than 20 failed token checks in a
   minute is refused before its token is looked at.

Behind a reverse proxy, set `SMARTSWITCH_TRUSTED_PROXIES` to the proxy's address. Otherwise every
client has the proxy's address, and these per-address rules apply to all of them together.

Limits on requests and connections:
- requests are limited to 256 KiB with a Content-Length;
- connections have a 10 s socket timeout and are closed after 30 s;
- at most 256 connections at once.

The coordinator speaks plain HTTP: put a TLS proxy in front of it.

## Deploy and measure

- `deploy/docker-compose.yml`: the coordinator, Prometheus with the alert rules
  (`deploy/prometheus/alerts.yml`) and Grafana with the dashboard. Fill `deploy/.env` from
  `deploy/.env.example` and put the fleet and the coordinator key in `deploy/keys/` first (see the
  file).
- `sf-smartswitch bench`: on this machine, it times:
  - signing and verifying one vote;
  - checking a certificate;
  - one agent status check;
  - aggregation through the HTTP API for 3, 5, 7 and 10 keyholders.

  The output is JSON.

More: [docs/operations.md](docs/operations.md), [docs/integration.md](docs/integration.md),
[docs/threat-model.md](docs/threat-model.md).

## Ports

The agent side (verification, log replay, the agent rules and the networked agent) is ported to seven
more languages. Every port is held to the same 302 vectors and checked against the Python coordinator.
None is published on a registry; use them from a clone. None has a dependency.

| Language | Folder | Vectors | Ed25519 |
|---|---|---|---|
| Node.js 22 | `ports/node` | `node test/conformance.js` | `crypto` |
| Go 1.24 | `ports/go` | `go test ./...` | `crypto/ed25519` |
| Rust | `ports/rust` | `cargo run --release --bin conformance` | own verify-only implementation, not independently audited |
| Java 21 | `ports/java` | `./build.sh` then `Conformance` | `java.security` |
| C# / .NET 8 | `ports/csharp` | `dotnet run --project Conformance` | own verify-only implementation (BigInteger), not independently audited |
| PHP 8 | `ports/php` | `php bin/conformance.php` | `ext-sodium` |
| Ruby 3.2+ | `ports/ruby` | `ruby bin/conformance.rb` | OpenSSL |

`ports/conformance/run.sh` runs the vectors on every engine. `ports/conformance/interop.sh` runs each
port's agent against the Python coordinator through a scripted sequence:
- halt and resume of the fleet;
- halt and resume of one agent;
- a keyholder suspended and reinstated with a new key;
- a refused second instance;
- the coordinator stopping.

Porting rules: [spec/PORTING.md](spec/PORTING.md).

## Status

- **Version 0.1.0, experimental.** It ships a quorum switch, a coordinator, an agent library and
  process wrapper, seven ports and deployment files.
- **Published:** PyPI `sf-smartswitch` (see Install). Nothing else is published.
- **Tested:** the Python tests (`tests/`) on Python 3.10, 3.12 and 3.13 and the install-line check gate
  every pull request (`.github/workflows/ci.yml`). The `ports` job runs the vectors on all eight engines
  and the interop test on all seven ports. It does not gate merges and has not run on GitHub before this
  release. Locally (Linux), all eight engines passed all vectors and all seven ports passed interop.
- **Not tested:** the Docker image and the compose stack (not run by CI), Windows and macOS for the
  coordinator, and real edge devices (ARM). The bench figures are from one Linux machine.
- **Changed from the council's specification:**
  - k-of-n Ed25519 signatures instead of Shamir secret sharing with threshold ECDSA. The
    no-single-person property is the same, keys never have to be combined, and every engine can check
    them with a standard library.
  - Strict-majority quorum above five keyholders: the spec's formula and its example disagree.
- **Not done from the council's notes:**
  - an F* proof;
  - a Kubernetes operator and Helm chart (the process wrapper works as a container entrypoint);
  - a ROS integration (the HTTP API is what a ROS node would call);
  - IPFS, etcd and S3/Glacier storage (a local log and mirror, which you ship to your own storage);
  - a voting web UI (the page is read-only; votes are signed with the CLI so that keys stay out of
    browsers);
  - usability tests, a video tutorial and an external audit.
- **Security review:** none independent. Report vulnerabilities as described in
  [SECURITY.md](SECURITY.md).

## The Smart* family

SmartSwitch is part of the Smart* family by SmartTasks Lab:
- [SmartGate](https://github.com/SmartTasksOrg/sf-smartgate): decision friction and a human override for
  single actions;
- [SmartDelegate](https://github.com/SmartTasksOrg/sf-smartdelegate): IAM for LLM agents;
- [SmartRoute](https://github.com/SmartTasksOrg/sf-smartroute);
- [SmartSeal](https://github.com/SmartTasksOrg/sf-smartseal);
- [SmartPangolin](https://github.com/SmartTasksOrg/sf-smartpangolin);
- [SmartCheck](https://github.com/SmartTasksOrg/sf-smartcheck);
- [SmartFabric](https://github.com/SmartTasksOrg/sf-smartfabric);
- the others listed on [smarttasks.cloud](https://smarttasks.cloud).

Every family package is on PyPI under its `sf-` name; a package without the `sf-` prefix is not ours.

## Contributing, security, licence

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
