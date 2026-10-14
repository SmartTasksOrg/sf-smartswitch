# Changelog

All notable changes to SmartSwitch are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semantic.

## Unreleased

## 0.1.0 — first release as `sf-smartswitch`

Built from the SmartSwitch council specification (quorum kill switch for AI fleets).

### Added
- Protocol (spec/SEMANTICS.md): fleet document as trust anchor; proposals, Ed25519 votes and
  certificates; quorum of 2 for up to five keyholders and a strict majority above five, always between
  2 and n − 1; actions halt / resume (whole fleet or one agent), suspend and reinstate (with a new key);
  seq and epoch against replay; ordered SW-* error codes.
- Hash-chained log (JSON Lines, fsync per entry) with optional mirror file compared every 30 s;
  `log verify` and `log export` (one line per vote: timestamp, vote hash, signature).
- Coordinator over HTTP (stdlib): votes, offline-assembled certificates, log paging, heartbeats signed
  over the agent's nonce, roster enforcement with replication alerts, aggregation watchdog (200 ms,
  10 % jitter tolerance, spikes above 1.5 × never masked), halt propagation time, alert webhook,
  read-only status page, Prometheus metrics; agent and operator tokens, operator IP allowlist, rate
  limits, request and connection limits; open connections closed on shutdown.
- Agent library and `sf-smartswitch agent -- program` wrapper: verifies the log itself, dead-man rule
  (offline timeout, 30 s default), halts delivered directly or as files ahead of the log, fork detection.
- Command line: keygen, fleet init/show, serve, propose, sign, assemble, submit, status, pending,
  instances, log verify/export, agent, vectors, bench, `--demo`.
- 302 shared vectors; ports of the agent side to Node.js, Go, Rust, Java, C#, PHP and Ruby, all passing
  the vectors and an interop test against the Python coordinator.
- Deployment: Dockerfile, docker-compose with Prometheus alert rules and a Grafana dashboard.

### Fixed before release (independent review; each has a regression test in tests/test_review_fixes.py)
- One wrong clock reading made later certificates expire: log `ts_ms` no longer has to increase.
- `sign` showed the reason unfiltered (terminal escapes could fake the action): control characters
  are now shown escaped, with the fleet hash.
- The process wrapper stopped only its direct child and ignored SIGTERM: it now stops the process group.
- The agent's poll loop survives any error. A delivered certificate's expiry is checked against the
  wall clock. A delivered halt ends only with its own certificate in the log or a later resume.
- `--cert-dir` re-reads changed files. The offline flow requires `--epoch`.
- Pending proposals are capped per keyholder. Replication alerts are written once a minute per reason.
- The instance table is bounded. The mirror check runs outside the lock and logs a mismatch.
- Trusted-proxy support for per-address limits. Weak public keys are refused. The mirror catch-up is
  limited to a missing certificate. The client follows no redirects. There is an optional agent state
  file. Addresses with many failed token checks are blocked.
