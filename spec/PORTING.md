# Porting SmartSwitch

A port is the **agent side** in another language: it verifies the log and certificates, applies the
agent rules and talks to the coordinator. Signing (keyholders) and the coordinator stay in Python.
Read `SEMANTICS.md` first; the vectors in `conformance/` are the test.

## What a port contains

1. **Canonical JSON** encoder over the language's parsed JSON values (`canonical.json`).
2. **SHA-256** (the standard library's, or an own implementation where there is none).
3. **Ed25519 verify** with the engine's own pre-checks (lower-case hex, lengths, S < L) before the
   library call (`ed25519.json`). Where the standard library has no Ed25519 (Rust without crates,
   .NET), the port carries its own verify-only implementation; it must pass the RFC 8032 vectors in
   `ed25519.json` and say in its README that it has not been audited.
4. **Fleet validation**, default threshold and fleet hash (`fleets.json`).
5. **Certificate checks and apply**, in the order of SEMANTICS.md (`certificates.json`).
6. **Log replay** (`logs.json`).
7. **Agent view**: log / heartbeat / certificate / status (`agent.json`).
8. **A networked agent**: every `poll_ms` send `GET /v1/heartbeat?agent_id=&instance_id=&nonce=` with a
   fresh 16-byte random nonce (a cryptographic random source, as 32 lower-case hex) and
   `Authorization: Bearer <token>`; record the monotonic time just before sending; on `SW-BEHIND` fetch
   `GET /v1/log?from=<replica size>&limit=1000&agent_id=&instance_id=` until caught up, then check the
   same heartbeat again. Network errors change nothing (the dead-man rule does the rest).
9. **A conformance runner** (`<runner> <vectors dir>`): prints failures and a last line
   `<port>: N/N vectors passed`, exit 1 on any failure. N must equal the Python count (302).
10. **An interop agent** for `ports/conformance/interop.py`: arguments `URL FLEET_FILE AGENT_ID INSTANCE_ID`,
    token from `SMARTSWITCH_AGENT_TOKEN`, poll every 100 ms, print `STATUS <code>` (flushed) whenever the
    status code changes, exit when standard input closes or after 60 s.

## How each vector file is checked (exactly what the Python runner does)

- `canonical.json`: for each case, `canonical(input)` equals `canonical` and the SHA-256 of its UTF-8
  bytes equals `sha256` (one check per case).
- `ed25519.json`: `verify(public_key, hex-decode(message_hex), sig) == valid`.
- `fleets.json`: `default_threshold(n) == k` for each of `default_thresholds`; for each case, validation
  gives `{ok: true, fleet_hash, threshold}` or `{ok: false, code}`, compared with the case's fields.
- `certificates.json`: genesis state of `fleets[fleet]`; apply each `setup` certificate at its `at_ms`;
  check `proposal_hash(certificate.proposal) == proposal_hash` (null when the certificate has no
  `proposal` field; that is one check); then with `ahead` false apply it, giving `{ok: true, state: summary}`,
  or with `ahead` true only verify it, giving `{ok: true, state: null}`; on failure `{ok: false, code}`.
  Compare with the case's `ok`, `state`, `code` (those present).
- `logs.json`: replay `entries` with `pinned` (null: no pin) and compare with `result`.
- `agent.json`: a new agent view for `fleet`, `agent_id`, `instance_id` per case; run the steps in order
  and compare each result with `expect` (one check per step). Results are exactly the objects in
  SEMANTICS.md: log `{ok, size}` or `{ok, code, size}`; heartbeat and certificate `{ok, code}`;
  status `{run, code}`.

Comparisons are of JSON values: key order does not matter, integers compare as integers.

## Pitfalls seen while porting

- JSON numbers: the documents only use integers up to 2^53 − 1. A value like `2.5` or `true` where an
  integer is required is invalid; parse numbers so that you can tell (`2.5`, `true` and `"1"` are
  in the vectors).
- The reason length limit is in UTF-8 bytes, not characters or UTF-16 units.
- Canonical strings: escape only the listed characters; U+2028, U+2029, U+007F and all non-ASCII are
  written as they are (not `\u` escapes, which JavaScript's `JSON.stringify` does not produce for these
  anyway, but other encoders do for non-ASCII).
- Object keys sort by bytes (ASCII), so `"B" < "_" < "a"`.
- Ed25519 libraries differ on edge cases; the S < L pre-check and the vectors keep engines in step.
- A heartbeat whose `log_size` is below the replica size is not a fork as long as the hashes match.
- Open a new connection for each request (no keep-alive pool), as the Python agent does. The coordinator
  closes its open connections when it stops, but a proxy in between may not; a pooled connection that
  outlives the coordinator could only delay the dead-man rule, never fake a halt or a resume.
- A value with no canonical form (a fractional number, or a string with an unpaired UTF-16 surrogate
  such as `"\ud800"`) can never hash or verify: such a log entry is `SW-LOG-CHAIN`, such a heartbeat
  `SW-BAD-HEARTBEAT`, such a reason `SW-BAD-PROPOSAL` in the Python reference. Engines whose JSON
  parser silently replaces unpaired surrogates (Go) reach a failure too, by another check; there is
  no vector for unpaired surrogates.
