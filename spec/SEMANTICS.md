# SmartSwitch semantics (version 1)

This is the contract every SmartSwitch engine implements: the Python reference (`src/sf_smartswitch/`)
and the ports (`ports/`). The vectors in `conformance/` test it: an engine conforms when it passes all
of them. Where this text and the vectors disagree, the vectors win and this text is a bug.

## What it guarantees, and what it does not

- No single keyholder can halt a fleet, resume it, or change who the keyholders are: each needs a
  certificate with valid signatures from a quorum of active keyholders (at least 2).
- No single keyholder can block a halt: the quorum is at most n − 1, so the others can always reach it.
  One exception, by construction: while keyholders are suspended, the active ones may number exactly the
  quorum (3 keyholders, 1 suspended, quorum 2), and then each of them can block until the suspended one
  is reinstated. Fleets of 5 or more keyholders keep a margin.
- Every agent checks every certificate itself against the fleet document it was deployed with. The
  coordinator cannot forge a halt or a resume, and neither can anyone on the network.
- Every certificate, and every alert the coordinator raises, is an entry in a hash-chained log that any
  holder of the fleet document can verify from the first entry.
- An agent that hears nothing valid from the coordinator for `offline_timeout_ms` stops by itself.

It does not: stop an agent that does not run the SmartSwitch agent code (or ignores it); protect a
keyholder's private key on the keyholder's own device; keep a coordinator from delaying a certificate
(agents also accept halts delivered another way, below); or prevent two quorums signing conflicting
proposals for the same seq (the first one written to the log wins; the other becomes stale).

## Encodings

- **Canonical JSON** (what is hashed and signed): objects with ASCII keys sorted byte-wise, no
  whitespace, `,` and `:` separators; strings in UTF-8, escaped only as `\"` `\\` `\b` `\f` `\n` `\r` `\t`
  and `\u00XX` (lower-case hex) for the other characters below U+0020, everything else written as is;
  integers only (no floats); `true`, `false`, `null`; arrays in order. Vectors: `canonical.json`.
- **Hashes**: SHA-256, lower-case hex (64 characters). `doc_hash(x) = sha256(canonical(x))`.
- **Keys and signatures**: Ed25519 (RFC 8032). A public key is 64 lower-case hex characters, a
  signature 128.
- **Ids** (fleet, keyholder, agent, instance): 1 to 64 characters from `A-Z a-z 0-9 . _ -`.
- **Integers** in the documents below are at most 2^53 − 1. A value with no canonical form (a
  fractional number, or text that is not valid Unicode) cannot be hashed: an entry or heartbeat holding
  one fails its hash or signature check.

## Signatures

`verify(public_key, message, sig)` is true only when all of these hold, checked by the engine itself
before calling its Ed25519 library: `public_key` is 64 and `sig` 128 lower-case hex characters; the
scalar `S` (signature bytes 32–63, little-endian) is less than the group order
L = 2^252 + 27742317777372353535851937790883648493; and the library verifies the signature (RFC 8032,
cofactorless). Any library error is false. Vectors: `ed25519.json`.

## Fleet document

The trust anchor. Every agent is deployed with it (or with its hash) and checks entry 0 of the log
against it. All fields are required; no other field is allowed.

| Field | Rule |
|---|---|
| `type` | `"smartswitch.fleet"` |
| `version` | `1` (an integer, not `true`) |
| `fleet_id` | an id |
| `keyholders` | 3 to 64 objects `{"id", "public_key"}` (exactly these fields); ids unique, keys unique |
| `threshold` | `null` (use the default) or an integer from 2 to n − 1 |
| `coordinator_key` | a public key, different from every keyholder key; signs heartbeats |
| `offline_timeout_ms` | integer, 1000 to 3 600 000 (council default 30 000) |
| `proposal_max_ttl_ms` | integer, 1000 to 86 400 000: the longest a proposal may stay valid |
| `agents` | `null` (no roster) or up to 100 000 objects `{"id", "max_instances"}`; ids unique; `max_instances` 1 to 1000 |

Anything else is `SW-BAD-FLEET`. `fleet_hash = doc_hash(fleet)`.

**Default threshold** (n = number of keyholders, fixed for the life of the fleet): 2 when n ≤ 5,
otherwise `floor(n / 2) + 1` (a strict majority: 4 of 6, 4 of 7, 5 of 8). The council's text wrote
`ceil(n/2) + 1` next to the example "4-of-7"; those disagree for odd n, and this version follows the
example (open decision in the maintainers' notes; set `threshold` to choose another value).

Keyholders cannot be added or removed: a fleet with other keyholders is a new fleet document (and a
new log). Keys can be replaced by suspension and reinstatement.

## State

Derived from the fleet document and the certificates applied so far:
`seq` (certificates applied, starts at 0), `epoch` (membership changes applied, starts at 0),
`threshold` (fixed), `keys` (keyholder id → current public key), `suspended` (set of keyholder ids),
`halted_all` (bool), `halted` (set of agent ids). The vectors compare the summary
`{seq, epoch, threshold, halted_all, halted (sorted), active (sorted ids not suspended), suspended (sorted),
keys}`.

An agent may run (by state) when `halted_all` is false and its id is not in `halted`.

## Proposal

Exactly these fields:

| Field | Rule |
|---|---|
| `type` | `"smartswitch.proposal"` |
| `fleet_id`, `fleet_hash` | of the fleet |
| `seq` | integer ≥ 1: the seq this proposal would take (state seq + 1) |
| `epoch` | integer ≥ 0: the epoch it was made in |
| `action` | `halt`, `resume`, `suspend` or `reinstate` |
| `target` | string. halt/resume: `"*"` (the whole fleet) or an agent id. suspend/reinstate: a keyholder id |
| `new_public_key` | reinstate: the keyholder's new public key (required); every other action: `null` |
| `reason` | string of at most 1000 bytes in UTF-8 |
| `created_ms`, `expires_ms` | integers ≥ 0, `expires_ms > created_ms` (wall-clock milliseconds) |

A format error is `SW-BAD-PROPOSAL`. `proposal_hash = doc_hash(proposal)`.

## Vote and certificate

A vote is `{"keyholder": id, "sig": verify-able signature}` over the ASCII bytes
`"smartswitch-vote-v1:" + proposal_hash`. A certificate is
`{"type": "smartswitch.certificate", "proposal": {...}, "votes": [1 to 64 votes]}` (exactly these fields;
each vote exactly `keyholder` and `sig`, both strings); otherwise `SW-BAD-CERTIFICATE`. The
coordinator writes votes sorted by keyholder id; verifiers accept any order.

## Certificate checks

`verify_certificate(state, certificate, at_ms, ahead)`. The first failing check gives the code:

1. certificate format: `SW-BAD-CERTIFICATE`
2. proposal format: `SW-BAD-PROPOSAL`
3. `fleet_id` and `fleet_hash` are the state's: else `SW-WRONG-FLEET`
4. `seq > state.seq`: else `SW-STALE-SEQ`
5. unless `ahead`: `seq == state.seq + 1`: else `SW-SEQ-GAP`
6. `epoch == state.epoch`: else `SW-WRONG-EPOCH`
7. `expires_ms − created_ms ≤ proposal_max_ttl_ms`: else `SW-BAD-PROPOSAL`
8. `at_ms < expires_ms`: else `SW-EXPIRED` (there is no lower bound: clocks differ)
9. target:
   - halt/resume: `"*"` or an id, else `SW-BAD-TARGET`
   - suspend: an active keyholder, else `SW-BAD-TARGET`; and the active keyholders minus one must still
     be at least the threshold, else `SW-QUORUM-IMPOSSIBLE`
   - reinstate: a suspended keyholder, else `SW-BAD-TARGET`; `new_public_key` must not be any
     keyholder's current key nor the coordinator key, else `SW-BAD-TARGET`
10. each vote, in list order: a keyholder (`SW-UNKNOWN-KEYHOLDER`), not seen before in this certificate
    (`SW-DUPLICATE-VOTE`), not suspended (`SW-SUSPENDED-KEYHOLDER`), not the target of a suspend
    (`SW-TARGET-VOTE`), signature valid with the keyholder's current key (`SW-BAD-SIGNATURE`)
11. the number of votes is at least the threshold: else `SW-NO-QUORUM`

## Apply

`apply(state, certificate, at_ms)` = the checks with `ahead = false`, then `seq += 1` and:
halt `*` → `halted_all = true`; halt id → add to `halted`; resume `*` → `halted_all = false` and
`halted` emptied; resume id → remove from `halted`; suspend → add to `suspended`, `epoch += 1`;
reinstate → remove from `suspended`, set its key to `new_public_key`, `epoch += 1`.
Halting a halted target or resuming a running one is allowed and changes nothing but `seq`.
Vectors: `certificates.json`.

## Log

A list of entries `{"n", "ts_ms", "kind", "body", "prev", "hash"}` (exactly these fields):
`n` is the index (0, 1, 2, ...), `ts_ms` an integer ≥ 0, `kind` one of `genesis`, `certificate`, `event`,
`body` an object, `prev` the previous entry's hash (64 zeros for entry 0) and
`hash = doc_hash(entry without "hash")`.

Replay checks each entry in order; the first failure gives `{ok: false, index, code}`:

1. shape (fields, kind, types, `ts_ms ≥ 0`): `SW-BAD-ENTRY`
2. `n` equals the index: `SW-LOG-ORDER`. (`ts_ms` is the coordinator's wall clock when it wrote the
   entry. It is not signed and need not increase: one wrong clock reading must not make every later
   certificate look expired.)
3. `prev` and `hash` match: `SW-LOG-CHAIN`
4. entry 0 must be a genesis (`SW-BAD-ENTRY`), its body a valid fleet (`SW-BAD-FLEET`) and, when a fleet
   hash is pinned, the pinned one (`SW-WRONG-FLEET`); later entries must not be a genesis (`SW-BAD-ENTRY`)
5. a certificate entry is applied with `at_ms = ts_ms` (its code on failure); an event entry changes nothing

An empty log is `{ok: false, index: 0, code: SW-BAD-ENTRY}`. Success is
`{ok: true, size, head (hash of the last entry), state (summary)}`. Vectors: `logs.json`.

## Heartbeat

The coordinator's signed answer to an agent's nonce:
`{"type": "smartswitch.heartbeat", "fleet_hash", "agent_id", "instance_id", "nonce", "log_size", "head",
"issued_ms", "sig"}` (exactly these fields). `nonce` is 32 lower-case hex characters chosen at random by
the agent for each request; `log_size` (≥ 1) and `head` describe the coordinator's log; `sig` is the
coordinator key's signature over `"smartswitch-heartbeat-v1:" + doc_hash(heartbeat without "sig")`.

## Agent

What every agent implementation does, with `at_ms` the agent's own monotonic clock (except for
`certificate`, below). The agent keeps a
verified copy of the log (a replica pinned to its fleet hash), `last_ok` (unset at start),
`provisional` (unset) and `fork` (false).

- **log(entries)**: append to the replica one entry at a time; on the first bad entry return
  `{ok: false, code, size}` (entries before it are kept); else `{ok: true, size}`. Each certificate entry
  appended changes `provisional` (a map from proposal hash to seq, empty at start): its own proposal
  hash is removed (the state now holds that halt); and if it is a resume of `*` or of this agent, every
  provisional halt with a seq below the resume's seq is removed. Another certificate taking the seq of
  a provisional halt does not remove it.
- **heartbeat(hb, nonce, at_ms)** (`at_ms`: when the agent sent `nonce`). First failing check:
  1. shape (fields, type, `log_size` integer ≥ 1, `head` 64 hex, `issued_ms` integer ≥ 0): `SW-BAD-HEARTBEAT`
  2. signature by the fleet's `coordinator_key`: `SW-BAD-HEARTBEAT`
  3. `fleet_hash`: `SW-WRONG-FLEET`
  4. `agent_id` and `instance_id` are this agent's: `SW-WRONG-AGENT`
  5. `nonce` is 32 lower-case hex and equals the one sent: `SW-NONCE`
  6. if the replica has at least `log_size` entries: entry `log_size − 1` must have hash `head`, else
     `fork = true` and `SW-FORK`. If it has fewer: `SW-BEHIND` (fetch the log, then check the same
     heartbeat again).
  
  On success `last_ok = max(last_ok, at_ms)` and the result is `{ok: true, code: SW-OK}`; on failure
  `{ok: false, code}` and nothing else changes (except `fork`).
- **certificate(cert, at_ms)**: a certificate delivered outside the log; `at_ms` here is **wall-clock**
  time (it is compared with `expires_ms`). No state yet: `SW-NO-STATE`. Otherwise the certificate checks
  with `ahead = true` (their code on failure). A valid certificate that is not a halt of `*` or of this
  agent: `SW-NOT-APPLICABLE`. A valid halt: `provisional[proposal_hash] = seq` and
  `{ok: true, code: SW-PROVISIONAL-HALT}`. A direct certificate never changes the replica: only the log
  does. A resume can only come through the log.
- **status(at_ms)**: the first that applies: `fork` → `SW-FORK`; state `halted_all` → `SW-HALTED-FLEET`;
  this agent in `halted` → `SW-HALTED-AGENT`; `provisional` not empty → `SW-PROVISIONAL-HALT`; no state or
  `last_ok` unset → `SW-NO-HEARTBEAT`; `at_ms − last_ok ≥ offline_timeout_ms` → `SW-OFFLINE`; otherwise
  `{run: true, code: SW-RUN}`. All others are `{run: false, code}`.

`fork` stays set until the agent is restarted (a person has to look). Vectors: `agent.json`.

A networked agent's poll loop must survive any error (a malformed answer, a parser limit, a broken
connection): an error changes nothing, and the dead-man rule takes over if errors persist. An
implementation may also keep, across restarts, the log size and head it had verified, and treat a
coordinator whose log is shorter, or differs at that size, as a fork (the Python agent's
`state_file`). This is optional and not covered by the vectors.

## Coordinator (not covered by the vectors)

- Accepts a vote when every certificate check except the quorum passes for that vote alone; keeps it
  with the proposal until the quorum is reached, then writes the certificate (votes sorted by keyholder)
  with `ts_ms` = its clock. Pending proposals with a seq at or below the new state seq are dropped;
  votes are kept in memory only. A keyholder may have opened (cast the first vote of) at most 10 pending
  proposals; an eleventh replaces that keyholder's oldest.
- **Key hygiene**: at start and before accepting a reinstatement, the coordinator (and `fleet init`)
  refuses public keys that are not the canonical encoding of a curve point, or are of small order.
  Agents do not repeat this check; such keys never reach them through a coordinator.
- Accepts complete certificates (assembled offline) the same way.
- Answers a heartbeat with its current log size and head. With a roster, it refuses (403) instances of
  agents not in the roster and (409) a new instance beyond `max_instances` live ones, counts every refusal, and writes a
  `replication-alert` event at most once a minute per reason. An instance is live while
  its last heartbeat is younger than `offline_timeout_ms`. Refused instances stop by the dead-man rule.
- **Watchdog**: aggregation time is measured from receiving the vote that completes the quorum to the
  certificate being written. Above `base_ms` (200) plus 10 % of the moving average (EWMA, α = 0.2) of
  earlier aggregations: `aggregation-slow`; above 1.5 × `base_ms`: `aggregation-spike` (never masked by
  the tolerance). Each is an event entry, a metric and, if configured, a webhook call.
- **Mirror**: with a mirror file, every entry is written (and fsynced) to both; every 30 s both are
  verified and compared; a difference sets `smartswitch_log_mirror_ok 0` and calls the webhook. At
  start, a log that does not verify, or differs from its mirror, stops the coordinator, with one
  exception: a mirror that is exactly the log minus its last entry (a crash between the two writes,
  which always go to the log first) is caught up.
