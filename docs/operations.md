# Operations

A walkthrough from keys to drills. Commands assume `sf-smartswitch` is installed (README, "Install").
Tokens come from the environment, never from the command line.

## 1. Keys

Each keyholder makes their key **on their own device**, then sends only the public key to the operator:

```bash
sf-smartswitch keygen --name alice --out alice.key
```

The file is created with mode 0600 and is never overwritten. Whoever reads it can vote as alice.
Keep it out of shared folders, backups others can read, and repositories (`*.key` is in `.gitignore`).

The operator makes the coordinator's key on the coordinator host:

```bash
sf-smartswitch keygen --name coordinator --out coordinator.key
```

## 2. The fleet document

```bash
sf-smartswitch fleet init --fleet-id prod \
    --keyholder alice=<public key> --keyholder bob=<public key> --keyholder carol=<public key> \
    --coordinator-key coordinator.key \
    --agent planner --agent worker:4 \
    --out fleet.json
sf-smartswitch fleet show fleet.json
```

- **Quorum:** 2 for 3 to 5 keyholders and a strict majority above five. `--threshold` sets it
  explicitly, between 2 and n − 1.
- **Roster:** `--agent ID[:MAX]` limits how many instances of each agent may run at once. Without any
  `--agent` there is no roster: every agent id is answered and nothing is counted as replication.
- **Offline timeout:** `--offline-timeout-ms`, default 30 000, sets the dead-man rule.
- **Proposal lifetime:** `--max-ttl-ms`, default 600 000, is the longest a proposal may stay open for
  votes.

`fleet.json` holds only public keys. Every agent and every keyholder needs a copy, and the fleet hash
it prints is what they check. Keyholders cannot be added or removed later. A different set of people
means a new fleet document and a new log. Keys can be replaced (section 6).

## 3. The coordinator

```bash
export SMARTSWITCH_AGENT_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export SMARTSWITCH_OPERATOR_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export SMARTSWITCH_OPERATOR_ALLOW=10.0.0.0/8           # optional: where votes may come from
export SMARTSWITCH_TRUSTED_PROXIES=127.0.0.1           # behind a reverse proxy: its address (X-Forwarded-For)
export SMARTSWITCH_ALERT_WEBHOOK=https://...           # optional: alerts as {"text", "alert", ...}
sf-smartswitch serve --fleet fleet.json --key coordinator.key \
    --log /var/lib/smartswitch/switch.jsonl --mirror /mnt/second-disk/switch.jsonl \
    --host 127.0.0.1 --port 8720
```

Put a TLS proxy in front (the coordinator speaks plain HTTP) and set connection limits there as well.

The log is the state. At start, the coordinator verifies the log from entry 0 and compares it with
the mirror. If the log does not verify, belongs to another fleet, or differs from the mirror, it
refuses to start. One case is repaired automatically: if the mirror is exactly one entry behind the
log and that entry is a certificate (signed, so it cannot have been slipped in), it is caught up, and
the catch-up is itself logged. If the missing entry is an event, check what happened, then start once
with `--repair-mirror`. Every entry is written to the log first and then to the mirror, so a crash
between the two writes leaves this state. A crash in the middle of a write leaves a torn last line.
The coordinator reports it (`SW-BAD-ENTRY`, with the line number) and does not start. Do not "fix" a log by hand. Find out what happened. The original is evidence.

Run one coordinator per fleet. Two coordinators writing different logs would show agents two
histories, and agents stop on a fork.

The read-only status page is `https://<proxy>/ui`. The browser asks for a user name (any) and a
password (the operator token).

## 4. Agents

Wrap each agent process so that it is stopped without having to cooperate:

```bash
export SMARTSWITCH_AGENT_TOKEN=...
sf-smartswitch agent --url https://switch.internal --fleet fleet.json --agent-id worker \
    --cert-dir /etc/smartswitch/certs -- ./worker --config worker.yaml
```

The wrapper:
- does not start the program until a heartbeat verifies (`--wait-s`, 30 s);
- runs the program in its own process group and stops the whole group, also when the wrapper itself is
  sent SIGTERM or SIGINT;
- with `--state-file`, remembers the log size and head it verified, so that a coordinator that comes
  back with less history is treated as a fork;
- polls every `--poll-ms` (1000);
- when the agent may no longer run, terminates the program, kills it after `--grace-s` (5 s) and exits
  with code 75.

Give your supervisor a restart policy that does not loop on exit code 75. For in-process use and the
ports, see [integration.md](integration.md).

## 5. Halting and resuming

Online, two keyholders:

```bash
sf-smartswitch propose --url https://switch.internal --key alice.key --action halt --target '*' --reason "runaway spend"
# prints the proposal hash; bob checks the proposal shown and signs it:
sf-smartswitch sign --url https://switch.internal --key bob.key --hash <hash>
```

`sign` shows the action, the target, the reason and the expiry, and asks for `yes`. Read it: a
keyholder's signature is the whole protection. `sf-smartswitch pending --url ...` lists open proposals.

Targets are `*` (the whole fleet) or an agent id. A whole-fleet resume also clears all single-agent
halts. Agents stop within one poll of the certificate being written: one second by default plus the
time to fetch the log. The `smartswitch_propagation_ms` metric shows how long it took until every live
instance had fetched the halt.

**Without the coordinator:** the keyholders exchange files over any channel, then deliver the
certificate to the agents' `--cert-dir`. The agents check it themselves.

```bash
sf-smartswitch propose --offline --fleet fleet.json --seq <current seq + 1> --epoch <current epoch> --key alice.key \
    --action halt --target '*' --reason "coordinator down, halting" --out halt.json
sf-smartswitch sign --proposal halt.json --key bob.key                     # writes halt.json.vote-bob.json
sf-smartswitch assemble --fleet fleet.json --log <a copy of the log, if you have one> \
    --proposal halt.json --vote halt.json.vote-alice.json --vote halt.json.vote-bob.json --out cert.json
```

Take seq and epoch from the last `sf-smartswitch status` you saw, or from a copy of the log
(`log verify` prints them). Without `--log`, `assemble` refuses a proposal whose epoch is not 0 unless
you add `--assume-epoch`. It cannot know about suspensions or key changes since the fleet document was
made.

An agent accepts a delivered halt when all of these hold:
- it is signed by a quorum of the agent's current keyholders;
- its epoch is the agent's epoch;
- its seq is above the agent's (any higher seq is accepted);
- it has not expired, by the agent's wall clock.

The halt then holds until the log contains that same certificate, or a later resume. Another
certificate taking its seq does not lift it. When the coordinator is back, `submit` the certificate. It is written only
if its seq is exactly the next one; otherwise propose again online. Resumes only come through the log.

## 6. Suspending and replacing a keyholder

When a keyholder's device is lost or the person leaves, any quorum of the others runs:

```bash
sf-smartswitch propose --url ... --key alice.key --action suspend --target carol --reason "laptop lost"
sf-smartswitch sign    --url ... --key bob.key --hash <hash>
```

Carol's votes stop counting at once, including on open proposals, because the epoch changes. To bring
her back, she makes a new key on her new device, and a quorum reinstates her with its public key:

```bash
sf-smartswitch propose --url ... --key alice.key --action reinstate --target carol \
    --new-public-key <carol's new public key> --reason "new laptop"
sf-smartswitch sign    --url ... --key bob.key --hash <hash>
```

The time from "laptop lost" to a working new key is the time two keyholders need to run two commands
each. The council's target is under 5 minutes; measure yours in a drill.

## 7. Monitoring and alerts

`deploy/prometheus/alerts.yml` alerts on:

| Alert | Fires when |
|---|---|
| `SmartSwitchDown` | the coordinator has not been scrapable for 30 s; agents stop at the same time |
| `SmartSwitchFleetHalted` | the whole fleet is halted |
| `SmartSwitchAggregationSlow` | a watchdog alert was raised in the last 5 minutes |
| `SmartSwitchReplication` | an unknown agent or an extra instance appeared |
| `SmartSwitchMirrorMismatch` | the log and its mirror differ |
| `SmartSwitchCertificateRejected` | votes or certificates are being refused at a rate that suggests probing |

Alerts are also entries in the log (`event`) and webhook calls.

## 8. Audit export and retention

```bash
sf-smartswitch log verify switch.jsonl --fleet fleet.json --mirror /mnt/second-disk/switch.jsonl
sf-smartswitch log export switch.jsonl --out votes-2026-10.jsonl
```

The export has one line per vote:
- `timestamp` (the entry's time);
- `entry` and `entry_hash`;
- `seq`, `action` and `target`;
- `proposal_hash`;
- `keyholder`, `vote_hash` and `signature`.

The council decided that logs are kept for 7 years, in encrypted object storage, with a move to
archive storage after one year. SmartSwitch writes the file; shipping it there is your storage's job.
Copy the log, not just the export: only the log can be verified from the fleet document. Keep a
record of the head hash that `log verify` prints, somewhere the coordinator's operators cannot write.
The chain proves that the log is consistent. It does not prove who wrote it. Whoever controls the file
can rewrite unsigned parts, such as timestamps and events, and recompute every hash after them. The
signed certificates cannot be changed this way. A recorded head, the mirror and the agents' own copies
catch such a rewrite.

## 9. Drills

Run a drill on a schedule, in a staging fleet or in production with a fleet halt you announce:
1. Two keyholders halt the fleet.
2. Check every agent stopped. Note `smartswitch_propagation_ms`.
3. Two other keyholders resume.
4. Stop the coordinator.
5. Check every agent stopped within the offline timeout.
6. Start the coordinator. Check agents resume.
7. Deliver an offline certificate to one agent's `--cert-dir`.
8. Suspend and reinstate one keyholder. Time it.
9. `log verify` and export.

Record the times. The private test harness of the maintainers does the same under simulated network
faults; your network is what matters.
