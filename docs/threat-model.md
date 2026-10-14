# Threat model

What SmartSwitch defends against, how, and what it leaves to you. The exact rules are in
[spec/SEMANTICS.md](../spec/SEMANTICS.md).

## Assets and parties

- **Keyholders** (3 to 64 people), each with one Ed25519 private key on their own device.
- **The coordinator**, which collects votes, writes the log and answers heartbeats with its own key.
- **Agents**, each deployed with the fleet document (or its hash) and running the agent code.
- **The log**, the hash-chained record of every certificate and alert.

## Threats and what stops them

| Threat | What happens | Why |
|---|---|---|
| One keyholder is compromised or coerced and halts the fleet | refused (`SW-NO-QUORUM`) | the quorum is at least 2 |
| One keyholder refuses to sign a real halt, or is unreachable | the others halt without them | the quorum is at most n − 1 (but see "Suspensions" below) |
| A suspended keyholder keeps voting | refused (`SW-SUSPENDED-KEYHOLDER`) | suspension needs the quorum and raises the epoch |
| A quorum suspends people until one person decides alone | refused (`SW-QUORUM-IMPOSSIBLE`) | the threshold is fixed at n's value; active keyholders may not drop below it |
| Someone replays an old halt or resume | ignored (`SW-STALE-SEQ`) | every certificate names the next seq; seq only grows |
| Someone replays an old vote after a membership change | refused (`SW-WRONG-EPOCH`) | votes name the epoch |
| The coordinator forges a halt or a resume | agents refuse it | agents verify every signature against the fleet document they were deployed with |
| The coordinator withholds a halt | the halt reaches agents another way | `--cert-dir` / `Agent.deliver`: a quorum-signed halt stops the agent provisionally |
| The coordinator rewrites history (another log) | the agent stops (`SW-FORK`) | heartbeats state the log head; an agent compares it with what it verified |
| A network attacker replays an old "all is fine" heartbeat | useless (`SW-NONCE`) | each heartbeat is signed over the agent's fresh random nonce |
| A network attacker blocks heartbeats | agents stop after `offline_timeout_ms` | the council's fail-safe: losing contact means stopping |
| An agent copies itself | refused and logged (`replication-alert`) | the roster limits instances per agent; refused copies get no heartbeat and stop |
| Someone edits the log on disk | an edit of signed content fails `log verify`; an edit of anything else fails it too unless the hashes after it are recomputed | SHA-256 chain from the fleet document |
| Someone rewrites the log with recomputed hashes (timestamps, events, a dropped tail) | it no longer matches the mirror (checked every 30 s and at start), the agents' copies (they stop with `SW-FORK`), or a head you recorded elsewhere | the chain proves consistency, not authorship: keep independent copies |
| Someone with an operator token sends votes | nothing happens without valid signatures | the token only opens the door |

## Suspensions

Suspension never lowers the quorum, and it is refused when fewer active keyholders than the quorum would
remain. In between, the active keyholders may number exactly the quorum. For example, 3 keyholders with
1 suspended and a quorum of 2 leave 2 active. Then each active keyholder can block halts, and the
reinstatement, until the suspended keyholder is back. With 5 keyholders and a quorum of 2, two
suspensions still leave a margin. Prefer 5 or more keyholders if suspensions will happen while the
switch must stay usable.

## What it does not defend against

- **Agents that do not run the agent code, or ignore it.** SmartSwitch can only stop what checks it.
  Use the process wrapper (`sf-smartswitch agent -- program`) so that the program does not need to
  cooperate. Run agents with only the credentials and network access they need, so that a stopped
  wrapper means a stopped agent.
- **A quorum of compromised keyholders.** By design, a quorum can halt and resume.
- **Theft of a key from a keyholder's device.** Use full-disk encryption and an OS account per person.
  Suspend and reinstate (with a new key) as soon as a device is lost. Hardware tokens are outside this
  version.
- **Copies that reuse a live instance id, and squatting.** Instance ids are reported by agents, not
  proven. The roster catches unmodified copies of the agent code. It does not catch an attacker who
  controls the copy. Anyone with the agent token can also hold an agent's instance slots, so that the
  real agent is refused (409) when it restarts. Keep the agent token as secret as the agents
  themselves.
- **A coordinator that loses its log.** Running agents that had seen the lost entries stop (`SW-FORK`).
  A restarted agent remembers nothing unless it was given a state file (`--state-file`, or `state_file`
  in Python). With one, a coordinator whose log is shorter, or different, is a fork for it too. Keep
  the mirror on another disk and ship the log to storage you trust.
- **Weak public keys** (small-order points, non-canonical encodings) would make engines disagree. Some
  would also let anyone forge that keyholder's vote. `fleet init` and the coordinator refuse them, at
  start and in a reinstatement. Agents rely on that check and do not repeat it.
- **Delay by the coordinator** while no other path delivers the certificate. Plan a second path, for
  example a shared folder or a configuration push that drops certificate files into `--cert-dir`.

## Numbers

The council estimated a 0.1 % chance per year that one keyholder is compromised, for teams of 3 to 5.
That figure is the council's estimate, not a measurement. If each keyholder is compromised
independently with p = 0.001 per year, the binomial distribution gives the chance that enough of them
are compromised in one year:

| Keyholders n | Quorum k | P(≥ k compromised: false halt) | P(≥ n − k + 1 compromised: blocked halt) |
|---|---|---|---|
| 3 | 2 | 3.0 × 10⁻⁶ | 3.0 × 10⁻⁶ |
| 4 | 2 | 6.0 × 10⁻⁶ | 4.0 × 10⁻⁹ |
| 5 | 2 | 1.0 × 10⁻⁵ | 5.0 × 10⁻¹² |
| 6 | 4 | 1.5 × 10⁻¹¹ | 2.0 × 10⁻⁸ |
| 7 | 4 | 3.5 × 10⁻¹¹ | 3.5 × 10⁻¹¹ |
| 8 | 5 | 5.6 × 10⁻¹⁴ | 7.0 × 10⁻¹¹ |
| 9 | 5 | 1.3 × 10⁻¹³ | 1.3 × 10⁻¹³ |
| 10 | 6 | 2.1 × 10⁻¹⁶ | 2.5 × 10⁻¹³ |

Real compromises are not independent: one phishing campaign or one shared laptop image can reach
several keyholders. Treat the table as a lower bound and keep keyholders' devices and accounts
separate. A blocked halt is also caused by keyholders who are simply unreachable, which this table
does not count. The dead-man rule and direct delivery are the answers to that.
