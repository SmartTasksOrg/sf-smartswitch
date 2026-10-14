# Security policy

SmartSwitch 0.1.0 is experimental software. It has had no independent security review.
[README "Status"](README.md#status) says what is tested and what is not.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Report privately through GitHub: open <https://github.com/SmartTasksOrg/sf-smartswitch>, go to the
**Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Only
the maintainers can read the report.

Do not open a public issue, pull request or discussion for a vulnerability, and do not put a working
exploit in one.

If the Security tab shows no "Report a vulnerability" button, private reporting is switched off. Open a
public issue that says only "I have a security report; please enable private vulnerability reporting",
with no details, and wait for a maintainer.

## What to include

- The version (`sf-smartswitch --version`) or the port, and your platform.
- The smallest input that shows the problem, and what you expected.

Remove real secrets, tokens and personal data from what you send.

## Packages that pretend to be SmartSwitch

The only package names the maintainers publish are listed with `"registered": true` in
[names.json](names.json). Official releases are built by `.github/workflows/release.yml` in
`SmartTasksOrg/sf-smartswitch` and published with trusted publishing, so each file carries a provenance
attestation that names this repository and that workflow.

A package on any registry that uses this project's name but is not listed there, or a release file
without that provenance, is not ours. Report it through the private form above, and to the registry
(PyPI: "Report project as malware" on the project page).

## What to expect

- An answer in the private report. No response time is promised; this is a small project without a
  security team on call.
- A confirmed issue is fixed in a new release, announced in `CHANGELOG.md` and in a GitHub security
  advisory, with credit to the reporter unless they ask not to be named.
- There is no bug bounty.

## Scope

In scope: the code in this repository and its build, deployment and release files. Especially:
- a halt, resume, suspension or reinstatement accepted with fewer valid keyholder signatures than the
  quorum, or by a suspended or unknown keyholder;
- an agent that runs although its verified state halts it, or after `offline_timeout_ms` without a
  valid heartbeat;
- a heartbeat or certificate accepted after replay, or for another fleet, agent or nonce;
- a log that verifies after tampering;
- reaching an operator endpoint without the operator token or from outside the allowlist;
- two engines (Python and a port) giving different results for the same input;
- a flaw in the Ed25519 verifiers of the Rust and C# ports.

Out of scope:
- agents that do not run the SmartSwitch agent code, or ignore it (see README, "What an agent checks");
- the protection of a keyholder's private key on the keyholder's own device;
- the example values in `deploy/.env.example`.

Known by design:
- A coordinator can delay a certificate by not writing it. Halts also reach agents directly
  (`--cert-dir`, `Agent.deliver`).
- Anyone who can stop the coordinator's heartbeats stops the agents after `offline_timeout_ms`. This is
  the council's fail-safe choice.
- Instance ids are reported by the agents. The roster catches copies that run the agent code
  unmodified, not an attacker who reuses a live instance id.
