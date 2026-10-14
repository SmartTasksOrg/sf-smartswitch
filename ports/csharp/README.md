# SmartSwitch for .NET

The agent side of SmartSwitch in C#: canonical JSON, fleet validation, certificate checks, log replay, the
agent rules (`spec/SEMANTICS.md`) and a networked agent that talks to the Python coordinator. Signing and
the coordinator stay in Python (`spec/PORTING.md`).

| Project | What it is |
|---|---|
| `SmartSwitch` | the library (assembly `SfSmartSwitch`, namespace `SmartSwitch`), net8.0 |
| `Conformance` | runs the shared vectors in `spec/conformance` |
| `Interop` | the agent used by `ports/conformance/interop.py` |

There are no package dependencies: `nuget.config` clears every package source, so a restore never pulls
code from a registry. It uses only the base class library (System.Text.Json to read JSON,
System.Security.Cryptography for SHA-256, SHA-512 and random nonces, System.Numerics.BigInteger, HttpClient).
It is not published on NuGet (`IsPackable` is false); reference the project from a clone.

## Ed25519

.NET has no Ed25519 in its base class library, so the library carries its own verify-only implementation
(`SmartSwitch/Ed25519.cs`), written for this port after the reference code in RFC 8032 section 6, with
BigInteger arithmetic. It passes the RFC 8032 test vectors (section 7.1, tests 1 to 3, included in
`spec/conformance/ed25519.json`) and the other shared vectors in that file. **It has not been
independently audited.**

Before the curve check it applies the pre-checks of `spec/SEMANTICS.md` ("Signatures"): lower-case hex,
64 characters for a key and 128 for a signature, and S < L. It then rejects a non-canonical y (y >= p) and
points that are not on the curve, and checks the cofactorless equation [S]B == R + [k]A. Any failure is
`false`, never an exception. It verifies public data and makes no attempt at constant time. One verify
takes about 5 ms in a Release build on the machine it was tested on
(`dotnet run -c Release --project Conformance -- ../../spec/conformance --time` prints it).

## Tests

    cd ports/csharp
    dotnet run -c Release --project Conformance -- ../../spec/conformance
    # csharp: 302/302 vectors passed

From the repository root, `ports/conformance/run.sh csharp` runs the vectors and
`ports/conformance/interop.sh csharp` runs the interop agent against the Python coordinator: halt and
resume of the fleet and of one agent, suspension and reinstatement with a new key, a refused second
instance and the dead-man rule.

## Usage

Reference the library from a clone:

```xml
<ProjectReference Include="../sf-smartswitch/ports/csharp/SmartSwitch/SmartSwitch.csproj" />
```

```csharp
using SmartSwitch;

var fleet = Agent.LoadFleet("fleet.json");                    // validated fleet document
using var agent = new Agent("https://switch.example:8720",
    Environment.GetEnvironmentVariable("SMARTSWITCH_AGENT_TOKEN"), fleet, "planner-1");
agent.Start();                                                // heartbeat every PollMs (1 s)
while (agent.MayRun())
{
    DoOneStep();
    agent.Checkpoint();                                       // throws HaltedException once stopped
}
```

`Agent.Status()` returns the status code (`SW-RUN`, `SW-HALTED-FLEET`, `SW-OFFLINE`, ...). A halt
certificate received another way can be given to `Agent.Deliver`, which checks it at wall-clock time
(it is compared with the proposal's `expires_ms`); heartbeats and status use a monotonic clock. The rules without I/O are in
`AgentView`, which is what the vectors test.

The agent uses HttpClient, which accepts http:// and https:// URLs (the interop test uses http:// only).
It closes the connection after every request, so each heartbeat shows that the coordinator can be reached
at that moment. Nonces come from `RandomNumberGenerator`, the clock is a `Stopwatch` (monotonic).
