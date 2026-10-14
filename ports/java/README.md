# SmartSwitch for Java (agent side)

This is the Java port of the SmartSwitch agent. It implements the agent side of `spec/SEMANTICS.md`:

- canonical JSON and SHA-256
- strict Ed25519 verification (its own checks for lower-case hex, lengths and S < L, then the JDK's `Ed25519`)
- fleet validation
- certificate checks and apply
- log replay
- the agent view (log, heartbeat, certificate, status)
- a networked agent that polls the coordinator

Signing (keyholders) and the coordinator stay in Python.

It uses only the JDK and has no dependencies. It needs JDK 17 or newer and is tested here with JDK 21.

It is not published to Maven Central or any other repository. Use it from a clone of this repository.

## Build and conformance

From the repository root:

```sh
ports/java/build.sh
java -cp ports/java/build/classes cloud.smarttasks.smartswitch.Conformance spec/conformance
# last line: java: 302/302 vectors passed
```

`build.sh` runs `javac -Xlint:all,-serial -Werror --release 17` into `ports/java/build/classes`. A `pom.xml`
without dependencies is included for Maven users (`mvn -q compile`), but this repository's checks do not use it.

Interop against the real Python coordinator (needs Python and the reference's dependencies):

```sh
ports/conformance/run.sh java        # the vectors
ports/conformance/interop.sh java    # the agent against the coordinator over HTTP
```

## Using the agent

```java
import cloud.smarttasks.smartswitch.Agent;
import java.nio.file.Path;
import java.time.Duration;

Agent agent = new Agent("http://127.0.0.1:8720", System.getenv("SMARTSWITCH_AGENT_TOKEN"),
        Agent.loadFleet(Path.of("fleet.json")), "planner-1", "instance-1", 1000, Duration.ofSeconds(2)).start();
try {
    while (agent.mayRun()) {
        doOneStep();
        agent.checkpoint();          // throws Agent.Halted with the SW-* code when the agent may not run
    }
} finally {
    agent.stop();
}
```

- `start()` polls in a daemon thread every `pollMs`. Each poll is a `GET /v1/heartbeat` with a fresh random
  nonce. When the agent is behind, it fetches `/v1/log` and verifies it.
- `status()` returns `{run, code}`.
- `deliver(certificate)` accepts a halt certificate that reached the agent some other way. It is checked
  against the wall clock (`System.currentTimeMillis()`), because it is compared with `expires_ms`. Heartbeats
  and status use the monotonic clock.
- `onChange(consumer)` is called whenever the status changes.
- Any error in a poll changes nothing, and the background loop catches every `Throwable`. Without a valid
  heartbeat for the fleet's `offline_timeout_ms`, the status becomes `SW-OFFLINE`.
- The JSON parser accepts at most 64 levels of nesting; deeper input is a parse error. Answers longer than
  32 MiB are refused.
- Each request opens a new HTTP connection.

The classes are:

- `Json`: the parser and the canonical writer.
- `SmartSwitch`: the protocol, `Replica` and `replay`.
- `AgentView`: the agent rules, with no I/O.
- `Client` and `Agent`: the network side.
- `Conformance` and `Interop`: the test programs.
