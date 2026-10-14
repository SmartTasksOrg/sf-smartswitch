# Integration

Three ways to put an agent under the switch, from the strongest to the most flexible.

## 1. The process wrapper (any language, no code change)

```bash
sf-smartswitch agent --url https://switch.internal --fleet fleet.json --agent-id worker \
    [--instance-id worker-7] [--cert-dir /etc/smartswitch/certs] [--poll-ms 1000] [--grace-s 5] \
    -- <program and its arguments>
```

The program starts only once the agent may run. It runs in its own process group. The whole group is
terminated, then killed after the grace period, as soon as the agent may not run: when it is halted,
offline or forked, or when a halt arrives in `--cert-dir`. The same happens when the wrapper is sent
SIGTERM or SIGINT. On Linux the program is also killed if the wrapper itself is killed. The wrapper
exits with the program's code, or 75 when SmartSwitch stopped it. A program that leaves its process
group on purpose (a double fork, `setsid`) escapes this, so run agents in a container whose lifetime is
the wrapper's.

**Containers:** make the wrapper the entrypoint, so that the container stops with the agent:

```dockerfile
ENTRYPOINT ["sf-smartswitch", "agent", "--url", "https://switch.internal", "--fleet", "/etc/smartswitch/fleet.json", \
            "--agent-id", "worker", "--"]
CMD ["./worker"]
```

Pass `SMARTSWITCH_AGENT_TOKEN` as a secret. Use the pod or container name as `--instance-id` if you want
readable instance ids. In Kubernetes, set `restartPolicy` and the controller's back-off so that a halted
agent is not restarted in a tight loop. A restart waits for a heartbeat and does not start while the
fleet is halted.

## 2. Inside a Python program

```python
from sf_smartswitch import Agent, Halted

agent = Agent("https://switch.internal", token, "fleet.json", "planner",
              cert_dir="/etc/smartswitch/certs", on_change=lambda s: print("switch:", s["code"])).start()
try:
    while True:
        agent.checkpoint()          # raises Halted between steps
        step()
except Halted as e:
    shut_down_cleanly(e.code)
finally:
    agent.stop()
```

`agent.may_run()` returns a boolean and `agent.status()` returns `{"run", "code"}`.
`agent.deliver(certificate_dict)` hands it a certificate received some other way.

Code between checkpoints runs to its end. Use the wrapper where a step can do damage on its own.

## 3. The ports

`ports/<language>` has the same agent in Node.js, Go, Rust, Java, C#, PHP and Ruby. Each port's
README has a usage example. They all pass the same vectors and the same interop test against the
Python coordinator. None is on a package registry: vendor the folder from a tagged clone.

## Talking to the coordinator yourself

A ROS node, a Kubernetes controller or anything else can use the HTTP API ([spec/openapi.yaml](../spec/openapi.yaml)).
An agent loop needs three calls:

1. `GET /v1/fleet` once, and compare its hash with the one you were deployed with. Better still, ship
   `fleet.json` with the agent.
2. `GET /v1/heartbeat?agent_id=…&instance_id=…&nonce=<32 random hex>` every poll.
3. `GET /v1/log?from=<entries you have>` when the heartbeat's `log_size` is larger.

Then apply the rules in [spec/SEMANTICS.md](../spec/SEMANTICS.md), "Agent". Do not shortcut them by
trusting `GET /v1/state`. That call is for people; agents verify.

## Alerts into other systems

Set `SMARTSWITCH_ALERT_WEBHOOK` to a URL that accepts a JSON POST. Each alert sends
`{"text": "...", "alert": "<kind>", ...fields}`. A Slack incoming webhook displays `text` as is. The
kinds are:
- `aggregation-slow` and `aggregation-spike`;
- `replication-alert`;
- `log-mirror-mismatch`.
