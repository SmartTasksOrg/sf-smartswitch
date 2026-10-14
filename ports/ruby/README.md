# SmartSwitch for Ruby (agent side)

This is the Ruby port of the SmartSwitch agent. It implements the agent side of `spec/SEMANTICS.md`:

- canonical JSON and SHA-256
- strict Ed25519 verification (its own checks for lower-case hex, lengths and S < L, then OpenSSL through
  `OpenSSL::PKey`)
- fleet validation
- certificate checks and apply
- log replay
- the agent view
- a networked agent

Signing (keyholders) and the coordinator stay in Python.

It needs Ruby 3.2 or newer with an OpenSSL that supports Ed25519. It is tested here with Ruby 3.3
and OpenSSL 3.0. It uses only the standard library and default gems: `json`, `openssl`, `digest`, `net/http`,
`securerandom`, `set` and `monitor`.

It is not published on RubyGems. The gemspec's `allowed_push_host` blocks `gem push`. Use it from a clone with
`ruby -Iports/ruby/lib` or `require_relative`.

## Conformance and interop

From the repository root:

```sh
ruby ports/ruby/bin/conformance.rb spec/conformance   # last line: ruby: 302/302 vectors passed
ports/conformance/run.sh ruby                         # the same, through the shared harness
ports/conformance/interop.sh ruby                     # the agent against the Python coordinator over HTTP
```

## Using the agent

```ruby
require 'smartswitch'   # with -Iports/ruby/lib

agent = SmartSwitch::Agent.new('http://127.0.0.1:8720', ENV['SMARTSWITCH_AGENT_TOKEN'],
                               SmartSwitch.load_fleet('fleet.json'), 'planner-1', 'instance-1',
                               poll_ms: 1000, timeout: 2.0) { |s| warn "status: #{s['code']}" }
agent.start
begin
  while agent.may_run?
    do_one_step
    agent.checkpoint # raises SmartSwitch::Halted (e.code) when the agent may not run
  end
ensure
  agent.stop
end
```

- `start` polls in a background thread every `poll_ms`. You can also call `poll_once` yourself.
- Each poll is a `GET /v1/heartbeat` with a fresh nonce from `SecureRandom.hex(16)`. When the agent is behind,
  it fetches `/v1/log` and verifies it.
- `status` returns `{'run' => bool, 'code' => 'SW-...'}`.
- `deliver(certificate)` accepts a halt certificate that reached the agent some other way. It is checked
  against the wall clock (`CLOCK_REALTIME`), because it is compared with `expires_ms`. Heartbeats and status
  use the monotonic clock.
- The optional block is called whenever the status changes.
- Any error in a poll changes nothing, and the background loop rescues every exception. Without a valid
  heartbeat for the fleet's `offline_timeout_ms`, the status becomes `SW-OFFLINE`. Answers longer than 32 MiB
  are refused.
- Each request opens a new HTTP connection.
