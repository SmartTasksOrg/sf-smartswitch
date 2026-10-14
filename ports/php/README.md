# SmartSwitch for PHP (agent side)

This is the PHP port of the SmartSwitch agent. It implements the agent side of `spec/SEMANTICS.md`:

- canonical JSON and SHA-256
- strict Ed25519 verification (its own checks for lower-case hex, lengths and S < L, then libsodium's
  `sodium_crypto_sign_verify_detached`)
- fleet validation
- certificate checks and apply
- log replay
- the agent view
- a networked agent

Signing (keyholders) and the coordinator stay in Python.

It needs PHP 8.1 or newer with `ext-sodium` and `ext-json`. It is tested here with PHP 8.3. It uses no Composer
packages. HTTP goes through PHP's built-in `http` stream wrapper, so curl is not needed.

It is not published on Packagist. Use it from a clone of this repository: `require 'ports/php/src/SmartSwitch.php';`.
You can also add the clone as a Composer `path` repository (`smarttasksorg/sf-smartswitch`).

## Conformance and interop

From the repository root:

```sh
php ports/php/bin/conformance.php spec/conformance   # last line: php: 302/302 vectors passed
ports/conformance/run.sh php                         # the same, through the shared harness
ports/conformance/interop.sh php                     # the agent against the Python coordinator over HTTP
```

## Using the agent

```php
require 'ports/php/src/SmartSwitch.php';

use SmartTasks\SmartSwitch\{Agent, Halted};
use function SmartTasks\SmartSwitch\load_fleet;

$agent = new Agent('http://127.0.0.1:8720', getenv('SMARTSWITCH_AGENT_TOKEN') ?: null, load_fleet('fleet.json'),
    'planner-1', 'instance-1', pollMs: 1000, timeout: 2.0);
try {
    while ($agent->mayRun()) {      // polls the coordinator first when a poll is due
        do_one_step();
        $agent->checkpoint();       // throws Halted ($e->swCode) when the agent may not run
    }
} catch (Halted $e) {
    // stop working: $e->swCode says why
}
```

- PHP has no background thread here. `mayRun()`, `checkpoint()` and `tick()` call `pollOnce()` when
  `pollMs` has passed since the last poll. You can also call `pollOnce()` yourself.
- Each poll is a `GET /v1/heartbeat` with a fresh 16-byte nonce from `random_bytes`. When the agent is behind,
  it fetches `/v1/log` and verifies it.
- `status()` returns `['run' => bool, 'code' => 'SW-...']` without network access.
- `deliver($certificate)` accepts a halt certificate that reached the agent some other way. It is checked
  against the wall clock (`microtime`), because it is compared with `expires_ms`. Heartbeats and status use the
  monotonic clock (`hrtime`).
- Any error in a poll (`\Throwable`) changes nothing. Without a valid heartbeat for the fleet's
  `offline_timeout_ms`, the status becomes `SW-OFFLINE`. Answers longer than 32 MiB are refused.

Documents are decoded with `SmartTasks\SmartSwitch\decode()`. JSON objects become `\stdClass`, so `{}` and
`[]` stay distinct for the canonical encoding. Results are PHP arrays. A `SwitchError` carries its code in
`$swCode`, because `Exception::$code` is an integer in PHP.
