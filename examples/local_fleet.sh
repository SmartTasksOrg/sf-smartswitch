#!/usr/bin/env bash
# A fleet on this machine with the real command line: keys, fleet document, coordinator, one wrapped
# agent, a halt by two keyholders. Everything is written to a temporary folder that is removed at the
# end; the coordinator runs with --insecure-dev (no tokens, 127.0.0.1 only). Needs sf-smartswitch installed.
set -euo pipefail
work=$(mktemp -d)
cleanup() { kill "${coord:-0}" "${agent:-0}" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
cd "$work"
port=$((20000 + RANDOM % 20000))
url=http://127.0.0.1:$port

for n in alice bob carol coordinator; do sf-smartswitch keygen --name "$n" --out "$n.key" >/dev/null; done
sf-smartswitch fleet init --fleet-id local --keyholder alice=alice.key --keyholder bob=bob.key \
  --keyholder carol=carol.key --coordinator-key coordinator.key --agent worker --out fleet.json

sf-smartswitch serve --fleet fleet.json --key coordinator.key --log switch.jsonl --port "$port" --insecure-dev \
  >coordinator.out 2>&1 &
coord=$!
sleep 1

# the "agent": prints a line every half second until SmartSwitch stops it
sf-smartswitch agent --url "$url" --fleet fleet.json --agent-id worker --poll-ms 200 -- \
  python -c "import time
while True: print('worker: working', flush=True); time.sleep(0.5)" &
agent=$!
sleep 2

echo "alice proposes a halt; one vote is not enough:"
sf-smartswitch propose --url "$url" --key alice.key --action halt --target '*' --reason "example halt" | tail -2
hash=$(sf-smartswitch pending --url "$url" | python -c "import json,sys; print(json.load(sys.stdin)['pending'][0]['proposal_hash'])")
sleep 1
echo "bob signs:"
sf-smartswitch sign --url "$url" --key bob.key --hash "$hash" --yes | tail -1
set +e
wait "$agent"
rc=$?
set -e
echo "the wrapper stopped the worker and exited with $rc (75 = stopped by SmartSwitch)"
sf-smartswitch log verify switch.jsonl --fleet fleet.json | head -1
