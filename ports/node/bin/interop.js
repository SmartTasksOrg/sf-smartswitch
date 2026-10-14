#!/usr/bin/env node
'use strict';
// Interop agent for ports/conformance/interop.py: URL FLEET_FILE AGENT_ID INSTANCE_ID, token from
// SMARTSWITCH_AGENT_TOKEN. Polls every 100 ms and prints "STATUS <code>" whenever the status code
// changes; exits when standard input closes or after 60 s.
const { Agent } = require('../src');

const [url, fleet, agentId, instanceId] = process.argv.slice(2);
if (!instanceId) {
  process.stderr.write('usage: interop.js URL FLEET_FILE AGENT_ID INSTANCE_ID\n');
  process.exit(2);
}
const agent = new Agent({ url, token: process.env.SMARTSWITCH_AGENT_TOKEN || null, fleet, agentId, instanceId, pollMs: 100, timeoutMs: 1000 });

let done = false;
process.stdin.on('end', () => { done = true; });
process.stdin.on('close', () => { done = true; });
process.stdin.on('error', () => { done = true; });
process.stdin.resume();
const end = Date.now() + 60000;

let last = null;
const print = (line) => new Promise((resolve) => { if (!process.stdout.write(line)) process.stdout.once('drain', resolve); else resolve(); });

(async () => {
  while (!done && Date.now() < end) {
    const s = await agent.pollOnce();
    if (s.code !== last) {
      last = s.code;
      await print('STATUS ' + s.code + '\n');
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  process.exit(0);
})();
