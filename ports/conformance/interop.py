#!/usr/bin/env python3
"""Interop test: one port's agent against the Python coordinator, over HTTP.

    python3 ports/conformance/interop.py -- <command that starts the port's interop agent>

The port's program is started as  <command> URL FLEET_FILE AGENT_ID INSTANCE_ID  with the agent token in
SMARTSWITCH_AGENT_TOKEN. It must poll every 100 ms and print "STATUS <code>" (flushed) whenever its
status code changes, starting with the first one. It exits when its standard input closes.

The test (all with fresh test keys made here, a 2 s offline timeout, roster a1 with one instance):
  the agent runs -> fleet halted and resumed -> the agent halted and resumed -> carol suspended and
  reinstated with a new key, then a halt signed with her new key -> resumed -> a second instance of a1
  is refused and never runs -> the coordinator stops and the agent goes offline by itself.
Exit 0 when every step is seen in time.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartswitch import ed25519  # noqa: E402
from sf_smartswitch.coordinator import Coordinator  # noqa: E402
from sf_smartswitch.protocol import new_proposal, sign_vote  # noqa: E402
from sf_smartswitch.server import Config, make_server  # noqa: E402


class Port:
    def __init__(self, cmd, url, fleet_path, agent, inst, token):
        env = dict(os.environ, SMARTSWITCH_AGENT_TOKEN=token)
        self.p = subprocess.Popen(cmd + [url, fleet_path, agent, inst], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, text=True)
        self.q: queue.Queue = queue.Queue()
        self.seen: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._err, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = line.strip()
            if line.startswith('STATUS '):
                self.q.put(line[7:])

    def _err(self):
        for line in self.p.stderr:
            sys.stderr.write('  [port] ' + line)

    def expect(self, code, timeout_s):
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            try:
                c = self.q.get(timeout=max(0.01, end - time.monotonic()))
            except queue.Empty:
                break
            self.seen.append(c)
            if c == code:
                return True
        raise SystemExit(f'FAIL: expected {code} within {timeout_s} s; saw {self.seen[-8:]}')

    def never(self, code, for_s):
        end = time.monotonic() + for_s
        while time.monotonic() < end:
            try:
                c = self.q.get(timeout=max(0.01, end - time.monotonic()))
            except queue.Empty:
                break
            self.seen.append(c)
            if c == code:
                raise SystemExit(f'FAIL: {code} must not happen; saw {self.seen[-8:]}')

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def main():
    if '--' not in sys.argv:
        raise SystemExit(__doc__)
    cmd = sys.argv[sys.argv.index('--') + 1:]
    seeds = {n: os.urandom(32) for n in ('alice', 'bob', 'carol', 'carol2', 'coordinator')}
    pub = {n: ed25519.public_key(s) for n, s in seeds.items()}
    fleet = {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': 'interop',
             'keyholders': [{'id': n, 'public_key': pub[n]} for n in ('alice', 'bob', 'carol')], 'threshold': None,
             'coordinator_key': pub['coordinator'], 'offline_timeout_ms': 2000, 'proposal_max_ttl_ms': 600000,
             'agents': [{'id': 'a1', 'max_instances': 1}]}
    tmp = tempfile.mkdtemp(prefix='smartswitch-interop-')
    fleet_path = os.path.join(tmp, 'fleet.json')
    with open(fleet_path, 'w', encoding='utf-8') as f:
        json.dump(fleet, f)
    co = Coordinator(fleet, seeds['coordinator'], os.path.join(tmp, 'log.jsonl'))
    agent_token, op_token = os.urandom(16).hex(), os.urandom(16).hex()
    srv = make_server(co, Config(agent_token, op_token), '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_address[1]}'

    def act(action, target, signers, new_key=None, seeds_=None):
        sd = seeds_ or seeds
        p = new_proposal(co.state, action, target, 'interop', int(time.time() * 1000), 60000, new_key)
        r = None
        for s in signers:
            r = co.submit_vote(p, sign_vote(sd[s], s, p))
        assert r['status'] == 'applied', r

    t0 = time.monotonic()
    a = Port(cmd, url, fleet_path, 'a1', 'i1', agent_token)
    try:
        a.expect('SW-RUN', 20)                     # first start may compile
        print('ok  the agent runs')
        act('halt', '*', ['alice', 'bob'])
        a.expect('SW-HALTED-FLEET', 3)
        act('resume', '*', ['bob', 'carol'])
        a.expect('SW-RUN', 3)
        print('ok  fleet halt and resume')
        act('halt', 'a1', ['alice', 'carol'])
        a.expect('SW-HALTED-AGENT', 3)
        act('resume', 'a1', ['alice', 'bob'])
        a.expect('SW-RUN', 3)
        print('ok  agent halt and resume')
        act('suspend', 'carol', ['alice', 'bob'])
        act('reinstate', 'carol', ['alice', 'bob'], new_key=pub['carol2'])
        act('halt', '*', ['alice', 'carol'], seeds_=dict(seeds, carol=seeds['carol2']))
        a.expect('SW-HALTED-FLEET', 3)
        act('resume', '*', ['alice', 'bob'])
        a.expect('SW-RUN', 3)
        print('ok  suspension, reinstatement with a new key, halt signed with it')
        b = Port(cmd, url, fleet_path, 'a1', 'i2', agent_token)
        try:
            b.never('SW-RUN', 3)
        finally:
            b.close()
        print('ok  a second instance of a1 is refused and does not run')
        srv.shutdown()
        srv.server_close()
        a.expect('SW-OFFLINE', 6)
        print('ok  coordinator gone: the agent stops by itself')
    finally:
        a.close()
    print(f'interop passed in {time.monotonic() - t0:.1f} s')


if __name__ == '__main__':
    main()
