"""``sf-smartswitch --demo``: a whole fleet on this machine, in about ten seconds, writing no files.

Three keyholders (alice, bob, carol), a coordinator on 127.0.0.1 (random port, random tokens) and
two agents polling it every 100 ms. Keys are made fresh for this run and thrown away.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time

from . import ed25519
from .agent import Agent
from .coordinator import Coordinator
from .log import LogFile, replay
from .protocol import SwitchError, make_certificate, new_proposal, sign_vote
from .server import Config, make_server


def _wait(cond, timeout_s=5.0):
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def run() -> int:
    import logging
    logging.getLogger('sf_smartswitch').setLevel(logging.CRITICAL)   # the demo prints what matters
    seeds = {n: ed25519.new_seed() for n in ('alice', 'bob', 'carol', 'coordinator')}
    pub = {n: ed25519.public_key(s) for n, s in seeds.items()}
    fleet = {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': 'demo-fleet',
             'keyholders': [{'id': n, 'public_key': pub[n]} for n in ('alice', 'bob', 'carol')], 'threshold': None,
             'coordinator_key': pub['coordinator'], 'offline_timeout_ms': 1500, 'proposal_max_ttl_ms': 600000,
             'agents': [{'id': 'planner', 'max_instances': 1}, {'id': 'worker', 'max_instances': 1}]}
    tmp = tempfile.TemporaryDirectory(prefix='smartswitch-demo-')
    log_path = os.path.join(tmp.name, 'switch.jsonl')
    co = Coordinator(fleet, seeds['coordinator'], log_path)
    agent_token, op_token = os.urandom(16).hex(), os.urandom(16).hex()
    srv = make_server(co, Config(agent_token, op_token), '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    print(f'SmartSwitch demo: fleet "demo-fleet", keyholders alice, bob, carol (quorum {co.state.threshold} of 3),')
    print(f'coordinator on {url}, agents "planner" and "worker" polling every 100 ms.\n')

    agents = [Agent(url, agent_token, fleet, a, poll_ms=100, timeout_s=1).start() for a in ('planner', 'worker')]
    ok = True

    def show(step, cond, text):
        nonlocal ok
        good = _wait(cond)
        ok = ok and good
        print(f'{"ok " if good else "FAIL"} {step:2d}. {text}')
        if not good:
            for ag in agents:
                print('       ', ag.agent_id, ag.status())

    def vote(action, target, who, reason):
        p = new_proposal(co.state, action, target, reason, int(time.time() * 1000), 60000)
        r = None
        for k in who:
            r = co.submit_vote(p, sign_vote(seeds[k], k, p))
        return r

    try:
        show(1, lambda: all(a.may_run() for a in agents), 'both agents run (each verified a heartbeat signed by the coordinator)')
        r = vote('halt', '*', ['carol'], 'carol alone, perhaps coerced')
        time.sleep(0.4)
        show(2, lambda: r['status'] == 'pending' and all(a.may_run() for a in agents),
             'carol alone asks for a halt: 1 of 2 votes, nothing stops')
        p = new_proposal(co.state, 'halt', '*', 'forged', int(time.time() * 1000), 60000)
        v = sign_vote(seeds['carol'], 'carol', p)
        try:
            co.submit_certificate(make_certificate(p, [v, v]))
            refused = False
        except SwitchError as e:
            refused = e.code == 'SW-DUPLICATE-VOTE'
        show(3, lambda: refused, 'a certificate with carol\'s vote twice is refused (SW-DUPLICATE-VOTE)')
        vote('halt', '*', ['alice', 'bob'], 'drill: halt everything')
        show(4, lambda: all(a.status()['code'] == 'SW-HALTED-FLEET' for a in agents),
             'alice and bob halt the fleet: both agents stop')
        vote('resume', '*', ['bob', 'carol'], 'drill over')
        show(5, lambda: all(a.may_run() for a in agents), 'bob and carol resume: both agents run again')
        vote('halt', 'worker', ['alice', 'carol'], 'worker misbehaves')
        show(6, lambda: agents[1].status()['code'] == 'SW-HALTED-AGENT' and agents[0].may_run(),
             'alice and carol halt only "worker"; "planner" keeps running')
        rogue = Agent(url, agent_token, fleet, 'planner', poll_ms=100, timeout_s=1).start()
        time.sleep(0.5)
        show(7, lambda: not rogue.may_run() and co.metrics.replication.value(reason='too-many-instances') >= 1,
             'a second "planner" instance appears: refused, replication alert logged, it does not run')
        rogue.stop()
        srv.shutdown()
        srv.server_close()
        show(8, lambda: agents[0].status()['code'] == 'SW-OFFLINE',
             'the coordinator goes away: "planner" stops by itself after 1.5 s without a heartbeat')
        r = replay(LogFile.read(log_path), co.fleet_hash)
        show(9, lambda: r['ok'], f'the log verifies from the fleet document: {r.get("size")} entries, '
                                 f'head {r.get("head", "")[:16]}...')
    finally:
        for a in agents:
            a.stop()
        tmp.cleanup()
    print('\nDemo ' + ('passed.' if ok else 'FAILED.'))
    return 0 if ok else 1
