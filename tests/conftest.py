import os
import threading
import time

import pytest

from sf_smartswitch import ed25519
from sf_smartswitch.coordinator import Coordinator
from sf_smartswitch.protocol import new_proposal, sign_vote
from sf_smartswitch.server import Config, make_server

NAMES = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi', 'ivan', 'judy']


class Keys:
    """Fresh keys for one test (never written to disk unless a test does so in tmp_path)."""

    def __init__(self):
        self.seed = {n: ed25519.new_seed() for n in NAMES + ['coordinator', 'mallory', 'new']}
        self.pub = {n: ed25519.public_key(s) for n, s in self.seed.items()}

    def fleet(self, n=3, roster=None, **over):
        d = {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': 'test-fleet',
             'keyholders': [{'id': x, 'public_key': self.pub[x]} for x in NAMES[:n]], 'threshold': None,
             'coordinator_key': self.pub['coordinator'], 'offline_timeout_ms': 30000, 'proposal_max_ttl_ms': 600000,
             'agents': roster}
        d.update(over)
        return d

    def vote(self, who, p):
        return sign_vote(self.seed[who], who, p)


@pytest.fixture
def keys():
    return Keys()


def now_ms():
    return int(time.time() * 1000)


def proposal(co, action='halt', target='*', reason='test', ttl=60000, new_key=None):
    return new_proposal(co.state, action, target, reason, now_ms(), ttl, new_key)


def decide(co, keys, action, target, who, **kw):
    p = proposal(co, action, target, **kw)
    r = None
    for w in who:
        r = co.submit_vote(p, keys.vote(w, p))
    return r


class Running:
    def __init__(self, co, cfg):
        self.co, self.cfg = co, cfg
        self.srv = make_server(co, cfg, '127.0.0.1', 0)
        self.url = f'http://127.0.0.1:{self.srv.server_address[1]}'
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def server(keys, tmp_path):
    made = []

    def start(fleet=None, **cfg):
        fleet = fleet or keys.fleet(roster=[{'id': 'a1', 'max_instances': 1}, {'id': 'a2', 'max_instances': 2}])
        co = Coordinator(fleet, keys.seed['coordinator'], str(tmp_path / f'log{len(made)}.jsonl'))
        c = Config(cfg.pop('agent_token', 'agent-token-' + os.urandom(4).hex()),
                   cfg.pop('operator_token', 'operator-token-' + os.urandom(4).hex()), **cfg)
        r = Running(co, c)
        made.append(r)
        return r
    yield start
    for r in made:
        try:
            r.stop()
        except Exception:
            pass


def wait_for(cond, timeout_s=5.0):
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()
