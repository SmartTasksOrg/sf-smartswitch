"""``sf-smartswitch bench``: time the parts of a halt on this machine.

- sign_ms / verify_ms: one Ed25519 vote (the keyholder side) and its check;
- certificate_verify_ms: checking a whole certificate (k signatures) as an agent does;
- agent_status_ms: one AgentView.status() call (what an agent does before each step);
- aggregation_ms: the coordinator's time from the quorum-completing vote to the certificate written
  (fsynced) to a log file in a temporary folder, through the HTTP API on 127.0.0.1, for n keyholders.
Percentiles are of ``rounds`` runs. The council's targets: under 5 ms per agent on an edge device,
aggregation within 200 ms. Numbers from one machine say nothing about another: run it on yours.
"""
from __future__ import annotations

import os
import platform
import statistics
import tempfile
import threading
import time

from . import __version__, ed25519
from .agentview import AgentView, sign_heartbeat
from .client import Client
from .coordinator import Coordinator
from .protocol import State, make_certificate, new_proposal, sign_vote, verify_certificate
from .server import Config, make_server


def _pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))], 4)


def _summary(xs):
    return {'p50': _pct(xs, 50), 'p95': _pct(xs, 95), 'p99': _pct(xs, 99), 'max': round(max(xs), 4),
            'mean': round(statistics.fmean(xs), 4), 'n': len(xs)}


def _timed(fn, rounds):
    out = []
    for _ in range(rounds):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


def _fleet(n, seeds):
    return {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': f'bench-{n}',
            'keyholders': [{'id': f'k{i}', 'public_key': ed25519.public_key(seeds[f'k{i}'])} for i in range(n)],
            'threshold': None, 'coordinator_key': ed25519.public_key(seeds['co']), 'offline_timeout_ms': 30000,
            'proposal_max_ttl_ms': 600000, 'agents': None}


def run(keyholders=(3, 5, 7, 10), rounds=200) -> dict:
    res = {'tool': f'sf-smartswitch {__version__}', 'python': platform.python_version(),
           'machine': platform.machine(), 'system': platform.system(), 'rounds': rounds}
    seed = ed25519.new_seed()
    pub = ed25519.public_key(seed)
    msg = b'smartswitch-vote-v1:' + b'0' * 64
    sig = ed25519.sign(seed, msg)
    res['sign_ms'] = _summary(_timed(lambda: ed25519.sign(seed, msg), rounds))
    res['verify_ms'] = _summary(_timed(lambda: ed25519.verify(pub, msg, sig), rounds))
    res['by_keyholders'] = {}
    for n in keyholders:
        seeds = {f'k{i}': ed25519.new_seed() for i in range(n)}
        seeds['co'] = ed25519.new_seed()
        fleet = _fleet(n, seeds)
        st = State.genesis(fleet)
        k = st.threshold
        p = new_proposal(st, 'halt', '*', 'bench', int(time.time() * 1000), 600000)
        cert = make_certificate(p, [sign_vote(seeds[f'k{i}'], f'k{i}', p) for i in range(k)])
        now = int(time.time() * 1000)
        cv = _timed(lambda: verify_certificate(st, cert, now), rounds)
        view = AgentView(fleet, 'a1', 'i1')
        from .log import make_entry
        view.log([make_entry(0, 0, 'genesis', fleet, '0' * 64)])
        nonce = '0' * 32
        view.heartbeat(sign_heartbeat(seeds['co'], view.fleet_hash, 'a1', 'i1', nonce, 1, view.replica.head, 0), nonce, 0)
        sv = _timed(lambda: view.status(1), rounds)
        agg = _aggregation(fleet, seeds, k, max(20, rounds // 5))
        res['by_keyholders'][str(n)] = {'threshold': k, 'certificate_verify_ms': _summary(cv),
                                        'agent_status_ms': _summary(sv), 'aggregation_ms': _summary(agg)}
    return res


def _aggregation(fleet, seeds, k, rounds):
    with tempfile.TemporaryDirectory(prefix='smartswitch-bench-') as tmp:
        co = Coordinator(fleet, seeds['co'], os.path.join(tmp, 'log.jsonl'))
        tok = os.urandom(16).hex()
        srv = make_server(co, Config(os.urandom(16).hex(), tok, operator_rate=10 ** 9), '127.0.0.1', 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        c = Client(f'http://127.0.0.1:{srv.server_address[1]}', tok)
        out = []
        try:
            for i in range(rounds):
                action = 'halt' if i % 2 == 0 else 'resume'
                p = new_proposal(co.state, action, '*', 'bench', int(time.time() * 1000), 600000)
                for j in range(k):
                    c.vote(p, sign_vote(seeds[f'k{j}'], f'k{j}', p))
            out = list(co.metrics.aggregation._obs)
        finally:
            srv.shutdown()
            srv.server_close()
        return out
