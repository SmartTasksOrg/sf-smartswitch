"""Run the shared vectors (spec/conformance/*.json) against this implementation.

    sf-smartswitch vectors [DIR]       # DIR defaults to the copy shipped in the wheel

Every port has a runner that does the same thing; spec/PORTING.md describes the file formats.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import canonical, ed25519
from .agentview import AgentView
from .log import replay
from .protocol import State, SwitchError, apply, default_threshold, doc_hash, proposal_hash, validate_fleet, \
    verify_certificate

FILES = ('canonical.json', 'ed25519.json', 'fleets.json', 'certificates.json', 'logs.json', 'agent.json')


def _load(d, name):
    with open(os.path.join(d, name), encoding='utf-8') as f:
        return json.load(f)


def run_dir(d: str):
    """(number of vectors, list of failure messages)."""
    total, fails = 0, []

    def check(name, got, want):
        nonlocal total
        total += 1
        if got != want:
            fails.append(f'{name}: got {json.dumps(got, sort_keys=True)[:300]}, want {json.dumps(want, sort_keys=True)[:300]}')

    v = _load(d, 'canonical.json')
    for c in v['cases']:
        text = canonical.dumps(c['input'])
        check('canonical/' + c['name'], [text, hashlib.sha256(text.encode()).hexdigest()], [c['canonical'], c['sha256']])

    v = _load(d, 'ed25519.json')
    for c in v['cases']:
        check('ed25519/' + c['name'], ed25519.verify(c['public_key'], bytes.fromhex(c['message_hex']), c['sig']), c['valid'])

    v = _load(d, 'fleets.json')
    for c in v['default_thresholds']:
        check(f'fleets/default threshold n={c["n"]}', default_threshold(c['n']), c['k'])
    for c in v['cases']:
        try:
            validate_fleet(c['fleet'])
            got = {'ok': True, 'fleet_hash': doc_hash(c['fleet']), 'threshold': State.genesis(c['fleet']).threshold}
        except SwitchError as e:
            got = {'ok': False, 'code': e.code}
        want = {k: c[k] for k in ('ok', 'fleet_hash', 'threshold', 'code') if k in c}
        check('fleets/' + c['name'], got, want)

    v = _load(d, 'certificates.json')
    for c in v['cases']:
        st = State.genesis(v['fleets'][c['fleet']])
        for s in c['setup']:
            st = apply(st, s['certificate'], s['at_ms'])
        try:
            ph = proposal_hash(c['certificate']['proposal'])
        except (KeyError, TypeError):
            ph = None
        check('certificates/' + c['name'] + ' (proposal hash)', ph, c['proposal_hash'])
        try:
            if c['ahead']:
                verify_certificate(st, c['certificate'], c['at_ms'], ahead=True)
                got = {'ok': True, 'state': None}
            else:
                got = {'ok': True, 'state': apply(st, c['certificate'], c['at_ms']).summary()}
        except SwitchError as e:
            got = {'ok': False, 'code': e.code}
        want = {k: c[k] for k in ('ok', 'state', 'code') if k in c}
        check('certificates/' + c['name'], got, want)

    v = _load(d, 'logs.json')
    for c in v['cases']:
        check('logs/' + c['name'], replay(c['entries'], c['pinned']), c['result'])

    v = _load(d, 'agent.json')
    for c in v['cases']:
        view = AgentView(v['fleet'], c['agent_id'], c['instance_id'])
        for i, s in enumerate(c['steps']):
            op = s['op']
            if op == 'log':
                got = view.log(s['entries'])
            elif op == 'heartbeat':
                got = view.heartbeat(s['heartbeat'], s['nonce'], s['at_ms'])
            elif op == 'certificate':
                got = view.certificate(s['certificate'], s['at_ms'])
            else:
                got = view.status(s['at_ms'])
            check(f'agent/{c["name"]} step {i} ({op})', got, s['expect'])
    return total, fails
