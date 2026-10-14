#!/usr/bin/env python3
"""Generate spec/conformance/*.json from the Python reference.

    python spec/tools/make_vectors.py            # write the files
    python spec/tools/make_vectors.py --check    # exit 1 if the files differ from what would be written

The keys below are TEST KEYS: their private seeds are SHA-256 of public labels, so anyone can sign
with them. They exist only to make these vectors reproducible. Never put them in a real fleet.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartswitch import canonical, ed25519  # noqa: E402
from sf_smartswitch.agentview import AgentView, sign_heartbeat  # noqa: E402
from sf_smartswitch.log import make_entry, replay  # noqa: E402
from sf_smartswitch.protocol import (State, SwitchError, apply, default_threshold, doc_hash, make_certificate,  # noqa: E402
                                     proposal_hash, sign_vote, validate_fleet, verify_certificate)

OUT = os.path.join(ROOT, 'spec', 'conformance')
T0 = 1_700_000_000_000
TTL = 600_000


def seed(label: str) -> bytes:
    return hashlib.sha256(('smartswitch test key, public, never use: ' + label).encode()).digest()


NAMES = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace']
SEED = {n: seed(n) for n in NAMES + ['mallory', 'coordinator', 'carol-2', 'other-coordinator']}
PUB = {n: ed25519.public_key(s) for n, s in SEED.items()}


def fleet(n=3, roster=True, **over):
    d = {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': 'fleet-test',
         'keyholders': [{'id': x, 'public_key': PUB[x]} for x in NAMES[:n]], 'threshold': None,
         'coordinator_key': PUB['coordinator'], 'offline_timeout_ms': 30000, 'proposal_max_ttl_ms': TTL,
         'agents': [{'id': 'a1', 'max_instances': 1}, {'id': 'a2', 'max_instances': 2}] if roster else None}
    d.update(over)
    return d


def prop(st: State, action='halt', target='*', reason='test', seq=None, epoch=None, created=T0, ttl=TTL,
         new_key=None, **over):
    p = {'type': 'smartswitch.proposal', 'fleet_id': st.fleet_id, 'fleet_hash': st.fleet_hash,
         'seq': st.seq + 1 if seq is None else seq, 'epoch': st.epoch if epoch is None else epoch, 'action': action,
         'target': target, 'new_public_key': new_key, 'reason': reason, 'created_ms': created, 'expires_ms': created + ttl}
    p.update(over)
    return p


def cert(p, signers, seeds=None):
    seeds = seeds or SEED
    return make_certificate(p, [sign_vote(seeds[s], s.split('#')[0], p) for s in signers])


def write(name, obj):
    text = json.dumps(obj, indent=1, ensure_ascii=True, sort_keys=False) + '\n'
    path = os.path.join(OUT, name)
    if CHECK:
        try:
            cur = open(path, encoding='utf-8').read()
        except OSError:
            cur = None
        if cur != text:
            print(f'{name}: differs from the generator')
            DIFF.append(name)
        return
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


# ---------------------------------------------------------------- canonical
def canonical_vectors():
    inputs = [
        ('empty object', {}), ('empty array', []), ('null', None), ('true', True), ('false', False),
        ('zero', 0), ('negative', -42), ('max safe integer', 2 ** 53 - 1),
        ('sorted keys', {'b': 1, 'a': 2, 'B': 3, '_': 4, 'a1': 5, 'a0': 6}),
        ('nested', {'z': [1, {'y': None, 'x': [True, False]}], 'a': {'c': 'd'}}),
        ('escapes', 'quote " backslash \\ slash / bs \b ff \f nl \n cr \r tab \t'),
        ('control characters', '\x00\x01\x1f\x7f'),
        ('non-ASCII as is', 'ü 漢字 🙂    '),
        ('empty string', ''),
        ('a proposal', prop(State.genesis(fleet()), reason='line\none ü 🙂')),
    ]
    cases = []
    for name, v in inputs:
        text = canonical.dumps(v)
        cases.append({'name': name, 'input': v, 'canonical': text,
                      'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()})
    return {'description': 'canonical(input) must equal "canonical" byte for byte (UTF-8); sha256 is of those bytes',
            'cases': cases}


# ---------------------------------------------------------------- ed25519
RFC = [('rfc8032 test 1', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', '',
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
       ('rfc8032 test 2', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '72',
        '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
       ('rfc8032 test 3', 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'af82',
        'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025')]


def flip(hexstr, byte, bit=0):
    b = bytearray(bytes.fromhex(hexstr))
    b[byte] ^= 1 << bit
    return b.hex()


def ed_vectors():
    cases = []
    sigs = {}
    for name, sk, msg, pk in RFC:
        s = bytes.fromhex(sk)
        assert ed25519.public_key(s) == pk, name
        sig = ed25519.sign(s, bytes.fromhex(msg))
        sigs[name] = (pk, msg, sig)
        cases.append({'name': name, 'public_key': pk, 'message_hex': msg, 'sig': sig, 'valid': True})
    pk, msg, sig = sigs['rfc8032 test 2']
    pk3 = sigs['rfc8032 test 3'][0]
    s_int = int.from_bytes(bytes.fromhex(sig[64:]), 'little')
    big = sig[:64] + (s_int + ed25519.L).to_bytes(32, 'little').hex()
    vote_msg = b'smartswitch-vote-v1:' + b'0' * 64
    cases += [
        {'name': 'R changed', 'public_key': pk, 'message_hex': msg, 'sig': flip(sig, 3), 'valid': False},
        {'name': 'S changed', 'public_key': pk, 'message_hex': msg, 'sig': flip(sig, 40), 'valid': False},
        {'name': 'S + L (non-canonical scalar)', 'public_key': pk, 'message_hex': msg, 'sig': big, 'valid': False},
        {'name': 'other message', 'public_key': pk, 'message_hex': '73', 'sig': sig, 'valid': False},
        {'name': 'other key', 'public_key': pk3, 'message_hex': msg, 'sig': sig, 'valid': False},
        {'name': 'upper-case hex signature', 'public_key': pk, 'message_hex': msg, 'sig': sig.upper(), 'valid': False},
        {'name': 'upper-case hex key', 'public_key': pk.upper(), 'message_hex': msg, 'sig': sig, 'valid': False},
        {'name': 'signature too short', 'public_key': pk, 'message_hex': msg, 'sig': sig[:-2], 'valid': False},
        {'name': 'signature too long', 'public_key': pk, 'message_hex': msg, 'sig': sig + '00', 'valid': False},
        {'name': 'key too short', 'public_key': pk[:-2], 'message_hex': msg, 'sig': sig, 'valid': False},
        {'name': 'not hex', 'public_key': pk, 'message_hex': msg, 'sig': 'zz' + sig[2:], 'valid': False},
        {'name': 'a vote message', 'public_key': PUB['alice'], 'message_hex': vote_msg.hex(),
         'sig': ed25519.sign(SEED['alice'], vote_msg), 'valid': True},
    ]
    for c in cases:
        assert ed25519.verify(c['public_key'], bytes.fromhex(c['message_hex']), c['sig']) == c['valid'], c['name']
    return {'description': 'verify(public_key, bytes(message_hex), sig) must equal "valid"; see SEMANTICS.md, Signatures',
            'cases': cases}


# ---------------------------------------------------------------- fleets
def fleet_vectors():
    cases = []

    def add(name, doc):
        try:
            validate_fleet(doc)
            st = State.genesis(doc)
            cases.append({'name': name, 'fleet': doc, 'ok': True, 'fleet_hash': doc_hash(doc), 'threshold': st.threshold})
        except SwitchError as e:
            cases.append({'name': name, 'fleet': doc, 'ok': False, 'code': e.code})

    add('three keyholders, roster', fleet())
    add('three keyholders, no roster', fleet(roster=False))
    for n in range(4, 8):
        add(f'{n} keyholders, default threshold', fleet(n))
    add('explicit threshold 3 of 7', fleet(7, threshold=3))
    add('explicit threshold 6 of 7', fleet(7, threshold=6))
    add('threshold 7 of 7 (one keyholder could block)', fleet(7, threshold=7))
    add('threshold 1 (one keyholder could trigger)', fleet(threshold=1))
    add('threshold 2.5', fleet(threshold=2.5))
    add('threshold true', fleet(threshold=True))
    add('two keyholders', fleet(2))
    d = fleet(); del d['agents']
    add('missing field', d)
    d = fleet(); d['extra'] = 1
    add('extra field', d)
    add('version 2', fleet(version=2))
    add('version true', fleet(version=True))
    add('type wrong', fleet(type='smartswitch.fleets'))
    add('fleet_id with a space', fleet(fleet_id='fleet one'))
    add('fleet_id 65 characters', fleet(fleet_id='f' * 65))
    d = fleet(); d['keyholders'][1]['id'] = 'alice'
    add('duplicate keyholder id', d)
    d = fleet(); d['keyholders'][1]['public_key'] = PUB['alice']
    add('duplicate public key', d)
    d = fleet(); d['keyholders'][0]['public_key'] = PUB['alice'].upper()
    add('upper-case public key', d)
    d = fleet(); d['keyholders'][0]['extra'] = 'x'
    add('keyholder with an extra field', d)
    add('coordinator key is a keyholder key', fleet(coordinator_key=PUB['bob']))
    add('offline timeout 999 ms', fleet(offline_timeout_ms=999))
    add('offline timeout 1000 ms', fleet(offline_timeout_ms=1000))
    add('max ttl one day + 1 ms', fleet(proposal_max_ttl_ms=86400001))
    add('agents: duplicate id', fleet(agents=[{'id': 'a', 'max_instances': 1}, {'id': 'a', 'max_instances': 1}]))
    add('agents: max_instances 0', fleet(agents=[{'id': 'a', 'max_instances': 0}]))
    add('agents: empty list', fleet(agents=[]))
    add('not an object', ['smartswitch.fleet'])
    defaults = [{'n': n, 'k': default_threshold(n)} for n in range(3, 13)]
    return {'description': 'validate the fleet; when ok, its sha256 (of the canonical form) and its quorum threshold',
            'default_thresholds': defaults, 'cases': cases}


# ---------------------------------------------------------------- certificates
def certificate_vectors():
    f3, f7 = fleet(), fleet(7)
    fleets = {'f3': f3, 'f7': f7}
    cases = []

    def run(name, fname, setup, c, at_ms=T0 + 1000, ahead=False):
        st = State.genesis(fleets[fname])
        for s_cert, s_at in setup:
            st = apply(st, s_cert, s_at)
        case = {'name': name, 'fleet': fname, 'setup': [{'certificate': x, 'at_ms': y} for x, y in setup],
                'certificate': c, 'at_ms': at_ms, 'ahead': ahead}
        try:
            case['proposal_hash'] = proposal_hash(c['proposal'])
        except (TypeError, KeyError):
            case['proposal_hash'] = None
        try:
            if ahead:
                verify_certificate(st, c, at_ms, ahead=True)
                case.update(ok=True, state=None)
            else:
                case.update(ok=True, state=apply(st, c, at_ms).summary())
        except SwitchError as e:
            case.update(ok=False, code=e.code)
        cases.append(case)

    g3 = State.genesis(f3)
    halt = cert(prop(g3), ['alice', 'bob'])
    run('halt the fleet, 2 of 3', 'f3', [], halt)
    run('halt the fleet, votes in reverse order', 'f3', [], {**halt, 'votes': list(reversed(halt['votes']))})
    run('all three vote', 'f3', [], cert(prop(g3), ['alice', 'bob', 'carol']))
    run('one vote is not a quorum', 'f3', [], cert(prop(g3), ['alice']))
    c = cert(prop(g3), ['alice'])
    c['votes'] = c['votes'] * 2
    run('the same keyholder twice', 'f3', [], c)
    run('an outsider and a keyholder', 'f3', [], cert(prop(g3), ['alice', 'mallory']))
    p = prop(g3)
    c = cert(p, ['alice'])
    c['votes'].append(sign_vote(SEED['bob'], 'bob', prop(g3, reason='something else')))
    run('a vote signed for another proposal', 'f3', [], c)
    c = cert(p, ['alice', 'bob'])
    c['votes'][1] = {'keyholder': 'bob', 'sig': c['votes'][1]['sig'].upper()}
    run('upper-case signature hex', 'f3', [], c)
    c = cert(p, ['alice', 'bob'])
    c['votes'][1] = {'keyholder': 'bob', 'sig': sign_vote(SEED['carol'], 'bob', p)['sig']}
    run("carol signs under bob's name", 'f3', [], c)
    run('another fleet hash', 'f3', [], cert(prop(g3, fleet_hash='ab' * 32), ['alice', 'bob']))
    run('another fleet id', 'f3', [], cert(prop(g3, fleet_id='fleet-other'), ['alice', 'bob']))
    run('seq skips one', 'f3', [], cert(prop(g3, seq=2), ['alice', 'bob']))
    run('seq skips one, agent mode (ahead)', 'f3', [], cert(prop(g3, seq=5), ['alice', 'bob']), ahead=True)
    run('epoch from the future', 'f3', [], cert(prop(g3, epoch=1), ['alice', 'bob']))
    run('valid until 1 ms after at_ms', 'f3', [], cert(prop(g3), ['alice', 'bob']), at_ms=T0 + TTL - 1)
    run('expired exactly at at_ms', 'f3', [], cert(prop(g3), ['alice', 'bob']), at_ms=T0 + TTL)
    run('at_ms before created_ms is allowed', 'f3', [], cert(prop(g3), ['alice', 'bob']), at_ms=T0 - 5000)
    run('valid for longer than the fleet allows', 'f3', [], cert(prop(g3, ttl=TTL + 1), ['alice', 'bob']))
    run('expires before it is created', 'f3', [], cert(prop(g3, ttl=0), ['alice', 'bob']))
    run('target with a space', 'f3', [], cert(prop(g3, target='a 1'), ['alice', 'bob']))
    run('target empty', 'f3', [], cert(prop(g3, target=''), ['alice', 'bob']))
    run('halt one agent', 'f3', [], cert(prop(g3, target='a1'), ['alice', 'bob']))
    run('halt an agent that is not in the roster (allowed)', 'f3', [], cert(prop(g3, target='zz-9'), ['bob', 'carol']))
    h1 = cert(prop(g3, target='a1'), ['alice', 'bob'])
    s1 = apply(g3, h1, T0 + 1000)
    h2 = cert(prop(s1, target='a2'), ['alice', 'bob'])
    s2 = apply(s1, h2, T0 + 1000)
    run('resume one of two halted agents', 'f3', [(h1, T0 + 1000), (h2, T0 + 1000)], cert(prop(s2, 'resume', 'a1'), ['bob', 'carol']))
    run('resume everything', 'f3', [(h1, T0 + 1000), (h2, T0 + 1000)], cert(prop(s2, 'resume', '*'), ['alice', 'carol']))
    run('replay of an applied certificate', 'f3', [(h1, T0 + 1000)], h1)
    run('resume needs a quorum too', 'f3', [(h1, T0 + 1000)], cert(prop(s1, 'resume', 'a1'), ['carol']))
    run('the reason is UTF-8 with control characters', 'f3', [], cert(prop(g3, reason='line1\nline2\t\x01 ü 漢 🙂 "q" \\'), ['alice', 'bob']))
    run('reason of 1000 UTF-8 bytes', 'f3', [], cert(prop(g3, reason='é' * 500), ['alice', 'bob']))
    run('reason of 1002 UTF-8 bytes', 'f3', [], cert(prop(g3, reason='é' * 501), ['alice', 'bob']))
    run('reason of 1000 bytes in 4-byte characters', 'f3', [], cert(prop(g3, reason='🙂' * 250), ['alice', 'bob']))
    run('reason of 1004 bytes in 4-byte characters', 'f3', [], cert(prop(g3, reason='🙂' * 251), ['alice', 'bob']))
    run('a field too many in the proposal', 'f3', [], cert(prop(g3, extra=1), ['alice', 'bob']))
    p = prop(g3); del p['reason']
    run('a field missing in the proposal', 'f3', [], cert(p, ['alice', 'bob']))
    run('unknown action', 'f3', [], cert(prop(g3, action='pause'), ['alice', 'bob']))
    run('seq 0', 'f3', [], cert(prop(g3, seq=0), ['alice', 'bob']))
    run('seq as a string', 'f3', [], cert(prop(g3, seq='1'), ['alice', 'bob']))
    run('halt with new_public_key', 'f3', [], cert(prop(g3, new_key=PUB['carol-2']), ['alice', 'bob']))
    c = cert(prop(g3), ['alice', 'bob']); del c['votes']
    run('certificate without votes', 'f3', [], c)
    c = cert(prop(g3), ['alice', 'bob']); c['votes'] = []
    run('certificate with an empty vote list', 'f3', [], c)
    c = cert(prop(g3), ['alice', 'bob']); c['votes'][0]['extra'] = 1
    run('vote with an extra field', 'f3', [], c)
    c = cert(prop(g3), ['alice', 'bob']); c['type'] = 'smartswitch.cert'
    run('certificate type wrong', 'f3', [], c)

    # membership
    sus = cert(prop(g3, 'suspend', 'carol', 'lost laptop'), ['alice', 'bob'])
    run('suspend carol', 'f3', [], sus)
    run('carol votes on her own suspension', 'f3', [], cert(prop(g3, 'suspend', 'carol'), ['alice', 'carol']))
    run('suspend an unknown keyholder', 'f3', [], cert(prop(g3, 'suspend', 'mallory'), ['alice', 'bob']))
    g3s = apply(g3, sus, T0 + 1000)
    run('suspending a second keyholder would make the quorum impossible', 'f3', [(sus, T0 + 1000)],
        cert(prop(g3s, 'suspend', 'bob'), ['alice', 'bob']))
    run('a suspended keyholder votes', 'f3', [(sus, T0 + 1000)], cert(prop(g3s), ['alice', 'carol']))
    run('old epoch after a suspension', 'f3', [(sus, T0 + 1000)], cert(prop(g3s, epoch=0), ['alice', 'bob']))
    rein = cert(prop(g3s, 'reinstate', 'carol', 'new laptop', new_key=PUB['carol-2']), ['alice', 'bob'])
    run('reinstate carol with a new key', 'f3', [(sus, T0 + 1000)], rein)
    run('reinstate without a new key', 'f3', [(sus, T0 + 1000)], cert(prop(g3s, 'reinstate', 'carol'), ['alice', 'bob']))
    run('reinstate with her old key', 'f3', [(sus, T0 + 1000)],
        cert(prop(g3s, 'reinstate', 'carol', new_key=PUB['carol']), ['alice', 'bob']))
    run("reinstate with alice's key", 'f3', [(sus, T0 + 1000)],
        cert(prop(g3s, 'reinstate', 'carol', new_key=PUB['alice']), ['alice', 'bob']))
    run('reinstate with the coordinator key', 'f3', [(sus, T0 + 1000)],
        cert(prop(g3s, 'reinstate', 'carol', new_key=PUB['coordinator']), ['alice', 'bob']))
    run('reinstate an active keyholder', 'f3', [], cert(prop(g3, 'reinstate', 'bob', new_key=PUB['carol-2']), ['alice', 'carol']))
    g3r = apply(g3s, rein, T0 + 2000)
    setup = [(sus, T0 + 1000), (rein, T0 + 2000)]
    run('after reinstatement, carol signs with her old key', 'f3', setup, cert(prop(g3r), ['alice', 'carol']))
    seeds = dict(SEED, carol=SEED['carol-2'])
    run('after reinstatement, carol signs with her new key', 'f3', setup, cert(prop(g3r), ['alice', 'carol'], seeds))

    g7 = State.genesis(f7)
    run('7 keyholders: 4 votes', 'f7', [], cert(prop(g7), ['alice', 'carol', 'erin', 'grace']))
    run('7 keyholders: 3 votes', 'f7', [], cert(prop(g7), ['alice', 'carol', 'erin']))
    return {'description': ('start from the genesis state of "fleet", apply each setup certificate at its at_ms, then '
                            'check "certificate" at "at_ms": apply it (ahead false) or only verify it as an agent does '
                            '(ahead true). ok true: "state" is the next state (null when ahead); ok false: "code".'),
            'fleets': fleets, 'cases': cases}


# ---------------------------------------------------------------- logs
def build_log(fl, steps):
    """steps: list of ("certificate", cert, ts) or ("event", body, ts)."""
    entries = [make_entry(0, T0, 'genesis', fl, '0' * 64)]
    for kind, body, ts in steps:
        entries.append(make_entry(len(entries), ts, kind, body, entries[-1]['hash']))
    return entries


def rehash_from(entries, i):
    out = copy.deepcopy(entries)
    for j in range(i, len(out)):
        out[j]['prev'] = out[j - 1]['hash'] if j else '0' * 64
        out[j]['n'] = j
        out[j] = make_entry(out[j]['n'], out[j]['ts_ms'], out[j]['kind'], out[j]['body'], out[j]['prev'])
    return out


def history():
    f3 = fleet()
    g = State.genesis(f3)
    c1 = cert(prop(g, reason='drill'), ['alice', 'bob'])
    s1 = apply(g, c1, T0 + 1000)
    c2 = cert(prop(s1, 'resume', '*', 'drill over'), ['bob', 'carol'])
    s2 = apply(s1, c2, T0 + 3000)
    c3 = cert(prop(s2, 'suspend', 'carol', 'lost laptop'), ['alice', 'bob'])
    s3 = apply(s2, c3, T0 + 4000)
    c4 = cert(prop(s3, 'reinstate', 'carol', 'new laptop', new_key=PUB['carol-2']), ['alice', 'bob'])
    s4 = apply(s3, c4, T0 + 5000)
    c5 = cert(prop(s4, target='a2', reason='a2 misbehaves'), ['alice', 'carol'], dict(SEED, carol=SEED['carol-2']))
    steps = [('certificate', c1, T0 + 1000), ('event', {'event': 'aggregation-slow', 'aggregation_ms': 250}, T0 + 2000),
             ('certificate', c2, T0 + 3000), ('certificate', c3, T0 + 4000), ('certificate', c4, T0 + 5000),
             ('certificate', c5, T0 + 6000)]
    return f3, steps


def log_vectors():
    f3, steps = history()
    good = build_log(f3, steps)
    pin = doc_hash(f3)
    cases = []

    def add(name, entries, pinned=pin):
        cases.append({'name': name, 'pinned': pinned, 'entries': entries, 'result': replay(entries, pinned)})

    add('a full history', good)
    add('a full history, nothing pinned', good, None)
    add('genesis only', good[:1])
    add('empty', [])
    bad = copy.deepcopy(good); bad[1]['body']['proposal']['reason'] = 'edited'
    add('a reason edited, hashes left', bad)
    add('a reason edited, hashes recomputed', rehash_from(bad, 1))
    bad = copy.deepcopy(good); bad[2]['body']['detail'] = 'x'
    add('an event edited', bad)
    add('two entries swapped', [good[0], good[2], good[1]] + good[3:])
    bad = copy.deepcopy(good); bad[3]['ts_ms'] = T0 + 500
    add('ts_ms goes backwards (allowed: it is the coordinator clock, unsigned)', rehash_from(bad, 3))
    add('another fleet pinned', good, doc_hash(fleet(4)))
    add('starts with a certificate', good[1:])
    bad = copy.deepcopy(good); bad.insert(2, copy.deepcopy(good[0])); bad[2]['ts_ms'] = good[1]['ts_ms']
    add('a second genesis', rehash_from(bad, 2))
    add('genesis with an invalid fleet', build_log(fleet(2), []), None)
    bad = copy.deepcopy(good); bad[1]['ts_ms'] = T0 + TTL + 1
    add('a certificate written after it expired', rehash_from(bad, 1))
    bad = copy.deepcopy(good); bad[2]['kind'] = 'note'
    add('an unknown entry kind', rehash_from(bad, 2))
    bad = copy.deepcopy(good); bad[1]['extra'] = 1
    add('an entry with an extra field', bad)
    bad = copy.deepcopy(good); bad[2]['body']['aggregation_ms'] = 250.5
    add('an event with a fractional number (no canonical form)', bad)
    bad = copy.deepcopy(good); del bad[3]
    add('an entry removed', bad)
    add('an entry removed, rehashed', rehash_from(bad, 3))
    return {'description': ('replay "entries" (pinned: the fleet hash entry 0 must have, or null). ok: size, head and the '
                            'final state; not ok: the index of the first bad entry and its code.'),
            'cases': cases}


# ---------------------------------------------------------------- agent
def agent_vectors():
    f3, steps = history()
    good = build_log(f3, steps)
    n1 = '00112233445566778899aabbccddeeff'
    n2 = 'ffeeddccbbaa99887766554433221100'

    def hb(size, nonce=n1, agent='a1', inst='i1', head=None, key='coordinator', fh=None, issued=T0 + 9, **over):
        h = sign_heartbeat(SEED[key], fh or doc_hash(f3), agent, inst, nonce, size,
                           head or good[size - 1]['hash'], issued)
        if over:
            h.update(over)
        return h

    cases = []

    def case(name, agent_id, steps_):
        v = AgentView(f3, agent_id, 'i1')
        out = []
        for st in steps_:
            op = st['op']
            if op == 'log':
                r = v.log(st['entries'])
            elif op == 'heartbeat':
                r = v.heartbeat(st['heartbeat'], st['nonce'], st['at_ms'])
            elif op == 'certificate':
                r = v.certificate(st['certificate'], st['at_ms'])
            else:
                r = v.status(st['at_ms'])
            out.append(dict(st, expect=r))
        cases.append({'name': name, 'agent_id': agent_id, 'instance_id': 'i1', 'steps': out})

    L = lambda a, b: {'op': 'log', 'entries': good[a:b]}  # noqa: E731
    H = lambda h, at, nonce=n1: {'op': 'heartbeat', 'heartbeat': h, 'nonce': nonce, 'at_ms': at}  # noqa: E731
    S = lambda at: {'op': 'status', 'at_ms': at}  # noqa: E731
    C = lambda c, at: {'op': 'certificate', 'certificate': c, 'at_ms': at}  # noqa: E731

    case('no heartbeat yet, then running, then the dead-man rule', 'a1',
         [S(0), L(0, 1), S(0), H(hb(1), 1000), S(1000), S(30999), S(31000), H(hb(1, n2), 40000, n2), S(40000)])
    case('behind the log, then caught up', 'a1',
         [L(0, 1), H(hb(2), 1000), S(1000), L(1, 2), H(hb(2), 1000), S(1000)])
    case('the history: halted, resumed, a2 halted (a1 runs)', 'a1', [L(0, 7), H(hb(7), 5), S(5)])
    case('the history as a2', 'a2', [L(0, 7), H(hb(7, agent='a2'), 5), S(5)])
    case('a heartbeat for an older log size is fine', 'a1', [L(0, 7), H(hb(3), 5), S(5)])
    forged = hb(2, head='ab' * 32)
    case('fork: the coordinator shows another head', 'a1',
         [L(0, 2), H(forged, 5), S(5), H(hb(2), 6), S(6)])
    case('bad heartbeats', 'a1', [
        L(0, 1),
        H(hb(1, key='alice'), 1), H(hb(1, key='other-coordinator'), 2), H(hb(1), 3, n2),
        H(hb(1, agent='a2'), 4), H(hb(1, inst='i2'), 5), H(hb(1, fh='cd' * 32), 6),
        H(dict(hb(1), extra=1), 7), H(dict(hb(1), log_size=0), 8), H(hb(1, nonce=n1.upper()), 9, n1.upper()),
        H(dict(hb(1), sig=hb(1)['sig'][:-2] + '00'), 10), H(dict(hb(1), agent_id=2.5), 11), S(11)])
    g = State.genesis(f3)
    halt_all_2 = cert(prop(g, seq=2, reason='direct'), ['alice', 'bob'])
    s2 = apply(apply(g, good[1]['body'], good[1]['ts_ms']), good[3]['body'], good[3]['ts_ms'])
    resume3 = cert(prop(s2, 'resume', '*', 'resume after the direct halt'), ['alice', 'carol'])
    resume3_entry = make_entry(4, T0 + 3500, 'certificate', resume3, good[3]['hash'])
    case('a halt delivered directly, whose seq another certificate takes: it stays until a later resume', 'a1', [
        L(0, 1), H(hb(1), 10), S(10), C(halt_all_2, 20), S(20), L(1, 2), H(hb(2), 30), S(30), L(2, 3), S(31),
        L(3, 4), H(hb(4), 40), S(40), {'op': 'log', 'entries': [resume3_entry]}, S(41)])
    case('a halt delivered directly that the log then applies: the state holds it', 'a1', [
        L(0, 1), H(hb(1), 10), C(good[1]['body'], 20), S(20), L(1, 2), H(hb(2), 30), S(30), L(2, 4), H(hb(4), 40), S(40)])
    case('direct certificates that do nothing', 'a1', [
        C(halt_all_2, 1), L(0, 1), H(hb(1), 1),
        C(cert(prop(g, target='a2'), ['alice', 'bob']), 2),
        C(cert(prop(g, 'resume', '*'), ['alice', 'bob']), 3),
        C(cert(prop(g, seq=3), ['alice']), 4),
        C(cert(prop(g, seq=3, epoch=1), ['alice', 'bob']), 5),
        C(cert(prop(g, seq=3), ['alice', 'mallory']), 6),
        C(cert(prop(g, seq=3), ['alice', 'bob']), T0 + TTL),
        S(10)])
    case('a direct halt of this agent', 'a1', [L(0, 1), H(hb(1), 1), C(cert(prop(g, target='a1', seq=4), ['bob', 'carol']), 2), S(2)])
    case('replay of an applied halt is ignored', 'a1', [L(0, 3), H(hb(3), 1), C(good[1]['body'], 2), S(2)])
    bad = copy.deepcopy(good[:4]); bad[2]['body']['detail'] = 'x'
    case('a log entry that does not verify', 'a1', [{'op': 'log', 'entries': bad}, H(hb(2), 1), S(1), H(hb(4), 2), S(2)])
    case('heartbeats do not move time backwards', 'a1', [L(0, 1), H(hb(1), 5000), H(hb(1, n2), 100, n2), S(34999), S(35000)])
    return {'description': ('drive one agent view through "steps" in order; each step\'s result must equal "expect". '
                            'ops: log (entries), heartbeat (heartbeat, nonce, at_ms), certificate (certificate, at_ms), '
                            'status (at_ms). at_ms is the agent\'s monotonic clock, except for certificate, where it is wall-clock '
                            'time. The fleet is "fleet"; the agent is agent_id / instance_id.'),
            'fleet': f3, 'cases': cases}


CHECK = '--check' in sys.argv
DIFF: list = []


def main():
    os.makedirs(OUT, exist_ok=True)
    write('canonical.json', canonical_vectors())
    write('ed25519.json', ed_vectors())
    write('fleets.json', fleet_vectors())
    write('certificates.json', certificate_vectors())
    write('logs.json', log_vectors())
    write('agent.json', agent_vectors())
    if CHECK:
        if DIFF:
            sys.exit(1)
        print('vectors are up to date')


if __name__ == '__main__':
    main()
