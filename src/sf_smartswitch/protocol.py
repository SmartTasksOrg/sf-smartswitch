"""The SmartSwitch protocol: fleet document, proposals, votes, certificates and the switch state.

Everything here is deterministic: no clock, no randomness, no I/O. Time comes in as ``at_ms``.
spec/SEMANTICS.md is the contract and spec/conformance/*.json are its tests; this module is the
reference that the vectors are generated from.

    fleet = validate_fleet(doc)                  # raises SwitchError("SW-BAD-FLEET", ...)
    st = State.genesis(fleet)
    st2 = apply(st, certificate, at_ms)         # raises SwitchError(code, ...) and leaves st as it was
    st2.may_run("agent-7")
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace

from . import canonical, ed25519

ID = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')
ACTIONS = ('halt', 'resume', 'suspend', 'reinstate')
VOTE_PREFIX = b'smartswitch-vote-v1:'
HEARTBEAT_PREFIX = b'smartswitch-heartbeat-v1:'
MAX_KEYHOLDERS = 64
MAX_AGENTS = 100000
MAX_REASON_BYTES = 1000
MAX_INT = 2 ** 53 - 1          # integers above this do not survive every JSON parser (JavaScript)

FLEET_FIELDS = {'type', 'version', 'fleet_id', 'keyholders', 'threshold', 'coordinator_key',
                'offline_timeout_ms', 'proposal_max_ttl_ms', 'agents'}
PROPOSAL_FIELDS = {'type', 'fleet_id', 'fleet_hash', 'seq', 'epoch', 'action', 'target', 'new_public_key',
                   'reason', 'created_ms', 'expires_ms'}


class SwitchError(ValueError):
    """A rule was broken. ``code`` is the stable SW-* code from spec/SEMANTICS.md."""

    def __init__(self, code: str, message: str = ''):
        super().__init__(f'{code}: {message}' if message else code)
        self.code = code
        self.message = message


def _utf8(s: str) -> bytes:
    try:
        return s.encode('utf-8')
    except UnicodeEncodeError:       # a lone surrogate from a JSON \ud800 escape: not valid text
        return b'\xff' * (MAX_REASON_BYTES + 1)


def hashable(obj) -> bool:
    """True when ``obj`` has a canonical form (no floats, valid Unicode)."""
    try:
        canonical.encode(obj)
        return True
    except (TypeError, UnicodeEncodeError, RecursionError):
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def doc_hash(obj) -> str:
    return sha256_hex(canonical.encode(obj))


def _int(v, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def is_id(v) -> bool:
    return isinstance(v, str) and bool(ID.match(v))


# ---------------------------------------------------------------- fleet

def default_threshold(n: int) -> int:
    """2 for up to five keyholders; a strict majority, floor(n/2) + 1, above five (4-of-7)."""
    return 2 if n <= 5 else n // 2 + 1


def threshold_ok(k, n: int) -> bool:
    """No single keyholder may trigger (k >= 2) or block (k <= n - 1) a quorum action."""
    return _int(k, 2, n - 1)


def validate_fleet(doc) -> dict:
    """Return ``doc`` if it is a valid fleet document; raise SwitchError('SW-BAD-FLEET') otherwise."""
    def bad(msg):
        raise SwitchError('SW-BAD-FLEET', msg)

    if not isinstance(doc, dict) or set(doc) != FLEET_FIELDS:
        bad('the fleet document must have exactly the fields ' + ', '.join(sorted(FLEET_FIELDS)))
    if doc['type'] != 'smartswitch.fleet' or not _int(doc['version'], 1, 1):
        bad('type must be "smartswitch.fleet" and version 1')
    if not is_id(doc['fleet_id']):
        bad('fleet_id must match [A-Za-z0-9._-]{1,64}')
    khs = doc['keyholders']
    if not isinstance(khs, list) or not 3 <= len(khs) <= MAX_KEYHOLDERS:
        bad(f'keyholders must be a list of 3 to {MAX_KEYHOLDERS}')
    ids, keys = set(), set()
    for kh in khs:
        if not isinstance(kh, dict) or set(kh) != {'id', 'public_key'}:
            bad('each keyholder must be {"id", "public_key"}')
        if not is_id(kh['id']) or not ed25519.is_key_hex(kh['public_key']):
            bad('keyholder id must match [A-Za-z0-9._-]{1,64} and public_key be 64 lower-case hex')
        if kh['id'] in ids or kh['public_key'] in keys:
            bad('keyholder ids and public keys must be unique')
        ids.add(kh['id'])
        keys.add(kh['public_key'])
    n = len(khs)
    if doc['threshold'] is not None and not threshold_ok(doc['threshold'], n):
        bad(f'threshold must be null or an integer from 2 to {n - 1}')
    if not ed25519.is_key_hex(doc['coordinator_key']) or doc['coordinator_key'] in keys:
        bad('coordinator_key must be 64 lower-case hex and differ from every keyholder key')
    if not _int(doc['offline_timeout_ms'], 1000, 3600000):
        bad('offline_timeout_ms must be an integer from 1000 to 3600000')
    if not _int(doc['proposal_max_ttl_ms'], 1000, 86400000):
        bad('proposal_max_ttl_ms must be an integer from 1000 to 86400000')
    agents = doc['agents']
    if agents is not None:
        if not isinstance(agents, list) or len(agents) > MAX_AGENTS:
            bad(f'agents must be null or a list of at most {MAX_AGENTS}')
        seen = set()
        for a in agents:
            if not isinstance(a, dict) or set(a) != {'id', 'max_instances'}:
                bad('each agent must be {"id", "max_instances"}')
            if not is_id(a['id']) or not _int(a['max_instances'], 1, 1000) or a['id'] in seen:
                bad('agent id must match [A-Za-z0-9._-]{1,64}, be unique, and max_instances be 1 to 1000')
            seen.add(a['id'])
    return doc


def fleet_threshold(fleet: dict) -> int:
    n = len(fleet['keyholders'])
    return fleet['threshold'] if fleet['threshold'] is not None else default_threshold(n)


# ---------------------------------------------------------------- proposals and votes

def check_proposal_format(p) -> dict:
    def bad(msg):
        raise SwitchError('SW-BAD-PROPOSAL', msg)

    if not isinstance(p, dict) or set(p) != PROPOSAL_FIELDS:
        bad('a proposal must have exactly the fields ' + ', '.join(sorted(PROPOSAL_FIELDS)))
    if p['type'] != 'smartswitch.proposal':
        bad('type must be "smartswitch.proposal"')
    if not is_id(p['fleet_id']) or not ed25519.is_key_hex(p['fleet_hash']):
        bad('fleet_id or fleet_hash is malformed')
    if not _int(p['seq'], 1, MAX_INT) or not _int(p['epoch'], 0, MAX_INT):
        bad('seq must be an integer >= 1 and epoch >= 0')
    if p['action'] not in ACTIONS:
        bad('action must be one of ' + ', '.join(ACTIONS))
    if not isinstance(p['target'], str):
        bad('target must be a string')
    if p['action'] == 'reinstate':
        if not ed25519.is_key_hex(p['new_public_key']):
            bad('reinstate needs new_public_key (64 lower-case hex)')
    elif p['new_public_key'] is not None:
        bad('new_public_key must be null unless the action is reinstate')
    if not isinstance(p['reason'], str) or len(_utf8(p['reason'])) > MAX_REASON_BYTES:
        bad(f'reason must be a string of at most {MAX_REASON_BYTES} UTF-8 bytes')
    if not _int(p['created_ms'], 0, MAX_INT) or not _int(p['expires_ms'], 0, MAX_INT):
        bad('created_ms and expires_ms must be integers >= 0')
    if p['expires_ms'] <= p['created_ms']:
        bad('expires_ms must be after created_ms')
    return p


def proposal_hash(p: dict) -> str:
    return doc_hash(p)


def vote_message(p_hash: str) -> bytes:
    return VOTE_PREFIX + p_hash.encode('ascii')


def sign_vote(seed: bytes, keyholder: str, proposal: dict) -> dict:
    return {'keyholder': keyholder, 'sig': ed25519.sign(seed, vote_message(proposal_hash(proposal)))}


def check_certificate_format(c) -> dict:
    def bad(msg):
        raise SwitchError('SW-BAD-CERTIFICATE', msg)

    if not isinstance(c, dict) or set(c) != {'type', 'proposal', 'votes'}:
        bad('a certificate must be {"type", "proposal", "votes"}')
    if c['type'] != 'smartswitch.certificate':
        bad('type must be "smartswitch.certificate"')
    votes = c['votes']
    if not isinstance(votes, list) or not 1 <= len(votes) <= MAX_KEYHOLDERS:
        bad(f'votes must be a list of 1 to {MAX_KEYHOLDERS}')
    for v in votes:
        if not isinstance(v, dict) or set(v) != {'keyholder', 'sig'} or not isinstance(v['keyholder'], str) \
                or not isinstance(v['sig'], str):
            bad('each vote must be {"keyholder": string, "sig": string}')
    return c


def make_certificate(proposal: dict, votes: list) -> dict:
    """A certificate with the votes sorted by keyholder id (the form the coordinator writes)."""
    return {'type': 'smartswitch.certificate', 'proposal': proposal,
            'votes': sorted(votes, key=lambda v: v['keyholder'])}


# ---------------------------------------------------------------- state

@dataclass(frozen=True)
class State:
    fleet_id: str
    fleet_hash: str
    coordinator_key: str
    n: int
    threshold: int
    max_ttl_ms: int
    offline_timeout_ms: int
    keys: dict                      # keyholder id -> public key hex (current)
    suspended: frozenset = frozenset()
    seq: int = 0                    # certificates applied
    epoch: int = 0                  # membership changes applied
    halted_all: bool = False
    halted: frozenset = frozenset()  # agent ids halted one by one
    roster: dict | None = field(default=None)   # agent id -> max_instances, or None

    @classmethod
    def genesis(cls, fleet: dict) -> 'State':
        validate_fleet(fleet)
        return cls(fleet_id=fleet['fleet_id'], fleet_hash=doc_hash(fleet), coordinator_key=fleet['coordinator_key'],
                   n=len(fleet['keyholders']), threshold=fleet_threshold(fleet),
                   max_ttl_ms=fleet['proposal_max_ttl_ms'], offline_timeout_ms=fleet['offline_timeout_ms'],
                   keys={k['id']: k['public_key'] for k in fleet['keyholders']},
                   roster=None if fleet['agents'] is None else {a['id']: a['max_instances'] for a in fleet['agents']})

    @property
    def active(self) -> list:
        return sorted(k for k in self.keys if k not in self.suspended)

    def may_run(self, agent_id: str) -> bool:
        return not self.halted_all and agent_id not in self.halted

    def summary(self) -> dict:
        """The state as the vectors compare it."""
        return {'seq': self.seq, 'epoch': self.epoch, 'threshold': self.threshold, 'halted_all': self.halted_all,
                'halted': sorted(self.halted), 'active': self.active, 'suspended': sorted(self.suspended),
                'keys': dict(sorted(self.keys.items()))}


def verify_certificate(st: State, cert, at_ms: int, ahead: bool = False) -> dict:
    """Check ``cert`` against ``st`` at time ``at_ms``; return its proposal or raise SwitchError.

    ``ahead=False`` (the switch, and log replay): the proposal's seq must be exactly st.seq + 1.
    ``ahead=True`` (an agent receiving a certificate directly): any seq above st.seq is accepted.
    The checks run in the order of spec/SEMANTICS.md, "Certificate checks"; the first failure wins.
    """
    check_certificate_format(cert)
    p = check_proposal_format(cert['proposal'])
    if p['fleet_id'] != st.fleet_id or p['fleet_hash'] != st.fleet_hash:
        raise SwitchError('SW-WRONG-FLEET', 'the proposal is for another fleet')
    if p['seq'] <= st.seq:
        raise SwitchError('SW-STALE-SEQ', f'seq {p["seq"]} is not after the current seq {st.seq}')
    if not ahead and p['seq'] != st.seq + 1:
        raise SwitchError('SW-SEQ-GAP', f'seq {p["seq"]} is not the next seq {st.seq + 1}')
    if p['epoch'] != st.epoch:
        raise SwitchError('SW-WRONG-EPOCH', f'epoch {p["epoch"]} is not the current epoch {st.epoch}')
    if p['expires_ms'] - p['created_ms'] > st.max_ttl_ms:
        raise SwitchError('SW-BAD-PROPOSAL', f'the proposal is valid for longer than {st.max_ttl_ms} ms')
    if at_ms >= p['expires_ms']:
        raise SwitchError('SW-EXPIRED', 'the proposal has expired')
    _check_target(st, p)
    ph = proposal_hash(p)
    msg = vote_message(ph)
    seen = set()
    for v in cert['votes']:
        kh = v['keyholder']
        if kh not in st.keys:
            raise SwitchError('SW-UNKNOWN-KEYHOLDER', f'{kh!r} is not a keyholder of this fleet')
        if kh in seen:
            raise SwitchError('SW-DUPLICATE-VOTE', f'{kh!r} voted twice')
        seen.add(kh)
        if kh in st.suspended:
            raise SwitchError('SW-SUSPENDED-KEYHOLDER', f'{kh!r} is suspended')
        if p['action'] == 'suspend' and kh == p['target']:
            raise SwitchError('SW-TARGET-VOTE', 'a keyholder cannot vote on its own suspension')
        if not ed25519.verify(st.keys[kh], msg, v['sig']):
            raise SwitchError('SW-BAD-SIGNATURE', f'the signature of {kh!r} does not verify')
    if len(seen) < st.threshold:
        raise SwitchError('SW-NO-QUORUM', f'{len(seen)} valid votes, {st.threshold} needed')
    return p


def _check_target(st: State, p: dict) -> None:
    a, t = p['action'], p['target']
    if a in ('halt', 'resume'):
        if t != '*' and not is_id(t):
            raise SwitchError('SW-BAD-TARGET', 'target must be "*" or an agent id')
    elif a == 'suspend':
        if t not in st.keys or t in st.suspended:
            raise SwitchError('SW-BAD-TARGET', 'target must be an active keyholder')
        if len(st.active) - 1 < st.threshold:
            raise SwitchError('SW-QUORUM-IMPOSSIBLE', 'suspending this keyholder would leave fewer active '
                                                      f'keyholders than the threshold {st.threshold}')
    else:  # reinstate
        if t not in st.suspended:
            raise SwitchError('SW-BAD-TARGET', 'target must be a suspended keyholder')
        k = p['new_public_key']
        if k in st.keys.values() or k == st.coordinator_key:
            raise SwitchError('SW-BAD-TARGET', 'new_public_key must be a key not used in this fleet')


def apply(st: State, cert, at_ms: int) -> State:
    """Verify ``cert`` (seq must be st.seq + 1) and return the next state."""
    p = verify_certificate(st, cert, at_ms)
    a, t = p['action'], p['target']
    nxt = replace(st, seq=st.seq + 1)
    if a == 'halt':
        nxt = replace(nxt, halted_all=True) if t == '*' else replace(nxt, halted=st.halted | {t})
    elif a == 'resume':
        nxt = replace(nxt, halted_all=False, halted=frozenset()) if t == '*' else replace(nxt, halted=st.halted - {t})
    elif a == 'suspend':
        nxt = replace(nxt, epoch=st.epoch + 1, suspended=st.suspended | {t})
    else:
        keys = dict(st.keys)
        keys[t] = p['new_public_key']
        nxt = replace(nxt, epoch=st.epoch + 1, suspended=st.suspended - {t}, keys=keys)
    return nxt


def new_proposal(st: State, action: str, target: str, reason: str, created_ms: int, ttl_ms: int,
                 new_public_key: str | None = None, seq: int | None = None) -> dict:
    p = {'type': 'smartswitch.proposal', 'fleet_id': st.fleet_id, 'fleet_hash': st.fleet_hash,
         'seq': st.seq + 1 if seq is None else seq, 'epoch': st.epoch, 'action': action, 'target': target,
         'new_public_key': new_public_key, 'reason': reason, 'created_ms': created_ms,
         'expires_ms': created_ms + ttl_ms}
    return check_proposal_format(p)
