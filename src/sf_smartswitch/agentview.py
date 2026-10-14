"""What an agent believes, and whether it may run: the agent-side rules, without any I/O.

The networked ``Agent`` (agent.py) and every port drive this same logic; spec/conformance/agent.json
checks it step by step. Times for heartbeats and status are the agent's own monotonic milliseconds;
the time for a delivered certificate is wall-clock milliseconds (it is compared with expires_ms).

An agent may run only while all of these hold:
- it has not seen a fork (the coordinator showing a history that contradicts what the agent verified);
- its verified state does not halt the fleet or this agent;
- no quorum-signed halt certificate for it, delivered directly and newer than its state, is pending
  (until the log applies that same halt, or a later resume);
- a valid heartbeat answered one of its own nonces less than ``offline_timeout_ms`` ago
  (the dead-man rule: no contact for 30 s by default means stop).
"""
from __future__ import annotations

from . import ed25519
from .log import Replica
from .protocol import (HEARTBEAT_PREFIX, NONCE, MAX_INT, SwitchError, _int, canonical, doc_hash, hashable, is_id,
                       proposal_hash, sha256_hex, verify_certificate)

HEARTBEAT_FIELDS = {'type', 'fleet_hash', 'agent_id', 'instance_id', 'nonce', 'log_size', 'head', 'issued_ms',
                    'sig'}


def heartbeat_message(hb: dict) -> bytes:
    body = {k: v for k, v in hb.items() if k != 'sig'}
    return HEARTBEAT_PREFIX + sha256_hex(canonical.encode(body)).encode('ascii')


def sign_heartbeat(seed: bytes, fleet_hash: str, agent_id: str, instance_id: str, nonce: str, log_size: int,
                   head: str, issued_ms: int) -> dict:
    hb = {'type': 'smartswitch.heartbeat', 'fleet_hash': fleet_hash, 'agent_id': agent_id,
          'instance_id': instance_id, 'nonce': nonce, 'log_size': log_size, 'head': head, 'issued_ms': issued_ms}
    hb['sig'] = ed25519.sign(seed, heartbeat_message(hb))
    return hb


class AgentView:
    def __init__(self, fleet: dict, agent_id: str, instance_id: str):
        if not is_id(agent_id) or not is_id(instance_id):
            raise ValueError('agent_id and instance_id must match [A-Za-z0-9._-]{1,64}')
        self.fleet_hash = doc_hash(fleet)
        self.fleet = fleet
        self.agent_id, self.instance_id = agent_id, instance_id
        self.replica = Replica(self.fleet_hash)
        self.last_ok_ms: int | None = None
        self.provisional: dict[str, int] = {}       # proposal hash -> seq of directly delivered halts
        self.fork = False
        # optional (not in the vectors): what this agent had verified before a restart; the coordinator's
        # log must reach this size with this head, and may never claim to be shorter (agent.py, state_file)
        self.floor_size, self.floor_head = 0, None

    # -- inputs
    def log(self, entries) -> dict:
        """Entries that continue the local copy (fetched from the coordinator). A provisional halt ends
        when the log applies that same proposal (the state then holds the halt), or applies a later
        resume of "*" or of this agent; another certificate taking its seq does not end it."""
        if not isinstance(entries, list):
            return {'ok': False, 'code': 'SW-BAD-ENTRY', 'size': self.replica.size}
        for e in entries:
            try:
                self.replica.extend([e])
            except SwitchError as err:
                return {'ok': False, 'code': err.code, 'size': self.replica.size}
            if self.provisional and e['kind'] == 'certificate':
                p = e['body']['proposal']
                ph = proposal_hash(p)
                if ph in self.provisional:
                    del self.provisional[ph]
                if p['action'] == 'resume' and p['target'] in ('*', self.agent_id):
                    self.provisional = {h: q for h, q in self.provisional.items() if q >= p['seq']}
            if self.floor_head is not None and self.replica.size == self.floor_size \
                    and self.replica.head != self.floor_head:
                self.fork = True
        return {'ok': True, 'size': self.replica.size}

    def heartbeat(self, hb, nonce: str, at_ms: int) -> dict:
        """A heartbeat answering ``nonce``, which the agent sent at ``at_ms``."""
        code = self._check_heartbeat(hb, nonce)
        if code is None:
            r = self.replica
            size = hb['log_size']
            if size < self.floor_size:
                self.fork = True                 # shorter than what this agent verified before a restart
                code = 'SW-FORK'
            elif r.size >= size:
                if r.hashes[size - 1] != hb['head']:
                    self.fork = True
                    code = 'SW-FORK'
            elif r.size < size:
                code = 'SW-BEHIND'
        if code is None:
            self.last_ok_ms = at_ms if self.last_ok_ms is None else max(self.last_ok_ms, at_ms)
            return {'ok': True, 'code': 'SW-OK'}
        return {'ok': False, 'code': code}

    def _check_heartbeat(self, hb, nonce):
        if not isinstance(hb, dict) or set(hb) != HEARTBEAT_FIELDS or hb['type'] != 'smartswitch.heartbeat' \
                or not _int(hb['log_size'], 1, MAX_INT) or not ed25519.is_key_hex(hb['head']) \
                or not _int(hb['issued_ms'], 0, MAX_INT) or not hashable(hb):
            return 'SW-BAD-HEARTBEAT'
        if not ed25519.verify(self.fleet['coordinator_key'], heartbeat_message(hb), hb['sig']):
            return 'SW-BAD-HEARTBEAT'
        if hb['fleet_hash'] != self.fleet_hash:
            return 'SW-WRONG-FLEET'
        if hb['agent_id'] != self.agent_id or hb['instance_id'] != self.instance_id:
            return 'SW-WRONG-AGENT'
        if not isinstance(nonce, str) or not NONCE.match(nonce) or hb['nonce'] != nonce:
            return 'SW-NONCE'
        return None

    def certificate(self, cert, at_ms: int) -> dict:
        """A certificate delivered directly (not through the log), checked at wall-clock time ``at_ms``
        (proposal expiry is wall-clock time). Only a quorum-signed halt of this agent or of the whole fleet,
        newer than the local state, has an effect: a provisional halt (see ``log`` for when it ends).
        Nothing else can be applied out of the log."""
        st = self.replica.state
        if st is None:
            return {'ok': False, 'code': 'SW-NO-STATE'}
        try:
            p = verify_certificate(st, cert, at_ms, ahead=True)
        except SwitchError as e:
            return {'ok': False, 'code': e.code}
        if p['action'] != 'halt' or p['target'] not in ('*', self.agent_id):
            return {'ok': False, 'code': 'SW-NOT-APPLICABLE'}
        self.provisional[proposal_hash(p)] = p['seq']
        return {'ok': True, 'code': 'SW-PROVISIONAL-HALT'}

    # -- the answer
    def status(self, at_ms: int) -> dict:
        """{"run": bool, "code"}; the first matching reason in this order wins."""
        st = self.replica.state
        if self.fork:
            code = 'SW-FORK'
        elif st is not None and st.halted_all:
            code = 'SW-HALTED-FLEET'
        elif st is not None and self.agent_id in st.halted:
            code = 'SW-HALTED-AGENT'
        elif self.provisional:
            code = 'SW-PROVISIONAL-HALT'
        elif self.last_ok_ms is None or st is None:
            code = 'SW-NO-HEARTBEAT'
        elif at_ms - self.last_ok_ms >= st.offline_timeout_ms:
            code = 'SW-OFFLINE'
        else:
            return {'run': True, 'code': 'SW-RUN'}
        return {'run': False, 'code': code}
