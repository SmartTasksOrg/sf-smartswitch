"""The coordinator: collects votes, writes certificates to the log, answers agents' heartbeats,
watches aggregation time and agent instances. The HTTP layer is server.py; this module has no I/O
other than the log files and an optional alert webhook.

The coordinator cannot halt or resume anything on its own: every change needs a certificate with a
quorum of keyholder signatures, which every agent checks again. What it can do wrong is delay: not
write a certificate, or stop answering. The first is why agents also accept halt certificates
delivered directly (agentview.py); the second is why they stop when heartbeats stop.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request

from . import ed25519
from .agentview import sign_heartbeat
from .log import LogFile, Replica, compare_files, make_entry
from .metrics import Metrics
from .keycheck import weakness
from .protocol import NONCE, SwitchError, apply, check_proposal_format, doc_hash, is_id, make_certificate, \
    proposal_hash, validate_fleet, verify_certificate

log = logging.getLogger('sf_smartswitch.coordinator')

SEQ_CODES = ('SW-STALE-SEQ', 'SW-SEQ-GAP', 'SW-WRONG-EPOCH')
MAX_INSTANCES_TRACKED = 100000
MAX_PENDING = 1000
MAX_PENDING_PER_KEYHOLDER = 10      # proposals a keyholder opened (first vote) that are still pending
ALERT_EVERY_MS = 60000              # each kind of replication alert is written at most once a minute


def wall_ms() -> int:
    return time.time_ns() // 1_000_000


def mono_ms() -> float:
    return time.monotonic_ns() / 1e6


class Refused(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


class Watchdog:
    """Aggregation-time alarm. Fires "aggregation-slow" when one certificate took longer than
    ``base_ms`` plus a tolerance of 10 % of the recent average (an EWMA, alpha 0.2) and "aggregation-spike"
    when it took more than 1.5 x ``base_ms``; a spike is never hidden by the tolerance."""

    def __init__(self, base_ms: float = 200.0, jitter: float = 0.10, alpha: float = 0.2):
        self.base_ms, self.jitter, self.alpha = base_ms, jitter, alpha
        self.ewma: float | None = None

    def check(self, ms: float) -> str | None:
        tol = 0.0 if self.ewma is None else self.jitter * self.ewma
        kind = None
        if ms > 1.5 * self.base_ms:
            kind = 'aggregation-spike'
        elif ms > self.base_ms + tol:
            kind = 'aggregation-slow'
        self.ewma = ms if self.ewma is None else self.alpha * ms + (1 - self.alpha) * self.ewma
        return kind


class Coordinator:
    def __init__(self, fleet: dict, coordinator_seed: bytes, log_path: str | None = None, mirror_path: str | None = None,
                 clock=wall_ms, mono=mono_ms, watchdog_ms: float = 200.0, webhook: str | None = None,
                 enforce_roster: bool = True, metrics: Metrics | None = None, repair_mirror: bool = False):
        validate_fleet(fleet)
        for k in [x['public_key'] for x in fleet['keyholders']] + [fleet['coordinator_key']]:
            why = weakness(k)
            if why:
                raise SwitchError('SW-BAD-FLEET', f'public key {k[:16]}...: {why}')
        if ed25519.public_key(coordinator_seed) != fleet['coordinator_key']:
            raise SwitchError('SW-BAD-FLEET', 'the coordinator key file does not match coordinator_key in the fleet')
        self.fleet, self.fleet_hash = fleet, doc_hash(fleet)
        self._seed = coordinator_seed
        self.clock, self.mono = clock, mono
        self.metrics = metrics or Metrics()
        self.watchdog = Watchdog(watchdog_ms)
        self.webhook = webhook
        self.enforce_roster = enforce_roster
        self.file = LogFile(log_path, mirror_path) if log_path else None
        self.mirror_path = mirror_path
        self.repair_mirror = repair_mirror
        self._lock = threading.RLock()
        self._mirror_bad = False
        self.entries: list[dict] = []
        self.replica = Replica(self.fleet_hash)
        self.pending: dict[str, dict] = {}       # proposal hash -> {"proposal", "votes": {kh: sig}, "first_ms"}
        self.instances: dict[tuple, dict] = {}   # (agent, instance) -> {"first_mono", "last_mono", "log_size"}
        self.by_agent: dict[str, set] = {}       # agent -> its instance ids (for the roster count)
        self._alerted: dict[str, float] = {}
        self._propagating: dict[int, dict] = {}  # entry index of a halt -> {"start", "waiting": set}
        self._load()

    # ---------------------------------------------------------------- log
    def _load(self):
        caught_up = None
        existing = LogFile.read(self.file.path) if self.file else []
        if self.file and self.mirror_path:
            mirrored = LogFile.read(self.mirror_path)
            if existing or mirrored:
                c = compare_files(self.file.path, self.mirror_path, self.fleet_hash)
                if not c['ok'] and self._mirror_lags(existing, mirrored, c):
                    # writes go to the log first, then the mirror: a crash in between leaves the mirror exactly
                    # one entry behind. A missing certificate is signed, so copying it cannot smuggle anything
                    # in; a missing event is copied only with --repair-mirror (a person looked at it).
                    missing = existing[-1]
                    if missing['kind'] == 'certificate' or self.repair_mirror:
                        LogFile(self.mirror_path).write(missing)
                        caught_up = missing
                        log.warning('mirror was one entry behind the log (a crash between the two writes); caught up')
                        c = compare_files(self.file.path, self.mirror_path, self.fleet_hash)
                    else:
                        c['message'] += ('; the mirror lacks the last entry, an event: if a crash between the two '
                                         'writes explains it, start once with --repair-mirror')
                if not c['ok']:
                    raise SwitchError('SW-LOG-CHAIN', 'log and mirror differ, refusing to start: ' + c['message'])
        if existing:
            try:
                self.replica.extend(existing)
            except SwitchError as e:
                raise SwitchError(e.code, f'the log file does not verify at entry {self.replica.size}: {e.message}') from None
            self.entries = existing
        else:
            self._append('genesis', self.fleet)
        if caught_up is not None:
            self.event('mirror-caught-up', entry=caught_up['n'], kind=caught_up['kind'], entry_hash=caught_up['hash'])
        self._gauges()

    @staticmethod
    def _mirror_lags(existing, mirrored, c) -> bool:
        return (c['primary'].get('ok') and c['mirror'].get('ok') and 0 < len(mirrored) < len(existing)
                and [e['hash'] for e in mirrored] == [e['hash'] for e in existing[:len(mirrored)]]
                and len(existing) - len(mirrored) == 1)

    def _append(self, kind: str, body: dict, ts: int | None = None) -> dict:
        """Verify and write one entry (the caller holds the lock). ts_ms is the clock now, even if an
        earlier entry has a later time: one wrong clock reading must not make later certificates expire."""
        ts = self.clock() if ts is None else ts
        if self.entries and ts < self.entries[-1]['ts_ms'] - 60000:
            log.warning('the clock (%d) is more than a minute behind the last log entry (%d)', ts, self.entries[-1]['ts_ms'])
        e = make_entry(self.replica.size, ts, kind, body, self.replica.head)
        self.replica.extend([e])            # raises before anything is written if the entry is invalid
        if self.file:
            self.file.write(e)
        self.entries.append(e)
        self.metrics.log_entries.set(len(self.entries))
        return e

    @property
    def state(self):
        return self.replica.state

    def _gauges(self):
        st = self.state
        self.metrics.halted.set(1 if st.halted_all else 0)
        self.metrics.agents_halted.set(len(st.halted))
        self.metrics.log_entries.set(len(self.entries))

    def entries_from(self, start: int, limit: int = 1000) -> list:
        with self._lock:
            return self.entries[start:start + max(0, min(limit, 1000))]

    def event(self, name: str, **fields) -> dict:
        with self._lock:
            body = dict(fields)
            body['event'] = name
            e = self._append('event', body)
        self._notify(name, fields)
        return e

    def _notify(self, name, fields):
        if not self.webhook:
            return
        text = f'SmartSwitch {self.fleet["fleet_id"]}: {name} ' + json.dumps(fields, sort_keys=True)

        def post():
            try:
                req = urllib.request.Request(self.webhook, data=json.dumps({'text': text, 'alert': name, **fields}).encode(),
                                             headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as e:  # an alert that cannot be sent is still in the log and the metrics
                log.warning('alert webhook failed: %s', e)
        threading.Thread(target=post, daemon=True).start()

    # ---------------------------------------------------------------- votes and certificates
    def _reject(self, e: SwitchError):
        self.metrics.rejected.inc(code=e.code)
        raise e

    def submit_vote(self, proposal, vote) -> dict:
        """One keyholder's signed vote on ``proposal``. Returns {"status": "pending" | "applied", ...}."""
        t0 = self.mono()
        if not isinstance(vote, dict) or set(vote) != {'keyholder', 'sig'}:
            self._reject(SwitchError('SW-BAD-CERTIFICATE', 'vote must be {"keyholder", "sig"}'))
        with self._lock:
            try:
                check_proposal_format(proposal)
                self._key_hygiene(proposal)
                # every check except the quorum, on this vote alone
                verify_certificate(self.state, make_certificate(proposal, [vote]), self.clock())
                single_ok = True
            except SwitchError as e:
                if e.code != 'SW-NO-QUORUM':
                    self.metrics.votes.inc(result='rejected')
                    self._reject(e)
                single_ok = False
            ph = proposal_hash(proposal)
            pend = self.pending.get(ph)
            if pend is None:
                self._expire_pending()
                mine = sorted((x['first_ms'], h) for h, x in self.pending.items() if x['opener'] == vote['keyholder'])
                while len(mine) >= MAX_PENDING_PER_KEYHOLDER:          # one keyholder cannot fill the table
                    del self.pending[mine.pop(0)[1]]
                if len(self.pending) >= MAX_PENDING:
                    raise Refused(429, 'too many pending proposals')
                pend = self.pending[ph] = {'proposal': proposal, 'votes': {}, 'first_ms': self.clock(),
                                           'opener': vote['keyholder']}
            if vote['keyholder'] in pend['votes']:
                self.metrics.votes.inc(result='duplicate')
            else:
                pend['votes'][vote['keyholder']] = vote['sig']
                self.metrics.votes.inc(result='accepted')
            have, need = len(pend['votes']), self.state.threshold
            if not single_ok and have < need:
                return {'status': 'pending', 'proposal_hash': ph, 'votes': sorted(pend['votes']), 'threshold': need}
            cert = make_certificate(proposal, [{'keyholder': k, 'sig': s} for k, s in pend['votes'].items()])
            entry = self._apply(cert, t0)
        return {'status': 'applied', 'proposal_hash': ph, 'votes': [v['keyholder'] for v in cert['votes']],
                'threshold': need, 'entry': entry['n'], 'seq': self.state.seq}

    def submit_certificate(self, cert) -> dict:
        """A complete certificate (assembled offline). Returns {"status": "applied", "entry", "seq"}."""
        t0 = self.mono()
        with self._lock:
            if isinstance(cert, dict) and isinstance(cert.get('proposal'), dict):
                try:
                    self._key_hygiene(cert['proposal'])
                except SwitchError as e:
                    self._reject(e)
            entry = self._apply(cert, t0)
        return {'status': 'applied', 'entry': entry['n'], 'seq': self.state.seq,
                'proposal_hash': proposal_hash(cert['proposal'])}

    @staticmethod
    def _key_hygiene(p: dict):
        if p.get('action') == 'reinstate' and isinstance(p.get('new_public_key'), str):
            why = weakness(p['new_public_key'])
            if why:
                raise SwitchError('SW-BAD-TARGET', f'new_public_key refused: {why}')

    def _apply(self, cert, t0: float) -> dict:
        v0 = time.perf_counter()
        ts = self.clock()
        try:
            apply(self.state, cert, ts)   # verify before writing
        except SwitchError as e:
            self._reject(e)
        self.metrics.verify_ms.observe((time.perf_counter() - v0) * 1000)
        entry = self._append('certificate', cert, ts)
        p = cert['proposal']
        self.metrics.certificates.inc(action=p['action'])
        self.pending = {h: x for h, x in self.pending.items() if x['proposal'].get('seq', 0) > self.state.seq}
        self._gauges()
        ms = self.mono() - t0
        self.metrics.aggregation.observe(ms)
        kind = self.watchdog.check(ms)
        if kind:
            self.metrics.watchdog.inc(kind=kind)
            self._append('event', {'event': kind, 'entry': entry['n'], 'aggregation_ms': int(ms),
                                   'base_ms': int(self.watchdog.base_ms)})
            self._notify(kind, {'entry': entry['n'], 'aggregation_ms': int(ms)})
        if p['action'] == 'halt':
            live = {k for k, v in self.instances.items() if self._live(v) and (p['target'] == '*' or k[0] == p['target'])}
            if live:
                self._propagating[entry['n']] = {'start': self.mono(), 'waiting': live}
        log.info('applied %s %s (seq %d) in %.1f ms', p['action'], p['target'], p['seq'], ms)
        return entry

    def _expire_pending(self):
        now = self.clock()
        self.pending = {h: x for h, x in self.pending.items() if x['proposal']['expires_ms'] > now}

    def pending_list(self) -> list:
        with self._lock:
            self._expire_pending()
            return [{'proposal_hash': h, 'proposal': x['proposal'], 'votes': sorted(x['votes']),
                     'threshold': self.state.threshold} for h, x in sorted(self.pending.items())]

    def pending_get(self, ph: str):
        with self._lock:
            x = self.pending.get(ph)
            return None if x is None else {'proposal_hash': ph, 'proposal': x['proposal'], 'votes': sorted(x['votes']),
                                           'threshold': self.state.threshold}

    # ---------------------------------------------------------------- agents
    def _live(self, inst) -> bool:
        return self.mono() - inst['last_mono'] < self.fleet['offline_timeout_ms']

    def _alert_once(self, reason: str, agent_id: str, instance_id: str):
        """Count every occurrence; write an event (and call the webhook) at most once a minute per reason,
        so that a flood of made-up agent ids cannot fill the log."""
        self.metrics.replication.inc(reason=reason)
        now = self.mono()
        if now - self._alerted.get(reason, -1e18) < ALERT_EVERY_MS:
            return
        self._alerted[reason] = now
        self.event('replication-alert', reason=reason, agent_id=agent_id, instance_id=instance_id)

    def heartbeat(self, agent_id, instance_id, nonce) -> dict:
        if not is_id(agent_id) or not is_id(instance_id) or not isinstance(nonce, str) or not NONCE.match(nonce):
            raise ValueError('agent_id and instance_id must match [A-Za-z0-9._-]{1,64}; nonce is 32 lower-case hex')
        with self._lock:
            key = (agent_id, instance_id)
            roster = self.state.roster
            known = self.instances.get(key)
            if roster is not None and agent_id not in roster:
                self._alert_once('unknown-agent', agent_id, instance_id)
                if self.enforce_roster:
                    self.metrics.heartbeats.inc(result='refused')
                    raise Refused(403, 'agent is not in the fleet roster')
            if roster is not None and agent_id in roster and (known is None or not self._live(known)):
                ids = self.by_agent.get(agent_id, set())
                for i in [i for i in ids if not self._live(self.instances[(agent_id, i)])]:   # forget silent ones
                    ids.discard(i)
                    del self.instances[(agent_id, i)]
                known = self.instances.get(key)
                others = sum(1 for i in ids if i != instance_id)
                if others >= roster[agent_id]:
                    self._alert_once('too-many-instances', agent_id, instance_id)
                    if self.enforce_roster:
                        self.metrics.heartbeats.inc(result='refused')
                        raise Refused(409, f'agent {agent_id} already has {others} live instance(s), the limit is '
                                           f'{roster[agent_id]}')
            now = self.mono()
            if known is None:
                if len(self.instances) >= MAX_INSTANCES_TRACKED:
                    self._forget_silent()
                    if len(self.instances) >= MAX_INSTANCES_TRACKED:
                        self.metrics.heartbeats.inc(result='refused')
                        raise Refused(429, 'too many agent instances')
                known = self.instances[key] = {'first_mono': now, 'last_mono': now, 'log_size': 0}
                self.by_agent.setdefault(agent_id, set()).add(instance_id)
            known['last_mono'] = now
            size = len(self.entries)
            hb = sign_heartbeat(self._seed, self.fleet_hash, agent_id, instance_id, nonce, size, self.replica.head,
                                self.clock())
            self.metrics.heartbeats.inc(result='ok')
            return hb

    def _forget_silent(self):
        self.instances = {k: v for k, v in self.instances.items() if self._live(v)}
        self.by_agent = {}
        for a, i in self.instances:
            self.by_agent.setdefault(a, set()).add(i)

    def refresh_gauges(self):
        """Gauges that cost a pass over the instances: computed when metrics are read, not per heartbeat."""
        with self._lock:
            self.metrics.instances_live.set(sum(1 for v in self.instances.values() if self._live(v)))
            self._gauges()

    def fetched(self, agent_id: str, instance_id: str, size: int) -> None:
        """An instance fetched the log up to ``size`` entries (for the propagation time of halts)."""
        with self._lock:
            inst = self.instances.get((agent_id, instance_id))
            if inst is None:
                return
            inst['log_size'] = max(inst['log_size'], size)
            done = []
            for n, pr in self._propagating.items():
                if size > n:
                    pr['waiting'].discard((agent_id, instance_id))
                pr['waiting'] = {k for k in pr['waiting'] if k in self.instances and self._live(self.instances[k])}
                if not pr['waiting']:
                    done.append(n)
            for n in done:
                ms = self.mono() - self._propagating.pop(n)['start']
                self.metrics.propagation.observe(ms)

    def instances_list(self, limit: int = 1000) -> list:
        with self._lock:
            now = self.mono()
            items = sorted(self.instances.items(), key=lambda kv: kv[1]['last_mono'], reverse=True)[:limit]
            return [{'agent_id': a, 'instance_id': i, 'live': self._live(v), 'last_seen_ms_ago': int(now - v['last_mono']),
                     'log_size': v['log_size']} for (a, i), v in sorted(items)]

    # ---------------------------------------------------------------- mirror
    def check_mirror(self) -> dict | None:
        if not (self.file and self.mirror_path):
            return None
        with self._lock:
            upto = len(self.entries)            # both files have at least this many entries; read outside the lock
        c = compare_files(self.file.path, self.mirror_path, self.fleet_hash, upto)
        if c['ok'] and c['primary']['size'] != upto:
            c = dict(c, ok=False, message=f'the files hold {c["primary"]["size"]} entries, the coordinator wrote {upto}')
        self.metrics.mirror_ok.set(1 if c['ok'] else 0)
        if not c['ok']:
            log.error('log mirror check failed: %s', c['message'])
            if not self._mirror_bad:            # one event per change, not one every 30 s
                self.event('log-mirror-mismatch', message=c['message'][:300])
        self._mirror_bad = not c['ok']
        return c

    def status(self) -> dict:
        with self._lock:
            return {'fleet_id': self.fleet['fleet_id'], 'fleet_hash': self.fleet_hash, 'log_size': len(self.entries),
                    'head': self.replica.head, 'state': self.state.summary(), 'pending': len(self.pending)}
