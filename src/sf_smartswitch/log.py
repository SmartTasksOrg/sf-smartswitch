"""The switch log: a hash-chained list of entries that is the whole history of a fleet.

entry = {"n": index, "ts_ms": t, "kind": "genesis" | "certificate" | "event", "body": {...}, "prev": hash of
         entry n-1 (64 zeros for entry 0), "hash": sha256(canonical(entry without "hash"))}

Entry 0 is the genesis: its body is the fleet document, whose hash every agent pins. A "certificate"
entry applies its body to the state with at_ms = ts_ms. ts_ms is the coordinator's wall clock when it
wrote the entry; it need not increase from entry to entry (a clock that jumped forward once must not make
every later certificate look expired), and nobody signs it: only the order (n) and the chain bind it. An "event" entry (an alert, a watchdog
reading) is chained but does not change the state. Replaying the log from entry 0 gives the state;
an agent that pins the fleet hash can check every entry itself and needs to trust nobody.

On disk the log is JSON Lines, one canonical entry per line (``LogFile``).
"""
from __future__ import annotations

import json
import os
import threading

from . import canonical
from .protocol import State, SwitchError, apply, doc_hash, hashable, validate_fleet

GENESIS_PREV = '0' * 64
ENTRY_FIELDS = {'n', 'ts_ms', 'kind', 'body', 'prev', 'hash'}
KINDS = ('genesis', 'certificate', 'event')


def entry_hash(entry: dict) -> str:
    return doc_hash({k: v for k, v in entry.items() if k != 'hash'})


def make_entry(n: int, ts_ms: int, kind: str, body: dict, prev: str) -> dict:
    e = {'n': n, 'ts_ms': ts_ms, 'kind': kind, 'body': body, 'prev': prev}
    e['hash'] = entry_hash(e)
    return e


class Replica:
    """A verified copy of a log. ``extend`` checks entries one by one and applies certificates; on the
    first bad entry it raises SwitchError and keeps everything before it."""

    def __init__(self, fleet_hash: str | None = None):
        self.pinned = fleet_hash          # None: accept any genesis (the coordinator itself pins by config)
        self.state: State | None = None
        self.size = 0
        self.head = GENESIS_PREV
        self.hashes: list[str] = []       # every entry's hash, to compare with heartbeats

    def extend(self, entries) -> int:
        for e in entries:
            self._one(e)
        return self.size

    def _one(self, e) -> None:
        if not isinstance(e, dict) or set(e) != ENTRY_FIELDS or e['kind'] not in KINDS \
                or not isinstance(e['body'], dict) or not isinstance(e['n'], int) or isinstance(e['n'], bool) \
                or not isinstance(e['ts_ms'], int) or isinstance(e['ts_ms'], bool) or e['ts_ms'] < 0:
            raise SwitchError('SW-BAD-ENTRY', f'entry {self.size} is malformed')
        if e['n'] != self.size:
            raise SwitchError('SW-LOG-ORDER', f'entry {self.size}: n is {e["n"]}')
        if e['prev'] != self.head or not hashable(e) or e['hash'] != entry_hash(e):
            raise SwitchError('SW-LOG-CHAIN', f'entry {self.size}: the hash chain is broken')
        if self.size == 0:
            if e['kind'] != 'genesis':
                raise SwitchError('SW-BAD-ENTRY', 'entry 0 must be the genesis')
            try:
                validate_fleet(e['body'])
            except SwitchError as err:
                raise SwitchError('SW-BAD-FLEET', f'entry 0: {err.message}') from None
            if self.pinned is not None and doc_hash(e['body']) != self.pinned:
                raise SwitchError('SW-WRONG-FLEET', 'entry 0 is not the pinned fleet')
            self.state = State.genesis(e['body'])
        elif e['kind'] == 'genesis':
            raise SwitchError('SW-BAD-ENTRY', f'entry {self.size}: only entry 0 can be a genesis')
        elif e['kind'] == 'certificate':
            self.state = apply(self.state, e['body'], e['ts_ms'])
        self.size += 1
        self.head = e['hash']
        self.hashes.append(e['hash'])


def replay(entries, fleet_hash: str | None = None) -> dict:
    """{"ok": true, "size", "head", "state"} or {"ok": false, "index", "code"} (the vectors' form)."""
    r = Replica(fleet_hash)
    try:
        r.extend(entries)
    except SwitchError as e:
        return {'ok': False, 'index': r.size, 'code': e.code}
    if r.size == 0:
        return {'ok': False, 'index': 0, 'code': 'SW-BAD-ENTRY'}
    return {'ok': True, 'size': r.size, 'head': r.head, 'state': r.state.summary()}


class LogFile:
    """Append-only JSON Lines file with fsync after every entry; optional mirror file written the same way.
    Loading verifies the whole chain (a broken file is refused, never repaired)."""

    def __init__(self, path: str, mirror: str | None = None):
        self.path, self.mirror = path, mirror
        self._lock = threading.Lock()

    @staticmethod
    def read(path: str, limit: int | None = None) -> list:
        """The entries of a log file (the first ``limit`` if given). A line that is not valid UTF-8 JSON
        (for example the last line, torn by a crash during a write) raises SwitchError('SW-BAD-ENTRY'):
        the file is evidence, so it is never repaired here; a person decides (docs/operations.md, section 3)."""
        if not os.path.exists(path):
            return []
        out = []
        i = 0
        with open(path, 'rb') as f:
            for i, raw in enumerate(f, 1):
                if limit is not None and len(out) >= limit:
                    break
                if not raw.strip():
                    continue
                try:
                    out.append(json.loads(raw.decode('utf-8')))
                except (ValueError, RecursionError):      # UnicodeDecodeError is a ValueError
                    raise SwitchError('SW-BAD-ENTRY', f'{path}, line {i}: not a JSON entry (a write torn by a crash?)') from None
        return out

    def write(self, entry: dict) -> None:
        line = (canonical.dumps(entry) + '\n').encode('utf-8')
        with self._lock:
            for p in (self.path, self.mirror):
                if p:
                    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
                    try:
                        os.write(fd, line)
                        os.fsync(fd)
                    finally:
                        os.close(fd)


def compare_files(primary: str, mirror: str, fleet_hash: str | None = None, upto: int | None = None) -> dict:
    """Verify both files and check that they hold the same entries (only the first ``upto`` of each when
    given: the files may grow while they are read). Any read or parse error is a mismatch. Returns
    {"ok", "primary": replay result, "mirror": replay result, "message"}."""
    try:
        a, b = LogFile.read(primary, upto), LogFile.read(mirror, upto)
    except (SwitchError, OSError, RecursionError) as e:
        bad = {'ok': False, 'index': None, 'code': getattr(e, 'code', 'SW-BAD-ENTRY')}
        return {'ok': False, 'primary': bad, 'mirror': bad, 'message': getattr(e, 'message', None) or str(e)}
    ra, rb = replay(a, fleet_hash), replay(b, fleet_hash)
    if not ra['ok'] or not rb['ok']:
        return {'ok': False, 'primary': ra, 'mirror': rb, 'message': 'a log does not verify'}
    if ra['head'] != rb['head'] or ra['size'] != rb['size']:
        return {'ok': False, 'primary': ra, 'mirror': rb,
                'message': f'primary has {ra["size"]} entries (head {ra["head"][:12]}), '
                           f'mirror {rb["size"]} (head {rb["head"][:12]})'}
    return {'ok': True, 'primary': ra, 'mirror': rb, 'message': f'{ra["size"]} entries, identical'}
