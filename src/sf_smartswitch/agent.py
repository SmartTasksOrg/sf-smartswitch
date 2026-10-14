"""The agent side: keep asking the coordinator, verify everything, and stop when told or when cut off.

    agent = Agent("https://switch.example:8720", token, "fleet.json", "planner-1")
    agent.start()                     # background thread: heartbeat every poll_ms, fetch the log
    while agent.may_run():
        do_one_step()
        agent.checkpoint()            # raises Halted

Or wrap any program, in any language, from the command line:
    sf-smartswitch agent --url ... --fleet fleet.json --agent-id planner-1 -- python my_agent.py
which stops the program's whole process group (terminate, then kill) when the agent may no longer run.

What it checks is in agentview.py. A halt reaches the agent within one poll (``poll_ms``, 1 s by
default) once the certificate is in the log; with no answer from the coordinator for the fleet's
``offline_timeout_ms`` (30 s by default) the agent stops by itself. Certificates delivered another way
(``deliver``, or files dropped into ``cert_dir``) can halt it even when the coordinator withholds them.
With ``state_file``, what the agent verified survives a restart: a coordinator that comes back with a
shorter or different log is a fork, not a fresh start.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid

from .agentview import AgentView
from .client import Client
from .protocol import validate_fleet

log = logging.getLogger('sf_smartswitch.agent')
# The dead-man rule needs a clock that keeps counting while the machine is suspended: on Linux,
# CLOCK_MONOTONIC stops during suspend and CLOCK_BOOTTIME does not.
_CLOCK = getattr(time, 'CLOCK_BOOTTIME', None)


class Halted(Exception):
    def __init__(self, code: str):
        super().__init__(f'SmartSwitch: this agent may not run ({code})')
        self.code = code


def mono_ms() -> int:
    if _CLOCK is not None:
        try:
            return time.clock_gettime_ns(_CLOCK) // 1_000_000
        except OSError:
            pass
    return time.monotonic_ns() // 1_000_000


def wall_ms() -> int:
    return time.time_ns() // 1_000_000


def load_fleet(fleet) -> dict:
    if isinstance(fleet, dict):
        return validate_fleet(fleet)
    with open(fleet, encoding='utf-8') as f:
        return validate_fleet(json.load(f))


# results of a delivered certificate that will not change however the log moves on
_FINAL = {'SW-PROVISIONAL-HALT', 'SW-STALE-SEQ', 'SW-NOT-APPLICABLE', 'SW-BAD-CERTIFICATE', 'SW-BAD-PROPOSAL',
          'SW-WRONG-FLEET', 'SW-UNKNOWN-KEYHOLDER', 'SW-DUPLICATE-VOTE', 'SW-EXPIRED'}


class Agent:
    def __init__(self, url: str, token: str | None, fleet, agent_id: str, instance_id: str | None = None,
                 poll_ms: int = 1000, timeout_s: float = 2.0, cert_dir: str | None = None, on_change=None,
                 clock=mono_ms, wall=wall_ms, state_file: str | None = None):
        self.fleet = load_fleet(fleet)
        self.instance_id = instance_id or uuid.uuid4().hex[:16]
        self.view = AgentView(self.fleet, agent_id, self.instance_id)
        self.client = Client(url, token, timeout_s)
        self.poll_ms, self.cert_dir, self.on_change = poll_ms, cert_dir, on_change
        self.clock, self.wall = clock, wall
        self.state_file = state_file
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._last = None
        self._files: dict[str, tuple] = {}     # name -> (content hash, replica size when read, final?)
        self._bad_files: set[str] = set()
        self.last_error: str | None = None
        if state_file:
            self._load_state()

    @property
    def agent_id(self) -> str:
        return self.view.agent_id

    # -- persisted floor (optional)
    def _load_state(self):
        try:
            with open(self.state_file, encoding='utf-8') as f:
                d = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            raise ValueError(f'{self.state_file}: unreadable agent state ({e}); refusing to start without it') from None
        if d.get('fleet_hash') != self.view.fleet_hash:
            raise ValueError(f'{self.state_file} belongs to another fleet')
        self.view.floor_size, self.view.floor_head = int(d['size']), d['head']
        self.view.fork = bool(d.get('fork'))

    def _save_state(self):
        if not self.state_file:
            return
        r = self.view.replica
        if r.size < self.view.floor_size and not self.view.fork:
            return
        d = {'fleet_hash': self.view.fleet_hash, 'size': max(r.size, self.view.floor_size),
             'head': r.head if r.size >= self.view.floor_size else self.view.floor_head, 'fork': self.view.fork}
        tmp = self.state_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(d, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)

    # -- one round
    def poll_once(self) -> dict:
        """One heartbeat (and log catch-up). Never raises: any error is recorded and changes nothing."""
        nonce = os.urandom(16).hex()
        sent = self.clock()
        try:
            hb = self.client.heartbeat(self.agent_id, self.instance_id, nonce)
            with self._lock:
                r = self.view.heartbeat(hb, nonce, sent)
            if r['code'] == 'SW-BEHIND':
                self._catch_up(hb['log_size'])
                with self._lock:
                    r = self.view.heartbeat(hb, nonce, sent)
            self._error(None if r['ok'] else r['code'])
        except Exception as e:                    # noqa: BLE001 - the loop must survive anything
            self._error(f'{type(e).__name__}: {str(e)[:200]}')
        try:
            if self.cert_dir:
                self._scan_cert_dir()
            with self._lock:
                self._save_state()
        except Exception as e:                    # noqa: BLE001
            self._error(f'{type(e).__name__}: {str(e)[:200]}')
        return self.status()

    def _error(self, err):
        if err != self.last_error and err is not None:     # log changes, not every poll
            log.warning('heartbeat failed: %s', err)
        self.last_error = err

    def _catch_up(self, size: int):
        while True:
            with self._lock:
                have = self.view.replica.size
            if have >= size:
                return
            page = self.client.log(have, 1000, self.agent_id, self.instance_id)['entries']
            if not isinstance(page, list) or not page:
                return
            with self._lock:
                r = self.view.log(page)
            if not r['ok']:
                raise ValueError(f'the coordinator log does not verify ({r["code"]} at entry {r["size"]})')

    def _scan_cert_dir(self):
        """Read new or changed files; read again files whose answer depended on the agent's state
        (no log yet, an older epoch or key) once the log has moved on."""
        try:
            names = sorted(n for n in os.listdir(self.cert_dir) if n.endswith('.json'))
        except OSError:
            return
        size = self.view.replica.size
        for n in names:
            path = os.path.join(self.cert_dir, n)
            try:
                with open(path, 'rb') as f:
                    raw = f.read(1 << 20)
            except OSError:
                continue
            h = hashlib.sha256(raw).hexdigest()
            seen = self._files.get(n)
            if seen and seen[0] == h and (seen[2] or seen[1] == size):
                continue
            try:
                cert = json.loads(raw.decode('utf-8'))
            except (ValueError, RecursionError) as e:
                if n not in self._bad_files:
                    self._bad_files.add(n)
                    log.warning('certificate file %s unreadable: %s', n, e)
                continue                       # may still be being written: read it again next time
            self._bad_files.discard(n)
            r = self.deliver(cert)
            self._files[n] = (h, size, r['code'] in _FINAL)
            if not seen or seen[0] != h:
                log.info('certificate file %s: %s', n, r['code'])

    def deliver(self, cert) -> dict:
        """A certificate that reached this agent some other way than the coordinator. Its expiry is
        checked against the wall clock."""
        with self._lock:
            r = self.view.certificate(cert, self.wall())
        self._changed()
        return r

    # -- answers
    def status(self) -> dict:
        with self._lock:
            s = self.view.status(self.clock())
        self._changed(s)
        return s

    def may_run(self) -> bool:
        return self.status()['run']

    def checkpoint(self) -> None:
        s = self.status()
        if not s['run']:
            raise Halted(s['code'])

    def _changed(self, s=None):
        if s is None:
            with self._lock:
                s = self.view.status(self.clock())
        if s != self._last:
            self._last = s
            log.info('status: %s', s['code'])
            if self.on_change:
                try:
                    self.on_change(s)
                except Exception:
                    log.exception('on_change failed')

    # -- background
    def start(self) -> 'Agent':
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name='smartswitch-agent')
            self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except BaseException as e:            # poll_once does not raise; this is the last line of defence
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                log.exception('poll failed')
            self._stop.wait(self.poll_ms / 1000)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def wait_until_running(self, timeout_s: float) -> bool:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            if self.may_run():
                return True
            time.sleep(0.05)
        return self.may_run()


def _pdeathsig():
    """Linux: the child gets SIGKILL if the wrapper dies (even by SIGKILL)."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)    # PR_SET_PDEATHSIG
    except Exception:
        pass


def run_guarded(agent: Agent, argv: list, grace_s: float = 5.0, wait_s: float = 30.0, check_ms: int = 100) -> int:
    """Start ``argv`` once the agent may run; stop it as soon as the agent may not. The program runs in its
    own process group (a session on POSIX), and the whole group is terminated, then killed after
    ``grace_s``, so programs started through a shell or a launcher stop too. A SIGTERM or SIGINT to the
    wrapper stops the group the same way; on Linux the program is also killed if the wrapper is killed.
    Returns the program's exit code, or 75 when SmartSwitch stopped it.

    A program that leaves its process group on purpose (double fork, setsid) escapes this: run agents
    in a container or cgroup whose lifetime is the wrapper's (docs/integration.md)."""
    import subprocess
    posix = os.name == 'posix'
    agent.start()
    if not agent.wait_until_running(wait_s):
        log.error('not starting: %s', agent.status()['code'])
        agent.stop()
        return 75
    kw = {'start_new_session': True} if posix else {'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)}
    if posix and sys.platform.startswith('linux'):
        kw['preexec_fn'] = _pdeathsig
    proc = subprocess.Popen(argv, **kw)
    stop_asked = threading.Event()

    def on_signal(signum, frame):
        stop_asked.set()
    old = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            old[sig] = signal.signal(sig, on_signal)

    def stop_group():
        try:
            if posix:
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            pass
        try:
            if posix:
                os.killpg(proc.pid, signal.SIGKILL)       # the rest of the group, even if the leader exited
            elif proc.poll() is None:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()

    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                if posix:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)   # leftovers of a program that exited
                    except (ProcessLookupError, PermissionError):
                        pass
                return rc
            if stop_asked.is_set():
                log.error('stopping the program: the wrapper was asked to stop')
                stop_group()
                return 75
            s = agent.status()
            if not s['run']:
                log.error('stopping the program: %s', s['code'])
                stop_group()
                return 75
            time.sleep(check_ms / 1000)
    finally:
        if proc.poll() is None:
            stop_group()
        for sig, h in old.items():
            signal.signal(sig, h)
        agent.stop()
