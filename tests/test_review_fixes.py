"""Regression tests for the findings of the independent review before 0.1.0 (one test or more per finding)."""
import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from conftest import decide, proposal, wait_for
from sf_smartswitch.agent import Agent, run_guarded
from sf_smartswitch.client import Client, ClientError
from sf_smartswitch.coordinator import Coordinator, Refused
from sf_smartswitch.log import make_entry
from sf_smartswitch.protocol import State, SwitchError, make_certificate, new_proposal, sign_vote
from sf_smartswitch.server import Config, make_server

T0 = 1_700_000_000_000


# H1: one bad clock reading must not make every later certificate expire
def test_a_clock_jump_does_not_block_later_certificates(keys, tmp_path):
    now = [int(time.time() * 1000)]
    p = str(tmp_path / 'log.jsonl')
    co = Coordinator(keys.fleet(roster=[]), keys.seed['coordinator'], p, clock=lambda: now[0])
    real = now[0]
    now[0] = real + 365 * 24 * 3600 * 1000            # one wrong reading (NTP step, snapshot)
    with pytest.raises(Refused):
        co.heartbeat('stranger', 'i', '0' * 32)        # writes an alert entry with the bad time
    now[0] = real
    assert decide(co, keys, 'halt', '*', ['alice', 'bob'])['status'] == 'applied'
    co2 = Coordinator(keys.fleet(roster=[]), keys.seed['coordinator'], p, clock=lambda: now[0])   # and after a restart
    assert co2.state.halted_all
    assert decide(co2, keys, 'resume', '*', ['alice', 'bob'])['status'] == 'applied'


# H2: what `sign` shows cannot be redrawn by the proposer
def test_sign_display_neutralises_control_characters(keys):
    from sf_smartswitch.cli import _describe
    st = State.genesis(keys.fleet())
    p = new_proposal(st, 'resume', '*', 'x\r\x1b[1A\x1b[2K  action  halt *‮', T0, 60000)
    text = _describe(p)
    assert '\x1b' not in text and '\r' not in text and '‮' not in text
    assert 'action  resume *' in text and '\\u001b' in text


# H3: the wrapper stops the whole process group, and stops it when it is itself told to stop
@pytest.mark.skipif(os.name != 'posix', reason='process groups')
def test_wrapper_stops_grandchildren(server, keys, tmp_path):
    s = server()
    a = Agent(s.url, s.cfg.agent_token, s.co.fleet, 'a1', poll_ms=50, timeout_s=1)
    pidfile = tmp_path / 'grandchild.pid'
    prog = ['sh', '-c', f'sleep 60 & echo $! > {pidfile}; wait']
    out = {}
    t = threading.Thread(target=lambda: out.setdefault('rc', run_guarded(a, prog, grace_s=1, wait_s=5)))
    t.start()
    assert wait_for(lambda: pidfile.exists() and pidfile.read_text().strip(), 10)
    gpid = int(pidfile.read_text())
    decide(s.co, keys, 'halt', 'a1', ['alice', 'bob'])
    t.join(10)
    assert out.get('rc') == 75
    assert wait_for(lambda: not _alive(gpid), 3), 'the grandchild survived'


@pytest.mark.skipif(os.name != 'posix', reason='signals')
def test_wrapper_stops_the_program_when_it_gets_sigterm(server, tmp_path):
    s = server()
    with open(tmp_path / 'fleet.json', 'w') as f:
        json.dump(s.co.fleet, f)
    pidfile = tmp_path / 'child.pid'
    env = dict(os.environ, SMARTSWITCH_AGENT_TOKEN=s.cfg.agent_token)
    w = subprocess.Popen([sys.executable, '-m', 'sf_smartswitch', 'agent', '--url', s.url, '--fleet', 'fleet.json',
                          '--agent-id', 'a1', '--poll-ms', '50', '--grace-s', '1', '--', sys.executable, '-c',
                          f'import os, time; open({str(pidfile)!r}, "w").write(str(os.getpid())); time.sleep(60)'],
                         cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_for(lambda: pidfile.exists() and pidfile.read_text().strip(), 15)
    child = int(pidfile.read_text())
    w.send_signal(signal.SIGTERM)
    assert w.wait(10) == 75
    assert wait_for(lambda: not _alive(child), 3)


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:                                                # a zombie no longer runs
        with open(f'/proc/{pid}/stat') as f:
            return f.read().split(')')[-1].split()[0] != 'Z'
    except OSError:
        return True


# M1: the polling thread survives anything
def test_poll_loop_survives_unexpected_errors(server, keys):
    s = server()
    a = Agent(s.url, s.cfg.agent_token, s.co.fleet, 'a1', poll_ms=20, timeout_s=1)
    real = a.client.heartbeat
    calls = {'n': 0}

    def flaky(*args):
        calls['n'] += 1
        if calls['n'] in (2, 3):
            raise RecursionError('deeply nested answer')
        return real(*args)
    a.client.heartbeat = flaky
    a.start()
    try:
        assert wait_for(lambda: calls['n'] > 5, 3)
        assert a._thread.is_alive()
        decide(s.co, keys, 'halt', '*', ['alice', 'bob'])
        assert wait_for(lambda: a.status()['code'] == 'SW-HALTED-FLEET', 2)
    finally:
        a.stop()


# M2: a delivered certificate's expiry is checked against the wall clock
def test_an_expired_delivered_halt_is_refused(server, keys):
    s = server()
    a = Agent(s.url, s.cfg.agent_token, s.co.fleet, 'a1', poll_ms=20, timeout_s=1).start()
    try:
        assert wait_for(a.may_run)
        old = int(time.time() * 1000) - 24 * 3600 * 1000
        p = new_proposal(s.co.state, 'halt', '*', 'old drill', old, 60000)
        r = a.deliver(make_certificate(p, [keys.vote('alice', p), keys.vote('bob', p)]))
        assert r['code'] == 'SW-EXPIRED' and a.may_run()
    finally:
        a.stop()


# M4: a new certificate under a name already seen is read; state-dependent answers are retried
def test_cert_dir_rereads_a_file_whose_content_changed(server, keys, tmp_path):
    s = server()
    d = tmp_path / 'certs'
    d.mkdir()
    p0 = proposal(s.co, 'halt', 'a2')
    (d / 'cert.json').write_text(json.dumps(make_certificate(p0, [keys.vote('alice', p0), keys.vote('bob', p0)])))
    a = Agent(s.url, s.cfg.agent_token, s.co.fleet, 'a1', poll_ms=20, timeout_s=1, cert_dir=str(d)).start()
    try:
        assert wait_for(a.may_run)
        time.sleep(0.1)
        p = proposal(s.co)
        (d / 'cert.json').write_text(json.dumps(make_certificate(p, [keys.vote('alice', p), keys.vote('carol', p)])))
        assert wait_for(lambda: a.status()['code'] == 'SW-PROVISIONAL-HALT', 2)
    finally:
        a.stop()


# M5: the offline flow does not silently produce a certificate for the wrong epoch
def test_offline_propose_requires_the_epoch(tmp_path, monkeypatch):
    from sf_smartswitch.cli import main
    monkeypatch.chdir(tmp_path)
    for n in ('alice', 'bob', 'carol', 'coordinator'):
        main(['keygen', '--name', n, '--out', f'{n}.key'])
    main(['fleet', 'init', '--fleet-id', 'f', '--keyholder', 'alice=alice.key', '--keyholder', 'bob=bob.key',
          '--keyholder', 'carol=carol.key', '--coordinator-key', 'coordinator.key', '--out', 'fleet.json'])
    with pytest.raises(SystemExit):
        main(['propose', '--offline', '--fleet', 'fleet.json', '--seq', '3', '--key', 'alice.key', '--action', 'halt',
              '--target', '*', '--reason', 'r', '--out', 'p.json'])
    main(['propose', '--offline', '--fleet', 'fleet.json', '--seq', '3', '--epoch', '1', '--key', 'alice.key',
          '--action', 'halt', '--target', '*', '--reason', 'r', '--out', 'p.json'])
    main(['sign', '--proposal', 'p.json', '--key', 'bob.key', '--yes'])
    with pytest.raises(SystemExit) as e:                # epoch 1 cannot be checked without a log copy
        main(['assemble', '--fleet', 'fleet.json', '--proposal', 'p.json', '--vote', 'p.json.vote-alice.json',
              '--vote', 'p.json.vote-bob.json', '--out', 'c.json'])
    assert 'assume-epoch' in str(e.value)


# M6: one keyholder cannot fill the table of pending proposals
def test_one_keyholder_cannot_block_proposals(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    for i in range(1200):
        p = new_proposal(co.state, 'halt', f'x{i}', 'flood', int(time.time() * 1000), 600000)
        co.submit_vote(p, keys.vote('carol', p))
    assert len(co.pending) <= 10
    assert decide(co, keys, 'halt', '*', ['alice', 'bob'])['status'] == 'applied'


# M7: a holder of the agent token cannot fill the log or make heartbeats slow
def test_unknown_agent_flood_writes_one_alert(keys):
    co = Coordinator(keys.fleet(roster=[]), keys.seed['coordinator'])
    for i in range(500):
        with pytest.raises(Refused):
            co.heartbeat(f'fake{i}', 'i', '0' * 32)
    assert sum(1 for e in co.entries if e['kind'] == 'event') == 1
    assert co.metrics.replication.value(reason='unknown-agent') == 500


def test_instance_table_is_bounded(keys, monkeypatch):
    import sf_smartswitch.coordinator as c
    monkeypatch.setattr(c, 'MAX_INSTANCES_TRACKED', 50)
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    for i in range(50):
        co.heartbeat('a', f'i{i}', '0' * 32)
    with pytest.raises(Refused) as e:
        co.heartbeat('a', 'one-more', '0' * 32)
    assert e.value.status == 429
    co.heartbeat('a', 'i3', '0' * 32)                  # known instances keep their heartbeat


# M8: behind a trusted proxy, limits apply to the client's address
def test_trusted_proxy_forwarded_address(server):
    import http.client
    import urllib.parse
    s = server(trusted_proxies='127.0.0.1/32', operator_allow='10.1.2.3/32')
    u = urllib.parse.urlsplit(s.url)

    def get(xff):
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        c.request('GET', '/v1/proposals', headers={'Authorization': 'Bearer ' + s.cfg.operator_token,
                                                   'X-Forwarded-For': xff})
        st = c.getresponse().status
        c.close()
        return st
    assert get('10.1.2.3') == 200
    assert get('10.1.2.3, 192.168.9.9') == 403         # the proxy's own (last) entry decides


# M9: a mirror that is not valid UTF-8 is a mismatch, not an exception
def test_mirror_with_invalid_utf8_is_a_mismatch(keys, tmp_path):
    p, m = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    co = Coordinator(keys.fleet(), keys.seed['coordinator'], str(p), str(m))
    m.write_bytes(m.read_bytes()[:-5] + b'\xff\xfe"}\n')
    c = co.check_mirror()
    assert not c['ok'] and co.metrics.mirror_ok.v == 0
    assert any(e['kind'] == 'event' and e['body']['event'] == 'log-mirror-mismatch' for e in co.entries)


# L1: weak public keys never enter a fleet
SMALL_ORDER = [(1).to_bytes(32, 'little').hex(), (0).to_bytes(32, 'little').hex(), (2 ** 255 - 20).to_bytes(32, 'little').hex()]


@pytest.mark.parametrize('weak', SMALL_ORDER + ['ff' * 32])
def test_weak_keys_are_refused(keys, weak):
    f = keys.fleet()
    f['keyholders'][2]['public_key'] = weak
    with pytest.raises(SwitchError):
        Coordinator(f, keys.seed['coordinator'])
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    decide(co, keys, 'suspend', 'carol', ['alice', 'bob'])
    p = new_proposal(co.state, 'reinstate', 'carol', 'r', int(time.time() * 1000), 60000, weak)
    with pytest.raises(SwitchError) as e:
        co.submit_vote(p, keys.vote('alice', p))
    assert e.value.code == 'SW-BAD-TARGET'


# L2: a missing event is not copied into the mirror without a person's say-so
def test_mirror_catch_up_of_an_event_needs_repair_flag(keys, tmp_path):
    p, m = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], str(p), str(m))
    co.event('note', text='x')
    lines = m.read_text().splitlines(keepends=True)
    m.write_text(''.join(lines[:-1]))
    with pytest.raises(SwitchError) as e:
        Coordinator(fleet, keys.seed['coordinator'], str(p), str(m))
    assert 'repair-mirror' in e.value.message
    co2 = Coordinator(fleet, keys.seed['coordinator'], str(p), str(m), repair_mirror=True)
    assert co2.entries[-1]['body']['event'] == 'mirror-caught-up' and co2.check_mirror()['ok']


# L3: the client never follows a redirect (it would carry the token elsewhere)
def test_client_does_not_follow_redirects():
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get('Authorization')))
            if self.path.startswith('/v1/state'):
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{srv.server_address[1]}/steal')
                self.send_header('Content-Length', '0')
                self.end_headers()
    srv = http.server.HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ClientError):
            Client(f'http://127.0.0.1:{srv.server_address[1]}', 'SECRET').state()
        assert [p for p, _ in seen] == ['/v1/state']
    finally:
        srv.shutdown()


# L4: with a state file, a restarted agent does not trust a coordinator that lost history
def test_state_file_turns_a_lost_log_into_a_fork(keys, tmp_path):
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], str(tmp_path / 'a.jsonl'))
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    srv = make_server(co, Config('agent-tok-1', 'op-tok-1'), '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    sf = str(tmp_path / 'agent.state')
    a = Agent(url, 'agent-tok-1', fleet, 'a1', 'i1', poll_ms=20, timeout_s=1, state_file=sf).start()
    assert wait_for(lambda: a.status()['code'] == 'SW-HALTED-FLEET')
    a.stop()
    srv.shutdown()
    srv.server_close()
    co2 = Coordinator(fleet, keys.seed['coordinator'], str(tmp_path / 'b.jsonl'))     # a coordinator with a fresh log
    srv2 = make_server(co2, Config('agent-tok-1', 'op-tok-1'), '127.0.0.1', 0)
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    try:
        b = Agent(f'http://127.0.0.1:{srv2.server_address[1]}', 'agent-tok-1', fleet, 'a1', 'i1', poll_ms=20, timeout_s=1,
                  state_file=sf).start()
        assert wait_for(lambda: b.status()['code'] == 'SW-FORK', 2), b.status()
        b.stop()
    finally:
        srv2.shutdown()
        srv2.server_close()


# L7: a guessing address is refused before its token is looked at
def test_failed_token_checks_block_the_address(server):
    s = server(auth_fail_rate=3)
    bad = Client(s.url, 'wrong')
    for _ in range(3):
        with pytest.raises(ClientError):
            bad.state()
    with pytest.raises(ClientError) as e:
        Client(s.url, s.cfg.operator_token).state()    # even the right token, from that address, for now
    assert e.value.status == 429
