import json
import sys

from conftest import decide, proposal, wait_for
from sf_smartswitch.agent import Agent, Halted, run_guarded
from sf_smartswitch.protocol import make_certificate


def agent(s, agent_id='a1', **kw):
    kw.setdefault('poll_ms', 50)
    return Agent(s.url, s.cfg.agent_token, s.co.fleet, agent_id, timeout_s=1, **kw)


def test_run_halt_resume(server, keys):
    s = server()
    a = agent(s).start()
    try:
        assert wait_for(a.may_run)
        decide(s.co, keys, 'halt', '*', ['alice', 'bob'])
        assert wait_for(lambda: a.status()['code'] == 'SW-HALTED-FLEET', 2)
        try:
            a.checkpoint()
            raise AssertionError('checkpoint must raise')
        except Halted as e:
            assert e.code == 'SW-HALTED-FLEET'
        decide(s.co, keys, 'resume', '*', ['bob', 'carol'])
        assert wait_for(a.may_run, 2)
    finally:
        a.stop()


def test_the_agent_stops_without_the_coordinator(server, keys):
    s = server(fleet=keys.fleet(offline_timeout_ms=1000))
    a = agent(s).start()
    try:
        assert wait_for(a.may_run)
        s.stop()
        assert wait_for(lambda: a.status()['code'] == 'SW-OFFLINE', 3)
    finally:
        a.stop()


def test_wrong_token_never_runs(server):
    s = server()
    a = Agent(s.url, 'wrong', s.co.fleet, 'a1', poll_ms=50, timeout_s=1).start()
    try:
        assert not wait_for(a.may_run, 0.5)
        assert a.status()['code'] == 'SW-NO-HEARTBEAT'
    finally:
        a.stop()


def test_a_coordinator_withholding_a_halt_is_bypassed_by_a_certificate_file(server, keys, tmp_path):
    s = server()
    d = tmp_path / 'certs'
    d.mkdir()
    a = agent(s, cert_dir=str(d)).start()
    try:
        assert wait_for(a.may_run)
        p = proposal(s.co)                    # signed by a quorum, never given to the coordinator
        cert = make_certificate(p, [keys.vote('alice', p), keys.vote('carol', p)])
        (d / 'halt.json').write_text(json.dumps(cert))
        assert wait_for(lambda: a.status()['code'] == 'SW-PROVISIONAL-HALT', 2)
        s.co.submit_certificate(cert)          # later the coordinator writes it: the halt is now in the state
        assert wait_for(lambda: a.status()['code'] == 'SW-HALTED-FLEET', 2)
    finally:
        a.stop()


def test_run_guarded_stops_a_program(server, keys, tmp_path):
    s = server()
    a = agent(s)
    marker = tmp_path / 'started'
    prog = [sys.executable, '-c', f'import time, pathlib; pathlib.Path({str(marker)!r}).write_text("x"); time.sleep(60)']
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.setdefault('rc', run_guarded(a, prog, grace_s=2, wait_s=5)))
    t.start()
    assert wait_for(marker.exists, 10)
    decide(s.co, keys, 'halt', 'a1', ['alice', 'bob'])
    t.join(10)
    assert out.get('rc') == 75


def test_run_guarded_refuses_to_start_when_halted(server, keys):
    s = server()
    decide(s.co, keys, 'halt', '*', ['alice', 'bob'])
    assert run_guarded(agent(s), [sys.executable, '-c', 'print(1)'], wait_s=1) == 75
