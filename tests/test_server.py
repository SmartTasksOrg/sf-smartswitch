import base64
import http.client
import json
import socket
import time
import urllib.parse

import pytest

from conftest import proposal
from sf_smartswitch.agentview import AgentView
from sf_smartswitch.client import Client, ClientError


def raw(url, method, path, body=None, headers=None):
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data, r


def test_tokens_and_roles(server, keys):
    s = server()
    agent = Client(s.url, s.cfg.agent_token)
    op = Client(s.url, s.cfg.operator_token)
    nobody = Client(s.url, 'wrong')
    assert agent.state()['state']['seq'] == 0
    with pytest.raises(ClientError) as e:
        nobody.state()
    assert e.value.status == 401
    p = proposal(s.co)
    with pytest.raises(ClientError) as e:                 # an agent cannot vote
        agent.vote(p, keys.vote('alice', p))
    assert e.value.status == 401
    assert op.vote(p, keys.vote('alice', p))['status'] == 'pending'
    assert op.vote(p, keys.vote('bob', p))['status'] == 'applied'
    assert agent.state()['state']['halted_all'] is True


def test_a_token_is_not_enough_to_halt(server, keys):
    s = server()
    op = Client(s.url, s.cfg.operator_token)
    p = proposal(s.co)
    forged = {'keyholder': 'alice', 'sig': keys.vote('mallory', p)['sig']}
    with pytest.raises(ClientError) as e:
        op.vote(p, forged)
    assert e.value.status == 400 and e.value.code == 'SW-BAD-SIGNATURE'
    assert not s.co.state.halted_all


def test_heartbeat_is_signed_and_verifiable(server, keys):
    s = server()
    v = AgentView(s.co.fleet, 'a1', 'i1')
    v.log(Client(s.url, s.cfg.agent_token).log(0)['entries'])
    nonce = 'ab' * 16
    hb = Client(s.url, s.cfg.agent_token).heartbeat('a1', 'i1', nonce)
    assert v.heartbeat(hb, nonce, 0) == {'ok': True, 'code': 'SW-OK'}
    assert v.heartbeat(hb, 'cd' * 16, 0)['code'] == 'SW-NONCE'          # a replayed answer is useless


def test_log_paging(server, keys):
    s = server()
    op = Client(s.url, s.cfg.operator_token)
    for i in range(3):
        p = proposal(s.co, 'halt' if i % 2 == 0 else 'resume')
        op.vote(p, keys.vote('alice', p))
        op.vote(p, keys.vote('bob', p))
    page = op.log(1, 2)
    assert [e['n'] for e in page['entries']] == [1, 2] and page['log_size'] == 4
    with pytest.raises(ClientError):
        op.log(-1)


def test_request_limits(server):
    s = server()
    tok = {'Authorization': 'Bearer ' + s.cfg.operator_token}
    st, _, _ = raw(s.url, 'POST', '/v1/votes', b'{}' * 10, dict(tok, **{'Transfer-Encoding': 'chunked'}))
    assert st in (400, 411)
    st, _, _ = raw(s.url, 'POST', '/v1/votes', b'x' * (300 * 1024), tok)
    assert st == 413
    st, _, _ = raw(s.url, 'GET', '/v1/state', b'{}', dict(tok, **{'Content-Length': '2'}))
    assert st == 400
    st, _, _ = raw(s.url, 'POST', '/v1/votes', b'[1]', tok)
    assert st == 400
    st, _, _ = raw(s.url, 'GET', '/nope')
    assert st == 404


def test_failed_logins_are_rate_limited(server):
    s = server(auth_fail_rate=3)
    codes = [raw(s.url, 'GET', '/v1/state', headers={'Authorization': 'Bearer x'})[0] for _ in range(5)]
    assert codes[:3] == [401] * 3 and 429 in codes[3:]


def test_operator_allowlist(server):
    s = server(operator_allow='10.9.9.9/32')
    st, _, _ = raw(s.url, 'GET', '/v1/proposals', headers={'Authorization': 'Bearer ' + s.cfg.operator_token})
    assert st == 403


def test_ui_needs_the_operator_token_and_escapes(server, keys):
    s = server()
    p = proposal(s.co, reason='<script>alert(1)</script>')
    s.co.submit_vote(p, keys.vote('alice', p))
    st, _, r = raw(s.url, 'GET', '/ui')
    assert st == 401 and 'Basic' in r.getheader('WWW-Authenticate')
    auth = base64.b64encode(b'op:' + s.cfg.operator_token.encode()).decode()
    st, body, r = raw(s.url, 'GET', '/ui', headers={'Authorization': 'Basic ' + auth})
    assert st == 200 and b'<script>' not in body and b'&lt;script&gt;' in body
    assert "default-src 'none'" in r.getheader('Content-Security-Policy')
    auth = base64.b64encode(b'op:' + s.cfg.agent_token.encode()).decode()
    assert raw(s.url, 'GET', '/ui', headers={'Authorization': 'Basic ' + auth})[0] == 401


def test_metrics_and_health(server):
    s = server()
    st, body, _ = raw(s.url, 'GET', '/metrics')
    assert st == 200 and b'smartswitch_log_entries 1' in body
    st, body, _ = raw(s.url, 'GET', '/healthz')
    assert json.loads(body)['ok'] is True


def test_shutdown_closes_kept_alive_connections(server):
    s = server()
    u = urllib.parse.urlsplit(s.url)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
    c.request('GET', '/healthz')
    assert c.getresponse().read()
    s.stop()
    time.sleep(0.1)
    with pytest.raises((ConnectionError, http.client.HTTPException, socket.timeout, OSError)):
        c.request('GET', '/healthz')
        c.getresponse().read()


def test_tokens_must_differ_and_exist(keys):
    from sf_smartswitch.coordinator import Coordinator
    from sf_smartswitch.server import Config, make_server
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    with pytest.raises(SystemExit):
        make_server(co, Config('same', 'same'), '127.0.0.1', 0)
    with pytest.raises(SystemExit):
        make_server(co, Config(None, None), '127.0.0.1', 0)
    with pytest.raises(SystemExit):
        make_server(co, Config(insecure_dev=True), '0.0.0.0', 0)


def test_many_agents_polling_at_once_are_not_delayed(server):
    """The listen backlog must hold a burst of connections (the standard library's default of 5 made
    some heartbeats wait for a TCP retransmit, a full second)."""
    import threading
    s = server()
    c = Client(s.url, s.cfg.agent_token, timeout_s=5)
    times = []

    def one(i):
        t = time.monotonic()
        c.heartbeat('a2', f'burst{i}', '%032x' % i)
        times.append(time.monotonic() - t)
    from sf_smartswitch.coordinator import Refused  # noqa: F401  (a2 allows 2 instances: most are refused, fast)
    ts = [threading.Thread(target=lambda i=i: _swallow(one, i)) for i in range(80)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert len(times) + len(_ERRS) == 80
    assert max(times + _ERRS) < 0.9, max(times + _ERRS)


_ERRS = []


def _swallow(fn, i):
    t = time.monotonic()
    try:
        fn(i)
    except ClientError:
        _ERRS.append(time.monotonic() - t)
