import pytest

from conftest import decide, proposal
from sf_smartswitch.coordinator import Coordinator, Refused, Watchdog
from sf_smartswitch.protocol import SwitchError, make_certificate


def test_votes_wait_for_the_quorum(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    p = proposal(co)
    r = co.submit_vote(p, keys.vote('carol', p))
    assert r['status'] == 'pending' and r['votes'] == ['carol'] and not co.state.halted_all
    r = co.submit_vote(p, keys.vote('carol', p))
    assert r['status'] == 'pending' and co.metrics.votes.value(result='duplicate') == 1
    r = co.submit_vote(p, keys.vote('alice', p))
    assert r['status'] == 'applied' and co.state.halted_all and r['votes'] == ['alice', 'carol']
    assert co.entries[-1]['body']['votes'][0]['keyholder'] == 'alice'      # sorted


def test_a_bad_vote_is_refused_at_once(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    p = proposal(co)
    for vote, code in [(keys.vote('mallory', p) | {'keyholder': 'mallory'}, 'SW-UNKNOWN-KEYHOLDER'),
                       ({'keyholder': 'bob', 'sig': keys.vote('alice', p)['sig']}, 'SW-BAD-SIGNATURE')]:
        with pytest.raises(SwitchError) as e:
            co.submit_vote(p, vote)
        assert e.value.code == code
    assert co.pending_list() == []


def test_competing_proposals_one_wins_the_other_goes_stale(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    a, b = proposal(co, target='a1'), proposal(co, target='a2')
    co.submit_vote(a, keys.vote('alice', a))
    co.submit_vote(b, keys.vote('bob', b))
    assert len(co.pending_list()) == 2
    co.submit_vote(a, keys.vote('carol', a))
    assert co.pending_list() == []
    with pytest.raises(SwitchError) as e:
        co.submit_vote(b, keys.vote('carol', b))
    assert e.value.code == 'SW-STALE-SEQ'


def test_offline_certificate_is_accepted_and_checked(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    p = proposal(co)
    with pytest.raises(SwitchError):
        co.submit_certificate(make_certificate(p, [keys.vote('alice', p)] * 2))
    r = co.submit_certificate(make_certificate(p, [keys.vote('bob', p), keys.vote('carol', p)]))
    assert r['status'] == 'applied' and co.state.halted_all


def test_watchdog_slow_and_spike():
    w = Watchdog(200)
    assert w.check(150) is None
    assert w.check(205) is None              # within 200 + 10 % of the moving average
    assert w.check(260) == 'aggregation-slow'
    assert w.check(301) == 'aggregation-spike'
    w2 = Watchdog(200)
    for _ in range(50):
        w2.check(290)                         # a high average never hides a spike
    assert w2.check(305) == 'aggregation-spike'


def test_slow_aggregation_is_logged(keys):
    t = [0.0]
    co = Coordinator(keys.fleet(), keys.seed['coordinator'], mono=lambda: t[0])
    p = proposal(co)
    co.submit_vote(p, keys.vote('alice', p))
    orig = co._append

    def slow_append(*a, **k):
        t[0] += 350
        return orig(*a, **k)
    co._append = slow_append
    co.submit_vote(p, keys.vote('bob', p))
    events = [e['body']['event'] for e in co.entries if e['kind'] == 'event']
    assert events == ['aggregation-spike'] and co.metrics.watchdog.value(kind='aggregation-spike') == 1


def test_roster_refuses_unknown_and_extra_instances(keys):
    t = [0.0]
    co = Coordinator(keys.fleet(roster=[{'id': 'a1', 'max_instances': 1}]), keys.seed['coordinator'], mono=lambda: t[0])
    n = '0' * 32
    co.heartbeat('a1', 'i1', n)
    with pytest.raises(Refused) as e:
        co.heartbeat('a1', 'i2', n)
    assert e.value.status == 409
    with pytest.raises(Refused) as e:
        co.heartbeat('zz', 'i1', n)
    assert e.value.status == 403
    co.heartbeat('a1', 'i1', n)                     # the first instance keeps going
    t[0] += 31000                                   # i1 falls silent: its slot frees
    co.heartbeat('a1', 'i2', n)
    reasons = sorted(e['body']['reason'] for e in co.entries if e['kind'] == 'event')
    assert reasons == ['too-many-instances', 'unknown-agent']


def test_roster_alert_only_mode(keys):
    co = Coordinator(keys.fleet(roster=[{'id': 'a1', 'max_instances': 1}]), keys.seed['coordinator'], enforce_roster=False)
    co.heartbeat('a1', 'i1', '0' * 32)
    assert co.heartbeat('a1', 'i2', '0' * 32)['agent_id'] == 'a1'
    assert co.metrics.replication.value(reason='too-many-instances') == 1


def test_alerts_are_rate_limited(keys):
    co = Coordinator(keys.fleet(roster=[]), keys.seed['coordinator'])
    for i in range(50):
        with pytest.raises(Refused):
            co.heartbeat('zz', f'i{i}', '0' * 32)
    assert sum(1 for e in co.entries if e['kind'] == 'event') == 1


def test_propagation_time_of_a_halt(keys):
    t = [0.0]
    co = Coordinator(keys.fleet(), keys.seed['coordinator'], mono=lambda: t[0])
    co.heartbeat('a1', 'i1', '0' * 32)
    co.heartbeat('a2', 'i1', '0' * 32)
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    t[0] += 120
    co.fetched('a1', 'i1', len(co.entries))
    assert co.metrics.propagation.count == 0
    t[0] += 30
    co.fetched('a2', 'i1', len(co.entries))
    assert co.metrics.propagation.count == 1 and co.metrics.propagation.percentile(50) == 150


def test_bad_heartbeat_parameters(keys):
    co = Coordinator(keys.fleet(), keys.seed['coordinator'])
    for args in [('a 1', 'i', '0' * 32), ('a', 'i', 'xyz'), ('a', 'i', '0' * 31), ('a', None, '0' * 32)]:
        with pytest.raises(ValueError):
            co.heartbeat(*args)
