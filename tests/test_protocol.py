"""The quorum rules, including the two promises: no single keyholder can trigger a quorum action, and
no single keyholder can block one."""
import itertools

import pytest

from sf_smartswitch.protocol import (State, SwitchError, apply, default_threshold, make_certificate, new_proposal,
                                     validate_fleet, verify_certificate)

T = 1_700_000_000_000


def cert(keys, st, who, action='halt', target='*', new_key=None, **over):
    p = new_proposal(st, action, target, 'r', T, 60000, new_key)
    p.update(over)
    return make_certificate(p, [keys.vote(w, p) for w in who])


@pytest.mark.parametrize('n,k', [(3, 2), (4, 2), (5, 2), (6, 4), (7, 4), (8, 5), (9, 5), (10, 6)])
def test_default_threshold(n, k):
    assert default_threshold(n) == k


@pytest.mark.parametrize('n', range(3, 9))
def test_no_single_keyholder_triggers_and_none_blocks(keys, n):
    st = State.genesis(keys.fleet(n))
    holders = [k['id'] for k in keys.fleet(n)['keyholders']]
    assert 2 <= st.threshold <= n - 1
    for who in holders:                                   # one alone: never enough
        with pytest.raises(SwitchError) as e:
            apply(st, cert(keys, st, [who]), T)
        assert e.value.code == 'SW-NO-QUORUM'
    for refuser in holders:                               # any one refusing: the others still reach it
        others = [h for h in holders if h != refuser][:st.threshold]
        assert apply(st, cert(keys, st, others), T).halted_all


def test_every_quorum_subset_works_and_smaller_ones_do_not(keys):
    st = State.genesis(keys.fleet(5))
    ids = [k['id'] for k in keys.fleet(5)['keyholders']]
    for size in range(1, 6):
        for who in itertools.combinations(ids, size):
            c = cert(keys, st, list(who))
            if size >= st.threshold:
                assert apply(st, c, T).halted_all
            else:
                with pytest.raises(SwitchError):
                    apply(st, c, T)


def test_signature_binds_every_field(keys):
    st = State.genesis(keys.fleet())
    c = cert(keys, st, ['alice', 'bob'])
    for field, value in [('target', 'a1'), ('reason', 'other'), ('expires_ms', T + 59999), ('action', 'resume')]:
        bad = {**c, 'proposal': {**c['proposal'], field: value}}
        with pytest.raises(SwitchError) as e:
            apply(st, bad, T)
        assert e.value.code == 'SW-BAD-SIGNATURE'


def test_suspension_cannot_lower_the_bar_or_make_quorum_impossible(keys):
    st = State.genesis(keys.fleet(3))
    st = apply(st, cert(keys, st, ['alice', 'bob'], 'suspend', 'carol'), T)
    assert st.threshold == 2 and st.active == ['alice', 'bob'] and st.epoch == 1
    with pytest.raises(SwitchError) as e:
        apply(st, cert(keys, st, ['alice', 'bob'], 'suspend', 'bob'), T)
    assert e.value.code == 'SW-QUORUM-IMPOSSIBLE'
    with pytest.raises(SwitchError) as e:                 # carol's vote no longer counts
        apply(st, cert(keys, st, ['alice', 'carol']), T)
    assert e.value.code == 'SW-SUSPENDED-KEYHOLDER'


def test_reinstatement_rotates_the_key(keys):
    st = State.genesis(keys.fleet(3))
    st = apply(st, cert(keys, st, ['alice', 'bob'], 'suspend', 'carol'), T)
    st = apply(st, cert(keys, st, ['alice', 'bob'], 'reinstate', 'carol', new_key=keys.pub['new']), T)
    assert st.keys['carol'] == keys.pub['new'] and st.epoch == 2
    p = new_proposal(st, 'halt', '*', 'r', T, 60000)
    old = make_certificate(p, [keys.vote('alice', p), keys.vote('carol', p)])
    with pytest.raises(SwitchError) as e:
        apply(st, old, T)
    assert e.value.code == 'SW-BAD-SIGNATURE'
    from sf_smartswitch.protocol import sign_vote
    new = make_certificate(p, [keys.vote('alice', p), sign_vote(keys.seed['new'], 'carol', p)])
    assert apply(st, new, T).halted_all


def test_a_vote_for_an_old_epoch_or_seq_is_dead(keys):
    st = State.genesis(keys.fleet(3))
    halt = cert(keys, st, ['alice', 'bob'])
    st2 = apply(st, halt, T)
    with pytest.raises(SwitchError) as e:
        apply(st2, halt, T)
    assert e.value.code == 'SW-STALE-SEQ'
    with pytest.raises(SwitchError) as e:
        verify_certificate(st2, halt, T, ahead=True)
    assert e.value.code == 'SW-STALE-SEQ'


def test_explicit_threshold_and_fleet_errors(keys):
    assert State.genesis(keys.fleet(7, threshold=5)).threshold == 5
    for bad in (dict(threshold=1), dict(threshold=3), dict(version=1.0), dict(fleet_id='x' * 65),
                dict(coordinator_key=keys.pub['alice'])):
        with pytest.raises(SwitchError) as e:
            validate_fleet(keys.fleet(3, **bad))
        assert e.value.code == 'SW-BAD-FLEET'


def test_unpaired_surrogate_in_reason_is_refused(keys):
    st = State.genesis(keys.fleet(3))
    p = new_proposal(st, 'halt', '*', 'ok', T, 60000)
    p['reason'] = 'bad \ud800'
    with pytest.raises(SwitchError) as e:
        apply(st, make_certificate(p, [{'keyholder': 'alice', 'sig': '0' * 128}]), T)
    assert e.value.code == 'SW-BAD-PROPOSAL'
