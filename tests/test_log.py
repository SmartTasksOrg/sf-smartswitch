import json

import pytest

from conftest import decide
from sf_smartswitch.coordinator import Coordinator
from sf_smartswitch.log import LogFile, compare_files, replay
from sf_smartswitch.protocol import SwitchError, doc_hash


def test_log_file_survives_a_restart_and_keeps_the_state(keys, tmp_path):
    p = str(tmp_path / 'log.jsonl')
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], p)
    decide(co, keys, 'halt', 'a1', ['alice', 'bob'])
    co2 = Coordinator(fleet, keys.seed['coordinator'], p)
    assert co2.state.halted == {'a1'} and co2.state.seq == 1 and len(co2.entries) == 2
    assert replay(LogFile.read(p), doc_hash(fleet))['ok']


def test_a_tampered_log_stops_the_coordinator(keys, tmp_path):
    p = tmp_path / 'log.jsonl'
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], str(p))
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    lines = p.read_text().splitlines()
    e = json.loads(lines[1])
    e['body']['proposal']['reason'] = 'edited'
    lines[1] = json.dumps(e)
    p.write_text('\n'.join(lines) + '\n')
    with pytest.raises(SwitchError) as err:
        Coordinator(fleet, keys.seed['coordinator'], str(p))
    assert err.value.code == 'SW-LOG-CHAIN'


def test_a_log_of_another_fleet_is_refused(keys, tmp_path):
    p = str(tmp_path / 'log.jsonl')
    Coordinator(keys.fleet(), keys.seed['coordinator'], p)
    with pytest.raises(SwitchError) as err:
        Coordinator(keys.fleet(4), keys.seed['coordinator'], p)
    assert err.value.code == 'SW-WRONG-FLEET'


def test_mirror_is_written_and_compared(keys, tmp_path):
    p, m = str(tmp_path / 'a.jsonl'), str(tmp_path / 'b.jsonl')
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], p, m)
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    assert co.check_mirror()['ok'] and co.metrics.mirror_ok.v == 1
    lines = open(m, encoding='utf-8').read().splitlines(keepends=True)
    e = json.loads(lines[1])
    e['body']['proposal']['reason'] = 'edited'
    with open(m, 'w', encoding='utf-8') as f:            # the mirror is edited
        f.write(lines[0] + json.dumps(e) + '\n')
    c = co.check_mirror()
    assert not c['ok'] and co.metrics.mirror_ok.v == 0
    with pytest.raises(SwitchError):
        Coordinator(fleet, keys.seed['coordinator'], p, m)
    assert not compare_files(p, m)['ok']


def test_wrong_coordinator_key_file_is_refused(keys, tmp_path):
    with pytest.raises(SwitchError):
        Coordinator(keys.fleet(), keys.seed['alice'], str(tmp_path / 'log.jsonl'))


def test_a_torn_last_line_is_reported_not_repaired(keys, tmp_path):
    p = tmp_path / 'log.jsonl'
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], str(p))
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    data = p.read_bytes()
    p.write_bytes(data[:-40])                         # a crash in the middle of the last write
    with pytest.raises(SwitchError) as err:
        Coordinator(fleet, keys.seed['coordinator'], str(p))
    assert err.value.code == 'SW-BAD-ENTRY' and 'line 2' in err.value.message
    assert p.read_bytes() == data[:-40]               # untouched


def test_a_mirror_one_entry_behind_after_a_crash_catches_up(keys, tmp_path):
    p, m = tmp_path / 'a.jsonl', tmp_path / 'b.jsonl'
    fleet = keys.fleet()
    co = Coordinator(fleet, keys.seed['coordinator'], str(p), str(m))
    decide(co, keys, 'halt', '*', ['alice', 'bob'])
    decide(co, keys, 'resume', '*', ['alice', 'bob'])
    lines = m.read_text().splitlines(keepends=True)      # genesis, halt, resume
    m.write_text(''.join(lines[:-1]))                    # crashed after writing the log, before the mirror
    co2 = Coordinator(fleet, keys.seed['coordinator'], str(p), str(m))
    assert co2.check_mirror()['ok'] and co2.state.seq == 2
    m.write_text(''.join(lines[:-2]))                    # two entries behind is not a crash artifact: refused
    with pytest.raises(SwitchError):
        Coordinator(fleet, keys.seed['coordinator'], str(p), str(m))
