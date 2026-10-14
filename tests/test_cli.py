import json
import os
import stat
import subprocess
import sys

import pytest

from sf_smartswitch.cli import main
from sf_smartswitch.coordinator import Coordinator
from sf_smartswitch import keys as keyfiles


def run(*args):
    try:
        main(list(args))
    except SystemExit as e:
        if e.code not in (0, None):
            raise


def test_offline_flow_keygen_fleet_propose_sign_assemble_verify_export(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for n in ('alice', 'bob', 'carol', 'coordinator'):
        run('keygen', '--name', n, '--out', f'{n}.key')
        assert stat.S_IMODE(os.stat(f'{n}.key').st_mode) == 0o600 or os.name == 'nt'
    with pytest.raises(SystemExit):
        run('keygen', '--name', 'alice', '--out', 'alice.key')          # never overwrites
    run('fleet', 'init', '--fleet-id', 'f1', '--keyholder', 'alice=alice.key', '--keyholder', 'bob=bob.key',
        '--keyholder', 'carol=carol.key', '--coordinator-key', 'coordinator.key', '--agent', 'a1', '--agent', 'a2:3',
        '--out', 'fleet.json')
    run('fleet', 'show', 'fleet.json')
    assert '"threshold": 2' in capsys.readouterr().out
    run('propose', '--key', 'alice.key', '--action', 'halt', '--target', '*', '--reason', 'drill', '--offline',
        '--fleet', 'fleet.json', '--seq', '1', '--epoch', '0', '--out', 'p.json')
    run('sign', '--key', 'bob.key', '--proposal', 'p.json', '--yes')
    run('assemble', '--fleet', 'fleet.json', '--proposal', 'p.json', '--vote', 'p.json.vote-alice.json',
        '--vote', 'p.json.vote-bob.json', '--out', 'cert.json')
    fleet = json.load(open('fleet.json'))
    _, seed = keyfiles.load('coordinator.key')
    co = Coordinator(fleet, seed, 'switch.jsonl')
    co.submit_certificate(json.load(open('cert.json')))
    run('log', 'verify', 'switch.jsonl', '--fleet', 'fleet.json')
    run('log', 'export', 'switch.jsonl', '--out', 'votes.jsonl')
    lines = [json.loads(x) for x in open('votes.jsonl')]
    assert [x['keyholder'] for x in lines] == ['alice', 'bob']
    assert set(lines[0]) >= {'timestamp', 'vote_hash', 'signature', 'proposal_hash', 'entry_hash'}


def test_assemble_refuses_one_keyholder_twice(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for n in ('alice', 'bob', 'carol', 'coordinator'):
        run('keygen', '--name', n, '--out', f'{n}.key')
    run('fleet', 'init', '--fleet-id', 'f1', '--keyholder', 'alice=alice.key', '--keyholder', 'bob=bob.key',
        '--keyholder', 'carol=carol.key', '--coordinator-key', 'coordinator.key', '--out', 'fleet.json')
    run('propose', '--key', 'alice.key', '--action', 'halt', '--target', '*', '--reason', 'x', '--offline',
        '--fleet', 'fleet.json', '--seq', '1', '--epoch', '0', '--out', 'p.json')
    with pytest.raises(SystemExit) as e:
        run('assemble', '--fleet', 'fleet.json', '--proposal', 'p.json', '--vote', 'p.json.vote-alice.json',
            '--vote', 'p.json.vote-alice.json', '--out', 'cert.json')
    assert 'SW-DUPLICATE-VOTE' in str(e.value)
    assert not os.path.exists('cert.json')


def test_log_verify_fails_on_a_tampered_file(tmp_path, keys):
    p = tmp_path / 'log.jsonl'
    Coordinator(keys.fleet(), keys.seed['coordinator'], str(p))
    e = json.loads(p.read_text())
    e['body']['fleet_id'] = 'other'
    p.write_text(json.dumps(e) + '\n')
    with pytest.raises(SystemExit) as err:
        main(['log', 'verify', str(p)])
    assert err.value.code == 1


def test_online_propose_and_sign(server, tmp_path, keys, monkeypatch):
    s = server()
    monkeypatch.chdir(tmp_path)
    for n in ('alice', 'bob'):
        (tmp_path / f'{n}.key').write_text(json.dumps({'type': 'smartswitch.key', 'name': n, 'public_key': keys.pub[n],
                                                       'seed': keys.seed[n].hex()}))
    monkeypatch.setenv('SMARTSWITCH_OPERATOR_TOKEN', s.cfg.operator_token)
    run('propose', '--url', s.url, '--key', 'alice.key', '--action', 'halt', '--target', 'a2', '--reason', 'test')
    (h,) = [x['proposal_hash'] for x in s.co.pending_list()]
    run('sign', '--url', s.url, '--key', 'bob.key', '--hash', h, '--yes')
    assert s.co.state.halted == {'a2'}


def test_version_and_demo_from_an_empty_folder(tmp_path):
    r = subprocess.run([sys.executable, '-m', 'sf_smartswitch', '--version'], capture_output=True, text=True, cwd=tmp_path)
    assert r.stdout.startswith('sf-smartswitch ')
    r = subprocess.run([sys.executable, '-m', 'sf_smartswitch', '--demo'], capture_output=True, text=True, cwd=tmp_path,
                       timeout=60)
    assert r.returncode == 0 and 'Demo passed.' in r.stdout, r.stdout + r.stderr
    assert os.listdir(tmp_path) == []
