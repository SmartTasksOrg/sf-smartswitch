"""sf-smartswitch command line. ``sf-smartswitch --help`` lists the commands; docs/operations.md walks
through them. Tokens come from the environment, never from the command line (it shows in process lists):
SMARTSWITCH_OPERATOR_TOKEN for keyholder and operator commands, SMARTSWITCH_AGENT_TOKEN for ``agent``.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from . import __version__, canonical, keys
from .protocol import (SwitchError, State, doc_hash, make_certificate, new_proposal, proposal_hash, sign_vote,
                       validate_fleet, verify_certificate)


def _read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _write_json(path, obj, exclusive=True):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC), 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write('\n')


def _client(a, env='SMARTSWITCH_OPERATOR_TOKEN'):
    from .client import Client
    return Client(a.url, os.environ.get(env), timeout_s=a.timeout)


def _now_ms():
    return time.time_ns() // 1_000_000


def _safe(text) -> str:
    """Text a proposer wrote, made safe to print: control and format characters (escape sequences, carriage
    returns, bidirectional overrides, line separators) are shown as \\uXXXX, so nothing can redraw the
    lines a keyholder reads before signing."""
    import unicodedata
    out = []
    for ch in str(text):
        if unicodedata.category(ch) in ('Cc', 'Cf', 'Zl', 'Zp', 'Co', 'Cs', 'Cn') or ch == '\\':
            out.append('\\u%04x' % ord(ch) if ord(ch) <= 0xFFFF else '\\U%08x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def _describe(p):
    lines = [f'  action  {_safe(p["action"])} {_safe(p["target"])}', f'  reason  {_safe(p["reason"])}',
             f'  fleet   {_safe(p["fleet_id"])} {p["fleet_hash"][:16]}... (seq {p["seq"]}, epoch {p["epoch"]})',
             f'  valid   until {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(p["expires_ms"] / 1000))}']
    if p['new_public_key']:
        lines.append(f'  new key {p["new_public_key"]}')
    return '\n'.join(lines)


# ---------------------------------------------------------------- commands
def c_keygen(a):
    pub = keys.create(a.out, a.name)
    print(f'{a.out}: private key for {a.name} (mode 0600; keep it off shared disks and out of git)')
    print(f'public key: {pub}')


def c_fleet_init(a):
    khs = []
    for spec in a.keyholder:
        name, _, key = spec.partition('=')
        if key.endswith('.key') or os.path.exists(key):
            key = _read_json(key)['public_key']
        khs.append({'id': name, 'public_key': key})
    ck = a.coordinator_key
    if ck.endswith('.key') or os.path.exists(ck):
        ck = _read_json(ck)['public_key']
    from .keycheck import weakness
    for name, key in [(k['id'], k['public_key']) for k in khs] + [('coordinator', ck)]:
        why = weakness(key) if isinstance(key, str) else 'not a string'
        if why:
            raise SystemExit(f'the public key of {name} is refused: {why}')
    agents = None
    if a.agent:
        agents = []
        for spec in a.agent:
            aid, _, mx = spec.partition(':')
            agents.append({'id': aid, 'max_instances': int(mx or 1)})
    doc = {'type': 'smartswitch.fleet', 'version': 1, 'fleet_id': a.fleet_id, 'keyholders': khs,
           'threshold': a.threshold, 'coordinator_key': ck, 'offline_timeout_ms': a.offline_timeout_ms,
           'proposal_max_ttl_ms': a.max_ttl_ms, 'agents': agents}
    validate_fleet(doc)
    _write_json(a.out, doc)
    st = State.genesis(doc)
    print(f'{a.out}: fleet {a.fleet_id}, {len(khs)} keyholders, quorum {st.threshold}')
    print(f'fleet hash: {doc_hash(doc)}  (agents pin this; give it to every agent with the file)')


def c_fleet_show(a):
    doc = validate_fleet(_read_json(a.fleet))
    st = State.genesis(doc)
    print(json.dumps({'fleet_id': doc['fleet_id'], 'fleet_hash': doc_hash(doc), 'keyholders': [k['id'] for k in doc['keyholders']],
                      'threshold': st.threshold, 'offline_timeout_ms': doc['offline_timeout_ms'],
                      'roster': None if doc['agents'] is None else len(doc['agents'])}, indent=2))


def c_serve(a):
    from .coordinator import Coordinator
    from .server import Config, make_server, start_mirror_checks
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    fleet = validate_fleet(_read_json(a.fleet))
    _, seed = keys.load(a.key)
    co = Coordinator(fleet, seed, a.log, a.mirror, watchdog_ms=a.watchdog_ms,
                     webhook=os.environ.get('SMARTSWITCH_ALERT_WEBHOOK'), enforce_roster=not a.no_enforce_roster,
                     repair_mirror=a.repair_mirror)
    srv = make_server(co, Config.from_env(a.insecure_dev), a.host, a.port)
    stop = start_mirror_checks(co, a.mirror_check_s)
    print(f'sf-smartswitch {__version__}: fleet {fleet["fleet_id"]} ({co.fleet_hash[:16]}), log {a.log} '
          f'({len(co.entries)} entries), http://{a.host}:{srv.server_address[1]}', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


def c_propose(a):
    name, seed = keys.load(a.key)
    kh = a.keyholder or name
    if a.offline:
        fleet = validate_fleet(_read_json(a.fleet))
        st = State.genesis(fleet)
        from dataclasses import replace
        st = replace(st, seq=a.seq - 1, epoch=a.epoch)
    else:
        c = _client(a)
        s = c.state()
        fleet = c.fleet()
        st = State.genesis(fleet)
        from dataclasses import replace
        st = replace(st, seq=s['state']['seq'], epoch=s['state']['epoch'])
    p = new_proposal(st, a.action, a.target, a.reason, _now_ms(), a.ttl_ms, a.new_public_key)
    vote = sign_vote(seed, kh, p)
    ph = proposal_hash(p)
    print(_describe(p))
    print(f'proposal hash: {ph}')
    if a.offline:
        _write_json(a.out, p)
        _write_json(a.out + f'.vote-{kh}.json', vote)
        print(f'wrote {a.out} and {a.out}.vote-{kh}.json; other keyholders run "sign --proposal {a.out}"')
        return
    r = c.vote(p, vote)
    print(f'{r["status"]}: {len(r["votes"])} of {r["threshold"]} votes ({", ".join(r["votes"])})')
    if r['status'] == 'pending':
        print(f'other keyholders: sf-smartswitch sign --url {a.url} --key <their key> --hash {ph}')


def c_sign(a):
    name, seed = keys.load(a.key)
    kh = a.keyholder or name
    if a.proposal:
        p = _read_json(a.proposal)
    else:
        c = _client(a)
        p = c.pending(a.hash)['proposal']
        if proposal_hash(p) != a.hash:
            raise SystemExit('the coordinator returned a proposal with a different hash; not signing')
    print(_describe(p))
    print(f'proposal hash: {proposal_hash(p)}')
    if not a.yes:
        if input(f'Sign this as {kh}? Type yes: ').strip().lower() != 'yes':
            raise SystemExit('not signed')
    vote = sign_vote(seed, kh, p)
    if a.proposal:
        out = a.out or (a.proposal + f'.vote-{kh}.json')
        _write_json(out, vote)
        print(f'wrote {out}')
        return
    r = c.vote(p, vote)
    print(f'{r["status"]}: {len(r["votes"])} of {r["threshold"]} votes ({", ".join(r["votes"])})')


def c_assemble(a):
    p = _read_json(a.proposal)
    cert = make_certificate(p, [_read_json(v) for v in a.vote])
    if a.log:
        from .log import LogFile, Replica
        fleet = validate_fleet(_read_json(a.fleet))
        r = Replica(doc_hash(fleet))
        r.extend(LogFile.read(a.log))
        st = r.state
    else:
        if p.get('epoch') != 0 and not a.assume_epoch:
            raise SystemExit('no --log: give a copy of the log (it knows suspensions and key changes), or confirm the '
                             'proposal\'s epoch with --assume-epoch')
        st = State.genesis(validate_fleet(_read_json(a.fleet)))
        from dataclasses import replace
        st = replace(st, seq=p['seq'] - 1, epoch=p['epoch'])
    verify_certificate(st, cert, _now_ms(), ahead=True)
    _write_json(a.out, cert)
    who = ', '.join(v['keyholder'] for v in cert['votes'])
    if a.log:
        print(f'{a.out}: certificate with {len(cert["votes"])} votes ({who}), checked against the log')
    else:
        print(f'{a.out}: certificate with {len(cert["votes"])} votes ({who}); signatures checked against the keys in '
              f'the fleet document only (no --log: a keyholder suspended or re-keyed since is not known here, '
              f'and agents will refuse the certificate if its epoch {p["epoch"]} is not theirs)')


def c_submit(a):
    r = _client(a).certificate(_read_json(a.certificate))
    print(json.dumps(r, indent=2))


def c_status(a):
    print(json.dumps(_client(a).state(), indent=2))


def c_pending(a):
    print(json.dumps(_client(a).pending(), indent=2))


def c_instances(a):
    print(json.dumps(_client(a).instances(), indent=2))


def c_log_verify(a):
    from .log import LogFile, compare_files, replay
    pinned = doc_hash(validate_fleet(_read_json(a.fleet))) if a.fleet else None
    r = replay(LogFile.read(a.log), pinned)
    if not r['ok']:
        print(f'{a.log}: FAILED at entry {r["index"]}: {r["code"]}')
        sys.exit(1)
    print(f'{a.log}: {r["size"]} entries, chain intact, head {r["head"]}')
    print(json.dumps(r['state'], indent=2))
    if a.mirror:
        c = compare_files(a.log, a.mirror, pinned)
        print(f'mirror {a.mirror}: {c["message"]}')
        if not c['ok']:
            sys.exit(1)


def c_log_export(a):
    from .log import LogFile, replay
    entries = LogFile.read(a.log)
    r = replay(entries)
    if not r['ok']:
        raise SystemExit(f'{a.log} does not verify (entry {r["index"]}: {r["code"]}); not exporting')
    n = 0
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
        for e in entries:
            if e['kind'] != 'certificate':
                continue
            p = e['body']['proposal']
            for v in e['body']['votes']:
                f.write(canonical.dumps({'timestamp': e['ts_ms'], 'entry': e['n'], 'entry_hash': e['hash'], 'seq': p['seq'],
                                         'action': p['action'], 'target': p['target'], 'proposal_hash': proposal_hash(p),
                                         'keyholder': v['keyholder'], 'vote_hash': doc_hash(v), 'signature': v['sig']}) + '\n')
                n += 1
    print(f'{a.out}: {n} votes')


def c_agent(a):
    from .agent import Agent, run_guarded
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s smartswitch %(message)s')
    argv = a.command[1:] if a.command and a.command[0] == '--' else a.command
    if not argv:
        raise SystemExit('give the program to run after --')
    ag = Agent(a.url, os.environ.get('SMARTSWITCH_AGENT_TOKEN'), a.fleet, a.agent_id, a.instance_id,
               poll_ms=a.poll_ms, cert_dir=a.cert_dir, state_file=a.state_file)
    sys.exit(run_guarded(ag, argv, grace_s=a.grace_s, wait_s=a.wait_s))


def c_vectors(a):
    from .conformance import run_dir
    from ._bundled import path
    d = a.dir or str(path('conformance'))
    total, failures = run_dir(d)
    for f in failures:
        print(f)
    print(f'{total - len(failures)}/{total} vectors passed')
    sys.exit(1 if failures else 0)


def c_bench(a):
    from .bench import run
    r = run(a.keyholders, a.rounds)
    print(json.dumps(r, indent=2))
    if a.out:
        _write_json(a.out, r, exclusive=False)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='sf-smartswitch', description='Quorum kill switch for AI agent fleets.')
    ap.add_argument('--version', action='version', version=f'sf-smartswitch {__version__}')
    ap.add_argument('--demo', action='store_true', help='run the built-in demo (no files written)')
    sub = ap.add_subparsers(dest='cmd')

    def net(p):
        p.add_argument('--url', required=True, help='coordinator URL')
        p.add_argument('--timeout', type=float, default=10.0)

    p = sub.add_parser('keygen', help='create a private key file and print its public key')
    p.add_argument('--name', required=True)
    p.add_argument('--out', required=True)
    p.set_defaults(fn=c_keygen)

    p = sub.add_parser('fleet', help='create or show a fleet document')
    fs = p.add_subparsers(dest='fleet_cmd', required=True)
    q = fs.add_parser('init')
    q.add_argument('--fleet-id', required=True)
    q.add_argument('--keyholder', action='append', required=True, help='NAME=PUBLIC_KEY or NAME=FILE.key (repeat, 3 or more)')
    q.add_argument('--coordinator-key', required=True, help='public key hex or the coordinator .key file')
    q.add_argument('--threshold', type=int, default=None, help='default: 2 up to 5 keyholders, floor(n/2)+1 above')
    q.add_argument('--agent', action='append', help='ID or ID:MAX_INSTANCES for the roster (repeat); none: no roster')
    q.add_argument('--offline-timeout-ms', type=int, default=30000)
    q.add_argument('--max-ttl-ms', type=int, default=600000)
    q.add_argument('--out', required=True)
    q.set_defaults(fn=c_fleet_init)
    q = fs.add_parser('show')
    q.add_argument('fleet')
    q.set_defaults(fn=c_fleet_show)

    p = sub.add_parser('serve', help='run the coordinator')
    p.add_argument('--fleet', required=True)
    p.add_argument('--key', required=True, help="the coordinator's key file")
    p.add_argument('--log', required=True)
    p.add_argument('--mirror', help='second log file written the same way and compared every --mirror-check-s')
    p.add_argument('--mirror-check-s', type=float, default=30.0)
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8720)
    p.add_argument('--watchdog-ms', type=float, default=200.0)
    p.add_argument('--no-enforce-roster', action='store_true', help='alert on unknown or extra instances but still answer them')
    p.add_argument('--repair-mirror', action='store_true',
                   help='at start, copy a last log entry missing from the mirror even if it is an event (after a crash)')
    p.add_argument('--insecure-dev', action='store_true', help='no tokens; binds 127.0.0.1 only')
    p.set_defaults(fn=c_serve)

    p = sub.add_parser('propose', help='create a proposal and cast your vote on it')
    p.add_argument('--key', required=True)
    p.add_argument('--keyholder', help='your keyholder id (default: the name in the key file)')
    p.add_argument('--action', required=True, choices=['halt', 'resume', 'suspend', 'reinstate'])
    p.add_argument('--target', required=True, help='"*" (whole fleet), an agent id, or a keyholder id')
    p.add_argument('--reason', required=True)
    p.add_argument('--ttl-ms', type=int, default=600000)
    p.add_argument('--new-public-key', help='reinstate only: the keyholder\'s new public key')
    p.add_argument('--url')
    p.add_argument('--timeout', type=float, default=10.0)
    p.add_argument('--offline', action='store_true', help='no coordinator: write the proposal and your vote to files')
    p.add_argument('--fleet')
    p.add_argument('--seq', type=int, help='offline: the current seq + 1 (sf-smartswitch status shows seq)')
    p.add_argument('--epoch', type=int, help='offline: the current epoch (sf-smartswitch status shows it)')
    p.add_argument('--out')
    p.set_defaults(fn=c_propose)

    p = sub.add_parser('sign', help='sign a pending proposal (online with --hash, offline with --proposal)')
    p.add_argument('--key', required=True)
    p.add_argument('--keyholder')
    p.add_argument('--hash')
    p.add_argument('--proposal')
    p.add_argument('--out')
    p.add_argument('--url')
    p.add_argument('--timeout', type=float, default=10.0)
    p.add_argument('--yes', action='store_true', help='do not ask')
    p.set_defaults(fn=c_sign)

    p = sub.add_parser('assemble', help='combine a proposal and vote files into a certificate')
    p.add_argument('--fleet', required=True)
    p.add_argument('--log', help='a copy of the log, to check against the current keyholders')
    p.add_argument('--proposal', required=True)
    p.add_argument('--vote', action='append', required=True)
    p.add_argument('--assume-epoch', action='store_true',
                   help='without --log: accept the proposal\'s epoch as current (you know the keyholders since)')
    p.add_argument('--out', required=True)
    p.set_defaults(fn=c_assemble)

    p = sub.add_parser('submit', help='send a certificate to the coordinator')
    net(p)
    p.add_argument('certificate')
    p.set_defaults(fn=c_submit)
    for name, fn in (('status', c_status), ('pending', c_pending), ('instances', c_instances)):
        p = sub.add_parser(name)
        net(p)
        p.set_defaults(fn=fn)

    p = sub.add_parser('log', help='verify or export a log file')
    ls = p.add_subparsers(dest='log_cmd', required=True)
    q = ls.add_parser('verify')
    q.add_argument('log')
    q.add_argument('--fleet', help='pin: the log must start with this fleet document')
    q.add_argument('--mirror')
    q.set_defaults(fn=c_log_verify)
    q = ls.add_parser('export', help='one JSON line per vote: timestamp, vote hash, signature, ...')
    q.add_argument('log')
    q.add_argument('--out', required=True)
    q.set_defaults(fn=c_log_export)

    p = sub.add_parser('agent', help='run a program and stop it when the switch says so')
    net(p)
    p.add_argument('--fleet', required=True)
    p.add_argument('--agent-id', required=True)
    p.add_argument('--instance-id')
    p.add_argument('--cert-dir', help='also accept certificate files dropped here')
    p.add_argument('--state-file', help='keep what was verified across restarts (a shorter or different log is a fork)')
    p.add_argument('--poll-ms', type=int, default=1000)
    p.add_argument('--grace-s', type=float, default=5.0)
    p.add_argument('--wait-s', type=float, default=30.0)
    p.add_argument('command', nargs=argparse.REMAINDER)
    p.set_defaults(fn=c_agent)

    p = sub.add_parser('vectors', help='run the shared conformance vectors')
    p.add_argument('dir', nargs='?')
    p.set_defaults(fn=c_vectors)

    p = sub.add_parser('bench', help='time signing, verification and aggregation on this machine')
    p.add_argument('--keyholders', type=int, nargs='+', default=[3, 5, 7, 10])
    p.add_argument('--rounds', type=int, default=200)
    p.add_argument('--out')
    p.set_defaults(fn=c_bench)

    a = ap.parse_args(argv)
    if a.demo:
        from .demo import run
        sys.exit(run())
    if not getattr(a, 'fn', None):
        ap.print_help()
        sys.exit(2)
    if a.fn in (c_propose, c_sign):
        if a.fn is c_propose and a.offline and not (a.fleet and a.seq and a.epoch is not None and a.out):
            ap.error('propose --offline needs --fleet, --seq, --epoch and --out (sf-smartswitch status shows seq and epoch)')
        if a.fn is c_sign and not (a.proposal or (a.hash and a.url)):
            ap.error('sign needs --proposal FILE, or --hash and --url')
        if a.fn is c_propose and not a.offline and not a.url:
            ap.error('propose needs --url (or --offline)')
    try:
        a.fn(a)
    except SwitchError as e:
        raise SystemExit(f'refused: {e.code}: {e.message}')
    except FileExistsError as e:
        raise SystemExit(f'{e.filename} exists; not overwriting')
    except Exception as e:
        from .client import ClientError
        if isinstance(e, ClientError):
            raise SystemExit(f'coordinator: {e}')
        raise


if __name__ == '__main__':
    main()
