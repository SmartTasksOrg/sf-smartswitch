"""The SmartSwitch coordinator over HTTP (stdlib only). Spec: spec/openapi.yaml.

    sf-smartswitch serve --fleet fleet.json --key coordinator.key --log switch.jsonl [--mirror mirror.jsonl]

Tokens (required unless --insecure-dev, which binds 127.0.0.1 only):
    SMARTSWITCH_AGENT_TOKEN     agents: heartbeat, log, fleet, state
    SMARTSWITCH_OPERATOR_TOKEN  keyholders and operators: votes, certificates, pending proposals, instances,
                                the read-only page /ui (HTTP Basic, any user name, the token as password);
                                also everything an agent may do
A token only opens the door: no request can halt or resume anything without a quorum of keyholder
signatures, which the coordinator and every agent verify.
Operator endpoints check the IP allowlist first (SMARTSWITCH_OPERATOR_ALLOW: comma-separated addresses
or CIDRs, when set), then the token, then a per-IP rate limit (60 per minute). An address with more than
20 failed token checks in a minute is refused before its token is looked at. Behind a reverse proxy set
SMARTSWITCH_TRUSTED_PROXIES to the proxy's address(es): the last X-Forwarded-For address it adds is then
the client's address for these checks (otherwise every client looks like the proxy). Requests: at most 256 KiB, Content-Length required (no chunked
bodies), 10 s socket timeout, at most 256 connections at once, each closed after 30 s; every error answer
closes the connection. Put the coordinator behind a TLS proxy: it speaks plain HTTP.
"""
from __future__ import annotations

import base64
import hmac
import html
import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .coordinator import Coordinator, Refused
from .protocol import SwitchError

log = logging.getLogger('sf_smartswitch.server')
MAX_BODY = 256 * 1024
SEQ_CODES = ('SW-STALE-SEQ', 'SW-SEQ-GAP', 'SW-WRONG-EPOCH', 'SW-EXPIRED')


class RateLimiter:
    """Token bucket per key: ``rate`` requests per ``per_s`` seconds."""

    def __init__(self, rate: int = 10, per_s: float = 60.0, clock=time.monotonic):
        self.rate, self.per_s, self.clock = rate, per_s, clock
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def exhausted(self, key: str) -> bool:
        """True while ``key`` has no token left (without spending one)."""
        now = self.clock()
        with self._lock:
            if key not in self._b:
                return False
            tokens, last = self._b[key]
            return min(self.rate, tokens + (now - last) * self.rate / self.per_s) < 1

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            if len(self._b) > 100000:
                self._b.clear()
            tokens, last = self._b.get(key, (float(self.rate), now))
            tokens = min(self.rate, tokens + (now - last) * self.rate / self.per_s)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return False
            self._b[key] = (tokens - 1, now)
            return True


def parse_allowlist(text):
    if not text:
        return None
    return [ipaddress.ip_network(x.strip(), strict=False) for x in text.split(',') if x.strip()]


def ip_allowed(ip: str, nets) -> bool:
    if nets is None:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


class Config:
    def __init__(self, agent_token=None, operator_token=None, operator_allow=None, insecure_dev=False,
                 operator_rate=60, auth_fail_rate=20, trusted_proxies=None):
        self.agent_token, self.operator_token = agent_token, operator_token
        self.operator_limiter = RateLimiter(operator_rate, 60.0)
        self.auth_fail_limiter = RateLimiter(auth_fail_rate, 60.0)
        self.operator_allow = parse_allowlist(operator_allow) if isinstance(operator_allow, str) else operator_allow
        self.insecure_dev = insecure_dev
        self.trusted_proxies = parse_allowlist(trusted_proxies) if isinstance(trusted_proxies, str) else trusted_proxies

    @classmethod
    def from_env(cls, insecure_dev=False):
        e = os.environ
        return cls(e.get('SMARTSWITCH_AGENT_TOKEN'), e.get('SMARTSWITCH_OPERATOR_TOKEN'),
                   e.get('SMARTSWITCH_OPERATOR_ALLOW'), insecure_dev, trusted_proxies=e.get('SMARTSWITCH_TRUSTED_PROXIES'))


class _HTTPError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


ROUTES = {
    ('GET', '/healthz'): ('healthz', None),
    ('GET', '/metrics'): ('metrics', None),
    ('GET', '/v1/fleet'): ('fleet', 'agent'),
    ('GET', '/v1/state'): ('state', 'agent'),
    ('GET', '/v1/log'): ('log', 'agent'),
    ('GET', '/v1/heartbeat'): ('heartbeat', 'agent'),
    ('GET', '/v1/proposals'): ('proposals', 'operator'),
    ('POST', '/v1/votes'): ('vote', 'operator'),
    ('POST', '/v1/certificates'): ('certificate', 'operator'),
    ('GET', '/v1/instances'): ('instances', 'operator'),
    ('GET', '/ui'): ('ui', 'operator'),
}


def make_handler(co: Coordinator, cfg: Config):
    class H(BaseHTTPRequestHandler):
        server_version = 'sf-smartswitch/' + __version__
        protocol_version = 'HTTP/1.1'
        timeout = 10

        def log_message(self, fmt, *args):
            log.info('%s %s', self.client_address[0], fmt % args)

        def _send(self, code, obj, ctype='application/json', headers=None):
            body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
            if code >= 400:
                self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if code >= 400:
                self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> bytes:
            if self.headers.get('Transfer-Encoding'):
                raise _HTTPError(411, 'send Content-Length; chunked bodies are not accepted')
            raw = self.headers.get('Content-Length')
            if raw is None or not raw.isdigit() or int(raw) > MAX_BODY:
                raise _HTTPError(413 if raw and raw.isdigit() else 411, 'Content-Length missing, invalid or above 256 KiB')
            n = int(raw)
            return self.rfile.read(n) if n else b''

        def _json(self, raw: bytes) -> dict:
            v = json.loads(raw or b'null')
            if not isinstance(v, dict):
                raise ValueError('body must be a JSON object')
            return v

        def _client_ip(self):
            """The peer address, or behind a trusted proxy (SMARTSWITCH_TRUSTED_PROXIES) the address the proxy
            put last in X-Forwarded-For: per-address limits and the allowlist then apply to real clients."""
            peer = self.client_address[0]
            if cfg.trusted_proxies and ip_allowed(peer, cfg.trusted_proxies):
                xff = self.headers.get('X-Forwarded-For', '')
                last = xff.split(',')[-1].strip() if xff else ''
                try:
                    ipaddress.ip_address(last)
                    return last
                except ValueError:
                    return peer
            return peer

        def _presented(self):
            got = self.headers.get('Authorization', '')
            if got.startswith('Bearer '):
                return got[7:]
            if got.startswith('Basic '):
                try:
                    return base64.b64decode(got[6:], validate=True).decode('utf-8').split(':', 1)[1]
                except (ValueError, IndexError, UnicodeDecodeError):
                    return None
            return None

        def _role_ok(self, role):
            if cfg.insecure_dev:
                return True
            tok = self._presented()
            if tok is None:
                return False
            if cfg.operator_token and hmac.compare_digest(tok.encode(), cfg.operator_token.encode()):
                return True
            return role == 'agent' and bool(cfg.agent_token) and hmac.compare_digest(tok.encode(), cfg.agent_token.encode())

        def _dispatch(self, method):
            parts = urllib.parse.urlsplit(self.path)
            route = ROUTES.get((method, parts.path))
            if route is None:
                return self._send(404, {'error': 'not found'})
            name, role = route
            ip = self._client_ip()
            try:
                if role == 'operator' and not ip_allowed(ip, cfg.operator_allow):
                    return self._send(403, {'error': 'source address not allowed'})
                if role and not cfg.insecure_dev and cfg.auth_fail_limiter.exhausted(ip):
                    return self._send(429, {'error': 'too many failed token checks from this address'})
                if role and not self._role_ok(role):
                    if not cfg.auth_fail_limiter.allow(ip):
                        return self._send(429, {'error': 'rate limit'})
                    extra = {'WWW-Authenticate': 'Basic realm="smartswitch"'} if name == 'ui' else None
                    return self._send(401, {'error': 'missing or wrong token'}, headers=extra)
                if role == 'operator' and not cfg.insecure_dev and not cfg.operator_limiter.allow(ip):
                    return self._send(429, {'error': 'rate limit'})
                if method == 'GET' and (self.headers.get('Transfer-Encoding') or
                                        (self.headers.get('Content-Length') or '0') != '0'):
                    raise _HTTPError(400, 'GET requests have no body')
                raw = self._body() if method == 'POST' else b''
                q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items()}
                return getattr(self, 'r_' + name)(raw, q)
            except _HTTPError as e:
                return self._send(e.code, {'error': str(e)})
            except Refused as e:
                return self._send(e.status, {'error': e.reason})
            except SwitchError as e:
                return self._send(409 if e.code in SEQ_CODES else 400, {'error': e.message or e.code, 'code': e.code})
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {'error': str(e) or 'bad request'})
            except Exception:
                log.exception('handler failed')
                return self._send(500, {'error': 'internal error'})

        def do_GET(self):
            self._dispatch('GET')

        def do_POST(self):
            self._dispatch('POST')

        # -- routes
        def r_healthz(self, raw, q):
            self._send(200, {'ok': True, 'version': __version__})

        def r_metrics(self, raw, q):
            co.refresh_gauges()
            self._send(200, co.metrics.expose(), 'text/plain; version=0.0.4')

        def r_fleet(self, raw, q):
            self._send(200, co.fleet)

        def r_state(self, raw, q):
            self._send(200, co.status())

        def r_log(self, raw, q):
            start = int(q.get('from', '0'))
            limit = int(q.get('limit', '1000'))
            if start < 0 or limit < 1:
                raise ValueError('from must be >= 0 and limit >= 1')
            entries = co.entries_from(start, limit)
            if q.get('agent_id') and q.get('instance_id'):
                co.fetched(q['agent_id'], q['instance_id'], start + len(entries))
            self._send(200, {'from': start, 'entries': entries, 'log_size': len(co.entries)})

        def r_heartbeat(self, raw, q):
            self._send(200, co.heartbeat(q.get('agent_id'), q.get('instance_id'), q.get('nonce')))

        def r_proposals(self, raw, q):
            if q.get('hash'):
                p = co.pending_get(q['hash'])
                return self._send(200, p) if p else self._send(404, {'error': 'no pending proposal with this hash'})
            self._send(200, {'pending': co.pending_list()})

        def r_vote(self, raw, q):
            b = self._json(raw)
            self._send(200, co.submit_vote(b.get('proposal'), b.get('vote')))

        def r_certificate(self, raw, q):
            b = self._json(raw)
            self._send(200, co.submit_certificate(b.get('certificate')))

        def r_instances(self, raw, q):
            self._send(200, {'instances': co.instances_list()})

        def r_ui(self, raw, q):
            self._send(200, render_ui(co), 'text/html; charset=utf-8',
                       headers={'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'"})

    return H


def render_ui(co: Coordinator) -> str:
    """A read-only page: state, pending proposals, instances, the last 50 log entries. No script."""
    e = html.escape
    s = co.status()
    st = s['state']
    if st['halted_all']:
        banner = '<p class="b halt">The whole fleet is HALTED.</p>'
    elif st['halted']:
        banner = f'<p class="b warn">Halted agents: {e(", ".join(st["halted"]))}</p>'
    else:
        banner = '<p class="b ok">The fleet is running.</p>'
    rows = ''.join(f'<tr><td>{x["n"]}</td><td>{x["ts_ms"]}</td><td>{e(x["kind"])}</td><td>{e(_entry_text(x))}</td></tr>'
                   for x in reversed(co.entries_from(max(0, s['log_size'] - 50), 50)))
    pend = ''.join(f'<tr><td>{e(p["proposal"]["action"])} {e(p["proposal"]["target"])}</td><td>{e(p["proposal"]["reason"])}</td>'
                   f'<td>{len(p["votes"])} of {p["threshold"]}: {e(", ".join(p["votes"]))}</td>'
                   f'<td><code>{e(p["proposal_hash"][:16])}</code></td></tr>' for p in co.pending_list()) \
        or '<tr><td colspan="4">none</td></tr>'
    inst = ''.join(f'<tr><td>{e(i["agent_id"])}</td><td>{e(i["instance_id"])}</td><td>{"live" if i["live"] else "silent"}</td>'
                   f'<td>{i["last_seen_ms_ago"]} ms ago</td></tr>' for i in co.instances_list()) \
        or '<tr><td colspan="4">none yet</td></tr>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>SmartSwitch {e(s["fleet_id"])}</title>
<style>body{{font:15px/1.45 system-ui,sans-serif;margin:16px;color:#111;background:#fff}}table{{border-collapse:collapse;width:100%;margin:8px 0 20px}}
td,th{{border-bottom:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}.b{{padding:10px;font-weight:600;border:2px solid}}
.halt{{border-color:#a00;color:#a00}}.warn{{border-color:#a60;color:#7a4a00}}.ok{{border-color:#060;color:#060}}code{{font-size:13px}}
@media (prefers-color-scheme: dark){{body{{background:#111;color:#eee}}td,th{{border-color:#444}}.halt{{color:#f88;border-color:#f88}}.warn{{color:#fc6;border-color:#fc6}}.ok{{color:#8d8;border-color:#8d8}}}}</style>
</head><body><main><h1>SmartSwitch: {e(s["fleet_id"])}</h1>{banner}
<p>seq {st["seq"]}, epoch {st["epoch"]}, quorum {st["threshold"]} of {len(st["keys"])} keyholders;
active: {e(", ".join(st["active"]))}; suspended: {e(", ".join(st["suspended"]) or "none")}.
Log: {s["log_size"]} entries, head <code>{e(s["head"][:16])}</code>. This page refreshes every 5 seconds and changes nothing:
votes are signed with the command line tool.</p>
<h2>Pending proposals</h2><table><thead><tr><th scope="col">Action</th><th scope="col">Reason</th><th scope="col">Votes</th><th scope="col">Hash</th></tr></thead><tbody>{pend}</tbody></table>
<h2>Agent instances</h2><table><thead><tr><th scope="col">Agent</th><th scope="col">Instance</th><th scope="col">Status</th><th scope="col">Last heartbeat</th></tr></thead><tbody>{inst}</tbody></table>
<h2>Log (latest 50)</h2><table><thead><tr><th scope="col">#</th><th scope="col">Time (ms)</th><th scope="col">Kind</th><th scope="col">What</th></tr></thead><tbody>{rows}</tbody></table>
</main></body></html>'''


def _entry_text(x) -> str:
    b = x['body']
    if x['kind'] == 'certificate':
        p = b['proposal']
        return f'{p["action"]} {p["target"]} (seq {p["seq"]}) by {", ".join(v["keyholder"] for v in b["votes"])}: {p["reason"]}'
    if x['kind'] == 'genesis':
        return f'fleet {b["fleet_id"]} created'
    return json.dumps(b, sort_keys=True)[:300]


CONNECTION_DEADLINE_S = 30


def _close_quietly(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class SwitchHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    # the listen backlog: the standard library's 5 drops connections when many agents poll at once, and a
    # dropped connection is retried by the client's TCP stack only after a second
    request_queue_size = 1024

    def __init__(self, addr, handler, max_threads=256):
        super().__init__(addr, handler)
        self._slots = threading.BoundedSemaphore(max_threads)
        self._open: set = set()
        self._open_lock = threading.Lock()

    def shutdown(self):
        """Stop accepting and close every open connection: a stopped coordinator must stop answering
        heartbeats on kept-alive connections too (agents rely on silence to stop)."""
        super().shutdown()
        with self._open_lock:
            socks = list(self._open)
        for sk in socks:
            _close_quietly(sk)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._open_lock:
            self._open.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._open_lock:
                self._open.discard(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = threading.Timer(CONNECTION_DEADLINE_S, _close_quietly, args=(request,))
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            with self._open_lock:
                self._open.discard(request)
            self._slots.release()


def make_server(co: Coordinator, cfg: Config, host='127.0.0.1', port=8720) -> SwitchHTTPServer:
    if not cfg.insecure_dev and not (cfg.agent_token and cfg.operator_token):
        raise SystemExit('set SMARTSWITCH_AGENT_TOKEN and SMARTSWITCH_OPERATOR_TOKEN (or use --insecure-dev on 127.0.0.1)')
    if cfg.insecure_dev and host not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('--insecure-dev only binds 127.0.0.1')
    if cfg.agent_token and cfg.agent_token == cfg.operator_token:
        raise SystemExit('SMARTSWITCH_AGENT_TOKEN and SMARTSWITCH_OPERATOR_TOKEN must differ')
    return SwitchHTTPServer((host, port), make_handler(co, cfg))


def start_mirror_checks(co: Coordinator, every_s: float = 30.0) -> threading.Event:
    stop = threading.Event()

    def loop():
        while not stop.wait(every_s):
            try:
                co.check_mirror()
            except Exception:
                log.exception('mirror check failed')
    if co.mirror_path:
        threading.Thread(target=loop, daemon=True, name='mirror-check').start()
    return stop
