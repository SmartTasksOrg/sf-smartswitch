"""A small JSON client for the coordinator (used by the agent and the command line)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE = 32 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would send the bearer token to wherever the answer points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class ClientError(Exception):
    def __init__(self, status: int, body: dict | str):
        msg = body.get('error') if isinstance(body, dict) else body
        super().__init__(f'HTTP {status}: {msg}')
        self.status, self.body = status, body
        self.code = body.get('code') if isinstance(body, dict) else None


class Client:
    def __init__(self, url: str, token: str | None = None, timeout_s: float = 5.0):
        if not url.startswith(('http://', 'https://')):
            raise ValueError('the coordinator URL must start with http:// or https://')
        self.url, self.token, self.timeout_s = url.rstrip('/'), token, timeout_s

    def _req(self, method: str, path: str, query: dict | None = None, body=None):
        u = self.url + path + ('?' + urllib.parse.urlencode(query) if query else '')
        data = None if body is None else json.dumps(body).encode()
        h = {'Accept': 'application/json'}
        if data is not None:
            h['Content-Type'] = 'application/json'
        if self.token:
            h['Authorization'] = 'Bearer ' + self.token
        req = urllib.request.Request(u, data=data, headers=h, method=method)
        try:
            with _OPENER.open(req, timeout=self.timeout_s) as r:
                data = r.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise ClientError(r.status, 'answer larger than 32 MiB')
                return json.loads(data)
        except urllib.error.HTTPError as e:
            raw = e.read(65536)
            try:
                b = json.loads(raw)
            except ValueError:
                b = raw.decode('utf-8', 'replace')[:300]
            raise ClientError(e.code, b) from None

    def fleet(self):
        return self._req('GET', '/v1/fleet')

    def state(self):
        return self._req('GET', '/v1/state')

    def log(self, start: int = 0, limit: int = 1000, agent_id: str | None = None, instance_id: str | None = None):
        q = {'from': start, 'limit': limit}
        if agent_id and instance_id:
            q.update(agent_id=agent_id, instance_id=instance_id)
        return self._req('GET', '/v1/log', q)

    def heartbeat(self, agent_id: str, instance_id: str, nonce: str):
        return self._req('GET', '/v1/heartbeat', {'agent_id': agent_id, 'instance_id': instance_id, 'nonce': nonce})

    def pending(self, proposal_hash: str | None = None):
        return self._req('GET', '/v1/proposals', {'hash': proposal_hash} if proposal_hash else None)

    def vote(self, proposal: dict, vote: dict):
        return self._req('POST', '/v1/votes', body={'proposal': proposal, 'vote': vote})

    def certificate(self, cert: dict):
        return self._req('POST', '/v1/certificates', body={'certificate': cert})

    def instances(self):
        return self._req('GET', '/v1/instances')
