'use strict';
// The networked agent: ask the coordinator for a signed heartbeat every pollMs, verify everything with
// AgentView, and stop when told or when cut off.
//
//   const agent = new Agent({ url, token, fleet: 'fleet.json', agentId: 'planner-1' }).start();
//   while (agent.mayRun()) { await doOneStep(); agent.checkpoint(); }   // checkpoint throws Halted
//   agent.stop();
//
// Network errors change nothing: without a valid heartbeat for the fleet's offline_timeout_ms the
// status becomes SW-OFFLINE by itself (the dead-man rule).
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { AgentView } = require('./agentview');
const { validateFleet } = require('./protocol');

class Halted extends Error {
  constructor(code) {
    super(`SmartSwitch: this agent may not run (${code})`);
    this.code = code;
  }
}

class HttpError extends Error {
  constructor(status, body) {
    super(`HTTP ${status}: ${String(body).slice(0, 300)}`);
    this.status = status;
  }
}

const monoMs = () => Number(process.hrtime.bigint() / 1000000n);

function loadFleet(fleet) {
  if (typeof fleet === 'string') return validateFleet(JSON.parse(fs.readFileSync(fleet, 'utf8')));
  return validateFleet(fleet);
}

class Agent {
  constructor({ url, token = null, fleet, agentId, instanceId = null, pollMs = 1000, timeoutMs = 2000, onChange = null, clock = monoMs, wallClock = Date.now }) {
    if (!/^https?:\/\//.test(String(url))) throw new Error('the coordinator URL must start with http:// or https://');
    this.url = String(url).replace(/\/+$/, '');
    this.token = token;
    this.fleet = loadFleet(fleet);
    this.instanceId = instanceId || crypto.randomBytes(8).toString('hex');
    this.view = new AgentView(this.fleet, agentId, this.instanceId);
    Object.assign(this, { pollMs, timeoutMs, onChange, clock, wallClock });
    this.lastError = null;
    this._last = null;
    this._timer = null;
    this._running = false;
  }

  get agentId() { return this.view.agentId; }

  // One connection per request (no keep-alive), as the Python reference client does: an answer always
  // comes from a coordinator that is accepting connections now. One deadline covers the whole request
  // (connect, headers and body), so a stalled or truncated answer always ends in an error.
  _get(path, query) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let req = null;
      const finish = (err, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          if (req) req.destroy();
          reject(err);
        } else {
          resolve(value);
        }
      };
      const timer = setTimeout(() => finish(new Error(`no answer within ${this.timeoutMs} ms`)), this.timeoutMs);
      try {
        const u = new URL(this.url + path + '?' + new URLSearchParams(query).toString());
        const headers = { Accept: 'application/json' };
        if (this.token) headers.Authorization = 'Bearer ' + this.token;
        const mod = u.protocol === 'https:' ? https : http;
        req = mod.request(u, { method: 'GET', headers, agent: false }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('error', (e) => finish(e));
          res.on('aborted', () => finish(new Error('the answer was cut off')));
          res.on('close', () => { if (!res.complete) finish(new Error('the answer was cut off')); });
          res.on('end', () => {
            if (!res.complete) return finish(new Error('the answer was cut off'));
            const text = Buffer.concat(chunks).toString('utf8');
            if (res.statusCode < 200 || res.statusCode >= 300) return finish(new HttpError(res.statusCode, text));
            let v;
            try { v = JSON.parse(text); } catch (e) { return finish(e); } // includes RangeError on deep nesting
            finish(null, v);
          });
        });
        req.on('error', (e) => finish(e));
        req.end();
      } catch (e) {
        finish(e);
      }
    });
  }

  // One round: heartbeat with a fresh nonce, catch up on SW-BEHIND, check the same heartbeat again.
  // Any error (network, HTTP, a malformed or cut-off answer, a parser limit) changes nothing.
  async pollOnce() {
    try {
      const nonce = crypto.randomBytes(16).toString('hex');
      const sent = this.clock();
      const hb = await this._get('/v1/heartbeat', { agent_id: this.agentId, instance_id: this.instanceId, nonce });
      let r = this.view.heartbeat(hb, nonce, sent);
      if (r.code === 'SW-BEHIND') {
        await this._catchUp(hb.log_size);
        r = this.view.heartbeat(hb, nonce, sent);
      }
      this.lastError = r.ok ? null : r.code;
    } catch (e) {
      this.lastError = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    }
    return this.status();
  }

  async _catchUp(size) {
    for (;;) {
      const have = this.view.replica.size;
      if (have >= size) return;
      const page = await this._get('/v1/log', { from: have, limit: 1000, agent_id: this.agentId, instance_id: this.instanceId });
      const entries = page && Array.isArray(page.entries) ? page.entries : [];
      if (entries.length === 0) return;
      const r = this.view.log(entries);
      if (!r.ok) throw new Error(`the coordinator log does not verify (${r.code} at entry ${r.size})`);
    }
  }

  // A certificate that reached this agent some other way than the coordinator. It is checked at
  // wall-clock time (wallClock, Date.now by default), because it is compared with expires_ms.
  deliver(cert) {
    const r = this.view.certificate(cert, this.wallClock());
    this.status();
    return r;
  }

  status() {
    const s = this.view.status(this.clock());
    if (this._last === null || this._last.code !== s.code || this._last.run !== s.run) {
      this._last = s;
      if (this.onChange) {
        try { this.onChange(s); } catch (e) { /* a callback must not break the agent */ }
      }
    }
    return s;
  }

  mayRun() { return this.status().run; }

  checkpoint() {
    const s = this.status();
    if (!s.run) throw new Halted(s.code);
  }

  // Poll in the background until stop(). The timer is unref'd: it does not keep the process alive.
  start() {
    if (this._running) return this;
    this._running = true;
    const loop = async () => {
      if (!this._running) return;
      try { await this.pollOnce(); } catch (e) { this.lastError = String(e); } // pollOnce does not throw; belt and braces
      if (!this._running) return;
      this._timer = setTimeout(loop, this.pollMs);
      this._timer.unref();
    };
    loop();
    return this;
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
  }
}

module.exports = { Agent, Halted, HttpError, loadFleet, monoMs };
