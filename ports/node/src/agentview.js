'use strict';
// What an agent believes, and whether it may run: the agent-side rules without any I/O
// (spec/SEMANTICS.md, "Agent"). Times for heartbeats and status are the agent's own monotonic
// milliseconds; the time for a delivered certificate is wall-clock milliseconds (compared with expires_ms).
const { docHash, encode, sha256Hex } = require('./canonical');
const ed25519 = require('./ed25519');
const { Replica } = require('./log');
const { SwitchError, verifyCertificate, proposalHash, isId, isInt, hasFields, NONCE, MAX_INT, HEARTBEAT_PREFIX } = require('./protocol');

const HEARTBEAT_FIELDS = ['agent_id', 'fleet_hash', 'head', 'instance_id', 'issued_ms', 'log_size', 'nonce', 'sig', 'type'];

function heartbeatMessage(hb) {
  const body = {};
  for (const k of Object.keys(hb)) if (k !== 'sig') body[k] = hb[k];
  return Buffer.from(HEARTBEAT_PREFIX + sha256Hex(encode(body)), 'ascii');
}

class AgentView {
  constructor(fleet, agentId, instanceId) {
    if (!isId(agentId) || !isId(instanceId)) throw new Error('agentId and instanceId must match [A-Za-z0-9._-]{1,64}');
    this.fleet = fleet;
    this.fleetHash = docHash(fleet);
    this.agentId = agentId;
    this.instanceId = instanceId;
    this.replica = new Replica(this.fleetHash);
    this.lastOkMs = null;
    this.provisional = new Map(); // proposal hash -> seq of directly delivered halts
    this.fork = false;
  }

  // Entries that continue the local copy (fetched from the coordinator), appended one at a time. A
  // provisional halt ends when the log applies that same proposal, or a later resume of "*" or of this
  // agent; another certificate taking its seq does not end it.
  log(entries) {
    if (!Array.isArray(entries)) return { ok: false, code: 'SW-BAD-ENTRY', size: this.replica.size };
    for (const e of entries) {
      try {
        this.replica.extend([e]);
      } catch (err) {
        if (!(err instanceof SwitchError)) throw err;
        return { ok: false, code: err.code, size: this.replica.size };
      }
      if (this.provisional.size > 0 && e.kind === 'certificate') {
        const p = e.body.proposal;
        this.provisional.delete(proposalHash(p));
        if (p.action === 'resume' && (p.target === '*' || p.target === this.agentId)) {
          for (const [h, seq] of this.provisional) if (seq < p.seq) this.provisional.delete(h);
        }
      }
    }
    return { ok: true, size: this.replica.size };
  }

  // A heartbeat answering nonce, which the agent sent at atMs.
  heartbeat(hb, nonce, atMs) {
    let code = this._checkHeartbeat(hb, nonce);
    if (code === null) {
      const r = this.replica;
      const size = hb.log_size;
      if (r.size >= size) {
        if (r.hashes[size - 1] !== hb.head) {
          this.fork = true;
          code = 'SW-FORK';
        }
      } else {
        code = 'SW-BEHIND';
      }
    }
    if (code === null) {
      this.lastOkMs = this.lastOkMs === null ? atMs : Math.max(this.lastOkMs, atMs);
      return { ok: true, code: 'SW-OK' };
    }
    return { ok: false, code };
  }

  _checkHeartbeat(hb, nonce) {
    if (!hasFields(hb, HEARTBEAT_FIELDS) || hb.type !== 'smartswitch.heartbeat' || !isInt(hb.log_size, 1, MAX_INT)
        || !ed25519.isKeyHex(hb.head) || !isInt(hb.issued_ms, 0, MAX_INT)) {
      return 'SW-BAD-HEARTBEAT';
    }
    let msg;
    try { msg = heartbeatMessage(hb); } catch (e) { return 'SW-BAD-HEARTBEAT'; } // not encodable: cannot be signed
    if (!ed25519.verify(this.fleet.coordinator_key, msg, hb.sig)) return 'SW-BAD-HEARTBEAT';
    if (hb.fleet_hash !== this.fleetHash) return 'SW-WRONG-FLEET';
    if (hb.agent_id !== this.agentId || hb.instance_id !== this.instanceId) return 'SW-WRONG-AGENT';
    if (typeof nonce !== 'string' || !NONCE.test(nonce) || hb.nonce !== nonce) return 'SW-NONCE';
    return null;
  }

  // A certificate delivered directly (not through the log), checked at WALL-CLOCK time atMs (it is
  // compared with expires_ms). Only a valid halt of this agent or of the whole fleet, newer than the
  // local state, has an effect: a provisional halt (see log() for when it ends).
  certificate(cert, atMs) {
    const st = this.replica.state;
    if (st === null) return { ok: false, code: 'SW-NO-STATE' };
    let p;
    try {
      p = verifyCertificate(st, cert, atMs, true);
    } catch (e) {
      if (!(e instanceof SwitchError)) throw e;
      return { ok: false, code: e.code };
    }
    if (p.action !== 'halt' || (p.target !== '*' && p.target !== this.agentId)) return { ok: false, code: 'SW-NOT-APPLICABLE' };
    this.provisional.set(proposalHash(p), p.seq);
    return { ok: true, code: 'SW-PROVISIONAL-HALT' };
  }

  // {run, code}; the first matching reason in this order wins.
  status(atMs) {
    const st = this.replica.state;
    let code;
    if (this.fork) code = 'SW-FORK';
    else if (st !== null && st.haltedAll) code = 'SW-HALTED-FLEET';
    else if (st !== null && st.halted.has(this.agentId)) code = 'SW-HALTED-AGENT';
    else if (this.provisional.size > 0) code = 'SW-PROVISIONAL-HALT';
    else if (this.lastOkMs === null || st === null) code = 'SW-NO-HEARTBEAT';
    else if (atMs - this.lastOkMs >= st.offlineTimeoutMs) code = 'SW-OFFLINE';
    else return { run: true, code: 'SW-RUN' };
    return { run: false, code };
  }
}

module.exports = { AgentView, heartbeatMessage };
