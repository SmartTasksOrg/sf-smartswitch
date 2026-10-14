'use strict';
// The switch log: a hash-chained list of entries {n, ts_ms, kind, body, prev, hash} (spec/SEMANTICS.md, "Log").
const { docHash, isObject } = require('./canonical');
const { State, SwitchError, apply, validateFleet, hasFields } = require('./protocol');

const GENESIS_PREV = '0'.repeat(64);
const ENTRY_FIELDS = ['body', 'hash', 'kind', 'n', 'prev', 'ts_ms'];
const KINDS = ['genesis', 'certificate', 'event'];
const isInteger = (v) => typeof v === 'number' && Number.isInteger(v);

function entryHash(e) {
  const rest = {};
  for (const k of Object.keys(e)) if (k !== 'hash') rest[k] = e[k];
  return docHash(rest);
}

// A verified copy of a log. extend() checks entries one by one and applies certificates; on the first
// bad entry it throws SwitchError and keeps everything before it.
class Replica {
  constructor(fleetHash = null) {
    this.pinned = fleetHash;
    this.state = null;
    this.size = 0;
    this.head = GENESIS_PREV;
    this.hashes = [];
  }

  extend(entries) {
    for (const e of entries) this._one(e);
    return this.size;
  }

  _one(e) {
    if (!hasFields(e, ENTRY_FIELDS) || !KINDS.includes(e.kind) || !isObject(e.body) || !isInteger(e.n)
        || !isInteger(e.ts_ms) || e.ts_ms < 0) {
      throw new SwitchError('SW-BAD-ENTRY', `entry ${this.size} is malformed`);
    }
    // ts_ms need not increase (spec/SEMANTICS.md, "Log" step 2): only n is checked.
    if (e.n !== this.size) throw new SwitchError('SW-LOG-ORDER', `entry ${this.size}: n is ${e.n}`);
    let h = null;
    if (e.prev === this.head) {
      try { h = entryHash(e); } catch (err) { h = null; } // not encodable (a float): cannot match
    }
    if (h === null || e.hash !== h) throw new SwitchError('SW-LOG-CHAIN', `entry ${this.size}: the hash chain is broken`);
    if (this.size === 0) {
      if (e.kind !== 'genesis') throw new SwitchError('SW-BAD-ENTRY', 'entry 0 must be the genesis');
      try {
        validateFleet(e.body);
      } catch (err) {
        if (err instanceof SwitchError) throw new SwitchError('SW-BAD-FLEET', 'entry 0: ' + err.detail);
        throw err;
      }
      if (this.pinned !== null && docHash(e.body) !== this.pinned) throw new SwitchError('SW-WRONG-FLEET', 'entry 0 is not the pinned fleet');
      this.state = State.genesis(e.body);
    } else if (e.kind === 'genesis') {
      throw new SwitchError('SW-BAD-ENTRY', `entry ${this.size}: only entry 0 can be a genesis`);
    } else if (e.kind === 'certificate') {
      this.state = apply(this.state, e.body, e.ts_ms);
    }
    this.size += 1;
    this.head = e.hash;
    this.hashes.push(e.hash);
  }
}

// {ok: true, size, head, state} or {ok: false, index, code} (the vectors' form).
function replay(entries, fleetHash = null) {
  const r = new Replica(fleetHash);
  try {
    r.extend(entries);
  } catch (e) {
    if (!(e instanceof SwitchError)) throw e;
    return { ok: false, index: r.size, code: e.code };
  }
  if (r.size === 0) return { ok: false, index: 0, code: 'SW-BAD-ENTRY' };
  return { ok: true, size: r.size, head: r.head, state: r.state.summary() };
}

module.exports = { Replica, replay, entryHash, GENESIS_PREV };
