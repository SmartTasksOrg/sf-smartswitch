'use strict';
// Fleet document, proposals, certificates and the switch state (spec/SEMANTICS.md).
// Deterministic: no clock, no randomness, no I/O. Time comes in as atMs.
const { docHash, isObject } = require('./canonical');
const ed25519 = require('./ed25519');

const ID = /^[A-Za-z0-9._-]{1,64}$/;
const NONCE = /^[0-9a-f]{32}$/;
const ACTIONS = ['halt', 'resume', 'suspend', 'reinstate'];
const VOTE_PREFIX = 'smartswitch-vote-v1:';
const HEARTBEAT_PREFIX = 'smartswitch-heartbeat-v1:';
const MAX_KEYHOLDERS = 64;
const MAX_AGENTS = 100000;
const MAX_REASON_BYTES = 1000;
const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

const FLEET_FIELDS = ['agents', 'coordinator_key', 'fleet_id', 'keyholders', 'offline_timeout_ms', 'proposal_max_ttl_ms',
  'threshold', 'type', 'version'];
const PROPOSAL_FIELDS = ['action', 'created_ms', 'epoch', 'expires_ms', 'fleet_hash', 'fleet_id', 'new_public_key', 'reason',
  'seq', 'target', 'type'];

class SwitchError extends Error {
  constructor(code, message = '') {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.detail = message;
  }
}

const isInt = (v, lo, hi) => typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;
const isId = (v) => typeof v === 'string' && ID.test(v);

// True when v is an object whose keys are exactly `fields` (given sorted).
function hasFields(v, fields) {
  if (!isObject(v)) return false;
  const keys = Object.keys(v).sort();
  return keys.length === fields.length && keys.every((k, i) => k === fields[i]);
}

// ---------------------------------------------------------------- fleet

const defaultThreshold = (n) => (n <= 5 ? 2 : Math.floor(n / 2) + 1);
const thresholdOk = (k, n) => isInt(k, 2, n - 1);

function validateFleet(doc) {
  const bad = (msg) => { throw new SwitchError('SW-BAD-FLEET', msg); };
  if (!hasFields(doc, FLEET_FIELDS)) bad('the fleet document must have exactly the fields ' + FLEET_FIELDS.join(', '));
  if (doc.type !== 'smartswitch.fleet' || doc.version !== 1) bad('type must be "smartswitch.fleet" and version 1');
  if (!isId(doc.fleet_id)) bad('fleet_id must match [A-Za-z0-9._-]{1,64}');
  const khs = doc.keyholders;
  if (!Array.isArray(khs) || khs.length < 3 || khs.length > MAX_KEYHOLDERS) bad(`keyholders must be a list of 3 to ${MAX_KEYHOLDERS}`);
  const ids = new Set();
  const keys = new Set();
  for (const kh of khs) {
    if (!hasFields(kh, ['id', 'public_key'])) bad('each keyholder must be {"id", "public_key"}');
    if (!isId(kh.id) || !ed25519.isKeyHex(kh.public_key)) bad('keyholder id must be an id and public_key 64 lower-case hex');
    if (ids.has(kh.id) || keys.has(kh.public_key)) bad('keyholder ids and public keys must be unique');
    ids.add(kh.id);
    keys.add(kh.public_key);
  }
  const n = khs.length;
  if (doc.threshold !== null && !thresholdOk(doc.threshold, n)) bad(`threshold must be null or an integer from 2 to ${n - 1}`);
  if (!ed25519.isKeyHex(doc.coordinator_key) || keys.has(doc.coordinator_key)) {
    bad('coordinator_key must be 64 lower-case hex and differ from every keyholder key');
  }
  if (!isInt(doc.offline_timeout_ms, 1000, 3600000)) bad('offline_timeout_ms must be an integer from 1000 to 3600000');
  if (!isInt(doc.proposal_max_ttl_ms, 1000, 86400000)) bad('proposal_max_ttl_ms must be an integer from 1000 to 86400000');
  const agents = doc.agents;
  if (agents !== null) {
    if (!Array.isArray(agents) || agents.length > MAX_AGENTS) bad(`agents must be null or a list of at most ${MAX_AGENTS}`);
    const seen = new Set();
    for (const a of agents) {
      if (!hasFields(a, ['id', 'max_instances'])) bad('each agent must be {"id", "max_instances"}');
      if (!isId(a.id) || !isInt(a.max_instances, 1, 1000) || seen.has(a.id)) {
        bad('agent id must be a unique id and max_instances 1 to 1000');
      }
      seen.add(a.id);
    }
  }
  return doc;
}

const fleetThreshold = (fleet) => (fleet.threshold !== null ? fleet.threshold : defaultThreshold(fleet.keyholders.length));

// ---------------------------------------------------------------- proposals and certificates

function checkProposalFormat(p) {
  const bad = (msg) => { throw new SwitchError('SW-BAD-PROPOSAL', msg); };
  if (!hasFields(p, PROPOSAL_FIELDS)) bad('a proposal must have exactly the fields ' + PROPOSAL_FIELDS.join(', '));
  if (p.type !== 'smartswitch.proposal') bad('type must be "smartswitch.proposal"');
  if (!isId(p.fleet_id) || !ed25519.isKeyHex(p.fleet_hash)) bad('fleet_id or fleet_hash is malformed');
  if (!isInt(p.seq, 1, MAX_INT) || !isInt(p.epoch, 0, MAX_INT)) bad('seq must be an integer >= 1 and epoch >= 0');
  if (!ACTIONS.includes(p.action)) bad('action must be one of ' + ACTIONS.join(', '));
  if (typeof p.target !== 'string') bad('target must be a string');
  if (p.action === 'reinstate') {
    if (!ed25519.isKeyHex(p.new_public_key)) bad('reinstate needs new_public_key (64 lower-case hex)');
  } else if (p.new_public_key !== null) {
    bad('new_public_key must be null unless the action is reinstate');
  }
  if (typeof p.reason !== 'string' || Buffer.byteLength(p.reason, 'utf8') > MAX_REASON_BYTES) {
    bad(`reason must be a string of at most ${MAX_REASON_BYTES} UTF-8 bytes`);
  }
  if (!isInt(p.created_ms, 0, MAX_INT) || !isInt(p.expires_ms, 0, MAX_INT)) bad('created_ms and expires_ms must be integers >= 0');
  if (p.expires_ms <= p.created_ms) bad('expires_ms must be after created_ms');
  return p;
}

const proposalHash = (p) => docHash(p);
const voteMessage = (pHash) => Buffer.from(VOTE_PREFIX + pHash, 'ascii');

function checkCertificateFormat(c) {
  const bad = (msg) => { throw new SwitchError('SW-BAD-CERTIFICATE', msg); };
  if (!hasFields(c, ['proposal', 'type', 'votes'])) bad('a certificate must be {"type", "proposal", "votes"}');
  if (c.type !== 'smartswitch.certificate') bad('type must be "smartswitch.certificate"');
  const votes = c.votes;
  if (!Array.isArray(votes) || votes.length < 1 || votes.length > MAX_KEYHOLDERS) bad(`votes must be a list of 1 to ${MAX_KEYHOLDERS}`);
  for (const v of votes) {
    if (!hasFields(v, ['keyholder', 'sig']) || typeof v.keyholder !== 'string' || typeof v.sig !== 'string') {
      bad('each vote must be {"keyholder": string, "sig": string}');
    }
  }
  return c;
}

// ---------------------------------------------------------------- state

class State {
  // Use State.genesis(fleet); the fields are treated as immutable (apply returns a new State).
  constructor(f) { Object.assign(this, f); }

  static genesis(fleet) {
    validateFleet(fleet);
    return new State({
      fleetId: fleet.fleet_id,
      fleetHash: docHash(fleet),
      coordinatorKey: fleet.coordinator_key,
      n: fleet.keyholders.length,
      threshold: fleetThreshold(fleet),
      maxTtlMs: fleet.proposal_max_ttl_ms,
      offlineTimeoutMs: fleet.offline_timeout_ms,
      keys: new Map(fleet.keyholders.map((k) => [k.id, k.public_key])),
      suspended: new Set(),
      seq: 0,
      epoch: 0,
      haltedAll: false,
      halted: new Set(),
      roster: fleet.agents === null ? null : new Map(fleet.agents.map((a) => [a.id, a.max_instances])),
    });
  }

  get active() { return [...this.keys.keys()].filter((k) => !this.suspended.has(k)).sort(); }

  mayRun(agentId) { return !this.haltedAll && !this.halted.has(agentId); }

  // The state as the vectors compare it.
  summary() {
    const keys = {};
    for (const k of [...this.keys.keys()].sort()) keys[k] = this.keys.get(k);
    return { seq: this.seq, epoch: this.epoch, threshold: this.threshold, halted_all: this.haltedAll,
      halted: [...this.halted].sort(), active: this.active, suspended: [...this.suspended].sort(), keys };
  }

  with(changes) { return new State({ ...this, ...changes }); }
}

function checkTarget(st, p) {
  const a = p.action;
  const t = p.target;
  if (a === 'halt' || a === 'resume') {
    if (t !== '*' && !isId(t)) throw new SwitchError('SW-BAD-TARGET', 'target must be "*" or an agent id');
  } else if (a === 'suspend') {
    if (!st.keys.has(t) || st.suspended.has(t)) throw new SwitchError('SW-BAD-TARGET', 'target must be an active keyholder');
    if (st.active.length - 1 < st.threshold) {
      throw new SwitchError('SW-QUORUM-IMPOSSIBLE', `suspending this keyholder would leave fewer active keyholders than the threshold ${st.threshold}`);
    }
  } else {
    if (!st.suspended.has(t)) throw new SwitchError('SW-BAD-TARGET', 'target must be a suspended keyholder');
    const k = p.new_public_key;
    if ([...st.keys.values()].includes(k) || k === st.coordinatorKey) {
      throw new SwitchError('SW-BAD-TARGET', 'new_public_key must be a key not used in this fleet');
    }
  }
}

// Check cert against st at atMs; return its proposal or throw SwitchError. The order is that of
// spec/SEMANTICS.md, "Certificate checks". ahead: any seq above st.seq is accepted.
function verifyCertificate(st, cert, atMs, ahead = false) {
  checkCertificateFormat(cert);
  const p = checkProposalFormat(cert.proposal);
  if (p.fleet_id !== st.fleetId || p.fleet_hash !== st.fleetHash) throw new SwitchError('SW-WRONG-FLEET', 'the proposal is for another fleet');
  if (p.seq <= st.seq) throw new SwitchError('SW-STALE-SEQ', `seq ${p.seq} is not after the current seq ${st.seq}`);
  if (!ahead && p.seq !== st.seq + 1) throw new SwitchError('SW-SEQ-GAP', `seq ${p.seq} is not the next seq ${st.seq + 1}`);
  if (p.epoch !== st.epoch) throw new SwitchError('SW-WRONG-EPOCH', `epoch ${p.epoch} is not the current epoch ${st.epoch}`);
  if (p.expires_ms - p.created_ms > st.maxTtlMs) throw new SwitchError('SW-BAD-PROPOSAL', `the proposal is valid for longer than ${st.maxTtlMs} ms`);
  if (atMs >= p.expires_ms) throw new SwitchError('SW-EXPIRED', 'the proposal has expired');
  checkTarget(st, p);
  const msg = voteMessage(proposalHash(p));
  const seen = new Set();
  for (const v of cert.votes) {
    const kh = v.keyholder;
    if (!st.keys.has(kh)) throw new SwitchError('SW-UNKNOWN-KEYHOLDER', `${JSON.stringify(kh)} is not a keyholder of this fleet`);
    if (seen.has(kh)) throw new SwitchError('SW-DUPLICATE-VOTE', `${JSON.stringify(kh)} voted twice`);
    seen.add(kh);
    if (st.suspended.has(kh)) throw new SwitchError('SW-SUSPENDED-KEYHOLDER', `${JSON.stringify(kh)} is suspended`);
    if (p.action === 'suspend' && kh === p.target) throw new SwitchError('SW-TARGET-VOTE', 'a keyholder cannot vote on its own suspension');
    if (!ed25519.verify(st.keys.get(kh), msg, v.sig)) throw new SwitchError('SW-BAD-SIGNATURE', `the signature of ${JSON.stringify(kh)} does not verify`);
  }
  if (seen.size < st.threshold) throw new SwitchError('SW-NO-QUORUM', `${seen.size} valid votes, ${st.threshold} needed`);
  return p;
}

// Verify cert (seq must be st.seq + 1) and return the next state; st is not changed.
function apply(st, cert, atMs) {
  const p = verifyCertificate(st, cert, atMs);
  const t = p.target;
  const seq = st.seq + 1;
  switch (p.action) {
    case 'halt':
      return t === '*' ? st.with({ seq, haltedAll: true }) : st.with({ seq, halted: new Set([...st.halted, t]) });
    case 'resume': {
      if (t === '*') return st.with({ seq, haltedAll: false, halted: new Set() });
      const halted = new Set(st.halted);
      halted.delete(t);
      return st.with({ seq, halted });
    }
    case 'suspend':
      return st.with({ seq, epoch: st.epoch + 1, suspended: new Set([...st.suspended, t]) });
    default: {
      const suspended = new Set(st.suspended);
      suspended.delete(t);
      const keys = new Map(st.keys);
      keys.set(t, p.new_public_key);
      return st.with({ seq, epoch: st.epoch + 1, suspended, keys });
    }
  }
}

module.exports = {
  SwitchError, State, validateFleet, defaultThreshold, fleetThreshold, checkProposalFormat, checkCertificateFormat,
  proposalHash, voteMessage, verifyCertificate, apply, isId, isInt, hasFields,
  ID, NONCE, MAX_INT, HEARTBEAT_PREFIX, VOTE_PREFIX,
};
