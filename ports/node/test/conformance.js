'use strict';
// Runs spec/conformance against this port, check for check as src/sf_smartswitch/conformance.py does.
// Usage: node test/conformance.js [vector dir]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ss = require('../src');

const dir = process.argv[2] || path.join(__dirname, '..', '..', '..', 'spec', 'conformance');
const load = (n) => JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8'));

// JSON value equality: key order does not matter.
function same(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => same(x, b[i]));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return same(ka, kb) && ka.every((k) => same(a[k], b[k]));
}
const show = (v) => { try { return ss.dumps(v).slice(0, 300); } catch (e) { return String(JSON.stringify(v)).slice(0, 300); } };
const pick = (c, keys) => Object.fromEntries(keys.filter((k) => Object.prototype.hasOwnProperty.call(c, k)).map((k) => [k, c[k]]));

let total = 0;
const fails = [];
function check(name, got, want) {
  total++;
  if (!same(got, want)) fails.push(`${name}: got ${show(got)}, want ${show(want)}`);
}
function code(fn) {
  try { return fn(); } catch (e) { if (e instanceof ss.SwitchError) return { ok: false, code: e.code }; throw e; }
}

for (const c of load('canonical.json').cases) {
  const text = ss.dumps(c.input);
  check('canonical/' + c.name, [text, crypto.createHash('sha256').update(text, 'utf8').digest('hex')], [c.canonical, c.sha256]);
}

for (const c of load('ed25519.json').cases) {
  check('ed25519/' + c.name, ss.verify(c.public_key, Buffer.from(c.message_hex, 'hex'), c.sig), c.valid);
}

const fleets = load('fleets.json');
for (const c of fleets.default_thresholds) check(`fleets/default threshold n=${c.n}`, ss.defaultThreshold(c.n), c.k);
for (const c of fleets.cases) {
  const got = code(() => {
    ss.validateFleet(c.fleet);
    return { ok: true, fleet_hash: ss.docHash(c.fleet), threshold: ss.State.genesis(c.fleet).threshold };
  });
  check('fleets/' + c.name, got, pick(c, ['ok', 'fleet_hash', 'threshold', 'code']));
}

const certs = load('certificates.json');
for (const c of certs.cases) {
  let st = ss.State.genesis(certs.fleets[c.fleet]);
  for (const s of c.setup) st = ss.apply(st, s.certificate, s.at_ms);
  let ph = null;
  if (ss.isObject(c.certificate) && Object.prototype.hasOwnProperty.call(c.certificate, 'proposal')) {
    try { ph = ss.proposalHash(c.certificate.proposal); } catch (e) { ph = null; }
  }
  check(`certificates/${c.name} (proposal hash)`, ph, c.proposal_hash);
  const got = code(() => {
    if (c.ahead) {
      ss.verifyCertificate(st, c.certificate, c.at_ms, true);
      return { ok: true, state: null };
    }
    return { ok: true, state: ss.apply(st, c.certificate, c.at_ms).summary() };
  });
  check('certificates/' + c.name, got, pick(c, ['ok', 'state', 'code']));
}

for (const c of load('logs.json').cases) check('logs/' + c.name, ss.replay(c.entries, c.pinned), c.result);

const agent = load('agent.json');
for (const c of agent.cases) {
  const view = new ss.AgentView(agent.fleet, c.agent_id, c.instance_id);
  c.steps.forEach((s, i) => {
    let got;
    if (s.op === 'log') got = view.log(s.entries);
    else if (s.op === 'heartbeat') got = view.heartbeat(s.heartbeat, s.nonce, s.at_ms);
    else if (s.op === 'certificate') got = view.certificate(s.certificate, s.at_ms);
    else got = view.status(s.at_ms);
    check(`agent/${c.name} step ${i} (${s.op})`, got, s.expect);
  });
}

for (const f of fails) console.log('FAIL', f);
console.log(fails.length ? `node: FAILED, ${fails.length} of ${total} vectors` : `node: ${total}/${total} vectors passed`);
process.exit(fails.length ? 1 : 0);
