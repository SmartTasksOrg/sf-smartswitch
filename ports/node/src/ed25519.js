'use strict';
// Ed25519 verify (RFC 8032) through Node's crypto (OpenSSL), with the engine's own pre-checks from
// spec/SEMANTICS.md, "Signatures": lower-case hex of the right length and S < L, before the library call.
const crypto = require('crypto');

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const isKeyHex = (s) => typeof s === 'string' && HEX64.test(s);

function verify(publicHex, message, sigHex) {
  if (!isKeyHex(publicHex) || typeof sigHex !== 'string' || !HEX128.test(sigHex)) return false;
  const sig = Buffer.from(sigHex, 'hex');
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  if (s >= L) return false;
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicHex, 'hex')]), format: 'der', type: 'spki' });
    return crypto.verify(null, message, key, sig) === true;
  } catch (e) {
    return false;
  }
}

module.exports = { verify, isKeyHex, L };
