'use strict';
// SmartSwitch agent side for Node.js. Semantics: spec/SEMANTICS.md; tests: spec/conformance.
module.exports = {
  ...require('./canonical'),
  ...require('./ed25519'),
  ...require('./protocol'),
  ...require('./log'),
  ...require('./agentview'),
  ...require('./agent'),
};
