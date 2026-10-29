// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// CommonJS entry for `noqtis/node`; call require('noqtis').init() first.
'use strict';

let m = null;

async function load() {
  if (m === null) m = await import('./node.js');
  return m;
}

// The ES module is loaded by init() of the main entry; these wait for it.
module.exports = {
  readCapsule: async (...a) => (await load()).readCapsule(...a),
  checkDir: async (...a) => (await load()).checkDir(...a),
  sealDir: async (...a) => (await load()).sealDir(...a),
};
