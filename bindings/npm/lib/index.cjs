// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// CommonJS entry: the same API as index.js, which it loads with a dynamic
// import() inside init() (Node 18 cannot require() an ES module). Every
// function but init() throws until init() has resolved.
'use strict';

let m = null;
let pending = null;

function need() {
  if (m === null) throw new Error('noqtis: call `await init()` first');
  return m;
}

async function init(opts) {
  if (pending === null) {
    pending = import('./index.js').then(async (mod) => {
      await mod.init(opts);
      m = mod;
    });
    pending.catch(() => {
      pending = null;
    });
  }
  return pending;
}

const fwd = (ns, fn) => (...a) => need()[ns][fn](...a);

class NoqtisError extends Error {}

module.exports = {
  init,
  version: (...a) => need().version(...a),
  algs: (...a) => need().algs(...a),
  random: (...a) => need().random(...a),
  hash: (...a) => need().hash(...a),
  hmac: (...a) => need().hmac(...a),
  errmsg: (...a) => need().errmsg(...a),
  sign: Object.freeze({
    keygen: fwd('sign', 'keygen'),
    sign: fwd('sign', 'sign'),
    verify: fwd('sign', 'verify'),
  }),
  kem: Object.freeze({
    keygen: fwd('kem', 'keygen'),
    encap: fwd('kem', 'encap'),
    decap: fwd('kem', 'decap'),
  }),
  capsule: Object.freeze({
    check: fwd('capsule', 'check'),
    seal: fwd('capsule', 'seal'),
  }),
  keyfile: Object.freeze({
    encode: fwd('keyfile', 'encode'),
    decode: fwd('keyfile', 'decode'),
  }),
  codes: Object.freeze({
    OK: 0, EARG: -1, EBUF: -2, EVRFY: -3, EDEC: -4, ERNG: -5, EMEM: -6,
    EIO: -7, ENOSUP: -8, ELIM: -9, ESTATE: -10,
  }),
};

// `err instanceof NoqtisError` works once init() has resolved: the class
// is the ES module's own.
Object.defineProperty(module.exports, 'NoqtisError', {
  enumerable: true,
  get: () => (m === null ? NoqtisError : m.NoqtisError),
});
