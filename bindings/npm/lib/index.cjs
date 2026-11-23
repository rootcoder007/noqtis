// SPDX-License-Identifier: LGPL-3.0-or-later
//
// CommonJS entry: the same API as main.js (index.js with the package's
// own noqtis.wasm found on Node), which it loads with import() of that one
// fixed file inside init(). Every function but init() throws until init()
// has resolved.
'use strict';

let m = null;
let pending = null;

function need() {
  if (m === null) throw new Error('noqtis: call `await init()` first');
  return m;
}

async function init(opts) {
  if (pending === null) {
    pending = import('./main.js').then(async (mod) => {
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
  selftest: (...a) => need().selftest(...a),
  algs: (...a) => need().algs(...a),
  random: (...a) => need().random(...a),
  hash: (...a) => need().hash(...a),
  hmac: (...a) => need().hmac(...a),
  errmsg: (...a) => need().errmsg(...a),
  cteq: (...a) => need().cteq(...a),
  blake2b: (...a) => need().blake2b(...a),
  argon2id: (...a) => need().argon2id(...a),
  pbkdf2: (...a) => need().pbkdf2(...a),
  kt128: (...a) => need().kt128(...a),
  kt256: (...a) => need().kt256(...a),
  chacha20: (...a) => need().chacha20(...a),
  sivenc: (...a) => need().sivenc(...a),
  sivdec: (...a) => need().sivdec(...a),
  gsivenc: (...a) => need().gsivenc(...a),
  gsivdec: (...a) => need().gsivdec(...a),
  hasher: (...a) => need().hasher(...a),
  sign: Object.freeze({
    keygen: fwd('sign', 'keygen'),
    sign: fwd('sign', 'sign'),
    verify: fwd('sign', 'verify'),
    mu: fwd('sign', 'mu'),
    signmu: fwd('sign', 'signmu'),
    verifymu: fwd('sign', 'verifymu'),
    sxsize: fwd('sign', 'sxsize'),
    sxmake: fwd('sign', 'sxmake'),
    sxcheck: fwd('sign', 'sxcheck'),
    signer: fwd('sign', 'signer'),
    verifier: fwd('sign', 'verifier'),
  }),
  kem: Object.freeze({
    keygen: fwd('kem', 'keygen'),
    encap: fwd('kem', 'encap'),
    decap: fwd('kem', 'decap'),
    seal: fwd('kem', 'seal'),
    open: fwd('kem', 'open'),
    sealer: fwd('kem', 'sealer'),
    opener: fwd('kem', 'opener'),
    box: fwd('kem', 'box'),
    unbox: fwd('kem', 'unbox'),
  }),
  capsule: Object.freeze({
    check: fwd('capsule', 'check'),
    seal: fwd('capsule', 'seal'),
    id: fwd('capsule', 'id'),
    prove: fwd('capsule', 'prove'),
    files: fwd('capsule', 'files'),
    rotate: fwd('capsule', 'rotate'),
    revoke: fwd('capsule', 'revoke'),
    inspect: fwd('capsule', 'inspect'),
    sealWhy: fwd('capsule', 'sealWhy'),
    tsreq: fwd('capsule', 'tsreq'),
    tsput: fwd('capsule', 'tsput'),
    ersreq: fwd('capsule', 'ersreq'),
    ersput: fwd('capsule', 'ersput'),
    pack: fwd('capsule', 'pack'),
    unpack: fwd('capsule', 'unpack'),
    chain: fwd('capsule', 'chain'),
  }),
  dsse: Object.freeze({
    sign: fwd('dsse', 'sign'),
    verify: fwd('dsse', 'verify'),
  }),
  idcard: Object.freeze({
    make: fwd('idcard', 'make'),
    verify: fwd('idcard', 'verify'),
  }),
  armor: Object.freeze({
    encode: fwd('armor', 'encode'),
    decode: fwd('armor', 'decode'),
  }),
  mail: Object.freeze({
    selfCert: fwd('mail', 'selfCert'),
    kemCert: fwd('mail', 'kemCert'),
    readCert: fwd('mail', 'readCert'),
    cmsSign: fwd('mail', 'cmsSign'),
    cmsVerify: fwd('mail', 'cmsVerify'),
    cmsEncrypt: fwd('mail', 'cmsEncrypt'),
    cmsDecrypt: fwd('mail', 'cmsDecrypt'),
    smimeSign: fwd('mail', 'smimeSign'),
    smimeVerify: fwd('mail', 'smimeVerify'),
    smimeEncrypt: fwd('mail', 'smimeEncrypt'),
    smimeDecrypt: fwd('mail', 'smimeDecrypt'),
  }),
  pgp: Object.freeze({
    generate: fwd('pgp', 'generate'),
    info: fwd('pgp', 'info'),
    sign: fwd('pgp', 'sign'),
    verify: fwd('pgp', 'verify'),
    encrypt: fwd('pgp', 'encrypt'),
    decrypt: fwd('pgp', 'decrypt'),
    armor: fwd('pgp', 'armor'),
    dearmor: fwd('pgp', 'dearmor'),
  }),
  keystore: Object.freeze({
    add: fwd('keystore', 'add'),
    list: fwd('keystore', 'list'),
    get: fwd('keystore', 'get'),
    certify: fwd('keystore', 'certify'),
    addCert: fwd('keystore', 'addCert'),
    trust: fwd('keystore', 'trust'),
    remove: fwd('keystore', 'remove'),
    export: fwd('keystore', 'export'),
    imports: fwd('keystore', 'imports'),
    url: fwd('keystore', 'url'),
  }),
  keyfile: Object.freeze({
    encode: fwd('keyfile', 'encode'),
    decode: fwd('keyfile', 'decode'),
    pwenc: fwd('keyfile', 'pwenc'),
    pwenc2: fwd('keyfile', 'pwenc2'),
    KDF_ARGON2ID: 1,
    KDF_PBKDF2: 2,
    pwdec: fwd('keyfile', 'pwdec'),
  }),
  data: Object.freeze(Object.fromEntries(['canon', 'add', 'put', 'check',
    'schema', 'schemaCheck', 'pin', 'drift', 'diff', 'addrs', 'verify',
    'field', 'request', 'reply', 'wayback', 'key', 'del', 'synth',
    'calibrate', 'chunks', 'piece', 'commitment', 'commit', 'reveal', 'cite',
    'report', 'env'].map((n) => [n, fwd('data', n)]))),
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
