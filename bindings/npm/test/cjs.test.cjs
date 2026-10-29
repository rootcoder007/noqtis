// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The CommonJS entry points.
'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const nq = require('../lib/index.cjs');
const nqnode = require('../lib/node.cjs');

test('require() entry', async () => {
  assert.throws(() => nq.algs(), /init/);
  await nq.init();
  await nq.init();
  assert.equal(nq.version(), '0.1.0');
  const { publicKey, secretKey } = nq.sign.keygen('ML-DSA-44');
  const sig = nq.sign.sign('ML-DSA-44', secretKey, 'cjs');
  assert.equal(nq.sign.verify('ML-DSA-44', publicKey, 'cjs', sig), true);
  const k = nq.kem.keygen('ML-KEM-512');
  const e = nq.kem.encap('ML-KEM-512', k.publicKey);
  assert.deepEqual(nq.kem.decap('ML-KEM-512', k.secretKey, e.ciphertext),
    e.sharedSecret);
  assert.equal(Buffer.from(nq.hash('sha256', 'abc')).toString('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.throws(() => nq.sign.keygen('nope'),
    (err) => err instanceof nq.NoqtisError && err.code === nq.codes.ENOSUP);
  assert.equal(typeof nqnode.checkDir, 'function');
});
