// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A runtime smoke test with no test framework, for Deno and Bun:
//   deno run --allow-read test/smoke.js    bun test/smoke.js
import { init, sign, kem, hash, capsule, random, version } from '../lib/index.js';

const fail = (m) => {
  throw new Error(`smoke: ${m}`);
};
await init();
for (const alg of ['ML-DSA-65', 'SLH-DSA-SHAKE-128f']) {
  const k = sign.keygen(alg);
  const s = sign.sign(alg, k.secretKey, 'smoke', { ctx: 'x' });
  if (!sign.verify(alg, k.publicKey, 'smoke', s, { ctx: 'x' })) fail(alg);
  if (sign.verify(alg, k.publicKey, 'smoke', s)) fail(`${alg} ctx`);
}
for (const alg of ['ML-KEM-768', 'HQC-128']) {
  const k = kem.keygen(alg);
  const e = kem.encap(alg, k.publicKey);
  const ss = kem.decap(alg, k.secretKey, e.ciphertext);
  if (ss.join() !== e.sharedSecret.join()) fail(alg);
}
const h = Array.from(hash('sha256', 'abc'),
  (b) => b.toString(16).padStart(2, '0')).join('');
if (h !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
  fail('sha256');
}
const k = sign.keygen('ML-DSA-44');
const f = new Map([['a.txt', 'a'], ['d/b', new Uint8Array(10)]]);
for (const [n, v] of Object.entries(capsule.seal(f, 'ML-DSA-44', k.secretKey,
  k.publicKey))) f.set(n, v);
if (!capsule.check(f, { trust: k.publicKey }).ok) fail('capsule');
const a = random(32);
const b = random(32);
if (a.join() === b.join()) fail('random');
console.log(`smoke OK noqtis ${version()}`);
