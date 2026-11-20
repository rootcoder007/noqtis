// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// KangarooTwelve, ChaCha20, AES-SIV and AES-GCM-SIV: an answer of each
// RFC, the round trips and the refusals.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  init, kt128, kt256, chacha20, sivenc, sivdec, gsivenc, gsivdec, codes,
} from '../lib/index.js';

await init();
const hx = (s) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
const ptn = (n) => Uint8Array.from({ length: n }, (_, i) => i % 251);
const code = (f) => {
  try {
    f();
  } catch (e) {
    return e.code;
  }
  return 0;
};

test('KangarooTwelve gives the answers of RFC 9861', () => {
  assert.deepEqual(kt128(''), hx('1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5'));
  assert.deepEqual(kt128(ptn(17)), hx('6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888'));
  assert.deepEqual(kt128(Uint8Array.of(255), { custom: ptn(41) }),
    hx('d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4'));
  assert.deepEqual(kt256('', { length: 32 }),
    hx('b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404'));
  const big = ptn(20000);
  assert.deepEqual(kt128(big, { length: 100 }).slice(0, 32), kt128(big));
  assert.equal(kt256(big).length, 64);
  assert.notDeepEqual(kt128(big, { custom: 'a' }), kt128(big));
  assert.equal(code(() => kt128('x', { length: 0 })), codes.EARG);
});

test('ChaCha20 gives the answer of RFC 8439 and is its own inverse', () => {
  assert.deepEqual(chacha20(new Uint8Array(32), new Uint8Array(12), new Uint8Array(64)),
    hx('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'
      + 'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'));
  const k = ptn(32);
  const n = ptn(12);
  const m = ptn(300);
  const c = chacha20(k, n, m, { counter: 7 });
  assert.notDeepEqual(c, m);
  assert.deepEqual(chacha20(k, n, c, { counter: 7 }), m);
  assert.deepEqual(chacha20(k, n, m.slice(64), { counter: 8 }), c.slice(64));
  assert.deepEqual(chacha20(k, n, m.slice(0, 64), { counter: 0xffffffff }).length, 64);
  assert.equal(code(() => chacha20(k, n, m, { counter: 0xffffffff })), codes.ELIM);
  assert.equal(code(() => chacha20(k.slice(16), n, m)), codes.EARG);
  assert.equal(code(() => chacha20(k, n.slice(4), m)), codes.EARG);
  assert.equal(code(() => chacha20(k, n, m, { counter: -1 })), codes.EARG);
});

test('AES-SIV gives the answer of RFC 5297 and refuses a change', () => {
  const key = hx('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  const ad = hx('101112131415161718191a1b1c1d1e1f2021222324252627');
  const pt = hx('112233445566778899aabbccddee');
  const out = hx('85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c');
  assert.deepEqual(sivenc(key, pt, [ad]), out);
  assert.deepEqual(sivdec(key, out, [ad]), pt);
  assert.notDeepEqual(sivenc(key, pt), out);
  assert.notDeepEqual(sivenc(key, pt, [ad, '']), out);
  for (const k of [ptn(48), ptn(64)]) {
    assert.deepEqual(sivdec(k, sivenc(k, pt, [ad, 'n']), [ad, 'n']), pt);
  }
  assert.deepEqual(sivdec(key, sivenc(key, '')), new Uint8Array(0));
  const bad = out.slice();
  bad[20] ^= 1;
  assert.equal(code(() => sivdec(key, bad, [ad])), codes.EVRFY);
  assert.equal(code(() => sivdec(key, out, [])), codes.EVRFY);
  assert.equal(code(() => sivdec(ptn(32), out, [ad])), codes.EVRFY);
  assert.equal(code(() => sivenc(ptn(40), pt)), codes.EARG);
  assert.equal(code(() => sivdec(key, ptn(5))), codes.EARG);
  assert.equal(code(() => sivenc(key, pt, ad)), codes.EARG);
  assert.equal(code(() => sivenc(key, pt, Array(127).fill('a'))), codes.EARG);
});

test('AES-GCM-SIV gives the answer of RFC 8452 and refuses a change', () => {
  const key = hx('01000000000000000000000000000000');
  const nonce = hx('030000000000000000000000');
  const pt = hx('0100000000000000');
  const out = hx('b5d839330ac7b786578782fff6013b815b287c22493a364c');
  assert.deepEqual(gsivenc(key, nonce, pt), out);
  assert.deepEqual(gsivdec(key, nonce, out), pt);
  const k2 = ptn(32);
  const c = gsivenc(k2, nonce, pt, 'header');
  assert.deepEqual(gsivdec(k2, nonce, c, 'header'), pt);
  const bad = c.slice();
  bad[bad.length - 1] ^= 0x80;
  assert.equal(code(() => gsivdec(k2, nonce, bad, 'header')), codes.EVRFY);
  assert.equal(code(() => gsivdec(k2, nonce, c, 'other')), codes.EVRFY);
  assert.equal(code(() => gsivdec(k2, ptn(12), c, 'header')), codes.EVRFY);
  assert.equal(code(() => gsivenc(ptn(24), nonce, pt)), codes.EARG);
  assert.equal(code(() => gsivenc(key, ptn(8), pt)), codes.EARG);
  assert.equal(code(() => gsivdec(key, nonce, ptn(3))), codes.EARG);
});
