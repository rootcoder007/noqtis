// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Passphrase key files, streaming signatures and hashes, messages and
// streams sealed to an ML-KEM key, external mu, BLAKE2b and Argon2id,
// against the known answers of tests/vectors (pwk, kseal, kstream,
// acvp/mu.txt, b2b, argon2) and the failures their formats name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { init, sign, kem, keyfile, hash, hasher, blake2b, argon2id, cteq,
  algs, codes, NoqtisError } from '../lib/main.js';

await init();

const here = fileURLToPath(new URL('.', import.meta.url));
const V = join(here, '..', '..', '..', 'tests', 'vectors');
const hx = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const kv = (name) => {
  const out = [];
  let cur = {};
  for (const l of [...readFileSync(join(V, name), 'utf8').split('\n'), '']) {
    if (l.startsWith('#')) continue;
    if (l === '') {
      if (Object.keys(cur).length) out.push(cur);
      cur = {};
      continue;
    }
    const i = l.indexOf('=');
    cur[l.slice(0, i)] = l.slice(i + 1);
  }
  return out;
};
const code = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof NoqtisError, String(e));
    return e.code;
  }
  assert.fail('no error');
};
const acode = async (fn) => {
  try {
    await fn();
  } catch (e) {
    assert.ok(e instanceof NoqtisError, String(e));
    return e.code;
  }
  assert.fail('no error');
};

test('passphrase key files: known answers, round trips, failures', () => {
  const v = kv('pwk/kat.txt');
  for (const r of v) {
    assert.deepEqual(keyfile.pwdec(hx(r.pw), hx(r.out), { ad: hx(r.ad) }),
      hx(r.sk));
  }
  const r = v[0];
  const out = hx(r.out);
  assert.equal(code(() => keyfile.pwdec('wrong', out, { ad: hx(r.ad) })),
    codes.EVRFY);
  assert.equal(code(() => keyfile.pwdec(hx(r.pw), out, { ad: 'x' })),
    codes.EVRFY);
  assert.equal(code(() => keyfile.pwdec(hx(r.pw), out.slice(0, 40),
    { ad: hx(r.ad) })), codes.EDEC);
  const o2 = out.slice();
  o2[o2.length - 1] ^= 1;
  assert.equal(code(() => keyfile.pwdec(hx(r.pw), o2, { ad: hx(r.ad) })),
    codes.EVRFY);
  const { secretKey } = sign.keygen('ML-DSA-44');
  assert.equal(code(() => keyfile.pwenc('pw', secretKey, { m: 1024, t: 1,
    p: 1 })), codes.EARG);
  const t = keyfile.encode('ML-DSA-44', 'sec', secretKey,
    { passphrase: 'pass' });
  assert.ok(t.startsWith('noqtis-key-1 ML-DSA-44 sec\n'));
  assert.deepEqual(keyfile.decode(t, { passphrase: 'pass' }).key, secretKey);
  assert.equal(code(() => keyfile.decode(t)), codes.EARG);
  try {
    keyfile.decode(t, { passphrase: 'nope' });
    assert.fail('opened');
  } catch (e) {
    assert.equal(e.code, codes.EVRFY);
    assert.ok(!/nope|pass/.test(e.message), e.message);
  }
});

test('streaming signatures are the one-call ones', () => {
  const msg = new Uint8Array(10000).map((_, i) => i % 251);
  for (const [alg, ph, n] of [['ML-DSA-44', undefined, 32],
    ['ML-DSA-65', 'sha512', 32], ['SLH-DSA-SHA2-128f', 'sha256', 48],
    ['Ed25519', 'sha512', 32], ['ML-DSA-65+Ed25519', 'sha512', 64]]) {
    const seed = new Uint8Array(n).map((_, i) => i);
    const k = sign.keygen(alg, { seed });
    const o = { ctx: 'c', prehash: ph, deterministic: true };
    const want = sign.sign(alg, k.secretKey, msg, o);
    for (const step of [1, 7, 4096, msg.length]) {
      const s = sign.signer(alg, k.secretKey, o);
      for (let i = 0; i < msg.length; i += step) {
        s.update(msg.subarray(i, i + step));
      }
      assert.deepEqual(s.sign(o), want, `${alg} ${step}`);
      assert.equal(code(() => s.update(msg)), codes.ESTATE);
    }
    const v = sign.verifier(alg, k.publicKey, o);
    v.update(msg);
    assert.equal(v.verify(want), true);
    const w = sign.verifier(alg, k.publicKey, o);
    w.update(msg.subarray(1));
    assert.equal(w.verify(want), false);
  }
  const { secretKey } = sign.keygen('SLH-DSA-SHA2-128f');
  assert.equal(code(() => sign.signer('SLH-DSA-SHA2-128f', secretKey)),
    codes.ENOSUP);
});

test('streaming hashes', () => {
  const msg = new Uint8Array(5000).fill(7);
  for (const a of ['sha256', 'sha3-384', 'sha512-224']) {
    const h = hasher(a);
    h.update(msg.subarray(0, 100)).update(msg.subarray(100));
    assert.deepEqual(h.digest(), hash(a, msg));
  }
  const h = hasher('shake128');
  h.update(msg);
  const x = [...h.digest(5), ...h.digest(27)];
  assert.deepEqual(Uint8Array.from(x), hash('shake128', msg, { length: 32 }));
  h.end();
});

test('sealed messages: known answers and failures', () => {
  const v = kv('kseal/kat.txt');
  for (const r of v) {
    const k = kem.keygen(r.alg, { seed: hx(r.kseed) });
    assert.deepEqual(kem.open(r.alg, k.secretKey, hx(r.out), { ctx: hx(r.ctx) }),
      hx(r.msg));
  }
  const r = v[v.length - 1];
  const k = kem.keygen(r.alg, { seed: hx(r.kseed) });
  const out = hx(r.out);
  out[30] ^= 1;
  assert.equal(code(() => kem.open(r.alg, k.secretKey, out,
    { ctx: hx(r.ctx) })), codes.EVRFY);
  assert.equal(code(() => kem.open(r.alg, k.secretKey, out.slice(0, 10))),
    codes.EDEC);
  const c = kem.seal(r.alg, k.publicKey, 'round', { ctx: 'x' });
  assert.equal(Buffer.from(kem.open(r.alg, k.secretKey, c, { ctx: 'x' }))
    .toString(), 'round');
  assert.equal(code(() => kem.open(r.alg, k.secretKey, c, { ctx: 'y' })),
    codes.EVRFY);
});

async function collect(it) {
  const parts = [];
  for await (const p of it) parts.push(p);
  return Buffer.concat(parts);
}

// the bytes in pieces of n
function* pieces(b, n) {
  for (let i = 0; i < b.length; i += n) yield b.subarray(i, i + n);
}

test('sealed streams: known answers and failures', async () => {
  const v = kv('kstream/kat.txt');
  const open = (r, b, n = 1000) => collect(kem.unbox(r.alg,
    kem.keygen(r.alg, { seed: hx(r.kseed) }).secretKey, pieces(b, n),
    { ctx: hx(r.ctx) }));
  let big = v[0];
  for (const r of v) {
    assert.deepEqual(new Uint8Array(await open(r, hx(r.out), 777)), hx(r.msg));
    if (r.out.length > big.out.length) big = r;
  }
  const a = algs().find((x) => x.name === big.alg);
  const out = hx(big.out);
  const h = 17 + a.ciphertext;
  const n = Number(big.chunk) + 16;
  const ch = out.slice();
  ch[h + 5] ^= 1;
  assert.equal(await acode(() => open(big, ch)), codes.EVRFY);
  assert.equal(await acode(() => open(big, out.slice(0, out.length - 3))),
    codes.EVRFY);
  const last = h + Math.floor((out.length - h - 1) / n) * n;
  assert.equal(await acode(() => open(big, out.slice(0, last))), codes.EVRFY);
  const sw = out.slice();
  sw.set(out.subarray(h, h + n), h + n);
  sw.set(out.subarray(h + n, h + 2 * n), h);
  assert.equal(await acode(() => open(big, sw)), codes.EVRFY);
  const ex = new Uint8Array(out.length + 1);
  ex.set(out);
  assert.equal(await acode(() => open(big, ex)), codes.EVRFY);
  const k = kem.keygen('ML-KEM-768');
  for (const m of [0, 1, 1023, 1024, 1025, 4096, 5000]) {
    const p = new Uint8Array(m).map((_, i) => i % 251);
    const e = await collect(kem.box('ML-KEM-768', k.publicKey, pieces(p, 300),
      { ctx: 'ctx', chunk: 1024 }));
    const d = await collect(kem.unbox('ML-KEM-768', k.secretKey,
      pieces(e, 500), { ctx: 'ctx' }));
    assert.deepEqual(new Uint8Array(d), p, `round trip ${m}`);
  }
  assert.equal(code(() => kem.sealer('ML-KEM-768', k.publicKey,
    { chunk: 100 })), codes.EARG);
});

test('external mu, BLAKE2b, Argon2id', () => {
  for (const r of kv('acvp/mu.txt')) {
    if (r.kind === 'gen') {
      assert.deepEqual(sign.signmu(r.alg, hx(r.key), hx(r.mu),
        { rnd: hx(r.rnd) }), hx(r.sig));
    } else {
      assert.equal(sign.verifymu(r.alg, hx(r.key), hx(r.mu), hx(r.sig)),
        r.ok === '1');
    }
  }
  const k = sign.keygen('ML-DSA-65');
  const o = { ctx: 'c', deterministic: true };
  const mu = sign.mu('ML-DSA-65', k.publicKey, 'msg', o);
  assert.deepEqual(sign.signmu('ML-DSA-65', k.secretKey, mu, o),
    sign.sign('ML-DSA-65', k.secretKey, 'msg', o));
  assert.equal(code(() => sign.mu('Ed25519', new Uint8Array(32), 'm')),
    codes.ENOSUP);
  for (const r of kv('b2b/kat.txt')) {
    const d = hx(r.hash);
    assert.deepEqual(blake2b(hx(r.in), { key: hx(r.key), length: d.length }),
      d);
  }
  assert.equal(code(() => blake2b('', { length: 65 })), codes.EARG);
  for (const r of [...kv('argon2/rfc9106.txt'), ...kv('argon2/ossl.txt')]) {
    if (r.y !== '2') continue;
    const t = hx(r.tag);
    assert.deepEqual(argon2id(hx(r.pw), hx(r.salt), { t: Number(r.t),
      m: Number(r.m), p: Number(r.p), length: t.length, key: hx(r.key),
      ad: hx(r.ad) }), t);
  }
  assert.equal(cteq('abc', 'abc'), true);
  assert.equal(cteq('abc', 'abd'), false);
  assert.equal(cteq('a', 'ab'), false);
});
