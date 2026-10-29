// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A sample of the NIST ACVP vectors (tests/vectors/acvp in the repository)
// through the JavaScript API: the first few cases of every group. The C
// test suite runs every vector; this checks the binding passes them on
// unchanged. Skips when the vectors are not there (an installed package).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { init, sign, kem, hash } from '../lib/index.js';

await init();

const dir = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..',
  '..', 'tests', 'vectors', 'acvp');
const skip = existsSync(dir) ? false : 'no ACVP vectors here';
const PER = Number(process.env.NQJSACVP || 3); // cases per group
const hex = (u8) => Buffer.from(u8).toString('hex');
const un = (s) => new Uint8Array(Buffer.from(s, 'hex'));

// [group, case, expected] for the first PER cases of each group
function* cases(set, per = PER) {
  const p = JSON.parse(readFileSync(join(dir, set, 'prompt.json'), 'utf8'));
  const e = JSON.parse(readFileSync(join(dir, set, 'expectedResults.json'),
    'utf8'));
  const want = new Map();
  for (const g of e.testGroups) {
    for (const t of g.tests) want.set(`${g.tgId}/${t.tcId}`, t);
  }
  for (const g of p.testGroups) {
    for (const t of g.tests.slice(0, per)) {
      yield [g, t, want.get(`${g.tgId}/${t.tcId}`)];
    }
  }
}

const HASH = {
  'SHA2-224': 'sha224', 'SHA2-256': 'sha256', 'SHA2-384': 'sha384',
  'SHA2-512': 'sha512', 'SHA2-512/224': 'sha512-224',
  'SHA2-512/256': 'sha512-256', 'SHA3-224': 'sha3-224',
  'SHA3-256': 'sha3-256', 'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512',
  'SHAKE-128': 'shake128', 'SHAKE-256': 'shake256',
};

test('ML-DSA keyGen', { skip }, () => {
  let n = 0;
  for (const [g, t, w] of cases('ML-DSA-keyGen-FIPS204')) {
    const k = sign.keygen(g.parameterSet, { seed: un(t.seed) });
    assert.equal(hex(k.publicKey), w.pk.toLowerCase(), `tc ${t.tcId}`);
    assert.equal(hex(k.secretKey), w.sk.toLowerCase(), `tc ${t.tcId}`);
    n++;
  }
  assert.ok(n >= 9, `${n} cases`);
});

test('ML-DSA sigVer (external interface)', { skip }, () => {
  let n = 0;
  for (const [g, t, w] of cases('ML-DSA-sigVer-FIPS204', 5)) {
    if (g.signatureInterface !== 'external') continue;
    const opts = { ctx: un(t.context) };
    if (g.preHash === 'preHash') opts.prehash = HASH[t.hashAlg];
    if (g.preHash === 'preHash' && !opts.prehash) continue;
    assert.equal(sign.verify(g.parameterSet, un(t.pk), un(t.message),
      un(t.signature), opts), w.testPassed, `tg ${g.tgId} tc ${t.tcId}`);
    n++;
  }
  assert.ok(n >= 20, `${n} cases`);
});

test('SLH-DSA keyGen', { skip }, () => {
  let n = 0;
  for (const [g, t, w] of cases('SLH-DSA-keyGen-FIPS205', 2)) {
    const seed = un(t.skSeed + t.skPrf + t.pkSeed);
    const k = sign.keygen(g.parameterSet, { seed });
    assert.equal(hex(k.publicKey), w.pk.toLowerCase(), `tc ${t.tcId}`);
    assert.equal(hex(k.secretKey), w.sk.toLowerCase(), `tc ${t.tcId}`);
    n++;
  }
  assert.ok(n >= 24, `${n} cases`);
});

test('ML-KEM keyGen', { skip }, () => {
  let n = 0;
  for (const [g, t, w] of cases('ML-KEM-keyGen-FIPS203')) {
    const k = kem.keygen(g.parameterSet, { seed: un(t.d + t.z) });
    assert.equal(hex(k.publicKey), w.ek.toLowerCase(), `tc ${t.tcId}`);
    assert.equal(hex(k.secretKey), w.dk.toLowerCase(), `tc ${t.tcId}`);
    n++;
  }
  assert.ok(n >= 9, `${n} cases`);
});

test('ML-KEM encapsulation and decapsulation', { skip }, () => {
  let n = 0;
  for (const [g, t, w] of cases('ML-KEM-encapDecap-FIPS203')) {
    if (g.function === 'encapsulation') {
      const e = kem.encap(g.parameterSet, un(t.ek), { seed: un(t.m) });
      assert.equal(hex(e.ciphertext), w.c.toLowerCase(), `tc ${t.tcId}`);
      assert.equal(hex(e.sharedSecret), w.k.toLowerCase(), `tc ${t.tcId}`);
      n++;
    } else if (g.function === 'decapsulation') {
      assert.equal(hex(kem.decap(g.parameterSet, un(t.dk), un(t.c))),
        w.k.toLowerCase(), `tc ${t.tcId}`);
      n++;
    }
  }
  assert.ok(n >= 18, `${n} cases`);
});

test('SHA-2 and SHA-3 (byte-aligned AFT cases)', { skip }, () => {
  let n = 0;
  for (const set of ['SHA2-256-1.0', 'SHA2-512-1.0', 'SHA2-512-224-1.0',
    'SHA3-256-2.0', 'SHA3-512-2.0']) {
    const alg = HASH[set.replace(/-[0-9.]+$/, '').replace('512-2', '512/2')];
    for (const [g, t, w] of cases(set, 20)) {
      if (g.testType !== 'AFT' || t.len % 8 !== 0) continue;
      const m = un(t.msg).subarray(0, t.len / 8);
      assert.equal(hex(hash(alg, m)), w.md.toLowerCase(), `${set} ${t.tcId}`);
      n++;
    }
  }
  assert.ok(n >= 25, `${n} cases`);
});
