// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Capsules: the golden sample, seal/check round trips, refusals, and the
// node:fs helpers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync }
  from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { init, capsule, sign, codes, NoqtisError } from '../lib/index.js';
import { readCapsule, checkDir, sealDir } from '../lib/node.js';

await init();

const here = fileURLToPath(new URL('.', import.meta.url));
const sample = join(here, '..', '..', '..', 'tests', 'vectors', 'cap',
  'sample');
const enc = new TextEncoder();

const files = () => new Map([
  ['a.txt', enc.encode('hello\n')],
  ['dir/b.bin', new Uint8Array(1000).map((_, i) => i & 255)],
  ['dir/deep/e', new Uint8Array(0)],
  ['ünï code.txt', enc.encode('x')],
]);

test('the golden capsule checks', () => {
  const r = checkDir(sample);
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal(r.code, 0);
  assert.ok(r.checks.length >= 3);
  assert.ok(r.checks.every((c) => c.ok && typeof c.check === 'string'));
  // tampered, extra, missing
  const f = readCapsule(sample);
  const t = new Map(f);
  t.set('a.txt', enc.encode('hellp\n'));
  const r2 = capsule.check(t);
  assert.equal(r2.ok, false);
  assert.equal(r2.code, codes.EVRFY);
  assert.ok(r2.checks.some((c) => !c.ok));
  const x = new Map(f);
  x.set('extra', enc.encode('1'));
  assert.equal(capsule.check(x).ok, false);
  const m = new Map(f);
  m.delete('data/b.csv');
  assert.equal(capsule.check(m).ok, false);
  const s = new Map(f);
  const sig = s.get('noqtis.sig').slice();
  sig[sig.length - 10] ^= 1;
  s.set('noqtis.sig', sig);
  assert.equal(capsule.check(s).ok, false);
});

test('seal and check round trip', () => {
  for (const alg of ['ML-DSA-65', 'SLH-DSA-SHA2-128f']) {
    const { publicKey: pk, secretKey: sk } = sign.keygen(alg);
    const f = files();
    const out = capsule.seal(f, alg, sk, pk, {
      meta: { project: 'js', n: 2 }, time: 1700000000,
    });
    const json = new TextDecoder().decode(out['noqtis.json']);
    assert.match(json, /"created":"2023-11-14T22:13:20Z"/);
    assert.match(json, /"meta":\{"n":2,"project":"js"\}/);
    for (const [k, v] of Object.entries(out)) f.set(k, v);
    const r = capsule.check(f);
    assert.equal(r.ok, true, JSON.stringify(r.checks));
    assert.equal(capsule.check(f, { trust: pk }).ok, true);
    const other = sign.keygen(alg).publicKey;
    assert.equal(capsule.check(f, { trust: other }).ok, false);
    // the same files and time give the same manifest
    const again = capsule.seal(files(), alg, sk, pk, {
      meta: { project: 'js', n: 2 }, time: 1700000000,
    });
    assert.equal(new TextDecoder().decode(again['noqtis.json']), json);
  }
  // no time: the clock
  const { publicKey: pk, secretKey: sk } = sign.keygen('ML-DSA-44');
  const out = capsule.seal({ 'f': 'x' }, 'ML-DSA-44', sk, pk);
  const y = new Date().getUTCFullYear();
  assert.match(new TextDecoder().decode(out['noqtis.json']),
    new RegExp(`"created":"${y}-`));
});

test('capsule refusals', () => {
  const { publicKey: pk, secretKey: sk } = sign.keygen('ML-DSA-44');
  for (const bad of ['../x', '/abs', 'a//b', './a', 'a/', '']) {
    assert.throws(() => capsule.seal({ [bad]: 'x' }, 'ML-DSA-44', sk, pk),
      (e) => e instanceof NoqtisError && e.code === codes.EARG, bad);
  }
  assert.throws(() => capsule.seal(new Map([['a', 'x'], ['a/b', 'y']]),
    'ML-DSA-44', sk, pk), NoqtisError);
  assert.throws(() => capsule.seal({ f: 'x' }, 'ML-DSA-44', sk, pk,
    { meta: '{not json' }), NoqtisError);
  assert.throws(() => capsule.seal({ f: 'x' }, 'ML-DSA-44', sk, pk,
    { time: -1 }), NoqtisError);
  // a key pair that does not match
  const pk2 = sign.keygen('ML-DSA-44').publicKey;
  assert.throws(() => capsule.seal({ f: 'x' }, 'ML-DSA-44', sk, pk2),
    NoqtisError);
  // no seal at all: a failed check, not an exception
  const r = capsule.check({ f: 'x' });
  assert.equal(r.ok, false);
  assert.equal(r.code, codes.EVRFY);
});

test('node:fs helpers', () => {
  const d = mkdtempSync(join(tmpdir(), 'nqjs-'));
  try {
    mkdirSync(join(d, 'sub', 'deeper'), { recursive: true });
    writeFileSync(join(d, 'top.txt'), 'top');
    writeFileSync(join(d, 'sub', 'deeper', 'z'), new Uint8Array(70000));
    const { publicKey: pk, secretKey: sk } = sign.keygen('ML-DSA-87');
    sealDir(d, 'ML-DSA-87', sk, pk, { time: 0 });
    const r = checkDir(d, { trust: pk });
    assert.equal(r.ok, true, JSON.stringify(r.checks));
    writeFileSync(join(d, 'top.txt'), 'tap');
    assert.equal(checkDir(d).ok, false);
    writeFileSync(join(d, 'top.txt'), 'top');
    assert.equal(checkDir(d).ok, true);
    let linked = true;
    try {
      symlinkSync('top.txt', join(d, 'link'));
    } catch {
      linked = false; // no symlinks here (Windows without privilege)
    }
    if (linked) {
      assert.throws(() => checkDir(d),
        (e) => e instanceof NoqtisError && e.code === codes.EARG);
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
