// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Capsule format 2, proofs, partial checks, lineage, key statements and
// DSSE envelopes.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { init, capsule, dsse, sign, hash, codes, NoqtisError }
  from '../lib/index.js';
import { checkDir } from '../lib/node.js';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

await init();

const enc = new TextEncoder();
const dec = new TextDecoder();
const T0 = 1700000000;

const files = () => new Map([
  ['f0.csv', enc.encode('a,b\n0,2\n')],
  ['f1.csv', enc.encode('a,b\n1,2\n')],
  ['sub/y.bin', new Uint8Array(256).map((_, i) => i)],
]);

function sealed(alg, k, opts = {}) {
  const f = files();
  const out = capsule.seal(f, alg, k.secretKey, k.publicKey, opts);
  f.set('noqtis.json', out['noqtis.json']);
  f.set('noqtis.sig', out['noqtis.sig']);
  return f;
}

const rows = (r, n) => r.checks.filter((c) => c.check === n);
const err = (code) => (e) => e instanceof NoqtisError && e.code === code;

test('format 2 seals, checks, ids and lists', () => {
  const k = sign.keygen('ML-DSA-44');
  const f = sealed('ML-DSA-44', k, { format: 2, time: T0 });
  assert.equal(JSON.parse(dec.decode(f.get('noqtis.sig'))).format,
    'noqtis-seal-2');
  const r = capsule.check(f, { trust: k.publicKey });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  const id = capsule.id(f);
  assert.equal(id.length, 32);
  assert.deepEqual(capsule.id(f), id);
  const l = capsule.files(new Map([['noqtis.json', f.get('noqtis.json')],
    ['noqtis.sig', f.get('noqtis.sig')]]));
  assert.deepEqual(l.map((x) => x.path).sort(),
    ['f0.csv', 'f1.csv', 'sub/y.bin']);
  const y = l.find((x) => x.path === 'sub/y.bin');
  assert.equal(y.size, 256);
  assert.equal(y.sha256, Buffer.from(hash('sha256', f.get('sub/y.bin')))
    .toString('hex'));
  assert.throws(() => capsule.seal(files(), 'ML-DSA-44', k.secretKey,
    k.publicKey, { format: 3 }), err(codes.EARG));
  assert.throws(() => capsule.seal(files(), 'ML-DSA-44', k.secretKey,
    k.publicKey, { format: 1, inputs: [] }), err(codes.EARG));
  assert.throws(() => capsule.id(files()), err(codes.EIO));
  assert.throws(() => capsule.files(files()), NoqtisError);
});

test('proofs', () => {
  const k = sign.keygen('ML-DSA-65');
  const f = sealed('ML-DSA-65', k, { format: 2 });
  const p = capsule.prove(f, ['f1.csv']);
  const t = dec.decode(p);
  assert.equal(JSON.parse(t).format, 'noqtis-proof-1');
  assert.ok(!t.includes('f0.csv') && !t.includes('sub/y.bin'));
  const r = capsule.check(null, { proof: p, trust: k.publicKey });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal(rows(r, 'proof.entry').length, 1);
  assert.equal(capsule.check(f, { proof: p, trust: k.publicKey }).ok, true);
  assert.equal(capsule.check(null, { proof: t }).ok, true);
  const g = new Map(f);
  g.set('f1.csv', enc.encode('x'));
  assert.equal(capsule.check(g, { proof: p }).ok, false);
  const k2 = sign.keygen('ML-DSA-65');
  assert.equal(capsule.check(null, { proof: p, trust: k2.publicKey }).ok,
    false);
  assert.equal(capsule.check(null,
    { proof: t.replace('f1.csv', 'f9.csv') }).ok, false);
  assert.ok(capsule.prove(f, 'sub/y.bin').length > 0);
  assert.throws(() => capsule.prove(f, ['nope']), err(codes.EIO));
  assert.throws(() => capsule.prove(f, []), err(codes.EARG));
  assert.throws(() => capsule.check(f, { proof: p, only: ['f1.csv'] }),
    err(codes.EARG));
  assert.throws(() => capsule.check(null), TypeError);
  const v1 = sealed('ML-DSA-65', k);
  assert.throws(() => capsule.prove(v1, ['f0.csv']), err(codes.ENOSUP));
});

test('partial checks', () => {
  const k = sign.keygen('ML-DSA-44');
  for (const format of [1, 2]) {
    const f = sealed('ML-DSA-44', k, { format });
    f.set('f0.csv', enc.encode('changed'));
    f.delete('sub/y.bin');
    assert.equal(capsule.check(f).ok, false);
    const r = capsule.check(f, { only: ['f1.csv'] });
    assert.equal(r.ok, true, JSON.stringify(r.checks));
    assert.ok(rows(r, 'partial').length > 0);
    assert.equal(capsule.check(f, { only: ['f0.csv'] }).ok, false);
    assert.equal(capsule.check(f, { only: ['missing'] }).ok, false);
  }
});

test('lineage', () => {
  const k = sign.keygen('ML-DSA-44');
  const a = sealed('ML-DSA-44', k);
  const b = sealed('ML-DSA-44', k,
    { inputs: [{ name: 'raw', id: capsule.id(a) }] });
  const m = JSON.parse(dec.decode(b.get('noqtis.json')));
  assert.equal(m.inputs[0].name, 'raw');
  const r = capsule.check(b, { trust: k.publicKey, lineage: [a] });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal(rows(r, 'lineage').length, 1);
  // with folders given, an input not among them fails
  assert.equal(capsule.check(b, { lineage: [b] }).ok, false);
  const a2 = new Map(a);
  a2.set('f0.csv', enc.encode('changed'));
  const r2 = capsule.check(b, { lineage: [a2] });
  assert.equal(r2.ok, false);
  assert.ok(rows(r2, 'lineage').some((c) => !c.ok));
  assert.throws(() => capsule.seal(files(), 'ML-DSA-44', k.secretKey,
    k.publicKey, { inputs: [{ name: 'x', id: new Uint8Array(3) }] }),
  err(codes.EARG));
  // the node helper takes folders
  const tmp = mkdtempSync(join(tmpdir(), 'nqlin-'));
  try {
    for (const [n, cap] of [['a', a], ['b', b]]) {
      for (const [p, d] of cap) {
        const full = join(tmp, n, ...p.split('/'));
        mkdirSync(join(full, '..'), { recursive: true });
        writeFileSync(full, d);
      }
    }
    assert.equal(checkDir(join(tmp, 'b'), { lineage: [join(tmp, 'a')] }).ok,
      true);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('key statements', () => {
  const k1 = sign.keygen('ML-DSA-44');
  const k2 = sign.keygen('ML-DSA-65');
  const st = capsule.rotate('ML-DSA-44', k1.secretKey, k1.publicKey,
    'ML-DSA-65', k2.secretKey, k2.publicKey, { at: T0, reason: 'yearly' });
  assert.equal(JSON.parse(dec.decode(st)).format, 'noqtis-keys-1');
  const d = sealed('ML-DSA-65', k2);
  assert.equal(capsule.check(d, { trust: k1.publicKey }).ok, false);
  const r = capsule.check(d, { trust: k1.publicKey, keys: [st] });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  const rv = capsule.revoke('ML-DSA-44', k1.secretKey, k1.publicKey,
    { at: new Date(T0 * 1000) });
  const e = sealed('ML-DSA-44', k1);
  assert.equal(capsule.check(e, { trust: k1.publicKey }).ok, true);
  const r2 = capsule.check(e, { trust: k1.publicKey, keys: [rv] });
  assert.equal(r2.ok, false);
  assert.ok(rows(r2, 'key.time').some((c) => !c.ok));
  assert.throws(() => capsule.check(e, { keys: [rv] }), err(codes.EARG));
  assert.throws(() => capsule.rotate('ML-DSA-44', k1.secretKey, k1.publicKey,
    'ML-DSA-44', k1.secretKey, k1.publicKey, { at: T0 }), err(codes.EARG));
  const ed = sign.keygen('Ed25519');
  assert.throws(() => capsule.revoke('Ed25519', ed.secretKey, ed.publicKey),
    err(codes.ENOSUP));
});

test('DSSE envelopes', () => {
  const t = 'application/vnd.in-toto+json';
  for (const alg of ['ML-DSA-65', 'Ed25519', 'ML-DSA-44+Ed25519',
    'SLH-DSA-SHAKE-128f']) {
    const k = sign.keygen(alg);
    const env = dsse.sign(alg, k.secretKey, k.publicKey, t, '{"a":1}');
    const j = JSON.parse(dec.decode(env));
    assert.equal(j.payloadType, t);
    assert.equal(j.signatures[0].keyid,
      Buffer.from(hash('sha256', k.publicKey)).toString('hex'));
    const v = dsse.verify(alg, k.publicKey, env);
    assert.equal(v.payloadType, t);
    assert.equal(dec.decode(v.payload), '{"a":1}');
    assert.equal(dsse.verify(alg, k.publicKey, dec.decode(env)).payloadType,
      t);
    assert.equal(dsse.verify(alg, sign.keygen(alg).publicKey, env), null);
    j.payload = 'e30=';
    assert.equal(dsse.verify(alg, k.publicKey, JSON.stringify(j)), null);
  }
  const k = sign.keygen('ML-DSA-44');
  assert.throws(() => dsse.verify('ML-DSA-44', k.publicKey, 'not json'),
    err(codes.EDEC));
  assert.throws(() => dsse.sign('ML-DSA-44', k.secretKey, k.publicKey,
    'has space', 'x'), err(codes.EARG));
  assert.throws(() => dsse.sign('ML-DSA-44', k.secretKey,
    sign.keygen('ML-DSA-44').publicKey, 't', 'x'), err(codes.EARG));
  assert.equal(dsse.sign('ML-DSA-44', k.secretKey, k.publicKey, 'text/plain',
    new Uint8Array(0)).length > 0, true);
});

test('a hybrid key seals; Ed25519 alone does not', () => {
  const k = sign.keygen('ML-DSA-65+Ed25519');
  const f = sealed('ML-DSA-65+Ed25519', k, { format: 2 });
  assert.equal(capsule.check(f, { trust: k.publicKey }).ok, true);
  const e = sign.keygen('Ed25519');
  assert.throws(() => capsule.seal(files(), 'Ed25519', e.secretKey,
    e.publicKey), err(codes.ENOSUP));
});
