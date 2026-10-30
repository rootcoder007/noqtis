// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Identity cards: made and checked, each field refused, changed cards,
// another key, and a card kept apart from seals and key statements.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { init, idcard, capsule, sign, hash, codes, NoqtisError }
  from '../lib/index.js';

await init();

const enc = new TextEncoder();
const dec = new TextDecoder();
const T0 = 1767225600; // 2026-01-01T00:00:00Z
const err = (code) => (e) => e instanceof NoqtisError && e.code === code;
const hex = (u8) => Buffer.from(u8).toString('hex');

test('a card round trips', () => {
  const k = sign.keygen('ML-DSA-44');
  const card = idcard.make('ML-DSA-44', k.secretKey, k.publicKey, {
    name: 'Ada Lovelace', orcid: 'https://orcid.org/0000-0002-1694-233x',
    email: 'ada@example.org', url: 'https://example.org/ada', affil: 'AES',
  }, { at: T0 });
  const j = JSON.parse(dec.decode(card));
  assert.equal(j.format, 'noqtis-idcard-1');
  assert.equal(j.orcid, '0000-0002-1694-233X');
  assert.equal(j.created, '2026-01-01T00:00:00Z');
  const c = idcard.verify(card);
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.orcid, '0000-0002-1694-233X');
  assert.equal(c.email, 'ada@example.org');
  assert.equal(c.url, 'https://example.org/ada');
  assert.equal(c.affil, 'AES');
  assert.equal(c.created, '2026-01-01T00:00:00Z');
  assert.equal(c.alg, 'ML-DSA-44');
  assert.deepEqual(c.publicKey, k.publicKey);
  assert.equal(c.keySha256, hex(hash('sha256', k.publicKey)));
  assert.deepEqual(idcard.verify(dec.decode(card), { trust: k.publicKey }), c);
  const m = idcard.verify(idcard.make('ML-DSA-44', k.secretKey, k.publicKey,
    { name: 'Adéle 李' }, { at: new Date(T0 * 1000) }));
  assert.equal(m.name, 'Adéle 李');
  assert.equal(m.orcid, null);
  assert.equal(m.affil, null);
});

test('bad fields and keys are refused', () => {
  const k = sign.keygen('ML-DSA-44');
  const mk = (f) => idcard.make('ML-DSA-44', k.secretKey, k.publicKey, f,
    { at: T0 });
  for (const f of [
    { name: 'A', orcid: '0000-0002-1825-0098' }, { name: 'A', email: 'ada' },
    { name: 'A', url: 'http://example.org' }, { name: 'A', affil: '' },
    { name: ' A' }, { name: 'A\nB' }, { name: 'A\u009bB' },
    { name: 'x'.repeat(256) }, { name: 'A\0B' },
  ]) {
    assert.throws(() => mk(f), err(codes.EARG), JSON.stringify(f));
  }
  assert.ok(mk({ name: 'x'.repeat(255) }).length > 0);
  assert.throws(() => mk({}), TypeError);
  assert.throws(() => mk(null), TypeError);
  assert.throws(() => mk({ name: 'A', orcid: 1 }), TypeError);
  const k2 = sign.keygen('ML-DSA-44');
  assert.throws(() => idcard.make('ML-DSA-44', k2.secretKey, k.publicKey,
    { name: 'A' }), err(codes.EARG));
  const ed = sign.keygen('Ed25519');
  assert.throws(() => idcard.make('Ed25519', ed.secretKey, ed.publicKey,
    { name: 'A' }), err(codes.ENOSUP));
});

test('changed cards, other keys and other formats', () => {
  const k = sign.keygen('ML-DSA-44');
  const k2 = sign.keygen('ML-DSA-44');
  const card = dec.decode(idcard.make('ML-DSA-44', k.secretKey, k.publicKey,
    { name: 'Ada Lovelace' }, { at: T0 }));
  assert.equal(idcard.verify(card.replace('Ada Lovelace', 'Ada Lovelacf')),
    null);
  assert.equal(idcard.verify(card, { trust: k2.publicKey }), null);
  const j = JSON.parse(card);
  j.signature = JSON.parse(dec.decode(idcard.make('ML-DSA-44', k2.secretKey,
    k2.publicKey, { name: 'Ada Lovelace' }, { at: T0 }))).signature;
  assert.equal(idcard.verify(JSON.stringify(j)), null);
  assert.throws(() => idcard.verify(' ' + card), err(codes.EDEC));
  assert.throws(() => idcard.verify('{}'), err(codes.EDEC));
  assert.throws(() => idcard.verify('['.repeat(256 * 1024 + 1)),
    err(codes.ELIM));
  const rv = capsule.revoke('ML-DSA-44', k.secretKey, k.publicKey,
    { at: T0 });
  assert.throws(() => idcard.verify(rv), err(codes.EDEC));
  const f = new Map([['a.txt', enc.encode('a\n')]]);
  const s = capsule.seal(f, 'ML-DSA-44', k.secretKey, k.publicKey);
  assert.throws(() => idcard.verify(s['noqtis.sig']), err(codes.EDEC));
  f.set('noqtis.json', s['noqtis.json']);
  f.set('noqtis.sig', enc.encode(card));
  assert.equal(capsule.check(f, { trust: k.publicKey }).ok, false);
});
