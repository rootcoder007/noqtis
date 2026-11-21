// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Armor, certificates, CMS and S/MIME, OpenPGP and the key store.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { init, armor, mail, pgp, keystore, sign, kem, codes, NoqtisError }
  from '../lib/main.js';

await init();

const enc = new TextEncoder();
const dec = new TextDecoder();
const T0 = 1767225600; // 2026-01-01T00:00:00Z
const YEAR = 365 * 86400;
const err = (code) => (e) => e instanceof NoqtisError && e.code === code;

test('armor goes there and back', () => {
  const data = Uint8Array.from([0, 1, 255, 10, 20, 30, 40, 50]);
  const a = armor.encode('NOQTIS TEST', data);
  assert.ok(a.startsWith('-----BEGIN NOQTIS TEST-----\n'));
  const r = armor.decode(a);
  assert.equal(r.label, 'NOQTIS TEST');
  assert.deepEqual(r.data, data);
  assert.throws(() => armor.decode('not armor'), err(codes.EDEC));
  assert.throws(() => armor.encode('lower case', data), err(codes.EARG));
});

function mailkeys() {
  const k = sign.keygen('ML-DSA-44');
  const cert = mail.selfCert('ML-DSA-44', k.secretKey, k.publicKey,
    'Ada Example', { email: 'ada@example.org', notBefore: T0,
      notAfter: T0 + YEAR });
  const e = kem.keygen('ML-KEM-768');
  const kc = mail.kemCert('ML-DSA-44', k.secretKey, cert, 'ML-KEM-768',
    e.publicKey, { notBefore: T0, notAfter: T0 + YEAR });
  return { k, cert, e, kc };
}

test('certificates say what they were made with', () => {
  const m = mailkeys();
  const c = mail.readCert(m.cert);
  assert.equal(c.alg, 'ML-DSA-44');
  assert.equal(c.kem, false);
  assert.equal(c.ca, true);
  assert.equal(c.name, 'Ada Example');
  assert.equal(c.email, 'ada@example.org');
  assert.deepEqual(c.publicKey, m.k.publicKey);
  assert.equal(c.notBefore, T0);
  assert.equal(c.notAfter, T0 + YEAR);
  assert.equal(c.fingerprint.length, 64);
  const k = mail.readCert(m.kc);
  assert.equal(k.kem, true);
  assert.equal(k.alg, 'ML-KEM-768');
  assert.equal(k.name, 'Ada Example');
  assert.deepEqual(k.publicKey, m.e.publicKey);
  assert.throws(() => mail.readCert(enc.encode('not a certificate')),
    err(codes.EDEC));
});

test('CMS signs, verifies against anchors, and encrypts', () => {
  const m = mailkeys();
  const msg = enc.encode('a message to sign and to seal');
  for (const detached of [false, true]) {
    const s = mail.cmsSign('ML-DSA-44', m.k.secretKey, m.cert, msg,
      { detached, at: T0 + 3600 });
    const o = { content: detached ? msg : null, at: T0 + 3600 };
    const v = mail.cmsVerify(s, [m.cert], o);
    assert.deepEqual(v.content, msg);
    assert.equal(v.signer.name, 'Ada Example');
    assert.equal(mail.cmsVerify(s, [m.kc], o), null);
    assert.equal(mail.cmsVerify(s, [], o), null);
  }
  const e = mail.cmsEncrypt([m.kc], msg);
  assert.deepEqual(mail.cmsDecrypt('ML-KEM-768', m.e.secretKey, e,
    { certificate: m.kc }), msg);
  assert.deepEqual(mail.cmsDecrypt('ML-KEM-768', m.e.secretKey, e), msg);
  const other = kem.keygen('ML-KEM-768');
  assert.equal(mail.cmsDecrypt('ML-KEM-768', other.secretKey, e), null);
});

test('S/MIME messages round trip', () => {
  const m = mailkeys();
  const ent = 'Content-Type: text/plain\r\n\r\nhello, mail\r\n';
  const sm = mail.smimeSign('ML-DSA-44', m.k.secretKey, m.cert, ent,
    { detached: true, at: T0 + 3600 });
  assert.ok(sm.includes('multipart/signed') && sm.includes('hello, mail'));
  const v = mail.smimeVerify(sm, [m.cert], { at: T0 + 3600 });
  assert.equal(v.entity, ent);
  assert.equal(v.signer.email, 'ada@example.org');
  assert.equal(mail.smimeVerify(sm.replace('hello', 'jello'), [m.cert],
    { at: T0 + 3600 }), null);
  const se = mail.smimeEncrypt([m.kc], ent);
  assert.equal(mail.smimeDecrypt('ML-KEM-768', m.e.secretKey, se), ent);
  const other = kem.keygen('ML-KEM-768');
  assert.equal(mail.smimeDecrypt('ML-KEM-768', other.secretKey, se), null);
});

test('OpenPGP keys, signatures and messages', () => {
  const pw = 'a passphrase';
  const k = pgp.generate('Ada Example <ada@example.org>',
    { passphrase: pw, created: T0 });
  const f = pgp.info(k.certificate);
  assert.equal(f.alg, 'mldsa65-ed25519');
  assert.equal(f.encAlg, 'mlkem768-x25519');
  assert.equal(f.secret, false);
  assert.equal(f.expires, null);
  assert.equal(f.created, T0);
  assert.equal(f.userId, 'Ada Example <ada@example.org>');
  assert.equal(f.fingerprint.length, 64);
  assert.equal(f.encFingerprint.length, 64);
  const s = pgp.info(k.secretKey);
  assert.ok(s.secret && s.locked);
  const a = pgp.armor('public key', k.certificate);
  assert.ok(a.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'));
  const d = pgp.dearmor(a);
  assert.equal(d.kind, 'public key');
  assert.deepEqual(d.data, k.certificate);
  const msg = enc.encode('signed text\nof two lines\n');
  for (const mode of ['inline', 'detached', 'clear']) {
    const sig = pgp.sign(k.secretKey, msg,
      { mode, passphrase: pw, at: T0 + 60 });
    const v = pgp.verify(k.certificate, sig,
      { content: mode === 'detached' ? msg : null });
    assert.equal(v.at, T0 + 60);
    if (mode !== 'clear') assert.deepEqual(v.data, msg);
    else assert.ok(dec.decode(sig).startsWith('-----BEGIN PGP SIGNED'));
  }
  assert.throws(() => pgp.sign(k.secretKey, msg, { passphrase: 'wrong' }),
    err(codes.EVRFY));
  const e = pgp.encrypt(msg, { to: [k.certificate],
    passphrase: 'open sesame', signer: k.secretKey, signerPassphrase: pw,
    at: T0 + 60 });
  let o = pgp.decrypt(e, { key: k.secretKey, passphrase: pw,
    signer: k.certificate });
  assert.deepEqual(o.data, msg);
  assert.equal(o.signed, true);
  assert.equal(o.at, T0 + 60);
  o = pgp.decrypt(pgp.armor('message', e), { passphrase: 'open sesame' });
  assert.deepEqual(o.data, msg);
  assert.equal(o.signed, false);
  assert.equal(pgp.decrypt(e, { passphrase: 'open sesam' }), null);
  const so = pgp.generate('Sig <sig@example.org>',
    { alg: 'ed25519', encAlg: null });
  assert.equal(pgp.info(so.certificate).encAlg, null);
  assert.throws(() => pgp.generate('X', { alg: 'rsa' }), err(codes.ENOSUP));
});

test('a key store keeps, certifies and carries keys', () => {
  const me = sign.keygen('ML-DSA-44');
  const bob = kem.keygen('ML-KEM-768');
  let r = keystore.add(null, 'ML-DSA-44', me.publicKey, 'Me Myself',
    { email: 'me@example.org' });
  const mine = r.fingerprint;
  r = keystore.add(r.files, 'ML-KEM-768', bob.publicKey, 'Bob Other',
    { email: 'bob@example.org' });
  const his = r.fingerprint;
  let files = r.files;
  assert.equal(mine.length, 32);
  assert.equal(keystore.list(files).length, 2);
  let l = keystore.list(files, 'bob@example.org');
  assert.equal(l.length, 1);
  assert.equal(l[0].alg, 'ML-KEM-768');
  assert.equal(l[0].kem, true);
  assert.equal(l[0].valid, 'none');
  assert.equal(l[0].trust, 'unknown');
  assert.deepEqual(l[0].fingerprint, his);
  const g = keystore.get(files, his);
  assert.equal(g.alg, 'ML-KEM-768');
  assert.deepEqual(g.publicKey, bob.publicKey);
  files = keystore.trust(files, mine, 'ultimate').files;
  r = keystore.certify(files, 'ML-DSA-44', me.secretKey, me.publicKey, his,
    { at: T0 });
  assert.ok(r.cert.length > 0);
  files = r.files;
  l = keystore.list(files, 'bob@example.org');
  assert.equal(l[0].valid, 'full');
  assert.equal(l[0].certs, 1);
  const bundle = keystore.export(files, his);
  const im = keystore.import(null, bundle, { email: 'bob@example.org' });
  assert.deepEqual(im.fingerprint, his);
  assert.ok(im.keys >= 1);
  assert.equal(keystore.list(im.files).length, im.keys);
  assert.throws(() => keystore.import(null, bundle,
    { email: 'eve@example.org' }), NoqtisError);
  files = keystore.remove(files, his).files;
  assert.equal(keystore.list(files).length, 1);
  assert.throws(() => keystore.trust(files, new Uint8Array(5), 'full'),
    err(codes.EARG));
  assert.throws(() => keystore.trust(files, mine, 'somewhat'),
    err(codes.EARG));
  const u = keystore.url('Ada@Example.org');
  assert.ok(u.startsWith('https://example.org/.well-known/noqtis/'));
  assert.throws(() => keystore.url('no address'), err(codes.EARG));
});
