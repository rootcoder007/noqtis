// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The JavaScript API: every algorithm, rejections, hashes, randomness.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nc from 'node:crypto';

import nq, {
  init, algs, version, random, hash, hmac, sign, kem, keyfile, codes,
  errmsg, NoqtisError, _heap,
} from '../lib/index.js';

await init();

const hex = (u8) => Buffer.from(u8).toString('hex');
const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const flip = (u8, i = 0) => {
  const c = u8.slice();
  c[i] ^= 1;
  return c;
};
const throwsCode = (fn, code) => assert.throws(fn, (e) => {
  assert.ok(e instanceof NoqtisError, `NoqtisError, got ${e}`);
  assert.equal(e.code, code);
  return true;
});

const SIGS = algs().filter((a) => a.kind === 'sign');
const KEMS = algs().filter((a) => a.kind === 'kem');

test('algs and version', () => {
  assert.equal(version(), '0.1.0');
  assert.equal(SIGS.length, 15);
  assert.equal(KEMS.length, 6);
  assert.equal(algs().filter((a) => a.kind === 'hash').length, 12);
  const md = SIGS.find((a) => a.name === 'ML-DSA-65');
  assert.deepEqual([md.publicKey, md.secretKey, md.signature],
    [1952, 4032, 3309]);
  const mk = KEMS.find((a) => a.name === 'ML-KEM-768');
  assert.deepEqual([mk.publicKey, mk.secretKey, mk.ciphertext,
    mk.sharedSecret], [1184, 2400, 1088, 32]);
  const sl = SIGS.find((a) => a.name === 'SLH-DSA-SHA2-128s');
  assert.deepEqual([sl.publicKey, sl.secretKey, sl.signature],
    [32, 64, 7856]);
  assert.equal(nq.sign, sign);
});

for (const a of SIGS) {
  test(`sign ${a.name}`, () => {
    const msg = new TextEncoder().encode(`message for ${a.name}`);
    const ctx = 'noqtis-js';
    const slow = /^SLH-DSA-.*s$/.test(a.name);
    const { publicKey: pk, secretKey: sk } = sign.keygen(a.name);
    assert.equal(pk.length, a.publicKey);
    assert.equal(sk.length, a.secretKey);
    const sig = sign.sign(a.name, sk, msg, { ctx });
    assert.equal(sig.length, a.signature);
    assert.equal(sign.verify(a.name, pk, msg, sig, { ctx }), true);
    // case does not matter in names
    assert.equal(sign.verify(a.name.toLowerCase(), pk, msg, sig, { ctx }),
      true);
    // rejections
    assert.equal(sign.verify(a.name, pk, flip(msg), sig, { ctx }), false);
    assert.equal(sign.verify(a.name, pk, msg, sig, { ctx: 'other' }), false);
    assert.equal(sign.verify(a.name, pk, msg, sig), false);
    assert.equal(sign.verify(a.name, pk, msg, flip(sig, 5), { ctx }), false);
    assert.equal(sign.verify(a.name, pk, msg,
      flip(sig, sig.length - 1), { ctx }), false);
    assert.equal(sign.verify(a.name, pk, msg, sig.subarray(1), { ctx }),
      false);
    const other = sign.keygen(a.name).publicKey;
    assert.equal(sign.verify(a.name, other, msg, sig, { ctx }), false);
    // deterministic: same bytes twice; hedged: fresh randomness each time.
    // The SLH-DSA "s" sets sign slowly, so they make fewer signatures.
    const d1 = sign.sign(a.name, sk, msg, { ctx, deterministic: true });
    assert.equal(sign.verify(a.name, pk, msg, d1, { ctx }), true);
    assert.notEqual(hex(sig), hex(d1));
    if (!slow) {
      const d2 = sign.sign(a.name, sk, msg, { ctx, deterministic: true });
      assert.equal(hex(d1), hex(d2));
      const h2 = sign.sign(a.name, sk, msg, { ctx });
      assert.notEqual(hex(sig), hex(h2));
      // string messages are UTF-8
      const s2 = sign.sign(a.name, sk, 'héllo');
      assert.equal(sign.verify(a.name, pk,
        new TextEncoder().encode('héllo'), s2), true);
    }
    // pre-hash variants are domain separated from the pure one
    const ph = sign.sign(a.name, sk, msg, { prehash: 'sha512' });
    assert.equal(sign.verify(a.name, pk, msg, ph, { prehash: 'sha512' }),
      true);
    assert.equal(sign.verify(a.name, pk, msg, ph), false);
    assert.equal(sign.verify(a.name, pk, msg, ph, { prehash: 'sha256' }),
      false);
    // seeded keys are reproducible
    const n = a.name.startsWith('ML-DSA') ? 32 : (a.publicKey / 2) * 3;
    const seed = new Uint8Array(n).map((_, i) => i);
    const k1 = sign.keygen(a.name, { seed });
    const k2 = sign.keygen(a.name, { seed });
    assert.equal(hex(k1.publicKey), hex(k2.publicKey));
    assert.equal(hex(k1.secretKey), hex(k2.secretKey));
    throwsCode(() => sign.keygen(a.name, { seed: seed.subarray(1) }),
      codes.EARG);
  });
}

test('sign argument errors', () => {
  const { secretKey: sk, publicKey: pk } = sign.keygen('ML-DSA-44');
  throwsCode(() => sign.keygen('ML-DSA-99'), codes.ENOSUP);
  throwsCode(() => sign.sign('ML-DSA-44', sk, 'm',
    { ctx: new Uint8Array(256) }), codes.EARG);
  throwsCode(() => sign.sign('ML-DSA-44', sk, 'm', { prehash: 'md5' }),
    codes.ENOSUP);
  throwsCode(() => sign.sign('ML-DSA-44', sk, 'm',
    { rnd: new Uint8Array(31) }), codes.EARG);
  assert.equal(sign.verify('ML-DSA-44', pk, 'm', new Uint8Array(0)), false);
  assert.throws(() => sign.sign('ML-DSA-44', 'not bytes', 'm'), TypeError);
  // a key of the wrong length is refused
  assert.throws(() => sign.sign('ML-DSA-44', sk.subarray(1), 'm'),
    NoqtisError);
  const e = new NoqtisError(codes.EVRFY);
  assert.equal(e.message, errmsg(codes.EVRFY));
  assert.ok(e.message.length > 0);
  for (const c of Object.values(codes)) assert.ok(errmsg(c).length > 0);
});

for (const a of KEMS) {
  test(`kem ${a.name}`, () => {
    const { publicKey: pk, secretKey: sk } = kem.keygen(a.name);
    assert.equal(pk.length, a.publicKey);
    assert.equal(sk.length, a.secretKey);
    const { ciphertext: ct, sharedSecret: ss } = kem.encap(a.name, pk);
    assert.equal(ct.length, a.ciphertext);
    assert.equal(ss.length, a.sharedSecret);
    assert.equal(hex(kem.decap(a.name, sk, ct)), hex(ss));
    // implicit rejection: no error, an unrelated secret, the same each time
    const bad = flip(ct, 3);
    const r1 = kem.decap(a.name, sk, bad);
    const r2 = kem.decap(a.name, sk, bad);
    assert.notEqual(hex(r1), hex(ss));
    assert.equal(hex(r1), hex(r2));
    // the wrong secret key
    const other = kem.keygen(a.name).secretKey;
    assert.notEqual(hex(kem.decap(a.name, other, ct)), hex(ss));
    // fresh randomness per encapsulation
    assert.notEqual(hex(kem.encap(a.name, pk).sharedSecret), hex(ss));
    // malformed sizes throw
    assert.throws(() => kem.decap(a.name, sk, ct.subarray(1)), NoqtisError);
    assert.throws(() => kem.encap(a.name, pk.subarray(1)), NoqtisError);
  });
}

test('kem seeded keys and encapsulation', () => {
  const seed = new Uint8Array(64).map((_, i) => 255 - i);
  const k1 = kem.keygen('ML-KEM-768', { seed });
  const k2 = kem.keygen('ML-KEM-768', { seed });
  assert.equal(hex(k1.publicKey), hex(k2.publicKey));
  const m = new Uint8Array(32).fill(7);
  const e1 = kem.encap('ML-KEM-768', k1.publicKey, { seed: m });
  const e2 = kem.encap('ML-KEM-768', k1.publicKey, { seed: m });
  assert.equal(hex(e1.ciphertext), hex(e2.ciphertext));
  assert.equal(hex(kem.decap('ML-KEM-768', k1.secretKey, e1.ciphertext)),
    hex(e1.sharedSecret));
  throwsCode(() => kem.keygen('ML-KEM-768', { seed: seed.subarray(1) }),
    codes.EARG);
  throwsCode(() => kem.keygen('X25519'), codes.ENOSUP);
});

test('hashes against known digests', () => {
  const abc = 'abc';
  const kat = {
    sha224: '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    sha384: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed' +
      '8086072ba1e7cc2358baeca134c825a7',
    sha512: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
      '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'sha512-224': '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
    'sha512-256':
      '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23',
    'sha3-224': 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    'sha3-256':
      '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    'sha3-384': 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0' +
      'e49be4b298d88cea927ac7f539f1edf228376d25',
    'sha3-512': 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d02' +
      '40d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
  };
  for (const [a, d] of Object.entries(kat)) assert.equal(hex(hash(a, abc)), d, a);
  assert.equal(hex(hash('shake128', '')),
    '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26');
  assert.equal(hex(hash('shake256', '')),
    '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
    'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be');
  assert.equal(hash('SHA256', abc).length, 32);
  throwsCode(() => hash('md5', abc), codes.ENOSUP);
  throwsCode(() => hash('sha256', abc, { length: 16 }), codes.EARG);
});

test('hashes and HMAC match node:crypto', () => {
  const node = {
    sha224: 'sha224', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512',
    'sha512-224': 'sha512-224', 'sha512-256': 'sha512-256',
    'sha3-224': 'sha3-224', 'sha3-256': 'sha3-256', 'sha3-384': 'sha3-384',
    'sha3-512': 'sha3-512',
  };
  const have = new Set(nc.getHashes());
  for (const len of [0, 1, 135, 136, 137, 1000, 100000]) {
    const d = nc.randomBytes(len);
    for (const [a, n] of Object.entries(node)) {
      if (!have.has(n)) continue;
      assert.equal(hex(hash(a, d)), nc.createHash(n).update(d).digest('hex'),
        `${a} ${len}`);
      const k = nc.randomBytes(len % 200);
      assert.equal(hex(hmac(a, k, d)),
        nc.createHmac(n, k).update(d).digest('hex'), `hmac ${a} ${len}`);
    }
    for (const [a, out] of [['shake128', 200], ['shake256', 300]]) {
      if (!have.has(a)) continue;
      assert.equal(hex(hash(a, d, { length: out })),
        nc.createHash(a, { outputLength: out }).update(d).digest('hex'));
    }
  }
  throwsCode(() => hmac('shake128', 'k', 'd'), codes.ENOSUP);
});

test('randomness comes from crypto.getRandomValues and is not repeated', () => {
  const c = globalThis.crypto ?? nc.webcrypto;
  const orig = c.getRandomValues;
  let calls = 0;
  c.getRandomValues = function spy(v) {
    calls++;
    return orig.call(this, v);
  };
  let a;
  let b;
  try {
    a = random(64);
    b = random(64);
  } finally {
    c.getRandomValues = orig;
  }
  assert.ok(calls >= 2, `getRandomValues calls: ${calls}`);
  assert.notEqual(hex(a), hex(b));
  assert.notEqual(hex(a), '00'.repeat(64));
  assert.equal(random(0).length, 0);
  assert.equal(random(1000).length, 1000);
  // keys without a seed differ
  assert.notEqual(hex(sign.keygen('ML-DSA-44').publicKey),
    hex(sign.keygen('ML-DSA-44').publicKey));
  assert.notEqual(hex(kem.keygen('ML-KEM-512').publicKey),
    hex(kem.keygen('ML-KEM-512').publicKey));
});

test('a failing random source fails closed (NQERNG)', () => {
  const c = globalThis.crypto ?? nc.webcrypto;
  const orig = c.getRandomValues;
  c.getRandomValues = () => {
    throw new Error('no entropy');
  };
  try {
    throwsCode(() => random(16), codes.ERNG);
    throwsCode(() => sign.keygen('ML-DSA-44'), codes.ERNG);
  } finally {
    c.getRandomValues = orig;
  }
  assert.equal(random(16).length, 16);
});

test('key files', () => {
  for (const a of ['ML-DSA-65', 'SLH-DSA-SHAKE-128f', 'ML-KEM-768',
    'HQC-128']) {
    const k = a.startsWith('ML-DSA') || a.startsWith('SLH')
      ? sign.keygen(a) : kem.keygen(a);
    for (const [kind, b] of [['pub', k.publicKey], ['sec', k.secretKey]]) {
      const t = keyfile.encode(a, kind, b);
      assert.ok(t.startsWith(`noqtis-key-1 ${a} ${kind}\n`));
      assert.ok(t.split('\n').every((l) => l.length <= 64 || l.startsWith('n')));
      const d = keyfile.decode(t);
      assert.equal(d.alg, a);
      assert.equal(d.kind, kind);
      assert.equal(hex(d.key), hex(b));
      assert.equal(hex(keyfile.decode(t.replace(/\n/g, '\r\n')).key), hex(b));
      // the base64 matches Buffer's
      assert.equal(t.split('\n').slice(1).join(''),
        Buffer.from(b).toString('base64'));
    }
  }
  const t = keyfile.encode('ML-DSA-44', 'pub', sign.keygen('ML-DSA-44')
    .publicKey);
  assert.throws(() => keyfile.decode(t.replace('pub', 'xyz')), NoqtisError);
  assert.throws(() => keyfile.decode(t.replace('A', '*')), NoqtisError);
  assert.throws(() => keyfile.decode(t.replace('ML-DSA-44', 'ml-dsa-44')),
    NoqtisError);
  assert.throws(() => keyfile.decode(t.split('\n').slice(0, 3).join('\n')),
    NoqtisError);
  // non-canonical padding bits
  const one = keyfile.decode(t).key;
  assert.equal(one.length, 1312);
  assert.throws(() => keyfile.decode('noqtis-key-1 ML-DSA-44 pub\nAB==\n'),
    NoqtisError);
  for (const x of ['QQ==', 'QR==', 'QUI=', 'QUJ=']) {
    // 'QQ==' / 'QUI=' are canonical; 'QR==' / 'QUJ=' are not
    const ok = x === 'QQ==' || x === 'QUI=';
    const f = () => keyfile.decode(`noqtis-key-1 ML-DSA-44 pub\n${x}\n`);
    // all fail on length, but non-canonical ones fail first on encoding
    assert.throws(f, (e) => e instanceof NoqtisError &&
      e.message.includes(ok ? 'length' : 'canonical'));
  }
});

test('calls before init throw a plain error in a fresh module', async () => {
  const m = await import(`../lib/index.js?fresh=${Date.now()}`);
  assert.throws(() => m.algs(), /init/);
});

test('no secret is left in WebAssembly memory', () => {
  const find = (needle) => {
    const h = _heap();
    const n = needle.length;
    outer: for (let i = 0; i + n <= h.length; i++) {
      if (h[i] !== needle[0]) continue;
      for (let j = 1; j < n; j++) if (h[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  };
  const seed = random(32);
  const { publicKey: pk, secretKey: sk } = sign.keygen('ML-DSA-65', { seed });
  const sig = sign.sign('ML-DSA-65', sk, 'm');
  assert.equal(sign.verify('ML-DSA-65', pk, 'm', sig), true);
  assert.equal(find(seed), -1, 'seed');
  assert.equal(find(sk.subarray(32, 64)), -1, 'ML-DSA K');
  assert.equal(find(sk.subarray(sk.length - 32)), -1, 'ML-DSA t0 tail');
  const s2 = random(48);
  const sl = sign.keygen('SLH-DSA-SHAKE-128f', { seed: s2 });
  sign.sign('SLH-DSA-SHAKE-128f', sl.secretKey, 'm');
  assert.equal(find(s2.subarray(0, 16)), -1, 'SLH SK.seed');
  assert.equal(find(s2.subarray(16, 32)), -1, 'SLH SK.prf');
  for (const a of ['ML-KEM-768', 'HQC-128']) {
    const k = kem.keygen(a);
    const e = kem.encap(a, k.publicKey);
    const ss = kem.decap(a, k.secretKey, e.ciphertext);
    assert.equal(find(ss), -1, `${a} shared secret`);
    if (a.startsWith('ML-KEM')) {
      // z, the implicit-rejection secret, ends the ML-KEM secret key
      assert.equal(find(k.secretKey.subarray(k.secretKey.length - 32)), -1,
        `${a} z`);
    }
  }
});
