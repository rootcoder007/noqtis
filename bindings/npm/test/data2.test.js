// SPDX-License-Identifier: LGPL-3.0-or-later
// The rest of the capsule and data functions: inspect, sealWhy, the
// timestamp requests, bundles, chains, the environment, commitments,
// citation, report, synthetic data, calibration and chunk digests, on the
// repository's vectors (tests/vectors/nqd).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { init, sign, capsule, data, codes, NoqtisError } from '../lib/main.js';
import { packages } from '../lib/node.js';

await init();

const here = fileURLToPath(new URL('.', import.meta.url));
const V = join(here, '..', '..', '..', 'tests', 'vectors', 'nqd');
const rd = (p) => readFileSync(join(V, p));
const cap = () => new Map([
  ['data/a.csv', rd('cap/data/a.csv')],
  ['data/b.csv', rd('cap/data/b.csv')],
]);
const code = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof NoqtisError, String(e));
    return e.code;
  }
  assert.fail('no error');
};
const sealed = (files, k) => {
  const s = capsule.seal(files, 'ML-DSA-44', k.secretKey, k.publicKey);
  for (const [n, b] of Object.entries(s)) files.set(n, b);
  return files;
};

test('inspect, sealWhy, timestamp requests', () => {
  const k = sign.keygen('ML-DSA-44');
  const f = sealed(new Map([['a', 'x']]), k);
  const i = capsule.inspect(f);
  assert.equal(i.ok, true);
  assert.equal(i.checks.find((r) => r.check === 'info.alg').detail,
    'ML-DSA-44');
  assert.equal(capsule.sealWhy(new Map([['a', 'x']])), null);
  const bad = new Map([['A', 'x'], ['a', 'y']]);
  assert.equal(code(() => capsule.seal(bad, 'ML-DSA-44', k.secretKey,
    k.publicKey)), codes.EARG);
  assert.equal(capsule.sealWhy(bad).why, 'case');
  const q = capsule.tsreq(f, { nonce: new Uint8Array([1, 2]) });
  assert.equal(q[0], 0x30);
  assert.notDeepEqual(capsule.tsreq(f), q);
  assert.equal(capsule.ersreq(f)[0], 0x30);
  assert.throws(() => capsule.tsput(f, new Uint8Array([0x30, 0])), NoqtisError);
  assert.throws(() => capsule.ersput(f, new Uint8Array([0x30, 0])),
    NoqtisError);
});

test('bundles and chains', () => {
  const k = sign.keygen('ML-DSA-44');
  const f = cap();
  f.set('noqtis.data.json', data.add(null, cap(), ['data/a.csv', 'data/b.csv']));
  sealed(f, k);
  const b = capsule.pack(f);
  assert.deepEqual(capsule.pack(f), b);
  const u = capsule.unpack(b);
  assert.deepEqual([...u.keys()], [...f.keys()].sort());
  assert.equal(capsule.check(u, { trust: k.publicKey }).ok, true);
  assert.equal(code(() => capsule.unpack(b.subarray(0, b.length - 10))),
    codes.EDEC);
  const links = [];
  for (let i = 0; i < 3; i++) {
    const g = new Map([['log.txt', `entry ${i}\n`]]);
    const inputs = i ? [{ name: 'prev', id: capsule.id(links[i - 1]) }] : [];
    const s = capsule.seal(g, 'ML-DSA-44', k.secretKey, k.publicKey,
      { format: 2, inputs });
    for (const [n, x] of Object.entries(s)) g.set(n, x);
    links.push(g);
  }
  const c = capsule.chain(links, { trust: k.publicKey });
  assert.equal(c.ok, true);
  assert.deepEqual(c.head, capsule.id(links[2]));
  const gap = capsule.chain([links[0], links[2]], { trust: k.publicKey });
  assert.equal(gap.ok, false);
  assert.equal(gap.head, null);
});

test('env, commit, reveal, cite, report', () => {
  let r = data.add(null, cap(), ['data/a.csv', 'data/b.csv']);
  r = data.env(r, { rng: 'xorshift', seed: 42, locks: { 'package-lock.json': '{}\n' },
    packages: [{ name: 'z', version: '1', source: 'npm' },
      { name: 'a', version: '2', source: 'npm' }] });
  const e = JSON.parse(r).env;
  assert.equal(e.runtime.language, 'javascript');
  assert.match(e.runtime.version, /^node /);
  assert.deepEqual(e.runtime.packages.map((p) => p.name), ['a', 'z']);
  assert.equal(e.locks[0].path, 'package-lock.json');
  assert.deepEqual(e.rng, { kind: 'xorshift', seed: 42 });
  assert.ok(Array.isArray(packages(join(here, '..'))));
  assert.equal(code(() => data.env(r, { seed: 1 })), codes.EARG);
  const plan = 'arm A: 1, 4\n';
  const c = data.commit(r, plan, { kind: 'randomisation', label: 'trial' });
  assert.equal(data.reveal(c.record, plan, c.salt), 0);
  assert.equal(data.reveal(c.record, 'x', c.salt), null);
  assert.ok(c.record.includes(data.commitment(c.salt, plan)));
  assert.equal(code(() => data.commitment(new Uint8Array(5), plan)),
    codes.EARG);
  assert.equal(code(() => data.cite(c.record)), codes.EIO);
  r = data.put(c.record, 'cite', { title: 'T', authors: ['A. Author'],
    year: 2026, doi: '10.1234/x' });
  assert.match(data.cite(r), /title: "T"/);
  assert.match(data.cite(r, 'bib'), /doi = \{10\.1234\/x\}/);
  const f = cap();
  f.set('noqtis.data.json', r);
  const k = sign.keygen('ML-DSA-44');
  sealed(f, k);
  const md = data.report(f, { trust: k.publicKey });
  assert.ok(md.startsWith('#') && md.includes('data/a.csv'));
  assert.ok(data.report(f, { format: 'txt' }).includes('data/a.csv'));
  assert.equal(data.key(r, 'sources', 'data/a.csv') !== null, true);
  assert.equal(data.key(r, 'sources', 'none'), null);
  assert.ok(!data.del(r, 'cite').includes('"cite"'));
});

test('synth, calibrate, chunks, schema checks', () => {
  const s = rd('syn/schema.json').toString();
  const rec = data.put('{"format":"noqtis-data-1"}', 'schemas', s);
  const y = data.synth(rec, new Map(), 'data/s.csv', 7, 16);
  assert.deepEqual(Buffer.from(y.data), rd('syn/s7.csv'));
  assert.equal(JSON.parse(y.record).sources[0].synthetic, true);
  const f = cap();
  const sc = data.schema(f, 'data/a.csv');
  assert.equal(data.schemaCheck(f, sc).ok, true);
  assert.equal(data.schemaCheck(f, sc.replace('"int"', '"bool"')).ok, false);
  const r2 = data.put(data.add(null, f, 'data/a.csv'), 'schemas', sc);
  assert.equal(code(() => data.synth(r2, f, 'data/a.csv', 1)), codes.EARG);
  const st = data.pin(f, 'data/a.csv');
  const cal = data.calibrate(st, [rd('cap/data/a.csv')]);
  assert.ok(JSON.parse(cal).columns.every((c) => 'cal' in c));
  const big = new Uint8Array(5000).map((_, i) => i % 253);
  const ch = data.chunks(big, 'big.bin', 1024);
  assert.equal(JSON.parse(ch).size, 5000);
  assert.equal(data.piece(ch, big.subarray(2048), 2048).ok, true);
  const bad = big.slice(2048);
  bad[1100] ^= 1;
  const p = data.piece(ch, bad, 2048);
  assert.equal(p.ok, false);
  assert.equal(p.rows[0].check, 'chunk');
  assert.equal(code(() => data.chunks(big, 'big.bin', 10)), codes.EARG);
});
