// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The data layer: records, schemas, drift, diff and sources, on the
// repository's vectors (tests/vectors/nqd), against the values the C
// tests check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { init, data, NoqtisError } from '../lib/main.js';

await init();

const here = fileURLToPath(new URL('.', import.meta.url));
const V = join(here, '..', '..', '..', 'tests', 'vectors', 'nqd');
const rd = (p) => readFileSync(join(V, p));
const cap = () => new Map([
  ['data/a.csv', rd('cap/data/a.csv')],
  ['data/b.csv', rd('cap/data/b.csv')],
]);

test('a record: canonical, sources added, checked', () => {
  const full = rd('full.json').toString();
  const c = data.canon(full);
  assert.equal(data.canon(c), c);
  assert.throws(() => data.canon('{"format":"x"}'), NoqtisError);
  const r = data.add(null, cap(), 'data/a.csv',
    { url: 'https://example.org/a.csv' });
  assert.match(r, /"path":"data\/a.csv","sha256":"7a1668480cde19db0b76c7a36e6fee9a82afd9937f5d03cec3dae1705ce173e2","size":89/);
  const f = cap();
  f.set('noqtis.data.json', r);
  assert.equal(data.check(f).ok, true);
  f.set('data/a.csv', 'changed\n');
  assert.equal(data.check(f).ok, false);
  const r2 = data.put(r, 'checks', { name: 'x', status: 'fail' });
  assert.match(r2, /"checks":\[\{"name":"x","status":"fail"\}\]/);
});

test('schemas, drift and diff', () => {
  const s = data.schema(cap(), 'data/a.csv');
  assert.match(s, /"kind":"csv"/);
  assert.equal(data.schemaCheck(cap(), s).ok, true);
  const st = data.pin(cap(), 'data/a.csv');
  const d = data.drift(st, rd('cap/data/a.csv'));
  assert.equal(d.ok, true);
  assert.ok(d.rows.some((x) => x.check === 'drift' && x.stats !== null));
  const a = cap();
  a.set('noqtis.data.json', data.add(null, cap(), 'data/a.csv'));
  const b = cap();
  b.set('data/a.csv', 'x\n1\n');
  b.set('noqtis.data.json', data.add(null, b, 'data/a.csv'));
  const df = data.diff(a, b);
  assert.equal(df.ok, false);
  assert.ok(df.rows.length > 0);
});

test('sources: addresses in order, bytes checked, resolvers', () => {
  let r = data.add(null, cap(), 'data/a.csv',
    { url: 'https://example.org/a.csv' });
  const e = JSON.parse(r).sources[0];
  r = data.put(r, 'sources', { ...e, mirrors: ['https://m.example.net/a.csv'],
    resolver: { base: 'https://data.example.org', id: 'abcd-1234',
      kind: 'socrata' } });
  assert.deepEqual(data.addrs(r, 'data/a.csv'), [
    { kind: 'url', url: 'https://example.org/a.csv' },
    { kind: 'portal', url: 'https://data.example.org/api/views/abcd-1234.json' },
    { kind: 'mirror', url: 'https://m.example.net/a.csv' },
  ]);
  assert.equal(data.verify(r, 'data/a.csv', rd('cap/data/a.csv')), true);
  assert.equal(data.verify(r, 'data/a.csv', 'other'), false);
  assert.equal(data.field(r, 'sources', 0, 'url'), 'https://example.org/a.csv');
  assert.equal(data.field(r, 'sources', 0, 'title'), null);
  assert.throws(() => data.addrs(r, 'none.csv'), NoqtisError);
  const wb = { base: 'https://example.org/a.csv', kind: 'wayback' };
  assert.deepEqual(data.reply(wb, rd('src/wb.json')), {
    url: 'https://web.archive.org/web/20240102030405id_/https://example.org/a.csv',
    time: '2024-01-02T03:04:05Z' });
  assert.throws(() => data.reply(wb, rd('src/wb-none.json')), /no copy/);
  assert.throws(() => data.request({ base: 'https://x.org/a', kind: 'direct' }),
    NoqtisError);
  assert.equal(data.wayback('http://web.archive.org/web/2024/https://x.org/a'),
    'https://web.archive.org/web/2024id_/https://x.org/a');
});
