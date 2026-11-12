// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The browser entry (lib/index.js, with wasm.js and wasi.js) without Node:
// its modules run in a fresh context that has WebAssembly, WebCrypto and
// the text codecs and nothing else (no process, no require, no fetch, no
// timers), may import only each other, and are handed noqtis.wasm as
// bytes. Needs node --experimental-vm-modules (npm test passes it). Also
// a check of the source text of every file the package ships.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const lib = new URL('../lib/', import.meta.url);
const src = (f) => readFileSync(new URL(f, lib), 'utf8');

test('the browser entry works with no Node API', async () => {
  const ctx = vm.createContext({
    WebAssembly, TextEncoder, TextDecoder, URL, crypto: globalThis.crypto,
    performance: { now: () => performance.now() },
    // the test's own realm for what crosses into the context
    Uint8Array, Uint32Array, ArrayBuffer, DataView, Map,
  });
  const mods = new Map();
  const load = (f) => {
    if (!mods.has(f)) {
      mods.set(f, new vm.SourceTextModule(src(f), {
        context: ctx, identifier: f,
      }));
    }
    return mods.get(f);
  };
  const allowed = { './wasm.js': 'wasm.js', './wasi.js': 'wasi.js' };
  const top = load('index.js');
  await top.link((spec) => {
    assert.ok(spec in allowed, `the browser entry imports ${spec}`);
    return load(allowed[spec]);
  });
  await top.evaluate();
  const nq = top.namespace;
  for (const g of ['process', 'require', 'fetch', 'XMLHttpRequest',
    'setTimeout', 'Buffer']) {
    assert.equal(vm.runInContext(`typeof ${g}`, ctx), 'undefined', g);
  }
  await assert.rejects(nq.init(), /pass the WebAssembly module/);
  const wasm = new Uint8Array(readFileSync(new URL('../dist/noqtis.wasm',
    import.meta.url)));
  await nq.init({ wasm });
  const k = nq.sign.keygen('ML-DSA-65');
  const s = nq.sign.sign('ML-DSA-65', k.secretKey, 'web', { ctx: 'x' });
  assert.ok(nq.sign.verify('ML-DSA-65', k.publicKey, 'web', s, { ctx: 'x' }));
  const kk = nq.kem.keygen('ML-KEM-768');
  const e = nq.kem.encap('ML-KEM-768', kk.publicKey);
  assert.deepEqual([...nq.kem.decap('ML-KEM-768', kk.secretKey, e.ciphertext)],
    [...e.sharedSecret]);
  const f = new Map([['a.txt', 'a'], ['d/b', new Uint8Array(3)]]);
  for (const [n, v] of Object.entries(nq.capsule.seal(f, 'ML-DSA-65',
    k.secretKey, k.publicKey))) f.set(n, v);
  assert.equal(nq.capsule.check(f).ok, true);
  f.set('a.txt', 'b');
  assert.equal(nq.capsule.check(f).ok, false);
});

test('the shipped JavaScript has no network, eval or process code', () => {
  const risky = ['fetch(', 'XMLHttpRequest', 'WebSocket', 'eval(',
    'new Function', 'child_process', 'process.', 'importScripts'];
  for (const f of ['index.js', 'wasm.js', 'wasi.js', 'main.js', 'index.cjs',
    'node.js', 'node.cjs']) {
    const s = src(f);
    for (const t of risky) assert.ok(!s.includes(t), `${f}: ${t}`);
  }
  for (const f of ['index.js', 'wasm.js', 'wasi.js']) {
    const s = src(f);
    for (const t of ["'node:", 'require(', 'import(']) {
      assert.ok(!s.includes(t), `${f}: ${t}`);
    }
  }
  // the one file read of main.js is the package's own module or the
  // caller's path; no computed import anywhere
  assert.equal(src('main.js').match(/readFileSync\(/g).length, 2);
  for (const f of ['index.cjs', 'node.cjs']) {
    for (const m of src(f).matchAll(/import\(([^)]+)\)/g)) {
      assert.match(m[1], /^'\.\/[a-z]+\.js'$/, `${f}: import(${m[1]})`);
    }
  }
});
