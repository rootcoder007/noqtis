// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// Instantiates noqtis.wasm (the C library built with wasi-sdk as a WASI
// reactor, no JavaScript runtime of its own) against the host in wasi.js,
// and gives the wrapper the few things it uses: the exported functions as
// M._name, the memory as M.HEAPU8 / M.HEAPU32, M.UTF8ToString and the
// in-memory file system as M.FS. Plain WebAssembly API calls only; the
// bytes come from the caller (or from the Node entry's own file read).

import { host } from './wasi.js';

// what the wrapper calls; a module without one of them is refused
const FNS = [
  'nqerr', 'nqver', 'nqselftest', 'nqwipe', 'nqrand', 'nqhlen', 'nqhash',
  'nqhmac', 'nqssize', 'nqsname', 'nqskg', 'nqskgd', 'nqsign', 'nqsignd',
  'nqvrfy', 'nqksize', 'nqkname', 'nqkkg', 'nqkkgd', 'nqenc', 'nqencd',
  'nqdec', 'nqseal', 'nqseal2', 'nqcapid', 'nqchkt', 'nqchkx', 'nqchkp',
  'nqprove', 'nqfiles', 'nqkstmt', 'nqdsse', 'nqdssevrfy', 'nqcard',
  'nqcardvrfy', 'nqrepn', 'nqrepi', 'nqrepfree', 'malloc', 'free',
  'setenv', 'unsetenv',
];

const dec = new TextDecoder();

/**
 * src: the module's bytes (ArrayBuffer or a view), a compiled
 * WebAssembly.Module, or a Response the caller fetched. rnd: an object
 * with getRandomValues (WebCrypto).
 */
export async function instance(src, rnd) {
  if (!rnd || typeof rnd.getRandomValues !== 'function') {
    throw new Error('noqtis: crypto.getRandomValues is not available');
  }
  const h = host((v) => rnd.getRandomValues(v));
  const imports = { wasi_snapshot_preview1: h.imports };
  let inst;
  if (src instanceof WebAssembly.Module) {
    inst = await WebAssembly.instantiate(src, imports);
  } else if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
    inst = (await WebAssembly.instantiate(src, imports)).instance;
  } else if (typeof Response === 'function' && src instanceof Response) {
    inst = (await WebAssembly.instantiateStreaming(src, imports)).instance;
  } else {
    throw new TypeError('noqtis: wasm must be the bytes of noqtis.wasm, a '
      + 'WebAssembly.Module or a Response');
  }
  const x = inst.exports;
  for (const n of [...FNS, '_initialize']) {
    if (typeof x[n] !== 'function') {
      throw new Error(`noqtis: noqtis.wasm does not export ${n}`);
    }
  }
  h.bind(x.memory);
  x._initialize();

  let u8 = new Uint8Array(x.memory.buffer);
  let u32 = new Uint32Array(x.memory.buffer);
  // the views are made again after the memory has grown
  const M = {
    FS: h.fs,
    get HEAPU8() {
      if (u8.buffer !== x.memory.buffer) u8 = new Uint8Array(x.memory.buffer);
      return u8;
    },
    get HEAPU32() {
      if (u32.buffer !== x.memory.buffer) {
        u32 = new Uint32Array(x.memory.buffer);
      }
      return u32;
    },
    UTF8ToString(p) {
      const m = M.HEAPU8;
      let e = p;
      while (m[e] !== 0) e++;
      return dec.decode(m.subarray(p, e));
    },
  };
  for (const n of FNS) M[`_${n}`] = x[n];
  return M;
}
