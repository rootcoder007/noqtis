// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// The package's main entry on Node, Deno and Bun (the "node" condition of
// "." in package.json): index.js, with init() able to find noqtis.wasm by
// itself. Its one file read is the package's own dist/noqtis.wasm, or the
// path the caller gives as `wasm`; browsers get index.js, which reads
// nothing.

import { readFileSync } from 'node:fs';

import nq, { init as load } from './index.js';

export * from './index.js';

/**
 * Loads the WebAssembly module: `opts.wasm` as index.js takes it, or a
 * path or file: URL of noqtis.wasm, by default the package's own.
 */
export async function init(opts = {}) {
  let w = opts.wasm;
  if (w === undefined) {
    w = readFileSync(new URL('../dist/noqtis.wasm', import.meta.url));
  } else if (typeof w === 'string' || w instanceof URL) {
    w = readFileSync(w);
  }
  return load({ ...opts, wasm: w });
}

export default { ...nq, init };
