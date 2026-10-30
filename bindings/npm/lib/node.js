// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// Node helpers (`noqtis/node`): capsules on disk. The library checks and
// seals capsules in its in-memory file system; these read a folder with
// node:fs into it and write the seal back. A link or a special file in the
// folder is refused (NQEARG), as the C library refuses it; nothing is
// followed. The whole folder is held in memory, so this suits capsules
// that fit in memory; the CLI streams larger ones.

import { lstatSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { capsule, codes, NoqtisError } from './index.js';

/** Every regular file under dir as a Map of '/'-separated path -> bytes. */
export function readCapsule(dir) {
  const files = new Map();
  const todo = [''];
  while (todo.length > 0) {
    const rel = todo.pop();
    const abs = rel === '' ? dir : join(dir, ...rel.split('/'));
    for (const name of readdirSync(abs).sort()) {
      const r = rel === '' ? name : `${rel}/${name}`;
      const st = lstatSync(join(abs, name));
      if (st.isDirectory()) {
        todo.push(r);
      } else if (st.isFile()) {
        files.set(r, readFileSync(join(abs, name)));
      } else {
        throw new NoqtisError(codes.EARG, `${r} is not a regular file`);
      }
    }
  }
  return files;
}

/**
 * capsule.check on a folder: { ok, code, checks }. `opts.lineage` may name
 * folders as well as give capsules as files; dir may be null with
 * `opts.proof`.
 */
export function checkDir(dir, opts = {}) {
  const o = { ...opts };
  if (Array.isArray(o.lineage)) {
    o.lineage = o.lineage.map((x) => (typeof x === 'string'
      ? readCapsule(x) : x));
  }
  return capsule.check(dir === null ? null : readCapsule(dir), o);
}

/** capsule.seal on a folder: writes noqtis.json and noqtis.sig into it. */
export function sealDir(dir, alg, secretKey, publicKey, opts = {}) {
  const files = readCapsule(dir);
  const out = capsule.seal(files, alg, secretKey, publicKey, opts);
  writeFileSync(join(dir, 'noqtis.json'), out['noqtis.json']);
  writeFileSync(join(dir, 'noqtis.sig'), out['noqtis.sig']);
  return out;
}
