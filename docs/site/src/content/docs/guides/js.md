---
title: Use from JavaScript
description: The noqtis npm package (WebAssembly) in Node, Deno, Bun and browsers - seal and check a folder, sign, verify and encapsulate.
---

The `noqtis` npm package is the C library compiled to WebAssembly: one
package for Node, browsers, Deno and Bun, with nothing to compile and no
dependencies. It needs Node 22 or later.

:::note[Before the first release]
`npm install noqtis` works once the first release is published. Until then, build
the package from the repository: with emscripten's `emcc` on `PATH`
(the version `bindings/npm/build.sh` names), run `sh build.sh` in
`bindings/npm`, then `npm install /path/to/noqtis/bindings/npm` in your
project.
:::

```sh
npm install noqtis
```

Every call after `await init()` is synchronous. Bytes go in and come out
as `Uint8Array`; messages, contexts and hash input may also be strings
(UTF-8).

## Node: seal and check a folder

`noqtis/node` reads a folder from disk and writes the seal into it.
Save this as `prov.mjs` and run `node prov.mjs`:

```js
import { mkdirSync, mkdtempSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { init, sign, kem, hash } from 'noqtis';
import { sealDir, checkDir } from 'noqtis/node';

await init(); // once: loads noqtis.wasm

// a folder with some results
const dir = join(mkdtempSync(join(tmpdir(), 'nq-')), 'results');
mkdirSync(join(dir, 'data'), { recursive: true });
writeFileSync(join(dir, 'data', 'in.csv'), 'a,b\n1,2\n');
writeFileSync(join(dir, 'report.txt'), 'r\n');

// seal it, then check it with the public key pinned
const { publicKey, secretKey } = sign.keygen('ML-DSA-65');
sealDir(dir, 'ML-DSA-65', secretKey, publicKey, { meta: { project: 'tutorial' } });
console.log('check:', checkDir(dir, { trust: publicKey }).ok);

// change a file: the check fails and says why
appendFileSync(join(dir, 'report.txt'), 'edited\n');
const r = checkDir(dir, { trust: publicKey });
console.log('after edit:', r.ok);
for (const c of r.checks.filter((c) => !c.ok)) console.log('FAIL', c.check, c.detail);

// a detached signature with a context string
const msg = 'the results in table 2';
const sig = sign.sign('ML-DSA-65', secretKey, msg, { ctx: 'app-v1' });
console.log('verify:', sign.verify('ML-DSA-65', publicKey, msg, sig, { ctx: 'app-v1' }));
console.log('other context:', sign.verify('ML-DSA-65', publicKey, msg, sig));
secretKey.fill(0); // wipe the secret key when done

// key encapsulation and hashes
const kp = kem.keygen('ML-KEM-768');
const { ciphertext, sharedSecret } = kem.encap('ML-KEM-768', kp.publicKey);
const back = kem.decap('ML-KEM-768', kp.secretKey, ciphertext);
console.log('decap matches:', back.every((b, i) => b === sharedSecret[i]));
console.log('sha3-256:', Buffer.from(hash('sha3-256', 'abc')).toString('hex'));
```

The first check passes. After the edit it fails, and the failing row
names the file and why (`report.txt: size differs`); the signature
verifies only under its own context.

The folder now holds `noqtis.json` and `noqtis.sig`, the same capsule
the `noqtis` command and the C library check. `checkDir` holds the files
in memory; for very large capsules use the command-line tool, which
streams. CommonJS works too: `const nq = require('noqtis')`, and the
`require('noqtis/node')` functions return promises.

## Browser: seal files the user picks

In a browser a capsule is a `Map` of `/`-separated relative paths to
file contents, so sealing and checking happen on the page and nothing
is uploaded:

```js
import { init, sign, capsule } from 'noqtis';

/** Seal the files of an <input type="file" webkitdirectory> and check them. */
export async function sealPicked(/** @type {FileList} */ list) {
  await init();
  const files = new Map();
  for (const f of Array.from(list)) {
    // webkitRelativePath is "picked-folder/sub/file"; drop the first part
    const path = f.webkitRelativePath.split('/').slice(1).join('/');
    files.set(path, new Uint8Array(await f.arrayBuffer()));
  }
  const { publicKey, secretKey } = sign.keygen('ML-DSA-65');
  const seal = capsule.seal(files, 'ML-DSA-65', secretKey, publicKey,
    { meta: { project: 'tutorial' } });
  secretKey.fill(0);
  for (const [name, bytes] of Object.entries(seal)) files.set(name, bytes);
  const report = capsule.check(files, { trust: publicKey });
  return { seal, ok: report.ok, checks: report.checks };
}
```

```html
<input type="file" webkitdirectory id="pick">
<script type="module">
  import { sealPicked } from './seal.js';
  document.getElementById('pick').addEventListener('change', async (e) => {
    const r = await sealPicked(e.target.files);
    console.log(r.ok, r.checks.length);
  });
</script>
```

To check a capsule someone gave you, put their `noqtis.json` and
`noqtis.sig` in the map with the other files and call
`capsule.check(files, { trust: theirPublicKey })`. Without `trust` the
check accepts the key the seal carries, and its report says so.

The package loads `noqtis.wasm` with
`new URL('noqtis.wasm', import.meta.url)`, which Vite, webpack 5,
esbuild and Rollup handle. Where that is not available, fetch the bytes
yourself and pass them: `await init({ wasm: bytes })`.

## Deno and Bun

```js
import { init, sign } from 'npm:noqtis';   // Deno
```

Bun imports `noqtis` as Node does.

## Notes

- Randomness comes only from `crypto.getRandomValues`; if it is missing
  the call throws, with no fallback.
- Buffers the package places in WebAssembly memory are wiped before they
  are freed, but the `Uint8Array` results are ordinary JavaScript
  memory: wipe secret keys yourself (`secretKey.fill(0)`). Strings cannot
  be wiped, so pass secrets as bytes.
- A signature that does not verify returns `false`; bad arguments throw
  `NoqtisError` with the library's code in `.code`.

The full API is in the package's
[README](https://github.com/rootcoder007/noqtis/tree/main/bindings/npm#readme),
with TypeScript types in the package.
