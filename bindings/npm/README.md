# noqtis

Post-quantum signatures (ML-DSA, SLH-DSA), key encapsulation (ML-KEM,
HQC), SHA-2/SHA-3 hashes and sealed file capsules for JavaScript: the
[noqtis](https://github.com/rootcoder007/noqtis) C11 library compiled to
WebAssembly. One package for Node (22 and later), browsers, Deno and Bun;
nothing to compile, no dependencies, no network access.

The code has not yet been audited. See the main repository's README and
SECURITY.md before relying on it.

```sh
npm install noqtis
```

## Use

```js
import { init, sign, kem, hash } from 'noqtis';

await init(); // once: loads noqtis.wasm

const { publicKey, secretKey } = sign.keygen('ML-DSA-65');
const sig = sign.sign('ML-DSA-65', secretKey, 'a message', { ctx: 'app-v1' });
sign.verify('ML-DSA-65', publicKey, 'a message', sig, { ctx: 'app-v1' }); // true

const kp = kem.keygen('ML-KEM-768');
const { ciphertext, sharedSecret } = kem.encap('ML-KEM-768', kp.publicKey);
kem.decap('ML-KEM-768', kp.secretKey, ciphertext); // equals sharedSecret

hash('sha3-256', 'abc'); // Uint8Array(32)
```

CommonJS works the same way: `const nq = require('noqtis'); await nq.init();`.

Bytes go in and come out as `Uint8Array` (a `Buffer` is one). Messages,
contexts and hash input may also be strings, taken as UTF-8. Every call
after `init()` is synchronous.

## API

| Call | Returns |
|---|---|
| `init({ wasm })` | a promise; `wasm` (optional) is noqtis.wasm as bytes, a `WebAssembly.Module` or a URL, for runtimes that cannot find it next to `dist/noqtis.js` |
| `algs()` | every algorithm with its sizes in bytes: `{ name, kind: 'sign', publicKey, secretKey, signature }`, `{ name, kind: 'kem', publicKey, secretKey, ciphertext, sharedSecret }`, `{ name, kind: 'hash', digest }` |
| `sign.keygen(alg, { seed })` | `{ publicKey, secretKey }`; `seed` is the standard's seed (xi, 32 bytes, for ML-DSA; SK.seed, SK.prf, PK.seed for SLH-DSA) |
| `sign.sign(alg, sk, msg, { ctx, deterministic, rnd, prehash })` | the signature (FIPS 204/205 encoding); `ctx` at most 255 bytes; `deterministic` uses all-zero per-signature randomness; `prehash` names a hash for HashML-DSA / HashSLH-DSA |
| `sign.verify(alg, pk, msg, sig, { ctx, prehash })` | `true` or `false` (`false` also for a malformed signature) |
| `kem.keygen(alg, { seed })` | `{ publicKey, secretKey }` |
| `kem.encap(alg, pk)` | `{ ciphertext, sharedSecret }` |
| `kem.decap(alg, sk, ct)` | the shared secret; a tampered ciphertext gives an unrelated secret, not an error (implicit rejection, as FIPS 203 and HQC require) |
| `hash(alg, data, { length })` | the digest; `length` for SHAKE only |
| `hmac(alg, key, data)` | HMAC with a SHA-2 or SHA-3 hash |
| `random(n)` | `n` bytes from `crypto.getRandomValues` |
| `capsule.seal(files, alg, sk, pk, { meta, time })` | `{ 'noqtis.json', 'noqtis.sig' }` |
| `capsule.check(files, { trust, anchors })` | `{ ok, code, checks: [{ check, ok, detail }] }` |
| `keyfile.encode(alg, 'pub' \| 'sec', key)`, `keyfile.decode(text)` | the CLI's key file text, and back (`{ alg, kind, key }`) |
| `NoqtisError`, `codes`, `errmsg(code)` | errors carry the library's `NQE*` code in `.code` and its message |
| `version()` | the library version |

Algorithm names are the standards' (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`,
`SLH-DSA-SHA2-128s` ... `SLH-DSA-SHAKE-256f`, `ML-KEM-512`, `ML-KEM-768`,
`ML-KEM-1024`, `HQC-128`, `HQC-192`, `HQC-256`); case does not matter.
Hashes: `sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224
sha3-256 sha3-384 sha3-512 shake128 shake256`.

A failure throws `NoqtisError`: an unknown algorithm is `ENOSUP`, a bad
argument (a context over 255 bytes, a seed of the wrong length) `EARG`, a
key of the wrong length `EDEC`, a failed random source `ERNG`. A signature
that does not verify is `false`, not an error.

## Capsules

A capsule is a folder with `noqtis.json` (a manifest of every file's
SHA-256 and SHA3-256) and `noqtis.sig` (its signature); the format is in
the main repository's DESIGN.md. In JavaScript a capsule is a map of
`'/'`-separated relative paths to file contents, so sealing and checking
work in browsers too:

```js
const files = new Map([['data/a.csv', bytesA], ['README', 'text']]);
const seal = capsule.seal(files, 'ML-DSA-65', secretKey, publicKey,
  { meta: { project: 'x' } });
// store seal['noqtis.json'] and seal['noqtis.sig'] beside the files
for (const [name, b] of Object.entries(seal)) files.set(name, b);
capsule.check(files, { trust: publicKey }).ok; // true
```

Without `trust`, `check` accepts the key the seal carries and its report
says so. `anchors` takes the DER certificates of RFC 3161 timestamp
authorities, for seals that carry a timestamp token; the library itself
makes no network requests, so it cannot obtain one: seal with the CLI's
`noqtis seal --tsa <url>` to add one.

On Node, `noqtis/node` reads a folder from disk and writes the seal back:

```js
import { checkDir, sealDir } from 'noqtis/node';
sealDir('out', 'ML-DSA-65', secretKey, publicKey);
checkDir('out', { trust: publicKey });
```

A link or a special file in the folder is refused, as the C library
refuses it. The files are held in memory while they are checked; for
very large capsules use the `noqtis` command-line tool, which streams.
The CommonJS `require('noqtis/node')` functions return promises.

## Security notes

- Randomness comes only from `crypto.getRandomValues`; if it is missing
  or fails, the call throws `ERNG`. There is no fallback.
- Every buffer the wrapper places in WebAssembly memory (keys, seeds,
  messages, shared secrets) is wiped before it is freed. The `Uint8Array`
  results you receive are ordinary JavaScript memory: wipe them yourself
  (`sk.fill(0)`) when done. JavaScript strings cannot be wiped, so pass
  secrets as `Uint8Array`.
- The C code is constant time on secret data; the WebAssembly engine's
  compiler is not under our control, and the JavaScript base64 coder in
  `keyfile` avoids table lookups but cannot promise constant time.

## Bundlers and other runtimes

The package is ESM with a CommonJS entry, `sideEffects: false`, and loads
`dist/noqtis.wasm` with `new URL('noqtis.wasm', import.meta.url)`, which
Vite, webpack 5, esbuild and Rollup handle. Where that is not available
(some edge runtimes), fetch or import the bytes yourself and pass them:
`await init({ wasm: bytes })`. The file is exported as `noqtis/noqtis.wasm`.

Deno: `import { init } from 'npm:noqtis';`. Bun: as Node.

## Building from source

```sh
# emsdk 6.0.12 active (emcc on PATH)
sh build.sh     # dist/noqtis.js and dist/noqtis.wasm from ../../src
npm test        # NOQTIS_CLI=/path/to/noqtis also runs the CLI cross-checks
```

## License

Apache-2.0 WITH LLVM-exception. See LICENSE and NOTICE.
