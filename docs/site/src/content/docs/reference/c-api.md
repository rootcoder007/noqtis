---
title: C API
description: Every public function, type and constant of noqtis.h, with arguments, return codes and errors.
---

Everything is declared in one header, `noqtis.h`, which compiles as C11,
C++11 and later, and under MSVC. Link with
`$(pkg-config --cflags --libs noqtis)` or CMake's `noqtis::noqtis`. The
[manual pages](/noqtis/reference/man/noqtis-3/) give the same reference
offline (`man nqsign`).

## Conventions

- Every function that can fail returns `int`: `NQOK` (0) or a negative
  error code. **A failed verification is `NQEVRFY`, never `NQOK`.** Test
  `rc == NQOK`.
- The caller allocates every output buffer and passes its length. Larger
  buffers are fine; a function never writes past the length, and returns
  `NQEBUF` when it is too small. (Fixed-length hashes want the exact
  length; see `nqhash`.)
- Keys, signatures and ciphertexts are byte strings in the standards'
  encodings; their sizes are fixed per algorithm and available at run time.
- Secrets are wiped before a function returns, on every path. Operations
  on secret data run in constant time.
- The algorithm code never allocates. The capsule layer allocates through
  `nqsetal`'s hook.
- Paths are UTF-8 on every operating system.
- No public struct changes layout: `nqssz`, `nqksz` and `nqhctx` have fixed
  members, `nqrep` is opaque.

## Errors and version

| Code | Value | `nqerr()` text |
|---|---|---|
| `NQOK` | 0 | success |
| `NQEARG` | −1 | invalid argument |
| `NQEBUF` | −2 | output buffer too small |
| `NQEVRFY` | −3 | verification failed |
| `NQEDEC` | −4 | input is not in the encoding the standard defines |
| `NQERNG` | −5 | the operating system's random source failed |
| `NQEMEM` | −6 | out of memory |
| `NQEIO` | −7 | file could not be read or written |
| `NQENOSUP` | −8 | algorithm or option not supported |
| `NQELIM` | −9 | input exceeds a size or depth limit |
| `NQESTATE` | −10 | context used out of order |

```c
const char *nqerr(int err);   /* the text above; "unknown error" otherwise */
const char *nqver(void);      /* "major.minor.patch" of the linked library */
#define NQVMAJ, NQVMIN, NQVPAT   /* the header's version */
```

[nqerr(3)](/noqtis/reference/man/nqerr-3/)

## Core

```c
void nqwipe(void *p, size_t len);
```
Zeroes `len` bytes at `p` through a volatile pointer, so the stores cannot
be optimised away. `p` may be `NULL`.
[nqwipe(3)](/noqtis/reference/man/nqwipe-3/)

```c
int nqcteq(const void *a, const void *b, size_t len);
```
1 when the buffers are equal, 0 otherwise, in time that depends only on
`len`. [nqcteq(3)](/noqtis/reference/man/nqcteq-3/)

```c
int nqrand(uint8_t *buf, size_t len);
```
Fills `buf` from the operating system's CSPRNG (getrandom,
arc4random_buf, BCryptGenRandom, getentropy under WebAssembly); no
fallback. `NQEARG` for `NULL` with `len > 0`, `NQERNG` when the source
fails. [nqrand(3)](/noqtis/reference/man/nqrand-3/)

```c
typedef void *(*nqmalfn)(size_t size, void *user);
typedef void (*nqfreefn)(void *ptr, size_t size, void *user);
int nqsetal(nqmalfn mal, nqfreefn fre, void *user);
```
Replaces the allocator of the capsule and parser layers; both `NULL`
restore `malloc`/`free`; exactly one `NULL` is `NQEARG`. Memory is wiped
before `fre` sees it. Not thread safe: call it first.
[nqsetal(3)](/noqtis/reference/man/nqsetal-3/)

## Hashes

```c
typedef enum {
  NQS224 = 1, NQS256, NQS384, NQS512, NQS512T224, NQS512T256,
  NQS3224, NQS3256, NQS3384, NQS3512, NQSHK128, NQSHK256
} nqhalg;
typedef struct { uint64_t opq[52]; } nqhctx;   /* opaque, stack-allocatable */

size_t nqhlen(nqhalg alg);
int nqhash(nqhalg alg, const uint8_t *in, size_t inlen,
           uint8_t *out, size_t outlen);
int nqhini(nqhctx *ctx, nqhalg alg);
int nqhupd(nqhctx *ctx, const uint8_t *in, size_t inlen);
int nqhfin(nqhctx *ctx, uint8_t *out, size_t outlen);
int nqhmac(nqhalg alg, const uint8_t *key, size_t keylen,
           const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
```

| Function | Does | Errors |
|---|---|---|
| `nqhlen` | digest size (SHAKE: 32 / 64, the pre-hash length); 0 if unknown | — |
| `nqhash` | one-shot digest; fixed-length hashes need `outlen == nqhlen(alg)`, SHAKE takes any length | `NQEARG` unknown alg, `NULL` with length, `outlen` too large; `NQEBUF` too small |
| `nqhini` | starts a context | `NQEARG` |
| `nqhupd` | absorbs more input | `NQESTATE` not started or finished; `NQEARG` |
| `nqhfin` | writes the digest; fixed-length hashes end the context, SHAKE may squeeze again | as `nqhash`; `NQESTATE` |
| `nqhmac` | HMAC, first `outlen` bytes (1 to `nqhlen`) of the tag | `NQENOSUP` for SHAKE; `NQEARG` |

[nqhash(3)](/noqtis/reference/man/nqhash-3/)

## Signatures

```c
typedef enum {
  NQMLDSA44 = 1, NQMLDSA65, NQMLDSA87,
  NQSLH128S, NQSLH128F, NQSLH192S, NQSLH192F, NQSLH256S, NQSLH256F,
  NQSLHK128S, NQSLHK128F, NQSLHK192S, NQSLHK192F, NQSLHK256S, NQSLHK256F
} nqsalg;                      /* NQSLH*: SHA2, NQSLHK*: SHAKE */
typedef struct { size_t pk, sk, sig; } nqssz;

int nqssize(nqsalg alg, nqssz *sz);
const char *nqsname(nqsalg alg);
int nqsfind(const char *name, nqsalg *alg);
int nqskg(nqsalg alg, uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqskgd(nqsalg alg, const uint8_t *seed, size_t seedlen,
           uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqsign(nqsalg alg, const uint8_t *sk, size_t sklen,
           const uint8_t *msg, size_t msglen,
           const uint8_t *ctx, size_t ctxlen, int ph,
           uint8_t *sig, size_t siglen, size_t *outlen);
int nqsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *msg, size_t msglen,
            const uint8_t *ctx, size_t ctxlen, int ph,
            const uint8_t *rnd, size_t rndlen,
            uint8_t *sig, size_t siglen, size_t *outlen);
int nqvrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
           const uint8_t *msg, size_t msglen,
           const uint8_t *ctx, size_t ctxlen, int ph,
           const uint8_t *sig, size_t siglen);
```

| Function | Does |
|---|---|
| `nqssize` | sizes of `alg`; `NQEARG` if unknown |
| `nqsname` | `"ML-DSA-65"`, `"SLH-DSA-SHA2-128s"`, ...; `NULL` if unknown |
| `nqsfind` | the `nqsalg` of an exact name; `NQENOSUP` if none, `NQEARG` for `NULL` |
| `nqskg` | key pair from `nqrand` |
| `nqskgd` | key pair from the standard's seed: xi (32 bytes) for ML-DSA, SK.seed ‖ SK.prf ‖ PK.seed (3n bytes) for SLH-DSA |
| `nqsign` | hedged signature; `*outlen` gets its length |
| `nqsignd` | signature with the caller's `rnd` (32 bytes ML-DSA, n bytes SLH-DSA); all zero is the deterministic variant |
| `nqvrfy` | `NQOK` only for a valid signature, else `NQEVRFY` (or another error) |

`ctx` is the FIPS 204/205 context (at most 255 bytes, `NULL`/0 for none).
`ph` is 0 for the pure variant, or any `nqhalg` for HashML-DSA /
HashSLH-DSA (the function hashes `msg`).

Errors: `NQEARG` (unknown alg, `NULL` pointer with a length, context over
255, bad `ph`, seed or `rnd` of the wrong length), `NQEBUF` (output too
small), `NQEDEC` (an input key or signature of the wrong length or
encoding), `NQEVRFY`, `NQERNG`.
[nqsign(3)](/noqtis/reference/man/nqsign-3/)

## Key encapsulation

```c
typedef enum {
  NQMLKEM512 = 1, NQMLKEM768, NQMLKEM1024, NQHQC128, NQHQC192, NQHQC256
} nqkalg;
typedef struct { size_t pk, sk, ct, ss; } nqksz;

int nqksize(nqkalg alg, nqksz *sz);
const char *nqkname(nqkalg alg);
int nqkfind(const char *name, nqkalg *alg);
int nqkkg(nqkalg alg, uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqkkgd(nqkalg alg, const uint8_t *seed, size_t seedlen,
           uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqenc(nqkalg alg, const uint8_t *pk, size_t pklen,
          uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
int nqencd(nqkalg alg, const uint8_t *pk, size_t pklen,
           const uint8_t *seed, size_t seedlen,
           uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
int nqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
          const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
```

| Function | Does |
|---|---|
| `nqksize`, `nqkname`, `nqkfind` | as for signatures |
| `nqkkg` | key pair from `nqrand` |
| `nqkkgd` | key pair from the seed: d ‖ z (64 bytes) for ML-KEM, 32 bytes for HQC |
| `nqenc` | ciphertext and 32-byte shared secret, fresh randomness |
| `nqencd` | the same from the caller's seed: m (32 bytes) for ML-KEM, m ‖ salt (32, 40, 48) for HQC |
| `nqdec` | the shared secret; a bad ciphertext of the right length gives a pseudorandom secret and `NQOK` (implicit rejection) |

Errors: `NQEARG`, `NQEBUF`, `NQEDEC` (input of the wrong length, or an
ML-KEM key failing FIPS 203's checks), `NQERNG` (also from ML-KEM `nqdec`,
whose masking draws fresh shares). Outputs are zeroed on failure.
[nqenc(3)](/noqtis/reference/man/nqenc-3/)

## Capsules

```c
typedef struct nqrep nqrep;    /* opaque report */

int nqseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
           const uint8_t *pk, size_t pklen, const char *meta,
           const char *tsa);
int nqchk(const char *dir, const uint8_t *trust, size_t trustlen,
          nqrep **rep);
int nqchkt(const char *dir, const uint8_t *trust, size_t trustlen,
           const uint8_t *const *anc, const size_t *anclen,
           size_t nanc, nqrep **rep);
int nqinsp(const char *dir, nqrep **rep);
int nqfiles(const char *dir, nqrep **rep);

typedef struct { uint8_t id[32]; const char *name; } nqcin;
int nqseal2(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, const char *meta,
            const nqcin *in, size_t nin);
int nqcapid(const char *dir, uint8_t id[32]);
typedef struct {
  const uint8_t *trust; size_t trustlen;
  const uint8_t *const *anc; const size_t *anclen; size_t nanc;
  const char *const *only; size_t nonly;   /* a partial check */
  const char *const *lin; size_t nlin;     /* input capsule folders */
  const char *const *stmt; const size_t *stmtlen; size_t nstmt; /* key statements */
} nqcopt;
int nqchkx(const char *dir, const nqcopt *o, nqrep **rep);
int nqdsse(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *pk,
           size_t pklen, const char *type, const uint8_t *payload,
           size_t n, char *out, size_t cap, size_t *outlen);
int nqdssevrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
               const char *env, size_t n, uint8_t *payload, size_t cap,
               size_t *outlen, char type[256]);
int nqkstmt(nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, nqsalg nalg,
            const uint8_t *nsk, size_t nsklen, const uint8_t *npk,
            size_t npklen, int64_t at, const char *reason, char *out,
            size_t cap, size_t *outlen);
int nqprove(const char *dir, const char *const *paths, size_t np,
            char *out, size_t cap, size_t *outlen);
int nqchkp(const char *proof, size_t n, const nqcopt *o, const char *dir,
           nqrep **rep);
size_t nqrepn(const nqrep *r);
int nqrepi(const nqrep *r, size_t i, const char **check, int *ok,
           const char **detail);
void nqrepfree(nqrep *r);
int nqtsreq(const char *dir, const uint8_t *nonce, size_t noncelen,
            uint8_t *req, size_t reqlen, size_t *outlen);
int nqtsput(const char *dir, const uint8_t *rsp, size_t rsplen,
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *const *anc, const size_t *anclen, size_t nanc,
            int64_t *gt, const char **why);
```

| Function | Does | Returns |
|---|---|---|
| `nqseal` | writes `noqtis.json` and `noqtis.sig` into `dir`; `meta` is `NULL` or a JSON object (≤ 1 MiB); `tsa` must be `NULL`; time from `SOURCE_DATE_EPOCH` or the clock | `NQOK`; `NQEARG` (bad keys or pair, a link, special file, refused or case-colliding name, bad `SOURCE_DATE_EPOCH`), `NQELIM` (a limit), `NQEDEC` (bad `meta`), `NQEIO`, `NQEMEM`, `NQENOSUP` (`tsa` given), `NQERNG`; nothing written on error |
| `nqchk` | checks `dir`; `trust` is the pinned public key or `NULL` to accept the seal's | `NQOK` all passed; `NQEVRFY` some failed (report set); `NQEARG`, `NQEMEM` (no report) |
| `nqchkt` | `nqchk` with up to 32 DER TSA anchors; the seal must then carry a timestamp that verifies under one | as `nqchk`; also `NQELIM` for more than 32 anchors |
| `nqseal2` | `nqseal` in format 2: a Merkle tree over the entries, the seal over the head, and up to 1024 inputs (`nqcapid` ids with names) | as `nqseal`; also `NQELIM` for more than 1024 inputs |
| `nqcapid` | the id of the capsule in `dir`: SHA-256 of the bytes its seal signs; checks nothing else | `NQOK`; `NQEDEC`, `NQEIO`, `NQEARG` |
| `nqchkx` | `nqchkt` with options (`NULL`: none): `only` for a partial check, `lin` folders to find and check the inputs in, `stmt` key statements followed from `trust` | as `nqchkt`; `NQEARG` for statements without `trust` |
| `nqdsse` | a DSSE envelope of a payload, signed over its PAE; keyid the SHA-256 of `pk` | `NQOK`; `NQEBUF`, `NQEARG`, `NQEMEM` |
| `nqdssevrfy` | checks an envelope: one signature under `pk`; gives the payload and its type | `NQOK`; `NQEVRFY`, `NQEDEC`, `NQEBUF`, `NQEARG`, `NQEMEM` |
| `nqkstmt` | a `noqtis-keys-1` statement: a rotation to `npk` (both keys sign) or, with `nsk`/`npk` `NULL`, a revocation, from `at` | `NQOK`; `NQEBUF`, `NQENOSUP` (Ed25519 alone), `NQEARG`, `NQEMEM` |
| `nqprove` | a `noqtis-proof-1` proof of `paths` in the format 2 capsule `dir`; `*outlen` is the size, also with `NQEBUF` | `NQOK`; `NQEBUF`, `NQENOSUP` (format 1), `NQEIO` (path not listed), `NQEDEC`, `NQELIM`, `NQEARG`, `NQEMEM` |
| `nqchkp` | checks a proof: the seal, its signature over the head and each audit path; with `dir`, the proven files there | as `nqchk` |
| `nqrepn` | number of rows (0 for `NULL`) | — |
| `nqinsp` | reads `dir`'s seal and manifest with `nqchk`'s strict readers and checks nothing; on success the report ends with `info.*` rows (format, alg, key fingerprint, created, files, bytes, timestamp, meta) | `NQOK`; `NQEDEC` one does not parse (report set); `NQEARG`, `NQEMEM` (no report) |
| `nqfiles` | `nqinsp` with one `info.file` row per listed file (`<size> <sha256> <path>`), paths the checker's rules accept; for fetching a published capsule | as `nqinsp` |
| `nqrepi` | row `i`: check name, 1/0, detail; strings live until `nqrepfree` | `NQOK`, `NQEARG` |
| `nqrepfree` | frees and wipes the report; `NULL` allowed | — |
| `nqtsreq` | the RFC 3161 `TimeStampReq` for the seal in `dir`: SHA-256 of its signature, the nonce (≤ 32 bytes, or `NULL`), certReq; at most 128 bytes | `NQOK`; `NQEARG`, `NQEBUF`, `NQEDEC` (not a canonical seal), `NQEIO` |
| `nqtsput` | checks a TSA's reply (granted, imprint, nonce, the token's signature; with up to 32 DER anchors, a path to one) and stores the token as the seal's `timestamp`; `*gt` genTime, `*why` what failed | `NQOK`; `NQEVRFY` (the reply does not check; nothing written), `NQEARG`, `NQEDEC`, `NQELIM`, `NQEIO`, `NQEMEM` |

Without anchors (`nqchk`), a seal that carries a timestamp fails its
`timestamp` row. Check names are listed in
[nqrep(3)](/noqtis/reference/man/nqrep-3/); the format is the
[capsule specification](/noqtis/spec/capsule/).
[nqseal(3)](/noqtis/reference/man/nqseal-3/),
[nqchk(3)](/noqtis/reference/man/nqchk-3/),
[nqchkt(3)](/noqtis/reference/man/nqchkt-3/),
[nqinsp(3)](/noqtis/reference/man/nqinsp-3/),
[nqseal2(3)](/noqtis/reference/man/nqseal2-3/),
[nqchkx(3)](/noqtis/reference/man/nqchkx-3/),
[nqprove(3)](/noqtis/reference/man/nqprove-3/),
[nqkstmt(3)](/noqtis/reference/man/nqkstmt-3/),
[nqdsse(3)](/noqtis/reference/man/nqdsse-3/),
[nqtsput(3)](/noqtis/reference/man/nqtsput-3/)

The library makes no network request: send the bytes from `nqtsreq` to
the TSA (HTTP POST, `application/timestamp-query`) and pass its reply to
`nqtsput`, as `noqtis seal --tsa` does.

## Shared libraries and Windows

`NQAPI` marks the exported functions; a shared build exports nothing else.
On Windows, programs that use `noqtis-0.dll` define `NQDLL` (the CMake
package and `noqtis.pc` do it for you). The shared library's ABI version is
the major version (`libnoqtis.so.0`).

## A complete program

```c
#include <noqtis.h>
#include <stdio.h>

int main(void) {
  static uint8_t pk[1952], sk[4032], sig[3309];
  const uint8_t msg[] = "results v1";
  size_t n = 0;
  int rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqsign(NQMLDSA65, sk, sizeof sk, msg, sizeof msg - 1, NULL, 0, 0,
                sig, sizeof sig, &n);
  nqwipe(sk, sizeof sk);
  if (rc == NQOK)
    rc = nqvrfy(NQMLDSA65, pk, sizeof pk, msg, sizeof msg - 1, NULL, 0, 0,
                sig, n);
  printf("%s\n", nqerr(rc));
  return rc == NQOK ? 0 : 1;
}
```

This is `docs/examples/sign.c`; it and the other programs in
`docs/examples/` are compiled with `-Wall -Wextra -Wpedantic -Wconversion
-Werror` and run in CI.
