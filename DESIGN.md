# noqtis: design

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

noqtis is a small library and command-line tool written in C11. It signs and
timestamps a record of the exact files an analysis used (a capsule), with
post-quantum signatures, and verifies such records. It is an independent
rewrite of the cryptographic core of rmoriebricklayer; it shares no code with
that package and carries none of its statistics.

## Goals

1. Small enough to audit: one library, no third-party dependencies at run time.
2. Standard algorithms only, byte-identical to the standards' test vectors:
   FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 202 (SHA-3,
   SHAKE), FIPS 180-4 (SHA-2), SP 800-90A (HMAC_DRBG), HQC (round 4, v5.0.0).
3. Ready for NIST CAVP algorithm validation: every algorithm has an ACVP
   harness that reads the ACVP JSON test vectors and writes ACVP responses.
4. Fail closed: every parser rejects anything the standard does not define,
   and every verifier returns a failure for anything it cannot check.
5. Constant time for every operation on secret data, checked by tools rather
   than assumed (valgrind memcheck with secrets marked undefined, dudect,
   simulated TVLA).

Non-goals: TLS, a general X.509 issuing toolkit, key storage formats beyond
what the capsule needs, an OpenSSL provider (OpenSSL 3.5 already has ML-DSA,
SLH-DSA and ML-KEM).

## Language and build

- ISO C11, no compiler extensions in the library (`-std=c11 -pedantic`).
  Platform code (randomness, file I/O) sits in `src/platform/` behind
  `#if` blocks for Linux, macOS, the BSDs and Windows.
- Builds with GCC and Clang on Linux and macOS, and with MSVC on Windows.
- CMake is the primary build (`cmake -S . -B build && cmake --build build`);
  a plain `Makefile` builds the library and tests on POSIX for auditors who
  do not want CMake.
- Warnings are errors in CI: `-Wall -Wextra -Wpedantic -Wconversion
  -Wshadow -Wstrict-prototypes -Wcast-qual -Wvla`.
- No VLAs, no recursion in parsers (explicit depth limits instead), no
  `malloc` in the algorithm code (the capsule and parser layers allocate,
  through one allocator hook (`nqsetal`)).

## Public API conventions (`include/noqtis.h`)

- **Short names everywhere**, no long snake_case: functions are `nq` plus
  a short word (`nqsign`, `nqvrfy`, `nqskg`, `nqenc`, `nqdec`, `nqhash`,
  `nqseal`, `nqchk`), types likewise (`nqhctx`, `nqsalg`), constants
  `NQ` plus a short word (`NQOK`, `NQEVRFY`, `NQMLDSA65`). File and folder
  names are short too (`int.h`, `rand.c`, `tcore.c`, `src/slh/`).
- Every function returns `int`: `NQOK` (0) or a negative `NQE*` error code.
  Verification failure is `NQEVRFY`, never 0.
- Keys, signatures and ciphertexts are byte strings in the encodings the
  standards define. Sizes are compile-time constants and also
  available at run time (`nqssize()`, `nqksize()`).
- The caller allocates output buffers and passes their length; a function
  never writes past the length it was given and returns `NQEBUF` when it is
  too small.
- Secrets are wiped with `nqwipe()` (cannot be optimised away) before a
  function returns, on every path.
- Randomness comes from `nqrand()` (operating system CSPRNG) unless
  the caller passes a seed through the `d` variants (`nqskgd`, `nqsignd`, `nqencd`), which exist for
  the test vectors.

## Modules

Each module is one directory under `src/`, with its tests under `tests/`.
A module is accepted only when every check in its row passes.

| # | Module | Contents | Must pass |
|---|---|---|---|
| M0 | `core` | error codes, `nqwipe`, constant-time helpers, `nqrand`, allocator hook, strict JSON reader, hex | unit tests, ASan/UBSan, valgrind clean |
| M1 | `hash` | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, SHAKE128/256 (incremental), HMAC | NIST CAVP/ACVP SHA vectors, Wycheproof HMAC, OpenSSL 3.5 differential fuzz |
| M2 | `drbg` | HMAC_DRBG (SP 800-90A) with SHA-256 and SHA-512 | CAVP DRBG vectors, reseed and prediction-resistance cases |
| M3 | `mldsa` | ML-DSA-44/65/87: keygen, sign (pure, with context, HashML-DSA pre-hash), verify; first-order masked signing | ACVP keyGen/sigGen/sigVer, Wycheproof ML-DSA, OpenSSL 3.5 cross-check, ctgrind, dudect, TVLA |
| M4 | `slh` | SLH-DSA, all 12 parameter sets, pure and HashSLH-DSA | ACVP keyGen/sigGen/sigVer, OpenSSL 3.5 cross-check, ctgrind |
| M5 | `mlkem` | ML-KEM-512/768/1024: keygen, encaps, decaps; first-order masked decaps; input checks of FIPS 203 section 7 | ACVP keyGen/encapDecap, Wycheproof ML-KEM, OpenSSL 3.5 cross-check, ctgrind, dudect, TVLA |
| M6 | `hqc` | HQC-128/192/256 (v5.0.0, 2025-08-22) | the reference KAT files (digests), ctgrind, dudect |
| M7 | `cls` | verification only: RSA PKCS#1 v1.5 and PSS (2048-4096), ECDSA P-256 and P-384 | Wycheproof RSA and ECDSA, OpenSSL 3.5 differential fuzz |
| M8 | `der` | strict DER reader (length, tag and depth limits), X.509 path checks, OCSP, CRL, RFC 3161 timestamp tokens | the rmoriebricklayer 1.0.3 x509/timestamp fixtures, libFuzzer corpus, positional-parse tests |
| M9 | `cap` | manifest of files (path, size, SHA-256, SHA3-256), canonical JSON, seal (sign + optional timestamp), verify | round-trip, tamper tests (every byte), path-containment tests, cross-verification with rmoriebricklayer |
| M10 | `cli` | `noqtis keygen / sign / verify / seal / check / timestamp / inspect` | golden-output tests, exit codes, fuzzed arguments |

Dependencies: M1 needs M0; M2-M7 need M0-M1; M8 needs M1 and M7; M9 needs
M1-M5 and M8; M10 needs everything.

## Capsule format, version 1

A capsule is a folder that holds the files of a result plus `noqtis.json`
(the manifest) and `noqtis.sig` (the seal).

- `noqtis.json`: canonical JSON (RFC 8785 JCS: sorted keys, no whitespace,
  shortest round-trip numbers, UTF-8). Fields: `format` ("noqtis-capsule-1"),
  `created` (RFC 3339 UTC), `files` (array sorted by path, each `{path,
  size, sha256, sha3_256}`), optional `meta` (object, opaque to noqtis).
  Paths are relative, use `/`, contain no `..`, no leading `/`, no NUL, and
  must resolve inside the capsule folder.
- `noqtis.sig`: canonical JSON: `format` ("noqtis-seal-1"), `alg` (for
  example "ML-DSA-65"), `context` (the FIPS 204/205 context string, default
  "noqtis-capsule-1"), `manifest_sha256`, `public_key` (base64),
  `signature` (base64), optional `timestamp` (base64 RFC 3161 token over
  the signature).
- Verification recomputes every file digest, fails on any file present but
  not listed or listed but missing, checks the signature over the exact
  manifest bytes, and checks the timestamp when present.

## Testing and CI

- `tests/vectors/`: ACVP JSON, Wycheproof JSON and KAT files, each with its
  source URL and SHA-256 in `tests/vectors/SOURCES.md`.
- `ctest` runs every module's tests; CI runs them on Linux (GCC, Clang),
  macOS (arm64, x86-64) and Windows (MSVC), plus ASan+UBSan, valgrind,
  ctgrind, dudect, TVLA, libFuzzer (time-boxed on each push, longer weekly)
  and an OpenSSL 3.5 differential job.
- `acvp/` holds one harness per algorithm for NIST CAVP submission.

## Security reporting

`SECURITY.md` gives a private reporting address and a 90-day disclosure
window. Until an external audit is published, the README says plainly that
the code is unaudited.
