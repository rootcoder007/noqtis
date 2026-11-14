# noqtis: design

**N**otary **o**f **Q**uantum-Safe **T**raceable **I**nputs and **S**eals.

noqtis is a standalone library and command-line tool written in C11. It signs and
timestamps a record of the exact files an analysis used (a capsule), with
post-quantum signatures, and verifies such records. It is an independent
rewrite of the cryptographic core of rmoriebricklayer; it shares no code with
that package and carries none of its statistics.

## Goals

1. Auditable: one library, no third-party dependencies at run time.
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

Non-goals: a general TLS library (no server, no TLS 1.2, no resumption:
the TLS 1.3 client in `src/tls` exists so the tool can fetch over HTTPS
without another library, for `noqtis check <url>`, and stays behind the
CMake option `NQTLS`, off by default, until reviewed), a general X.509 issuing toolkit, key storage formats beyond
what the capsule needs, an OpenSSL provider (OpenSSL 3.5 already has ML-DSA,
SLH-DSA and ML-KEM).

## Language and build

- ISO C11, no compiler extensions in the library (`-std=c11 -pedantic`).
  Platform code (randomness, file I/O) sits in `src/platform/` behind
  `#if` blocks for Linux, macOS, the BSDs and Windows.
- Builds with GCC and Clang on Linux and macOS, and with MSVC on Windows.
- CMake is the only build (`cmake -S . -B build && cmake --build build`),
  3.20 or later; the R, Rust and Go bindings build the vendored sources
  with their own tools.
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

The "Must pass" column is the acceptance target, not a record of what
runs today. In place: dudect and simulated TVLA (`ct/`, workflow
`ct.yml`; results and their limits under "Side-channel results" below),
libFuzzer targets for every parser of untrusted bytes (`fuzz/`, workflow
`fuzz.yml`), ACVP harnesses for every algorithm family (`acvp/`), and
cross-verification with rmoriebricklayer where the formats overlap
(`tests/interop/`), a differential test against rmoriebricklayer's own
implementations of every algorithm both have (`tests/diff/`, CTest
`tdiff` with `-DNQDIFF=ON`, workflow `diff.yml`), the cross-check
against OpenSSL 3.5 or later (`tests/ossl/xossl.c`: the same keys,
signatures, ciphertexts and digests byte for byte) and its differential
fuzzer (`fuzz/ossl/fdiff.c`), both in workflow `ossl.yml`, and fuzzed
command-line arguments (`fuzz/fcli.c`). HMAC is tested with the ACVP
and Wycheproof HMAC vectors and against OpenSSL.

| # | Module | Contents | Must pass |
|---|---|---|---|
| M0 | `core` | error codes, `nqwipe`, constant-time helpers, `nqrand` and the caller's random source (`nqsetrng`), allocator hook, progress hook (`nqsetprog`), strict JSON reader, hex; `api/self.c`: the known-answer self-test (`nqselftest`) | unit tests, ASan/UBSan, valgrind clean |
| M1 | `hash` | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, SHAKE128/256 (incremental), HMAC; BLAKE2b (RFC 7693, keyed, 1 to 64 bytes) and Argon2id (RFC 9106, version 0x13; Argon2d and Argon2i internal, for the vectors), whose memory, allocated once through `nqsetal` and bounded, is wiped and freed before return | NIST CAVP/ACVP SHA vectors, Wycheproof HMAC, OpenSSL 3.5 differential fuzz |
| M2 | `drbg` | HMAC_DRBG (SP 800-90A) with SHA-256 and SHA-512 | CAVP DRBG vectors, reseed and prediction-resistance cases |
| M3 | `mldsa` | ML-DSA-44/65/87: keygen, sign (pure, with context, HashML-DSA pre-hash), verify, the external-mu interface (`nqsmu`, `nqsignmu`, `nqvrfymu`); first-order masked signing | ACVP keyGen/sigGen/sigVer, Wycheproof ML-DSA, OpenSSL 3.5 cross-check, ctgrind, dudect, TVLA |
| M4 | `slh` | SLH-DSA, all 12 parameter sets, pure and HashSLH-DSA; PRF masked (masked SHAKE256, bitsliced masked SHA-256; shared gadgets in `msk`) | ACVP keyGen/sigGen/sigVer, OpenSSL 3.5 cross-check, ctgrind, TVLA |
| M5 | `mlkem` | ML-KEM-512/768/1024: keygen, encaps, decaps; first-order masked decaps; input checks of FIPS 203 section 7 | ACVP keyGen/encapDecap, Wycheproof ML-KEM, OpenSSL 3.5 cross-check, ctgrind, dudect, TVLA |
| M6 | `hqc` | HQC-128/192/256 (v5.0.0, 2025-08-22); first-order masked decapsulation (`mdec.c`) | the reference KAT files (digests), masked against unmasked on every ciphertext class, ctgrind, dudect, TVLA |
| M3e | `ed` | Ed25519, Ed25519ctx, Ed25519ph (RFC 8032), strict verification (prime-order keys, S < L, canonical encodings); masked signing with a hedged nonce (`nqsignd`: RFC 8032's deterministic one); hybrid ML-DSA + Ed25519 in `api/sig.c` | RFC 8032 vectors, Wycheproof Ed25519, OpenSSL 3.5 cross-check and differential fuzz, ctgrind |
| M7 | `cls` | verification only: RSA PKCS#1 v1.5 and PSS (2048-4096), ECDSA P-256 and P-384 | Wycheproof RSA and ECDSA, OpenSSL 3.5 differential fuzz |
| M8 | `der` | strict DER reader (length, tag and depth limits), X.509 path checks, OCSP, CRL, RFC 3161 timestamp tokens | the rmoriebricklayer 1.0.3 x509/timestamp fixtures, libFuzzer corpus, positional-parse tests |
| M9 | `cap` | manifest of files (path, size, SHA-256, SHA3-256), canonical JSON, seal (sign + optional timestamp), verify; format 2: Merkle tree over the entries (RFC 9162), seal over the head, partial checks, proofs of single files, inputs and lineage; key statements (rotation, revocation), identity cards (`noqtis-idcard-1`), exports (in-toto, DSSE, RO-Crate, BagIt); RFC 4998 evidence records over the seal (`ers.c`: timestamp and hash-tree renewal, reduced hash trees read) | round-trip, tamper tests (every byte), path-containment tests, cross-verification with rmoriebricklayer; `tcap2` (tree against RFC 9162 by construction, every proof field tampered), an independent recomputation of the spec's example, `fproof`; evidence records against two local OpenSSL TSAs (`tcli`), `fers` |
| M10 | `cli` | `noqtis keygen / sign / verify / enc / dec / hash / seal / timestamp / ers / check / prove / export / rotate / revoke / idcard / inspect / selftest / algs / version`; a progress bar on a terminal (`prog.c`) | golden-output tests, exit codes, fuzzed arguments |
| M11 | `port` | platform layer for files and paths (Windows wide-char), symbol visibility, shared-library versioning, `noqtis.pc` and CMake package config | the full suite passes on every platform in the CI matrix |
| M12 | `bind` | WebAssembly (npm), Python, R, Rust, Go and Java bindings (done); .NET, Swift, Android and Ruby next | each binding's own tests on every platform it supports |
| M13 | `tls` | TLS 1.3 client (RFC 8446) with X25519MLKEM768 and X25519 key shares (`xdh`), AES-GCM and ChaCha20-Poly1305 (`aead`), certificate path, OCSP and CT checks; behind `NQTLS` | `taead`, `tecdh`, `thyb`, `thkdf` and `tests/tls` (a local test server through the `NQTEST` hooks); not yet reviewed |
| M14 | `box` | a secret key under a passphrase (noqtis-pwkey-1: Argon2id and ChaCha20-Poly1305, the header bound as associated data, parameter limits checked before any memory is taken; `nqpwenc`, `nqpwdec`, `noqtis keygen/sign/dec --pass-fd/--pass-env`) | `tpw` (known answers checked against OpenSSL's ARGON2ID and Python's `cryptography`, every byte tampered, the limits), `tcli`, `fpw` |

Dependencies: M1 needs M0; M2-M7 need M0-M1; M8 needs M1 and M7; M9 needs
M1-M5 and M8; M10 needs everything; M11 runs alongside; M12 needs M9;
M13 needs M1, M3e, M5, M7 and M8; M14 needs M1 and the AEAD of M13.

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
- The timestamp's message imprint is its hash (SHA-256/384/512) of the
  decoded `signature` bytes. `nqchkt` takes the TSA trust anchors: with
  anchors, the seal must carry a timestamp that verifies under one of them
  (RFC 3161 token, signer certificate path valid at genTime); with none
  (`nqchk`), a timestamp present is a failing check, never a silent pass.
  `nqseal` writes no timestamp (no network in the library): `nqtsreq`
  builds the request over the signature, the caller sends it, and
  `nqtsput` checks the reply and stores the token; `noqtis seal --tsa`
  does the HTTP part.
- Limits (each refused with its own report row or `nqcseal` reason, never
  a silent truncation): `noqtis.json` at most 512 MiB (its size is checked
  before it is read, and again if it grows while being read); at most
  2,000,000 files (a sanity bound); a path at most 4096 bytes; folders at
  most 64 levels deep; `noqtis.sig` and `meta` at most 1 MiB each.
- Memory: `nqchk` reads the manifest in its canonical layout one entry at
  a time and checks each against the folder as it goes (sorted order and
  duplicates incrementally), so it never builds a tree of the manifest.
  It holds the manifest bytes once (the pure signature is over those exact
  bytes, so they must be in memory for `nqvrfy`), the folder listing
  (about 100 bytes per file), the report (one row per file) and O(1)
  per-entry state: for 1,000,000 files, about 1x the manifest plus some
  200 MB. Bounding it below the manifest size would need a streaming
  verify API or the pre-hash variant (HashML-DSA), a format change.

### Interop with rmoriebricklayer

rmoriebricklayer's capsule is `capsule_bundle.json` (`cpsbndl`): pretty
JSON, not RFC 8785; per file only `path`, `sha256` and `size_bytes` (no
SHA3-256); a manifest digest and a time; and an attestation whose
ML-DSA, SLH-DSA, XMSS or HMAC signature is over the hex SHA-256 of the
canonical attestation payload (`mnfcanon`), not over the manifest's
bytes, with its own context. It has no reader for `noqtis.json` and
`noqtis.sig`, and noqtis none for the bundle, so neither checks the
other's capsule as such. What they share, and what is tested both ways:
FIPS 204 and 205 signatures in the standards' encodings with a context
string, SHA-256 file digests, and RFC 3161 tokens. rmoriebricklayer can
seal in the noqtis format with its own keys and signatures
(`tests/interop/blseal.R`, taking SHA3-256 from `noqtis hash` because it
has none) and check a noqtis capsule with its own code
(`tests/interop/blchk.R`: signature, SHA-256 and sizes, unlisted files,
and the timestamp with `tsvrf`; not SHA3-256); noqtis checks its
bundles' attestation signatures and file digests (`blbndl.R`).

## The data layer (nqd)

nqd (`include/nqd.h`, `nqd/`) is the part of noqtis that knows about
data: where a file came from, the shape of a CSV file, summaries that
show drift. It is a separate library, `libnqd`, with these boundaries:

- **Public API only.** nqd includes `noqtis.h` and nothing under
  `src/`: it hashes with `nqhash`/`nqhini`, compares digests with
  `nqcteq`, and reports through its own `nqdrep`. It has its own JSON
  reader and canonical writer (`nqd/js.c`), so a change to it never
  touches the audited core, and the core's reader is not reachable
  through it. Its internal symbols are prefixed `qd`, so a static link
  next to the core or a program meets no clash.
- **Not audited.** The core's audit scope (`src/`) is unchanged; nqd
  is listed separately in SECURITY.md. A bug in nqd can make a data
  check wrong, never a seal: the record is an ordinary file of the
  capsule, listed in the manifest and covered by the seal like any
  other, so `noqtis check` needs no change and fails when the record
  changes.
- **No network.** As with `nqtsreq`/`nqtsput`, where a source must be
  fetched nqd builds the request and reads the reply; the command-line
  tool moves the bytes.
- **The same rules as the core.** C11, no dependencies, no VLAs, no
  recursion in parsers (the JSON reader keeps an explicit stack of 32
  levels; the CSV reader is a state machine), every input bounded
  (a record 64 MiB, a CSV field 1 MiB, a line 16 MiB or 16,384
  fields, a regex pattern 1,024 bytes), every parser fuzzed (`fuzz/fdrec.c`,
  `fuzz/fdcsv.c`, `fuzz/fddft.c`, `fuzz/fdrx.c`, `fuzz/fdbnd.c`); the regex rule's matcher
  runs a set of states (Thompson), never backtracks, so its time is
  linear in the value. nqd
  allocates with `malloc` and `free` and never `realloc`; it does not
  go through the core's `nqsetal` hook, which is not public.
- **Format.** `noqtis.data.json` is `noqtis-data-1` (`noqtis-data(5)`,
  the site's specification): canonical JSON (RFC 8785, numbers as
  ECMAScript writes doubles), every member known (an unknown one is
  refused, so a record of a later format is never half-read), arrays
  keyed by path or name sorted and unique. Elements go in and out of
  the library as JSON text, so every binding builds the same bytes.

| # | Module | Contents | Must pass |
|---|---|---|---|
| Q1 | record | `noqtis.data.json`: reader, canonical writer, members, `nqdchk` (recomputes recorded checks, step digests and summaries); `noqtis data` | `tdrec` (RFC 8785 appendix B numbers, refusals), `tdcli`, `fdrec` |
| Q2 | schemas | CSV reader (RFC 4180), schema inference and check, rules (with regex and MAD); `noqtis schema` | `tdcsv` (the reader's refusals, every type and rule), `tdrx` (the matcher against Python's `re`, the MAD rule against R), `tdcli`, `fdcsv`, `fdrx` |
| Q3 | drift | summaries (`nqdstats`), KS from the sketch, PSI, Jensen-Shannon, chi-square of homogeneity, Benford (`nqddrift`), calibration (`nqddcal`); `noqtis drift` | `tddft` (against R's `ks.test` and `chisq.test`, `tests/nqd/drift.R`), `tdcli`, `fddft`; `tests/nqd/kserr.c` measures the sketch's error |
| Q5, Q6 | env, commitments, citation | `noqtis env`; `nqdcommit`, `nqdreveal` (`noqtis commit`, `reveal`); `nqdcite` (`noqtis cite`) | `tdrec` (a commitment known answer from another SHA3 implementation), `tdcli` |
| Q4 | diff | `nqddiff` (manifests through `nqfiles`, records member by member); `noqtis diff`; `seal -r`, `check -r` | `tdcli` (a file added, removed and changed, sources, schemas, env; nested capsules) |
| Q7 | synthetic data | `nqdsyn` (a CSV file from its schema, deterministic, recorded as synthetic); `noqtis data syn` | `tdcli` (against a file made by a separate Python implementation; refusals) |
| Q8 | reports | `nqdrpt` (Markdown and text, values escaped once); `noqtis report`; the action's report mode, outputs and annotations | `tdrpt`, `tdcli`, `.github/workflows/action.yml` |
| Q9 | bundles, chunks | `nqdpack`, `nqdunpack` (`noqtis-bundle-1`); `noqtis export --as bundle`, `check <file>`, `pack`; `nqdchunk`, `nqdpiece` (`chunks`); `noqtis chunk` | `tdbnd` (every refusal of the reader, a bundle cut at every byte, round trips that leave nothing behind), `tdcnk` (digests against SHA-256 computed apart, pieces), `tdcli`, `fdbnd` |
| Q7b | sources | `nqdaddr`, `nqdvrfy`, `nqdfld`; the portal resolvers `nqdrslv`, `nqdrsp`, `nqdwb` (CKAN, Socrata, ArcGIS, the Wayback Machine), pure; `noqtis src`, its HTTP in `cli/net.c` (`ncfetch`: same-server redirects, limits, resumption) | `tdsrc` (requests, replies as each portal documents them, refusals), `tdcli` (a local server: fallback order, refused bytes, cut and larger replies, redirects, each portal), `fdrsp` |
| Q4b | chains | `nqdchain` on format 2 lineage; `noqtis chain` | `tdcli` (a gap, a fork, links out of order, two inputs, another key, a changed link) |

## Platforms and packaging

noqtis must build, pass its tests and install on every platform people use,
with nothing to compile for the user where a package manager allows it.

### Platforms built and tested in CI

| OS | CPUs | Compilers | Notes |
|---|---|---|---|
| Linux (glibc) | x86-64, arm64 | gcc, clang | Ubuntu and Fedora images; done: also Debian stable and testing, Arch, openSUSE Tumbleweed, Rocky 9 and 10, Amazon Linux 2023, Wolfi, Void, Gentoo and Nix, each with its own compiler, on every push |
| Linux (musl) | x86-64 (arm64: the Python wheels) | gcc | Alpine; static binaries |
| Linux, 32-bit | i686, armv7 | gcc | catches size_t and shift assumptions |
| Linux, big-endian | s390x (QEMU) | gcc | catches byte-order bugs |
| macOS | arm64, x86-64 | Apple clang | a release archive for each |
| Windows | x86-64, arm64 | MSVC, clang-cl, MinGW-w64 | BCryptGenRandom; no POSIX assumed |
| FreeBSD, OpenBSD, NetBSD | x86-64 | clang; gcc on NetBSD | arc4random_buf |
| WebAssembly | wasm32 | emscripten, wasi-sdk | the tests under Node (emscripten) and under wasmtime (wasi-sdk); the npm package (wasi-sdk, loaded by its own lib/wasm.js and lib/wasi.js) on Node, Deno and Bun |
| Android | x86-64 (emulator); arm64 built only | NDK clang | API 28 and later; the tests through adb; no CLI |
| iOS | arm64 (simulator) | Apple clang | the tests through xcrun simctl spawn; no CLI |

A platform counts as supported only when the full test suite passes on it
in CI (every vector in the release builds; slow jobs sample the slowest). Randomness on each platform comes
from its OS source (getrandom, arc4random_buf, BCryptGenRandom, WebCrypto
getRandomValues through the WASI or emscripten layer); there is no fallback.

### Portability rules

- ISO C11 only; platform code lives in one file per concern
  (`src/core/rand.c` now, `src/cap/fs.c` for files) behind `#if` blocks.
- No assumption about endianness, `long` size, alignment of byte buffers,
  or `char` signedness; loads and stores go through the int.h helpers.
- No dependency on POSIX in the library except in `src/cap/fs.c`, which has
  a Windows branch (wide-character paths, UTF-8 at the API).
- The public header compiles as C11, C++11 and later, and under MSVC.
- File paths at the API are UTF-8 on every OS.

### Library form

- Static and shared builds from the same sources; symbols outside the
  public API are hidden (`-fvisibility=hidden`, a `.def` file on Windows).
  Done (`NQSHARED`; Windows exports through `NQAPI`'s `__declspec`).
- Semantic versioning. The shared library carries an ABI version
  (`libnoqtis.so.0`, `noqtis-0.dll`, `libnoqtis.0.dylib`); the public API
  never exposes a struct whose layout may change (sizes are fixed or
  opaque). Done (the version is `project(... VERSION)` in CMakeLists.txt,
  SOVERSION 0; `packaging/vercheck.sh` checks every other place that
  names it).
- `pkg-config` file (`noqtis.pc`) and a CMake package config
  (`find_package(noqtis)`) are installed with the library. Done; CI builds
  `tests/consumer` against each install both ways.
- `nqver()` and `NQVMAJ`/`NQVMIN`/`NQVPAT` give the version at run time and
  compile time. Done.
- A freestanding build (`-DNQFREE=ON`) of the algorithms and the one-call
  API alone, for firmware and kernels: no files, capsules, JSON, TLS or
  default allocator; the library needs only `memcpy`, `memmove`, `memset`
  and `strcmp` (it is built with `-fno-stack-protector -U_FORTIFY_SOURCE`,
  so no libc hardening call creeps in; `-DNQFREESSP=ON` keeps
  `-fstack-protector-strong` for a target with its own
  `__stack_chk_fail`), and randomness comes from the caller (`nqsetrng`).
  Done;
  CI checks the undefined symbols with `nm` and runs `tests/free/tfree.c`.

### Releases

- Every release is a signed git tag plus, for each platform above, a
  binary archive with `noqtis`, the library and the header, a SHA-256 file,
  a signature (Sigstore and an SSH signature by the release key), an SBOM
  (SPDX) and build provenance (SLSA).
- Builds are reproducible: the same tag gives byte-identical archives;
  CI rebuilds each release twice and compares.
- A source tarball, `noqtis-<version>.tar.gz` (`git archive` of the tag,
  made twice and compared), is what Homebrew and distributions build from.
- `install.sh` (for `curl -fsSL .../install.sh | sh`) picks the archive for
  the machine, checks its SHA-256 and signature, and installs into
  `~/.local` or a chosen prefix; it never runs anything it has not verified.
  `install.ps1` does the same on Windows.

### Packages

| Ecosystem | Package | Form | Status |
|---|---|---|---|
| Homebrew (macOS, Linux) | `noqtis` | formula in `packaging/brew`, tested in CI | taps `rootcoder007/homebrew-noqtis` and `homebrew-morie`, updated by each release; homebrew-core later |
| curl / shell | `install.sh`, `install.ps1` | verified binary download (above) | live |
| npm (Node, Deno, Bun, browsers) | `noqtis` | WebAssembly build, nothing to compile | live (trusted publishing); no native addon |
| PyPI | `noqtis` | wheels for every OS/CPU above (cibuildwheel), no compiler needed | live |
| R | `noqtis` | the C sources vendored (`tools/vendor.sh`); no network in tests, under 5 MB | r-universe; CRAN not yet submitted |
| crates.io (Rust) | `noqtis` | one crate with the C sources vendored and a safe API | live |
| Go | `github.com/rootcoder007/noqtis/bindings/go` | cgo binding with the C sources vendored; its own tag `bindings/go/vX.Y.Z`, on the release commit, pushed with each release tag | live (Go module proxy) |
| Java / Kotlin | Maven Central `io.github.rootcoder007:noqtis` | Panama (JDK 22+); the jar carries the library for six platforms | live |
| .NET | NuGet `Noqtis` | P/Invoke with runtime-specific natives | not yet |
| Swift / iOS / macOS apps | Swift Package | XCFramework | not yet |
| Android | Maven `noqtis-android` | AAR with NDK builds | not yet (the library's tests already run on the emulator) |
| Ruby | gem `noqtis` | FFI | not yet |
| C/C++ package managers | vcpkg, Conan, conda-forge | source recipes in `packaging/community`, built by `pkgs.yml` | conda-forge pull request open; vcpkg and Conan ready, not submitted |
| Linux distributions | Fedora/EPEL, openSUSE, Debian/Ubuntu, Arch (AUR), Alpine, Nix, Gentoo, Void, Wolfi | recipes in `packaging/` and `flake.nix`, built and tested in CI; community recipes in `packaging/community` | Fedora COPR and openSUSE OBS live, updated by each release; nixpkgs pull request open; AUR, Alpine and Gentoo GURU to be submitted by hand; Void and Wolfi ready, not submitted |
| Windows | Scoop, winget, Chocolatey | the release archives; `noqtis.exe` carries its C runtime | Scoop bucket `rootcoder007/scoop-noqtis` live; winget pull request open; Chocolatey not yet |
| Containers | `ghcr.io/rootcoder007/noqtis` | Wolfi image (`Dockerfile`) with the CLI, the shared library, the header and the pkg-config and CMake files | live |
| CI | GitHub Action `rootcoder007/noqtis@v0` (`action.yml` in this repository) | seal and check capsules in workflows; tested by `.github/workflows/action.yml` on Linux, macOS and Windows | live |

Every binding has its own tests that run the capsule round trip and a
sample of the ACVP vectors through the binding, on every platform the
ecosystem supports, before a release is published.

### Order

1. Library and CLI on every platform in CI (M11). Done.
2. Release archives, signatures, `install.sh`/`install.ps1`, Homebrew tap.
   Done.
3. npm (WebAssembly) and PyPI wheels. Done.
4. R (r-universe done; CRAN to submit).
5. vcpkg, conda-forge, AUR, Nix, winget, Scoop, the container image and the
   GitHub Action. The image, the Action and Scoop are done; conda-forge,
   nixpkgs and winget are open pull requests; the others are ready.
6. homebrew-core and the distribution packages: COPR and OBS are done;
   homebrew-core, Fedora, Debian and the others wait on their reviews and
   on adoption.
7. The other language bindings: Rust, Go and Java are done; .NET, Swift,
   Android and Ruby are next.

## Launch checklist

noqtis is announced only when every item below is done; releases from
0.1.1 on came first. Each item says how it is checked.

### Product

- [x] Every module M0-M10 accepted (its "Must pass" row green in CI:
      `ci.yml` vectors, ASan, valgrind; `ct.yml` ctgrind, dudect, TVLA;
      `ossl.yml` cross-check and differential fuzz; `fuzz.yml`; `tcli`).
- [x] `noqtis seal <dir>` and `noqtis check <dir>` work end to end on Linux,
      macOS and Windows, with a public timestamp from at least two RFC 3161
      authorities (`xseal.yml`: DigiCert, Sectigo and FreeTSA).
- [x] A capsule sealed on one platform checks on every other (`xseal.yml`
      seals on each OS and checks the result on all the others).
- [x] Capsules sealed by rmoriebricklayer check with noqtis, and the other
      way round, wherever their formats overlap (`tests/interop/`: tcli
      checks its fixtures everywhere; CTest `tbl` and `interop.yml` run
      the live round trip; see "Interop with rmoriebricklayer").
- [x] Error messages say what failed and what to do, for every refusal in
      `noqtis check` (a test reads each one: tcli reads every check name
      in `src/cap/chk.c`, makes each fail and requires its advice).

### Install

- [x] Signed, reproducible release archives for every platform in the CI
      matrix, with SHA-256 sums, Sigstore and SSH signatures, an SPDX SBOM
      and SLSA provenance; a second CI build of the tag is byte-identical
      (`release.yml`, jobs repro, sums, sign and provenance).
- [x] `curl -fsSL .../install.sh | sh` and `install.ps1` verify before they
      install, tested on a clean machine of each OS (`install.yml`; the
      SSH signature by default, a missing or foreign one refused).
- [x] Homebrew tap, the Wolfi container image, and the Arch, Alpine, Fedora,
      Debian and Wolfi (melange) recipes build and pass their tests (`ci.yml`
      jobs package, melange, brew, brewmac, docker).
- [x] npm (WebAssembly) and PyPI wheels install and pass the capsule round
      trip with nothing to compile (`npm.yml`, `py.yml`).
- [x] The GitHub Action seals and checks a capsule in a sample workflow
      (`action.yml`).

### Trust

- [x] SECURITY.md with a private reporting route (GitHub private
      vulnerability reports), the release signing key, and the disclosure
      window (a reply within 7 days, a fix within 90).
- [x] Fuzzing (libFuzzer on every parser) runs on each push for minutes and
      weekly for hours; OSS-Fuzz application filed (google/oss-fuzz#16392).
- [x] Bounded CBMC proofs of the parsers of untrusted bytes: no access out
      of bounds, overflow or undefined shift in the DER reader (headers of
      any length, trees to 6 bytes), the base64 decoder (to 32 characters)
      and the JSON reader (lexers to 4 bytes, the parser to 1), on every
      push (`proofs/cbmc/`, `cbmc.yml`).
- [x] dudect and simulated TVLA results for every secret operation are
      published with the release, with what they do and do not show
      (`noqtis-<version>-sidechannel.tar.gz`, its README.txt).
- [x] OpenSSF Best Practices (passing) badge in the README; Scorecard runs
      on every push (`scorecard.yml`) and its alerts are worked through; no
      score is quoted anywhere.
- [x] Every algorithm's ACVP harness produces responses ready for a CAVP
      lab; the README links the test-vector results (the security page,
      "Test vectors").
- [x] Lab-ready ACVP: `acvp/run.sh` answers a folder of ACVP requests
      (tested as `acvp-run`), and the site's Validation page says how an
      accredited lab would run the harnesses, what they cover, and that
      there is no CAVP or CMVP certificate.
- [x] The README states plainly that the code is not yet audited, and links
      the audit application and its funding page (OSTIF, on LFX
      Crowdfunding).
- [x] Threat model (what noqtis protects, against whom, and what it does
      not protect) on the site's security page
      (`docs/security.md`).

### Documentation

- [x] README: one-sentence pitch, a 30-second demo (seal, tamper, check
      fails) as an animated terminal recording, install for every platform,
      and the guarantees in plain words.
- [x] `docs/`: the capsule format specification (versioned, `spec/capsule`),
      the C API reference generated from noqtis.h, a tutorial per binding
      (`guides/c`, `js`, `py`, `r`, `rust`, `go`, `java`), and a "why
      post-quantum provenance now" explainer (`explain/why`).
- [x] A browser demo page: drop a folder, it is checked in WebAssembly with
      nothing uploaded.
- [x] CONTRIBUTING.md (build, tests, commit style, short-name rule,
      Signed-off-by), CODE_OF_CONDUCT.md, issue and pull-request templates,
      and labelled starter issues ("good first issue", "help wanted").
- [x] CITATION.cff, for researchers (GitHub's "Cite this repository").

### Launch

- [ ] Write-up: the problem (results that cannot be traced to their data,
      and signatures quantum computers will break), what noqtis does, and
      how it was tested; posted on the project site.
- [ ] Announce the same day on Hacker News (Show HN), Lobsters, r/crypto,
      r/programming, r/cpp/r/C_Programming, the IACR community and Mastodon,
      with the demo GIF; answer questions for the first 48 hours.
- [ ] Reach out to projects that would use it: reproducible-research and
      data-publishing platforms, CI and supply-chain tools, R and Python
      data communities.
- [x] Track adoption: downloads per package manager, Action usage and
      dependents, reviewed monthly (`adopt.yml`, on the 1st of each month,
      in the run summary).

## Documentation

Kept in the repository, so it is reviewed and tested like the code.

- **API reference:** one mdoc man page per public function and one for the
  tool: `noqtis(3)`, `nqsign(3)`, `nqvrfy(3)`, `nqseal(3)`, ..., `noqtis(1)`.
  They install with the library, so `man nqsign` works offline, and
  `mandoc -T lint` checks them in CI.
- **ABI:** a symbol-version map (`src/noqtis.map`, ELF) exports only the
  public functions, and libabigail (`abidiff`, `packaging/abi.sh`)
  compares each build's shared library with the last release in CI; a
  change that would break programs compiled against an earlier version
  fails unless the major version changes. Each release publishes the
  report.
- **Site:** published at `noqtis.dev`. GitHub Pages
  (`rootcoder007.github.io/noqtis`) carries the R package's reference, and
  sends any other address to `noqtis.dev`. It is dark unless the reader picks light. It carries getting started per platform,
  guides (sealing, checking someone else's capsule, keys, timestamps, CI),
  the versioned capsule format specification, the API reference rendered
  from the man pages, the binding references, the security page (threat
  model, test-vector, fuzzing and leakage results, audit status, reporting)
  and the WebAssembly browser demo.
- **Examples are code:** every example in the man pages and on the site is
  compiled and run in CI.

## Testing and CI

- `tests/vectors/`: ACVP JSON, Wycheproof JSON and KAT files, each with its
  source URL and SHA-256 in `tests/vectors/SOURCES.md`.
- `ctest` runs every module's tests; CI runs them on Linux (GCC, Clang),
  macOS (arm64, x86-64) and Windows (MSVC, clang-cl, MinGW), plus
  ASan+UBSan, valgrind and ctgrind. `ct.yml` runs dudect and the
  simulated TVLA, short on each push and long weekly, and uploads their
  JSON results. `fuzz.yml` runs libFuzzer on every parser, 90 s on each
  push and an hour weekly. `ossl.yml` runs the OpenSSL 3.5 cross-check
  and the differential fuzzer on Fedora's OpenSSL, 120 s on each push and
  an hour weekly.
- `acvp/` holds one harness per algorithm for NIST CAVP submission.

### Side-channel results

`ct/dd.c` (dudect: Welch's t on fixed-vs-random timings, raw and 100
upper crops, pass at |t| < 4.5, an early-exit compare as control) and
`ct/tv.c` (simulated TVLA on traces the masked code records in a
`-DNQTVLA` build; Hamming weight and Hamming distance; a point leaks at
|t| > 4.5 in two independent sets with the same sign; controls with the
masks forced to zero). The hooks compile to nothing otherwise: the 37
release objects are byte-identical with and without them (GCC 16.2.1,
Clang 22.1.8). Measured on an Intel Core i5-10310U, Linux 7.2.11,
GCC 16.2.1 Release, one core; the security page has every target.

| Operation | dudect N, max \|t\| | TVLA traces, masked max \|t\| (value model) |
|---|---|---|
| `nqcteq`, `nqcmov`, `nqctmask`/`nqctsel`, base64, hex | 40,000; 1.90 at most | not masked |
| HMAC, HMAC_DRBG (SHA-256, SHA-512) | 40,000; 2.19 at most | not masked |
| ML-KEM decaps, masked (512/768/1024; key and validity tests) | 5,000; 3.61 at most | 10,000; 4.19 / 4.67 / 4.87, no point |
| ML-KEM decaps, unmasked | 40,000; 2.14 at most | not masked |
| ML-KEM keygen | 20,000; 127.0: fails, its time depends on the public rho | not masked |
| ML-DSA sign, masked (44/65/87) | 2,500; 2.07 / 1.38 / 1.80 | 2,500 / 1,250 / 1,250; 5.57 / 5.60 / 5.20, no point; nonce test (44) 5.14 |
| ML-DSA sign, unmasked | 20,000; 1.99 / 1.83 / 4.55 (87: 1.41 at 64,000 when repeated) | not masked |
| SLH-DSA sign (SHA2-128f, SHAKE-128f) | 1,250 / 625; 5.72 / 4.83: fail (3.59 at 4,000 and 2.24 at 2,000 when repeated) | its PRF masked (SHA2, 64 calls bitsliced / SHAKE): 500 / 4,000; 4.86 / 3.64, no point |
| HQC decaps, masked (128; one key vs random keys) | 10,000 / 5,000 / 2,500; 2.73 at most (unmasked, 0.1.3) | 2,000 traces of 6,008,081 samples; 5.44, no point |
| Ed25519 sign, masked (scalar shares, randomised ladders, hedged nonce) | not run | 10,000; 4.71, no point |

dudect runs on one machine with one compiler: a pass is not a proof for
another CPU, compiler or flags, and says nothing about power. The TVLA is
a model of the values the C code computes, not a power measurement; it
finds the stored key leaking as it is loaded and split (expected: keys
are stored unmasked; the split's sign also leaks), the transition model
failing (shares are handled one after the other, without the
reference's assembly), and no leak of a masked value in the value model.
For SLH-DSA only PRF, the one function keyed with SK.seed, is masked; the
WOTS+ and FORS values it outputs are used unmasked, each meeting only its
own address.

## Security reporting

`SECURITY.md` gives a private reporting address and a 90-day disclosure
window. Until an external audit is published, the README says plainly that
the code is unaudited.

## CLI

`noqtis` (sources in `cli/`, built by default; `-DNQCLI=OFF` skips it) is
a thin tool over the public API in `noqtis.h`: it links the library as
built, static or shared, and calls nothing else. `noqtis help <command>`
prints each command's options.

| Command | What it does |
|---|---|
| `noqtis keygen -a <alg> -o <key> [--seed <hex\|file>] [--force]` | a key pair: secret key in `<key>`, public key in `<key>.pub`; `<alg>` is any name `noqtis algs` lists (case does not matter); `--seed` gives the standard's seed (hex, or a file of raw bytes) for deterministic keys |
| `noqtis sign -k <key> [-o <sig>] [-c <ctx>] [-d] [--ph <hash>] <file>` | the raw signature (FIPS 204/205 encoding) in `<sig>`, default `<file>.sig`; `-c` context string (at most 255 bytes), `-d` deterministic (all-zero per-signature randomness), `--ph` HashML-DSA / HashSLH-DSA with that hash; `<file>` may be `-` (stdin) with `-o` |
| `noqtis verify -p <key.pub> -s <sig> [-c <ctx>] [--ph <hash>] [-q] <file>` | prints `<file>: OK (<alg>)`; `verify -p <key.pub> --dsse [-o <payload>] <env>` checks a DSSE envelope from `export --as dsse` |
| `noqtis enc -p <key.pub> -o <ct> (<ss> \| --stdout)` | KEM encapsulation: ciphertext to `<ct>`, shared secret to `<ss>` |
| `noqtis dec -k <key> (-o <ss> \| --stdout) <ct>` | KEM decapsulation; a tampered ciphertext gives an unrelated secret and exit 0 (implicit rejection, as FIPS 203 and HQC require) |
| `noqtis hash [-a <hash>] [-c\|--check] [<file>...]` | `<hex>  <file>` lines in `sha256sum`'s format (names with `\` or a line break are escaped the same way); `--check` reads such lines and prints `<file>: OK` or `FAILED`; hashes `sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256` (default `sha256`; SHAKE prints 32 or 64 bytes) |
| `noqtis seal -k <key> [-p <key.pub>] [--meta <json-file>] [--format 1\|2] [--input [<name>=]<dir>]... [--tsa <url>]... [--anchor <der-file>]... <dir>` | `nqseal`: writes `noqtis.json` and `noqtis.sig`; the public key defaults to `<key>.pub` and must pair with `<key>`; `--format 2` makes the Merkle tree `prove` needs, and `--input` (up to 32 sealed capsules, which must check) records what this one was made from; `--tsa` then asks an RFC 3161 TSA for a timestamp (`nqtsreq`, an HTTP/1.1 POST over plain TCP in `cli/net.c`, http:// only, `nqtsput`); the seal holds one token, so a repeated `--tsa` is a fallback tried in order, and when none gives a token that checks the seal is removed (exit 2); `--anchor` (up to 32 DER certificates) checks the TSA at seal time |
| `noqtis check [-p <key.pub>] [--json] [--anchor <der-file>]... [--only <path>]... [--lineage <dir>]... [--keys <file>]... [--card <file>] <dir\|file\|url>` | `nqchkt`: one row per check (`ok`/`FAIL`, check, detail), then a summary, then on stderr what to do about each failed check; `--json` prints `{"capsule","ok","result","checks":[{"check","ok","detail"[,"fix"]}]}` on one line; without `-p` the seal's own key is accepted and the `key` row says so; `--anchor` gives up to 32 DER TSA anchors, and the seal must then carry a timestamp that verifies under one; `--only` checks some files (a partial check, which the report says); `--lineage` checks the recorded inputs; `--keys` takes rotation and revocation statements; `--card` names the sealer; a `<url>` (http://, or https:// with `NQTLS`) is fetched seal and manifest first; a `<file>` is a bundle from `export --as bundle`, unpacked to a temporary folder (refused whole when malformed), checked there and removed; `check --proof <file\|url>` checks a proof from `prove` |
| `noqtis timestamp --tsa <url>... [--anchor <der-file>]... [--force] <dir>` | adds an RFC 3161 token over a sealed capsule's signature; the manifest and signature are unchanged |
| `noqtis prove [-p <key.pub>] [-o <file>] [-f] <dir> <path>...` | a proof (JSON) that the named files are in a format 2 capsule, naming no other file |
| `noqtis export --as intoto\|dsse\|rocrate\|bagit\|bundle [-k <key>] [-p <key.pub>] [-o <file\|dir>] [-f] [--no-files] <dir>` | the checked capsule as an in-toto Statement v1, a DSSE envelope signed with `-k`, RO-Crate 1.1 metadata, a BagIt 1.0 bag, or a bundle (`noqtis-bundle-1`, one file that `check` reads; `--no-files`: the data record alone) |
| `noqtis pack init\|build\|check\|unpack` | reproducibility bundles: a template (`init -t plain\|r\|python`), `env` + `seal` + the bundle file (`build`), the capsule, the record, the lock files and the environment checked before shipping (`check`), a bundle opened (`unpack`) |
| `noqtis src add\|resolve\|fetch\|refresh\|list` | the sources of the data record: recorded by address or portal (CKAN, Socrata, ArcGIS), restored from the first address giving the recorded bytes (url, portal, mirrors, archived copy), fetched again to say whether they changed (`--write` records the new bytes) |
| `noqtis chunk pin\|check [--size <bytes>] [--at <offset>]` | `nqdchunk`/`nqdpiece`: chunk digests of a large file in the data record; a piece of it checked alone |
| `noqtis chain [-p <key.pub>] [--anchor <der-file>]... <dir>...` | `nqdchain`: an append-only chain of capsules (each sealed with the last as its only input) checked link by link, with its head |
| `noqtis rotate -k <key> -n <new> [--at <time>] [--reason <text>] [-o <file>]` | a key statement, signed by both keys, that `<key>` was replaced by `<new>` from `<time>` |
| `noqtis revoke -k <key> [--at <time>] [--reason <text>] [-o <file>]` | a key statement, signed by `<key>`, that it is revoked from `<time>` |
| `noqtis idcard -k <key> --name <name> [--orcid <id>] [--email <addr>] [--url <url>] [--affil <text>] [-o <file>]` | an identity card binding the key to its holder, signed by the key; `idcard --verify <card> [-p <key.pub>]` checks one |
| `noqtis ers --tsa <url>... [--anchor <der-file>]... [--hash sha256\|sha384\|sha512] <dir>` | `nqersreq`/`nqersput`: starts or renews the RFC 4998 evidence record `noqtis.ers` over the seal file (timestamp renewal, or hash-tree renewal with another `--hash`), the record there checked first; `check --anchor` checks it (`ers` row); `seal` and `timestamp` then refuse the folder |
| `noqtis selftest` | `nqselftest`: the known-answer self-test, exit 1 on a mismatch |
| `noqtis inspect [--json] <dir>` | what a capsule says (format, algorithm, key fingerprint, created, meta, files, timestamp); nothing is checked |
| `noqtis algs` | every algorithm (ML-DSA, SLH-DSA, Ed25519 and the ML-DSA + Ed25519 hybrids; ML-KEM, HQC) with its public key, secret key, signature or ciphertext, and shared secret sizes in bytes |
| `noqtis version` | `noqtis <nqver()>` |

Exit status, for every command: **0** success (signature valid, every
capsule check passed, every digest matched); **1** a verification failed
(bad or wrong-length signature, a capsule check failed, a digest differs
or a listed file is missing, a malformed `--check` line); **2** usage
error, unreadable or unwritable file, wrong kind of key, or a library
error.

### Key files

A key file is text: one header line, then the key bytes in the standard's
own encoding (FIPS 203, 204, 205; HQC v5.0.0) as base64 (RFC 4648, with
padding) in lines of 64 characters:

```
noqtis-key-1 <algorithm> <pub|sec>
<base64>
...
```

`<algorithm>` is the name `nqsname()` or `nqkname()` gives (`ML-DSA-65`,
`SLH-DSA-SHAKE-128f`, `ML-KEM-768`, `HQC-128`, ...). Readers accept `\n` or
`\r\n` line ends, reject any other character, non-canonical padding, a
header that is not exactly three space-separated fields, the wrong kind
(`pub` where a secret key is needed, or the reverse), and a key whose
decoded length is not the algorithm's size. The base64 encoder and decoder
are constant time (no table lookup or branch on a key byte).

Signatures and ciphertexts are raw bytes (the standard's encoding, no
header); a shared secret file is the raw 32 bytes.

### Secrets and files

- Secret key and shared-secret files are created owner-only (`0600` with
  `O_EXCL | O_NOFOLLOW` on POSIX; on Windows they inherit the folder's
  ACL) and through unbuffered streams, so no stdio buffer keeps a copy.
- No command overwrites an existing file unless given `--force`; with it
  the old file is removed first, so the new one never inherits its
  permissions or follows a link.
- Every buffer that held a secret key, seed or shared secret is wiped with
  `nqwipe` before it is freed. No secret is printed: a shared secret
  reaches stdout only with `--stdout` (in hex); keys never do.
- Windows: arguments are read as UTF-16 (`GetCommandLineW`) and passed on
  as UTF-8, files are opened with `_wfopen`/`_wopen`, and stdin and stdout
  are in binary mode. MSVC, clang-cl and MinGW-w64 need no `-municode`.

### Tests

`tests/cli/tcli.c` (CTest `tcli`) runs the built tool through the shell as
a user would, on every platform: help and usage errors (exit 2),
keygen/sign/verify for ML-DSA-44/65/87 and SLH-DSA SHA2/SHAKE-128f (all
twelve SLH-DSA sets with `NQCLIALL=1`), tampered message, signature,
length, context and key (exit 1), deterministic keys and signatures,
pre-hash, every ML-KEM and HQC set (round trip, implicit rejection, owner-
only files, no secret on stdout), digests against known values and
`--check`, seal/check with changed, added and removed files and a
changed manifest or seal, `seal --tsa` and `check --anchor` against
`tests/cli/tsad` (a local TSA over HTTP on 127.0.0.1 that answers with
`openssl ts -reply` when openssl is on the PATH, or replays a token, an
HTTP error, a redirect or junk; never the network), and every check name
in `src/cap/chk.c` made to fail, with what to do printed for each failed
row. `NQCLIWRAP="valgrind -q --error-exitcode=9
--leak-check=full"` runs every command under a wrapper; a sanitizer or
valgrind report in stderr fails the check whatever the exit status.
