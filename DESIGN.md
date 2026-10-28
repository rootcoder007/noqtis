# noqtis: design

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

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
| M11 | `port` | platform layer for files and paths (Windows wide-char), symbol visibility, shared-library versioning, `noqtis.pc` and CMake package config | the full suite passes on every platform in the CI matrix |
| M12 | `bind` | WebAssembly build and the npm, PyPI and CRAN packages first, then the other bindings | each binding's own tests on every platform it supports |

Dependencies: M1 needs M0; M2-M7 need M0-M1; M8 needs M1 and M7; M9 needs
M1-M5 and M8; M10 needs everything; M11 runs alongside from now on; M12 needs M9.

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

## Platforms and packaging

noqtis must build, pass its tests and install on every platform people use,
with nothing to compile for the user where a package manager allows it.

### Platforms built and tested in CI

| OS | CPUs | Compilers | Notes |
|---|---|---|---|
| Linux (glibc) | x86-64, arm64 | gcc, clang | Ubuntu and Fedora images |
| Linux (musl) | x86-64, arm64 | gcc | Alpine; static binaries |
| Linux, 32-bit | i686, armv7 | gcc | catches size_t and shift assumptions |
| Linux, big-endian | s390x (QEMU) | gcc | catches byte-order bugs |
| macOS | arm64, x86-64 | Apple clang | universal binaries for releases |
| Windows | x86-64, arm64 | MSVC, clang-cl, MinGW-w64 | BCryptGenRandom; no POSIX assumed |
| FreeBSD, OpenBSD | x86-64 | clang | arc4random_buf |
| WebAssembly | wasm32 | emscripten, wasi-sdk | browsers, Node, Deno, Bun, WASI runtimes |
| Android, iOS | arm64 | NDK clang, Xcode | built as libraries; no CLI |

A platform counts as supported only when the full test suite, including
every ACVP vector, passes on it in CI. Randomness on each platform comes
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
- Semantic versioning. The shared library carries an ABI version
  (`libnoqtis.so.0`, `noqtis-0.dll`, `libnoqtis.0.dylib`); the public API
  never exposes a struct whose layout may change (sizes are fixed or
  opaque).
- `pkg-config` file (`noqtis.pc`) and a CMake package config
  (`find_package(noqtis)`) are installed with the library.
- `nqver()` and `NQVMAJ`/`NQVMIN`/`NQVPAT` give the version at run time and
  compile time.

### Releases

- Every release is a signed git tag plus, for each platform above, a
  binary archive with `noqtis`, the library and the header, a SHA-256 file,
  a signature (Sigstore and an SSH signature by the release key), an SBOM
  (SPDX) and build provenance (SLSA).
- Builds are reproducible: the same tag gives byte-identical archives;
  CI rebuilds each release twice and compares.
- `install.sh` (for `curl -fsSL .../install.sh | sh`) picks the archive for
  the machine, checks its SHA-256 and signature, and installs into
  `~/.local` or a chosen prefix; it never runs anything it has not verified.
  `install.ps1` does the same on Windows.

### Packages

| Ecosystem | Package | Form |
|---|---|---|
| Homebrew (macOS, Linux) | `noqtis` | tap `rootcoder007/homebrew-morie` first, homebrew-core later |
| curl / shell | `install.sh`, `install.ps1` | verified binary download (above) |
| npm (Node, Deno, Bun, browsers) | `noqtis` | WebAssembly build, works everywhere with nothing to compile; optional native addon (Node-API, prebuilt per platform) for speed |
| PyPI | `noqtis` | wheels for every OS/CPU above (cibuildwheel), no compiler needed |
| CRAN (R) | `noqtis` | the C sources vendored in an R package; no network in tests, under 5 MB (test vectors stay in this repo) |
| crates.io (Rust) | `noqtis-sys`, `noqtis` | raw bindings plus a safe wrapper |
| Go | `github.com/rootcoder007/noqtis/go` | cgo binding |
| Java / Kotlin | Maven Central `noqtis` | Panama (JDK 22+) with a JNI fallback; per-platform natives in the jar |
| .NET | NuGet `Noqtis` | P/Invoke with runtime-specific natives |
| Swift / iOS / macOS apps | Swift Package | XCFramework |
| Android | Maven `noqtis-android` | AAR with NDK builds |
| Ruby | gem `noqtis` | FFI |
| C/C++ package managers | vcpkg, Conan, conda-forge, xmake | source recipes |
| Linux distributions | Debian/Ubuntu, Fedora/EPEL, Arch (AUR), Alpine, Nix, Gentoo | distro packages |
| Windows | winget, Scoop, Chocolatey | the release archives |
| Containers | `ghcr.io/rootcoder007/noqtis` | distroless image with the CLI |
| CI | GitHub Action `rootcoder007/noqtis-action` | seal and check capsules in workflows |

Every binding has its own tests that run the capsule round trip and a
sample of the ACVP vectors through the binding, on every platform the
ecosystem supports, before a release is published.

### Order

1. Library and CLI on every platform in CI (M11).
2. Release archives, signatures, `install.sh`/`install.ps1`, Homebrew tap.
3. npm (WebAssembly) and PyPI wheels.
4. CRAN.
5. vcpkg, conda-forge, AUR, Nix, winget, Scoop, the container image and the
   GitHub Action.
6. homebrew-core and the distribution packages.
7. The other language bindings.

## Release channels

Where noqtis is published, what each channel requires before it accepts
the project, and when it can go there. "Day one" means the day the
repository goes public with a signed v0.1.0 tag.

| Channel | What it requires | When |
|---|---|---|
| npm, PyPI, crates.io, NuGet, Maven Central, RubyGems, Go modules | published by us | day one |
| CRAN | CRAN's submission review (policy, `R CMD check --as-cran`, no network in tests, under 5 MB) | after its review, days |
| Homebrew tap `rootcoder007/homebrew-morie` | ours | day one |
| Scoop bucket, GHCR and Docker Hub images (Wolfi), GitHub Action Marketplace | ours | day one |
| winget, Chocolatey | a pull request or package submission; moderated, routine | day one to days |
| Arch User Repository | an upload by any user | day one |
| Nixpkgs | a pull request reviewed by maintainers | first week |
| conda-forge | a pull request to staged-recipes | first week |
| vcpkg, Conan Center | a pull request; build and licence checked | first weeks |
| Wolfi (`wolfi-dev/os`) | a melange recipe pull request | first weeks |
| Alpine (aports `testing`, then `community`) | a merge request with a named maintainer | first weeks |
| MacPorts, FreeBSD ports, OpenBSD ports, pkgsrc | a port reviewed by a committer | weeks |
| homebrew-core | a stable tagged release, a source build on macOS (arm64, x86-64) and Linux, a real `test do` block, and notability (about 75 stars, or 30 forks or watchers; stricter for self-submissions) | weeks after launch |
| Fedora and EPEL | a package review, and a sponsor until we are packagers | 1-2 months |
| Debian, then Ubuntu (which syncs from Debian) | an intent-to-package bug, a Debian Developer sponsor and FTP-master review | 1-3 months |
| Arch official repositories, Gentoo main tree | adoption by a trusted user or developer | once widely used |
| OSS-Fuzz | Google's acceptance of important or widely used projects | after adoption |

Every recipe lives in `packaging/` and is built and tested in CI before it
is submitted, so each channel gets a recipe that already passes its own
checks. The homebrew-core formula is the tap's formula, so moving it is a
pull request, not a rewrite.

Funding and credibility, not distribution: OSTIF (audit), Sovereign Tech
Agency, NLnet NGI Zero, OpenSSF Alpha-Omega and the R Consortium; apply
around launch (see the launch checklist).

## Launch checklist

The repository goes public, and v0.1.0 is announced, only when every item
below is done. Each item says how it is checked.

### Product

- [ ] Every module M0-M10 accepted (its "Must pass" row green in CI).
- [ ] `noqtis seal <dir>` and `noqtis check <dir>` work end to end on Linux,
      macOS and Windows, with a public timestamp from at least two RFC 3161
      authorities.
- [ ] A capsule sealed on one platform checks on every other (CI seals on
      each OS and checks the result on all the others).
- [ ] Capsules sealed by rmoriebricklayer check with noqtis, and the other
      way round, wherever their formats overlap.
- [ ] Error messages say what failed and what to do, for every refusal in
      `noqtis check` (a test reads each one).

### Install

- [ ] Signed, reproducible release archives for every platform in the CI
      matrix, with SHA-256 sums, Sigstore and SSH signatures, an SPDX SBOM
      and SLSA provenance; a second CI build of the tag is byte-identical.
- [ ] `curl -fsSL .../install.sh | sh` and `install.ps1` verify before they
      install, tested on a clean machine of each OS.
- [ ] Homebrew tap, the Wolfi container image, and the Arch, Alpine, Fedora,
      Debian and Wolfi (melange) recipes build and pass their tests.
- [ ] npm (WebAssembly) and PyPI wheels install and pass the capsule round
      trip with nothing to compile.
- [ ] The GitHub Action seals and checks a capsule in a sample workflow.

### Trust

- [ ] SECURITY.md with a private reporting route, a published key for
      reports, and the disclosure window.
- [ ] Fuzzing (libFuzzer on every parser) runs on each push for minutes and
      weekly for hours; OSS-Fuzz application filed.
- [ ] dudect and simulated TVLA results for every secret operation are
      published with the release, with what they do and do not show.
- [ ] OpenSSF Scorecard and Best Practices (passing) badges; no number is
      claimed that the badge pages do not show.
- [ ] Every algorithm's ACVP harness produces responses ready for a CAVP
      lab; the README links the test-vector results.
- [ ] The README states plainly that the code is not yet audited, and links
      the audit application and its funding page.
- [ ] Threat model (what noqtis protects, against whom, and what it does
      not protect) in `docs/threat.md`.

### Documentation

- [ ] README: one-sentence pitch, a 30-second demo (seal, tamper, check
      fails) as an animated terminal recording, install for every platform,
      and the guarantees in plain words.
- [ ] `docs/`: the capsule format specification (versioned), the C API
      reference generated from noqtis.h, a tutorial per binding, and a
      "why post-quantum provenance now" explainer.
- [ ] A browser demo page: drop a folder, it is checked in WebAssembly with
      nothing uploaded.
- [ ] CONTRIBUTING.md (build, tests, commit style, short-name rule,
      Signed-off-by), CODE_OF_CONDUCT.md, issue and pull-request templates,
      and labelled starter issues.
- [ ] CITATION.cff and a Zenodo DOI for the release, for researchers.

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
- [ ] Track adoption: downloads per package manager, Action usage and
      dependents, reviewed monthly.

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
