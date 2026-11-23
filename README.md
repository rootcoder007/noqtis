# NOQTIS <img src="docs/logo/noqtis-hex.svg" align="right" height="139" alt="NOQTIS hex logo" />

[![Website](https://img.shields.io/badge/website-noqtis.dev-12706b)](https://noqtis.dev/)
[![ci](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml)
[![coverage](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml)
[![R-CMD-check](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml)
[![fuzz](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml)
[![docs](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16049/badge)](https://www.bestpractices.dev/projects/16049)
[![Release](https://img.shields.io/github/v/release/rootcoder007/noqtis?label=release&color=2ea44f)](https://github.com/rootcoder007/noqtis/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/noqtis?label=PyPI&color=3775a9)](https://pypi.org/project/noqtis/)
[![npm](https://img.shields.io/npm/v/noqtis?label=npm&color=cb3837)](https://www.npmjs.com/package/noqtis)
[![crates.io](https://img.shields.io/crates/v/noqtis?label=crates.io&color=f0b400)](https://crates.io/crates/noqtis)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.rootcoder007/noqtis?label=Maven%20Central&color=6f42c1)](https://central.sonatype.com/artifact/io.github.rootcoder007/noqtis)
[![Go Reference](https://pkg.go.dev/badge/github.com/rootcoder007/noqtis/bindings/go.svg)](https://pkg.go.dev/github.com/rootcoder007/noqtis/bindings/go)
[![r-universe](https://rootcoder007.r-universe.dev/badges/noqtis)](https://rootcoder007.r-universe.dev/noqtis)
[![COPR](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fcopr.fedorainfracloud.org%2Fapi_3%2Fpackage%2F%3Fownername%3Drootcoder007%26projectname%3Dnoqtis%26packagename%3Dnoqtis%26with_latest_build%3Dtrue&query=%24.builds.latest.state&label=COPR%20build&color=2ea44f)](https://copr.fedorainfracloud.org/coprs/rootcoder007/noqtis/)
[![OBS](https://build.opensuse.org/projects/home:rootcoder007/packages/noqtis/badge.svg?type=default)](https://build.opensuse.org/package/show/home:rootcoder007/noqtis)

**Seal the exact files behind a result with a post-quantum signature, so
anyone can check later, offline, that nothing changed.**

**N**otary **o**f **Q**uantum-Safe **T**raceable **I**nputs and **S**eals.

![NOQTIS in a minute and a half: make a key, pin a table schema, seal a folder, check it, change one file, the check fails, then a table that no longer fits its schema; then the report sealed to two people and signed, a key kept in the key store, signed mail and an OpenPGP signature](docs/demo.svg)

A sealed folder (a capsule) carries a manifest of every file and a
signature over it, so a check finds any file that changed, was added or
removed, and shows which key sealed it. NOQTIS is one C11 library with no
dependencies and a command-line tool, implementing ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
ML-KEM (FIPS 203), SHA-2 and SHA-3, byte-identical to the NIST test vectors, and HQC
(experimental, matching its reference known-answer files), with bindings for Python,
JavaScript, R, Rust, Go and Java.

> An independent audit through OSTIF has been applied for, and is open for
> [funding](https://app.lfx.dev/crowdfunding/initiatives/noqtis-security-audit-of-a-post-quantum-signing-and-provenance-library-in-c11).
> How it is tested, and the test-vector results, are on the
> [security page](https://noqtis.dev/security/#test-vectors).


```sh
noqtis keygen -a ML-DSA-65 -o me        # me (secret key), me.pub (public key)
noqtis seal -k me results/              # writes results/noqtis.json and noqtis.sig
noqtis check -p me.pub results/         # exit 0: every file is exactly as sealed
echo oops >> results/report.txt
noqtis check -p me.pub results/         # exit 1: "report.txt: size differs"
```

## Security guarantees

- Every file the seal lists is in the folder, byte for byte: same size,
  same SHA-256 and same SHA3-256.
- No file was added, removed or renamed, and no link or special file was
  slipped in.
- The list itself is exactly what the holder of the secret key signed,
  with a signature (ML-DSA or SLH-DSA) designed to resist attacks by
  quantum computers, which would break RSA and elliptic-curve signatures.
- With `-p key.pub`, it was that key that sealed it; without `-p`, only
  that *someone* did (anyone can make a capsule that checks without
  `-p`), and the report says so.
- Anything NOQTIS cannot check is a failed check, never a silent pass.

It does **not** prove that a result is correct, when it was sealed
(unless it carries a timestamp), or who owns a key: see
[what a check proves](https://noqtis.dev/guides/others/)
and the [threat model](https://noqtis.dev/security/).

## Design principles

- **Evidence that outlives its certificates**: `noqtis ers` keeps an RFC 4998
  evidence record beside the seal, renewed before a time-stamping
  authority's certificate expires or a hash weakens, so when a folder was
  sealed stays provable for decades.
- **First-order masking**: ML-DSA signing, ML-KEM and HQC
  decapsulation, SLH-DSA's secret-keyed hash and Ed25519 signing work on
  two random shares of the key, checked by a simulated first-order power
  analysis (TVLA) in CI; no measurement on hardware has been made.
- **No faulty signature leaves the library**: each one is verified under
  the public key before it is returned, since a signature made in a
  glitched computation can give the key away.
- **A self-test**: `noqtis selftest` (and `nqselftest()` in every binding)
  runs known answers for every algorithm family (SLH-DSA by its key
  generation only; `nqselftest(3)` lists the tests) in about a tenth of a
  second.
- **Embedded**: `-DNQFREE=ON` builds the algorithms alone, for firmware and
  kernels: no operating system, randomness from the caller, and no
  allocator except for Argon2id, which takes one from the caller
  (`nqsetal`).

## Mail, key management and hardware tokens

The same keys also sign and encrypt for people, in the formats mail and
key tools already read:

- **Several recipients, and signed**: `noqtis box -p ann.pub -p bob.pub -s me`
  seals a file to several people at once, signed by its sender; any one
  of them opens it.
- **A key store**: `noqtis keys` keeps other people's public keys under
  their names, certifies them, and finds a key by its e-mail address.
- **S/MIME and CMS**: `noqtis cert` writes X.509 certificates for noqtis
  keys, and `noqtis smime` signs and encrypts mail with ML-DSA, SLH-DSA
  and ML-KEM.
- **OpenPGP**: `noqtis pgp` makes version 6 keys (RFC 9580) with the
  post-quantum algorithms of RFC 9980, and
  signs, verifies, encrypts and decrypts with them.
- **Keys on a token**: `noqtis token` signs and decapsulates with keys
  that stay on a PKCS #11 token (a smart card or a hardware security
  module), and `noqtis seal --token` seals a folder with one.
- **Passphrase-protected keys**: Argon2id by default, or
  PBKDF2-HMAC-SHA-256 (`--kdf pbkdf2`) where rules require it;
  `noqtis passwd` changes the passphrase.
- **Text armor**: `sign -a` and `box -a` write a signature or a sealed
  file as text (RFC 7468), to paste into a message.

## Data provenance

A capsule can also say where its data came from and what shape it has,
in a data record (`noqtis.data.json`) that the seal covers like any
other file:

```sh
noqtis data add --url https://example.org/a.csv --retrieved now results data/a.csv
noqtis seal -k me results/
noqtis data check results/              # exit 1 when a file no longer matches its record
```

The data layer (`nqd.h`, `-lnqd`) is a separate library on the public
API, outside the core; see `noqtis-data(1)` and
`noqtis-data(5)`.

## Install

Every channel, with its status, is on the
[install page](https://noqtis.dev/start/install/).
In short:

| Platform | From source | Packages |
|---|---|---|
| Linux, macOS, Windows, FreeBSD | build from source (below) | release archives with `install.sh` / `install.ps1`, Homebrew (`brew install rootcoder007/noqtis/noqtis`), Scoop on Windows (`scoop bucket add noqtis https://github.com/rootcoder007/scoop-noqtis`, then `scoop install noqtis/noqtis`); RPMs and debs from the openSUSE Build Service and Fedora COPR |
| Containers | `docker build -t noqtis .` | `ghcr.io/rootcoder007/noqtis` |
| Nix | `nix build` (`flake.nix`) | Nixpkgs after its review |
| Arch, Alpine, Fedora, Debian, Wolfi | recipes in `packaging/` (`packaging/pkgtest.sh` builds one) | AUR first; the distributions after their review |
| JavaScript (Node, Deno, Bun, browsers) | `sh bindings/npm/build.sh` (wasi-sdk) | `npm install noqtis` |
| Python | `pip install ./bindings/py` | `pip install noqtis` |
| R | `R CMD INSTALL bindings/r` | r-universe (`rootcoder007.r-universe.dev`); `install.packages("noqtis")` after CRAN's review |
| Rust | `cargo add noqtis --git https://github.com/rootcoder007/noqtis` | `cargo add noqtis` |
| Go | `go get github.com/rootcoder007/noqtis/bindings/go` (cgo) | the same, at a release (`@latest`) |
| Java (JDK 22 or later) | `sh bindings/java/build.sh` (FFM, no JNI) | Maven Central `io.github.rootcoder007:noqtis`, the library inside the jar |


## Build

```sh
cmake -S . -B build                  # static library; -DNQSHARED=ON for shared
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ~/.local
```

`-DNQTESTS=OFF` skips the tests; `-DNQFREE=ON` builds the freestanding,
algorithms-only library (it needs only `memcpy`, `memmove`, `memset` and
`strcmp`; give it a random source with `nqsetrng` and, for Argon2id, an
allocator with `nqsetal`). The install gives the `noqtis` tool,
`libnoqtis`, `noqtis.h`, `noqtis.pc`, a CMake package and the manual pages
(`-DNQMAN=OFF` skips them), so other projects build against it with
`pkg-config --cflags --libs noqtis` or
`find_package(noqtis CONFIG)` and `target_link_libraries(... noqtis::noqtis)`.

The same seal and check from C (`cc prog.c $(pkg-config --cflags --libs noqtis)`):

```c
#include <noqtis.h>
static uint8_t pk[1952], sk[4032];   /* ML-DSA-65 key sizes, see nqssize() */
nqrep *rep = NULL;
int rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
if (rc == NQOK)
  rc = nqseal("results", NQMLDSA65, sk, sizeof sk, pk, sizeof pk, NULL, NULL);
nqwipe(sk, sizeof sk);
if (rc == NQOK)
  rc = nqchk("results", pk, sizeof pk, &rep);   /* NQOK, or NQEVRFY + report */
nqrepfree(rep);
```

## Documentation

- The site: <https://noqtis.dev/>: getting started, guides, a tutorial for
  [C](https://noqtis.dev/guides/c/),
  [Python](https://noqtis.dev/guides/py/),
  [JavaScript](https://noqtis.dev/guides/js/),
  [R](https://noqtis.dev/guides/r/),
  [Rust](https://noqtis.dev/guides/rust/),
  [Go](https://noqtis.dev/guides/go/) and
  [Java](https://noqtis.dev/guides/java/), the capsule format,
  the C, Python, JavaScript, R, Rust, Go and Java API references, the
  command line, and
  [why post-quantum provenance now](https://noqtis.dev/explain/why/).
- Manual pages, installed with the library: `man noqtis`, `man noqtis-seal`,
  `man noqtis-inspect`, `man noqtis-timestamp`,
  `man nqsign`, `man noqtis-capsule` (sources in [man/](man/)).
- The capsule format specification:
  [docs/spec/capsule.md](docs/spec/capsule.md); the data record format:
  [docs/spec/data.md](docs/spec/data.md).
- Runnable examples: [docs/examples/](docs/examples/), compiled and run in CI.

## Contributing, security, citing

- [CONTRIBUTING.md](CONTRIBUTING.md): build, tests, commit style and the
  rules for the code. Everyone follows the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- [SECURITY.md](SECURITY.md): report a vulnerability privately.
- [CITATION.cff](CITATION.cff): how to cite NOQTIS.

## Acknowledgements

NOQTIS implements published standards and is checked against other
people's work.

- The algorithms are those of NIST's FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
  and FIPS 205 (SLH-DSA), which standardise the designs of the
  CRYSTALS-Kyber, CRYSTALS-Dilithium and SPHINCS+ teams; HQC, by its
  submitters to the NIST process; SHA-2 and SHA-3 (FIPS 180-4, FIPS 202);
  and Ed25519 (RFC 8032; Bernstein, Duif, Lange, Schwabe and Yang).
- The test vectors are NIST's, from the Automated Cryptographic Validation
  Protocol, and those of Project Wycheproof.
- The checks run on CBMC (bounded proofs), Lean 4 and Mathlib (proofs of
  the arithmetic), dudect and Valgrind (timing), libFuzzer and
  ClusterFuzzLite (fuzzing) and OpenSSL 3.5 (agreement on the same
  inputs).
- Timestamps and evidence records follow RFC 3161 and RFC 4998.

Thanks, too, to the people who gave their time: Uwe Ligges and his
colleagues at CRAN; Jeroen Ooms, for R-universe; Mark Padgham and Mauro
Lepore, in rOpenSci's review, whose reviews and tools shaped the checks
here; the Fedora community, and especially its system administrators,
for their help with COPR; the maintainers of the CRAN Task Views and of
the distributions' package collections who answered and reviewed the
requests; and everyone
who reviewed this work.

## Licence

Apache-2.0 WITH LLVM-exception. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
