# NOQTIS <img src="docs/logo/noqtis-hex.svg" align="right" height="139" alt="NOQTIS hex logo" />

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16049/badge)](https://www.bestpractices.dev/projects/16049)

**Seal the exact files behind a result with a post-quantum signature, so
anyone can check later, offline, that nothing changed.**

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

![NOQTIS in 30 seconds: make a key, seal a folder, check it, change one file, the check fails](docs/demo.svg)

A sealed folder (a capsule) carries a manifest of every file and a
signature over it, so a check finds any file that changed, was added or
removed, and shows which key sealed it. NOQTIS is one C11 library with no
dependencies and a command-line tool, implementing ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
ML-KEM (FIPS 203), HQC (experimental), SHA-2 and SHA-3, byte-identical to the NIST test
vectors, with bindings for Python, JavaScript and R.

> **Status: unaudited, before its first release.** The code has not had an
> external security audit; do not rely on it for anything that matters yet.
> How it is tested, and the test-vector results, are on the
> [security page](https://rootcoder007.github.io/noqtis/security/#test-vectors).


```sh
noqtis keygen -a ML-DSA-65 -o me        # me (secret key), me.pub (public key)
noqtis seal -k me results/              # writes results/noqtis.json and noqtis.sig
noqtis check -p me.pub results/         # exit 0: every file is exactly as sealed
echo oops >> results/report.txt
noqtis check -p me.pub results/         # exit 1: "report.txt: size differs"
```

## What a passing check guarantees

- Every file the seal lists is in the folder, byte for byte: same size,
  same SHA-256 and same SHA3-256.
- No file was added, removed or renamed, and no link or special file was
  slipped in.
- The list itself is exactly what the holder of the secret key signed,
  with a post-quantum signature (ML-DSA or SLH-DSA) that stays hard to
  forge after quantum computers break RSA and elliptic curves.
- With `-p key.pub`, it was that key that sealed it; without `-p`, only
  that *someone* did, and the report says so.
- Anything NOQTIS cannot check is a failed check, never a silent pass.

It does **not** prove that a result is correct, when it was sealed
(without a timestamp), or who owns a key: see
[what a check proves](https://rootcoder007.github.io/noqtis/guides/others/)
and the [threat model](https://rootcoder007.github.io/noqtis/security/).

## Install

Every channel, with its status, is on the
[install page](https://rootcoder007.github.io/noqtis/start/install/).
In short:

| Platform | Today | From v0.1.1 |
|---|---|---|
| Linux, macOS, Windows, FreeBSD | build from source (below) | release archives with `install.sh` / `install.ps1`, Homebrew tap, Scoop |
| Containers | `docker build -t noqtis .` | `ghcr.io/rootcoder007/noqtis` |
| Nix | `nix build` (`flake.nix`) | Nixpkgs after its review |
| Arch, Alpine, Fedora, Debian, Wolfi | recipes in `packaging/` (`packaging/pkgtest.sh` builds one) | AUR first; the distributions after their review |
| JavaScript (Node, Deno, Bun, browsers) | `sh bindings/npm/build.sh` (emscripten) | `npm install noqtis` |
| Python | `pip install ./bindings/py` | `pip install noqtis` |
| R | `R CMD INSTALL bindings/r` | `install.packages("noqtis")` after CRAN's review |

No package is published yet: every "From v0.1.1" channel opens with the
first tagged release.

## Build

```sh
cmake -S . -B build                  # static library; -DNQSHARED=ON for shared
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ~/.local
```

`-DNQTESTS=OFF` skips the tests. The install gives the `noqtis` tool,
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

- The site: <https://rootcoder007.github.io/noqtis/> (sources in
  `docs/site`): getting started, guides, a tutorial for
  [C](https://rootcoder007.github.io/noqtis/guides/c/),
  [Python](https://rootcoder007.github.io/noqtis/guides/py/),
  [JavaScript](https://rootcoder007.github.io/noqtis/guides/js/) and
  [R](https://rootcoder007.github.io/noqtis/guides/r/), the capsule format,
  the C, Python, JavaScript and R API references, the command line, and
  [why post-quantum provenance now](https://rootcoder007.github.io/noqtis/explain/why/).
- Manual pages, installed with the library: `man noqtis`, `man noqtis-seal`,
  `man noqtis-inspect`, `man noqtis-timestamp`,
  `man nqsign`, `man noqtis-capsule` (sources in [man/](man/)).
- The capsule format specification:
  [docs/site/src/content/docs/spec/capsule.md](docs/site/src/content/docs/spec/capsule.md).
- Runnable examples: [docs/examples/](docs/examples/), compiled and run in CI.
- [DESIGN.md](DESIGN.md): the modules, the checks each must pass, and the
  release plan.

## Contributing, security, citing

- [CONTRIBUTING.md](CONTRIBUTING.md): build, tests, commit style and the
  rules for the code. Everyone follows the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- [SECURITY.md](SECURITY.md): report a vulnerability privately.
- [CITATION.cff](CITATION.cff): how to cite NOQTIS.

## Licence

Apache-2.0 WITH LLVM-exception. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
