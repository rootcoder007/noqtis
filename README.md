# noqtis

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

noqtis seals a folder of files (the exact data, code and outputs behind a
result) with a post-quantum signature, so that anyone can check later,
offline, that every file is unchanged, nothing was added or removed, and who
sealed it. It is one C11 library with no dependencies and a command-line
tool, implementing ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203),
HQC, SHA-2 and SHA-3, byte-identical to the NIST test vectors.

> **Status: unaudited, before its first release.** The code has not had an
> external security audit; do not rely on it for anything that matters yet.

```sh
noqtis keygen -a ML-DSA-65 -o me        # me (secret key), me.pub (public key)
noqtis seal -k me results/              # writes results/noqtis.json and noqtis.sig
noqtis check -p me.pub results/         # exit 0: every file is exactly as sealed
echo oops >> results/report.txt
noqtis check -p me.pub results/         # exit 1: "report.txt: size differs"
```

The same from C (`cc prog.c $(pkg-config --cflags --libs noqtis)`):

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

- The site (Getting started, guides, the capsule format, C API, CLI,
  security): `docs/site`, published at
  <https://rootcoder007.github.io/noqtis/> once the repository is public.
- Manual pages, installed with the library: `man noqtis`, `man noqtis-seal`,
  `man nqsign`, `man noqtis-capsule` (sources in [man/](man/)).
- The capsule format specification:
  [docs/site/src/content/docs/spec/capsule.md](docs/site/src/content/docs/spec/capsule.md).
- Runnable examples: [docs/examples/](docs/examples/), compiled and run in CI.
- [DESIGN.md](DESIGN.md): the modules, the checks each must pass, and the
  release plan. [SECURITY.md](SECURITY.md): how to report a vulnerability.

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

## Install

Now, from a clone of this repository:

- the CMake install above (Linux, macOS, Windows, FreeBSD);
- `nix build` (the `flake.nix` here);
- `docker build -t noqtis .` (Wolfi image with the library);
- the recipes in `packaging/`: Homebrew (`brew`), Arch (`PKGBUILD`), Alpine
  (`APKBUILD`), Fedora (`noqtis.spec`), Debian (`debian/`) and Wolfi
  (`melange.yaml`). `packaging/pkgtest.sh` builds one from the local tree;
  CI builds and tests every one.

After the first public release: the Homebrew tap, the container image on
GHCR, and the distribution and language packages listed in
[DESIGN.md](DESIGN.md).

## Licence

Apache-2.0 WITH LLVM-exception. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
