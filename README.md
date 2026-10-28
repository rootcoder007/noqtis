# noqtis

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

A standalone C11 library and command-line tool that records the exact files a
result came from, signs that record with post-quantum signatures (ML-DSA,
SLH-DSA) and timestamps it, so anyone can check later that nothing changed.

> **Status: under construction and unaudited.** Do not rely on it yet.

See [DESIGN.md](DESIGN.md) for the modules, the capsule format and the checks
each module must pass.

## Build

```sh
cmake -S . -B build                  # static library; -DNQSHARED=ON for shared
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ~/.local
```

`-DNQTESTS=OFF` skips the tests. The install gives `libnoqtis`, `noqtis.h`,
`noqtis.pc` and a CMake package, so other projects build against it with
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
