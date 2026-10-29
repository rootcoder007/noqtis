---
title: Install
description: Install the NOQTIS library and command-line tool from source, a package manager, a container or a language package.
---

NOQTIS is one C11 library (`libnoqtis`, header `noqtis.h`) and one
command-line tool (`noqtis`). Every channel below gives you both, or a
language binding built on the library.

:::note[Before the first release]
The repository has not yet published its first tagged release. Channels
marked **coming with v0.1.0** open on that day; until then, build from
source (below). Version numbers on this site come from the release you
install, never from this page.
:::

## From source (works today)

You need a C11 compiler (GCC, Clang, MSVC, MinGW-w64) and CMake.

```sh
git clone https://github.com/rootcoder007/noqtis.git
cd noqtis
cmake -S . -B build                   # static library; -DNQSHARED=ON for shared
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ~/.local
```

This installs `bin/noqtis`, the library, `include/noqtis.h`, `noqtis.pc`, a
CMake package and the manual pages (`man noqtis`, `man nqsign`). Options:

| Option | Default | Effect |
|---|---|---|
| `-DNQSHARED=ON` | off | a shared library (`libnoqtis.so.0`, `libnoqtis.0.dylib`, `noqtis-0.dll`) |
| `-DNQCLI=OFF` | on | skip the command-line tool |
| `-DNQTESTS=OFF` | on | skip the tests |
| `-DNQMAN=OFF` | on | do not install the manual pages |
| `-DNQSAN=ON` | off | AddressSanitizer and UBSan, for development |
| `-DNQWERROR=OFF` | on | do not treat warnings as errors |

Build against the install with pkg-config or CMake:

```sh
cc prog.c $(pkg-config --cflags --libs noqtis)
```

```cmake
find_package(noqtis CONFIG REQUIRED)
target_link_libraries(prog PRIVATE noqtis::noqtis)
```

### Nix and containers from the source tree

```sh
nix build                    # the flake.nix in the repository
docker build -t noqtis .     # Wolfi image: the noqtis command and the library
docker run --rm -v "$PWD:/w" -w /w noqtis noqtis check results
```

The recipes in `packaging/` (Homebrew, Arch `PKGBUILD`, Alpine `APKBUILD`,
Fedora `noqtis.spec`, Debian `debian/`, Wolfi `melange.yaml`) build from the
local tree with `packaging/pkgtest.sh`; CI builds and tests each one on every
push.

## Package managers

| Channel | Command | Status |
|---|---|---|
| Homebrew (macOS, Linux) | `brew install rootcoder007/morie/noqtis` | coming with v0.1.0 (the formula is in `packaging/brew` and tested in CI) |
| curl / shell | `curl -fsSL https://github.com/rootcoder007/noqtis/releases/latest/download/install.sh \| sh` | coming with v0.1.0 |
| PowerShell (Windows) | `irm https://github.com/rootcoder007/noqtis/releases/latest/download/install.ps1 \| iex` | coming with v0.1.0 |
| Docker / OCI | `docker run --rm ghcr.io/rootcoder007/noqtis` | coming with v0.1.0 |
| npm (Node, Deno, Bun, browsers) | `npm install noqtis` | coming with v0.1.0 (WebAssembly, nothing to compile) |
| PyPI | `pip install noqtis` | coming with v0.1.0 (wheels for every OS and CPU) |
| CRAN (R) | `install.packages("noqtis")` | after CRAN's review of v0.1.0 |
| Scoop, winget, Chocolatey | `scoop install noqtis`, `winget install noqtis` | coming with v0.1.0 (winget and Chocolatey after their moderation) |
| Arch User Repository | `yay -S noqtis` | coming with v0.1.0 |
| Nixpkgs, conda-forge | `nix-env -iA nixpkgs.noqtis`, `conda install -c conda-forge noqtis` | first weeks after v0.1.0 (their review) |
| vcpkg, Conan, Alpine, Wolfi | `vcpkg install noqtis`, ... | first weeks after v0.1.0 (their review) |
| Debian, Ubuntu, Fedora, EPEL, homebrew-core | `apt install noqtis`, `dnf install noqtis` | months after v0.1.0 (sponsorship and review) |

The `install.sh` and `install.ps1` scripts pick the archive for the machine,
check its SHA-256 and signature before anything runs, and install into
`~/.local` or a prefix you choose. Every release archive comes with a
SHA-256 file, Sigstore and SSH signatures, an SPDX SBOM and SLSA build
provenance, and is reproducible: CI builds each tag twice and compares the
archives byte for byte.

## Check what you installed

```sh
noqtis version
noqtis algs
man noqtis
```
