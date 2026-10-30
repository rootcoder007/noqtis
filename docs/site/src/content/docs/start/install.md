---
title: Install
description: Install the NOQTIS library and command-line tool from source, a package manager, a container or a language package.
---

NOQTIS is one C11 library (`libnoqtis`, header `noqtis.h`) and one
command-line tool (`noqtis`). Every channel below gives you both, or a
language binding built on the library.

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
CMake package, the manual pages (`man noqtis`, `man nqsign`) and shell
completions for bash, zsh and fish (under `share/`, where each shell looks;
not on Windows). Options:

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
Fedora `noqtis.spec`, Debian `debian/`, Wolfi `melange.yaml`, a Gentoo
ebuild for an overlay in `packaging/gentoo`, a Void Linux `xbps-src`
template in `packaging/void`) build from the
local tree with `packaging/pkgtest.sh`; CI builds and tests each one on every
push.

## Package managers

| Channel | Command | Status |
|---|---|---|
| Homebrew (macOS, Linux) | `brew install rootcoder007/morie/noqtis` | available (the formula is in `packaging/brew` and tested in CI) |
| curl / shell | `curl -fsSL https://github.com/rootcoder007/noqtis/releases/latest/download/install.sh \| sh` | available (see [Release archives](#release-archives)) |
| PowerShell (Windows) | `irm https://github.com/rootcoder007/noqtis/releases/latest/download/install.ps1 \| iex` | available |
| Docker / OCI | `docker run --rm ghcr.io/rootcoder007/noqtis` | available |
| npm (Node, Deno, Bun, browsers) | `npm install noqtis` | available (WebAssembly, nothing to compile) |
| PyPI | `pip install noqtis` | available (wheels for every OS and CPU) |
| r-universe (R) | `install.packages("noqtis", repos = c("https://rootcoder007.r-universe.dev", "https://cloud.r-project.org"))` | available (built from each release, binaries for Windows, macOS and Linux) |
| CRAN (R) | `install.packages("noqtis")` | after CRAN's review of the first release |
| Maven Central (Java 22+) | `io.github.rootcoder007:noqtis` | available (the jar carries the library for Linux, macOS and Windows, x86-64 and arm64) |
| crates.io (Rust) | `cargo add noqtis` | available |
| openSUSE Build Service | RPMs and debs for openSUSE, Fedora, Debian, Ubuntu | available (project `home:rootcoder007/noqtis`) |
| Fedora COPR | `dnf copr enable rootcoder007/noqtis` | available (Fedora and EPEL) |
| Go | `go get github.com/rootcoder007/noqtis/bindings/go@latest` | available (cgo; the module proxy has each release) |
| Scoop, winget, Chocolatey | `scoop install noqtis`, `winget install noqtis` | after the first release, once each accepts it (winget and Chocolatey are moderated) |
| Arch User Repository | `yay -S noqtis` | after the first release, once the package is uploaded |
| Nixpkgs, conda-forge | `nix-env -iA nixpkgs.noqtis`, `conda install -c conda-forge noqtis` | first weeks after the first release (their review) |
| vcpkg, Conan, Alpine, Wolfi | `vcpkg install noqtis`, ... | first weeks after the first release (their review) |
| Debian, Ubuntu, Fedora, EPEL, homebrew-core | `apt install noqtis`, `dnf install noqtis` | months after the first release (sponsorship and review) |

## Release archives

Every release carries one archive per platform, built by the release
workflow from the tagged commit:

| Archive `noqtis-<version>-...` | For | Library |
|---|---|---|
| `linux-x86_64.tar.gz`, `linux-arm64.tar.gz` | any Linux distribution | static; `noqtis` is statically linked, so it needs no matching C library |
| `linux-x86_64-shared.tar.gz`, `linux-arm64-shared.tar.gz` | Linux | shared (`libnoqtis.so.0`); `noqtis` finds it in `../lib` |
| `macos-arm64.tar.gz`, `macos-x86_64.tar.gz` | macOS 11 and later | static |
| `windows-x86_64.zip`, `windows-arm64.zip` | Windows (MSVC) | static (`noqtis.lib`) |

Each holds `bin/noqtis`, `lib/` (the library, `pkgconfig/noqtis.pc`,
`cmake/noqtis/`), `include/noqtis.h`, `share/man/`, `LICENSE` and `NOTICE`.
It works wherever it is unpacked: `noqtis.pc` and the CMake package find
their prefix from their own place. Beside the archives are `SHA256SUMS`
(every file of the release), its Sigstore bundle `SHA256SUMS.sigstore.json`,
its SSH signature `SHA256SUMS.sig`, the SPDX SBOM `noqtis-<version>.spdx.json`,
the SLSA provenance `noqtis-<version>.intoto.jsonl`, the side-channel
results `noqtis-<version>-sidechannel.tar.gz` (dudect and the simulated
TVLA on the release build), the ABI report against the previous release
`noqtis-<version>-abi.txt`, `install.sh` and `install.ps1`.

### install.sh (Linux, macOS)

```sh
curl -fsSL https://github.com/rootcoder007/noqtis/releases/latest/download/install.sh | sh
```

Or download it, read it, then run it:

```sh
curl -fsSLO https://github.com/rootcoder007/noqtis/releases/latest/download/install.sh
sh install.sh --prefix ~/.local     # --version X.Y.Z, --shared (Linux)
```

It picks the archive for the machine, downloads `SHA256SUMS`, checks its
SSH signature (`SHA256SUMS.sig`) with `ssh-keygen` against the release
key in [SECURITY.md](https://github.com/rootcoder007/noqtis/blob/main/SECURITY.md),
and its Sigstore signature when `cosign` is installed, so it knows who
published the release and not only that the download is whole. Without
`ssh-keygen` (and without cosign) it stops; `NOQTIS_VERIFY=0` installs
anyway, and says so. It then checks the archive's SHA-256 against
`SHA256SUMS`, checks that no
path in the archive leaves its top directory, and only then copies `bin/`,
`include/`, `lib/` and `share/` into the prefix. Any failure stops it with
nothing installed. It never calls `sudo`: if the prefix is not writable it
says so and stops. The prefix defaults to `~/.local` (`$NOQTIS_PREFIX`);
`NOQTIS_VERSION` pins a release; `NOQTIS_COSIGN=1` refuses to install
without the Sigstore check. Plain `http` is accepted only for
`http://127.0.0.1` or `http://localhost` (for testing), with no
redirects. In latest-version mode the version comes from the signed
`SHA256SUMS`, so an older signed release could be served in place of the
newest: pin `NOQTIS_VERSION` when that matters.

### install.ps1 (Windows)

```powershell
irm https://github.com/rootcoder007/noqtis/releases/latest/download/install.ps1 | iex
```

The same checks and the same variables (`NOQTIS_PREFIX`, default
`$HOME\.local`; `NOQTIS_VERSION`; `NOQTIS_COSIGN`; `NOQTIS_VERIFY`), for
the x64 or ARM64
archive. It needs no administrator rights and does not change `PATH`; it
prints the command that adds `bin` to your user `PATH`.

## Verify a release by hand

Set `V` to the release you downloaded (without the leading `v`) and fetch
the archive with the files that vouch for it:

```sh
V=...                                # the release, for example from its page
f=noqtis-$V-linux-x86_64.tar.gz      # your archive
base=https://github.com/rootcoder007/noqtis/releases/download/v$V
curl -fsSL --remote-name-all "$base/$f" "$base/SHA256SUMS" \
  "$base/SHA256SUMS.sigstore.json" "$base/SHA256SUMS.sig" \
  "$base/noqtis-$V.intoto.jsonl"
```

**SHA-256.** The archive must match its line in `SHA256SUMS`:

```sh
grep " $f\$" SHA256SUMS | sha256sum -c -        # macOS: shasum -a 256 -c -
```

**Sigstore.** `SHA256SUMS` is signed without a long-lived key: the
signing certificate names the release workflow of this repository at that
tag, and the signature is in the public Rekor transparency log. With
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/rootcoder007/noqtis/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

**SSH signature.** `SHA256SUMS.sig` is made with the project's release key
(namespace `file`). Put the published release key in an allowed-signers
file under a name of your choice, then:

```sh
echo "noqtis <the release public key>" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I noqtis -n file \
  -s SHA256SUMS.sig < SHA256SUMS
```

The release key and its fingerprint are published in the repository's
[SECURITY.md](https://github.com/rootcoder007/noqtis/blob/main/SECURITY.md#release-signing-key).

**SLSA provenance.** `noqtis-<version>.intoto.jsonl` records which
workflow built which file from which commit. With
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact "$f" --provenance-path "noqtis-$V.intoto.jsonl" \
  --source-uri github.com/rootcoder007/noqtis --source-tag "v$V"
```

**SBOM.** `noqtis-<version>.spdx.json` (SPDX 2.3) lists the source
package and every archive with its SHA-256. noqtis has no third-party
code, so there is nothing else in it.

**Reproducible builds.** The archives are built with `SOURCE_DATE_EPOCH`
set to the tag's commit time, source paths mapped out of the objects, and
entries sorted with fixed times, owners and modes. For each release, CI
builds the four Linux archives a second time on fresh runners, from a
fresh checkout in another directory, and the release stops unless they
are byte-identical. To rebuild one yourself, on Ubuntu 24.04 (the release
runner's compiler) from the tag:

```sh
git clone --branch "v$V" https://github.com/rootcoder007/noqtis.git
cd noqtis
packaging/dist.sh linux-x86_64 out
sha256sum out/noqtis-*.tar.gz                   # compare with SHA256SUMS
```

## Check what you installed

```sh
noqtis version
noqtis algs
man noqtis
```
