# Community recipes

The files each outside repository wants when NOQTIS is submitted there. They
build the published release tarball and carry its checksum, unlike the
templates one level up (`packaging/alpine`, `arch`, `void`, `wolfi`,
`gentoo`), which `packaging/pkgtest.sh` builds from the tarball of the commit
under test.

| Directory | Goes to |
|---|---|
| `alpine/testing/noqtis` | gitlab.alpinelinux.org alpine/aports |
| `aur` | aur.archlinux.org (with `.SRCINFO`) |
| `conan/recipes/noqtis` | conan-io/conan-center-index |
| `conda-forge/recipes/noqtis` | conda-forge/staged-recipes |
| `guru/dev-libs/noqtis` | Gentoo GURU |
| `nixpkgs/pkgs/by-name/no/noqtis` | NixOS/nixpkgs |
| `scoop/bucket` | a Scoop bucket |
| `vcpkg/ports/noqtis` | microsoft/vcpkg |
| `void/srcpkgs/noqtis` | void-linux/void-packages |
| `winget/manifests` | microsoft/winget-pkgs |
| `wolfi` | wolfi-dev/os |

`.github/workflows/pkgs.yml` builds and tests every one of them on its own
system when they change and when a release is published.
