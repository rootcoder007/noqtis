# Community recipes

The files each outside repository wants when NOQTIS is submitted there. Here
they carry the version 0.0.0 and no checksums: `fill.py` writes them for a
release from its archives, and every release ships the result as
`noqtis-recipes-X.Y.Z.tar.gz`. The templates one level up
(`packaging/alpine`, `arch`, `void`, `wolfi`, `gentoo`) are the ones
`packaging/pkgtest.sh` builds from the tarball of the commit under test.

| Directory | Goes to |
|---|---|
| `alpine/testing/noqtis` | gitlab.alpinelinux.org alpine/aports |
| `aur` | aur.archlinux.org (with `.SRCINFO`) |
| `conan/recipes/noqtis` | conan-io/conan-center-index |
| `conda-forge/recipes/noqtis` | conda-forge/staged-recipes |
| `guru/dev-libs/noqtis` | Gentoo GURU |
| `nixpkgs/pkgs/by-name/no/noqtis` | NixOS/nixpkgs |
| `scoop/bucket` | a Scoop bucket |
| `t2/package/security/noqtis` | T2 SDE (svn.exactcode.de t2/trunk) |
| `vcpkg/ports/noqtis` | microsoft/vcpkg |
| `void/srcpkgs/noqtis` | void-linux/void-packages |
| `winget/manifests` | microsoft/winget-pkgs |
| `wolfi` | wolfi-dev/os |

`.github/workflows/pkgs.yml` builds and tests every one of them on its own
system when they change and when a release is published.
