#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
# Builds the CRAN tarball of the R package: a copy of the tracked files of
# bindings/r with the guides of vignettes/ combined into five
# (tools/cran_merge_vignettes.py), built with NOT_CRAN set so the five are
# rendered in full into the tarball; CRAN's own check then re-builds only
# their first chunk. The size is printed at the end.
#   tools/cran_build.sh [output directory, default /tmp/cran]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)
pkg=$(sed -n "s/^Package: //p" "$here/DESCRIPTION")
out=${1:-/tmp/cran}
rm -rf "${out:?}/${pkg:?}" "${out:?}/.x"
mkdir -p "$out/.x"
# only what git tracks: a stray log or object file never reaches the tarball
git -C "$top" archive HEAD bindings/r | tar -xf - -C "$out/.x"
mv "$out/.x/bindings/r" "$out/$pkg"
rm -rf "$out/.x"
cd "$out/$pkg"
python3 "$here/tools/cran_merge_vignettes.py"
cd "$out"
NOT_CRAN=true R CMD build "$pkg" > "$out/build_$pkg.log" 2>&1 || { tail -20 "$out/build_$pkg.log" >&2; exit 1; }
if tar tzf "$out"/${pkg}_*.tar.gz | grep -E "[.](o|so|dll|gcno|gcda|gcov)$"; then
  echo "cran_build.sh: build artifacts in the tarball (above)" >&2
  exit 1
fi
ls -la "$out"/${pkg}_*.tar.gz | awk "{printf \"%s %.2f MiB\n\", \$9, \$5/1048576}"
tar tzf "$out"/${pkg}_*.tar.gz | grep -c "inst/doc/.*[.]html$" | sed "s/^/vignettes in the tarball: /"
