#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Copies the noqtis C library (../../src/*/ and ../../include/noqtis.h)
# and the licence files into this crate, so that `cargo package` ships a
# crate that builds on its own. build.rs prefers ../../src when it is
# there; vendor/ is ignored by git. Rerun after any change to the library.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
top=$(cd "$here/../.." && pwd)
test -f "$top/include/noqtis.h" || {
  echo "vendor.sh: $top/include/noqtis.h not found" >&2
  exit 2
}
rm -rf "$here/vendor"
mkdir -p "$here/vendor/src" "$here/vendor/include"
n=0
for d in "$top"/src/*/; do
  m=$(basename "$d")
  mkdir "$here/vendor/src/$m"
  for f in "$d"*.c "$d"*.h; do
    test -f "$f" || continue
    cp "$f" "$here/vendor/src/$m/"
    n=$((n + 1))
  done
done
cp "$top/include/noqtis.h" "$here/vendor/include/"
cp "$top/LICENSE" "$top/NOTICE" "$here/"
echo "vendor.sh: copied $n files and include/noqtis.h"
