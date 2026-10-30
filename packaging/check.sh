#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The build check the Linux distribution and macOS jobs run, from the
# source root, once the compiler, cmake, make and pkg-config are in:
# a static build with every test, its install and the consumer program,
# then a shared build, its install, the consumer program again, and a check
# that the shared library exports only what noqtis.h declares.
#   packaging/check.sh [work dir]
set -eu
w=${1:-/tmp/nqchk}
j=${NQJOBS:-4}
rm -rf "$w"
mkdir -p "$w"

echo "== static build and tests"
cmake -S . -B "$w/st" -DCMAKE_BUILD_TYPE=Release
cmake --build "$w/st" -j "$j"
ctest --test-dir "$w/st" --output-on-failure -j "$j"
cmake --install "$w/st" --prefix "$w/pst"
tests/consumer/run.sh "$w/pst" "$w/ust"

echo "== shared build"
cmake -S . -B "$w/sh" -DCMAKE_BUILD_TYPE=Release -DNQSHARED=ON \
  -DNQTESTS=OFF
cmake --build "$w/sh" -j "$j"
cmake --install "$w/sh" --prefix "$w/psh"
tests/consumer/run.sh "$w/psh" "$w/ush"

# the shared library exports only what noqtis.h declares
lib=
# (OpenBSD names it libnoqtis.so.<major>.<minor>, with no .so.0 link)
for f in "$w"/psh/lib*/libnoqtis.so.0 "$w"/psh/lib/*/libnoqtis.so.0 \
         "$w"/psh/lib/libnoqtis.so.0.* "$w"/psh/lib/libnoqtis.0.dylib; do
  if [ -f "$f" ]; then lib=$f; break; fi
done
[ -n "$lib" ] || { echo "no shared libnoqtis installed" >&2; exit 1; }
if command -v nm >/dev/null 2>&1; then
  echo "== exported symbols"
  case $lib in
  *.dylib) syms=$(nm -gU "$lib" | awk '{print $3}' | sed 's/^_//') ;;
  # ELF names carry their version (nqsign@@NOQTIS_0): compare the name.
  # Defined globals only (T, D, B, R; an undefined one is U), so no
  # --defined-only, which OpenBSD's nm lacks; nm -g where -D fails
  *) syms=$( (nm -D "$lib" 2>/dev/null || nm -g "$lib") |
            awk '$2 ~ /^[TDBR]$/ {print $3}' | sed 's/@.*//') ;;
  esac
  n=0
  for s in $syms; do
    n=$((n + 1))
    if ! grep -q "[ *]$s(" include/noqtis.h; then
      echo "exports $s, which noqtis.h does not declare" >&2
      exit 1
    fi
  done
  [ "$n" -gt 0 ] || { echo "exports nothing" >&2; exit 1; }
  echo "$n symbols, all declared in noqtis.h"
fi
echo "== ok"
