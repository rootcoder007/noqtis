#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Compares the shared library's ABI with an earlier release, with
# libabigail's abidiff (needs git, cmake, a C compiler and libabigail):
#   packaging/abi.sh [base tag] [report file]
# The base is by default the newest vX.Y.Z tag before HEAD. Exit status:
# 0 when nothing incompatible changed (or the major version changed with
# it), 1 on an incompatible change within one major version, 2 when the
# libraries could not be compared.
set -eu
w=${NQWORK:-/tmp/nqabi}
base=${1:-$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' \
  HEAD^ 2>/dev/null || true)}
out=${2:-$w.txt}
if [ -z "$base" ]; then
  echo "abi.sh: no earlier release tag, nothing to compare" | tee "$out"
  exit 0
fi
rm -rf "$w"
mkdir -p "$w"
git worktree add -q --detach "$w/old" "$base"
trap 'git worktree remove --force "$w/old"' EXIT
build() {
  cmake -S "$1" -B "$2" -DNQSHARED=ON -DNQTESTS=OFF -DNQCLI=OFF -DNQMAN=OFF \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS=-Og > "$2.log" 2>&1
  cmake --build "$2" -j "${NQJOBS:-4}" >> "$2.log" 2>&1
  # the real file, not the libnoqtis.so.N links
  ls "$2"/libnoqtis.so.*.*.*
}
old=$(build "$w/old" "$w/bo")
new=$(build . "$w/bn")
set +e
abidiff --headers-dir1 "$w/old/include" --headers-dir2 include \
  "$old" "$new" > "$w/diff.txt" 2>&1
rc=$?
set -e
{
  echo "ABI of $(git describe --tags --always --match 'v[0-9]*.[0-9]*.[0-9]*' HEAD) against $base"
  echo "($(basename "$old") -> $(basename "$new"), abidiff exit $rc)"
  echo
  cat "$w/diff.txt"
} > "$out"
cat "$out"
# abidiff's exit status: 1 and 2 an error, 4 a change, 8 an incompatible one
if [ $((rc & 3)) -ne 0 ]; then
  echo "abi.sh: abidiff could not compare the libraries" >&2
  exit 2
fi
if [ $((rc & 8)) -ne 0 ]; then
  om=${base#v}
  om=${om%%.*}
  nm=$(sed -n 's/^project(noqtis VERSION \([0-9]*\)\..*/\1/p' CMakeLists.txt)
  if [ "$om" = "$nm" ]; then
    echo "abi.sh: incompatible ABI change within major version $nm" >&2
    exit 1
  fi
  echo "abi.sh: incompatible change, with a new major version ($om -> $nm)"
fi
