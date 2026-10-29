#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Compiles and runs the C examples of the manual pages and the site
# against an installed noqtis. Usage: c.sh <install prefix>
set -eu
P=$(cd "$1" && pwd)
D=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PKG_CONFIG_PATH="$P/lib/pkgconfig:$P/lib64/pkgconfig:$(ls -d "$P"/lib/*/pkgconfig 2> /dev/null | tr '\n' ':')${PKG_CONFIG_PATH:-}"
export PKG_CONFIG_PATH
FLAGS="-std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror"
for e in sign kem hash seal readme; do
  # shellcheck disable=SC2046
  ${CC:-cc} $FLAGS -o "$T/$e" "$D/$e.c" $(pkg-config --cflags --libs noqtis)
done
"$T/sign"
"$T/kem"
"$T/hash"
mkdir -p "$T/cap/data"
printf 'a,b\n' > "$T/cap/data/in.csv"
"$T/seal" "$T/cap" | tail -1
test -s "$T/cap/noqtis.json"
mkdir -p "$T/r"
printf "x\n" > "$T/r/x.txt"
"$T/readme" "$T/r"
echo "c examples: ok"
