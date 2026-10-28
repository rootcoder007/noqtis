#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds and runs use.c against an installed noqtis twice: once through
# pkg-config, once through find_package(noqtis CONFIG).
#   tests/consumer/run.sh <prefix> [work dir]
# <prefix> is where noqtis was installed (/usr for a distro package).
set -eu
prefix=$1
here=$(cd "$(dirname "$0")" && pwd)
work=${2:-${TMPDIR:-/tmp}/nquse.$$}
cc=${CC:-cc}
mkdir -p "$work"

libdir=
for d in "$prefix/lib64" "$prefix/lib" "$prefix"/lib/*-linux-gnu*; do
  if [ -f "$d/pkgconfig/noqtis.pc" ]; then libdir=$d; break; fi
done
if [ -z "$libdir" ]; then
  echo "run.sh: no noqtis.pc under $prefix" >&2
  exit 1
fi
PKG_CONFIG_PATH=$libdir/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
export PKG_CONFIG_PATH
LD_LIBRARY_PATH=$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
DYLD_LIBRARY_PATH=$libdir${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}
export LD_LIBRARY_PATH DYLD_LIBRARY_PATH

pc=${PKG_CONFIG:-pkg-config}
command -v "$pc" >/dev/null 2>&1 || pc=pkgconf
if command -v "$pc" >/dev/null 2>&1; then
  echo "== pkg-config: noqtis $("$pc" --modversion noqtis)"
  # --static adds Libs.private; harmless for a shared install
  # shellcheck disable=SC2046
  "$cc" -std=c11 -Wall -Wextra -Werror -o "$work/usepc" "$here/use.c" \
    $("$pc" --cflags noqtis) $("$pc" --static --libs noqtis)
  "$work/usepc"
elif [ -n "${NQNEEDPC:-}" ]; then
  echo "run.sh: no pkg-config" >&2
  exit 1
else
  echo "== pkg-config: not installed, skipped"
fi

echo "== find_package(noqtis CONFIG)"
cmake -S "$here" -B "$work/cm" -DCMAKE_PREFIX_PATH="$prefix" >/dev/null
cmake --build "$work/cm" >/dev/null
"$work/cm/use"
