#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds one release archive from the source tree it is run in (the
# repository root), reproducibly: the same commit gives the same bytes.
#
#   packaging/dist.sh <target> <out dir>      prints the archive's path
#
# Targets (one per release archive):
#   linux-x86_64 linux-arm64     static library, statically linked noqtis
#   linux-x86_64-shared linux-arm64-shared
#                                shared library, noqtis linked against it
#   macos-arm64 macos-x86_64     static library
#   windows-x86_64 windows-arm64 static library, MSVC (.zip)
#
# The archive noqtis-<version>-<target>.tar.gz (.zip on Windows) holds one
# top directory with bin/noqtis, lib/ (library, noqtis.pc, the CMake
# package), include/noqtis.h, share/man, LICENSE and NOTICE (also in
# share/doc/noqtis).
#
# Reproducible: SOURCE_DATE_EPOCH is the commit time (git log) unless set;
# source and build paths are mapped out of the objects
# (-ffile-prefix-map); macOS archives get no member times (ZERO_AR_DATE),
# MSVC objects and binaries no time stamps (-Brepro); pack.py writes a
# sorted archive with fixed times, owners and modes.
#
# Environment: NQDIST work dir (default: a new temporary dir), NQJOBS
# parallel build jobs (2), PY the Python to run pack.py with (python3).
set -eu

[ $# -eq 2 ] || { echo "usage: packaging/dist.sh <target> <out dir>" >&2; exit 2; }
t=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
src=$(pwd)
[ -f "$src/CMakeLists.txt" ] && [ -f "$src/include/noqtis.h" ] || {
  echo "dist.sh: run it from the noqtis source root" >&2; exit 2; }
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
[ -n "$v" ] || { echo "dist.sh: no version in CMakeLists.txt" >&2; exit 1; }
py=${PY:-python3}
j=${NQJOBS:-2}

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -c safe.directory='*' log -1 --format=%ct)
fi
export SOURCE_DATE_EPOCH

case $t in
  *-shared) kind=shared; base=${t%-shared} ;;
  *) kind=static; base=$t ;;
esac
os=${base%%-*}
arch=${base#*-}
case $os-$arch-$kind in
  linux-x86_64-*|linux-arm64-*|macos-arm64-static|macos-x86_64-static) ;;
  windows-x86_64-static|windows-arm64-static) ;;
  *) echo "dist.sh: unknown target $t" >&2; exit 2 ;;
esac

# the build host's CPU, as the target names spell it
host=$(uname -m)
case $host in
  x86_64|amd64|AMD64) host=x86_64 ;;
  aarch64|arm64|ARM64) host=arm64 ;;
esac
native=1
[ "$host" = "$arch" ] || native=0

w=${NQDIST:-$(mktemp -d)}
b=$w/b
n=noqtis-$v-$t
st=$w/st/$n
rm -rf "$b" "$w/st"
mkdir -p "$b" "$st"

set -- -DCMAKE_BUILD_TYPE=Release -DNQTESTS=OFF -DCMAKE_INSTALL_LIBDIR=lib
[ "$kind" = shared ] && set -- "$@" -DNQSHARED=ON
strip=--strip
ext=tar.gz
case $os in
  linux)
    [ "$native" = 1 ] || { echo "dist.sh: $t needs a $arch host" >&2; exit 2; }
    CFLAGS="${CFLAGS:-} -ffile-prefix-map=$src=. -ffile-prefix-map=$b=build"
    if [ "$kind" = static ]; then
      # one binary that runs on any Linux of its CPU, with no libc to match
      set -- "$@" -DCMAKE_EXE_LINKER_FLAGS=-static
    else
      # bin/noqtis finds lib/libnoqtis.so.0 wherever the tree is unpacked;
      # linked with that RPATH from the start, so that install does not
      # rewrite it and the build directory's path (whose length varies)
      # never reaches the binary or its build ID
      # shellcheck disable=SC2016
      set -- "$@" '-DCMAKE_INSTALL_RPATH=$ORIGIN/../lib' \
        -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON
    fi
    ;;
  macos)
    CFLAGS="${CFLAGS:-} -ffile-prefix-map=$src=. -ffile-prefix-map=$b=build"
    ZERO_AR_DATE=1
    export ZERO_AR_DATE
    set -- "$@" -DCMAKE_OSX_ARCHITECTURES="$arch" \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
    ;;
  windows)
    # -Brepro, not /Brepro: Git Bash would turn /Brepro into a path
    CFLAGS="${CFLAGS:-} -Brepro"
    LDFLAGS="${LDFLAGS:-} -Brepro"
    export LDFLAGS
    case $arch in
      x86_64) set -- "$@" -A x64 ;;
      arm64) set -- "$@" -A ARM64 ;;
    esac
    set -- "$@" -DCMAKE_STATIC_LINKER_FLAGS=-Brepro
    strip=
    ext=zip
    ;;
esac
export CFLAGS

echo "== $n (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)" >&2
cmake -S "$src" -B "$b" "$@" >&2
cmake --build "$b" --config Release --parallel "$j" >&2
# shellcheck disable=SC2086
cmake --install "$b" --config Release --prefix "$st" $strip >&2

for f in LICENSE NOTICE; do
  cp "$src/$f" "$st/$f"
  mkdir -p "$st/share/doc/noqtis"
  cp "$src/$f" "$st/share/doc/noqtis/$f"
done

exe=$st/bin/noqtis
[ "$os" = windows ] && exe=$exe.exe
[ -f "$exe" ] || { echo "dist.sh: no $exe" >&2; exit 1; }
if [ "$native" = 1 ]; then
  "$exe" version >&2
fi
if [ "$os-$kind" = linux-static ] && command -v readelf >/dev/null 2>&1; then
  if readelf -d "$exe" | grep -q NEEDED; then
    echo "dist.sh: $exe is not statically linked" >&2
    exit 1
  fi
fi

"$py" "$src/packaging/pack.py" "$w/st" "$out/$n.$ext"
[ -n "${NQDIST:-}" ] || rm -rf "$w"
echo "$out/$n.$ext"
