#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Builds dist/noqtis.wasm from the C sources in ../../src with wasi-sdk
# (wasm32-wasip1, the toolchain and version the WASI job of ci.yml tests
# the library with), as a reactor: no main and no JavaScript runtime of its
# own. lib/wasm.js instantiates it and lib/wasi.js gives it the few WASI
# functions it calls: randomness from crypto.getRandomValues, the time,
# and an in-memory folder for capsules. Run with WASI_SDK_PATH set to an
# unpacked wasi-sdk 34 (npm.yml downloads it and checks its SHA-256).
# The same sources and wasi-sdk give the same bytes.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out="$here/dist"
want=34

sdk=${WASI_SDK_PATH:?build.sh: set WASI_SDK_PATH to wasi-sdk $want}
# wasi-sdk's VERSION file starts with its version (34.0)
ver=$(sed -n 1p "$sdk/VERSION" 2>/dev/null | cut -d. -f1)
if [ "$ver" != "$want" ] && [ -z "${NQWASIANY:-}" ]; then
  echo "build.sh: wasi-sdk ${ver:-?} found, $want wanted (NQWASIANY=1 to override)" >&2
  exit 2
fi

fns='nqerr nqver nqselftest nqwipe nqrand nqhlen nqhash nqhmac
nqssize nqsname nqskg nqskgd nqsign nqsignd nqvrfy
nqksize nqkname nqkkg nqkkgd nqenc nqencd nqdec
nqseal nqseal2 nqcapid nqchkt nqchkx nqchkp nqprove nqfiles
nqkstmt nqdsse nqdssevrfy nqcard nqcardvrfy nqrepn nqrepi nqrepfree
malloc free setenv unsetenv'
exp=$(printf ' -Wl,--export=%s' $fns)

mkdir -p "$out"
rm -f "$out/noqtis.js" "$out/noqtis.wasm"

# every module folder, as the CMake glob takes them
srcs=$(ls "$root"/src/*/*.c)

# 8 MiB of stack, as the WASI CMake build gives its programs: masked
# ML-DSA and HQC need more than wasm-ld's default 64 KiB
# shellcheck disable=SC2086
"$sdk/bin/clang" --target=wasm32-wasip1 --sysroot="$sdk/share/wasi-sysroot" \
  -mexec-model=reactor -std=c11 -O3 -flto \
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes \
  -Wcast-qual -Wvla -Wmissing-prototypes -Werror \
  -ffile-prefix-map="$root"=. \
  -DNQBUILD -I"$root/include" -I"$root/src" \
  $srcs \
  -Wl,-z,stack-size=8388608 -Wl,--strip-debug $exp \
  -o "$out/noqtis.wasm"

cp "$root/LICENSE" "$root/NOTICE" "$here/"
ls -l "$out"
