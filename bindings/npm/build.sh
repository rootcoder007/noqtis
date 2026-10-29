#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Builds dist/noqtis.js (ES module glue) and dist/noqtis.wasm from the C
# sources in ../../src with emscripten. Run with emcc on PATH (emsdk
# 6.0.12, the version npm.yml pins). The library has no network code; the
# in-memory file system (MEMFS) is there only for capsules, which the
# wrapper fills from a map of files and empties after each call.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out="$here/dist"
want=6.0.12

ver=$(emcc --version | head -n 1 |
  grep -o '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' | head -n 1)
if [ "$ver" != "$want" ] && [ -z "${NQEMANY:-}" ]; then
  echo "build.sh: emcc $ver found, $want wanted (NQEMANY=1 to override)" >&2
  exit 2
fi

fns='nqerr nqver nqwipe nqrand nqhlen nqhash nqhmac
nqssize nqsname nqskg nqskgd nqsign nqsignd nqvrfy
nqksize nqkname nqkkg nqkkgd nqenc nqencd nqdec
nqseal nqchkt nqrepn nqrepi nqrepfree
malloc free setenv unsetenv'
inc=wasmBinary,locateFile,instantiateWasm,print,printErr
exp=$(printf '%s\n' $fns | sed 's/^/_/' | paste -sd, -)

mkdir -p "$out"
rm -f "$out/noqtis.js" "$out/noqtis.wasm"

# every module folder, as the CMake glob takes them
srcs=$(ls "$root"/src/*/*.c)

# shellcheck disable=SC2086
emcc -std=c11 -O3 -flto \
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes \
  -Wcast-qual -Wvla -Wmissing-prototypes -Werror \
  -DNQBUILD -I"$root/include" -I"$root/src" \
  $srcs \
  --js-library "$here/src/rand.js" \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=nqload \
  -sENVIRONMENT=web,webview,worker,node \
  -sFILESYSTEM=1 -sFORCE_FILESYSTEM=1 \
  -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=4MB -sSTACK_OVERFLOW_CHECK=1 \
  -sINCOMING_MODULE_JS_API="$inc" \
  -sEXPORTED_FUNCTIONS="$exp" \
  -sEXPORTED_RUNTIME_METHODS=FS,HEAPU8,HEAPU32,UTF8ToString,stringToNewUTF8 \
  -sDYNAMIC_EXECUTION=0 -sTEXTDECODER=2 \
  -o "$out/noqtis.js"

cp "$root/LICENSE" "$root/NOTICE" "$here/"
ls -l "$out"
