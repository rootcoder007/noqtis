#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Runs the CBMC proofs of the parsers that read untrusted bytes: the DER
# reader, the base64 decoder and the JSON reader (see README.md for what
# each shows and its bounds). CBMC checks every array access, pointer,
# division, shift and signed and unsigned overflow, and (json) that
# nothing leaks; --unwinding-assertions fails a proof whose loops need
# more unwinding than given, so a bound too small never passes quietly.
# Exit 0 when every proof holds.
#   proofs/cbmc/run.sh [<source root>]
set -eu
top=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
here=$top/proofs/cbmc
out=${TMPDIR:-/tmp}
command -v cbmc > /dev/null || {
  echo "run.sh: cbmc is needed"
  exit 2
}
echo "cbmc $(cbmc --version)"
checks="--bounds-check --pointer-check --div-by-zero-check
  --signed-overflow-check --unsigned-overflow-check
  --pointer-overflow-check --undefined-shift-check --unwinding-assertions"
fails=0
# prove <name> <source or -> <unwind> <unwindset> [cbmc flags...]
prove() {
  name=$1
  src=$2
  unw=$3
  set=$4
  shift 4
  s=$(date +%s)
  if [ "$src" = - ]; then
    src=
  else
    src=$top/$src
  fi
  # shellcheck disable=SC2086 # the flags and $src are words
  if cbmc $checks --unwind "$unw" --unwindset "$set" -I "$top/include" \
    -I "$top/src" "$@" "$here/$name.c" $src \
    > "$out/cbmc-$name.log" 2>&1; then
    echo "proof $name: VERIFICATION SUCCESSFUL ($(($(date +%s) - s)) s)"
  else
    echo "proof $name: FAILED ($(($(date +%s) - s)) s)"
    grep -E "FAILURE|VERIFICATION|rror" "$out/cbmc-$name.log" | head -20
    fails=$((fails + 1))
  fi
}
hdr="nqdhdr.0:4,nqdhdr.1:5"
# nqdhdr: every length
prove hdr src/der/der.c 6 "$hdr"
# the cursor (nqdinit, nqdnext, nqddown): N = 6 bytes, every level
prove der src/der/der.c 4 "walk.0:4,$hdr" -DN=6 -DLEVELS=2 \
  --slice-formula
# the tree check (nqdone, nqdwalk, nqdprim): N = 6 bytes
prove dwalk src/der/der.c 7 "strchr.0:14,$hdr" -DN=6 \
  --slice-formula
# nqb64d: N = 32 characters into up to M = 24 bytes
prove b64 src/cap/misc.c 9 "nqb64d.0:9" -DN=32 -DM=24
# the JSON lexers: N = 4 bytes
js="skipws.0:5,rdstr.0:5,rdstr.1:5,rdnum.0:5,rdnum.1:5,rdnum.2:5"
js="$js,rd4hex.0:5,memcmp.0:6,strlen.0:6,nqjfree.0:1"
prove jlex - 2 "$js" -DN=4 --memory-leak-check --slice-formula
# nqjparse and nqjfree: N = 1 byte; --slice-formula leaves out what
# no check depends on, without which even this does not fit in 6 GB
dk="dupkeys.0:1,dupkeys.1:1,dupkeys.2:1,dupkeys.3:1,dupkeys.4:1"
dk="$dk,dupkeys.5:1,dupkeys.6:1"
js="skipws.0:2,rdstr.0:2,rdstr.1:2,rdnum.0:2,rdnum.1:2,rdnum.2:2"
js="$js,rd4hex.0:5,memcmp.0:6,strlen.0:6,nqjparse.1:2"
js="$js,nqjparse.0:2,nqjfree.0:1,$dk"
prove json src/core/json.c 2 "$js" -DN=1 --memory-leak-check \
  --slice-formula
# the negative controls: a parser told of one byte more than it was
# given must fail, in both input layouts, or the proofs show nothing
# refute <name> <unwind> <unwindset> [cbmc flags...]
refute() {
  name=$1
  unw=$2
  set=$3
  shift 3
  # shellcheck disable=SC2086 # the flags are words
  if cbmc $checks --unwind "$unw" --unwindset "$set" -I "$top/include" \
    -I "$top/src" "$@" "$here/neg.c" "$top/src/der/der.c" \
    > "$out/cbmc-$name.log" 2>&1; then
    echo "control $name: passed, but must fail"
    fails=$((fails + 1))
  elif grep -q "FAILURE" "$out/cbmc-$name.log"; then
    echo "control $name: fails as it must"
    grep "FAILURE" "$out/cbmc-$name.log" | head -2
  else
    echo "control $name: CBMC error"
    tail -5 "$out/cbmc-$name.log"
    fails=$((fails + 1))
  fi
}
refute neg 6 "$hdr"
refute negend 6 "strchr.0:14,$hdr" -DEND --slice-formula
[ "$fails" = 0 ]
