#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Answers every ACVP request in a folder, as a lab's ACVP client saves
# them: for each <name>.json it runs the harness for the request's
# "algorithm" and writes the response to <response dir>/<name>.json.
#   acvp/run.sh [-e <expected dir>] <harness dir> <request dir> <response dir>
# <harness dir> holds the built harnesses (build/acvp). With -e, each
# response is also compared with <expected dir>/<name>.json when that
# file exists. Exit 0 when every request was answered (and matched).
set -eu
exp=
if [ "${1:-}" = -e ] && [ $# -ge 2 ]; then
  exp=$2
  shift 2
fi
if [ $# != 3 ]; then
  echo "usage: run.sh [-e <expected dir>] <harness dir> <request dir>" \
    "<response dir>" >&2
  exit 2
fi
bin=$1
in=$2
out=$3
mkdir -p "$out"
fails=0
n=0
for f in "$in"/*.json; do
  [ -f "$f" ] || continue
  b=$(basename "$f")
  # the first "algorithm" member: the vector set's own, which comes
  # before its test groups (also in a live server's [{acvVersion}, {...}])
  # shellcheck disable=SC2020 # each of , and { becomes a newline
  alg=$(tr ',{' '\n\n' < "$f" |
    sed -n 's/^[[:space:]]*"algorithm"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
    head -n 1)
  case $alg in
  SHA2-* | SHA3-* | SHAKE-*) h=acvsh ;;
  HMAC-*) h=acvhm ;;
  hmacDRBG) h=acvdr ;;
  ML-DSA) h=acvmd ;;
  SLH-DSA) h=acvsl ;;
  ML-KEM) h=acvmk ;;
  *)
    echo "$b: no harness for algorithm \"$alg\"" >&2
    fails=$((fails + 1))
    continue
    ;;
  esac
  n=$((n + 1))
  set -- "$f" "$out/$b"
  if [ -n "$exp" ] && [ -f "$exp/$b" ]; then
    set -- "$@" "$exp/$b"
  fi
  if "$bin/$h" "$@"; then
    echo "$b: $alg: answered by $h"
  else
    echo "$b: $alg: FAILED ($h)" >&2
    fails=$((fails + 1))
  fi
done
echo "run.sh: $n requests, $fails failed"
[ "$n" -gt 0 ] && [ "$fails" = 0 ]
