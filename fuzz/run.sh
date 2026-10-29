#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Runs one libFuzzer target built by fuzz/build.sh for a time, on a copy
# of its seed corpus (fuzz/corpus/<target>/) with its dictionary.
#
#   fuzz/run.sh <out> <target> <seconds> [libFuzzer options]
#
# The corpus grows in <out>/run/<target>/corpus; a crash, leak, timeout
# or out-of-memory input lands in <out>/run/<target>/ as crash-*,
# leak-*, timeout-* or oom-*, and the exit status is libFuzzer's
# (nonzero on any of them).
set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
out=$1
t=$2
secs=$3
shift 3

case $t in
  fder | fx509 | focsp | ftsp | fcls) dict=der.dict ;;
  fjson | fcap) dict=json.dict ;;
  fkey) dict=key.dict ;;
  *) dict= ;;
esac

w=$out/run/$t
mkdir -p "$w/corpus"
cp "$top/fuzz/corpus/$t/"* "$w/corpus/"
set -- -max_total_time="$secs" -rss_limit_mb=1024 -timeout=60 \
  -print_final_stats=1 -artifact_prefix="$w/" "$@"
if [ -n "$dict" ]; then
  set -- -dict="$top/fuzz/$dict" "$@"
fi
exec "$out/$t" "$@" "$w/corpus"
