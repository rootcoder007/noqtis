#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# OSS-Fuzz build script for noqtis: builds every target with the
# repository's own fuzz/build.sh (which honours CC, CFLAGS and
# LIB_FUZZING_ENGINE), then puts in $OUT each target, its seed corpus
# (<target>_seed_corpus.zip), its dictionary (<target>.dict) and the
# fixture folder fix/ the targets read beside themselves.
cd "$SRC/noqtis"
NQJ=$(nproc) fuzz/build.sh "$WORK/nq"
mkdir -p "$OUT/fix"
cp -R "$WORK/nq/fix/." "$OUT/fix/"
for f in fuzz/f*.c; do
  t=$(basename "$f" .c)
  cp "$WORK/nq/$t" "$OUT/"
  (cd "fuzz/corpus/$t" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
  case $t in
    fder | fx509 | focsp | ftsp | fcls) cp fuzz/der.dict "$OUT/$t.dict" ;;
    fjson | fcap | fproof | fcard) cp fuzz/json.dict "$OUT/$t.dict" ;;
    fkey) cp fuzz/key.dict "$OUT/$t.dict" ;;
  esac
done
