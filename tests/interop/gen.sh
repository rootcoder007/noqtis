#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Makes the rmoriebricklayer fixtures in tests/vectors/interop/bl, which
# tcli checks with noqtis on every platform (no R needed there): two
# capsules sealed by rmoriebricklayer (blseal.R; ML-DSA-65 and
# SLH-DSA-SHA2-128s, created 2026-01-01T00:00:00Z) and one of its own
# bundles (blbndl.R). Every run makes new keys; the committed files are
# one run. Needs Rscript and rmoriebricklayer.
#
#   gen.sh <noqtis>
set -eu
nq=$1
here=$(cd "$(dirname "$0")" && pwd)
out=$here/../vectors/interop/bl
rm -rf "$out"
mkdir -p "$out"
for c in mldsa:ML-DSA-65 slh:SLH-DSA-SHA2-128s; do
  d=$out/${c%%:*}
  mkdir -p "$d/data"
  printf 'x,y\n1,2\n3,4\n' > "$d/data/table.csv"
  printf 'sealed by rmoriebricklayer, checked by noqtis\n' > "$d/readme.txt"
  SOURCE_DATE_EPOCH=1767225600 Rscript "$here/blseal.R" "$d" "${c#*:}" \
    "$out/${c%%:*}.pub" "$nq"
done
Rscript "$here/blbndl.R" "$out/bundle" ML-DSA-65
