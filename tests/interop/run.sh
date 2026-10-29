#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Interop with rmoriebricklayer (CTest tbl), both ways, live: capsules
# sealed by noqtis (and the golden capsule with its RFC 3161 token) are
# checked by rmoriebricklayer alone (blchk.R); capsules sealed and a
# bundle made by rmoriebricklayer (blseal.R, blbndl.R) are checked by
# noqtis. Needs Rscript and the rmoriebricklayer package: without them it
# exits 77, which CTest reports as skipped. No network.
#
#   run.sh <noqtis> <tests/ in the source tree>
set -u
nq=$1
src=$2
here=$src/interop
command -v Rscript > /dev/null 2>&1 || {
  echo "tbl: no Rscript on the PATH; skipped"
  exit 77
}
Rscript -e 'if (!requireNamespace("rmoriebricklayer", quietly = TRUE))
  quit(status = 77)' || {
  echo "tbl: the rmoriebricklayer package is not installed; skipped"
  exit 77
}
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
cd "$w" || exit 2
n=0
bad=0
# want <status> <command...>: runs it and requires that exit status
want() {
  ws=$1
  shift
  "$@" > out 2>&1
  s=$?
  n=$((n + 1))
  if [ "$s" != "$ws" ]; then
    cat out
    echo "FAIL: $*: exit $s, want $ws"
    bad=$((bad + 1))
  fi
}

# noqtis seals, rmoriebricklayer checks
for a in ML-DSA-65 SLH-DSA-SHAKE-128f; do
  rm -rf c
  mkdir -p c/sub
  printf 'one\n' > c/a.txt
  printf 'two\r\n' > c/sub/b.csv
  : > c/empty
  want 0 "$nq" keygen -a "$a" -o "k$a"
  want 0 "$nq" keygen -a "$a" -o "o$a"
  want 0 "$nq" seal -k "k$a" c
  want 0 Rscript "$here/blchk.R" c "k$a.pub"
  want 0 Rscript "$here/blchk.R" c -
  want 1 Rscript "$here/blchk.R" c "o$a.pub"
  printf 'more\n' >> c/a.txt
  want 1 Rscript "$here/blchk.R" c "k$a.pub"
done
# the golden capsule with the token over its signature: rmoriebricklayer's
# tsvrf checks noqtis's timestamp field, fail-closed without an anchor
cp -R "$src/vectors/cap/sample" g
want 0 Rscript -e 'a <- commandArgs(TRUE)
  p <- file.path(a[[1]], "noqtis.sig")
  s <- rawToChar(readBin(p, "raw", file.size(p)))
  t <- gsub("[\r\n]", "", rmoriebricklayer::jsb64enc(
    readBin(a[[2]], "raw", file.size(a[[2]]))))
  s <- sub("\"}$", paste0("\",\"timestamp\":\"", t, "\"}"), s)
  writeBin(charToRaw(s), p)' g "$src/vectors/cap/tsa/sample.tok"
want 0 "$nq" check --anchor "$src/vectors/cap/tsa/root.der" g
want 0 Rscript "$here/blchk.R" g - "$src/vectors/cap/tsa/root.der"
want 1 Rscript "$here/blchk.R" g - "$src/vectors/cap/tsa/other.der"
want 1 Rscript "$here/blchk.R" g -

# rmoriebricklayer seals, noqtis checks
for a in ML-DSA-65 SLH-DSA-SHA2-128s; do
  rm -rf b
  mkdir -p b/d
  printf 'x\n' > b/x.txt
  printf 'y\n' > b/d/y.txt
  want 0 Rscript "$here/blseal.R" b "$a" "b$a.pub" "$nq"
  want 0 "$nq" check -p "b$a.pub" b
  printf 'z\n' > b/z.txt
  want 1 "$nq" check -p "b$a.pub" b
done
want 0 Rscript "$here/blbndl.R" bn ML-DSA-65
want 0 "$nq" verify -p bn/attest.pub -s bn/attest.sig \
  -c "$(cat bn/attest.ctx)" bn/attest.msg
cd bn/files || exit 2
want 0 "$nq" hash --check ../files.sha256
cd "$w" || exit 2
printf 'tampered\n' > bn/attest.msg
want 1 "$nq" verify -p bn/attest.pub -s bn/attest.sig \
  -c "$(cat bn/attest.ctx)" bn/attest.msg

echo "tbl: $n checks, $bad failed"
test "$bad" = 0
