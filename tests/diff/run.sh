#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Differential test against rmoriebricklayer, an independent implementation
# of the same standards (CTest tdiff, built with -DNQDIFF=ON). For each
# algorithm both implement, dv (dv.c, noqtis) writes deterministic cases
# with its outputs: keys from seeds, encapsulations and signatures with
# given randomness (deterministic and hedged), decapsulation of tampered
# ciphertexts, verification of tampered signatures, messages, contexts
# and keys, malformed keys, ML-DSA hints and z, wrong lengths, and every
# SHA-2, SHA-3, SHAKE and HMAC digest both have; dv.R recomputes each line
# with rmoriebricklayer and compares byte for byte; dv chk checks the
# lines it writes back for a difference (its signature verified and its
# ciphertext decapsulated by noqtis). Any difference fails, including one
# side refusing what the other accepts.
#
#   run.sh <dv> [<n>]
#
# <n> (default 300): cases per ML-KEM, HQC and ML-DSA set and of the
# hashes; SLH-DSA, sampled: n/50 per f set (at least 2), n/150 per s set
# (at least 1), n/10 each with NQSLOW=1. NQDIFFALG="<alg> ..." runs some
# algorithms only (names as `noqtis algs` gives them, and hash);
# NQDIFFSEED changes the seed (default 20261112). Needs Rscript and the
# rmoriebricklayer package: without them it exits 77 (CTest: skipped).
set -u
dv=$1
n=${2:-300}
here=$(cd "$(dirname "$0")" && pwd)
command -v Rscript > /dev/null 2>&1 || {
  echo "tdiff: no Rscript on the PATH; skipped"
  exit 77
}
Rscript -e 'if (!requireNamespace("rmoriebricklayer", quietly = TRUE))
  quit(status = 77)' || {
  echo "tdiff: the rmoriebricklayer package is not installed; skipped"
  exit 77
}
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
# the check works: a line whose last output digit was changed differs,
# on both sides
"$dv" gen hash 1 | head -n 1 | sed 's/0$/1/;t;s/.$/0/' > "$w/g"
if Rscript "$here/dv.R" "$w/g" > /dev/null 2>&1 ||
  "$dv" chk "$w/g" > /dev/null 2>&1; then
  echo "FAIL: a changed output was not reported"
  exit 1
fi
all="hash ML-KEM-512 ML-KEM-768 ML-KEM-1024 HQC-128 HQC-192 HQC-256
ML-DSA-44 ML-DSA-65 ML-DSA-87
SLH-DSA-SHA2-128f SLH-DSA-SHAKE-128f SLH-DSA-SHA2-192f SLH-DSA-SHAKE-192f
SLH-DSA-SHA2-256f SLH-DSA-SHAKE-256f SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s
SLH-DSA-SHA2-192s SLH-DSA-SHAKE-192s SLH-DSA-SHA2-256s SLH-DSA-SHAKE-256s"
na=0
bad=0
for a in ${NQDIFFALG:-$all}; do
  case $a in
  SLH-DSA-*s) c=$((n / 150)); [ "$c" -ge 1 ] || c=1 ;;
  SLH-DSA-*f) c=$((n / 50)); [ "$c" -ge 2 ] || c=2 ;;
  *) c=$n ;;
  esac
  case "${NQSLOW:-0}:$a" in
  1:SLH-DSA-*) c=$((n / 10)) ;;
  esac
  na=$((na + 1))
  t0=$(date +%s)
  if ! "$dv" gen "$a" "$c" "${NQDIFFSEED:-20261112}" > "$w/g"; then
    echo "FAIL: $a: dv gen"
    bad=$((bad + 1))
    continue
  fi
  Rscript "$here/dv.R" "$w/g" > "$w/f" 2> "$w/e"
  s=$?
  # the differences (the first 40 lines of them) and the counts
  grep -v '^dv\.R: ' "$w/e" | head -n 40
  grep '^dv\.R: ' "$w/e"
  "$dv" chk "$w/f"
  s2=$?
  echo "tdiff: $a: $c cases in $(($(date +%s) - t0)) s"
  if [ "$s" != 0 ] || [ "$s2" != 0 ]; then
    echo "FAIL: $a (dv.R exit $s, dv chk exit $s2)"
    bad=$((bad + 1))
  fi
done
echo "tdiff: $na algorithms, $bad with a difference"
[ "$bad" = 0 ]
