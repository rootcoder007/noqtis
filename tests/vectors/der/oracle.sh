#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds oracle.txt, the list of signatures the tests' stub verifier
# accepts. Run from tests/:
#   NQDREC=/tmp/rec.txt ./tx509; NQDREC=/tmp/rec.txt ./ttsp
#   sh vectors/der/oracle.sh /tmp/rec.txt > vectors/der/oracle.txt
# Each record line is: key kind hash pq spki-hex msg-hex sig-hex (see
# tderh.h). A key goes into oracle.txt only when OpenSSL verifies that
# signature over those bytes with that key, independently of noqtis.
set -eu
rec=$1
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
sort -u "$rec" > "$d/u"
ok=0
bad=0
while read -r key kind h pq spki msg sig; do
  printf '%s' "$spki" | xxd -r -p > "$d/k.der"
  printf '%s' "$msg" | xxd -r -p > "$d/m"
  printf '%s' "$sig" | xxd -r -p > "$d/s"
  case $h in
    2) md=sha256 ;;
    3) md=sha384 ;;
    4) md=sha512 ;;
    *) md= ;;
  esac
  case $kind in
    1|3) set -- -digest "$md" ;;
    2) set -- -digest "$md" -pkeyopt rsa_padding_mode:pss \
         -pkeyopt rsa_pss_saltlen:digest -pkeyopt "rsa_mgf1_md:$md" ;;
    4) set -- ;;
    *) bad=$((bad + 1)); continue ;;
  esac
  if openssl pkeyutl -verify -pubin -keyform DER -inkey "$d/k.der" \
      -rawin -in "$d/m" -sigfile "$d/s" "$@" >/dev/null 2>&1; then
    echo "$key"
    ok=$((ok + 1))
  else
    bad=$((bad + 1))
  fi
done < "$d/u"
echo "oracle: $ok verified, $bad refused" >&2
