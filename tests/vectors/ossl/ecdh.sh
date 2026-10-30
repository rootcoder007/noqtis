#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# ECDH known answers for tests/tecdh.c, made by OpenSSL (3.5 or later):
# for each curve, n key pairs a and b from `openssl genpkey`, and the
# shared secret from `openssl pkeyutl -derive` with a's key and b's
# public key. Every run makes new keys. Run as
#
#   sh ecdh.sh > ecdh.json
set -eu
o=${OPENSSL:-openssl}
n=${N:-8}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# hex FIELD KEY: the colon-separated hex block after "FIELD:" in the
# text form of KEY
hex() {
  "$o" pkey -in "$2" -text -noout | awk -v f="$1:" '
    $1 == f { on = 1; next }
    on && /^ / { gsub(/[ :]/, ""); s = s $0; next }
    on { exit }
    END { print s }'
}

printf '{"tests": [\n'
sep=""
for c in P-256 P-384; do
  case $c in P-256) nb=32 ;; *) nb=48 ;; esac
  i=0
  while [ $i -lt "$n" ]; do
    "$o" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$c \
      -out "$tmp/a.pem" 2>/dev/null
    "$o" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$c \
      -out "$tmp/b.pem" 2>/dev/null
    "$o" pkey -in "$tmp/b.pem" -pubout -out "$tmp/bp.pem"
    "$o" pkeyutl -derive -inkey "$tmp/a.pem" -peerkey "$tmp/bp.pem" \
      -out "$tmp/z"
    sk=$(hex priv "$tmp/a.pem")
    # the text form drops leading zero bytes, or adds one
    while [ ${#sk} -lt $((2 * nb)) ]; do sk=0$sk; done
    sk=$(printf '%s' "$sk" | awk -v n=$((2 * nb)) '{ print substr($0, length($0) - n + 1) }')
    pk=$(hex pub "$tmp/a.pem")
    peer=$(hex pub "$tmp/b.pem")
    z=$(od -An -v -tx1 "$tmp/z" | tr -d ' \n')
    printf '%s  {"crv": "%s", "sk": "%s", "pk": "%s", "peer": "%s", "z": "%s"}' \
      "$sep" "$c" "$sk" "$pk" "$peer" "$z"
    sep=",
"
    i=$((i + 1))
  done
done
printf '\n]}\n'
