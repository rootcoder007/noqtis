#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Writes ossl.txt: Argon2id answers from OpenSSL 3.5's ARGON2ID KDF (one
# lane at a time: threads 1), for tests/ta2.c.
#   sh ossl.sh > ossl.txt
set -eu
v=$(openssl version | cut -d' ' -f1,2)
echo "# Argon2id known answers from OpenSSL's ARGON2ID KDF ($v),"
echo "# an implementation independent of noqtis's: openssl kdf -keylen"
echo "# <bytes> -kdfopt hexpass:<pw> -kdfopt hexsalt:<salt> [-kdfopt"
echo "# hexsecret:<key> -kdfopt hexad:<ad>] -kdfopt iter:<t> -kdfopt"
echo "# memcost:<m> -kdfopt lanes:<p> ARGON2ID, written by"
echo "# tests/vectors/argon2/ossl.sh. y 2 is Argon2id, m KiB, t passes,"
echo "# p lanes."
echo
one() { # m t p pw salt key ad bytes
  set -- "$@"
  ex=
  if [ -n "$6" ]; then ex="-kdfopt hexsecret:$6 -kdfopt hexad:$7"; fi
  # shellcheck disable=SC2086
  tag=$(openssl kdf -keylen "$8" -kdfopt "hexpass:$4" -kdfopt "hexsalt:$5" \
    $ex -kdfopt "iter:$2" -kdfopt "memcost:$1" -kdfopt "lanes:$3" \
    -kdfopt threads:1 ARGON2ID | tr -d ':' | tr 'A-F' 'a-f')
  printf 'y=2\nm=%s\nt=%s\np=%s\npw=%s\nsalt=%s\nkey=%s\nad=%s\ntag=%s\n\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$tag"
}
s=000102030405060708090a0b0c0d0e0f
one 8 1 1 70617373776f7264 "$s" "" "" 32
one 35 2 2 70617373776f7264 "$s" "" "" 100
one 2048 2 1 6e6f71746973 "$s" "" "" 44
one 4100 1 4 6e6f71746973 "$s" a1a2a3a4 b1b2b3 64
one 8192 3 4 "" "$s$s" "" "" 65
one 65536 3 4 636f727265637420686f727365 "$s" "" "" 44
