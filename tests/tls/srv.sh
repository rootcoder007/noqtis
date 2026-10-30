#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The TLS 1.3 client against OpenSSL's s_server (3.5 or later, for
# X25519MLKEM768) on the loopback, one server per case, with the test
# PKI of tests/vectors/tls/pki. OpenSSL is only the peer here; noqtis
# never links it. Run by ctest as
#
#   sh srv.sh path/to/tlcli
#
# Each case starts a server, runs tlcli and checks the first line it
# prints against a pattern. Exit 0 when every case passes.
set -u
cli=$1
pki=$(cd "$(dirname "$0")/../vectors/tls/pki" && pwd)
o=${OPENSSL:-openssl}
tmp=$(mktemp -d)
port=$((20000 + $$ % 20000))
fails=0
n=0
trap 'rm -rf "$tmp"' EXIT

# X25519MLKEM768 came in OpenSSL 3.5; ctest counts 77 as skipped
v=$("$o" version 2>/dev/null | sed -n 's/^OpenSSL \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
set -- "$cli" $v
if [ $# -lt 3 ] || [ "$2" -lt 3 ] || { [ "$2" -eq 3 ] && [ "$3" -lt 5 ]; }; then
  echo "srv.sh: needs OpenSSL 3.5 or later as the peer; skipped"
  exit 77
fi

# serve ARGS...: an s_server on a fresh port; sets pid and port
serve() {
  port=$((port + 1))
  ( cd "$tmp" && exec "$o" s_server -accept "$port" "$@" ) \
    > "$tmp/log" 2>&1 < /dev/null &
  pid=$!
  i=0
  while ! grep -q ACCEPT "$tmp/log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 50 ] || ! kill -0 $pid 2>/dev/null; then
      echo "s_server did not start: $*"
      cat "$tmp/log"
      return 1
    fi
    sleep 0.1
  done
}

# case NAME PATTERN TLCLI-ARGS... (the server is already up)
check() {
  name=$1
  pat=$2
  shift 2
  n=$((n + 1))
  out=$("$cli" "$@" 2>&1 | head -1)
  kill $pid 2>/dev/null
  wait $pid 2>/dev/null
  case $out in
  $pat) echo "ok   $name: $out" ;;
  *)
    echo "FAIL $name: got '$out', wanted '$pat'"
    fails=$((fails + 1))
    ;;
  esac
}

c="-cert $pki/rsa.pem -key $pki/rsa.key -cert_chain $pki/inter.pem"
e="-cert $pki/ec.pem -key $pki/ec.key -cert_chain $pki/inter.pem"
r=$pki/root.pem

serve $c -www && check "RSA, X25519MLKEM768" "ok 1301 11ec 0 *" localhost $port $r
serve $c -www -groups X25519 && check "HelloRetryRequest to X25519" "ok 1301 001d 1 *" -1 localhost $port $r
serve $c -www -groups X25519 && check "X25519 share" "ok 1301 001d 0 *" localhost $port $r
serve $e -www -ciphersuites TLS_CHACHA20_POLY1305_SHA256 && check "ECDSA P-256, ChaCha20" "ok 1303 11ec 0 *" localhost $port $r
serve -cert $pki/ec384.pem -key $pki/ec384.key -www -ciphersuites TLS_AES_256_GCM_SHA384 && check "ECDSA P-384, AES-256" "ok 1302 11ec 0 *" localhost $port $r
serve $c -www -sigalgs rsa_pss_rsae_sha384 && check "RSA-PSS SHA-384" "ok 1301 *" localhost $port $r
serve $c -www && check "IPv4 address" "ok 1301 *" 127.0.0.1 $port $r
serve $c -www -6 -accept "[::1]:$((port + 1))" && check "IPv6 address" "ok 1301 *" -6 ::1 $port $r
serve $c -www && check "wrong host" "fail: *not for this host name*" example.com $port $r
serve -cert $pki/old.pem -key $pki/ec.key -cert_chain $pki/inter.pem -www && check "expired" "fail: *expired*" localhost $port $r
serve -cert $pki/evil.pem -key $pki/ec.key -cert_chain $pki/other.pem -www && check "untrusted root" "fail: *no valid path*" localhost $port $r
serve $c -www && check "anchors that are not its root" "fail: *no valid path*" localhost $port $pki/other.pem
serve -cert $pki/rsa.pem -key $pki/rsa.key -www && check "missing intermediate" "fail: *no valid path*" localhost $port $r
serve -cert $pki/cli.pem -key $pki/ec.key -cert_chain $pki/inter.pem -www && check "clientAuth only" "fail: *serverAuth*" localhost $port $r
serve -cert $pki/noku.pem -key $pki/rsa.key -cert_chain $pki/inter.pem -www && check "no digitalSignature" "fail: *keyUsage*" localhost $port $r
serve -cert $pki/cn.pem -key $pki/ec.key -cert_chain $pki/inter.pem -www && check "common name only" "fail: *not for this host name*" localhost $port $r
serve -cert $pki/crit.pem -key $pki/ec.key -cert_chain $pki/inter.pem -www && check "critical subjectAltName" "ok 1301 *" localhost $port $r
serve $c -www -verify 1 && check "CertificateRequest" "ok 1301 *" localhost $port $r
serve $c -www -max_send_frag 512 && check "small records" "ok 1301 *" localhost $port $r
serve $c -www -groups P-256 && check "no common group" "fail: *handshake_failure*" localhost $port $r
serve $c -www -tls1_2 && check "TLS 1.2 only" "fail: *" localhost $port $r
head -c 300000 /dev/zero | tr '\0' 'x' > "$tmp/big.txt"
serve $c -WWW && check "a 300 kB reply" "ok 1301 11ec 0 3000[0-9][0-9]" localhost $port $r /big.txt

echo "srv.sh: $n cases, $fails failed"
[ $fails -eq 0 ]
