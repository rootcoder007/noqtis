#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The TLS 1.3 client against OpenSSL's s_server (3.5 or later, for
# X25519MLKEM768) on the loopback, one server per case, with the test
# PKI of tests/vectors/tls/pki. OpenSSL is only the peer here; noqtis
# never links it. Run by ctest as
#
#   sh srv.sh path/to/tlcli [path/to/tlget on|off]
#
# Each case starts a server, runs tlcli (or tlget, the tool's HTTP
# client) and checks the first line it prints against a pattern. Exit 0
# when every case passes.
set -u
cli=$1
get=${2:-}
tlson=${3:-off}
pki=$(cd "$(dirname "$0")/../vectors/tls/pki" && pwd)
o=${OPENSSL:-openssl}
tmp=$(mktemp -d)
port=$((20000 + $$ % 20000))
fails=0
n=0
trap 'rm -rf "$tmp"' EXIT

# X25519MLKEM768 came in OpenSSL 3.5; ctest counts 77 as skipped
v=$("$o" version 2>/dev/null | sed -n 's/^OpenSSL \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
set -- x $v
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
  # a server that printed ACCEPT may not take connections at once on a
  # slow VM: a refused connection is tried again, twice
  t=0
  while :; do
    out=$("$cli" "$@" 2>&1 | head -1)
    case $out in
    "fail: cannot connect"*) ;;
    *) break ;;
    esac
    t=$((t + 1))
    [ $t -gt 2 ] && break
    sleep 1
  done
  kill $pid 2>/dev/null
  wait $pid 2>/dev/null
  case $out in
  $pat) echo "ok   $name: $out" ;;
  *)
    echo "FAIL $name: got '$out', wanted '$pat'"
    echo "  s_server said:"
    sed 's/^/    /' "$tmp/log" | head -20
    fails=$((fails + 1))
    ;;
  esac
}

c="-cert $pki/rsa.pem -key $pki/rsa.key -cert_chain $pki/inter.pem"
e="-cert $pki/ec.pem -key $pki/ec.key -cert_chain $pki/inter.pem"
r=$pki/root.pem

# X25519MLKEM768 asked for by name: some builds leave it out of their
# default groups (Rocky 9), and a few out altogether; then X25519
hy=11ec
hg="-groups X25519MLKEM768:X25519"
if serve $c -www -groups X25519MLKEM768 > /dev/null 2>&1; then
  kill $pid 2>/dev/null
  wait $pid 2>/dev/null
else
  echo "note: this OpenSSL does not serve X25519MLKEM768; X25519 expected"
  hy=001d
  hg=""
fi
serve $c -www $hg && check "RSA, X25519MLKEM768" "ok 1301 $hy 0 *" localhost $port $r
serve $c -www -groups X25519 && check "HelloRetryRequest to X25519" "ok 1301 001d 1 *" -1 localhost $port $r
serve $c -www -groups X25519 && check "X25519 share" "ok 1301 001d 0 *" localhost $port $r
serve $e -www $hg -ciphersuites TLS_CHACHA20_POLY1305_SHA256 && check "ECDSA P-256, ChaCha20" "ok 1303 $hy 0 *" localhost $port $r
serve -cert $pki/ec384.pem -key $pki/ec384.key -www $hg -ciphersuites TLS_AES_256_GCM_SHA384 && check "ECDSA P-384, AES-256" "ok 1302 $hy 0 *" localhost $port $r
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
serve $c -www -groups P-256 && check "HelloRetryRequest to P-256" "ok 1301 0017 1 *" localhost $port $r
serve $e -www -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 && check "HelloRetryRequest to P-384" "ok 1302 0018 1 *" localhost $port $r
serve $c -www -groups ffdhe2048 && check "no common group" "fail: *handshake_failure*" localhost $port $r
serve $c -www -tls1_2 && check "TLS 1.2 only" "fail: *" localhost $port $r
# stapled OCSP responses (RFC 8446 4.4.2.1) and must-staple (RFC 7633)
serve $c -www -status_file $pki/ocsp-good.der && check "OCSP staple, good" "ok 1301 *" localhost $port $r
serve $c -www -status_file $pki/ocsp-rev.der && check "OCSP staple, revoked" "fail: *is revoked*" localhost $port $r
serve $c -www -status_file $pki/ocsp-old.der && check "OCSP staple, stale" "fail: *OCSP response does not check*" localhost $port $r
serve $c -www -status_file $pki/ocsp-oth.der && check "OCSP staple, wrong responder" "fail: *OCSP response does not check*" localhost $port $r
m="-cert $pki/ms.pem -key $pki/ec.key -cert_chain $pki/inter.pem"
serve $m -www && check "must-staple, no staple" "fail: *must-staple*" localhost $port $r
serve $m -www -status_file $pki/ocsp-ms.der && check "must-staple, stapled" "ok 1301 *" localhost $port $r
head -c 300000 /dev/zero | tr '\0' 'x' > "$tmp/big.txt"
serve $c -WWW $hg && check "a 300 kB reply" "ok 1301 $hy 0 3000[0-9][0-9]" localhost $port $r /big.txt

# the tool's client: GET over TLS, the system bundle overridden
getc() {
  name=$1
  pat=$2
  shift 2
  n=$((n + 1))
  out=$("$@" 2>&1 | head -1)
  case $out in
  $pat) echo "ok   $name: $out" ;;
  *)
    echo "FAIL $name: got '$out', wanted '$pat'"
    fails=$((fails + 1))
    ;;
  esac
}
if [ -n "$get" ]; then
  if [ "$tlson" = on ]; then
    serve $c -WWW
    getc "GET over TLS" "ok 300000 xxxx*" env SSL_CERT_FILE=$r "$get" \
      "https://localhost:$port/big.txt"
    getc "GET, wrong anchors" "fail: TLS with localhost: no valid path*" \
      env SSL_CERT_FILE=$pki/other.pem "$get" "https://localhost:$port/big.txt"
    getc "GET, no anchors file" "fail: cannot read SSL_CERT_FILE*" \
      env SSL_CERT_FILE=$tmp/none "$get" "https://localhost:$port/big.txt"
    getc "GET, CT on, no SCTs" "fail: TLS with localhost: *has no SCTs*" \
      env SSL_CERT_FILE=$r NOQTIS_CT_LOGS=$pki/ct-logs.json "$get" \
      "https://localhost:$port/big.txt"
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
    # Certificate Transparency (NOQTIS_CT_LOGS): a leaf with SCTs from the
    # test logs of two operators embedded
    serve -cert $pki/sct.pem -key $pki/ec.key -cert_chain $pki/inter.pem -WWW
    getc "GET, CT" "ok 300000 xxxx*" env SSL_CERT_FILE=$r \
      NOQTIS_CT_LOGS=$pki/ct-logs.json "$get" "https://localhost:$port/big.txt"
    getc "GET, CT, one operator listed" \
      "fail: TLS with localhost: Certificate Transparency: *1 log operator*" \
      env SSL_CERT_FILE=$r NOQTIS_CT_LOGS=$pki/ct-one.json "$get" \
      "https://localhost:$port/big.txt"
    getc "GET, CT, not a log list" "fail: NOQTIS_CT_LOGS * is not a log list*" \
      env SSL_CERT_FILE=$r NOQTIS_CT_LOGS=$r "$get" \
      "https://localhost:$port/big.txt"
    getc "GET, CT, no list file" "fail: cannot read NOQTIS_CT_LOGS*" \
      env SSL_CERT_FILE=$r NOQTIS_CT_LOGS=$tmp/none "$get" \
      "https://localhost:$port/big.txt"
    getc "GET, CT off" "ok 300000 xxxx*" env SSL_CERT_FILE=$r \
      NOQTIS_CT_LOGS= "$get" "https://localhost:$port/big.txt"
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
  else
    getc "https without NQTLS" "fail: https:// is not supported*" \
      "$get" "https://localhost:1/"
  fi
  # redirects, resolved without a server
  getc "redirect, absolute" "http://b.example/x" "$get" -r \
    http://a.example/p/q http://b.example/x
  getc "redirect, path" "http://a.example:8443/x?y" "$get" -r \
    http://a.example:8443/p/q /x?y
  getc "redirect, relative" "http://a.example/p/r.php" "$get" -r \
    http://a.example/p/q?z=1 r.php
  getc "redirect, relative to the root" "http://a.example/r" "$get" -r \
    http://a.example r
  getc "redirect, scheme-relative" "http://c.example/z" "$get" -r \
    http://a.example/ //c.example/z
  # which redirects ncget follows: the same server only
  getc "follow, same host" "same" "$get" -s http://a.example/p /q
  getc "follow, host in another case" "same" "$get" -s \
    http://a.example/p http://A.Example/q
  if [ "$tlson" = on ]; then
    getc "follow, http to https" "same" "$get" -s \
      http://a.example/p https://a.example/q
  fi
  getc "refuse, another host" "other" "$get" -s \
    http://a.example/p http://b.example/q
  getc "refuse, localhost" "other" "$get" -s \
    http://a.example/p http://127.0.0.1:8080/secret
  getc "refuse, another port" "other" "$get" -s \
    http://a.example:8000/p http://a.example:9000/q
  getc "refuse, scheme-relative to another host" "other" "$get" -s \
    http://a.example/p //c.example/z
fi

echo "srv.sh: $n cases, $fails failed"
[ $fails -eq 0 ]
