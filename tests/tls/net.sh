#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Opt-in interoperation test of the TLS 1.3 client with public HTTPS
# servers (NQNET=1; ctest counts 77 as skipped otherwise), with the
# system's CA bundle or SSL_CERT_FILE:
#
#   NQNET=1 sh net.sh path/to/tlcli path/to/tlget
#
# tlcli does the handshake (and prints the suite and group chosen; with
# -1, the hybrid share only, to draw HelloRetryRequests), tlget the
# tool's GET with redirects. Public servers change: a failure here is a
# reason to look, not proof of a bug.
set -u
if [ "${NQNET:-0}" != 1 ]; then
  echo "net.sh: set NQNET=1 to talk to public servers; skipped"
  exit 77
fi
cli=$1
get=$2
ca=${SSL_CERT_FILE:-}
if [ -z "$ca" ]; then
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
    if [ -r "$f" ]; then ca=$f; break; fi
  done
fi
if [ -z "$ca" ]; then
  echo "net.sh: no CA bundle; set SSL_CERT_FILE"
  exit 77
fi
fails=0
n=0
for h in example.com www.google.com www.cloudflare.com github.com \
  letsencrypt.org www.rfc-editor.org www.wikipedia.org cdn.jsdelivr.net \
  www.microsoft.com www.digicert.com freetsa.org; do
  for m in "" -1; do
    n=$((n + 1))
    out=$("$cli" -n $m "$h" 443 "$ca" / 2>&1 | head -1)
    case $out in
    ok*) echo "ok   $h $m: $out" ;;
    *) echo "FAIL $h $m: $out"; fails=$((fails + 1)) ;;
    esac
  done
done
for u in https://freetsa.org/ https://www.rfc-editor.org/rfc/rfc8448.txt \
  https://1.1.1.1/; do
  n=$((n + 1))
  out=$(SSL_CERT_FILE=$ca "$get" "$u" 2>&1 | head -1)
  case $out in
  ok*) echo "ok   GET $u: $out" ;;
  *) echo "FAIL GET $u: $out"; fails=$((fails + 1)) ;;
  esac
done
echo "net.sh: $n cases, $fails failed"
[ $fails -eq 0 ]
