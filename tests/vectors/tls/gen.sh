#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Regenerates the TLS test PKI (OpenSSL 3.5 as the CA): a P-256 root, an
# RSA intermediate and server certificates for tests/ttlscrt.c and the
# local-server test tests/tls/srv.sh, with their throwaway keys. Run
# from tests/vectors/tls/ with the output directory as $1 (default: pki/).
# Every run makes new keys; the committed files are one run. Validity is
# fixed (2026-01-01 to 2046-01-01; the expired one 2020 to 2021) so the
# tests do not depend on the day they run.
set -eu
out=${1:-pki}
mkdir -p "$out"
cd "$out"
o=openssl
w=work
rm -rf $w
mkdir $w
nb=20260101000000Z
na=20460101000000Z

cat > $w/x.cnf <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = unused
[ root ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ inter ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ srv ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ wild ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:*.w.example,DNS:f*.bad.example,DNS:*.com,DNS:exact.example,DNS:*.*.x.example,DNS:Upper.Example,IP:192.0.2.7,IP:2001:db8::7
[ cli ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:localhost
[ noku ]
basicConstraints = critical,CA:false
keyUsage = critical,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
[ cn ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
[ crit ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = critical,DNS:localhost
EOF

key() {
  case $2 in
  ec) $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" ;;
  ec384) $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" ;;
  rsa) $o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" ;;
  esac
}

# mk CERT KEY SUBJECT EXT ISSUERCERT ISSUERKEY [NOTBEFORE NOTAFTER]
mk() {
  $o req -new -key "$2" -subj "$3" -config $w/x.cnf -out $w/r.csr
  $o x509 -req -in $w/r.csr -CA "$5" -CAkey "$6" -set_serial "0x$($o rand -hex 8)" \
    -extfile $w/x.cnf -extensions "$4" -sha256 \
    -not_before "${7:-$nb}" -not_after "${8:-$na}" -out "$1"
}

key root.key ec
$o req -new -x509 -key root.key -subj "/CN=noqtis TLS test root" \
  -config $w/x.cnf -extensions root -sha256 \
  -not_before $nb -not_after $na -out root.pem
key inter.key rsa
mk inter.pem inter.key "/CN=noqtis TLS test intermediate" inter root.pem root.key
key rsa.key rsa
mk rsa.pem rsa.key "/CN=localhost" srv inter.pem inter.key
key ec.key ec
mk ec.pem ec.key "/CN=localhost" srv inter.pem inter.key
key ec384.key ec384
mk ec384.pem ec384.key "/CN=localhost" srv root.pem root.key
mk wild.pem ec.key "/CN=wild" wild inter.pem inter.key
mk old.pem ec.key "/CN=localhost" srv inter.pem inter.key 20200101000000Z 20210101000000Z
mk cli.pem ec.key "/CN=localhost" cli inter.pem inter.key
mk noku.pem rsa.key "/CN=localhost" noku inter.pem inter.key
mk cn.pem ec.key "/CN=localhost" cn inter.pem inter.key
mk crit.pem ec.key "/" crit inter.pem inter.key
# a root nobody trusts, and a server certificate under it
key other.key ec
$o req -new -x509 -key other.key -subj "/CN=noqtis TLS test root" \
  -config $w/x.cnf -extensions root -sha256 \
  -not_before $nb -not_after $na -out other.pem
mk evil.pem ec.key "/CN=localhost" srv other.pem other.key
# CertificateVerify signatures (RFC 8446 4.4.3) over the transcript hash
# 00 01 .. 1f (SHA-256) or 00 .. 2f (SHA-384), for tests/ttlscrt.c
cv() {
  printf '%64s' '' > $w/m
  printf 'TLS 1.3, server CertificateVerify\000' >> $w/m
  i=0
  while [ $i -lt "$1" ]; do
    printf "\\$(printf '%03o' $i)" >> $w/m
    i=$((i + 1))
  done
}
cv 32
$o pkeyutl -sign -rawin -digest sha256 -inkey rsa.key -in $w/m \
  -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest -out cv-rsa.sig
$o pkeyutl -sign -rawin -digest sha256 -inkey ec.key -in $w/m -out cv-ec.sig
cv 48
$o pkeyutl -sign -rawin -digest sha384 -inkey ec384.key -in $w/m -out cv-ec384.sig
$o pkeyutl -sign -rawin -digest sha384 -inkey rsa.key -in $w/m \
  -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest -out cv-rsa384.sig
rm -rf $w
