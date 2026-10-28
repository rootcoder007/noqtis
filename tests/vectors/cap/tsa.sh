#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Makes the timestamp fixtures of tcap with a throwaway local TSA (OpenSSL
# 3.5): an EC P-384 root and P-256 TSA certificate (as der/gen.sh), a
# second, unrelated root, and an RFC 3161 token over the signature bytes
# of sample/noqtis.sig. Run from tests/vectors/cap/ after "tcap gen".
# Every run makes new keys; the committed files are one run.
set -eu
o=openssl
out=tsa
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
mkdir -p $out
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
[ tsa ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
cat > $w/tsa.cnf <<EOF
[ tsa ]
default_tsa = t
[ t ]
serial = $w/serial
crypto_device = builtin
signer_digest = sha384
default_policy = 1.2.3.4.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF
echo 01 > $w/serial
$o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $w/root.key
$o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $w/tsa.key
$o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $w/other.key
$o req -x509 -new -key $w/root.key -out $w/root.pem -days 7300 \
  -subj "/O=noqtis test/CN=Capsule TSA Root" -config $w/x.cnf \
  -extensions root -sha384
$o req -x509 -new -key $w/other.key -out $w/other.pem -days 7300 \
  -subj "/O=noqtis test/CN=Capsule TSA Root" -config $w/x.cnf \
  -extensions root -sha384
$o req -new -key $w/tsa.key -out $w/tsa.csr \
  -subj "/O=noqtis test/CN=Capsule TSA" -config $w/x.cnf
$o x509 -req -in $w/tsa.csr -CA $w/root.pem -CAkey $w/root.key \
  -set_serial 0x$($o rand -hex 8) -days 7300 -extfile $w/x.cnf \
  -extensions tsa -out $w/tsa.pem -sha384
$o x509 -in $w/root.pem -outform DER -out $out/root.der
$o x509 -in $w/other.pem -outform DER -out $out/other.der
# the stamped data: the decoded "signature" of the golden seal
sed -n 's/.*"signature":"\([^"]*\)".*/\1/p' sample/noqtis.sig |
  $o base64 -d -A > $w/sig.bin
$o ts -query -data $w/sig.bin -sha256 -cert -no_nonce -out $w/q.tsq
$o ts -reply -config $w/tsa.cnf -queryfile $w/q.tsq -signer $w/tsa.pem \
  -inkey $w/tsa.key -out $w/r.tsr
$o ts -reply -in $w/r.tsr -token_out -out $out/sample.tok
$o ts -verify -in $out/sample.tok -token_in -data $w/sig.bin \
  -CAfile $w/root.pem -untrusted $w/tsa.pem >/dev/null
echo "wrote $out/root.der $out/other.der $out/sample.tok"
