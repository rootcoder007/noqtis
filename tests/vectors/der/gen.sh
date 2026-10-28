#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Regenerates the locally made DER fixtures (throwaway PKIs, OpenSSL 3.5
# as CA, TSA and OCSP responder). Run from tests/vectors/der/ with the
# output directory as $1 (default: local/). Every run makes new keys, so
# the committed fixtures are one run of this script; oracle.sh must be
# rerun afterwards.
set -eu
out=${1:-local}
mkdir -p "$out"
cd "$out"
o=openssl
w=work
rm -rf $w
mkdir $w

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
[ tsa ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ leaf ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ resp ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ ca ]
default_ca = ca1
[ ca1 ]
database = work/index.txt
crlnumber = work/crlnumber
default_md = sha256
default_crl_days = 30
EOF

# req KEY CERT SUBJECT EXT [ISSUERCERT ISSUERKEY [SIGOPTS...]]
mk() {
  key=$1; crt=$2; subj=$3; ext=$4
  shift 4
  if [ $# -eq 0 ]; then
    $o req -x509 -new -key $w/$key.key -out $w/$crt.pem -days 3650 \
      -subj "$subj" -config $w/x.cnf -extensions $ext -sha256
  else
    ic=$1; ik=$2
    shift 2
    $o req -new -key $w/$key.key -out $w/$crt.csr -subj "$subj" \
      -config $w/x.cnf
    $o x509 -req -in $w/$crt.csr -CA $w/$ic.pem -CAkey $w/$ik.key \
      -set_serial 0x$($o rand -hex 8) -days 3650 -extfile $w/x.cnf \
      -extensions $ext -out $w/$crt.pem "$@"
  fi
  $o x509 -in $w/$crt.pem -outform DER -out $crt.der
}

# RSA: root -> inter (signed with RSA-PSS) -> tsa, leaf_good, leaf_rev,
# ocsp responder
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/root.key
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/inter.key
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/tsa.key
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/leaf.key
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/resp.key
mk root rsa_root "/O=noqtis test/CN=RSA Root" root
mk inter rsa_inter "/O=noqtis test/CN=RSA Inter" inter rsa_root root \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -sigopt rsa_mgf1_md:sha256
mk tsa rsa_tsa "/O=noqtis test/CN=RSA TSA" tsa rsa_inter inter -sha256
mk leaf rsa_leaf_good "/O=noqtis test/CN=Leaf Good" leaf rsa_inter inter \
  -sha256
mk leaf rsa_leaf_rev "/O=noqtis test/CN=Leaf Revoked" leaf rsa_inter inter \
  -sha384
mk leaf rsa_leaf_unk "/O=noqtis test/CN=Leaf Unknown" leaf rsa_inter inter \
  -sha512
mk resp rsa_resp "/O=noqtis test/CN=OCSP Responder" resp rsa_inter inter \
  -sha256
# below rsa_inter (pathlen 0): a CA and its leaf, a path one too long
$o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $w/inter2.key
mk inter2 rsa_inter2 "/O=noqtis test/CN=RSA Inter 2" root rsa_inter inter \
  -sha256
mk leaf rsa_leaf_deep "/O=noqtis test/CN=Leaf Deep" leaf rsa_inter2 inter2 \
  -sha256

# EC: P-384 root -> P-256 TSA (ECDSA-SHA384 over the signed attributes)
$o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $w/ecroot.key
$o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $w/ectsa.key
mk ecroot ec_root "/O=noqtis test/CN=EC Root" root
mk ectsa ec_tsa "/O=noqtis test/CN=EC TSA" tsa ec_root ecroot -sha384

# ML-DSA-65 root -> ML-DSA-44 TSA certificate (OpenSSL 3.5 cannot sign a
# timestamp with ML-DSA: the path tests use it)
$o genpkey -algorithm ML-DSA-65 -out $w/mlroot.key
$o genpkey -algorithm ML-DSA-44 -out $w/mltsa.key
mk mlroot ml_root "/O=noqtis test/CN=ML-DSA Root" root
mk mltsa ml_tsa "/O=noqtis test/CN=ML-DSA TSA" tsa ml_root mlroot

# ---- timestamp tokens ----
printf 'noqtis der fixture\n' > data.txt
tsacnf() {
  cat > $w/tsa-$1.cnf <<EOF
[ tsa ]
default_tsa = t
[ t ]
serial = $w/serial
crypto_device = builtin
signer_digest = $2
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.2
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:500
ordering = $3
tsa_name = $4
ess_cert_id_chain = no
ess_cert_id_alg = $5
EOF
}
echo 01 > $w/serial
# tok NAME CNF SIGNERCERT SIGNERKEY HASH CHAIN(yes|no) [NONONCE]
tok() {
  if [ "${7:-}" = nonce0 ]; then
    $o ts -query -data data.txt -$5 -cert -no_nonce -out $w/$1.tsq
  else
    $o ts -query -data data.txt -$5 -cert -out $w/$1.tsq
  fi
  if [ "$6" = yes ]; then
    $o ts -reply -config $w/tsa-$2.cnf -queryfile $w/$1.tsq \
      -signer $w/$3.pem -inkey $w/$4.key -chain $w/rsa_inter.pem \
      -out $1.tsr
  else
    $o ts -reply -config $w/tsa-$2.cnf -queryfile $w/$1.tsq \
      -signer $w/$3.pem -inkey $w/$4.key -out $1.tsr
  fi
  $o ts -reply -in $1.tsr -token_out -out $1.tok
  n=$($o ts -query -in $w/$1.tsq -text | sed -n 's/^Nonce: 0x//p')
  echo "$1|${n:--}" >> nonces.txt
}
: > nonces.txt
tsacnf rsa sha256 no no sha256
tsacnf ec sha384 yes yes sha1
tok l_rsa rsa rsa_tsa tsa sha256 yes
tok l_rsa384 rsa rsa_tsa tsa sha384 yes
tok l_rsa_nonce0 rsa rsa_tsa tsa sha512 yes nonce0
tok l_ec ec ec_tsa ectsa sha256 no
for t in l_rsa l_rsa384 l_rsa_nonce0; do
  $o ts -verify -in $t.tsr -data data.txt -CAfile $w/rsa_root.pem \
    -untrusted $w/rsa_inter.pem
done
$o ts -verify -in l_ec.tsr -data data.txt -CAfile $w/ec_root.pem

# ---- OCSP and CRL, issued by rsa_inter ----
: > $w/index.txt
echo 01 > $w/crlnumber
for c in rsa_leaf_good rsa_leaf_rev rsa_resp rsa_tsa; do
  $o ca -config $w/x.cnf -valid $w/$c.pem -keyfile $w/inter.key \
    -cert $w/rsa_inter.pem 2>/dev/null
done
$o ca -config $w/x.cnf -revoke $w/rsa_leaf_rev.pem -keyfile $w/inter.key \
  -cert $w/rsa_inter.pem -crl_reason keyCompromise 2>/dev/null
$o ca -config $w/x.cnf -gencrl -keyfile $w/inter.key -cert $w/rsa_inter.pem \
  -out $w/crl.pem 2>/dev/null
$o crl -in $w/crl.pem -outform DER -out rsa_crl.der
# a CRL from another CA with the same contents: signed by the root
$o ca -config $w/x.cnf -gencrl -keyfile $w/root.key -cert $w/rsa_root.pem \
  -out $w/crl2.pem 2>/dev/null
$o crl -in $w/crl2.pem -outform DER -out rsa_crl_root.der

# ocsp NAME CERT HASH SIGNER SIGNERKEY [EXTRA...]
ocsp() {
  name=$1; c=$2; h=$3; sc=$4; sk=$5
  shift 5
  $o ocsp -issuer $w/rsa_inter.pem -$h -cert $w/$c.pem -no_nonce \
    -reqout $w/$name.req
  $o ocsp -index $w/index.txt -rsigner $w/$sc.pem -rkey $w/$sk.key \
    -CA $w/rsa_inter.pem -reqin $w/$name.req -respout $name.der -ndays 30 \
    "$@"
}
ocsp o_good rsa_leaf_good sha1 rsa_inter inter
ocsp o_good256 rsa_leaf_good sha256 rsa_inter inter
ocsp o_rev rsa_leaf_rev sha1 rsa_inter inter
ocsp o_unk rsa_leaf_unk sha1 rsa_inter inter
ocsp o_deleg rsa_leaf_good sha1 rsa_resp resp
ocsp o_keyid rsa_leaf_good sha256 rsa_inter inter -resp_key_id
ocsp o_nocerts rsa_leaf_good sha256 rsa_inter inter -resp_no_certs
for r in o_good o_good256 o_rev o_unk o_deleg o_keyid; do
  $o ocsp -respin $r.der -CAfile $w/rsa_root.pem \
    -untrusted $w/rsa_inter.pem -issuer $w/rsa_inter.pem \
    -resp_text >/dev/null 2>&1 || true
done
rm -rf $w
