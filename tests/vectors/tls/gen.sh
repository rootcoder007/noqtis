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
[ ms ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
tlsfeature = status_request
EOF

key() {
  case $2 in
  ec) $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" ;;
  ec384) $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" ;;
  rsa) $o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" ;;
  esac
}

# mk CERT KEY SUBJECT EXT ISSUERCERT ISSUERKEY [NOTBEFORE NOTAFTER]
# (a random serial, or $ser)
mk() {
  $o req -new -key "$2" -subj "$3" -config $w/x.cnf -out $w/r.csr
  $o x509 -req -in $w/r.csr -CA "$5" -CAkey "$6" -set_serial "0x${ser:-$($o rand -hex 8)}" \
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
# a must-staple leaf (TLS Feature status_request, RFC 7633)
mk ms.pem ec.key "/CN=localhost" ms inter.pem inter.key
# OCSP responses to staple (tests/ttlscrt.c, srv.sh), from the
# intermediate unless said: rsa.pem good, revoked, and stale (a minute
# to live, so past its nextUpdate from then on), ms.pem good, and
# rsa.pem good but signed by the untrusted root (no authority to answer)
# osp OUT CERT V|R SIGNER KEY VALIDITY
osp() {
  s=$($o x509 -in "$2" -noout -serial | sed 's/serial=//')
  if [ "$3" = R ]; then
    printf 'R\t460101000000Z\t260601000000Z\t%s\tunknown\t/CN=localhost\n' "$s"
  else
    printf 'V\t460101000000Z\t\t%s\tunknown\t/CN=localhost\n' "$s"
  fi > $w/idx
  $o ocsp -index $w/idx -rsigner "$4" -rkey "$5" -CA inter.pem \
    -issuer inter.pem -cert "$2" -no_nonce -respout "$1" $6
}
osp ocsp-good.der rsa.pem V inter.pem inter.key "-ndays 7000"
osp ocsp-rev.der rsa.pem R inter.pem inter.key "-ndays 7000"
osp ocsp-old.der rsa.pem V inter.pem inter.key "-nmin 1"
osp ocsp-ms.der ms.pem V inter.pem inter.key "-ndays 7000"
osp ocsp-oth.der rsa.pem V other.pem other.key "-ndays 7000"
# Certificate Transparency (RFC 6962), for tests/ttlscrt.c and srv.sh:
# three test logs (ct1 P-256 and ct3 P-256 of operator A, ct2 RSA of
# operator B; their SubjectPublicKeyInfo in ct1.der ..), their log list
# (ct-logs.json, the Chrome v3 form) and the same without ct2
# (ct-one.json); sct.pem, a leaf with SCTs from ct1 and ct2 embedded
# (precert entries over its TBSCertificate without the SCT extension);
# and SignedCertificateTimestampLists over rsa.pem (x509 entries) as the
# TLS extension carries them: sct-x.bin from ct1 and ct2, sct-a.bin from
# ct1 and ct3 (one operator); sct-b.bin over sct.pem from ct2. SCT time
# 2026-01-02T00:00:00Z.
hx() { od -An -v -tx1 | tr -d ' \n'; }
# bin HEX: the bytes
bin() {
  printf "$(printf '%s' "$1" | awk '{
    h = "0123456789abcdef"
    for (i = 1; i < length($0); i += 2) {
      a = index(h, substr($0, i, 1))
      b = index(h, substr($0, i + 1, 1))
      printf "\\%03o", 16 * a + b - 17
    }
  }')"
}
ts=$(printf '%016x' 1767312000000)
key $w/ct1.key ec
key $w/ct2.key rsa
key $w/ct3.key ec
for k in ct1 ct2 ct3; do
  $o pkey -in $w/$k.key -pubout -outform DER -out $k.der
done
# sct LOG SIGALG ENTRY: the SCT (hex) log LOG signs over ENTRY (hex:
# entry_type and signed_entry); SIGALG 03 ECDSA, 01 RSA PKCS #1 v1.5
sct() {
  id=$($o dgst -sha256 -binary $1.der | hx)
  bin "0000$ts${3}0000" > $w/tbs
  $o pkeyutl -sign -rawin -digest sha256 -inkey $w/$1.key -in $w/tbs \
    -out $w/sig
  sg=$(hx < $w/sig)
  printf '00%s%s000004%s%04x%s' "$id" "$ts" "$2" $((${#sg} / 2)) "$sg"
}
# lst SCT...: a SignedCertificateTimestampList (hex)
lst() {
  l=""
  for x in "$@"; do l="$l$(printf '%04x' $((${#x} / 2)))$x"; done
  printf '%04x%s' $((${#l} / 2)) "$l"
}
# x509 entries over rsa.pem
c=$($o x509 -in rsa.pem -outform DER | hx)
e=$(printf '0000%06x%s' $((${#c} / 2)) "$c")
bin "$(lst "$(sct ct1 03 "$e")" "$(sct ct2 01 "$e")")" > sct-x.bin
bin "$(lst "$(sct ct1 03 "$e")" "$(sct ct3 03 "$e")")" > sct-a.bin
# the embedded ones: the leaf without the extension first, its TBS
# signed as the precertificate's, then the leaf with it (same serial)
ser=$($o rand -hex 8)
mk $w/pre.pem ec.key "/CN=localhost" srv inter.pem inter.key
c=$($o x509 -in $w/pre.pem -outform DER | hx)
case $c in 3082????3082*) ;; *) echo "gen.sh: TBS too short" >&2; exit 1 ;; esac
m=$(printf '%s' "$c" | cut -c13-16)
tbs=$(printf '%s' "$c" | cut -c9-$((8 + (4 + 0x$m) * 2)))
ikh=$($o x509 -in inter.pem -pubkey -noout | $o pkey -pubin -outform DER |
  $o dgst -sha256 -binary | hx)
e=$(printf '0001%s%06x%s' "$ikh" $((${#tbs} / 2)) "$tbs")
l=$(lst "$(sct ct1 03 "$e")" "$(sct ct2 01 "$e")")
n=$((${#l} / 2))
if [ $n -lt 128 ]; then dl=$(printf '%02x' $n)
elif [ $n -lt 256 ]; then dl=$(printf '81%02x' $n)
else dl=$(printf '82%04x' $n); fi
{
  sed -n '/^\[ srv \]/,/^authorityKeyIdentifier/p' $w/x.cnf |
    sed 's/^\[ srv \]/[ sct ]/'
  echo "1.3.6.1.4.1.11129.2.4.2 = DER:04$dl$l"
} >> $w/x.cnf
mk sct.pem ec.key "/CN=localhost" sct inter.pem inter.key
ser=
# and over sct.pem, in the TLS extension, from ct2 alone: sct-b.bin
c=$($o x509 -in sct.pem -outform DER | hx)
e=$(printf '0000%06x%s' $((${#c} / 2)) "$c")
bin "$(lst "$(sct ct2 01 "$e")")" > sct-b.bin
# the log lists; log_id is the SHA-256 of the key
# lg LOG: one log's entry
lg() {
  printf '        {"description": "noqtis test log %s", "log_id": "%s",\n' \
    $1 "$($o dgst -sha256 -binary $1.der | $o base64 -A)"
  printf '         "key": "%s",\n' "$($o base64 -A -in $1.der)"
  printf '         "url": "https://%s.invalid/", "mmd": 86400,\n' $1
  printf '         "state": {"usable": {"timestamp": "2025-06-01T00:00:00Z"}}}'
}
# ll FILE OPERATOR-A-LOGS OPERATOR-B-LOGS
ll() {
  {
    printf '{"version": "1.0", "log_list_timestamp": "2026-01-01T00:00:00Z",\n'
    printf ' "operators": [\n'
    printf '  {"name": "A", "email": ["a@a.invalid"], "logs": [\n'
    sep=""
    for x in $2; do printf '%s' "$sep"; lg $x; sep=",
"; done
    printf ']}'
    if [ -n "$3" ]; then
      printf ',\n  {"name": "B", "email": ["b@b.invalid"], "logs": [\n'
      sep=""
      for x in $3; do printf '%s' "$sep"; lg $x; sep=",
"; done
      printf ']}'
    fi
    printf '\n ]}\n'
  } > "$1"
}
ll ct-logs.json "ct1 ct3" "ct2"
ll ct-one.json "ct1 ct3" ""
rm -rf $w
