#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Makes the name-constraint fixtures (nc/, RFC 5280 4.2.1.10) for
# tests/tx509.c: a P-256 root, intermediates under it that carry
# nameConstraints, and leaves inside and outside them. OpenSSL 3.5 as
# CA. Run from tests/vectors/der/ with the output directory as $1
# (default: nc/). Every run makes new keys, so the committed fixtures
# are one run of this script.
#
#   nc_root     no constraints
#   nc_dns      permitted DNS example.com and .example.net, excluded DNS
#               bad.example.com
#   nc_ip       permitted IP 192.0.2.0/24 and 2001:db8::/32, excluded IP
#               192.0.2.128/25
#   nc_dn       permitted dirName C=CA, O=Good and email example.com
#   nc_uri      permitted URI .example.com (a form noqtis does not
#               compare)
#   nc_max      a subtree with a maximum, nc_min one with a minimum of 1
#               (both refused by the profile)
#   nc_si       self-issued under nc_dn (its subject, another key)
#   l_*         leaves; see the table at the end
set -eu
out=${1:-nc}
mkdir -p "$out"
cd "$out"
o=openssl
w=work
rm -rf $w
mkdir $w

cat > $w/x.cnf <<'CNF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = unused
[ root ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ dns ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical,permitted;DNS:example.com,permitted;DNS:.example.net,excluded;DNS:bad.example.com
[ ip ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical,permitted;IP:192.0.2.0/255.255.255.0,permitted;IP:2001:db8:0:0:0:0:0:0/ffff:ffff:0:0:0:0:0:0,excluded;IP:192.0.2.128/255.255.255.128
[ dirn ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical,permitted;dirName:good,permitted;email:example.com
[ good ]
C = CA
O = Good
[ other ]
C = US
O = Other
[ uri ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical,permitted;URI:.example.com
[ max ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# permitted DNS a.test with maximum 2
nameConstraints = critical,DER:300fa00d300b8206612e74657374810102
[ min ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# permitted DNS a.test with minimum 1
nameConstraints = critical,DER:300fa00d300b8206612e74657374800101
[ si ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ leaf ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

key() {
  $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $w/$1.key
}

# mk KEY NAME SUBJECT EXT [ISSUER ISSUERKEY [SAN]]
mk() {
  k=$1; n=$2; subj=$3; ext=$4
  if [ $# -eq 4 ]; then
    $o req -x509 -new -key $w/$k.key -out $w/$n.pem -days 3650 \
      -subj "$subj" -config $w/x.cnf -extensions $ext -sha256
  else
    ic=$5; ik=$6
    cp $w/x.cnf $w/e.cnf
    if [ $# -ge 7 ] && [ "$7" != - ]; then
      printf '[ ext ]\n' >> $w/e.cnf
      sed -n "/^\[ $ext \]/,/^\[/p" $w/x.cnf | sed '1d;/^\[/d' >> $w/e.cnf
      printf 'subjectAltName = %s\n' "$7" >> $w/e.cnf
      ext=ext
    fi
    $o req -new -key $w/$k.key -out $w/$n.csr -subj "$subj" -config $w/x.cnf
    $o x509 -req -in $w/$n.csr -CA $w/$ic.pem -CAkey $w/$ik.key \
      -set_serial 0x$($o rand -hex 8) -days 3650 -extfile $w/e.cnf \
      -extensions $ext -out $w/$n.pem -sha256
  fi
  $o x509 -in $w/$n.pem -outform DER -out $n.der
}

key root
key ca
key si
key leaf
mk root nc_root "/CN=NC root" root
mk ca nc_dns "/CN=NC dns CA" dns nc_root root
mk ca nc_ip "/CN=NC ip CA" ip nc_root root
mk ca nc_dn "/CN=NC dn CA" dirn nc_root root
mk ca nc_uri "/CN=NC uri CA" uri nc_root root
mk ca nc_max "/CN=NC max CA" max nc_root root
mk ca nc_min "/CN=NC min CA" min nc_root root
mk si nc_si "/CN=NC dn CA" si nc_dn ca

# leaves: name, issuer, subject, subjectAltName
while read -r n i s a; do
  mk leaf "$n" "$s" leaf "$i" "$( [ "$i" = nc_si ] && echo si || echo ca)" "$a"
done <<'LEAVES'
l_dns_ok nc_dns /CN=x DNS:www.example.com,DNS:example.com,DNS:a.b.example.net
l_dns_cn nc_dns /CN=www.evil.org DNS:www.example.com,IP:198.51.100.1
l_dns_dot nc_dns /CN=x DNS:example.net
l_dns_out nc_dns /CN=x DNS:www.badexample.com
l_dns_ex nc_dns /CN=x DNS:x.bad.example.com
l_dns_wild nc_dns /CN=x DNS:*.example.com
l_ip_ok nc_ip /CN=x IP:192.0.2.5,IP:2001:db8:0:0:0:0:0:1,DNS:any.example.org
l_ip_out nc_ip /CN=x IP:198.51.100.1
l_ip_ex nc_ip /CN=x IP:192.0.2.200
l_ip_v6 nc_ip /CN=x IP:2001:db9:0:0:0:0:0:1
l_dn_ok nc_dn /C=CA/O=Good/CN=leaf email:a@example.com
l_dn_out nc_dn /C=CA/O=Bad/CN=leaf DNS:www.example.com
l_dn_san nc_dn /C=CA/O=Good/CN=leaf dirName:other
l_dn_mail nc_dn /C=CA/O=Good/CN=leaf email:a@sub.example.com
l_dn_subj nc_dn /C=CA/O=Good/CN=leaf/emailAddress=a@evil.org -
l_si_ok nc_si /C=CA/O=Good/CN=deep DNS:x.example.org
l_uri_has nc_uri /CN=x URI:https://www.example.com/
l_uri_none nc_uri /CN=x DNS:www.example.com
LEAVES
# a leaf whose subject is its issuer's: self-issued, and checked
mk leaf l_dn_self "/CN=NC dn CA" leaf nc_dn ca DNS:x.example.org
rm -rf $w
