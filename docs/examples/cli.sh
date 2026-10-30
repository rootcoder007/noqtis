#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Runs every command-line example of the manual pages (man/*.1) and the
# site, and checks the output they show. Usage: cli.sh <path to noqtis>
set -eu
NQ=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cd "$T"
fails=0
n=0

noqtis() { "$NQ" "$@"; }

# same <want> <got>: one example's output
same() {
  n=$((n + 1))
  if [ "$1" != "$2" ]; then
    fails=$((fails + 1))
    printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$n" "$1" "$2"
  fi
}

# code <want> <command...>: the exit status
code() {
  w=$1
  shift
  set +e
  "$@" > /dev/null 2>&1
  c=$?
  set -e
  same "exit $w: $*" "exit $c: $*"
}

# ---- noqtis(1), noqtis-keygen(1), noqtis-seal(1), noqtis-check(1)
mkdir -p results/data
printf 'a,b\n' > results/data/in.csv
printf 'r\n' > results/report.txt
same "ML-DSA-65 key pair: me (secret), me.pub (public)" \
  "$(noqtis keygen -a ML-DSA-65 -o me)"
same "noqtis-key-1 ML-DSA-65 pub" "$(head -1 me.pub)"
same "noqtis-key-1 ML-DSA-65 sec" "$(head -1 me)"
echo '{"project":"demo"}' > meta.json
same "sealed results with ML-DSA-65" \
  "$(noqtis seal -k me -m meta.json results)"
same "data noqtis.json noqtis.sig report.txt" "$(ls results | tr '\n' ' ' |
  sed 's/ $//')"
same "results: OK (22 checks passed)" \
  "$(noqtis check -p me.pub results | tail -1)"
same "ok    signature           ML-DSA-65 signature over noqtis.json is valid" \
  "$(noqtis check -p me.pub results | grep '^ok    signature ')"
same "ok    key                 not pinned: accepted the public key in the seal (no trusted key given)" \
  "$(noqtis check results 2> /dev/null | grep '^ok    key ')"
same "results: OK (22 checks passed)" \
  "$(SOURCE_DATE_EPOCH=1767225600 noqtis seal -k me results > /dev/null &&
     noqtis check -p me.pub results | tail -1)"
same '{"created":"2026-01-01T00:00:00Z",' "$(cut -c1-34 results/noqtis.json)"
# the same folder, SOURCE_DATE_EPOCH and --meta give a byte-identical
# manifest (guides/seal.md); the signature differs, ML-DSA signs hedged
mkdir -p repro/data
printf 'a,b\n' > repro/data/in.csv
printf 'r\n' > repro/report.txt
SOURCE_DATE_EPOCH=1767225600 noqtis seal -k me -m meta.json repro > /dev/null
cp repro/noqtis.json first.json
SOURCE_DATE_EPOCH=1767225600 noqtis seal -k me -m meta.json repro > /dev/null
same "manifests identical" \
  "$(cmp -s first.json repro/noqtis.json && echo manifests identical ||
     echo manifests differ)"
echo extra >> results/report.txt
code 1 noqtis check -p me.pub results
same "FAIL  file                report.txt: size differs" \
  "$(noqtis check -p me.pub results | grep '^FAIL' || true)"
same "results: FAILED (1 of 22 checks failed)" \
  "$(noqtis check -p me.pub results | tail -1 || true)"
touch results/new.txt
same "results: FAILED (2 of 23 checks failed)" \
  "$(noqtis check -p me.pub results | tail -1 || true)"
if command -v jq > /dev/null 2>&1; then
  same "report.txt: size differs new.txt: not in the manifest" \
    "$(noqtis check --json -p me.pub results |
       jq -r '.checks[] | select(.ok | not) | .detail' | tr '\n' ' ' |
       sed 's/ $//')"
fi
same '{"capsule":"results","ok":false,' \
  "$(noqtis check --json -p me.pub results | cut -c1-32 || true)"
code 2 noqtis seal -k me --tsa http://tsa.invalid results
code 2 noqtis check -p me.pub no-such-folder
noqtis keygen -a ML-DSA-44 -o other > /dev/null
code 1 noqtis check -p other.pub results

# ---- noqtis-prove(1); noqtis-check(1) --proof, --only, --lineage
mkdir -p r2/data
printf 'a,b\n' > r2/data/in.csv
printf 'r\n' > r2/report.txt
same "sealed r2 with ML-DSA-65" "$(noqtis seal --format 2 -k me r2)"
noqtis prove -p me.pub -o in.proof r2 data/in.csv
same "absent" "$(grep -q report.txt in.proof && echo present || echo absent)"
same "in.proof: OK (16 checks passed)" \
  "$(noqtis check -p me.pub --proof in.proof | tail -1)"
same "in.proof: OK (19 checks passed)" \
  "$(noqtis check -p me.pub --proof in.proof r2 | tail -1)"
code 1 noqtis check -p other.pub --proof in.proof
same "r2: OK (24 checks passed)" \
  "$(noqtis check -p me.pub --only data/in.csv r2 | tail -1)"
code 2 noqtis prove repro report.txt
mkdir r3
printf 'x\n' > r3/sum.txt
noqtis seal -k me --input raw=r2 r3 > /dev/null
same "ok    lineage             raw: checks, in r2" \
  "$(noqtis check -p me.pub --lineage r2 r3 | grep '^ok    lineage')"

# ---- noqtis-keygen(1)
same "ML-DSA-44 key pair: det (secret), det.pub (public)" \
  "$(noqtis keygen -a ml-dsa-44 -o det --seed \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)"
noqtis keygen -a ml-dsa-44 -o det2 --seed \
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  > /dev/null
same "$(cat det.pub)" "$(cat det2.pub)"
code 2 noqtis keygen -a ml-dsa-44 -o det3 --seed 0001
code 2 noqtis keygen -a ML-DSA-65 -o me
same "ML-KEM-768 key pair: box (secret), box.pub (public)" \
  "$(noqtis keygen -a ML-KEM-768 -o box)"

# ---- noqtis-sign(1), noqtis-verify(1)
printf 'report\n' > report.pdf
same "" "$(noqtis sign -k me report.pdf)"
same "report.pdf: OK (ML-DSA-65)" \
  "$(noqtis verify -p me.pub -s report.pdf.sig report.pdf)"
printf 'notes\n' > notes.txt
noqtis sign -k me -c release-2026 -d -o notes.sig - < notes.txt
same "notes.txt: OK (ML-DSA-65)" \
  "$(noqtis verify -p me.pub -s notes.sig -c release-2026 notes.txt)"
noqtis sign -k me -c release-2026 -d -o notes2.sig notes.txt
same "$(noqtis hash notes.sig | cut -c1-64)" \
  "$(noqtis hash notes2.sig | cut -c1-64)"
code 1 noqtis verify -p me.pub -s notes.sig notes.txt
noqtis sign -k me -d -o a.sig notes.txt
noqtis sign -k me -d -o b.sig notes.txt
same "same" "$(cmp a.sig b.sig && echo same)"
tar cf - results | noqtis sign -k me -o results.tar.sig -
tar cf - results | noqtis verify -q -p me.pub -s results.tar.sig -
printf 'big\n' > big.tar
noqtis sign -k me --ph sha512 -o big.sig big.tar
same "big.tar: OK (ML-DSA-65)" \
  "$(noqtis verify -p me.pub -s big.sig --ph sha512 big.tar)"
code 1 noqtis verify -p me.pub -s big.sig big.tar
same "" "$(noqtis verify -q -p me.pub -s report.pdf.sig report.pdf)"
echo changed >> report.pdf
code 1 noqtis verify -p me.pub -s report.pdf.sig report.pdf
same "noqtis verify: report.pdf: FAILED: the signature does not verify" \
  "$(noqtis verify -p me.pub -s report.pdf.sig report.pdf 2>&1 || true)"
code 2 noqtis sign -k box report.pdf
code 2 noqtis sign -k me report.pdf

# ---- noqtis-enc(1), noqtis-dec(1)
noqtis enc -p box.pub -o msg.ct sender.ss
noqtis dec -k box -o receiver.ss msg.ct
same "same" "$(cmp sender.ss receiver.ss && echo same)"
same "65" "$(noqtis dec -k box --stdout msg.ct | wc -c | tr -d ' ')"
same "$(od -An -tx1 sender.ss | tr -d ' \n')" \
  "$(noqtis dec -k box --stdout msg.ct)"
same "-rw-------" "$(ls -l receiver.ss | cut -c1-10)"
same "-rw-------" "$(ls -l box | cut -c1-10)"
code 2 noqtis enc -p me.pub -o x.ct x.ss

# ---- noqtis-hash(1)
printf 'abc' > abc.txt
same "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt" \
  "$(noqtis hash abc.txt)"
noqtis hash -a sha3-256 abc.txt > SUMS
same "abc.txt: OK" "$(noqtis hash -a sha3-256 -c SUMS)"
code 1 noqtis hash -c SUMS
if command -v sha256sum > /dev/null 2>&1; then
  same "abc.txt: OK" "$(sha256sum abc.txt | noqtis hash -c)"
fi
code 2 noqtis hash no-such-file

# ---- noqtis-algs(1), noqtis-version(1), noqtis(1)
same "ML-DSA-65              sig     1952    4032    3309    -" \
  "$(noqtis algs | grep '^ML-DSA-65 ')"
same "HQC-256                kem     7237    7333   14421   32" \
  "$(noqtis algs | grep '^HQC-256 ')"
same "noqtis" "$(noqtis version | cut -d' ' -f1)"
same "$(noqtis version)" "$(noqtis --version)"
code 2 noqtis
code 2 noqtis frobnicate
code 0 noqtis help seal

echo "cli examples: $n checked, $fails failed"
[ "$fails" -eq 0 ]
