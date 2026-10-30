#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Builds every libFuzzer target fuzz/f*.c against the library (src/) and
# the tool's key and base64 code (cli/), and copies the fixtures they
# read into <out>/fix/.
#
#   fuzz/build.sh [out]           (default out: build-fuzz/)
#   build-fuzz/fder fuzz/corpus/fder -dict=fuzz/der.dict
#
# CC, CFLAGS and LIB_FUZZING_ENGINE are OSS-Fuzz's (fuzz/oss-fuzz/); when
# LIB_FUZZING_ENGINE is unset this builds with clang,
# -fsanitize=fuzzer,address,undefined. NQJ is the number of compilers
# run at once (default 2).
#
# Seed corpora (fuzz/corpus/<target>/) come from the test fixtures:
# fder, fx509, focsp, ftsp from tests/vectors/der/local (certificates,
# OCSP responses, CRLs, tokens); fcap from tests/vectors/cap (the sample
# seal and manifest, and the seal with the sample token); fjson from
# those and from small ACVP files; fcls from the RSA and EC roots' keys;
# fkey from key files the tool writes; fsig from the first test of each
# parameter set in the ACVP sigVer and encapDecap sets; fenc from all of
# these as text; ftls from the RFC 8448 server flight (fuzz/t8448.py),
# ftlsc from the TLS test PKI (tests/vectors/tls/pki).
set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$top/build-fuzz}
CC=${CC:-clang}
NQJ=${NQJ:-2}
if [ -z "${LIB_FUZZING_ENGINE:-}" ]; then
  CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
  CFLAGS="$CFLAGS -fno-sanitize-recover=all -fsanitize=fuzzer-no-link"
  LIB_FUZZING_ENGINE=-fsanitize=fuzzer
  LD=$CC
  LDFLAGS=$CFLAGS
else
  # OSS-Fuzz: its engines are C++ libraries, linked by the C++ driver
  LD=${CXX:-clang++}
  LDFLAGS=${CXXFLAGS:-$CFLAGS}
fi
export CC CFLAGS top

mkdir -p "$out/obj/lib" "$out/obj/cli" "$out/obj/clif" "$out/fix/cap/data/deep"
obj=$out/obj

# one object per source, NQJ at a time
for f in "$top"/src/*/*.c; do
  m=$(basename "$(dirname "$f")")
  printf '%s %s\n' "$f" "$obj/lib/$m-$(basename "$f" .c).o"
done > "$obj/lib.lst"
for f in b64 key io; do
  printf '%s %s\n' "$top/cli/$f.c" "$obj/cli/$f.o"
done > "$obj/cli.lst"
cat "$obj/lib.lst" "$obj/cli.lst" | xargs -P "$NQJ" -n 2 sh -c '
  $CC $CFLAGS -std=c11 -DNQTEST -I"$top/include" -I"$top/src" -I"$top/cli" \
    -c "$0" -o "$1"'
# the whole tool, its main renamed, for fcli (fuzzed arguments)
for f in "$top"/cli/*.c; do
  printf '%s %s\n' "$f" "$obj/clif/$(basename "$f" .c).o"
done | xargs -P "$NQJ" -n 2 sh -c '
  $CC $CFLAGS -std=c11 -Dmain=nqclimain -I"$top/include" -I"$top/src" \
    -I"$top/cli" -c "$0" -o "$1"'
rm -f "$obj/libnq.a" "$obj/libnqcli.a"
ar rcs "$obj/libnq.a" "$obj"/lib/*.o
ar rcs "$obj/libnqcli.a" "$obj"/cli/*.o

for f in "$top"/fuzz/f*.c; do
  t=$(basename "$f" .c)
  $CC $CFLAGS -std=c11 -DNQTEST -I"$top/include" -I"$top/src" -I"$top/cli" \
    -I"$top/fuzz" -c "$f" -o "$obj/$t.o"
  if [ "$t" = fcli ]; then
    $LD $LDFLAGS "$obj/$t.o" "$obj"/clif/*.o "$obj/libnq.a" -pthread \
      $LIB_FUZZING_ENGINE -o "$out/$t"
  else
    $LD $LDFLAGS "$obj/$t.o" "$obj/libnqcli.a" "$obj/libnq.a" \
      $LIB_FUZZING_ENGINE -o "$out/$t"
  fi
done

# with NQOSSL=1, the differential target against OpenSSL 3.5 or later
# (fuzz/ossl/; not for OSS-Fuzz, which has no OpenSSL 3.5)
if [ "${NQOSSL:-0}" = 1 ]; then
  $CC $CFLAGS -std=c11 -I"$top/include" -I"$top/src" \
    -c "$top/fuzz/ossl/fdiff.c" -o "$obj/fdiff.o"
  $LD $LDFLAGS "$obj/fdiff.o" "$obj/libnq.a" -lcrypto \
    $LIB_FUZZING_ENGINE -o "$out/fdiff"
fi

# the fixtures (fz.h: fix/ beside the targets)
d=$top/tests/vectors
for f in rsa_root rsa_inter rsa_inter2 rsa_leaf_good ec_root ml_root; do
  cp "$d/der/local/$f.der" "$out/fix/"
done
cp "$d/cap/tsa/root.der" "$out/fix/tsa_root.der"
cp "$d/cap/sample/noqtis.sig" "$out/fix/cap/"
for f in a.txt empty data/b.csv data/deep/c.bin; do
  cp "$d/cap/sample/$f" "$out/fix/cap/$f"
done
echo "fuzz/build.sh: targets in $out"
