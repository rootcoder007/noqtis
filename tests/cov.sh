#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Line and branch coverage of the library (src/) by the library's own
# tests: configures a build with -DNQCOV=ON (gcc --coverage), runs ctest
# (sampled as the Debug CI jobs are: NQSLSUB=8 NQFAST=1, unless set), then
# reads the counters with gcov, which comes with gcc. Prints one line per
# folder of src/ and a total (lines, branches taken at least once), then
# the functions with the most lines never run. Nothing to install.
#
#   tests/cov.sh [<build dir>] [<number of functions to list>]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
b=${1:-$here/build-cov}
top=${2:-25}
command -v gcov > /dev/null 2>&1 || {
  echo "cov.sh: gcov not found" >&2
  exit 2
}
# NQCOVTEST=0: report on the counters a previous run left, without
# building or testing again
if [ "${NQCOVTEST:-1}" != 0 ]; then
  CC=${CC:-gcc} cmake -S "$here" -B "$b" -DCMAKE_BUILD_TYPE=Debug -DNQCOV=ON \
    -DNQCLI=ON -DNQWERROR=ON > "$b.cfg.log"
  cmake --build "$b" -j "${NQJ:-2}" > "$b.build.log"
  find "$b" -name '*.gcda' -exec rm -f {} +
  (cd "$b" && NQSLSUB=${NQSLSUB:-8} NQFAST=${NQFAST:-1} \
    ctest -j "${NQJ:-2}" --output-on-failure > "$b.test.log" 2>&1) || {
    echo "cov.sh: some tests failed; see $b.test.log" >&2
  }
fi
out=$b.gcov
rm -rf "$out"
mkdir -p "$out"
# the library's objects (nqobj, and nqtlt for src/tls in the tests); the
# tool and the tests are not counted
find "$b" -path '*CMakeFiles/nqobj.dir/*' -name '*.gcda' > "$out/list"
find "$b" -path '*CMakeFiles/nqtlt.dir/*' -name '*.gcda' >> "$out/list"
(cd "$out" && while read -r f; do
  gcov -b -c -f -o "$(dirname "$f")" "$f" > /dev/null 2>&1 || true
done < list)
# per source file: lines run/total and branches taken/total, from the
# .gcov annotations (gcov -b writes one 'branch' line per branch)
for g in "$out"/*.c.gcov; do
  test -f "$g" || continue
  src=$(sed -n 's/^ *-: *0:Source://p' "$g" | head -n 1)
  case $src in
  "$here"/src/*) ;;
  *) continue ;;
  esac
  rel=${src#"$here"/}
  awk -v f="$rel" '
    /^ *-: *[0-9]+:/ { next }
    /^ *#####: *[0-9]+:/ || /^ *=====: *[0-9]+:/ { lt++; next }
    /^ *[0-9]+\*?: *[0-9]+:/ { lt++; lr++; next }
    /^branch / { bt++; if ($0 ~ /taken [1-9]/) br++ }
    END { printf "%s %d %d %d %d\n", f, lr, lt, br, bt }
  ' "$g"
done > "$out/files"
awk '
  { split($1, p, "/"); d = p[1] "/" p[2]
    lr[d] += $2; lt[d] += $3; br[d] += $4; bt[d] += $5
    LR += $2; LT += $3; BR += $4; BT += $5 }
  END {
    printf "%-12s %8s %16s %16s\n", "folder", "lines", "lines run", "branches taken"
    for (d in lr) printf "%-12s %8d %15.1f%% %15.1f%%\n", d, lt[d],
      100 * lr[d] / lt[d], bt[d] ? 100 * br[d] / bt[d] : 100
    printf "%-12s %8d %15.1f%% %15.1f%%\n", "total", LT, 100 * LR / LT,
      BT ? 100 * BR / BT : 100
  }' "$out/files" | sort
# functions with the most lines never run (gcov -f summaries)
echo
echo "functions with the most lines never run:"
while read -r f; do
  gcov -f -n -o "$(dirname "$f")" "$f" 2>/dev/null |
    awk -v obj="$f" '
      /^Function / { fn = $2; gsub(/\x27/, "", fn); next }
      /^Lines executed:/ && fn != "" {
        split($2, a, "%"); sub(/executed:/, "", a[1]); p = a[1]
        n = $4
        miss = int(n * (100 - p) / 100 + 0.5)
        if (miss > 0) printf "%d %s %s\n", miss, fn, obj
        fn = ""
      }'
done < "$out/list" | sort -rn | head -n "$top" |
  awk '{ n = split($3, s, "/"); o = s[n]; sub(/\.gcda$/, "", o)
         printf "%5d lines  %-28s %s\n", $1, $2, o }'
