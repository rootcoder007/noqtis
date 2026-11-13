#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The tool's data-layer commands, as a user runs them: exit codes,
# outputs, the files written, and every refusal saying what to do.
# POSIX sh only (runs under busybox).
#   tests/nqd/cli.sh <noqtis> <tests dir> [<noqtis built with NQTEST>]
set -u
nq=$1
td=$2
nqt=${3:-}
# absolute, as one test runs the tool from another folder
case $nq in /*) ;; *) nq=$(pwd)/$nq ;; esac
case $nqt in /* | "") ;; *) nqt=$(pwd)/$nqt ;; esac
v=$td/vectors/nqd
w=${TMPDIR:-/tmp}/nqdcli.$$
rm -rf "$w"
mkdir -p "$w" || exit 2
trap 'rm -rf "$w"' EXIT INT TERM
n=0
bad=0
export SOURCE_DATE_EPOCH=1767225600

# ok <want-exit> <what> <command...>: runs it, keeps stdout in $w/out and
# stderr in $w/err
ok() {
  want=$1
  what=$2
  shift 2
  n=$((n + 1))
  "$@" >"$w/out" 2>"$w/err"
  got=$?
  if [ "$got" != "$want" ]; then
    bad=$((bad + 1))
    echo "FAIL $what: exit $got, expected $want" >&2
    sed 's/^/  out: /' "$w/out" >&2
    sed 's/^/  err: /' "$w/err" >&2
  fi
}

# has <file> <text> <what>: the file holds the text
has() {
  n=$((n + 1))
  if ! grep -q -- "$2" "$1"; then
    bad=$((bad + 1))
    echo "FAIL $3: no '$2' in $(basename "$1")" >&2
    sed 's/^/  /' "$1" >&2
  fi
}

# same <file> <file> <what>: the two files hold the same bytes. Compared by
# the tool's own digest: a small container image has no cmp.
same() {
  n=$((n + 1))
  if [ "$("$nq" hash <"$1")" != "$("$nq" hash <"$2")" ] || [ ! -r "$1" ] || [ ! -r "$2" ]; then
    bad=$((bad + 1))
    echo "FAIL $3: $1 and $2 differ" >&2
  fi
}

# ---- data: init, add, show, check ----

c=$w/cap
mkdir -p "$c/data"
cp "$v/cap/data/a.csv" "$v/cap/data/b.csv" "$c/data/"
ok 2 "data check without a record" "$nq" data check "$c"
has "$w/err" "noqtis data init" "no record says how to start one"
ok 0 "data init" "$nq" data init "$c"
ok 2 "data init twice" "$nq" data init "$c"
has "$w/err" "force" "init twice names --force"
ok 0 "data init -f" "$nq" data init -f "$c"
ok 0 "data add" "$nq" data add --url https://example.org/a.csv \
  --publisher "City of Example" --licence "OGL-Canada-2.0" \
  --retrieved now "$c" data/a.csv
ok 0 "data add second" "$nq" data add --synthetic "$c" data/b.csv
ok 0 "data add again keeps the url" "$nq" data add "$c" data/a.csv
ok 0 "data show" "$nq" data show "$c"
has "$w/out" "https://example.org/a.csv" "the url is kept"
has "$w/out" '"retrieved":"2026-01-01T00:00:00Z"' "retrieved now"
has "$w/out" '"synthetic":true' "synthetic flag"
ok 0 "data show --json" "$nq" data show --json "$c"
same "$c/noqtis.data.json" "$v/cap/noqtis.data.json" "the record is the vector"
ok 0 "data check" "$nq" data check "$c"
has "$w/out" "OK (3 checks passed)" "check passes"
has "$w/out" "data/b.csv \[synthetic\]" "synthetic rows say so"
ok 2 "data add a missing file" "$nq" data add "$c" data/none.csv
has "$w/err" "cannot be read" "missing file refused"
ok 2 "data add outside" "$nq" data add "$c" ../x.csv
has "$w/err" "not a path a capsule holds" "path outside refused"
ok 2 "data add a bad time" "$nq" data add --retrieved yesterday "$c" \
  data/a.csv
has "$w/err" "YYYY-MM-DDTHH:MM:SSZ" "bad time says the form"

# put, del, fmt
printf '{"name":"total","status":"pass","expected":12,"observed":12}' \
  >"$w/chk.json"
ok 0 "data put a check" "$nq" data put "$c" checks "$w/chk.json"
printf '{"name":"x","status":"maybe"}' >"$w/bad.json"
ok 2 "data put a bad check" "$nq" data put "$c" checks "$w/bad.json"
has "$w/err" "must be one of pass, warn, fail" "bad status says the names"
printf '{"title":"Example data","authors":["A. Author"],"year":2026}' \
  >"$w/cite.json"
ok 0 "data put cite from stdin" "$nq" data put "$c" cite - <"$w/cite.json"
ok 2 "data put to no member" "$nq" data put "$c" nope "$w/chk.json"
ok 0 "data del" "$nq" data del "$c" checks total
ok 2 "data del again" "$nq" data del "$c" checks total
ok 0 "data del cite" "$nq" data del "$c" cite
same "$c/noqtis.data.json" "$v/cap/noqtis.data.json" "back to the vector"
printf '{"name":"total","status":"fail","note":"12 != 13"}' >"$w/f.json"
ok 0 "data put a failed check" "$nq" data put "$c" checks "$w/f.json"
ok 1 "data check with a failed check" "$nq" data check "$c"
has "$w/out" "FAIL  recorded" "a recorded failure fails its row"
ok 0 "data del it" "$nq" data del "$c" checks total

# a record edited by hand
cp "$c/noqtis.data.json" "$w/keep.json"
printf '{ "format" : "noqtis-data-1" }\n' >"$c/noqtis.data.json"
ok 1 "data check, not canonical" "$nq" data check "$c"
has "$w/out" "canonical" "not canonical says so"
has "$w/err" "noqtis data fmt" "and how to fix it"
ok 0 "data fmt" "$nq" data fmt "$c"
printf '{"format":"noqtis-data-1"}' >"$w/want.json"
same "$c/noqtis.data.json" "$w/want.json" "fmt writes canonical form"
printf '{"format":"noqtis-data-1","sorces":[]}' >"$c/noqtis.data.json"
ok 2 "data fmt refuses an unknown member" "$nq" data fmt "$c"
has "$w/err" "sorces: not a member" "names the member"
printf '{"format":"noqtis-data-1","format":"noqtis-data-1"}' \
  >"$c/noqtis.data.json"
ok 2 "data fmt refuses a duplicate key" "$nq" data fmt "$c"
has "$w/err" "duplicate key" "says duplicate"
cp "$w/keep.json" "$c/noqtis.data.json"

# a changed file
cp "$c/data/a.csv" "$w/a.csv"
printf '4,dan,1,2024-04-01\r\n' >>"$c/data/a.csv"
ok 1 "data check, a file changed" "$nq" data check "$c"
has "$w/out" "FAIL  source  data/a.csv: SHA-256 is" "changed file fails"
has "$w/err" "noqtis data add" "and says how to record it"
ok 1 "data check --json" "$nq" data check --json "$c"
has "$w/out" '"ok":false' "json says not ok"
has "$w/out" '"fix":' "json has the fix"
cp "$w/a.csv" "$c/data/a.csv"
rm "$c/data/b.csv"
ok 1 "data check, a file missing" "$nq" data check "$c"
has "$w/out" "data/b.csv \[synthetic\]: missing" "missing file fails"
cp "$v/cap/data/b.csv" "$c/data/"

# sealed with the record: the seal covers it, changes need a new seal
ok 0 "keygen" "$nq" keygen -a ML-DSA-44 -o "$w/k"
ok 0 "seal" "$nq" seal -k "$w/k" "$c"
ok 0 "check" "$nq" check -p "$w/k.pub" "$c"
ok 0 "data put after sealing" "$nq" data put "$c" checks "$w/chk.json"
has "$w/err" "seal it again" "sealed folder warns"
ok 1 "check after a change" "$nq" check -p "$w/k.pub" "$c"
has "$w/out" "noqtis.data.json" "the seal check names the record"

# ---- schema ----

s=$w/sch
mkdir -p "$s/data"
cp "$v/cap/data/a.csv" "$v/cap/data/b.csv" "$s/data/"
ok 0 "schema infer" "$nq" schema infer "$s" data/a.csv data/b.csv
has "$w/out" '"name":"score","nulls":true,"type":"real"' "infer types"
has "$w/out" '"path":"data/b.csv"' "infer second file"
ok 2 "schema check without a record" "$nq" schema check "$s"
ok 0 "schema infer --put" "$nq" schema infer --put --ranges "$s" data/a.csv
ok 0 "schema check" "$nq" schema check "$s"
has "$w/out" "3 rows, 4 columns as the schema says" "schema check passes"
ok 2 "schema check, file with no schema" "$nq" schema check "$s" data/b.csv
has "$w/err" "schema infer --put" "says how to pin one"
ok 0 "data check with the schema" "$nq" data check "$s"
printf '4,dan,9,2024-04-01\n' >>"$s/data/a.csv"
ok 1 "schema check, a changed file" "$nq" schema check "$s" data/a.csv
has "$w/out" 'line 5: column id: "4" is outside its range' "range row"
has "$w/out" "4 rows, the schema allows 3 to 3" "row count row"
has "$w/err" "schema infer" "and what to do"
ok 1 "schema check --json" "$nq" schema check --json "$s"
has "$w/out" '"check":"schema","ok":false' "json rows"
printf 'a;b\n1;x\n' >"$s/data/c.csv"
ok 0 "schema infer --delim" "$nq" schema infer -d ';' "$s" data/c.csv
has "$w/out" '"delim":";"' "delim kept"
printf 'a,"b\n' >"$s/data/d.csv"
ok 2 "schema infer, bad CSV" "$nq" schema infer "$s" data/d.csv
has "$w/err" "not closed" "bad CSV says why"
printf '{"path":"data/c.csv","kind":"csv","delim":";","rules":[{"kind":"unique","col":"a"},{"kind":"range","col":"a","min":2}]}' \
  >"$w/r.json"
ok 0 "data put a schema with rules" "$nq" data put "$s" schemas "$w/r.json"
ok 1 "schema check rules" "$nq" schema check "$s" data/c.csv
has "$w/out" "ok    rule    data/c.csv: unique(a): holds" "unique holds"
has "$w/out" "range(a): 1 rows fail, the first at line 2" "range fails"
ok 2 "schema nothing" "$nq" schema nothing "$s"

# ---- drift ----

f=$w/dft
mkdir -p "$f/data"
cp "$v/drift/ref.csv" "$f/data/a.csv"
cp "$v/drift/bigref.csv" "$f/data/big.csv"
ok 2 "drift check without summaries" "$nq" drift check "$f"
ok 0 "drift pin" "$nq" drift pin "$f" data/a.csv data/big.csv
ok 0 "drift check, unchanged" "$nq" drift check "$f"
has "$w/out" "OK (" "unchanged passes"
ok 3 "drift check, small sample: warns" "$nq" drift check "$f" \
  "data/a.csv=$v/drift/cur.csv"
has "$w/out" "drift.warn  data/a.csv: x: n 60 then 70; KS D 0.3857 (exact" "KS row"
has "$w/out" "chi-square 19.89 on 4 df" "chi-square row"
ok 1 "drift check --min-n 1: fails" "$nq" drift check --min-n 1 "$f" \
  "data/a.csv=$v/drift/cur.csv"
has "$w/err" "noqtis drift pin" "drift says what to do"
ok 1 "drift check --json" "$nq" drift check --json --min-n 1 "$f" \
  "data/a.csv=$v/drift/cur.csv"
has "$w/out" '"level":"fail"' "json level"
has "$w/out" '"ksexact":true' "json KS"
ok 3 "drift check big, --alpha 0.01" "$nq" drift check --alpha 0.01 "$f" \
  "data/big.csv=$v/drift/bigcur.csv"
has "$w/out" "from the sketch, D within 0.0010" "sketch error said"
ok 0 "drift check --alpha 0" "$nq" drift check --alpha 0 "$f" \
  "data/big.csv=$v/drift/bigcur.csv"
ok 2 "drift check --alpha 2" "$nq" drift check --alpha 2 "$f"
ok 2 "drift check unknown file" "$nq" drift check "$f" data/none.csv
ok 2 "drift cal without =" "$nq" drift cal "$f" data/a.csv
has "$w/err" "give <file>=<file known not to have drifted" "cal says the form"
ok 2 "drift cal, no summary" "$nq" drift cal "$f" "data/none.csv=$v/drift/cur.csv"
has "$w/err" "noqtis drift pin" "cal says how to pin"
ok 2 "drift cal, other columns" "$nq" drift cal "$f" \
  "data/a.csv=$v/cap/data/a.csv"
has "$w/err" "has the reference's columns" "cal refuses another file"
ok 0 "drift cal" "$nq" drift cal "$f" "data/a.csv=$v/drift/ref.csv" \
  "data/a.csv=$v/drift/cur.csv"
has "$w/out" "data/a.csv: calibrated on 2 files known not to have drifted" "cal says what it did"
ok 0 "show: cal recorded" "$nq" data show "$f"
has "$w/out" '"n":2,"p":0.00008379216300369308,"psi":0.7582422554889341}' "cal in the record"
ok 0 "drift check calibrated: no warning" "$nq" drift check "$f" \
  "data/a.csv=$v/drift/cur.csv"
has "$w/out" "calibrated: PSI 0.7582" "the detail says calibrated"
ok 3 "drift check calibrated: a larger shift warns" "$nq" drift check "$f" \
  "data/a.csv=$v/drift/cur2.csv"
printf 'x,c,b\n1,a\n' >"$w/ragged.csv"
ok 1 "drift check ragged" "$nq" drift check "$f" "data/a.csv=$w/ragged.csv"
has "$w/out" "line 2 has 2 fields" "ragged says the line"

# ---- data check recomputes what the record holds ----

ok 0 "data check: summaries recompute" "$nq" data check "$f"
has "$w/out" "data/a.csv: the summaries recompute from the file" "stats row"
cp "$f/data/a.csv" "$w/keepa.csv"
cp "$v/drift/cur.csv" "$f/data/a.csv"
ok 1 "data check: summaries differ" "$nq" data check "$f"
has "$w/out" "data/a.csv: the recorded summaries are not those of the file (column" "stats row fails"
has "$w/err" "noqtis drift pin" "stats row says what to do"
cp "$w/keepa.csv" "$f/data/a.csv"
printf 'a;b\n1;x\n2;y\n3;x\n' >"$f/data/s.csv"
printf '1,x\n2,y\n' >"$f/data/h.csv"
ok 0 "drift pin -d ;" "$nq" drift pin -d ';' "$f" data/s.csv
ok 0 "drift pin --no-header" "$nq" drift pin --no-header "$f" data/h.csv
ok 0 "show: pinned read options" "$nq" data show "$f"
has "$w/out" '"delim":";","path":"data/s.csv"' "stats keeps its delimiter"
has "$w/out" '"header":false,"path":"data/h.csv"' "stats keeps no header"
ok 0 "data check reads them the same way" "$nq" data check "$f"
has "$w/out" "data/s.csv: the summaries recompute" "delimiter used"
has "$w/out" "data/h.csv: the summaries recompute" "no header used"
ok 0 "drift check reads them the same way" "$nq" drift check "$f" \
  data/s.csv data/h.csv
has "$w/out" "data/s.csv: b: n 3 then 3" "drift reads with the delimiter"

k2=$w/rec
mkdir -p "$k2"
ok 0 "rec: init" "$nq" data init "$k2"
printf '{"name":"total","status":"pass","expected":1204,"observed":1203.5,"tol":0.5}' \
  >"$w/c1.json"
ok 0 "rec: put a check within tol" "$nq" data put "$k2" checks "$w/c1.json"
ok 0 "rec: check recomputed, holds" "$nq" data check "$k2"
has "$w/out" "total: pass (observed 1203.5, expected 1204, tolerance 0.5: holds)" "holds"
printf '{"name":"total","status":"pass","expected":1204,"observed":1203.5,"tol":0.4}' \
  >"$w/c1.json"
ok 0 "rec: put a check over tol" "$nq" data put "$k2" checks "$w/c1.json"
ok 1 "rec: pass that does not hold fails" "$nq" data check "$k2"
has "$w/out" "total: recorded as pass, but observed 1203.5 and expected 1204 differ by more than 0.4" "over tol"
printf '{"name":"total","status":"pass","expected":1204,"observed":1203.5}' \
  >"$w/c1.json"
ok 0 "rec: put a check, no tol" "$nq" data put "$k2" checks "$w/c1.json"
ok 1 "rec: no tol is 0" "$nq" data check "$k2"
has "$w/out" "differ by more than 0" "tol 0"
printf '{"name":"total","status":"warn","expected":1204,"observed":1203.5}' \
  >"$w/c1.json"
ok 0 "rec: put a warning" "$nq" data put "$k2" checks "$w/c1.json"
ok 0 "rec: a warning passes" "$nq" data check "$k2"
has "$w/out" "total: warn (observed 1203.5, expected 1204, tolerance 0: does not hold)" "warn row"
printf '{"name":"code","status":"pass","expected":"AB","observed":"Ab"}' \
  >"$w/c2.json"
ok 0 "rec: put a string check" "$nq" data put "$k2" checks "$w/c2.json"
ok 1 "rec: strings differ" "$nq" data check "$k2"
has "$w/out" 'code: recorded as pass, but observed "Ab" is not expected "AB"' "strings"
printf '{"name":"code","status":"pass","expected":"AB","observed":"AB"}' \
  >"$w/c2.json"
ok 0 "rec: put it equal" "$nq" data put "$k2" checks "$w/c2.json"
ok 0 "rec: strings equal" "$nq" data check "$k2"
has "$w/out" "code: pass (observed and expected equal)" "strings equal"
printf '{"name":"t","status":"pass","expected":1,"observed":1,"tol":-1}' \
  >"$w/c3.json"
ok 2 "rec: a negative tol" "$nq" data put "$k2" checks "$w/c3.json"
has "$w/err" "a tolerance is at least 0" "negative tol refused"
printf 'from,to\n1,a\n2,b\n' >"$k2/map.csv"
hm=$("$nq" hash <"$k2/map.csv" | cut -c1-64)
printf '{"kind":"recode","from":"code","to":"label","script":"map.csv","sha256":"%s"}' \
  "$hm" >"$w/s1.json"
ok 0 "rec: put a recode step" "$nq" data put "$k2" steps "$w/s1.json"
ok 0 "rec: the mapping checks" "$nq" data check "$k2"
has "$w/out" "step 1 (recode code -> label): map.csv has its recorded SHA-256" "step row"
printf '3,c\n' >>"$k2/map.csv"
ok 1 "rec: a changed mapping fails" "$nq" data check "$k2"
has "$w/out" "step 1 (recode code -> label): map.csv has SHA-256" "changed step"
has "$w/err" "the script or mapping of a step changed" "step says what to do"
rm "$k2/map.csv"
ok 1 "rec: a missing mapping fails" "$nq" data check "$k2"
has "$w/out" "map.csv missing or unreadable" "missing step"

# ---- diff ----

d1=$w/d1
mkdir -p "$d1/data"
cp "$v/cap/data/a.csv" "$v/cap/data/b.csv" "$d1/data/"
ok 0 "diff: data add" "$nq" data add --url https://example.org/a.csv "$d1" \
  data/a.csv
ok 0 "diff: data add b" "$nq" data add "$d1" data/b.csv
ok 0 "diff: schema" "$nq" schema infer --put "$d1" data/a.csv
ok 0 "diff: seal 1" "$nq" seal -k "$w/k" "$d1"
cp -R "$d1" "$w/d2"
d2=$w/d2
ok 0 "diff: same" "$nq" diff "$d1" "$d2"
has "$w/out" "the same" "diff says the same"
printf '4,dan,1.5,2024-04-01\r\n' >>"$d2/data/a.csv"
printf 'new\n' >"$d2/data/c.txt"
rm "$d2/data/b.csv"
ok 0 "diff: data add again" "$nq" data add --url https://example.org/a2.csv \
  "$d2" data/a.csv
ok 0 "diff: data del b" "$nq" data del "$d2" sources data/b.csv
ok 0 "diff: schema again" "$nq" schema infer --put "$d2" data/a.csv
printf '{"os":"linux","arch":"x86_64"}' >"$w/env.json"
ok 0 "diff: env" "$nq" data put "$d2" env "$w/env.json"
ok 0 "diff: seal 2" "$nq" seal -k "$w/k" "$d2"
ok 1 "diff: differs" "$nq" diff "$d1" "$d2"
has "$w/out" "data/a.csv changed: 89 -> 111 bytes" "file changed"
has "$w/out" "data/b.csv removed" "file removed"
has "$w/out" "data/c.txt added" "file added"
has "$w/out" 'url "https://example.org/a.csv" -> "https://example.org/a2.csv"' "source url"
has "$w/out" 'rows {"max":3,"min":3} -> {"max":4,"min":4}' "schema rows"
has "$w/out" "env.*added" "env added"
ok 1 "diff --json" "$nq" diff --json "$d1" "$d2"
has "$w/out" '"same":false' "json same false"
ok 2 "diff one folder" "$nq" diff "$d1"

# ---- report ----

p=$w/rpt
mkdir -p "$p/data"
printf 'id,code\n1,AB\n2,CD\n' >"$p/data/a.csv"
ok 2 "report: neither sealed nor recorded" "$nq" report "$p"
has "$w/err" "noqtis seal" "report says to seal"
ok 2 "report: not a folder" "$nq" report "$w/nope"
ok 0 "report: data add" "$nq" data add --licence 'CC|BY' "$p" data/a.csv
printf '{"title":"a\\nb|c*d"}' >"$w/rc.json"
ok 0 "report: put cite" "$nq" data put "$p" cite "$w/rc.json"
ok 1 "report: not sealed fails" "$nq" report "$p"
has "$w/out" "Failed.*: 1 of 3 checks failed (not sealed)" "unsealed counts"
has "$w/out" '^- title: a b\\|c\\\*d$' "a line break and markup in a value, escaped once"
has "$w/out" '| CC\\|BY |' "a | in a cell is escaped"
ok 0 "report: seal" "$nq" seal -k "$w/k" "$p"
ok 0 "report" "$nq" report -p "$w/k.pub" "$p"
has "$w/out" "Passed.*: 0 of 24 checks failed" "sealed report passes"
has "$w/out" "^| ok | data.source | data/a.csv: SHA-256 and size match |$" "data rows"
ok 0 "report -f txt -o" "$nq" report -p "$w/k.pub" -f txt -o "$w/r.txt" "$p"
has "$w/r.txt" "^Passed: 0 of 24 checks failed$" "text report to a file"
has "$w/r.txt" "^    title: a b|c\*d$" "text keeps the value on its line"
ok 2 "report -f html" "$nq" report -f html "$p"
has "$w/err" "md or txt" "format refused"
ok 0 "report --json" "$nq" report --json -p "$w/k.pub" "$p"
has "$w/out" '"status":"passed","sealed":true,"total":24,"failed":0,"verified":2,"changed":0' "json counts"
printf '{"name":"50%%\\nx","status":"fail"}' >"$w/rf.json"
ok 0 "report: a failed check" "$nq" data put "$p" checks "$w/rf.json"
ok 1 "report --json --github" "$nq" report --json --github -p "$w/k.pub" "$p"
has "$w/out" '^::error title=noqtis data.recorded::.*/rpt: 50%25%0Ax: fail$' "annotation escaped"
has "$w/out" '^::error title=noqtis file::.*: noqtis.data.json' "changed file annotated"
has "$w/out" '"status":"failed","sealed":true,"total":25,"failed":2,"verified":1,"changed":1' "json counts on failure"
has "$w/out" '"check":"data.recorded","ok":false,"detail":"50%\\u000ax: fail"' "json rows"

# ---- synthetic data ----

y=$w/syn
mkdir -p "$y/data"
ok 0 "syn: init" "$nq" data init "$y"
ok 2 "syn: no seed" "$nq" data syn "$y" data/s.csv
has "$w/err" "give --seed" "syn needs a seed"
ok 2 "syn: no schema" "$nq" data syn --seed 7 "$y" data/s.csv
has "$w/err" "no schema with columns" "syn needs a recipe"
has "$w/err" "schema infer --put" "and says how to make one"
ok 0 "syn: put the recipe" "$nq" data put "$y" schemas "$v/syn/schema.json"
ok 2 "syn: a bad seed" "$nq" data syn --seed 18446744073709551616 "$y" data/s.csv
ok 2 "syn: a bad row count" "$nq" data syn --seed 1 --rows -3 "$y" data/s.csv
# s7.csv was written by tests/vectors/nqd/syn's recipe with seed 7 and
# 16 rows by a separate implementation in Python (hashlib)
ok 0 "syn: seed 7, 16 rows" "$nq" data syn --seed 7 --rows 16 "$y" data/s.csv
same "$y/data/s.csv" "$v/syn/s7.csv" "syn is the reference vector"
ok 0 "syn: marked synthetic" "$nq" data show "$y"
has "$w/out" '"synthetic":true' "syn records the source as synthetic"
ok 0 "syn: data check" "$nq" data check "$y"
has "$w/out" "data/s.csv \[synthetic\]: 16 rows, 6 columns as the schema says" "syn fits its schema"
ok 0 "syn: again, over the synthetic file" "$nq" data syn --seed 7 --rows 16 "$y" data/s.csv
same "$y/data/s.csv" "$v/syn/s7.csv" "the same seed, the same bytes"
ok 0 "syn: rows from the schema" "$nq" data syn --seed 7 "$y" data/s.csv
ok 0 "syn: hash" sh -c '"$1" hash <"$2" >"$3"' sh "$nq" "$y/data/s.csv" "$w/h5"
ok 1 "syn: 5 rows, so not s7" test "$("$nq" hash <"$v/syn/s7.csv")" = "$(cat "$w/h5")"
ok 0 "syn: 3,000 rows" "$nq" data syn --seed 9 --rows 3000 "$y" data/s.csv
ok 0 "syn: 3,000 rows fit the schema" "$nq" schema check "$y"
has "$w/out" "data/s.csv: 3000 rows, 6 columns as the schema says" "every value fits"
# real data is never replaced
cp "$v/cap/data/a.csv" "$y/data/real.csv"
printf '{"path":"data/real.csv","kind":"csv","columns":[{"name":"id","type":"int"}]}' >"$w/rs.json"
ok 0 "syn: a schema for a real file" "$nq" data put "$y" schemas "$w/rs.json"
ok 2 "syn: refuses an unrecorded file" "$nq" data syn --seed 1 "$y" data/real.csv
has "$w/err" "the file is there and not recorded as synthetic" "unrecorded refused"
ok 0 "syn: record the real file" "$nq" data add "$y" data/real.csv
ok 2 "syn: refuses a real source" "$nq" data syn --seed 1 "$y" data/real.csv
has "$w/err" "its source is not marked synthetic" "real source refused"
same "$y/data/real.csv" "$v/cap/data/a.csv" "the real file is untouched"
ok 2 "syn: refuses a path outside" "$nq" data syn --seed 1 "$y" ../x.csv

# ---- seal -r, check -r ----

t=$w/tree
mkdir -p "$t/a/data" "$t/b/inner" "$t/c"
cp "$v/cap/data/b.csv" "$t/a/data/"
ok 0 "-r: data add a" "$nq" data add "$t/a" data/b.csv
printf 'x\n' >"$t/b/inner/f.txt"
ok 0 "-r: data init b" "$nq" data init "$t/b/inner"
printf 'no capsule\n' >"$t/c/g.txt"
ok 0 "seal -r" "$nq" seal -k "$w/k" -r "$t"
has "$w/err" "2 capsules, 2 sealed, 0 failed" "seal -r counts"
ok 1 "c not sealed" test -f "$t/c/noqtis.sig"
ok 0 "check -r" "$nq" check -p "$w/k.pub" -r "$t"
has "$w/err" "2 capsules, 2 OK, 0 failed" "check -r counts"
printf 'y\n' >>"$t/b/inner/f.txt"
ok 1 "check -r, one changed" "$nq" check -p "$w/k.pub" -r "$t"
has "$w/err" "2 capsules, 1 OK, 1 failed" "check -r finds it"
ok 2 "check -r, nothing" "$nq" check -r "$t/c"
has "$w/err" "no capsule under" "check -r says none"

# -r never follows a link: not one inside the tree, not the top folder,
# not a folder that turns into a link after the walk
o=$w/outside
mkdir -p "$o/cap" "$t/l"
printf 'z\n' >"$o/cap/f.txt"
ok 0 "-r: data init outside" "$nq" data init "$o/cap"
ln -s "$o" "$t/l/out"
ok 0 "seal -r with a link inside" "$nq" seal -k "$w/k" -r "$t"
has "$w/err" "2 capsules, 2 sealed, 0 failed" "the link is not descended"
ok 1 "nothing written outside" test -f "$o/cap/noqtis.json"
ok 0 "check -r with a link inside" "$nq" check -p "$w/k.pub" -r "$t"
has "$w/err" "2 capsules, 2 OK, 0 failed" "check -r skips the link"
ln -s "$t" "$w/tlink"
ok 2 "seal -r on a link" "$nq" seal -k "$w/k" -r "$w/tlink"
has "$w/err" "without following links" "a top link is refused"
ok 1 "nothing written through the top link" test -f "$o/cap/noqtis.sig"
# option paths relative to where the tool is run still work
ok 0 "check -r, relative paths" sh -c 'cd "$1" && "$2" check -p k.pub -r tree' \
  sh "$w" "$nq"
if [ -n "$nqt" ]; then
  # the test hook swaps $t/a for a link to $o/cap after the walk
  export NQTESTSWAP="$t/a" NQTESTSWAPTO="$o/cap"
  ok 2 "seal -r, a folder swapped for a link" "$nqt" seal -k "$w/k" -r "$t"
  has "$w/err" "is no longer a folder" "the swapped folder is refused"
  has "$w/err" "2 capsules, 1 sealed, 1 failed" "and counted as failed"
  ok 1 "nothing sealed through the swap" test -f "$o/cap/noqtis.sig"
  ok 1 "nor its manifest" test -f "$o/cap/noqtis.json"
  rm "$t/a"
  mv "$t/a.was" "$t/a"
  ok 2 "check -r, a folder swapped for a link" "$nqt" check -p "$w/k.pub" \
    -r "$t"
  has "$w/err" "is no longer a folder" "check -r refuses it too"
  rm "$t/a"
  mv "$t/a.was" "$t/a"
  unset NQTESTSWAP NQTESTSWAPTO
  ok 0 "check -r after the swaps" "$nq" check -p "$w/k.pub" -r "$t"
fi

# ---- env, commit, reveal, cite ----

e=$w/env
mkdir -p "$e"
printf 'x\n' >"$e/f.txt"
printf '{"R":{"Version":"4.6.2"}}' >"$e/renv.lock"
ok 0 "env" "$nq" env --rng Mersenne-Twister --seed 42 "$e"
ok 0 "env: show" "$nq" data show "$e"
has "$w/out" '"arch":' "env arch"
has "$w/out" '"path":"renv.lock","sha256":"' "env lock found"
has "$w/out" '"rng":{"kind":"Mersenne-Twister","seed":"42"}' "env rng"
ok 2 "env --seed alone" "$nq" env --seed 1 "$e"
ok 2 "env --lock missing" "$nq" env --lock nope.lock "$e"
ok 0 "data check with a lock file" "$nq" data check "$e"
has "$w/out" "renv.lock: SHA-256 matches" "the lock file is checked"
printf '{}' >"$e/renv.lock"
ok 1 "data check, a lock file changed" "$nq" data check "$e"
has "$w/err" "noqtis env" "a changed lock file says what to do"
printf '{"R":{"Version":"4.6.2"}}' >"$e/renv.lock"
printf 'arm,id\nA,1\nB,2\n' >"$w/list.csv"
ok 0 "commit" "$nq" commit --kind randomisation --label trial "$e" \
  "$w/list.csv"
has "$w/err" "keep it secret" "commit says to keep the salt"
ok 0 "commit: salt written" test -f "$w/list.csv.salt"
ok 2 "commit again: salt exists" "$nq" commit "$e" "$w/list.csv"
ok 2 "commit: bad kind" "$nq" commit -f --kind lottery "$e" "$w/list.csv"
ok 0 "reveal" "$nq" reveal "$e" "$w/list.csv" "$w/list.csv.salt"
has "$w/out" "matches commitment 1" "reveal matches"
printf 'arm,id\nB,1\nA,2\n' >"$w/list2.csv"
ok 1 "reveal another list" "$nq" reveal "$e" "$w/list2.csv" \
  "$w/list.csv.salt"
has "$w/err" "not the list or plan recorded" "reveal says why"
ok 2 "cite without cite" "$nq" cite "$e"
has "$w/err" "data put" "cite says how to add one"
printf '{"title":"Example","authors":["A. Author"],"year":2026}' \
  >"$w/cite.json"
ok 0 "put cite" "$nq" data put "$e" cite "$w/cite.json"
ok 0 "cite cff" "$nq" cite "$e"
has "$w/out" "cff-version: 1.2.0" "cff"
ok 0 "cite bibtex" "$nq" cite --format bibtex "$e"
has "$w/out" "@misc{data," "bibtex"
ok 2 "cite bad format" "$nq" cite --format ris "$e"

# ---- bundles: export --as bundle, check <file>, pack unpack ----

b=$w/bnd
mkdir -p "$b/data" "$w/tmp"
printf 'AAAA\n' >"$b/a.txt"
cp "$v/cap/data/a.csv" "$b/data/"
ok 0 "bundle: seal without a record" "$nq" seal -k "$w/k" "$b"
ok 2 "bundle --no-files without a record" "$nq" export --as bundle \
  --no-files -o "$w/b0.nqb" "$b"
has "$w/err" "no data record" "--no-files says the record is needed"
ok 0 "bundle: add a record" "$nq" data add "$b" data/a.csv
ok 0 "bundle: seal" "$nq" seal -k "$w/k" "$b"
ok 0 "export --as bundle" "$nq" export --as bundle -o "$w/b.nqb" "$b"
ok 2 "export --as bundle over a file" "$nq" export --as bundle \
  -o "$w/b.nqb" "$b"
has "$w/err" "force" "over a file names --force"
cp "$w/b.nqb" "$w/b1.nqb"
ok 0 "export --as bundle -f" "$nq" export --as bundle -f -o "$w/b.nqb" "$b"
same "$w/b.nqb" "$w/b1.nqb" "a bundle is the same bytes each time"
ok 2 "export --as bundle to stdout" "$nq" export --as bundle "$b"
ok 2 "--no-files elsewhere" "$nq" export --as intoto --no-files "$b"
TMPDIR=$w/tmp
export TMPDIR
ok 0 "check a bundle" "$nq" check -p "$w/k.pub" "$w/b.nqb"
has "$w/out" "b.nqb: OK" "the bundle checks, named as given"
has "$w/out" "data/a.csv" "its files are checked"
ok 0 "check a bundle --json" "$nq" check --json -p "$w/k.pub" "$w/b.nqb"
has "$w/out" '"ok":true' "json"
ok 0 "export --no-files" "$nq" export --as bundle --no-files \
  -o "$w/lean.nqb" "$b"
ok 0 "check a bundle without its files" "$nq" check -p "$w/k.pub" \
  "$w/lean.nqb"
has "$w/out" "partial" "a partial check, which the report says"
has "$w/out" "noqtis.data.json" "the record is checked"
dd if="$w/b.nqb" bs=100 count=1 2>/dev/null >"$w/cut.nqb"
ok 1 "check a cut bundle" "$nq" check "$w/cut.nqb"
has "$w/err" "ends" "a cut bundle says where it ends"
printf 'hello\n' >"$w/junk.nqb"
ok 2 "check a file that is not a bundle" "$nq" check "$w/junk.nqb"
has "$w/err" "not a folder" "junk is neither a folder nor a bundle"
# a.txt is the first entry: its bytes start at 16 + 2 + 5 + 8
cp "$w/b.nqb" "$w/t.nqb"
printf 'Z' | dd of="$w/t.nqb" bs=1 seek=31 conv=notrunc 2>/dev/null
ok 1 "check a bundle with a changed file" "$nq" check -p "$w/k.pub" \
  "$w/t.nqb"
has "$w/out" "FAIL  file" "the changed file fails"
# paths that would leave the folder: ../x, /x, C:x
for p in '\000\004../x' '\000\002/x' '\000\003C:x'; do
  { printf 'noqtis-bundle-1\n'; printf "$p"
    printf '\000\000\000\000\000\000\000\001x\000\000'; } >"$w/evil.nqb"
  ok 1 "check refuses $p" "$nq" check "$w/evil.nqb"
  has "$w/err" "not a path a capsule holds" "the path is named as refused"
done
ok 1 "nothing left the folder" test -e "$w/tmp/x"
ok 0 "check leaves nothing in TMPDIR" test -z "$(ls -A "$w/tmp")"
unset TMPDIR

# ---- pack: unpack, init, build, check ----

ok 0 "pack unpack" "$nq" pack unpack "$w/b.nqb" "$w/u"
ok 0 "check the unpacked folder" "$nq" check -p "$w/k.pub" "$w/u"
ok 2 "pack unpack into a folder that is there" "$nq" pack unpack \
  "$w/b.nqb" "$w/u"
has "$w/err" "must not exist" "unpack never writes into a folder"
ok 1 "pack unpack a cut bundle" "$nq" pack unpack "$w/cut.nqb" "$w/u2"
ok 1 "a cut bundle leaves no folder" test -e "$w/u2"
for p in '\000\004../x' '\000\002/x' '\000\003C:x'; do
  { printf 'noqtis-bundle-1\n'; printf "$p"
    printf '\000\000\000\000\000\000\000\001x\000\000'; } >"$w/evil.nqb"
  ok 1 "pack unpack refuses $p" "$nq" pack unpack "$w/evil.nqb" "$w/u3"
  has "$w/err" "not a path a capsule holds" "the path is named as refused"
  ok 1 "nothing of $p is written" test -e "$w/u3"
done
ok 1 "nothing left the folder" test -e "$w/x"
p=$w/proj
ok 0 "pack init -t r" "$nq" pack init -t r "$p"
ok 0 "pack init made R/" test -d "$p/R"
ok 0 "pack init made data/" test -d "$p/data"
has "$p/README.md" "renv.lock" "the README names the lock file"
ok 2 "pack init twice" "$nq" pack init "$p"
has "$w/err" "already has a data record" "init twice says so"
ok 2 "pack init, unknown template" "$nq" pack init -t cobol "$w/p2"
has "$w/err" "plain, r or python" "the templates are listed"
ok 0 "pack init python" "$nq" pack init --template python "$w/py"
ok 0 "pack init python made src/" test -d "$w/py/src"
cp "$v/cap/data/a.csv" "$p/data/"
printf '{"R":{"Version":"4.6.2"}}\n' >"$p/renv.lock"
ok 0 "pack: data add" "$nq" data add "$p" data/a.csv
ok 1 "pack check before build" "$nq" pack check "$p"
has "$w/out" "not ready to ship" "unsealed is not ready"
ok 2 "pack build --no-files without -o" "$nq" pack build -k "$w/k" \
  --no-files "$p"
ok 2 "pack build without a key" "$nq" pack build "$p"
ok 0 "pack build" "$nq" pack build -k "$w/k" -o "$w/p.nqb" "$p"
has "$w/out" "bundle written" "build writes the bundle"
ok 0 "pack check the bundle" "$nq" pack check -p "$w/k.pub" "$w/p.nqb"
has "$w/out" "renv.lock: SHA-256 matches" "the lock file is checked"
has "$w/out" "1 lock files recorded" "the lock file is counted"
has "$w/out" "ready to ship" "the bundle is ready"
ok 0 "pack check the folder" "$nq" pack check -p "$w/k.pub" "$p"
ok 0 "check the pack bundle" "$nq" check -p "$w/k.pub" "$w/p.nqb"
printf '{"R":{"Version":"4.6.3"}}\n' >"$p/renv.lock"
ok 0 "pack: seal again without env" "$nq" seal -k "$w/k" "$p"
ok 1 "pack check, lock changed after env" "$nq" pack check -p "$w/k.pub" \
  "$p"
has "$w/out" "renv.lock: SHA-256 is" "the changed lock file fails"
has "$w/err" "noqtis env" "and says to record it again"
ok 0 "pack build again" "$nq" pack build -k "$w/k" "$p"
ok 0 "pack check after build" "$nq" pack check -p "$w/k.pub" "$p"
ok 0 "pack build python, no lock" "$nq" pack build -k "$w/k" "$w/py"
ok 1 "pack check without a lock file" "$nq" pack check "$w/py"
has "$w/out" "0 lock files recorded" "no lock file fails"
ok 2 "pack nothing" "$nq" pack nothing
ok 0 "help pack" "$nq" help pack
has "$w/out" "noqtis pack build" "help lists build"

# ---- chunk: pin, check, a piece ----

k=$w/cnk
mkdir -p "$k"
i=0
while [ $i -lt 200 ]; do
  echo "line $i of a file read in pieces" >>"$k/big.txt"
  i=$((i + 1))
done
ok 0 "chunk pin" "$nq" chunk pin --size 1024 "$k" big.txt
ok 0 "chunk: show" "$nq" data show "$k"
has "$w/out" '"chunk":1024' "the chunk size is recorded"
ok 0 "chunk check" "$nq" chunk check "$k" big.txt
has "$w/out" "chunks 0 to" "every chunk matches"
dd if="$k/big.txt" of="$w/piece" bs=1024 skip=2 count=2 2>/dev/null
ok 0 "chunk check a piece" "$nq" chunk check --at 2048 "$k" big.txt \
  "$w/piece"
has "$w/out" "chunks 2 to 3" "the piece's chunks match"
ok 1 "chunk check a piece at the wrong place" "$nq" chunk check --at 1024 \
  "$k" big.txt "$w/piece"
has "$w/err" "chunk pin" "a differing chunk says what to do"
ok 1 "chunk check, not a chunk's start" "$nq" chunk check --at 5 "$k" \
  big.txt "$w/piece"
ok 2 "chunk check --at without a piece" "$nq" chunk check --at 0 "$k" \
  big.txt
ok 2 "chunk check --at not a number" "$nq" chunk check --at x "$k" \
  big.txt "$w/piece"
ok 2 "chunk pin --size too small" "$nq" chunk pin --size 10 "$k" big.txt
ok 2 "chunk pin a missing file" "$nq" chunk pin "$k" none.txt
ok 2 "chunk check, no chunks recorded" "$nq" chunk check "$k" none.txt
has "$w/err" "chunk pin" "no chunks says how to pin them"
ok 0 "data check with chunks" "$nq" data check "$k"
ok 0 "chunk: seal" "$nq" seal -k "$w/k" "$k"
mv "$k/big.txt" "$w/big.txt"
ok 0 "the record checks without the file" "$nq" check -p "$w/k.pub" \
  --only noqtis.data.json "$k"
ok 0 "and a piece against it" "$nq" chunk check --at 2048 "$k" big.txt \
  "$w/piece"
printf 'x' >>"$w/big.txt"
mv "$w/big.txt" "$k/big.txt"
ok 1 "chunk check, a changed file" "$nq" chunk check --json "$k" big.txt
has "$w/out" '"check":"chunk","ok":false' "json rows"
ok 1 "data check, a changed file" "$nq" data check "$k"
ok 2 "chunk nothing" "$nq" chunk nothing

# ---- chain ----

ok 0 "chain: second key" "$nq" keygen -a ML-DSA-44 -o "$w/k2"
for i in 1 2 3 4 5; do
  mkdir -p "$w/l$i"
  echo "$i" >"$w/l$i/f"
done
ok 0 "chain: start" "$nq" seal --format 2 -k "$w/k" "$w/l1"
ok 0 "chain: link 2" "$nq" seal -k "$w/k" --input prev="$w/l1" "$w/l2"
ok 0 "chain: link 3" "$nq" seal -k "$w/k" --input prev="$w/l2" "$w/l3"
ok 0 "chain" "$nq" chain -p "$w/k.pub" "$w/l1" "$w/l2" "$w/l3"
has "$w/out" "OK (5 checks passed)" "every link, the key and the head"
has "$w/out" "head" "the head is given"
ok 0 "chain --json" "$nq" chain --json "$w/l1" "$w/l2" "$w/l3"
has "$w/out" '"check":"head","ok":true' "json head"
ok 0 "chain from the middle" "$nq" chain "$w/l2" "$w/l3"
has "$w/out" "not part of what is checked" "the first link's inputs"
ok 1 "chain with a gap" "$nq" chain "$w/l1" "$w/l3"
has "$w/out" "a fork, or links out of order" "the gap is found"
ok 1 "chain out of order" "$nq" chain "$w/l2" "$w/l1"
ok 1 "chain, another key" "$nq" chain -p "$w/k2.pub" "$w/l1" "$w/l2"
ok 0 "chain: link by another key" "$nq" seal -k "$w/k2" \
  --input prev="$w/l3" "$w/l4"
ok 1 "chain with a link by another key" "$nq" chain "$w/l1" "$w/l2" \
  "$w/l3" "$w/l4"
has "$w/out" "sealed by another key" "the key row fails"
ok 0 "chain: two inputs" "$nq" seal -k "$w/k" --input a="$w/l3" \
  --input b="$w/l2" "$w/l5"
ok 1 "chain with a link of two inputs" "$nq" chain "$w/l1" "$w/l2" \
  "$w/l3" "$w/l5"
has "$w/out" "2 inputs" "two inputs are refused"
echo changed >"$w/l2/f"
ok 1 "chain with a changed link" "$nq" chain "$w/l1" "$w/l2" "$w/l3"
has "$w/out" "does not check" "the changed link fails"
ok 2 "chain, not a folder" "$nq" chain "$w/none"
ok 2 "chain, nothing" "$nq" chain
ok 0 "help chain" "$nq" help chain

ok 0 "help data" "$nq" help data
has "$w/out" "noqtis data check" "help lists check"
ok 2 "data nothing" "$nq" data nothing "$c"

echo "tdcli: $n checks, $bad failed"
[ "$bad" = 0 ]
