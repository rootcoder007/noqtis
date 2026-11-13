#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The tool's data-layer commands, as a user runs them: exit codes,
# outputs, the files written, and every refusal saying what to do.
# POSIX sh only (runs under busybox).
#   tests/nqd/cli.sh <noqtis> <tests dir>
set -u
nq=$1
td=$2
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

same() {
  n=$((n + 1))
  if ! cmp -s "$1" "$2"; then
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
printf 'x,c,b\n1,a\n' >"$w/ragged.csv"
ok 1 "drift check ragged" "$nq" drift check "$f" "data/a.csv=$w/ragged.csv"
has "$w/out" "line 2 has 2 fields" "ragged says the line"

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

ok 0 "help data" "$nq" help data
has "$w/out" "noqtis data check" "help lists check"
ok 2 "data nothing" "$nq" data nothing "$c"

echo "tdcli: $n checks, $bad failed"
[ "$bad" = 0 ]
