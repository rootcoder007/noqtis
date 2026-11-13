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

ok 0 "help data" "$nq" help data
has "$w/out" "noqtis data check" "help lists check"
ok 2 "data nothing" "$nq" data nothing "$c"

echo "tdcli: $n checks, $bad failed"
[ "$bad" = 0 ]
