#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The notice of a newer release (cli/upd.c). The kept answer decides most
# of it, so most checks need no network; the two that ask accept either
# end, an answer or none. POSIX sh only (runs under busybox).
#   tests/cli/upd.sh <noqtis>
set -u
nq=$1
case $nq in /*) ;; *) nq=$(pwd)/$nq ;; esac
w=${TMPDIR:-/tmp}/nqupd.$$
rm -rf "$w"
mkdir -p "$w/noqtis" || exit 2
trap 'rm -rf "$w"' EXIT INT TERM
f=$w/noqtis/update
n=0
bad=0
unset CI NOQTIS_NO_UPDATE_CHECK NOQTIS_UPDATE_CHECK
XDG_CACHE_HOME=$w
export XDG_CACHE_HOME
now=$(date +%s)

# is <what> <got> <want>
is() {
  n=$((n + 1))
  [ "$2" = "$3" ] && return 0
  bad=$((bad + 1))
  echo "FAIL $1: got '$2', want '$3'"
}
# the lines of the notice a command wrote to standard error (variables
# for it go through env: one set before a shell function does not reach
# the commands in it in every sh)
said() { "$@" 2>&1 >/dev/null | grep -c 'is available'; }

# a kept answer of today, newer than this version: said when asked for
# away from a terminal, in two lines, and the answer is left as it was
echo "$now 999.0.1" >"$f"
NOQTIS_UPDATE_CHECK=1 "$nq" algs >/dev/null 2>"$w/err"
is "status with the notice" "$?" 0
is "lines of the notice" "$(wc -l <"$w/err" | tr -d ' ')" 2
is "the newer version" "$(grep -c '^noqtis: version 999.0.1 is available (this is ' "$w/err")" 1
is "how to stop it" "$(grep -c '^noqtis: NOQTIS_NO_UPDATE_CHECK=1 stops this notice.$' "$w/err")" 1
is "kept answer unchanged" "$(cat "$f")" "$now 999.0.1"
# standard output is the command's alone
is "stdout untouched" "$(NOQTIS_UPDATE_CHECK=1 "$nq" algs 2>/dev/null | grep -c 'is available')" 0

# not at a terminal, under CI, or turned off: nothing
is "away from a terminal" "$(said "$nq" algs)" 0
is "CI without the force" "$(said env CI=true "$nq" algs)" 0
is "CI with the force" "$(said env CI=true NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 1
is "NOQTIS_UPDATE_CHECK=0" "$(said env NOQTIS_UPDATE_CHECK=0 "$nq" algs)" 0
is "NOQTIS_NO_UPDATE_CHECK wins" "$(said env NOQTIS_NO_UPDATE_CHECK=1 NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0
# never after help or version, nor after a command that failed
is "after version" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" version)" 0
is "after help" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" help)" 0
is "after a failure" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" hash "$w/none")" 0

# a kept answer that is this version, or an older one: nothing
v=$("$nq" version | cut -d' ' -f2)
echo "$now $v" >"$f"
is "the same version" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0
echo "$now 0.0.1" >"$f"
is "an older version" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0
# 0.10 is later than 0.9: numbers, not text
echo "$now 0.0.0.1" >"$f"
is "more parts, still older" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0

# anything else in the file is never shown; it is asked again and the
# file rewritten with the time and the answer (or none, without network)
echo "x; rm -rf y" >"$f"
is "junk is not shown" "$(said env NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0
t=$(cut -d' ' -f1 "$f")
n=$((n + 1))
{ [ "$t" -ge "$now" ] 2>/dev/null && [ "$t" -le $((now + 120)) ]; } ||
  { bad=$((bad + 1)); echo "FAIL rewritten time: '$(cat "$f")'"; }
n=$((n + 1))
grep -Eq '^[0-9]+ ([0-9]+(\.[0-9]+)*)?$' "$f" ||
  { bad=$((bad + 1)); echo "FAIL rewritten form: '$(cat "$f")'"; }
# an answer older than a day is asked again; one from a clock ahead too
echo "1 999.0.1" >"$f"
NOQTIS_UPDATE_CHECK=1 "$nq" algs >/dev/null 2>&1
n=$((n + 1))
[ "$(cut -d' ' -f1 "$f")" -ge "$now" ] || { bad=$((bad + 1)); echo "FAIL old answer kept"; }
echo "$((now + 999999)) 999.0.1" >"$f"
NOQTIS_UPDATE_CHECK=1 "$nq" algs >/dev/null 2>&1
n=$((n + 1))
[ "$(cut -d' ' -f1 "$f")" -le $((now + 120)) ] || { bad=$((bad + 1)); echo "FAIL answer from a clock ahead kept"; }

# no cache directory to be had: nothing, and status 0
is "no place to keep it" "$(said env XDG_CACHE_HOME='' HOME='' NOQTIS_UPDATE_CHECK=1 "$nq" algs)" 0
# a cache directory made on first use
rm -rf "$w/new"
XDG_CACHE_HOME=$w/new NOQTIS_UPDATE_CHECK=1 "$nq" algs >/dev/null 2>&1
n=$((n + 1))
[ -f "$w/new/noqtis/update" ] || { bad=$((bad + 1)); echo "FAIL cache directory not made"; }

# version --check: one line on standard output and status 0 with an
# answer; one line on standard error and status 1 without
"$nq" version --check >"$w/out" 2>"$w/err"
s=$?
n=$((n + 1))
case $s in
0) [ "$(wc -l <"$w/out" | tr -d ' ')" = 1 ] && grep -Eq '^noqtis [0-9.]+ is (up to date|available )' "$w/out" && [ ! -s "$w/err" ] ||
  { bad=$((bad + 1)); echo "FAIL --check answer: $(cat "$w/out" "$w/err")"; } ;;
1) grep -q '^noqtis version: the latest release could not be asked for' "$w/err" && [ ! -s "$w/out" ] ||
  { bad=$((bad + 1)); echo "FAIL --check without an answer: $(cat "$w/out" "$w/err")"; } ;;
*) bad=$((bad + 1)); echo "FAIL --check status $s" ;;
esac
# its usage errors
"$nq" version --check extra >/dev/null 2>&1
is "version --check extra" "$?" 2
"$nq" version --nope >/dev/null 2>&1
is "version --nope" "$?" 2

echo "upd.sh: $n checks, $bad failed"
[ "$bad" -eq 0 ]
