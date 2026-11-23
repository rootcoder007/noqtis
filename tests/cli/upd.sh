#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# `noqtis version --check` (cli/upd.c): it asks the network, so both ends
# pass, an answer or none; and no other command asks or says anything of
# a newer release. POSIX sh only (runs under busybox).
#   tests/cli/upd.sh <noqtis>
set -u
nq=$1
case $nq in /*) ;; *) nq=$(pwd)/$nq ;; esac
w=${TMPDIR:-/tmp}/nqupd.$$
rm -rf "$w"
mkdir -p "$w" || exit 2
trap 'rm -rf "$w"' EXIT INT TERM
n=0
bad=0

# is <what> <got> <want>
is() {
  n=$((n + 1))
  [ "$2" = "$3" ] && return 0
  bad=$((bad + 1))
  echo "FAIL $1: got '$2', want '$3'"
}

# a command that did its work writes nothing to standard error, and keeps
# nothing in the cache directory
XDG_CACHE_HOME=$w/cache
export XDG_CACHE_HOME
"$nq" algs >/dev/null 2>"$w/err"
is "algs: status" "$?" 0
is "algs: standard error" "$(wc -c <"$w/err" | tr -d ' ')" 0
n=$((n + 1))
[ ! -e "$w/cache" ] || { bad=$((bad + 1)); echo "FAIL something was kept in the cache directory"; }

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
