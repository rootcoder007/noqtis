#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The CMAKE_CROSSCOMPILING_EMULATOR of the Android job: runs a test
# program on the device adb talks to and exits with its status.
#   adb.sh <source root> <build dir> <program> [args...]
# Before the first test, the job pushes <source root>/tests to $NQDEV/tests
# (default /data/local/tmp/nq). The program runs there, as ctest runs it
# in tests/ on the host; arguments under the host's tests/ or build dir
# are mapped to the device's copies; NQ* variables are passed on, and
# TMPDIR is $NQDEV/tmp.
set -eu
src=$1
bld=$2
prog=$3
shift 3
dev=${NQDEV:-/data/local/tmp/nq}
name=$(basename "$prog")

# q <word>: the word quoted for the device's sh
q() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# map <arg>: a host path under tests/ or the build dir as the device sees it
map() {
  case $1 in
  "$src"/tests/*) printf '%s' "$dev/tests/${1#"$src"/tests/}" ;;
  "$bld"/*) printf '%s' "$dev/b/${1#"$bld"/}" ;;
  *) printf '%s' "$1" ;;
  esac
}

# a per-test copy of the program, so tests can run in parallel
bin=$dev/bin/$name.$$
adb push "$prog" "$bin" > /dev/null 2>&1 || {
  echo "adb.sh: cannot push $name" >&2
  exit 1
}
cmd="mkdir -p $dev/tmp $dev/b"
for a in "$@"; do
  m=$(map "$a")
  case $m in
  "$dev"/b/*) cmd="$cmd && mkdir -p $(q "$(dirname "$m")")" ;;
  esac
done
cmd="$cmd && cd $dev/tests && chmod 755 $bin && env TMPDIR=$dev/tmp"
for v in $(env | sed -n 's/^\(NQ[A-Z0-9_]*\)=.*/\1/p'); do
  [ "$v" = NQDEV ] && continue
  val=
  eval "val=\${$v}"
  cmd="$cmd $v=$(q "$val")"
done
cmd="$cmd $bin"
for a in "$@"; do
  cmd="$cmd $(q "$(map "$a")")"
done
# the status comes back on the last line, whatever adb itself returns
out=$(mktemp)
adb shell "$cmd; echo nqrc=\$?; rm -f $bin" > "$out" 2>&1 || true
rc=$(sed -n 's/^nqrc=\([0-9]*\).*$/\1/p' "$out" | tail -n 1)
sed '/^nqrc=[0-9]*/d' "$out"
rm -f "$out"
[ -n "$rc" ] || rc=1
exit "$rc"
