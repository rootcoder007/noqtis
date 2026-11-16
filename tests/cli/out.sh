#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The tool's outputs when they cannot be finished: an output file cut by
# a signal is never left under its name, and a command whose standard
# output cannot be written fails. POSIX sh only (runs under busybox).
#   tests/cli/out.sh <noqtis> <tests dir>
set -u
nq=$1
td=$2
case $nq in /*) ;; *) nq=$(pwd)/$nq ;; esac
w=${TMPDIR:-/tmp}/nqout.$$
rm -rf "$w"
mkdir -p "$w" || exit 2
trap 'rm -rf "$w"' EXIT INT TERM
n=0
bad=0

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

# no <path> <what>: nothing is at path
no() {
  n=$((n + 1))
  if [ -e "$1" ] || [ -h "$1" ]; then
    bad=$((bad + 1))
    echo "FAIL $2: $(basename "$1") is there" >&2
  fi
}

# notmp <dir> <what>: no temporary output name (.noqtis.<hex>.tmp) is
# left in dir
notmp() {
  n=$((n + 1))
  if ls -a "$1" | grep -q '^\.noqtis\.[0-9a-f]\{16\}\.tmp$'; then
    bad=$((bad + 1))
    echo "FAIL $2: a temporary name is left:" >&2
    ls -a "$1" >&2
  fi
}

# same <file> <file> <what>: the two hold the same bytes (by the tool's
# own digest: a small container image has no cmp)
same() {
  n=$((n + 1))
  if [ ! -r "$1" ] || [ ! -r "$2" ] ||
    [ "$("$nq" hash <"$1")" != "$("$nq" hash <"$2")" ]; then
    bad=$((bad + 1))
    echo "FAIL $3: $1 and $2 differ" >&2
  fi
}

# started <dir> <name>: the output, under its name or a temporary one,
# has been created (up to 10 s)
started() {
  i=0
  while [ $i -lt 100 ]; do
    for t in "$1/$2" "$1"/.noqtis.*.tmp; do
      [ -e "$t" ] && return 0
    done
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

ok 0 "keygen" "$nq" keygen -a ML-KEM-512 -o "$w/k"
i=0
while [ $i -lt 200 ]; do
  echo "line $i of a plaintext boxed in 1 KiB chunks" >>"$w/p"
  i=$((i + 1))
done
ok 0 "box" "$nq" box -p "$w/k.pub" --chunk 1024 -o "$w/b" "$w/p"
sz=$(wc -c <"$w/b")
part=$((sz - 1500))

# ---- an output cut by a signal (H1) ----

# unbox from a FIFO that gives all but the last chunks, then waits: the
# output has begun when the signal comes, and cannot have ended, so its
# name must not be there after it
for s in TERM HUP; do
  d=$w/u$s
  mkdir "$d"
  mkfifo "$d/f"
  "$nq" unbox -k "$w/k" -o "$d/o" "$d/f" 2>"$d/err" &
  pid=$!
  exec 3>"$d/f"
  dd if="$w/b" bs="$part" count=1 2>/dev/null >&3
  n=$((n + 1))
  if ! started "$d" o; then
    bad=$((bad + 1))
    echo "FAIL unbox SIG$s: no output began" >&2
  fi
  kill -s "$s" $pid
  wait $pid
  exec 3>&-
  no "$d/o" "unbox cut by SIG$s leaves no output"
  notmp "$d" "unbox cut by SIG$s"
done

# box from a FIFO, the same
d=$w/bx
mkdir "$d"
mkfifo "$d/f"
"$nq" box -p "$w/k.pub" --chunk 1024 -o "$d/o" "$d/f" 2>"$d/err" &
pid=$!
exec 3>"$d/f"
dd if="$w/p" bs=4096 count=1 2>/dev/null >&3
n=$((n + 1))
if ! started "$d" o; then
  bad=$((bad + 1))
  echo "FAIL box SIGTERM: no output began" >&2
fi
kill -s TERM $pid
wait $pid
exec 3>&-
no "$d/o" "box cut by SIGTERM leaves no output"
notmp "$d" "box cut by SIGTERM"

# a stream that fails part way leaves nothing either, and an output
# that is whole has its name and nothing beside it
dd if="$w/b" bs="$part" count=1 2>/dev/null >"$w/cut"
ok 2 "unbox a cut stream" "$nq" unbox -k "$w/k" -o "$w/o1" "$w/cut"
no "$w/o1" "a failed unbox leaves no output"
ok 0 "unbox" "$nq" unbox -k "$w/k" -o "$w/o2" "$w/b"
n=$((n + 1))
if [ "$("$nq" hash <"$w/o2")" != "$("$nq" hash <"$w/p")" ]; then
  bad=$((bad + 1))
  echo "FAIL unbox: the output is not the plaintext" >&2
fi
notmp "$w" "a finished output"
# never over a file without --force, never through a link
ok 2 "unbox over a file" "$nq" unbox -k "$w/k" -o "$w/o2" "$w/b"
ln -s "$w/elsewhere" "$w/o3"
ok 2 "unbox to a link" "$nq" unbox -k "$w/k" -o "$w/o3" "$w/b"
no "$w/elsewhere" "the link is not followed"
ok 0 "unbox --force over a link" "$nq" unbox -f -k "$w/k" -o "$w/o3" "$w/b"
no "$w/elsewhere" "--force replaces the link, not its target"
n=$((n + 1))
if [ -h "$w/o3" ]; then
  bad=$((bad + 1))
  echo "FAIL unbox --force: the link is still there" >&2
fi
notmp "$w" "outputs replaced"

# a folder renamed while the output is written: the temporary file goes
# with it, and is removed there all the same
d=$w/mv
mkdir -p "$d/sub"
mkfifo "$d/f"
"$nq" unbox -k "$w/k" -o "$d/sub/o" "$d/f" 2>"$d/err" &
pid=$!
exec 3>"$d/f"
dd if="$w/b" bs="$part" count=1 2>/dev/null >&3
n=$((n + 1))
if ! started "$d/sub" o; then
  bad=$((bad + 1))
  echo "FAIL unbox into a renamed folder: no output began" >&2
fi
mv "$d/sub" "$d/moved"
exec 3>&-
wait $pid
notmp "$d/moved" "unbox into a folder renamed meanwhile"

# ---- outputs written by the library, folders, and pairs ----

ok 0 "keygen a signature key" "$nq" keygen -a ML-DSA-44 -o "$w/sk"
c=$w/cp
mkdir -p "$c"
i=0
while [ $i -lt 300 ]; do
  echo "line $i of a file in a capsule, long enough to pass 1 KiB" >>"$c/a"
  i=$((i + 1))
done
ok 0 "data init" "$nq" data init "$c"
ok 0 "seal" "$nq" seal -k "$w/sk" "$c"
mkdir -p "$w/nr"
echo b >"$w/nr/b"
ok 0 "seal one without a record" "$nq" seal -k "$w/sk" "$w/nr"

# report -o: never over a file or through a link without --force, and
# never a cut report (N1)
echo precious >"$w/pr"
cp "$w/pr" "$w/pr0"
ok 2 "report -o over a file" "$nq" report -p "$w/sk.pub" -o "$w/pr" "$c"
same "$w/pr" "$w/pr0" "the file is kept"
echo victim >"$w/vi"
cp "$w/vi" "$w/vi0"
ln -s "$w/vi" "$w/rl"
ok 2 "report -o to a link" "$nq" report -p "$w/sk.pub" -o "$w/rl" "$c"
same "$w/vi" "$w/vi0" "the link's target is kept"
ok 0 "report -o --force over a link" "$nq" report --force -p "$w/sk.pub" \
  -o "$w/rl" "$c"
same "$w/vi" "$w/vi0" "--force replaces the link, not its target"
n=$((n + 1))
if [ -h "$w/rl" ] || ! grep -q "noqtis report" "$w/rl"; then
  bad=$((bad + 1))
  echo "FAIL report --force: not a report in place of the link" >&2
fi
d=$w/rp
mkdir "$d"
ok 153 "report -o over ulimit -f" sh -c 'ulimit -f 1; exec "$@"' sh \
  "$nq" report -p "$w/sk.pub" -o "$d/r.md" "$c"
no "$d/r.md" "a cut report is not left"
notmp "$d" "report -o over ulimit -f"

# two outputs: the first is not named until the second is written (N4)
d=$w/two
mkdir "$d"
ok 0 "keygen a KEM key" "$nq" keygen -a ML-KEM-768 -o "$d/kk"
mkdir "$d/ss"
ok 2 "enc, the secret's name a folder" "$nq" enc -p "$d/kk.pub" -f \
  -o "$d/ct" "$d/ss"
no "$d/ct" "enc leaves no ciphertext without its secret"
notmp "$d" "enc that fails"
ok 0 "keygen" "$nq" keygen -a ML-DSA-44 -o "$d/me"
cp "$d/me" "$d/me0"
rm "$d/me.pub"
mkdir "$d/me.pub"
ok 2 "keygen -f, the public key's name a folder" "$nq" keygen -a ML-DSA-44 \
  -f -o "$d/me"
same "$d/me" "$d/me0" "the old secret key is kept"
notmp "$d" "keygen that fails"
rmdir "$d/me.pub"
ok 0 "keygen -f" "$nq" keygen -a ML-DSA-44 -f -o "$d/me"
ok 0 "the pair is new" test -f "$d/me.pub"
n=$((n + 1))
if [ "$("$nq" hash <"$d/me")" = "$("$nq" hash <"$d/me0")" ]; then
  bad=$((bad + 1))
  echo "FAIL keygen -f: the secret key was not replaced" >&2
fi

# ---- standard output that cannot be written (M4) ----

# full <command...>: with standard output on /dev/full the command fails
# with exit 2 and says why
full() {
  n=$((n + 1))
  "$nq" "$@" >/dev/full 2>"$w/err"
  got=$?
  if [ "$got" != 2 ] || ! grep -q "cannot write to stdout" "$w/err"; then
    bad=$((bad + 1))
    echo "FAIL $* >/dev/full: exit $got, expected 2 and a message" >&2
    sed 's/^/  err: /' "$w/err" >&2
  fi
}

if [ -w /dev/full ]; then
  ok 0 "keygen a signature key" "$nq" keygen -a ML-DSA-44 -o "$w/s"
  printf 'a message\n' >"$w/m"
  ok 0 "sign" "$nq" sign -k "$w/s" "$w/m"
  c=$w/cap
  mkdir -p "$c/data"
  printf 'a,b\n1,x\n2,y\n3,z\n' >"$c/data/a.csv"
  ok 0 "data add" "$nq" data add "$c" data/a.csv
  ok 0 "schema infer --put" "$nq" schema infer --put "$c" data/a.csv
  ok 0 "drift pin" "$nq" drift pin "$c" data/a.csv
  ok 0 "seal" "$nq" seal -k "$w/s" "$c"
  ok 0 "idcard" "$nq" idcard -k "$w/s" --name Example
  cp "$w/out" "$w/card.json"
  full verify -p "$w/s.pub" -s "$w/m.sig" "$w/m"
  full check -p "$w/s.pub" "$c"
  full check -j -p "$w/s.pub" "$c"
  full inspect "$c"
  full report -p "$w/s.pub" "$c"
  full report -j -p "$w/s.pub" "$c"
  full data show "$c"
  full data show -j "$c"
  full data check "$c"
  full schema infer "$c" data/a.csv
  full schema check "$c"
  full drift check "$c"
  full idcard --verify "$w/card.json"
  full algs
  full version
  full --version
  full selftest
  full help
  full --help
  # a failed check on an unwritable output is 2 too, as hash does
  printf 'x' >>"$c/data/a.csv"
  full check -p "$w/s.pub" "$c"
fi

if [ $bad -gt 0 ]; then
  echo "out.sh: $bad of $n checks failed" >&2
  exit 1
fi
echo "out.sh: $n checks passed"
