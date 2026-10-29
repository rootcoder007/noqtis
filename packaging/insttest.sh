#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Tests install.sh against fake releases served on localhost (see
# fakerel.sh): a good install (latest and a pinned version, piped into sh
# as with curl | sh), then cases that must be refused with nothing
# installed: a tampered archive, an archive missing from SHA256SUMS, a
# required but absent (or failing) cosign check, a non-https base URL.
# Run from the source root:
#   packaging/insttest.sh <dist dir> <work dir>
# <dist dir> holds this machine's release archive(s) from dist.sh.
# Environment: NQPORT (8471), PY (python3).
set -eu
[ $# -eq 2 ] || { echo "usage: packaging/insttest.sh <dist dir> <work dir>" >&2; exit 2; }
dist=$(cd "$1" && pwd)
w=$2
py=${PY:-python3}
port=${NQPORT:-8471}
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
rm -rf "$w"
mkdir -p "$w/srv"
w=$(cd "$w" && pwd)
# a release key for the fake releases, trusted through NOQTIS_SSHKEY
ssh-keygen -q -t ed25519 -N "" -C test -f "$w/tk"
NQTESTKEY=$w/tk
NOQTIS_SSHKEY="noqtis $(cut -d' ' -f1,2 "$w/tk.pub")"
export NQTESTKEY NOQTIS_SSHKEY
for m in ok tamper nosum; do
  packaging/fakerel.sh "$dist" "$w/srv/$m" "$m" > /dev/null
done

"$py" -m http.server "$port" --bind 127.0.0.1 --directory "$w/srv" \
  > "$w/http.log" 2>&1 &
srv=$!
trap 'kill "$srv" 2>/dev/null || true' EXIT
i=0
until curl -fs "http://127.0.0.1:$port/ok/latest/download/SHA256SUMS" >/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 50 ] || { echo "the test server did not start" >&2; cat "$w/http.log" >&2; exit 1; }
  sleep 0.2
done
url=http://127.0.0.1:$port
fail=0

# must pass: <name> <prefix> <command...>
pass() {
  n=$1 p=$2
  shift 2
  if "$@" > "$w/$n.log" 2>&1 && "$p/bin/noqtis" version | grep -qx "noqtis $v"; then
    echo "ok   $n"
  else
    echo "FAIL $n (should have installed)"; cat "$w/$n.log"; fail=1
  fi
}
# must be refused, leaving no noqtis in the prefix: <name> <prefix> <text> <command...>
refuse() {
  n=$1 p=$2 t=$3
  shift 3
  if "$@" > "$w/$n.log" 2>&1; then
    echo "FAIL $n (should have been refused)"; cat "$w/$n.log"; fail=1
  elif [ -e "$p/bin/noqtis" ]; then
    echo "FAIL $n (refused, but left $p/bin/noqtis)"; cat "$w/$n.log"; fail=1
  elif ! grep -q "$t" "$w/$n.log"; then
    echo "FAIL $n (refused without saying \"$t\")"; cat "$w/$n.log"; fail=1
  else
    echo "ok   $n (refused: $t)"
  fi
}

if command -v cosign >/dev/null 2>&1; then hascosign=1; else hascosign=0; fi

if [ "$hascosign" = 0 ]; then
  # as with curl -fsSL .../install.sh | sh
  pass latest "$w/p1" sh -c "NOQTIS_BASE='$url/ok' NOQTIS_PREFIX='$w/p1' sh < install.sh"
  grep -q "cosign not found" "$w/latest.log" ||
    { echo "FAIL latest (no word that cosign was skipped)"; fail=1; }
  pass pinned "$w/p2" env NOQTIS_BASE="$url/ok" \
    sh install.sh --prefix "$w/p2" --version "v$v"
  refuse needcosign "$w/p3" "cosign is not installed" \
    env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p3" NOQTIS_COSIGN=1 sh install.sh
else
  # cosign is here, and the fake release has no Sigstore bundle: refuse
  refuse nobundle "$w/p1" "sigstore.json cannot be downloaded" \
    env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p1" sh install.sh
  # a bundle that is not a valid signature of these sums: refuse
  cp -R "$w/srv/ok" "$w/srv/badsig"
  for d in "$w/srv/badsig/latest/download" "$w/srv/badsig/download/v$v"; do
    printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' \
      > "$d/SHA256SUMS.sigstore.json"
  done
  refuse badsig "$w/p3" "does not verify" \
    env NOQTIS_BASE="$url/badsig" NOQTIS_PREFIX="$w/p3" sh install.sh
  pass skipsig "$w/p2" env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p2" \
    NOQTIS_COSIGN=0 sh install.sh --version "$v"
  grep -q "is NOT checked" "$w/skipsig.log" ||
    { echo "FAIL skipsig (no word that the signature was skipped)"; fail=1; }
fi
if [ "$(uname -s)" = Linux ] && ls "$dist"/noqtis-*-shared.tar.gz >/dev/null 2>&1; then
  pass shared "$w/p4" env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p4" \
    NOQTIS_COSIGN=0 sh install.sh --shared
  [ -f "$w/p4/lib/libnoqtis.so.0" ] || { echo "FAIL shared (no libnoqtis.so.0)"; fail=1; }
fi
refuse tamper "$w/p5" "SHA-256 mismatch" \
  env NOQTIS_BASE="$url/tamper" NOQTIS_PREFIX="$w/p5" NOQTIS_COSIGN=0 sh install.sh
refuse tamperpin "$w/p6" "SHA-256 mismatch" \
  env NOQTIS_BASE="$url/tamper" NOQTIS_PREFIX="$w/p6" NOQTIS_COSIGN=0 \
  sh install.sh --version "$v"
refuse nosum "$w/p7" "lists no" \
  env NOQTIS_BASE="$url/nosum" NOQTIS_PREFIX="$w/p7" NOQTIS_COSIGN=0 sh install.sh
refuse plainhttp "$w/p8" "must be an https URL" \
  env NOQTIS_BASE="http://example.com/releases" NOQTIS_PREFIX="$w/p8" sh install.sh
# "localhost:" as user info names another host: refused
refuse userinfo "$w/p10" "must be an https URL" \
  env NOQTIS_BASE="http://localhost:@127.0.0.2:$port/ok" NOQTIS_PREFIX="$w/p10" \
  NOQTIS_COSIGN=0 sh install.sh
# the SSH signature: missing, or by another key, is refused
cp -R "$w/srv/ok" "$w/srv/nossh"
rm -f "$w/srv/nossh/latest/download/SHA256SUMS.sig" "$w/srv/nossh/download/v$v/SHA256SUMS.sig"
refuse nossh "$w/p11" "SHA256SUMS.sig cannot be downloaded" \
  env NOQTIS_BASE="$url/nossh" NOQTIS_PREFIX="$w/p11" NOQTIS_COSIGN=0 sh install.sh
ssh-keygen -q -t ed25519 -N "" -C other -f "$w/tk2"
refuse otherkey "$w/p12" "SSH signature of SHA256SUMS does not verify" \
  env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p12" NOQTIS_COSIGN=0 \
  NOQTIS_SSHKEY="noqtis $(cut -d' ' -f1,2 "$w/tk2.pub")" sh install.sh
pass noverify "$w/p13" env NOQTIS_BASE="$url/nossh" NOQTIS_PREFIX="$w/p13" \
  NOQTIS_COSIGN=0 NOQTIS_VERIFY=0 sh install.sh
grep -q "who signed this release is NOT checked" "$w/noverify.log" ||
  { echo "FAIL noverify (no word that the SSH check was skipped)"; fail=1; }
grep -q "SSH signature: good" "$w/pinned.log" 2>/dev/null || [ "$hascosign" = 1 ] ||
  { echo "FAIL pinned (no word that the SSH signature was checked)"; fail=1; }
refuse noversion "$w/p9" "cannot download SHA256SUMS" \
  env NOQTIS_BASE="$url/ok" NOQTIS_PREFIX="$w/p9" NOQTIS_COSIGN=0 \
  sh install.sh --version 9.9.9

[ "$fail" = 0 ] && echo "install.sh: every case passed"
exit "$fail"
