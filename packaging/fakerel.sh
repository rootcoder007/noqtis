#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Lays out a fake GitHub release for testing install.sh and install.ps1
# before (or without) a real one: <root>/download/v<version>/ and
# <root>/latest/download/, each with the archives in <dist dir>, the two
# install scripts and SHA256SUMS. Serve <root> over http on localhost and
# point NOQTIS_BASE at it. No signature bundle is made: keyless Sigstore
# signing needs the release workflow's identity.
#
#   packaging/fakerel.sh <dist dir> <root> <mode>
#
# <mode>  ok      archives as built, sums that match
#         tamper  each archive changed by one appended byte after the
#                 sums were taken (an installer must refuse it)
#         nosum   SHA256SUMS without the archives (must be refused)
set -eu
[ $# -eq 3 ] || { echo "usage: packaging/fakerel.sh <dist dir> <root> <mode>" >&2; exit 2; }
dist=$1
root=$2
mode=$3
case $mode in ok|tamper|nosum) ;; *) echo "fakerel.sh: bad mode $mode" >&2; exit 2 ;; esac
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
d=$root/download/v$v
mkdir -p "$d"
cp "$dist"/noqtis-* "$d/"
cp install.sh install.ps1 "$d/"

sum() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
  else shasum -a 256 "$1"; fi
}
(
  cd "$d"
  : > SHA256SUMS.new
  for f in noqtis-* install.sh install.ps1; do
    case $mode-$f in nosum-noqtis-*) continue ;; esac
    sum "$f" >> SHA256SUMS.new
  done
  mv SHA256SUMS.new SHA256SUMS
  if [ "$mode" = tamper ]; then
    for f in noqtis-*; do printf 'x' >> "$f"; done
  fi
)
mkdir -p "$root/latest/download"
cp "$d"/* "$root/latest/download/"
echo "$root"
