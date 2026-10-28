#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Makes noqtis-<version>.tar.gz from the source tree it is run in, laid out
# like the GitHub release tarball (one top directory noqtis-<version>/).
# In a git checkout it takes the tracked and untracked files git does not
# ignore; elsewhere every file except .git and build directories.
#   packaging/tarball.sh <out dir>     prints the tarball's path
set -eu
out=$(mkdir -p "${1:-.}" && cd "${1:-.}" && pwd)
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
n=noqtis-$v
t=$(mktemp -d)
mkdir "$t/$n"
if git -c safe.directory='*' rev-parse --git-dir >/dev/null 2>&1; then
  # shellcheck disable=SC2016
  git -c safe.directory='*' ls-files -co --exclude-standard -z |
    xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\n" "$f"; done' sh |
    tar -cf - -T - | tar -xf - -C "$t/$n"
else
  tar -cf - --exclude=./.git --exclude='./build*' . | tar -xf - -C "$t/$n"
fi
tar -C "$t" -czf "$out/$n.tar.gz" "$n"
rm -rf "$t"
echo "$out/$n.tar.gz"
