#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Checks that every file naming the release version names the one in
# CMakeLists.txt, so that a release commit cannot leave a binding, a
# package recipe or a test on the previous version. Given a tag (vX.Y.Z),
# also checks that the tag is that version. The community recipes are not
# checked: they carry the release archive's hash, so they change after it.
#   sh packaging/vercheck.sh [vX.Y.Z]
set -eu

cd "$(dirname "$0")/.."
v=$(sed -n 's/^project(noqtis VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
[ -n "$v" ] || { echo "vercheck: no version in CMakeLists.txt" >&2; exit 1; }
maj=${v%%.*}
r=${v#*.}
min=${r%%.*}
pat=${r#*.}
bad=0

# has FILE TEXT: FILE holds TEXT as a fixed string
has() {
  if ! grep -qF -- "$2" "$1"; then
    echo "vercheck: $1 lacks: $2" >&2
    bad=1
  fi
}

if [ "$#" -gt 0 ] && [ "$1" != "v$v" ]; then
  echo "vercheck: tag $1, but CMakeLists.txt says $v" >&2
  bad=1
fi

for h in include/noqtis.h bindings/go/csrc/include/noqtis.h \
  bindings/r/src/include/noqtis.h; do
  has "$h" "#define NQVMAJ $maj"
  has "$h" "#define NQVMIN $min"
  has "$h" "#define NQVPAT $pat"
done
j=bindings/java/src
q=io/github/rootcoder007/noqtis
has CITATION.cff "version: $v"
has tests/tcore.c "strcmp(nqver(), \"$v\")"
has flake.nix "version = \"$v\";"
has bindings/go/noqtis.go "\"$v\""
has bindings/go/noqtis_test.go "Version() != \"$v\""
has "$j/main/java/$q/Noqtis.java" "@return \"$v\""
has "$j/test/java/$q/Tests.java" "eq(Noqtis.version(), \"$v\""
has bindings/npm/lib/index.js "\"$v\""
has bindings/npm/package.json "\"version\": \"$v\""
has bindings/npm/test/api.test.js "version(), '$v'"
has bindings/npm/test/cjs.test.cjs "nq.version(), '$v'"
has bindings/r/DESCRIPTION "Version: $v"
has bindings/rust/Cargo.toml "version = \"$v\""
has bindings/rust/src/lib.rs "\"$v\""
has packaging/alpine/APKBUILD "pkgver=$v"
has packaging/arch/PKGBUILD "pkgver=$v"
has packaging/brew/noqtis.rb "/v$v/noqtis-$v.tar.gz"
has packaging/rpm/noqtis.spec "Version:        $v"
has packaging/void/template "version=$v"
has packaging/wolfi/melange.yaml "version: $v"
has packaging/wolfi/melange.yaml "libnoqtis.so.$v"

# package-lock.json names the package's version twice: at the top and
# under ""
n=$(grep -cF "\"version\": \"$v\"" bindings/npm/package-lock.json || :)
if [ "${n:-0}" -lt 2 ]; then
  echo "vercheck: bindings/npm/package-lock.json is not at $v" >&2
  bad=1
fi
# the newest entry of each changelog is this version
for f in NEWS.md bindings/r/NEWS.md; do
  top=$(grep -m 1 '^# noqtis ' "$f" || :)
  if [ "$top" != "# noqtis $v" ]; then
    echo "vercheck: $f starts with \"$top\"" >&2
    bad=1
  fi
done
top=$(sed -n '1s/^noqtis (\([^)]*\)).*/\1/p' packaging/debian/changelog)
if [ "$top" != "$v-1" ]; then
  echo "vercheck: packaging/debian/changelog starts with $top" >&2
  bad=1
fi

# the Gentoo ebuild carries the version in its file name (PV), not inside
eb=$(ls packaging/gentoo/*.ebuild 2>/dev/null)
if [ "$eb" != "packaging/gentoo/noqtis-$v.ebuild" ]; then
  echo "vercheck: the Gentoo ebuild is $eb, not packaging/gentoo/noqtis-$v.ebuild" >&2
  bad=1
fi

# pkgs.yml builds the community recipes, so it names their version (which
# moves after the release, with the archive hashes), not CMakeLists.txt's
cv=$(sed -n 's/^pkgver=//p' packaging/community/aur/PKGBUILD)
for w in $(grep -oE '(noqtis[-/]|--version )[0-9]+\.[0-9]+\.[0-9]+' \
    .github/workflows/pkgs.yml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u); do
  if [ "$w" != "$cv" ]; then
    echo "vercheck: .github/workflows/pkgs.yml names $w, the community recipes $cv" >&2
    bad=1
  fi
done

# the T2 package names that version too, in [V] and in its [D] file and URL;
# its checksum is checked against the download by T2's own Download in pkgs.yml
t2=packaging/community/t2/package/security/noqtis/noqtis.desc
has "$t2" "[V] $cv"
has "$t2" " noqtis-$cv.tar.gz https://github.com/rootcoder007/noqtis/releases/download/v$cv/"

[ "$bad" = 0 ] || exit 1
echo "vercheck: $v everywhere"
