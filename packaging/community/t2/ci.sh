#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds the noqtis T2 package the way T2 builds packages, inside a T2
# userland (as root, in a container made from a T2 ISO's root file system):
# the T2 tree is the one mounted at /t2, the noqtis tree at /nq.
#   sh /nq/packaging/community/t2/ci.sh
# It checks the .desc with T2's Check-PkgFormat, fetches the release tarball
# from its [D] URL with T2's Download (which checks the [D] checksum), builds
# and installs the package and the build dependencies its .cache names with
# Emerge-Pkg, then the package again with SDECFG_DO_CHECK (for it alone), so that the build
# runs the noqtis tests (NQFAST, NQSLSUB and CTEST_PARALLEL_LEVEL reach
# them), and uses the installed package (tests/consumer).
set -eu
s=/usr/src/t2-src
p=/nq/packaging/community/t2/package/security/noqtis

# a T2 install runs this as the ca-certificates postinstall step
update-ca-certificates >/dev/null 2>&1
cp -a /t2/. "$s/"
# the ExactBuild makefiles are an svn:externals of the T2 tree, which its
# git mirror lacks; T2's Config builds its Lua accelerator with them
[ -f "$s/misc/luabash/build/top.make" ] ||
  svn export -q https://svn.exactcode.de/exact-build/trunk/build@75 \
    "$s/misc/luabash/build"
# cmake.desc bootstraps with its configure script when no cmake is
# installed (runconf), but build_this_package tries CMake first while
# runcmake=1, so cmake does not build on a T2 system without cmake (the
# ISO's); this is the one change made to the T2 tree, and a T2 bug
c=$s/package/develop/cmake/cmake.desc
grep -q '^type -p cmake >/dev/null && runconf=0$' "$c"
sed -i 's|^type -p cmake >/dev/null && runconf=0$|& \|\| runcmake=0|' "$c"
mkdir -p "$s/package/security/noqtis"
cp "$p"/* "$s/package/security/noqtis/"
cd "$s"

echo "== Check-PkgFormat"
out=$(scripts/Check-PkgFormat noqtis)
if [ -n "$out" ]; then
  echo "$out"
  exit 1
fi

echo "== Config"
scripts/Config -oldconfig >/dev/null
scripts/Config PARALLEL="$(nproc)"
grep -q ' noqtis ' config/default/packages

echo "== Download (the [D] URL, not a mirror)"
scripts/Download -mirror none noqtis
ls -l download/mirror/n/noqtis-*

echo "== Emerge-Pkg noqtis (and the build dependencies its .cache names)"
gcc --version | head -n 1
scripts/Emerge-Pkg -optional-deps=no -parallel 1 noqtis
# the .cache this build wrote, against the shipped one
cat /var/adm/cache/noqtis
grep '^\[DEP\]' "$p/noqtis.cache" > /tmp/dep.old
grep '^\[DEP\]' /var/adm/cache/noqtis > /tmp/dep.new
diff /tmp/dep.old /tmp/dep.new || echo "the build's [DEP] lines differ from noqtis.cache"

echo "== Emerge-Pkg noqtis again, with its tests (SDECFG_DO_CHECK)"
scripts/Config DO_CHECK=1
scripts/Emerge-Pkg -optional-deps=no -parallel 1 -force noqtis
log=$(ls /var/adm/logs/*-noqtis.log)
grep -E 'tests passed|Running make test' "$log"
head -n 3 /var/adm/packages/noqtis
grep -v ' var/adm/' /var/adm/flists/noqtis

echo "== use"
noqtis --version
sh /nq/tests/consumer/run.sh /usr /tmp/use
echo "== t2 package ok"

# T2 builds with -O2 or -Os (SDECFG_OPT) and its wrapper drops -Werror, so
# the tree under test is also built here with -Werror at both, by T2's gcc
for o in O2 Os; do
  echo "== this tree, -$o -Werror"
  cmake -S /nq -B "/tmp/$o" -DCMAKE_BUILD_TYPE=None -DCMAKE_C_FLAGS="-$o" \
    -DNQSHARED=ON -DNQWERROR=ON >/dev/null
  cmake --build "/tmp/$o" -j"$(nproc)"
  ctest --test-dir "/tmp/$o" -j"$(nproc)" --output-on-failure
done
echo "== t2 ok"
