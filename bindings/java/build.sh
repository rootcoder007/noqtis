#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds the Java binding with no build tool and no downloads: the shared
# library (CMake, -DNQSHARED=ON) and noqtis.jar (javac and jar, JDK 22 or
# later), all under build/ (or $NQJB). Then, with "test", runs the tests;
# with "examples", the two examples. The library is passed to Java as
# -Dnoqtis.library, so nothing is installed.
#   sh build.sh [test] [examples]
set -eu

cd "$(dirname "$0")"
b=${NQJB:-build}
j=${NQJOBS:-2}
mkdir -p "$b"

cmake -S ../.. -B "$b/lib" -DCMAKE_BUILD_TYPE=Release -DNQSHARED=ON \
  -DNQTESTS=OFF -DNQCLI=OFF -DNQMAN=OFF >"$b/cmake.log"
cmake --build "$b/lib" --config Release -j "$j" >>"$b/cmake.log"

lib=
for f in "$b/lib/libnoqtis.so" "$b/lib/libnoqtis.dylib" \
  "$b/lib/Release/noqtis-0.dll" "$b/lib/noqtis-0.dll" "$b/lib/libnoqtis-0.dll"; do
  if test -f "$f"; then
    lib=$f
    break
  fi
done
test -n "$lib" || {
  echo "build.sh: no shared library in $b/lib" >&2
  exit 2
}

# ';' between class path entries on Windows
case $(uname -s) in
MINGW* | MSYS* | CYGWIN*) sep=';' ;;
*) sep=':' ;;
esac

rm -rf "$b/classes" "$b/tclasses" "$b/eclasses"
# the source lists are split into words on purpose: no path has a space
# shellcheck disable=SC2046
javac --release 22 -Xlint:all -Werror -d "$b/classes" \
  $(find src/main/java -name '*.java' | sort)
jar --create --file "$b/noqtis.jar" -C "$b/classes" .
echo "build.sh: $b/noqtis.jar and $lib"

run() {
  java --enable-native-access=ALL-UNNAMED -Dnoqtis.library="$lib" "$@"
}

for w in "$@"; do
  case $w in
  test)
    # shellcheck disable=SC2046
    javac --release 22 -Xlint:all -Werror -cp "$b/noqtis.jar" -d "$b/tclasses" \
      $(find src/test/java -name '*.java' | sort)
    run -Dnoqtis.repo=../.. -cp "$b/noqtis.jar$sep$b/tclasses" \
      io.github.rootcoder007.noqtis.Tests
    ;;
  examples)
    javac --release 22 -Xlint:all -Werror -cp "$b/noqtis.jar" -d "$b/eclasses" \
      examples/*.java
    run -cp "$b/noqtis.jar$sep$b/eclasses" SignExample
    run -cp "$b/noqtis.jar$sep$b/eclasses" SealExample
    ;;
  *)
    echo "build.sh: unknown step $w (test, examples)" >&2
    exit 2
    ;;
  esac
done
