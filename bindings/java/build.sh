#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds the Java binding with no build tool and no downloads: the shared
# library (CMake, -DNQSHARED=ON) and noqtis.jar (javac and jar, JDK 22 or
# later), all under build/ (or $NQJB). Then, with "test", runs the tests;
# with "examples", the three examples. The library is passed to Java as
# -Dnoqtis.library, so nothing is installed. With "bundled", the jar also
# carries the library (native/<os>-<arch>/, as the Maven Central jar does)
# and the tests run with no library given, so they use that copy.
#   sh build.sh [test] [examples] [bundled]
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
    run -cp "$b/noqtis.jar$sep$b/eclasses" CardExample
    ;;
  bundled)
    case $(uname -s) in
    Linux) os=linux f=libnoqtis.so ;;
    Darwin) os=macos f=libnoqtis.dylib ;;
    MINGW* | MSYS* | CYGWIN*) os=windows f=noqtis-0.dll ;;
    *) echo "build.sh: no bundled name for $(uname -s)" >&2; exit 2 ;;
    esac
    case $(uname -m) in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "build.sh: no bundled name for $(uname -m)" >&2; exit 2 ;;
    esac
    rm -rf "$b/bclasses"
    cp -R "$b/classes" "$b/bclasses"
    mkdir -p "$b/bclasses/native/$os-$arch"
    cp -L "$lib" "$b/bclasses/native/$os-$arch/$f"
    jar --create --file "$b/noqtis-bundled.jar" -C "$b/bclasses" .
    test -d "$b/tclasses" || {
      echo "build.sh: run the test step before bundled" >&2
      exit 2
    }
    # no -Dnoqtis.library and no NOQTIS_LIBRARY: the jar's own copy
    env -u NOQTIS_LIBRARY java --enable-native-access=ALL-UNNAMED \
      -Dnoqtis.repo=../.. -cp "$b/noqtis-bundled.jar$sep$b/tclasses" \
      io.github.rootcoder007.noqtis.Tests
    ;;
  *)
    echo "build.sh: unknown step $w (test, examples, bundled)" >&2
    exit 2
    ;;
  esac
done
