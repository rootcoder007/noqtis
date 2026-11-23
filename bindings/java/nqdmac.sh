#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# macOS: makes a copy of libnqd.dylib look for libnoqtis beside itself
# (@loader_path/libnoqtis.dylib), as the two lie in the folder the jar
# unpacks them to; the build's copy names it by @rpath, which a user's
# machine does not have. The changed file is signed again (ad hoc), which
# arm64 requires. Elsewhere the script does nothing: on Linux and Windows
# the loader takes the libnoqtis already loaded, by its name.
#   sh nqdmac.sh <libnqd.dylib>
set -eu
f=${1:?usage: nqdmac.sh <libnqd.dylib>}
test "$(uname -s)" = Darwin || exit 0
dep=$(otool -L "$f" | awk '/libnoqtis/ { print $1; exit }')
test -n "$dep" || {
  echo "nqdmac.sh: $f does not name libnoqtis" >&2
  exit 1
}
install_name_tool -change "$dep" @loader_path/libnoqtis.dylib "$f"
codesign --force --sign - "$f"
otool -L "$f" | grep -F @loader_path/libnoqtis.dylib > /dev/null
