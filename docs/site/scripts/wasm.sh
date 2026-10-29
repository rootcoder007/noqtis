#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Copies the WebAssembly build of the npm package (bindings/npm: lib/index.js,
# dist/noqtis.js, dist/noqtis.wasm) and the sample capsule
# (tests/vectors/cap/sample) into public/, for the page that checks a
# capsule in the browser (demo.mdx). The site serves them itself: the page
# loads nothing from anywhere else. Runs before `npm run build`. Without
# the WebAssembly build (sh bindings/npm/build.sh) it leaves it out with a
# note and the page says it is missing; NQWASM=1 makes that an error (CI).
set -eu
site=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$site/../.." && pwd)
npm="$root/bindings/npm"
pub="$site/public"
rm -rf "$pub/wasm" "$pub/sample.json"
if [ -f "$npm/dist/noqtis.wasm" ] && [ -f "$npm/dist/noqtis.js" ]; then
  mkdir -p "$pub/wasm/lib" "$pub/wasm/dist"
  cp "$npm/lib/index.js" "$pub/wasm/lib/"
  cp "$npm/dist/noqtis.js" "$npm/dist/noqtis.wasm" "$pub/wasm/dist/"
  cp "$root/LICENSE" "$root/NOTICE" "$pub/wasm/"
elif [ "${NQWASM:-}" = 1 ]; then
  echo "wasm.sh: $npm/dist/noqtis.wasm is missing (sh bindings/npm/build.sh)" >&2
  exit 1
else
  echo "wasm.sh: no WebAssembly build in $npm/dist; the browser check" \
    "page will say it is missing (sh bindings/npm/build.sh to add it)" >&2
fi
# the sample capsule as one file, {"<path>": "<base64>", ...}: a static
# server need not serve its empty or extension-less files
NQCAP="$root/tests/vectors/cap/sample" node -e '
const fs = require("fs"), path = require("path");
const top = process.env.NQCAP, out = {};
const walk = (d, p) => {
  for (const n of fs.readdirSync(d).sort()) {
    const f = path.join(d, n), q = p ? p + "/" + n : n;
    if (fs.statSync(f).isDirectory()) walk(f, q);
    else out[q] = fs.readFileSync(f).toString("base64");
  }
};
walk(top, "");
process.stdout.write(JSON.stringify(out));
' > "$pub/sample.json"
