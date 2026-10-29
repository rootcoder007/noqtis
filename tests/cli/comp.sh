#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Checks the shell completions (cli/completions/): each parses in its own
# shell where that shell is installed, and the bash one offers every
# command and every option the manual pages list.
#   tests/cli/comp.sh <source root>
set -eu
top=$1
c=$top/cli/completions
fail=0
bash -n "$c/noqtis.bash" || fail=1
if command -v zsh >/dev/null 2>&1; then zsh -n "$c/_noqtis" || fail=1; fi
if command -v fish >/dev/null 2>&1; then fish -n "$c/noqtis.fish" || fail=1; fi
for m in "$top"/man/noqtis-*.1; do
  cmd=$(basename "$m" .1)
  cmd=${cmd#noqtis-}
  for f in "$c/noqtis.bash" "$c/_noqtis" "$c/noqtis.fish"; do
    grep -q "$cmd" "$f" || { echo "comp: $cmd missing in $f"; fail=1; }
  done
  # the options in the SYNOPSIS: ".Fl x" and ".Fl -long"
  for o in $(sed -n '/^\.Sh SYNOPSIS/,/^\.Sh DESCRIPTION/p' "$m" |
    grep -o 'Fl -*[a-zA-Z][a-zA-Z-]*' | sed 's/^Fl /-/' | sort -u); do
    grep -q -- "$o\\b" "$c/noqtis.bash" ||
      { echo "comp: $cmd option $o missing in noqtis.bash"; fail=1; }
  done
done
[ "$fail" = 0 ] && echo "comp: ok"
exit "$fail"
