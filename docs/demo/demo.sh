#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The 30-second demo behind docs/demo.svg: make a key, seal a folder,
# check it (passes), change one file, check again (fails). Every command
# really runs, in a fresh temporary folder; the prompt and the typing are
# only paced for reading. Usage: sh docs/demo/demo.sh [path to noqtis]
# (default: noqtis on PATH). NQFAST=1 skips the pauses. To record:
#   asciinema rec -i 2 -c 'sh docs/demo/demo.sh' demo.cast   (asciinema 2.4)
#   svg-term --in demo.cast --out docs/demo.svg --window --no-cursor \
#     --padding 12                                     (svg-term-cli 2.1.1)
# with the cast's header set to width 92, height 24, and one more output
# event (" ") 5 s after the last, so the final frame holds before the loop.
set -eu
NQ=${1:-noqtis}
NQ=$(command -v "$NQ")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cd "$T"
noqtis() { "$NQ" "$@"; }

nap() { [ -n "${NQFAST:-}" ] || sleep "$1"; }

# run <command> [pause]: show it typed at a prompt, then run it
run() {
  printf '\033[1;32m$\033[0m '
  s=$1
  while [ -n "$s" ]; do
    r=${s#?}
    printf '%s' "${s%"$r"}"
    s=$r
    nap 0.03
  done
  printf '\n'
  nap 0.3
  eval "$1" || true
  nap "${2:-1.2}"
}

say() {
  printf '\033[2m# %s\033[0m\n' "$1"
  nap 0.6
}

clear 2> /dev/null || true
say "make a post-quantum key pair"
run "noqtis keygen -a ML-DSA-65 -o me"
say "a folder of results"
run "mkdir results && echo 'a,b' > results/in.csv && echo 'r = 0.42' > results/report.txt" 0.4
say "seal it: writes noqtis.json and noqtis.sig into the folder"
run "noqtis seal -k me results"
say "check it"
run "noqtis check -p me.pub results | tail -5" 2
say "change one character of one file"
run "sed -i.bak 's/0.42/0.43/' results/report.txt && rm results/report.txt.bak" 0.6
run "noqtis check -p me.pub results | grep -E 'FAIL|results:'" 1.5
run "noqtis check -p me.pub results > /dev/null; echo \"exit status \$?\"" 3
