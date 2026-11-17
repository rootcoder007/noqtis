#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The one-minute demo behind docs/demo.svg: make a key, pin a table's
# schema, seal the folder, check it (passes), change one file, check again
# (fails), put it back, then a delivery whose table no longer fits its
# schema, and what the capsule says of itself. Every command really runs,
# in a fresh temporary folder; the prompt and the typing are only paced for
# reading. Usage: sh docs/demo/demo.sh [path to noqtis] (default: noqtis on
# PATH). NQFAST=1 skips the pauses. To record:
#   python3 docs/demo/rec.py demo.cast sh docs/demo/demo.sh [noqtis]
#   svg-term --in demo.cast --out docs/demo.svg --window --no-cursor \
#     --padding 12                                     (svg-term-cli 2.1.1)
# rec.py writes the cast 92 columns by 24 rows, with one more output event
# (" ") 5 s after the last, so the final frame holds before the loop.
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
say "a folder of results: a table and a report"
run "mkdir results && printf 'id,score\\n1,0.42\\n2,0.57\\n3,0.61\\n' > results/scores.csv" 0.3
run "echo 'r = 0.42' > results/report.txt" 0.4
say "pin the table's schema (columns, types, ranges) in the capsule's data record"
run "noqtis data init results && noqtis schema infer --ranges --put results scores.csv" 0.8
say "seal it: writes noqtis.json and noqtis.sig into the folder"
run "noqtis seal -k me results"
say "check it"
run "noqtis check -p me.pub results | tail -4" 2
say "change one character of one file"
run "sed -i.bak 's/0.42/0.43/' results/report.txt && rm results/report.txt.bak" 0.6
run "noqtis check -p me.pub results | grep -E 'FAIL|results:'" 1.5
run "noqtis check -p me.pub results > /dev/null; echo \"exit status \$?\"" 2
say "put it back; then a new delivery of the table, with a score that is no number"
run "echo 'r = 0.42' > results/report.txt" 0.3
run "printf 'id,score\\n1,0.42\\n2,high\\n3,0.61\\n' > results/scores.csv" 0.4
run "noqtis schema check results 2>&1 | head -3" 2.5
say "what the capsule says of itself"
run "noqtis inspect results | head -6" 3
