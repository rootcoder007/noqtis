#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Records the terminal sessions the home page replays (src/data/demos.json) from a built
# noqtis: every line shown on the page is this program's real output.
#   sh scripts/demos.sh <path to the noqtis binary>
set -eu
N=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
out=$(cd "$(dirname "$0")/.." && pwd)/src/data/demos.json
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; cd "$W"
export SOURCE_DATE_EPOCH=1767225600
txt=$W/demos.txt; : > "$txt"
sec() { echo "@@ $1" >> "$txt"; }
r() { printf '$ noqtis' >> "$txt"; for a in "$@"; do case "$a" in *" "*) printf ' "%s"' "$a" >> "$txt";; *) printf ' %s' "$a" >> "$txt";; esac; done; echo >> "$txt"; "$N" "$@" >> "$txt" 2>&1 || true; }
sh_() { echo "\$ $*" >> "$txt"; sh -c "$*" >> "$txt" 2>&1 || true; }
mkdir results; printf 'id,score\n1,0.91\n2,0.87\n' > results/scores.csv; printf 'Model A beats B.\n' > results/report.txt
sec seal; r keygen -a ML-DSA-65 -o me; r seal -k me results; r check -p me.pub results
sec tamper; sh_ "echo oops >> results/report.txt"; r check -p me.pub results
sec algs; r algs
mkdir study; printf 'id,score\n1,0.91\n' > study/scores.csv; printf 'private notes\n' > study/notes.txt; printf 'summary\n' > study/report.txt
"$N" seal --format 2 -k me study >/dev/null 2>&1
sec prove; r prove -p me.pub -o report.proof study report.txt; sh_ "grep -c notes.txt report.proof"; r check -p me.pub --proof report.proof study
sec idcard; r idcard -k me --name "Josiah Carberry" --orcid https://orcid.org/0000-0002-1825-0097 --affil "Brown University" -o me.card
r idcard --verify me.card; r check --card me.card results
sec rotate; r keygen -a ML-DSA-65 -o new; r rotate -k me -n new --at 2025-12-01T00:00:00Z --reason "laptop replaced" -o rot.json
sh_ "rm study/noqtis.json study/noqtis.sig"; r seal --format 2 -k new study; r check -p me.pub --keys rot.json study
sec export; r export --as rocrate -p new.pub study
python3 - "$txt" "$out" <<'PY'
import json, sys
secs, cur = {}, None
for line in open(sys.argv[1]):
    line = line.rstrip("\n")
    if line.startswith("@@ "): cur = line[3:]; secs[cur] = []; continue
    if cur: secs[cur].append(line)
ex = secs["export"]
if len(ex) > 1:
    secs["export"] = [ex[0], json.dumps(json.loads("".join(ex[1:])), indent=1)[:900] + "\n..."]
json.dump(secs, open(sys.argv[2], "w"))
PY
echo "wrote $out"
