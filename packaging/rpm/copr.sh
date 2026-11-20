#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds a source RPM on Fedora COPR and waits until every target has
# been built. The login is the file ~/.config/copr.
#   sh packaging/rpm/copr.sh PROJECT SRPM [TARGET...]
# With TARGETs only those are built, otherwise every target of the
# project. A PROJECT that does not exist is made, with the targets of the
# project noqtis: a scratch project, where a commit is built before it
# is tagged. The wait asks COPR once a minute and goes on when COPR does
# not answer: a build on riscv64 takes over an hour, and a lost
# connection is not a failed build.
set -eu
proj=$1
srpm=$2
shift 2
api=https://copr.fedorainfracloud.org/api_3
me=$(copr-cli whoami)

# the HTTP status of a project's page: 200, 404, or 000 when COPR is away
code() {
  curl -sL -m 60 -o /dev/null -w '%{http_code}' \
    "$api/project?ownername=$me&projectname=$1" || true
}

c=000
i=0
while [ "$i" -lt 10 ]; do
  c=$(code "$proj")
  case $c in 200 | 404) break ;; esac
  i=$((i + 1))
  sleep 30
done
case $c in
  200) ;;
  404)
    ch=$(curl -fsSL -m 60 "$api/project?ownername=$me&projectname=noqtis" |
      python3 -c 'import json, sys
print(" ".join("--chroot " + c for c in sorted(json.load(sys.stdin)["chroot_repos"])))')
    [ -n "$ch" ]
    # shellcheck disable=SC2086 # options and their values, one word each
    copr-cli create "$proj" $ch --unlisted-on-hp on \
      --description "Scratch builds of noqtis, made before a release. Install from rootcoder007/noqtis instead."
    ;;
  *)
    echo "copr.sh: COPR does not answer (HTTP $c)" >&2
    exit 1
    ;;
esac

r=""
for t in "$@"; do r="$r --chroot $t"; done
# shellcheck disable=SC2086
out=$(copr-cli build --nowait $r "$proj" "$srpm")
printf '%s\n' "$out"
id=$(printf '%s\n' "$out" | sed -n 's/^Created builds: *\([0-9][0-9]*\).*/\1/p')
[ -n "$id" ] || {
  echo "copr.sh: no build number in the answer of copr-cli" >&2
  exit 1
}
echo "https://copr.fedorainfracloud.org/coprs/build/$id/"

# the state of the build, empty when COPR does not answer
state() {
  curl -fsSL -m 60 "$api/build/$id" 2>/dev/null |
    python3 -c 'import json, sys
print(json.load(sys.stdin)["state"])' 2>/dev/null || true
}

# every target with its state and its minutes
targets() {
  curl -fsSL -m 60 "$api/build-chroot/list?build_id=$id" 2>/dev/null |
    python3 -c 'import json, sys
for c in sorted(json.load(sys.stdin)["items"], key=lambda c: c["name"]):
    s, e = c.get("started_on"), c.get("ended_on")
    m = "%d min" % round((e - s) / 60) if s and e else ""
    print("  %-22s %-10s %s" % (c["name"], c["state"], m))' 2>/dev/null || true
}

n=0
away=0
while :; do
  st=$(state)
  case $st in
    succeeded) break ;;
    failed | canceled | skipped)
      echo "copr.sh: build $id is $st" >&2
      targets
      exit 1
      ;;
    "")
      away=$((away + 1))
      if [ "$away" -gt 90 ]; then
        echo "copr.sh: COPR has not answered for 90 minutes" >&2
        exit 1
      fi
      ;;
    *) away=0 ;;
  esac
  n=$((n + 1))
  if [ $((n % 10)) -eq 0 ]; then
    echo "after $n minutes: ${st:-no answer}"
    targets
  fi
  sleep 60
done
echo "build $id succeeded after $n minutes"
targets
