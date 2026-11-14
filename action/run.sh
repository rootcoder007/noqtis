#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# The GitHub Action's data steps (action.yml), in POSIX sh:
#   action/run.sh data     modes drift and refresh
#   action/run.sh diff     the capsule against the same path at base-ref
#   action/run.sh comment  one sticky comment on the pull request
# Everything comes from the environment action.yml sets (NQ*, and the
# runner's GITHUB_* and RUNNER_TEMP); outputs go to $GITHUB_OUTPUT, the
# Markdown report to $NQREPORT.
set -u

out() { printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; }
die() {
  out "status=error"
  echo "::error title=noqtis::$*"
  exit 2
}
# a workflow command's value: % and line breaks escaped as GitHub reads them
ann() {
  v=$(printf '%s' "$3" | sed 's/%/%25/g' | tr '\n' ' ')
  echo "::$1 title=noqtis $NQMODE::$2: $v"
}
# a Markdown table cell: | and line breaks cannot end it
cell() { printf '%s' "$1" | sed 's/|/\\|/g' | tr '\n' ' '; }

t=${RUNNER_TEMP:-/tmp}/noqtis-$$
mkdir -p "$t" || die "cannot make a temporary folder under ${RUNNER_TEMP:-/tmp}"
trap 'rm -rf "$t"' EXIT
NQREPORT=${NQREPORT:-${RUNNER_TEMP:-/tmp}/noqtis-report.md}

# the level of a finding: 1 warn, 2 drift (or changed), 3 error; whether
# fail-on fails the step on it
fails() {
  case "$NQFAILON" in
    never) return 1 ;;
    error) [ "$1" -ge 3 ] ;;
    drift) [ "$1" -ge 2 ] ;;
    warn) [ "$1" -ge 1 ] ;;
  esac
}
kind() { if fails "$1"; then echo error; else echo warning; fi; }

data() {
  case "${NQFAILON:=drift}" in
    error | drift | warn | never) ;;
    *) die "fail-on must be error, drift, warn or never, not '$NQFAILON'" ;;
  esac
  [ -n "$NQDIR" ] || die "dir is required for $NQMODE"
  [ -d "$NQDIR" ] || die "$NQDIR: no such folder"
  lvl=0
  nchg=0
  : > "$t/rows"
  # refresh: the sources fetched again (in a copy for drift with fetch)
  if [ "$NQMODE" = refresh ] || [ "${NQFETCH:-false}" = true ]; then
    target=$NQDIR
    set -- src refresh
    if [ "$NQMODE" = drift ]; then
      target=$t/copy
      cp -R "$NQDIR" "$target" || die "cannot copy $NQDIR"
      set -- "$@" --write
    elif [ "${NQWRITE:-false}" = true ]; then
      set -- "$@" --write
    fi
    rc=0
    "$NQBIN" "$@" -- "$target" > "$t/out" 2> "$t/err" || rc=$?
    cat "$t/out" "$t/err"
    case $rc in
      0 | 1 | 3) ;;
      *) die "noqtis src refresh could not run (exit $rc): $(tail -n 1 "$t/err")" ;;
    esac
    while IFS= read -r l; do
      st=${l%% *}
      rest=$(printf '%s' "${l#"$st"}" | sed 's/^ *//')
      p=${rest%% *}
      case $st in
        changed) k=2; nchg=$((nchg + 1)) ;;
        unreachable) k=1 ;;
        *) k=0 ;;
      esac
      [ "$k" -gt "$lvl" ] && lvl=$k
      if [ "$k" -gt 0 ]; then
        ann "$(kind "$k")" "$NQDIR/$p" "source $rest"
        printf '| %s | source | %s |\n' "$st" "$(cell "$rest")" >> "$t/rows"
      else
        printf '| %s | source | %s |\n' "$st" "$(cell "$rest")" >> "$t/rows"
      fi
    done < "$t/out"
  fi
  if [ "$NQMODE" = drift ]; then
    [ "${NQFETCH:-false}" = true ] || target=$NQDIR
    rc=0
    "$NQBIN" drift check --psi-warn "${NQPSIW:-0.1}" --psi-fail \
      "${NQPSIF:-0.25}" -- "$target" > "$t/out" 2> "$t/err" || rc=$?
    cat "$t/out" "$t/err"
    case $rc in
      0 | 1 | 3) ;;
      *) die "noqtis drift check could not run (exit $rc): $(tail -n 1 "$t/err")" ;;
    esac
    # rows: "ok|FAIL  <check>  <detail>"
    while IFS= read -r l; do
      ok=${l%% *}
      rest=$(printf '%s' "${l#"$ok"}" | sed 's/^ *//')
      c=${rest%% *}
      d=$(printf '%s' "${rest#"$c"}" | sed 's/^ *//')
      case "$ok:$c" in
        FAIL:*) k=2; [ "$c" = drift ] && nchg=$((nchg + 1)) ;;
        ok:drift.warn) k=1 ;;
        ok:*) k=0 ;;
        *) continue ;;
      esac
      [ "$k" -gt "$lvl" ] && lvl=$k
      [ "$k" -gt 0 ] && ann "$(kind "$k")" "$NQDIR" "$c $d"
      printf '| %s | %s | %s |\n' "$ok" "$(cell "$c")" "$(cell "$d")" >> "$t/rows"
    done < "$t/out"
  fi
  case $lvl in
    0) st=passed; head="**Passed**" ;;
    1) st=warned; head="**Passed, with warnings**" ;;
    *) st=failed; head="**Failed**" ;;
  esac
  {
    echo "$head: noqtis $NQMODE of \`$NQDIR\` ($nchg changed; fail-on $NQFAILON)"
    echo
    echo "| | check | detail |"
    echo "|---|---|---|"
    cat "$t/rows"
  } > "$NQREPORT"
  cat "$NQREPORT"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$NQREPORT" >> "$GITHUB_STEP_SUMMARY"; fi
  out "status=$st"
  out "changed=$nchg"
  out "report=$NQREPORT"
  if [ "$lvl" = 0 ]; then out "ok=true"; else out "ok=false"; fi
  if fails "$lvl"; then exit 1; fi
  exit 0
}

bdiff() {
  [ -n "${NQBASE:-}" ] || exit 0
  [ -n "$NQDIR" ] && [ -d "$NQDIR" ] || die "base-ref needs dir, a folder"
  case $NQDIR in
    /* | ../* | */../* | ..) die "base-ref needs dir as a path inside the repository" ;;
  esac
  git rev-parse --verify -q "$NQBASE^{commit}" > /dev/null ||
    die "base-ref $NQBASE is not a commit here: check it out with fetch-depth: 0"
  mkdir -p "$t/base"
  differs=true
  sec=$t/sec.md
  if [ -z "$(git ls-tree "$NQBASE" -- "$NQDIR")" ]; then
    echo "::notice title=noqtis diff::$NQDIR is new since $NQBASE"
    printf '\n%s is new since %s.\n' "\`$NQDIR\`" "\`$NQBASE\`" > "$sec"
  else
    git archive "$NQBASE" -- "$NQDIR" | tar -x -C "$t/base" ||
      die "cannot read $NQDIR at $NQBASE"
    rc=0
    "$NQBIN" diff -- "$t/base/$NQDIR" "$NQDIR" > "$t/out" 2> "$t/err" || rc=$?
    cat "$t/out" "$t/err"
    case $rc in
      0) differs=false ;;
      1) ;;
      *) die "noqtis diff could not run (exit $rc): $(tail -n 1 "$t/err")" ;;
    esac
    {
      echo
      if [ "$differs" = true ]; then
        echo "Changes since \`$NQBASE\`:"
        echo
        echo "| | check | detail |"
        echo "|---|---|---|"
      else
        echo "Nothing changed since \`$NQBASE\`."
      fi
    } > "$sec"
    # rows: "diff  <check>  <detail>", and blank-marked notes
    while IFS= read -r l; do
      case $l in
        "diff "*) ;;
        *) continue ;;
      esac
      rest=$(printf '%s' "${l#diff}" | sed 's/^ *//')
      c=${rest%% *}
      d=$(printf '%s' "${rest#"$c"}" | sed 's/^ *//')
      echo "::notice title=noqtis diff::$NQDIR: $c $(printf '%s' "$d" | sed 's/%/%25/g')"
      printf '| changed | %s | %s |\n' "$(cell "$c")" "$(cell "$d")" >> "$sec"
    done < "$t/out"
  fi
  cat "$sec" >> "$NQREPORT"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$sec" >> "$GITHUB_STEP_SUMMARY"; fi
  out "differs=$differs"
  exit 0
}

# the comment's body as a JSON object {"body": ...}
jbody() {
  LC_ALL=C awk 'BEGIN { ORS = ""; print "{\"body\":\"" }
    { if (NR > 1) print "\\n"
      n = length($0)
      for (i = 1; i <= n; i++) {
        c = substr($0, i, 1)
        if (c == "\\") print "\\\\"
        else if (c == "\"") print "\\\""
        else if (c == "\t") print "\\t"
        else if (c < " ") print " "
        else print c
      } }
    END { print "\"}" }' "$1"
}

comment() {
  case "${NQCOMMENT:-false}" in
    true | dry-run) ;;
    *) out "comment=off"; exit 0 ;;
  esac
  if [ ! -s "$NQREPORT" ]; then
    out "comment=skipped"
    exit 0
  fi
  # one comment per capsule folder: its marker names the folder by digest
  h=$(printf '%s' "$NQDIR" | "$NQBIN" hash | cut -c1-16)
  key="noqtis-sticky:$h"
  { echo "<!-- $key -->"; cat "$NQREPORT"; } > "$t/body.md"
  if [ "$NQCOMMENT" = dry-run ]; then
    cp "$t/body.md" "${RUNNER_TEMP:-/tmp}/noqtis-comment.md"
    out "comment=dry-run"
    exit 0
  fi
  case "${GITHUB_REF:-}" in
    refs/pull/*/merge) n=${GITHUB_REF#refs/pull/}; n=${n%/merge} ;;
    *)
      echo "::notice title=noqtis::not a pull request, so no comment"
      out "comment=skipped"
      exit 0 ;;
  esac
  if [ -z "${NQTOKEN:-}" ]; then
    echo "::warning title=noqtis::comment needs a token (the token input, github.token by default)"
    out "comment=failed"
    exit 0
  fi
  api=${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY
  jbody "$t/body.md" > "$t/body.json"
  id=
  p=1
  while [ -z "$id" ] && [ "$p" -le 10 ]; do
    curl -fsS -H "Authorization: Bearer $NQTOKEN" \
      -H "Accept: application/vnd.github+json" \
      "$api/issues/$n/comments?per_page=100&page=$p" > "$t/list" || {
      echo "::warning title=noqtis::cannot list the pull request's comments"
      out "comment=failed"
      exit 0
    }
    # the comment whose body has the marker: the last comment URL before it
    id=$(awk -v k="$key" 'BEGIN { RS = "\001" }
      { i = index($0, k); if (i == 0) exit
        s = substr($0, 1, i); id = ""
        while (match(s, /issues\/comments\/[0-9]+/)) {
          id = substr(s, RSTART + 16, RLENGTH - 16); s = substr(s, RSTART + RLENGTH) }
        print id }' "$t/list")
    grep -q '"id"' "$t/list" || break
    p=$((p + 1))
  done
  if [ -n "$id" ]; then
    m=PATCH
    u=$api/issues/comments/$id
    what=updated
  else
    m=POST
    u=$api/issues/$n/comments
    what=created
  fi
  if curl -fsS -X "$m" -H "Authorization: Bearer $NQTOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" --data-binary "@$t/body.json" \
    "$u" > /dev/null; then
    out "comment=$what"
  else
    echo "::warning title=noqtis::the comment could not be $what (does the job have pull-requests: write?)"
    out "comment=failed"
  fi
  exit 0
}

case "${1:-}" in
  data) data ;;
  diff) bdiff ;;
  comment) comment ;;
  *) echo "usage: run.sh data|diff|comment" >&2; exit 2 ;;
esac
