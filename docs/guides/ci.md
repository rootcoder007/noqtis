# Use in CI

`noqtis` is built for scripts: every command exits **0** on success, **1**
when a verification fails, **2** on a usage, file or library error, and
`check --json` prints one machine-readable line.

## Check a capsule as a gate

```sh
set -e
noqtis check -p keys/release.pub dist/      # exit 1 fails the job
```

Keep the public key in the repository (it is not secret) and always pass
`-p`: without it, any key's seal passes.

To show only what failed:

```sh
noqtis check --json -p keys/release.pub dist/ > check.json || {
  jq -r '.checks[] | select(.ok | not) | "\(.check): \(.detail)"' check.json
  exit 1
}
```

The JSON line is
`{"capsule":"<dir>","ok":<bool>,"result":"<text>","checks":[{"check":"<name>","ok":<bool>,"detail":"<text>"},...]}`;
the check names are listed in [noqtis-check(1)](https://noqtis.dev/reference/man/noqtis-check-1/)
and stay stable.

## Seal outputs in a workflow

Store the secret key file as an encrypted CI secret, write it to a file
only the job can read, seal, and remove it:

```yaml
# GitHub Actions
- name: seal the results
  env:
    NQKEY: ${{ secrets.NOQTIS_KEY }}   # the whole secret key file
  run: |
    umask 077
    printf '%s\n' "$NQKEY" > "$RUNNER_TEMP/key"
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
      noqtis seal -k "$RUNNER_TEMP/key" -p keys/release.pub \
        -m build-meta.json results/
    rm -f "$RUNNER_TEMP/key"
    noqtis check -p keys/release.pub results/
```

`SOURCE_DATE_EPOCH` from the commit makes the manifest reproducible: the
same commit gives the same `noqtis.json`. Put the commit, the workflow run
and the tool versions in `build-meta.json` so the capsule records how the
results were made.

## The GitHub Action

The repository is also a GitHub Action, `rootcoder007/noqtis@v0`. It
builds `noqtis` from the action's own source with CMake (cached, so later
runs skip the build), puts it on `PATH`, and seals, checks or reports
on a folder. It
runs on Linux, macOS and Windows runners. The tag `v0` follows each 0.x
release; pin a full version (`@v0.1.4`) or a commit if a workflow must not
change when noqtis does.

```yaml
permissions:
  contents: read

steps:
  # first check out the repository (actions/checkout, pinned by commit SHA)

  # seal: the secret key file comes from a secret
  - uses: rootcoder007/noqtis@v0
    with:
      mode: seal
      dir: results
      key: ${{ secrets.NOQTIS_KEY }}   # the whole secret key file
      pub: keys/release.pub
      meta: build-meta.json            # optional

  # check: fails the job unless every check passes
  - id: check
    uses: rootcoder007/noqtis@v0
    with:
      mode: check
      dir: results
      pub: keys/release.pub
      json: "true"                     # optional: the report as an output

  # report: the same checks, outputs and annotations, but the step
  # passes; decide from the outputs
  - id: report
    uses: rootcoder007/noqtis@v0
    with:
      mode: report
      dir: results
      pub: keys/release.pub
  - if: steps.report.outputs.changed != '0'
    run: echo "${{ steps.report.outputs.changed }} files changed since the seal"
```

| Input | For | Meaning |
|---|---|---|
| `mode` | all | `seal`, `check` (fails the step when a check fails), `report` (the same, without failing), `drift`, `refresh` (below), or `install` (only build and put `noqtis` on `PATH`) |
| `dir` | seal, check, report, drift, refresh | the capsule folder |
| `key` | seal | the secret key file's text, from a secret; written to an owner-only temporary file for the one command, then deleted, never printed |
| `pub` | seal, check, report | the public key file; for `check` and `report`, the key the seal must carry (leave it out and any key's seal passes, with a warning) |
| `meta` | seal | a JSON file kept in the manifest as `meta` |
| `json` | check, report | `"true"` sets the `json` output |
| `fail-on` | drift, refresh | when the step fails: `error` (only when noqtis cannot check), `drift` (the default: also when a column drifted past `psi-fail` or a source changed), `warn` (also on a drift warning or an unreachable source), `never` |
| `psi-warn`, `psi-fail` | drift | the population stability index from which a column warns (0.1) and fails (0.25) |
| `fetch` | drift | `"true"`: fetch each source again, into a copy of the folder, and check those files |
| `write` | refresh | `"true"`: write the changed sources' new bytes into `dir` and record them, for a later step to seal and commit |
| `base-ref` | check, report, drift, refresh | a branch, tag or commit to compare the capsule with, at the same path (`noqtis diff`); needs `fetch-depth: 0` |
| `comment` | check, report, drift, refresh | `"true"`: on a pull request, the report as one comment, updated by each run; `dry-run`: written to `$RUNNER_TEMP/noqtis-comment.md` instead |
| `token` | comment | the token the comment is posted with (`github.token` by default) |

`check` and `report` run `noqtis report` once, on the capsule and its
data record. Each failed check becomes an error annotation on the run,
the Markdown report goes to the job summary, and the outputs are `ok`
(`"true"` or `"false"`), `status` (`passed`, `failed`, or `error` when
noqtis could not check at all), `verified` (sealed files that match),
`changed` (sealed files changed or missing, and files added), `failed`
(failed checks, of the capsule and of its data record), `report` (the
path of the Markdown report) and `json` (the `noqtis report --json` line,
when asked for); every mode has `bin` (the path to `noqtis`). A failing
`check` fails its step; use `report`, or `continue-on-error: true`, to
decide yourself. After the action has run once in a job, later `run:`
steps can call `noqtis` directly.

### Drift, refresh, the base branch and a pull-request comment

`drift` compares the files of `dir` with the summaries pinned in its
data record (`noqtis drift check`); with `fetch: "true"` it first
fetches each source again (`noqtis src refresh`, in a copy of the
folder) and compares those. `refresh` fetches each source again and says
whether it changed. Each drifted column, changed source and unreachable
source is an annotation (an error when `fail-on` fails the step on it,
else a warning), the report is a table of every row, and the outputs are
`status` (`passed`, `warned`, `failed` or `error`), `changed` (columns
that drifted, sources that changed), `ok` and `report`.

`base-ref` compares the capsule with its copy at another commit, such
as the pull request's base: each difference is a notice and a section
of the report, and `differs` says whether there was one. `comment:
"true"` posts the report on the pull request as one comment, found again
by a marker and updated on each run rather than repeated; the output
`comment` says `created`, `updated`, `skipped` (not a pull request),
`failed` or `off`. The job needs only these permissions:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write   # only for comment: "true"

steps:
  - uses: actions/checkout@v7   # pin by commit SHA
    with:
      fetch-depth: 0             # for base-ref
  - id: drift
    uses: rootcoder007/noqtis@v0
    with:
      mode: drift
      dir: results
      fetch: "true"
      fail-on: drift
      psi-fail: "0.25"
      base-ref: origin/${{ github.base_ref }}
      comment: "true"
  - if: always()
    run: echo "${{ steps.drift.outputs.status }}, ${{ steps.drift.outputs.changed }} changed"
```

A scheduled workflow with `mode: refresh` and `write: "true"`, then a
seal and a commit or pull request of its own, keeps a capsule's data in
step with its sources; `fail-on: never` lets it run to the end.

For a reproducible manifest, set `SOURCE_DATE_EPOCH` for the seal step
(for example `echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >>
"$GITHUB_ENV"` in an earlier step). The repository's own
`.github/workflows/action.yml` uses the action this way on all three
systems: it seals a sample folder, checks it, changes one byte and
asserts that the check fails, and that `report` passes with outputs
that say what changed; then it serves a data file from a local server,
records it as a source with summaries, and checks `drift` (passing, then
failing after the source changes, with `fetch`), `refresh` (failing,
then written with `fail-on: never`), `base-ref` and the comment in
`dry-run`.

## Checksums alongside

`noqtis hash` writes and checks `sha256sum`-format lines, with SHA-2,
SHA-3 and SHAKE:

```sh
noqtis hash -a sha3-256 dist/* > SHA3SUMS
noqtis hash -a sha3-256 --check SHA3SUMS
```

It reads lines made by `sha256sum` as well:

```sh
sha256sum dist/* | noqtis hash -c
```

## Signing release files

```sh
noqtis sign -k "$RUNNER_TEMP/key" -c release -o app.tar.gz.sig app.tar.gz
noqtis verify -p keys/release.pub -s app.tar.gz.sig -c release app.tar.gz
```
