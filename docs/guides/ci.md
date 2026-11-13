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
| `mode` | all | `seal`, `check` (fails the step when a check fails), `report` (the same, without failing), or `install` (only build and put `noqtis` on `PATH`) |
| `dir` | seal, check, report | the capsule folder |
| `key` | seal | the secret key file's text, from a secret; written to an owner-only temporary file for the one command, then deleted, never printed |
| `pub` | seal, check, report | the public key file; for `check` and `report`, the key the seal must carry (leave it out and any key's seal passes, with a warning) |
| `meta` | seal | a JSON file kept in the manifest as `meta` |
| `json` | check, report | `"true"` sets the `json` output |

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
decide yourself. There is no pull-request comment: that needs the
GitHub API and a token. After the action has run once
in a job, later `run:` steps can call `noqtis` directly.

For a reproducible manifest, set `SOURCE_DATE_EPOCH` for the seal step
(for example `echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >>
"$GITHUB_ENV"` in an earlier step). The repository's own
`.github/workflows/action.yml` uses the action this way on all three
systems: it seals a sample folder, checks it, changes one byte and
asserts that the check fails, and that `report` passes with outputs
that say what changed.

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
