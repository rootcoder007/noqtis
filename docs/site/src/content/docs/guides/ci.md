---
title: Use in CI
description: Seal build or analysis outputs in CI and check capsules as a gate, with exit codes and JSON output.
---

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
the check names are listed in [noqtis-check(1)](/noqtis/reference/man/noqtis-check-1/)
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

A GitHub Action (`rootcoder007/noqtis-action`) that installs noqtis and
seals or checks a folder is planned for the first release.

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
