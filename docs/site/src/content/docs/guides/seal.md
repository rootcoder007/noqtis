---
title: Seal and check a capsule
description: What noqtis seal records, what it refuses, metadata, reproducible capsules and reading the check report.
---

## Sealing

```sh
$ echo '{"project":"demo","run":42}' > meta.json
$ noqtis seal -k me -m meta.json results
sealed results with ML-DSA-65
```

`seal` lists every regular file under `results/`, records each one's path,
size, SHA-256 and SHA3-256 in `noqtis.json` (canonical JSON, sorted by
path), signs the exact bytes of `noqtis.json`, checks the new signature
with the public key (`-p`, default `me.pub`) and only then writes
`noqtis.sig`. Sealing again replaces both files.

Two digests are recorded so that a break of either hash alone does not
break the capsule.

### What cannot be sealed

`seal` refuses (exit 2, nothing written) a folder that holds:

- a symbolic link, or a Windows junction or other reparse point;
- a device, pipe or socket;
- a name that is empty, holds a control character, `/`, `\` or `:`, or is
  not valid UTF-8;
- two paths that differ only in ASCII case (`Data.csv` and `data.csv`),
  since they collide on macOS and Windows;
- a NOQTIS secret key file, which would ship with the capsule (keep keys
  outside the folder you seal);
- more than 2,000,000 files, a path over 4096 bytes, folders more than 64
  levels deep, or a manifest over 512 MiB.

A folder swapped for a link while `seal` or `check` runs is refused, not
followed: files are opened folder by folder from the capsule folder.

Empty folders are not recorded: only files are.

### Metadata

`-m file.json` stores a JSON object (at most 1 MiB) as the manifest's
`meta` field. It is signed with everything else, but NOQTIS does not read
it: put your own provenance there (the command line that made the results,
a dataset DOI, a commit).

### Reproducible capsules

The creation time comes from `SOURCE_DATE_EPOCH` when it is set:

```sh
$ SOURCE_DATE_EPOCH=1767225600 noqtis seal -k me results
sealed results with ML-DSA-65
$ cut -c1-34 results/noqtis.json
{"created":"2026-01-01T00:00:00Z",
```

With the same files, time and metadata, `noqtis.json` is byte-identical.
The signature still differs between runs (hedged signing).

## Checking

```sh
$ noqtis check -p me.pub results
```

prints one row per check and a summary, and exits 0 only when every check
passed. A failure never stops the check early: you see everything that is
wrong at once. The rows:

| Row | Passes when |
|---|---|
| `seal.read`, `seal.parse`, `seal.canonical`, `seal.fields`, `seal.format` | `noqtis.sig` is canonical JSON with exactly the fields of `noqtis-seal-1` |
| `seal.alg`, `seal.context`, `seal.key`, `seal.signature` | a known algorithm, the context `noqtis-capsule-1`, a key and signature of the right sizes |
| `manifest.read`, `manifest.digest` | `noqtis.json` is readable and its SHA-256 is the seal's |
| `key` | the seal's key is the one given with `-p` (or says it was not pinned) |
| `signature` | the signature over `noqtis.json` verifies |
| `timestamp` | only when the seal has a timestamp; see [timestamps](/noqtis/guides/timestamps/) |
| `folder` | the folder could be listed |
| `file` (one per listed file) | present, a regular file, same size, SHA-256 and SHA3-256 |
| `manifest.parse`, `manifest.canonical`, `manifest.fields`, `manifest.format`, `manifest.created`, `manifest.order` | `noqtis.json` is canonical `noqtis-capsule-1` with sorted, unique paths |
| `path` | one failing row per bad, duplicate or case-colliding path |
| `extra` | one failing row per file present but not listed |
| `unsafe` | one failing row per link, special file or refused name |

`--json` prints the same as one line of JSON for scripts:

```sh
$ noqtis check --json -p me.pub results |
    jq -r '.checks[] | select(.ok | not) | .detail'
report.txt: size differs
new.txt: not in the manifest
```

## From C

```c
nqrep *rep = NULL;
int rc = nqseal("results", NQMLDSA65, sk, sizeof sk, pk, sizeof pk,
                "{\"project\":\"demo\"}", NULL);
if (rc == NQOK)
  rc = nqchk("results", pk, sizeof pk, &rep);   /* NQOK or NQEVRFY */
for (size_t i = 0; i < nqrepn(rep); i++) {
  const char *check, *detail;
  int ok;
  nqrepi(rep, i, &check, &ok, &detail);
  printf("%-4s %s: %s\n", ok ? "ok" : "FAIL", check, detail);
}
nqrepfree(rep);
```

See [nqseal(3)](/noqtis/reference/man/nqseal-3/),
[nqchk(3)](/noqtis/reference/man/nqchk-3/) and
[nqrep(3)](/noqtis/reference/man/nqrep-3/).
