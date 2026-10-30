---
title: Command line
description: The NOQTIS commands, their options and exit status, with links to the full manual pages.
---

```text
noqtis <command> [options] [args]
noqtis help [<command>]
```

| Command | Does | Manual |
|---|---|---|
| `keygen -a <alg> -o <key> [--seed <hex\|file>] [--force]` | key pair: `<key>` (secret, 0600) and `<key>.pub` | [noqtis-keygen(1)](/noqtis/reference/man/noqtis-keygen-1/) |
| `sign -k <key> [-o <sig>] [-c <ctx>] [-d] [--ph <hash>] [--force] <file>` | raw signature, default `<file>.sig`; `-` for stdin | [noqtis-sign(1)](/noqtis/reference/man/noqtis-sign-1/) |
| `verify -p <key.pub> -s <sig> [-c <ctx>] [--ph <hash>] [-q] <file>`, or `verify -p <key.pub> --dsse [-o <payload>] <envelope>` | prints `<file>: OK (<alg>)`; `--dsse` checks a DSSE envelope | [noqtis-verify(1)](/noqtis/reference/man/noqtis-verify-1/) |
| `enc -p <key.pub> -o <ct> [--force] (<ss> \| --stdout)` | KEM ciphertext and shared secret | [noqtis-enc(1)](/noqtis/reference/man/noqtis-enc-1/) |
| `dec -k <key> (-o <ss> \| --stdout) [--force] <ct>` | shared secret; implicit rejection | [noqtis-dec(1)](/noqtis/reference/man/noqtis-dec-1/) |
| `hash [-a <hash>] [-c\|--check] [<file>...]` | `sha256sum`-format digests, or check them | [noqtis-hash(1)](/noqtis/reference/man/noqtis-hash-1/) |
| `seal -k <key> [-p <key.pub>] [-m <json-file>] [--format 1\|2] [--input [<name>=]<dir>]... [--tsa <url>]... [--anchor <der-file>]... <dir>` | writes `noqtis.json` and `noqtis.sig`; `--format 2` adds a Merkle tree so single files can be proven, `--input` records a capsule this one was made from; `--tsa` adds an RFC 3161 timestamp (http://, repeat for fallbacks), `--anchor` checks the TSA at seal time | [noqtis-seal(1)](/noqtis/reference/man/noqtis-seal-1/) |
| `check [-p <key.pub>] [-j\|--json] [--anchor <der-file>]... [--only <path>]... [--lineage <dir>]... (<dir>\|<url>)` | one row per check, then a summary, then what to do about each failed check; `--anchor` (up to 32 DER TSA certificates) checks the timestamp, `--only` checks just those files, `--lineage` checks the inputs too; a `<url>` (`http://`, or `https://` with TLS) is the folder of a published capsule, fetched and checked (the files only once the seal and the manifest check) | [noqtis-check(1)](/noqtis/reference/man/noqtis-check-1/) |
| `check [-p <key.pub>] --proof <file> [<dir>]` | checks a proof from `prove`, and with `<dir>` the proven files there | [noqtis-check(1)](/noqtis/reference/man/noqtis-check-1/) |
| `export --as intoto\|dsse\|rocrate\|bagit [-k <key>] [-o <file\|dir>] <dir>` | the checked capsule as an in-toto statement, a signed DSSE envelope, RO-Crate metadata or a BagIt bag | [noqtis-export(1)](/noqtis/reference/man/noqtis-export-1/) |
| `rotate -k <key> -n <new> [--at <time>] [--reason <text>] [-o <file>]` | a key statement, signed by both keys, that `<new>` replaced `<key>`; for `check --keys` | [noqtis-rotate(1)](/noqtis/reference/man/noqtis-rotate-1/) |
| `revoke -k <key> [--at <time>] [--reason <text>] [-o <file>]` | a key statement that `<key>` must no longer be trusted; seals by it then need a timestamp from before | [noqtis-revoke(1)](/noqtis/reference/man/noqtis-revoke-1/) |
| `prove [-p <key.pub>] [-o <file>] [-f] <dir> <path>...` | a proof that these files are in a format 2 capsule, naming no other file | [noqtis-prove(1)](/noqtis/reference/man/noqtis-prove-1/) |
| `timestamp --tsa <url>... [--anchor <der-file>]... [--force] <dir>` | adds an RFC 3161 timestamp to a capsule sealed before; the manifest and signature are unchanged, nothing is written if no TSA's token checks, and an existing timestamp is kept unless `--force` | [noqtis-timestamp(1)](/noqtis/reference/man/noqtis-timestamp-1/) |
| `inspect [-j\|--json] <dir>` | what a capsule says (format, algorithm, key fingerprint, created, files, size, timestamp, meta) without checking anything | [noqtis-inspect(1)](/noqtis/reference/man/noqtis-inspect-1/) |
| `algs` | every algorithm and its sizes | [noqtis-algs(1)](/noqtis/reference/man/noqtis-algs-1/) |
| `version` | `noqtis <version>` (also `--version`, `-V`) | [noqtis-version(1)](/noqtis/reference/man/noqtis-version-1/) |

Overview, key files and the handling of secrets:
[noqtis(1)](/noqtis/reference/man/noqtis-1/).

## Options

Options follow the command. Short options take a value as the next
argument or joined (`-kme`); long options as the next argument or after `=`
(`--key=me`). `-h`/`--help` after any command prints its usage. `--` ends
the options.

Long forms: `-a --alg`, `-o --out`, `-f --force`, `-k --key`, `-p --pub`,
`-s --sig`, `-c --ctx` (sign, verify) or `--check` (hash), `-d --det`,
`-q --quiet`, `-m --meta`, `-j --json`. `--tsa`, `--anchor`, `--input`,
`--only` and `--lineage` have no short form and may be repeated (up to 32
times each); `--format` and `--proof` are given once.

## Exit status

| Status | Meaning |
|---|---|
| 0 | success: a valid signature, every capsule check passed, every digest matched |
| 1 | a verification failed: a bad or wrong-length signature, a failed capsule check, a different digest or missing listed file, a malformed `--check` line |
| 2 | a usage error, an unreadable or unwritable file, the wrong kind of key, a library error, or no `--tsa` that gave a timestamp (the seal is then removed) |

## Files and secrets

- Secret keys and shared secrets are written owner-only (0600, `O_EXCL |
  O_NOFOLLOW` on POSIX) through unbuffered streams.
- No command overwrites a file without `--force`, which removes the old
  file first.
- No secret is printed, except a shared secret with `--stdout`, in hex.
- On Windows, arguments are read as UTF-16 and used as UTF-8; standard
  input and output are binary.
