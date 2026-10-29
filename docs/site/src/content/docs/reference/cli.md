---
title: Command line
description: The noqtis commands, their options and exit status, with links to the full manual pages.
---

```text
noqtis <command> [options] [args]
noqtis help [<command>]
```

| Command | Does | Manual |
|---|---|---|
| `keygen -a <alg> -o <key> [--seed <hex\|file>] [--force]` | key pair: `<key>` (secret, 0600) and `<key>.pub` | [noqtis-keygen(1)](/noqtis/reference/man/noqtis-keygen-1/) |
| `sign -k <key> [-o <sig>] [-c <ctx>] [-d] [--ph <hash>] [--force] <file>` | raw signature, default `<file>.sig`; `-` for stdin | [noqtis-sign(1)](/noqtis/reference/man/noqtis-sign-1/) |
| `verify -p <key.pub> -s <sig> [-c <ctx>] [--ph <hash>] [-q] <file>` | prints `<file>: OK (<alg>)` | [noqtis-verify(1)](/noqtis/reference/man/noqtis-verify-1/) |
| `enc -p <key.pub> -o <ct> [--force] (<ss> \| --stdout)` | KEM ciphertext and shared secret | [noqtis-enc(1)](/noqtis/reference/man/noqtis-enc-1/) |
| `dec -k <key> (-o <ss> \| --stdout) [--force] <ct>` | shared secret; implicit rejection | [noqtis-dec(1)](/noqtis/reference/man/noqtis-dec-1/) |
| `hash [-a <hash>] [-c\|--check] [<file>...]` | `sha256sum`-format digests, or check them | [noqtis-hash(1)](/noqtis/reference/man/noqtis-hash-1/) |
| `seal -k <key> [-p <key.pub>] [-m <json-file>] [--tsa <url>] <dir>` | writes `noqtis.json` and `noqtis.sig` | [noqtis-seal(1)](/noqtis/reference/man/noqtis-seal-1/) |
| `check [-p <key.pub>] [-j\|--json] <dir>` | one row per check, then a summary | [noqtis-check(1)](/noqtis/reference/man/noqtis-check-1/) |
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
`-q --quiet`, `-m --meta`, `-j --json`.

## Exit status

| Status | Meaning |
|---|---|
| 0 | success: a valid signature, every capsule check passed, every digest matched |
| 1 | a verification failed: a bad or wrong-length signature, a failed capsule check, a different digest or missing listed file, a malformed `--check` line |
| 2 | a usage error, an unreadable or unwritable file, the wrong kind of key, or a library error |

## Files and secrets

- Secret keys and shared secrets are written owner-only (0600, `O_EXCL |
  O_NOFOLLOW` on POSIX) through unbuffered streams.
- No command overwrites a file without `--force`, which removes the old
  file first.
- No secret is printed, except a shared secret with `--stdout`, in hex.
- On Windows, arguments are read as UTF-16 and used as UTF-8; standard
  input and output are binary.
