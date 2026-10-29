---
title: Check someone else's capsule
description: What a passing check proves, why you pin the public key, and what to do when a check fails.
---

You received a folder with `noqtis.json` and `noqtis.sig` in it, perhaps
with a paper, a dataset or a build. Here is how to check it and what the
result means.

## Get the sealer's public key from somewhere else

The seal carries its own public key, so

```sh
$ noqtis check results
```

passes for **anyone's** seal: it proves the files are unchanged since
*someone* sealed them, not who. The `key` row says
`not pinned: accepted the public key in the seal`, and a note on standard
error says so too.

To know *who* sealed it, get their `.pub` file through a channel you trust
(their website, a signed release, a paper's supplement, in person) and
pin it:

```sh
$ noqtis check -p alice.pub results
...
ok    key                 the seal's key is the trusted key
...
results: OK (22 checks passed)
```

With `-p`, a capsule resealed by anyone else fails the `key` and
`signature` rows.

## What a passing check proves

- Every file the manifest lists is present, is a regular file, and has
  exactly the recorded size, SHA-256 and SHA3-256.
- No other file is in the folder (apart from `noqtis.json` and
  `noqtis.sig` themselves), and no link or special file.
- The manifest is exactly the bytes the holder of the key signed, with a
  post-quantum signature.

## What it does not prove

- **When** it was sealed. The `created` field is what the sealer's clock
  said; only a [timestamp](/noqtis/guides/timestamps/) from a third party
  proves a time.
- That the results are **correct**, or that the listed inputs were the ones
  actually used: a capsule records what was there, not how it was made.
  Put the commands and versions in `meta`, and seal the code too.
- That the key holder is who they claim to be: that is what getting the
  public key from a trusted source is for.
- Anything about empty folders, file permissions, owners or modification
  times, which are not recorded.

## When a check fails

Every failing row says what failed:

| Row | Meaning | What to do |
|---|---|---|
| `file ...: size differs`, `sha256 differs`, `sha3_256 differs` | the file changed after sealing | get the original; compare with `noqtis hash` |
| `file ...: missing` | a listed file is gone | the copy is incomplete (an archive extracted partly, a `.gitignore`d file) |
| `extra ...: not in the manifest` | a file was added | remove it, or ask for a new seal |
| `unsafe ...` | a link or special file appeared | remove it; noqtis never follows links |
| `key`, `signature` | sealed by another key, or the manifest or seal was edited | do not trust the capsule |
| `manifest.digest` | `noqtis.json` was changed | do not trust the capsule |
| `seal.*`, `manifest.parse`, ... | damaged or not a noqtis capsule | get a fresh copy |
| `timestamp` | see [timestamps](/noqtis/guides/timestamps/) | |

Archive tools and file systems sometimes change what they carry: a ZIP or
Git checkout that converts line endings (`core.autocrlf`) changes text
files, and a case-insensitive file system cannot hold two names that
differ only in case (which noqtis refuses to seal for that reason). Prefer
`tar` and binary transfers.

Exit status 2 (not 1) means the check could not run: a wrong option, a
folder that does not exist, a key file that is not a public signature key.
