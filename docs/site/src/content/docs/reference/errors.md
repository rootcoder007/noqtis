---
title: Exit codes and errors
description: What each exit status, each failed check row and each library error code means, and what to do about it.
---

## Exit status

Every `noqtis` command exits with one of three values:

| Status | Meaning |
|---|---|
| `0` | Success: a signature is valid, every capsule check passed, every digest matched. |
| `1` | A verification failed: a bad or wrong-length signature, a failed capsule check, a digest that differs or a listed file that is missing, a malformed `hash --check` line. |
| `2` | A usage error, an unreadable or unwritable file, the wrong kind of key, a time-stamping authority that gave no usable token, or a library error. |

In a script, treat `1` as "the evidence does not hold" and `2` as "the
check could not be made". Never treat `2` as a pass.

```sh
noqtis check -p alice.pub results
case $? in
  0) echo "capsule checks" ;;
  1) echo "capsule does NOT check" >&2; exit 1 ;;
  *) echo "could not check (usage, file or network error)" >&2; exit 2 ;;
esac
```

`noqtis inspect` exits `1` when the seal or the manifest does not parse,
since it checks nothing else.

## Failed checks

`noqtis check` prints one row per check. After the table, standard error
says once per failed check what to do; with `--json` the same advice is
in each failed row's `fix` member:

```sh
$ noqtis check -p me.pub results
...
FAIL  file                a.txt: size differs
...
results: FAILED (1 of 22 checks failed)
noqtis check: file: a sealed file changed after sealing: restore it from the original, or seal the folder again if the change was intended
```

The rows, in the order they are checked, and the advice for each when it
fails:

### The seal (`noqtis.sig`)

| Row | When it fails | What to do |
|---|---|---|
| `seal.read` | `noqtis.sig` is missing or unreadable. | Give the folder that holds `noqtis.json` and `noqtis.sig`, or seal it with `noqtis seal`. |
| `seal.parse` | `noqtis.sig` is not JSON. | Restore it from the sealed copy, or seal the folder again. |
| `seal.canonical` | `noqtis.sig` was edited: it is not in the canonical form noqtis writes. | Restore it from the sealed copy, or seal the folder again. |
| `seal.fields` | It was edited or made by another tool. | Restore it from the sealed copy, or seal the folder again. |
| `seal.format` | It is not a `noqtis-seal-1` or `noqtis-seal-2` seal. | Restore it from the sealed copy, or seal the folder again. |
| `seal.alg` | The algorithm is not one this noqtis knows (`noqtis algs`). | Use a newer noqtis, or seal again. |
| `seal.context` | The context is not the capsule context of its format, so the signature was not made for a capsule (for example, it is a plain `noqtis sign` of the same bytes). | Restore it from the sealed copy, or seal the folder again. |
| `seal.key` | The seal's `public_key` is damaged. | Restore it from the sealed copy, or seal the folder again. |
| `seal.signature` | The seal's signature is damaged. | Restore it from the sealed copy, or seal the folder again. |

### The manifest (`noqtis.json`)

| Row | When it fails | What to do |
|---|---|---|
| `manifest.read` | `noqtis.json` is missing or unreadable, or is over 512 MiB. | Restore it; for one over the limit, split the folder into smaller capsules. |
| `manifest.digest` | `noqtis.json` is not the manifest this seal signed. | Restore the sealed `noqtis.json`, or seal again if the files changed on purpose. |
| `manifest.parse` | It is not JSON. | Restore it from the sealed copy, or seal the folder again. |
| `manifest.canonical` | It was edited. | Restore it from the sealed copy, or seal the folder again. |
| `manifest.fields` | It was edited or made by another tool, or lists more files than noqtis checks. | Restore it; for too many files, split the folder into smaller capsules. |
| `manifest.format` | It is not a manifest of the seal's format. | Restore it from the sealed copy, or seal the folder again. |
| `manifest.created` | Its `created` time is not RFC 3339 UTC. | Restore it from the sealed copy, or seal the folder again. |
| `manifest.order` | Its files are not sorted, so it was edited. | Restore it from the sealed copy, or seal the folder again. |
| `manifest.merkle` | (Format 2.) Its file entries are not the ones the seal's Merkle root covers, so an entry was edited. | Restore it from the sealed copy, or seal the folder again. |

### Who sealed it

| Row | When it fails | What to do |
|---|---|---|
| `key` | The seal was made with another key than `-p` gives. | Check that `-p` is the signer's public key. If it is, someone else sealed the folder again. |
| `key.alg` | The `-p` key file is for another algorithm than the seal's (the row names both). | Give the signer's public key file as `noqtis keygen` wrote it, for the seal's algorithm. |
| `keys` | A key statement (`--keys`) does not check; two statements are about one key; or a rotation leads back to an earlier key. | Get the statement again from the key holder, or leave it out; for two statements, keep the one its holder gave last. |
| `key.time` | The seal's key was replaced or revoked, and no verified timestamp shows the seal is older. If the timestamp is later than the replacement, the seal was made after it. | Check with `--anchor` for its timestamp, or ask for a seal with the current key. Do not trust a seal made after its key was revoked. |
| `card` | (With `--card`.) The identity card does not verify (it was changed, or is not a card), or it is for another key than the one that made the seal. | Get the card again from its holder (`noqtis idcard --verify <card>` says why); for another key, ask the sealer for the card of their seal key. |
| `signature` | The signature over `noqtis.json` does not verify. | `noqtis.json` or `noqtis.sig` changed after sealing: restore both from the sealed copy. |

### Timestamps (with `--anchor`)

| Row | When it fails | What to do |
|---|---|---|
| `timestamp` | The seal has no timestamp. | Check without `--anchor`, or seal again with `--tsa <url>`. |
| `timestamp` | No TSA trust anchors were given, but the seal has a timestamp. | Give the TSA's root or issuing certificate with `--anchor <der-file>`. |
| `timestamp` | The token's imprint is over another signature. | Seal again with `--tsa <url>`. |
| `timestamp` | An `--anchor` file is not a DER certificate. | Convert a PEM one with `openssl x509 -outform DER`. |
| `timestamp` | The token is not from a TSA under the anchors given. | Give `--anchor` the certificate of the TSA that made it, or seal again with `--tsa <url>`. |
| `timestamp` | The timestamp in `noqtis.sig` is damaged. | Restore `noqtis.sig` from the sealed copy, or seal again with `--tsa <url>`. |

### The files

| Row | When it fails | What to do |
|---|---|---|
| `folder` | The folder cannot be listed. | Check its permissions, and that it is within the limits in [`noqtis-capsule(5)`](/noqtis/reference/man/noqtis-capsule-5/). |
| `path` | Two files differ only in case (this breaks on Windows and macOS), or the manifest lists a path noqtis refuses or lists one twice. | Rename one file and seal again; a refused path means the manifest was not written by `noqtis seal`. |
| `file` | A sealed file changed, is gone, was replaced by a link, or cannot be read. | Restore it from the original (put the file itself back, not a link), check its permissions, or seal the folder again if the change was intended. |
| `extra` | A file was added after sealing. | Remove it, or seal the folder again to include it. |
| `unsafe` | The folder holds a link, a special file or a file with a name that is not portable. | Remove the link or special file (or rename the file), then seal again. |

### Proofs and lineage

| Row | When it fails | What to do |
|---|---|---|
| `proof.parse`, `proof.canonical`, `proof.fields` | The proof is not JSON, was edited, or was made by another tool. | Make it again with `noqtis prove`. |
| `proof.entry` | A file entry of the proof is not in the sealed Merkle tree. | Make the proof again with `noqtis prove`. |
| `lineage` | An input capsule is not in the `--lineage` folders, does not check, or the inputs nest too deep. | Give the folder of each input (the row names its id); run `noqtis check` on a failing input to see why. |

A failed row with the advice "no advice for this check: please report it
as a bug" means noqtis printed a check it has no advice for. Please
[open an issue](https://github.com/rootcoder007/noqtis/issues).

## Library error codes

Every function in `noqtis.h` returns `NQOK` (0) or one of these negative
codes; [`nqerr(3)`](/noqtis/reference/man/nqerr-3/) gives the message the
command line prints. The bindings raise an error with the same message:
in Python a subclass of `noqtis.NoqtisError` per code (`VerifyError`,
`DecodeError`, ...), in JavaScript a `NoqtisError` with the code in
`.code`, and in R an error condition.

| Code | Value | `nqerr()` | Usual cause |
|---|---|---|---|
| `NQOK` | 0 | success | |
| `NQEARG` | -1 | invalid argument | An argument is out of range or `NULL`: a wrong key or signature length, an unknown algorithm number, a context over 255 bytes. |
| `NQEBUF` | -2 | output buffer too small | Use the sizes `nqssize` and `nqksize` give. |
| `NQEVRFY` | -3 | verification failed | A signature, MAC or digest does not verify. |
| `NQEDEC` | -4 | input is not in the encoding the standard defines | A malformed key, signature, DER, JSON or capsule file. |
| `NQERNG` | -5 | the operating system's random source failed | `getrandom`, `getentropy`, `arc4random_buf` or `BCryptGenRandom` failed; retry, and check the system. |
| `NQEMEM` | -6 | out of memory | The allocation hook (`nqsetal`) returned `NULL`. |
| `NQEIO` | -7 | file could not be read or written | Permissions, a full disk, a missing folder. |
| `NQENOSUP` | -8 | algorithm or option not supported | For example a pre-hash for Ed25519, or a feature built out. |
| `NQELIM` | -9 | input exceeds a size or depth limit | The limits are in [`noqtis-capsule(5)`](/noqtis/reference/man/noqtis-capsule-5/). |
| `NQESTATE` | -10 | context used out of order | A context (for example the DRBG, or a TLS connection) used before it is ready or after it is closed. |

On the command line a library error is exit status `2`, except where
something is being checked: `NQEVRFY`, and `NQEDEC` for a signature or
capsule file that is malformed, are `1`.
