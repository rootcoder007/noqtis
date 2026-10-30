---
title: Coming from BagIt
description: BagIt bags and NOQTIS capsules side by side, and how to make a bag from a capsule.
---

BagIt (RFC 8493) is the packaging format of many archives and
repositories: the files go under `data/`, and `manifest-sha256.txt`,
`bagit.txt` and `bag-info.txt` sit beside them. Tools such as
`bagit-python` make and validate bags:

```sh
bagit.py --sha256 results          # turns the folder into a bag, in place
bagit.py --validate results
```

A NOQTIS capsule is the same idea with a signature: the files stay where
they are, and `noqtis.json` (the manifest) and `noqtis.sig` (the seal)
are added.

## What maps to what

| BagIt | NOQTIS |
|---|---|
| `data/` | the folder itself (nothing is moved) |
| `manifest-sha256.txt` | `noqtis.json`: size, SHA-256 and SHA3-256 of each file |
| `tagmanifest-sha256.txt` | the seal's digest of `noqtis.json` |
| `bag-info.txt` | `--meta <file.json>` (any JSON object) |
| validate | `noqtis check` |
| *(no counterpart)* | the signature, and who made it (`-p`) |
| *(no counterpart)* | an RFC 3161 timestamp (`--tsa`) |

## What a bag cannot tell you

A valid bag proves that the files match the manifest. Anyone who changes
a file can also rewrite the manifest and the tag manifest, and the bag is
valid again. A capsule's manifest is signed, so a change shows unless the
changer also holds the secret key; with `-p` the check also says who
sealed it.

## Making a bag from a capsule

Repositories that take BagIt can still get one:

```sh
noqtis check -p me.pub results                       # the capsule must check
noqtis export --as bagit -p me.pub -o results-bag results
bagit.py --validate results-bag                      # any BagIt validator
```

`export --as bagit` checks the capsule first, then writes a new folder:
a copy of every file under `data/`, each checked against the manifest as
it is copied, `manifest-sha256.txt`, `bag-info.txt` (with the capsule's
id as `External-Identifier`), `bagit.txt`, and the capsule's
`noqtis.json` and `noqtis.sig` as tag files, listed in
`tagmanifest-sha256.txt`.

Whoever receives the bag can still check the seal, on a copy so the bag
itself stays valid:

```sh
cp -R results-bag/data chk
cp results-bag/noqtis.json results-bag/noqtis.sig chk/
noqtis check -p me.pub chk
```

## Differences to keep in mind

- A bag can be "holey" (files fetched from URLs listed in `fetch.txt`).
  A capsule is always complete; `noqtis check <url>` fetches a published
  capsule instead.
- BagIt allows any of its listed digest algorithms. NOQTIS always records
  SHA-256 and SHA3-256.
- BagIt percent-encodes `%`, CR and LF in manifest paths. A capsule may
  hold a `%` in a name (CR and LF are refused when sealing); the export
  encodes it as BagIt asks.
