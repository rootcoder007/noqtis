---
title: Coming from minisign or signify
description: Signing single files with minisign or OpenBSD's signify, and the NOQTIS commands that do the same with post-quantum keys.
---

minisign and signify sign files with Ed25519 and small key files. NOQTIS
works the same way, with a choice of post-quantum algorithms, and adds
sealed folders.

| minisign | signify | NOQTIS |
|---|---|---|
| `minisign -G` | `signify -G -p key.pub -s key.sec` | `noqtis keygen -a ML-DSA-65 -o key` (writes `key`, `key.pub`) |
| `minisign -Sm file` | `signify -S -s key.sec -m file` | `noqtis sign -k key file` (writes `file.sig`) |
| `minisign -Vm file -p key.pub` | `signify -V -p key.pub -m file` | `noqtis verify -p key.pub -s file.sig file` |
| | `signify -C -p key.pub -x SHA256.sig` | `noqtis check -p key.pub <dir>` on a sealed folder |

## Differences to know

- **Algorithms.** minisign and signify have one: Ed25519. NOQTIS has
  ML-DSA and SLH-DSA (post-quantum), Ed25519, and hybrids of ML-DSA with
  Ed25519 that need both to verify. `noqtis algs` lists them. Ed25519
  alone is there for compatibility and cannot seal a capsule.
- **Signature size.** An Ed25519 signature is 64 bytes. An ML-DSA-65
  signature is 3309 bytes and an SLH-DSA-SHA2-128s one 7856. For files
  that is rarely a problem; for many tiny messages it may be.
- **Raw signatures.** `noqtis sign` writes the raw signature bytes, with
  no comment lines. minisign's trusted comments have no counterpart; put
  what you want signed in the file, or seal a folder and use `--meta`.
- **Contexts.** `noqtis sign -c <ctx>` binds a signature to a purpose
  string (FIPS 204 and 205 contexts), so it cannot be passed off as a
  signature for something else. A verifier must give the same `-c`.
- **Pre-hashing.** minisign signs a BLAKE2b pre-hash of large files.
  `noqtis sign --ph sha512` uses the standard pre-hash variants
  (HashML-DSA, HashSLH-DSA); without `--ph` the whole file is signed.
- **Secret key files.** minisign encrypts the secret key with a password
  by default. NOQTIS writes it owner-only (mode 0600) but not encrypted:
  keep it on an encrypted disk or in your CI's secret store
  ([keys](/noqtis/guides/keys/)).

## signify's checksum lists and sealed folders

`signify -C` checks a signed list of digests, like `sha256sum -c` with a
signature. A sealed folder does that and more: it also refuses files
added after sealing, links and special files, and an edited manifest.
See [coming from sha256sum and GPG](/noqtis/from/sha256sum-gpg/).
