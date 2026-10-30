---
title: Coming from sha256sum and GPG
description: The SHA256SUMS-plus-signature workflow, and what changes when you seal a folder with NOQTIS instead.
---

A common way to publish files people can check is a digest list signed
with GPG:

```sh
sha256sum results/* > SHA256SUMS
gpg --armor --detach-sign SHA256SUMS        # SHA256SUMS.asc
# the reader:
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

NOQTIS does the same job in one step, with a post-quantum signature:

```sh
noqtis keygen -a ML-DSA-65 -o me            # once: me (secret), me.pub
noqtis seal -k me results                   # writes noqtis.json, noqtis.sig
# the reader:
noqtis check -p me.pub results
```

## What maps to what

| sha256sum + GPG | NOQTIS |
|---|---|
| `gpg --full-generate-key` | `noqtis keygen -a ML-DSA-65 -o me` |
| your public key on a key server or web page | `me.pub`, published the same way |
| `SHA256SUMS` | `noqtis.json`, the manifest (size, SHA-256 and SHA3-256 of every file) |
| `SHA256SUMS.asc` | `noqtis.sig`, the seal |
| `gpg --verify` + `sha256sum -c` | `noqtis check -p me.pub results` |
| `gpg --detach-sign file` | `noqtis sign -k me file` (writes `file.sig`) |
| `gpg --verify file.sig file` | `noqtis verify -p me.pub -s file.sig file` |

`noqtis hash` prints and checks the same `<hex>  <file>` lines as
`sha256sum`, so existing `SHA256SUMS` files keep working:

```sh
noqtis hash -c SHA256SUMS                   # like sha256sum -c
noqtis hash -a sha3-256 results/*           # other hashes too
```

## What you gain

- **A whole folder, not a list.** `sha256sum -c` checks the files the list
  names and says nothing about files added next to them. `noqtis check`
  fails for an added file (`extra`), a missing one, a link or special
  file in place of a file, and an edited manifest.
- **A post-quantum signature.** GPG keys are RSA, DSA, ECDSA or EdDSA; a
  large quantum computer would let someone forge them, including for
  files signed years earlier. ML-DSA and SLH-DSA are the NIST standards
  meant to resist that. A [hybrid](/noqtis/glossary/#hybrid-signature)
  `ML-DSA-65+Ed25519` key keeps a classical signature alongside.
- **One file format, no keyring.** A public key is one `.pub` file, and
  nothing is imported into a keyring or trust database.
- **A time, if you want one.** `noqtis seal --tsa <url>` adds an RFC 3161
  timestamp, so a reader can prove the seal existed at that time.

## What you give up

- **The web of trust.** GPG can tell you a key was signed by people you
  trust. NOQTIS has no key signing: you get the sealer's `.pub` through a
  channel you trust (their web page, a paper, a signed release) and pin
  it with `-p`.
- **Encryption.** `gpg --encrypt` encrypts files. NOQTIS has KEMs
  (`noqtis enc`, `dec`) that agree on a shared secret, but it does not
  encrypt files.
- **Ubiquity.** `gpg` and `sha256sum` are installed nearly everywhere;
  your readers need `noqtis` ([install](/noqtis/start/install/)).

## Moving over

You can do both for a while: seal the folder, and keep publishing a
signed `SHA256SUMS` beside it for readers who do not have NOQTIS yet.
Write `SHA256SUMS` outside the sealed folder, or before you seal it: a
file added after sealing fails the check as `extra`. Ship `noqtis.json`
and `noqtis.sig` inside the folder, in the same archive as the files.
