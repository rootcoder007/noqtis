---
title: How NOQTIS compares
description: An honest comparison with sha256sum and GPG, minisign and signify, Sigstore, BagIt and in-toto, including where NOQTIS is the wrong choice.
---

No tool is right for everything. This page says what NOQTIS does that the
usual tools do not, what they do that NOQTIS does not, and what NOQTIS has
not yet earned.

## At a glance

| | NOQTIS | sha256sum + GPG | minisign / signify | Sigstore (cosign) | BagIt | in-toto |
|---|---|---|---|---|---|---|
| Post-quantum signatures | yes (ML-DSA, SLH-DSA, hybrids) | no | no | no | no signature | depends on the signer |
| Signs a whole folder | yes | a digest list | a file (signify: a digest list) | one artefact | digests only | a statement of artefacts |
| Notices added files, links | yes | no | no | n/a | added payload files, yes | no |
| Works offline | yes | yes | yes | checking with a pinned root only | yes | yes |
| Needs a service | no (a TSA only for timestamps) | key servers, optional | no | Fulcio and Rekor | no | no |
| Proof of time | RFC 3161 timestamp | no | no | transparency log | no | no |
| Who signed | a pinned key | a key and its web of trust | a pinned key | an identity (OIDC) | nobody | a pinned key or identity |
| Public record of signing | no | no | no | yes | no | no |
| Show some files only | yes (format 2 proofs) | no | no | no | no | no |
| Key management | yours | yours | yours | none for the signer | none | yours |
| Encryption | no (KEMs only) | yes | no | no | no | no |
| Maturity | new; not audited | decades | years | years, wide use | an RFC, wide use | a CNCF project, wide use |

## Where NOQTIS is a good fit

- Research data, code and results that must stay checkable for decades,
  past the point where quantum computers could forge today's RSA, ECDSA
  and Ed25519 signatures.
- Work that is unpublished, confidential or sensitive: nothing is sent to
  any service, and a format 2 proof can show a reviewer one table without
  the rest.
- Air-gapped and offline checking: a binary, a folder and a `.pub` file.
- Folders as units of evidence, where an added file must make the check
  fail.

## Where something else is better

- **You want no keys to manage.** Sigstore's keyless signing ties a
  signature to an identity, and its log shows every use. NOQTIS needs you
  to keep a secret key safe.
- **You need a public, append-only record** that a signature was made
  (for software supply chains, a log you can monitor for misuse). NOQTIS
  has none.
- **You need to encrypt files.** Use age, GPG or your platform's tools.
- **Your readers will not install anything.** `sha256sum` and `gpg` are
  everywhere; NOQTIS is one more binary (or a package for Python,
  JavaScript, R, Rust, Go or Java).
- **Container images.** cosign and the registries' signing support are
  built for them; NOQTIS signs folders and files.
- **You need validated cryptography** (FIPS 140-3). NOQTIS implements the
  FIPS 203, 204 and 205 algorithms and passes the NIST test vectors, but
  it has **no** CMVP certificate. Use a validated module where policy
  requires one.

## What NOQTIS has not yet earned

- **An audit.** No independent firm has reviewed the code. An audit
  through OSTIF has been applied for and is open for
  [funding](https://app.lfx.dev/crowdfunding/initiatives/noqtis-security-audit-of-a-post-quantum-signing-and-provenance-library-in-c11); until a report is published, treat NOQTIS as you
  would any new cryptographic code. See [security](/noqtis/security/) for
  what is tested and how.
- **Years of use.** The format and library are new. The capsule format is
  specified ([spec](/noqtis/spec/capsule/)) so that other tools can check
  capsules without NOQTIS, but none do yet.
- **Hardware side-channel evidence.** Timing is measured (dudect) and the
  masked code is checked against a *simulated* power model (TVLA); that is
  not a measurement on real hardware.
- **A reviewed TLS client.** The `https://` client for `check <url>` is
  built in only when asked for (`-DNQTLS=ON`); plain `http://` is the
  default, which is safe for checking because the capsule itself is
  signed, but it does not hide what you fetch.

## Using them together

NOQTIS does not ask you to give anything up. A capsule can also carry a
signed `SHA256SUMS`, its in-toto statement (`noqtis export --as intoto`)
can be signed with cosign, and a BagIt copy (`noqtis export --as bagit`)
can go to an archive that only takes bags. See the
[coming-from pages](/noqtis/from/sha256sum-gpg/) for each.
