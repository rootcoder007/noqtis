---
title: Coming from Sigstore
description: How Sigstore's keyless signing and transparency log compare with NOQTIS keys, seals and timestamps, and how to use both.
---

Sigstore (`cosign`, `gitsign`, the `sigstore` Python and JavaScript
clients) signs artefacts without long-lived keys: you sign in with an
identity provider, Sigstore's certificate authority (Fulcio) issues a
short-lived certificate for that identity, and the signature is recorded
in a public transparency log (Rekor). A verifier checks the identity and
the log entry rather than a key you gave them.

```sh
cosign sign-blob --bundle results.sigstore.json results.tar
cosign verify-blob --bundle results.sigstore.json \
  --certificate-identity you@example.org \
  --certificate-oidc-issuer https://accounts.google.com results.tar
```

NOQTIS takes the other road: a key you hold, a seal that needs no
service, and a check that runs offline.

```sh
noqtis seal -k me --tsa http://timestamp.example results
noqtis check -p me.pub --anchor tsa-root.der results
```

## How they differ

| | Sigstore | NOQTIS |
|---|---|---|
| Who signed | an identity (email, CI workflow) in a short-lived certificate | the holder of a key; you pin its `.pub` |
| Keys to manage | none for the signer | a secret key file per signer ([keys](/noqtis/guides/keys/)) |
| Proof of time | the transparency log's entry time | an optional RFC 3161 timestamp in the seal |
| Needs at signing | Sigstore's services (or your own deployment) | nothing; a TSA only for a timestamp |
| Needs at checking | Sigstore's trust root (fetched, or pinned) | the `.pub` file, and a TSA root for timestamps |
| Signature algorithm | ECDSA P-256 today | ML-DSA, SLH-DSA, ML-DSA+Ed25519 hybrids |
| What is signed | one artefact (a file, an image) | a whole folder, file by file |
| Public record | every signature is in a public log | none: nothing is published unless you publish it |

## When Sigstore fits better

- Releases from CI where you do not want to manage signing keys at all.
- When you want a public, auditable record that a signature was made,
  and that a key or identity was not used behind your back.
- Container images and the tooling around them (`cosign verify` in
  admission controllers, policy engines).

## When NOQTIS fits better

- **Records that must outlive today's cryptography.** A seal made now with
  ML-DSA or SLH-DSA is meant to stay unforgeable after large quantum
  computers exist; an ECDSA signature is not.
- **Offline and air-gapped checking.** A capsule checks with the `noqtis`
  binary, the folder and a `.pub` file; no network, no trust root to
  refresh.
- **Unpublished or sensitive work.** Nothing about the seal goes to a
  public log: the identity of the sealer, the file names and the time
  stay with the capsule. A format 2 capsule can even show some files to a
  reader without the rest ([`noqtis prove`](/noqtis/reference/man/noqtis-prove-1/)).
- **A folder as one unit**, refusing added files, links and special
  files, rather than a single blob.

## Using both

They do not exclude each other:

- `noqtis export --as intoto` writes an in-toto statement of a capsule's
  files and their SHA-256. Sign that statement with `cosign attest-blob`
  (or any in-toto tooling) to put a Sigstore record next to the
  post-quantum seal.
- `noqtis export --as dsse -k me` signs the same statement with your
  NOQTIS key in a DSSE envelope, the format Sigstore bundles and in-toto
  use; `noqtis verify --dsse -p me.pub` checks it.
- In CI, seal with a key from the CI secret store and also sign the
  release archive keylessly: readers can check whichever they trust.
