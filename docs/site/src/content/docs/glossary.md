---
title: Glossary
description: The words NOQTIS uses, from anchor to transparency log, in plain language.
---

### Algorithm

The signature or key-exchange scheme a key belongs to,
for example `ML-DSA-65` or `SLH-DSA-SHA2-128s`. `noqtis algs` lists them
with their sizes. A key, its signatures and its seals always name one
algorithm.

### Anchor (trust anchor)

A certificate you trust without checking who
issued it: the root of a time-stamping authority (`--anchor`) or the
roots in a CA bundle for `https://`. Everything else is trusted only by
a path that ends at an anchor.

### Audit path

In a [format 2](#format) capsule, the few digests that
link one file's entry to the [Merkle root](#merkle-tree). A
[proof](#proof) carries one per file it shows.

### BagIt

A folder layout for archives (RFC 8493): the files under
`data/` and a manifest of their digests. `noqtis export --as bagit`
makes one from a capsule. A bag has digests but no signature.

### Canonical JSON

The single byte-for-byte form noqtis writes for
`noqtis.json`, `noqtis.sig`, proofs and key statements: sorted keys, no
spaces, fixed escapes. A check refuses any other form, so an edited file
is noticed even when it still means the same thing.

### Capsule

A folder sealed by `noqtis seal`: your files plus
`noqtis.json` (the [manifest](#manifest)) and `noqtis.sig` (the
[seal](#seal)). It can be checked anywhere, offline, by anyone with
`noqtis`.

### Capsule id

The SHA-256 of what a seal signs. It names a capsule in
another capsule's [lineage](#lineage).

### Check

`noqtis check`: reads a capsule and reports, row by row,
whether each part holds (seal, manifest, key, signature, every file).
Exit 0 only if every row passes. See [exit codes and
errors](/noqtis/reference/errors/).

### Context

A short string mixed into a signature so that it cannot be
reused for another purpose. Seals use `noqtis-capsule-1` or
`noqtis-capsule-2`; `noqtis sign -c` sets your own.

### DSSE

Dead Simple Signing Envelope: a JSON wrapper that signs a
payload together with its type. `noqtis export --as dsse` wraps an
[in-toto](#in-toto) statement of a capsule in one.

### Fingerprint

The SHA-256 of a public key, in hex. `noqtis inspect`
prints the seal's; compare it with the one the sealer published.

### Format

The capsule format: 1 (a flat list of files) or 2 (the same
list under a [Merkle tree](#merkle-tree), which allows
[proofs](#proof) and [lineage](#lineage)). `noqtis seal --format 2`.

### Hybrid signature

A signature made with two schemes at once, here
ML-DSA and Ed25519 (`ML-DSA-65+Ed25519`). It verifies only if both parts
do, so it stays secure while either scheme is unbroken.

### in-toto

A format for statements about software artefacts and how
they were made. `noqtis export --as intoto` writes an in-toto Statement
v1 listing a capsule's files and their SHA-256; SLSA provenance uses the
same format.

### Key statement

A signed file from `noqtis rotate` (this key was
replaced by that one) or `noqtis revoke` (this key must no longer be
trusted), from a given time. `noqtis check --keys` follows them.

### KEM

Key-encapsulation mechanism: a way to agree on a shared secret
with someone's public key (`noqtis enc`, `noqtis dec`). ML-KEM and HQC
are KEMs; they encrypt nothing by themselves.

### Lineage

The capsules a capsule was made from, recorded by
`noqtis seal --input`. `noqtis check --lineage` checks them too.

### Manifest

`noqtis.json`: the list of every file in the capsule with
its size, SHA-256 and SHA3-256, the time it was sealed (`created`, as
the sealer's clock said) and optional `meta`.

### Merkle tree

A tree of hashes over the manifest's file entries
(RFC 9162). Its root is what a format 2 seal signs, so one entry can be
shown with its [audit path](#audit-path) without the others.

### ML-DSA

The lattice signature scheme of FIPS 204 (formerly
Dilithium): small, fast signatures. `ML-DSA-44`, `-65` and `-87` are its
security levels.

### ML-KEM

The lattice KEM of FIPS 203 (formerly Kyber).

### Pin (`-p`)

Giving `noqtis check` the public key you expect. Without
it a check proves the files are unchanged since *someone* sealed them,
not who.

### Post-quantum

Believed secure against an attacker with a large
quantum computer, which would break RSA, ECDSA and Ed25519. ML-DSA,
SLH-DSA, ML-KEM and HQC are post-quantum.

### Proof

A file from `noqtis prove` showing that some files are in a
format 2 capsule, without naming or giving the digests of the others.
`noqtis check --proof` checks it.

### RFC 3161 timestamp

A token from a time-stamping authority (TSA)
saying that a digest existed at a time, signed by the TSA. A seal can
carry one over its signature (`seal --tsa`, `noqtis timestamp`), which
proves the seal is no younger than that time.

### RO-Crate

A JSON-LD description of a research dataset
(`ro-crate-metadata.json`). `noqtis export --as rocrate` writes one for a
capsule.

### Seal

`noqtis.sig`: the algorithm, the public key, the signature
over the manifest (or, in format 2, over its head) and an optional
timestamp.

### SLH-DSA

The hash-based signature scheme of FIPS 205 (formerly
SPHINCS+). Its security rests only on the hash function; signatures are
larger and slower than ML-DSA's.

### SLSA

Supply-chain Levels for Software Artifacts: a framework for
build provenance. Its provenance statements are in-toto statements.

### Transparency log

A public append-only log of signatures or
certificates (Sigstore's Rekor, Certificate Transparency). NOQTIS has
none: a capsule needs no service to be checked, and a timestamp is how
it proves a time.

### TSA

Time-stamping authority: a service that signs RFC 3161
timestamps. NOQTIS fetches tokens over `http://`; the token is itself
signed, so it needs no TLS.
