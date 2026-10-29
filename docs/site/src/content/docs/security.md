---
title: Security
description: Threat model, what a check does and does not verify, constant-time and masking claims and how they are tested, test vectors, fuzzing, audit status and reporting.
---

:::caution[Not yet audited]
NOQTIS has not had an external security audit. Until an audit report is
published, treat NOQTIS as unaudited code.
:::

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the
[repository's Security tab](https://github.com/rootcoder007/noqtis/security),
not in a public issue. We aim to reply within 7 days and to publish a fix
and advisory within 90 days. See `SECURITY.md`.

## Threat model

**What NOQTIS protects.** The integrity and origin of a set of files: that
a folder holds exactly the files a key holder sealed, byte for byte, and
nothing else; and, with a timestamp, that the seal existed at a time a TSA
vouches for. Signatures are post-quantum (ML-DSA, SLH-DSA), so the record
stays checkable after large quantum computers break RSA and elliptic
curves.

**Against whom.**

- Anyone who changes, adds, removes or renames a file in a capsule, edits
  the manifest or seal, or reseals with another key: a check with the
  pinned key fails.
- A hostile capsule built to attack the checker: every parser is strict and
  bounded (sizes, counts, depth), uses no recursion, never follows links,
  and fails closed; a check that cannot be made is a failed check.
- An attacker who measures time, cache or branch behaviour while NOQTIS
  handles secret keys, seeds or shared secrets (see below).
- A future attacker with a quantum computer, against the signatures.

**What NOQTIS does not protect.**

- **Who the key holder is.** The seal carries a public key; without
  `-p` (or `trust` in C) a check accepts it. Getting the right public key
  is your job.
- **When**, without a timestamp: `created` is the sealer's own clock.
- **Correctness or completeness of a result.** A capsule records what was in
  the folder, not how it was produced or whether other inputs were used.
- **A stolen secret key.** Whoever holds it can seal anything. There is no
  revocation in the format.
- **The machine you run on.** Malware on the sealing or checking machine,
  or a compromised compiler or package, defeats any tool.
- **Confidentiality.** Capsules are not encrypted; the manifest lists every
  path. The KEM commands give a shared secret, not an encrypted channel.
- **Physical side channels beyond first order.** Masking is first-order
  only (see below); power or electromagnetic attacks with many traces and
  higher-order analysis are out of scope.
- **Metadata** the format does not record: empty folders, permissions,
  owners, file times.

## What a check verifies

| Verified | How |
|---|---|
| every listed file is present, regular, same size | the folder walked without following links |
| its content | SHA-256 **and** SHA3-256 recomputed from the bytes |
| no other file, link or special file is present | every entry under the root compared with the manifest |
| the manifest is what was signed | its SHA-256 against the seal, and the signature over its exact bytes |
| the key | byte-equal to the pinned key, when one is given |
| both files are well formed | canonical JSON, exact fields, limits |
| the timestamp | RFC 3161 token, imprint, signer certificate path to an anchor at genTime (C API with anchors) |

| Not verified | |
|---|---|
| who owns the key | your trust in the `.pub` you pin |
| the `created` time | not evidence |
| `meta` | stored and signed, never interpreted |
| a timestamp, when no anchors are given | it fails the check instead of passing |

## Constant time and masking

**Claim.** In key generation, signing, encapsulation and decapsulation, no
branch, memory index or variable-time instruction (division, variable
shifts) depends on a secret key, seed, signing randomness or shared
secret, except the values the standards themselves make public (for
example ML-DSA's rejection decisions and hint, SLH-DSA's published tree
roots). ML-DSA signing and ML-KEM decapsulation are also first-order
masked: secrets are split into two random shares (for ML-KEM drawn fresh
from the random source on every call). The base64 coder that reads key files is constant
time too.

**How it is tested.**

- **ctgrind** (valgrind memcheck with secrets marked undefined): each
  secret-handling module has a test (`tests/tmldsact.c`,
  `tests/tslhct.c`, `tests/tmlkemct.c`, `tests/thqcct.c`,
  `tests/tdrbgct.c`, `tests/tclsct.c`). Built with `-DNQCTGRIND` and run
  under valgrind, memcheck reports any branch or address that depends on a
  secret. The places a standard publishes a value are declassified
  explicitly in the source, and only there. Built normally, the same files
  run as ordinary tests.
- **Masked against unmasked**: the masked and unmasked ML-DSA signers and
  ML-KEM decapsulation are run on the same inputs and must give the same
  bytes, including on tampered ciphertexts.
- **Not yet published**: dudect timing measurements and simulated TVLA
  leakage tests are part of the plan for every secret operation, and will
  be published with the release, with what they do and do not show. Until
  then the constant-time claim rests on the ctgrind tests and review.

ctgrind finds secret-dependent control flow and memory access in the
compiled code under test; it does not see variable-time CPU instructions
(such as division on some processors) or what another compiler might
generate, and masking is checked for correctness, not leakage, until the
TVLA results are published.

## Test vectors

Every algorithm is checked against the standards' own test vectors, in the
JSON files NIST's ACVP server publishes and in Google's/C2SP's Wycheproof:

| Algorithm | Vectors |
|---|---|
| ML-DSA (FIPS 204) | ACVP keyGen, sigGen, sigVer; Wycheproof `mldsa_*` sign and verify |
| SLH-DSA (FIPS 205) | ACVP keyGen, sigGen, sigVer for all twelve sets |
| ML-KEM (FIPS 203) | ACVP keyGen and encapDecap (including both key checks); Wycheproof `mlkem_*` |
| HQC v5.0.0 | the reference implementation's known answers (digests) |
| SHA-2, SHA-3, SHAKE | ACVP AFT and MCT (LDT on request) |
| HMAC | ACVP HMAC-SHA2 and HMAC-SHA3 |
| HMAC_DRBG | ACVP hmacDRBG |
| RSA, ECDSA (verification, for timestamps) | Wycheproof RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256 and P-384 |
| RFC 3161 tokens | real tokens from five public TSAs, a local OpenSSL TSA and rmoriebricklayer's, plus a mutation test of every byte |

Each test prints how many vectors of each set ran, passed and were
skipped; the CI logs of every push and the release notes carry those
counts. Every vector file's source URL and SHA-256 are in
`tests/vectors/SOURCES.md`. Each algorithm also has an ACVP harness that
writes responses in the format a CAVP lab accepts.

## Other testing

- Every test runs under AddressSanitizer and UBSan, and under valgrind, in
  CI; with GCC and Clang, on Linux distributions, macOS, Windows, FreeBSD,
  32-bit and big-endian Linux.
- Capsules: round trips, a tamper test of every byte, path containment
  (links, `..`, case collisions, special files), allocation failures, and
  a golden sample capsule.
- Fuzzing: a libFuzzer target for the DER reader (`fuzz/fder.c`). Fuzzing
  of every parser on each push, and an OSS-Fuzz application, are on the
  launch checklist.
- The command-line tool is tested as a user runs it, including exit codes,
  owner-only files and that no secret reaches standard output.

## Design choices that limit damage

- No third-party code at run time; one allocator hook; no `malloc` in the
  algorithm code; no recursion in parsers.
- Secrets are wiped on every path, including freed capsule memory.
- Randomness comes only from the operating system; there is no fallback.
- Fail closed everywhere: verification returns `NQOK` only for a valid
  signature, and unknown fields, non-canonical JSON or an uncheckable
  timestamp are failures.
