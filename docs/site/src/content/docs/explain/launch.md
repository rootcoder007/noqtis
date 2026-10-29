---
title: "NOQTIS: sealing the exact files behind a result, with post-quantum signatures"
description: The problem NOQTIS addresses, what it does, how it is tested, and its limits.
draft: true
---

<!-- Launch write-up. draft: true keeps it out of the published site until
     the launch checklist in DESIGN.md is done; check every claim against
     the code and CI again before removing it. -->

## The problem

Two problems meet in research data, software releases and anything else
whose results must be checked years later.

**Results cannot be traced to their data.** A figure or a release is the
output of particular files, but the record of which files is usually a
folder name, a checksum list that can be edited along with the files, or
nothing. Later nobody can show that a result came from these exact bytes,
or notice that a file was added or quietly replaced.

**Today's signatures will not last as long as the records.** RSA and
elliptic-curve signatures can be forged by a large enough quantum
computer. NIST's transition plan (NIST IR 8547) deprecates them after
2030 and disallows them after 2035. A seal made today with RSA or ECDSA
stops being evidence on the day its public key can be broken: anyone can
then sign different files under it. Records that matter for decades need
signatures designed to survive that.

The longer argument, with sources, is in
[Why post-quantum provenance now](/noqtis/explain/why/).

## What NOQTIS does

NOQTIS is one C11 library with no dependencies, and a command-line tool.

```sh
noqtis keygen -a ML-DSA-65 -o me
noqtis seal -k me results/
noqtis check -p me.pub results/      # exit 0
echo oops >> results/report.txt
noqtis check -p me.pub results/      # exit 1: report.txt: size differs
```

`seal` writes two files into the folder: `noqtis.json`, a canonical JSON
manifest of every file's path, size, SHA-256 and SHA3-256, and
`noqtis.sig`, a post-quantum signature (ML-DSA, FIPS 204, or SLH-DSA,
FIPS 205) over the manifest's exact bytes. `check` recomputes every
digest, fails on any file that is missing, changed or not listed, on any
link or special file, and on any edit to the manifest or the seal, and
prints one row per check so you see everything that is wrong at once.
It needs no network.

The library also provides ML-KEM (FIPS 203) and HQC key encapsulation,
SHA-2, SHA-3, SHAKE and HMAC, and checks RFC 3161 timestamp tokens over a
seal's signature through `nqchkt`. Bindings for Python, JavaScript
(WebAssembly, for Node and browsers) and R use the same library and read
and write the same capsules.

## How it was tested

What runs today, in CI on every push or on the weekly schedule:

- **Standard test vectors.** Every algorithm against NIST's ACVP vectors
  (ML-DSA, SLH-DSA all twelve sets, ML-KEM, SHA-2, SHA-3, SHAKE, HMAC,
  HMAC_DRBG) and the Wycheproof sets for ML-DSA, ML-KEM, RSA and ECDSA;
  HQC against its reference known answers. Each vector file's source and
  SHA-256 are recorded in `tests/vectors/SOURCES.md`.
- **Constant time.** ctgrind tests (valgrind memcheck with secrets marked
  undefined) for every module that handles secrets; ML-DSA signing and
  ML-KEM decapsulation are first-order masked and checked byte for byte
  against the unmasked code.
- **Memory safety.** Every test under AddressSanitizer and UBSan, and
  under valgrind (with the slowest vector sets sampled).
- **Capsules.** Round trips, a tamper test of every byte of a sealed
  capsule, path-containment tests (links, `..`, case collisions, special
  files), allocation failures, and real RFC 3161 tokens from public
  time-stamping authorities with a mutation test of every token byte.
- **The command-line tool,** run through the shell as a user would:
  exit codes, owner-only key files, no secret on standard output.
- **Platforms.** GCC and Clang on Linux (x86-64 and arm64, a dozen
  distributions, musl, 32-bit, big-endian s390x), macOS, Windows (MSVC,
  clang-cl, MinGW-w64) and FreeBSD.

- **Side channels.** dudect timing tests and the simulated TVLA run on
  every push and for longer every week (`ct.yml`).
- **Fuzzing.** libFuzzer runs on every parser of untrusted bytes, briefly
  on every push and for an hour every week (`fuzz.yml`).

Not yet done: OpenSSL 3.5 differential tests beyond a fixed set of
cross-checks, fuzzed command-line arguments, and an external security
audit.

## Limits

- **Not audited.** Do not rely on NOQTIS for anything that matters until
  an external audit is published.
- A passing check says the files are exactly those a key holder sealed.
  It does not say the result is correct, that these were the only
  inputs, or who the key holder is: you pin the public key you trust.
- Without a timestamp, a seal does not prove when it was made. The
  command-line tool does not request timestamps yet; the library checks
  them.
- There is no revocation: a stolen secret key can seal anything.
- Capsules are not encrypted.

## Try it

- [Install](/noqtis/start/install/) and [your first capsule](/noqtis/start/quick/).
- From [C](/noqtis/guides/c/), [Python](/noqtis/guides/py/),
  [JavaScript](/noqtis/guides/js/) or [R](/noqtis/guides/r/).
- The [capsule format](/noqtis/spec/capsule/) and the
  [security page](/noqtis/security/).
- Source, issues and contributions: <https://github.com/rootcoder007/noqtis>.
