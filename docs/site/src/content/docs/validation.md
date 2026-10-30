---
title: Validation
description: How an accredited lab would run NIST ACVP against NOQTIS, which algorithms and parameter sets the harnesses cover, and what has and has not been validated.
---

:::caution[No certificate]
NOQTIS has no CAVP algorithm certificate and no CMVP module certificate.
No lab has tested it. What this page describes is ready for a lab to
run; it is not a validation.
:::

## What is ready

NIST validates an algorithm implementation through the Cryptographic
Algorithm Validation Program (CAVP). An accredited lab registers the
implementation's capabilities with NIST's ACVP server, downloads test
requests (vector sets) for them, has the implementation answer each one,
and uploads the responses. NOQTIS has one ACVP harness per algorithm
family in `acvp/`: each reads a request file and writes the response
file, computed by the library itself. A CMVP module validation
(FIPS 140-3) needs more than this: a defined module boundary, power-on
self-tests, a security policy and a lab's review. NOQTIS has none of
these yet.

The test suite runs every harness on NIST's own sample vector sets
(`tests/vectors/acvp/`, from the ACVP-Server repository's `gen-val`
files, each with its SHA-256 in `tests/vectors/SOURCES.md`) and checks
every response against NIST's expected results, in CI.

## Algorithms covered

| Harness | ACVP algorithm, revision | Modes and tests |
|---|---|---|
| `acvmd` | ML-DSA (FIPS204): ML-DSA-44, 65, 87 | keyGen; sigGen and sigVer, external (pure and pre-hash, with a context) and internal (message or external mu), deterministic and hedged |
| `acvsl` | SLH-DSA (FIPS205): all twelve parameter sets | keyGen; sigGen and sigVer, external (pure and pre-hash) and internal, deterministic and hedged |
| `acvmk` | ML-KEM (FIPS203): ML-KEM-512, 768, 1024 | keyGen; encapDecap: encapsulation, decapsulation, and both key checks |
| `acvsh` | SHA2-224, 256, 384, 512, 512/224, 512/256 (1.0); SHA3-224, 256, 384, 512 (2.0); SHAKE-128, SHAKE-256 (FIPS202) | AFT, MCT (SHA-2 standard and alternate, SHA-3 standard), LDT; SHAKE AFT, VOT and MCT |
| `acvhm` | HMAC-SHA2-224 to HMAC-SHA2-512/256, HMAC-SHA3-224 to HMAC-SHA3-512 (2.0) | AFT, truncated MACs |
| `acvdr` | hmacDRBG (1.0) with SHA2-256 and SHA2-512 | AFT, with and without prediction resistance and reseed |

No harness: HQC (ACVP has no HQC tests yet), Ed25519, and the
verification-only RSA and ECDSA used for timestamps. A lab must not
register SHA-3 with the alternate Monte Carlo test, or hmacDRBG with
other hashes: NOQTIS does not provide them, and the harnesses leave
such groups out of the response with a message.

## Running the harnesses

Build them with the tests (the default), with sampling switches unset:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
unset NQFAST NQSLSUB
```

The harnesses are then in `build/acvp/`. One request at a time:

```sh
build/acvp/acvmd request.json response.json
```

A request may be the vector set object alone (the form of the
`gen-val` files) or the form a live ACVP server sends,
`[{"acvVersion": "1.0"}, {vector set}]`. The response takes the same
form, with the request's `vsId`, `algorithm`, `mode`, `revision` and
`isSample`, and one entry per test. Hex is written in upper case.

A whole session at once: save each request the lab's ACVP client
downloads as `<name>.json` in one folder, and run

```sh
sh acvp/run.sh build/acvp requests/ responses/
```

`run.sh` picks the harness from each request's `algorithm`, writes
`responses/<name>.json`, and exits 0 only when every request was
answered. Give the response files back to the client to upload.

With an expected-results file as a third argument (or
`run.sh -e <folder>`), a harness also compares its response with it:
the same tests, with equal values in each field (key order and hex
case do not matter). This is how the test suite checks the harnesses.

The exit status is 0 when the response was written (and matches) and 1
otherwise. A test the harness cannot answer (a missing or malformed
field) stops it with a message naming its `tgId` and `tcId`, and no
response is written. A harness that left tests out because `NQFAST` or
`NQSLSUB` was set says "not a complete response" on stderr: such a
response is not for submission.

## Run time

Most vector sets take seconds. Signing with an SLH-DSA "s" parameter
set takes seconds per test, and the large-data hash tests (LDT) hash up
to 8 GiB each, so a full run of those sets takes minutes.

## What the harnesses run

They call the library's own code, the paths the public API uses: ML-DSA
signing through the masked signer, ML-KEM decapsulation through the
masked decapsulation. A signature or key check that fails for any
reason (it does not verify, does not decode, or has a wrong length) is
answered `"testPassed": false`.

The harnesses themselves are in `acvp/`, with a README of the same
material for a reader of the source.
