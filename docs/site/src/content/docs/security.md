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
masked. The evidence for the masking is a simulated TVLA over the values
the code computes, not power or EM traces from real hardware: it shows
the shares are used as intended, not that a given chip leaks nothing,
and compilers and processors can recombine shares in ways a simulation
does not see. Masked: secrets are split into two random shares (for ML-KEM drawn fresh
from the random source on every call), first order in the value model,
from the point the stored key is split (see the TVLA results below). The base64 coder that reads key files is constant
time too.

**How it is tested.**

- **ctgrind** (valgrind memcheck with secrets marked undefined): each
  secret-handling module has a test (`tests/tmldsact.c`,
  `tests/tslhct.c`, `tests/tmlkemct.c`, `tests/thqcct.c`,
  `tests/tdrbgct.c`, `tests/tclsct.c`, `tests/tecdhct.c`). Built with `-DNQCTGRIND` and run
  under valgrind, memcheck reports any branch or address that depends on a
  secret. The places a standard publishes a value are declassified
  explicitly in the source, and only there. Built normally, the same files
  run as ordinary tests. CI runs the check on every push (`ct.yml`, job
  `ctgrind`) on gcc and clang Release builds, the way users build the
  library, after checking that valgrind does catch a deliberately
  secret-dependent branch.
- **Masked against unmasked**: the masked and unmasked ML-DSA signers and
  ML-KEM decapsulation are run on the same inputs and must give the same
  bytes, including on tampered ciphertexts.
- **dudect** (`ct/dd.c`): timing, measured. See below.
- **Simulated TVLA** (`ct/tv.c`): first-order leakage of the masked code,
  simulated. See below.

ctgrind finds secret-dependent control flow and memory access in the
compiled code under test; it does not see variable-time CPU instructions
(such as division on some processors) or what another compiler might
generate. dudect sees those on the machine it runs on, and only there.

### Timing: dudect

**Method.** The fixed-against-random test of Reparaz, Balasch and
Verbauwhede (*Dude, is my code constant time?*, DATE 2017), written in
C11 with no dependencies. Each measurement times one call (or a fixed
batch of calls) with ISO C `timespec_get` on an input of class 0 or
class 1, the class drawn at random per measurement. Inputs for a chunk
of measurements are made before any of them is timed and reach their
slot by the same copy in both classes. Welch's t compares the classes on
the raw times and under 100 upper crops; a target **passes when every
|t| < 4.5** after its N measurements. Inputs and classes come from a
seeded generator (`-s`), so a run repeats. A control, an early-exit
compare, runs first and must be detected (|t| > 10), or the run stops:
otherwise the clock could not have seen a leak.

What differs between the classes is the secret. Where an operation's
time depends on a public value by design, that value is the same in both
classes or random in both:

- ML-DSA signing: every input signs in one attempt (the number of
  attempts is public: a signature's time shows it), all keys of a test
  share rho (ExpandA rejects on rho), and both classes draw a fresh rnd
  (so c~, and SampleInBall's rejections, vary in both).
- ML-KEM decapsulation, key test: all keys share rho (SampleNTT rejects
  on rho during re-encryption); validity test: one key, valid against
  random (implicitly rejected) ciphertexts.
- HQC decapsulation, key test: keys whose y-sampler (re-run from seed_dk
  in every decapsulation) drew no rejected and no repeated position, as
  most keys do. The sampler's rejections and repeats are declared public
  in the code, as the specification allows; they are fixed per key, so
  they are the one place HQC decapsulation time may depend on the key.

**Results**, on an Intel Core i5-10310U (Linux 7.2.11, GCC 16.2.1,
`-O3` Release build, `taskset` to one core, other jobs running on the
other cores), `nqdd -n 40000 -s 1`, measured for the tree of the commit
that added `ct/`:

| Operation | Classes | N | max \|t\| | |
|---|---|---|---|---|
| control: early-exit compare | equal vs random | 40,000 | 39,927 | detected |
| `nqcteq` (64 bytes) | equal vs random | 40,000 | 1.67 | pass |
| `nqcmov` (32 bytes) | no copy vs random condition and source | 40,000 | 1.42 | pass |
| `nqctmask` / `nqctsel` | zero vs random words | 40,000 | 1.74 | pass |
| key-file base64 encode / decode | fixed vs random | 40,000 | 1.31 / 1.51 | pass |
| seed hex decode | fixed vs random | 40,000 | 1.90 | pass |
| HMAC-SHA-256 / -512 | fixed vs random key | 40,000 | 1.36 / 1.19 | pass |
| HMAC_DRBG SHA-256 / -512 | fixed vs random entropy | 40,000 | 2.19 / 1.68 | pass |
| ML-KEM-512 / 768 / 1024 masked decaps | one key vs others | 5,000 | 2.67 / 1.72 / 3.08 | pass |
| ML-KEM-512 / 768 / 1024 masked decaps | valid vs random ciphertexts | 5,000 | 3.61 / 2.19 / 1.62 | pass |
| ML-KEM-512 / 768 / 1024 unmasked decaps | one key vs others | 40,000 | 1.82 / 1.59 / 1.61 | pass |
| ML-KEM-512 / 768 / 1024 unmasked decaps | valid vs random ciphertexts | 40,000 | 1.25 / 1.28 / 2.14 | pass |
| ML-DSA-44 / 65 / 87 masked sign | one key vs others | 2,500 | 2.07 / 1.38 / 1.80 | pass |
| ML-DSA-44 / 65 unmasked sign | one key vs others | 20,000 | 1.99 / 1.83 | pass |
| ML-DSA-87 unmasked sign | one key vs others | 20,000 | 4.55 | fail, see below |
| SLH-DSA-SHA2-128f sign | one key and opt_rand vs others | 1,250 | 5.72 | fail, see below |
| SLH-DSA-SHAKE-128f sign | one key and opt_rand vs others | 625 | 4.83 | fail, see below |
| HQC-128 / 192 / 256 decaps | one key vs others | 10,000 / 5,000 / 2,500 | 1.57 / 2.73 / 1.51 | pass |
| HQC-128 / 192 / 256 decaps | valid vs random ciphertexts | 10,000 / 5,000 / 2,500 | 0.43 / 1.69 / 2.08 | pass |

The three failures are in crops (keeping the fastest 24 to 56% of the
measurements) of the slowest targets, 0.8 ms per ML-DSA-87 signature and
63 ms and 160 ms per SLH-DSA signature, with raw |t| of 1.41, 0.22 and
0.66. Measured again with
another seed and more measurements (`nqdd -n 128000 -s 3`), ML-DSA-87
unmasked signing gave max |t| 1.41 over 64,000 measurements and
SLH-DSA-SHA2-128f 3.59 over 4,000 and SLH-DSA-SHAKE-128f 2.24 over 2,000:
all pass. Nothing in SLH-DSA signing branches on or indexes by a secret
(ctgrind), so we read the first run as noise; they are reported as failures above because that is what the first run
gave; nothing in the code under test was changed between the runs.

**Public values, measured on purpose** (`nqdd -n 20000 -s 2 -t kg,raw`).
These show what the designs above exclude, and they fail:

| Target | max \|t\| | Why |
|---|---|---|
| ML-KEM-512 / 768 / 1024 keygen, fixed vs random seed | 27.4 / 127.0 / 110.6 | rho comes from the secret seed; SampleNTT rejects on it |
| SampleNTT alone on the same rho (768) | 185.5 | 3.37 us mean difference, more than keygen's 2.76 us |
| ML-KEM-768 unmasked decaps, keys from keygen | 135.9 | each key has its own rho |
| ML-DSA-44 unmasked sign, keys from keygen, one rnd | 21.0 | rho and c~ differ by class |
| HQC-128 decaps, keys from keygen | 2.70 | the sampler's counts differ by key; not resolved at 5,000 (an earlier run at 2,000 gave 6.17) |

So ML-KEM key generation does not pass a fixed-vs-random-seed test, and
cannot: its time depends on rho, which FIPS 203 makes public. Its
secret-dependent part is covered by ctgrind, not by dudect.

**What this shows and does not show.** A pass means this machine, with
this compiler and these flags, did not resolve a timing difference
between the classes in N measurements. It does not show the absence of a
smaller difference, a difference on another CPU (for example one with
variable-time multiplication), another compiler or other flags, cache or
branch-predictor effects across processes, or anything about power or
electromagnetic emanation. CI (`.github/workflows/ct.yml`) runs the same
harness on shared GitHub runners, short on every push and long weekly;
there the noise is larger and a pass is weaker evidence still.

### Simulated power: TVLA

**Method.** The library built with `-DNQTVLA` (a test build only)
compiles hooks in the masked ML-KEM decapsulation (`src/mlkem/mdec.c`)
and ML-DSA signer (`src/mldsa/msk.c`): every share word passed through
the gadgets' opaque copies, every 64-bit lane of the masked Keccak, the
share polynomials after each linear step, the stored key as it is loaded
and split, and the unmasked output. In every other build the hooks are
`((void)0)`: the release objects are byte-identical with and without
them (all 37 objects of `libnoqtis.a`, GCC 16.2.1 and Clang 22.1.8,
Release, compared with `cmp`). A trace is one call; each recorded value
gives one sample under two models: its Hamming weight (the value model)
and its Hamming distance from the value recorded before it (the
transition model). The test is TVLA (Goodwill et al. 2011; ISO/IEC
17825): one secret against random secrets, Welch's t at every sample in
two independent sets of traces; a point leaks when **|t| > 4.5 in both
sets with the same sign**. Samples that fewer than 30 traces of a class
reach are not assessed (none were, in the run below). Controls run the
same code with every mask forced to zero and must be flagged.

- ML-KEM: one ciphertext for both classes, valid under the fixed key and
  so rejected under every random key.
- ML-DSA, key test: one mu, every input signing in one attempt, a fresh
  rnd in both classes. Nonce test (`mldsa44y`): one key, one rnd against
  random rnd, which asks whether y, w and z leak. There w1 differs by
  class; it is public (the signer reveals it), so share words ANDed with
  constants made from it leak only those constants and are reported
  apart, not judged.

**Results** (`nqtv -n 10000 -s 1`, same machine):

| Operation | Traces | Samples | Masked, value model: max \|t\|, points | Masked, transition model: points | Key load and split | Output |
|---|---|---|---|---|---|---|
| ML-KEM-512 decaps | 10,000 | 123,360 | 4.19, 0: pass | 13,150 | leaks (985 points) | leaks |
| ML-KEM-768 decaps | 10,000 | 155,184 | 4.67, 0: pass | 16,004 | leaks (1,451) | leaks |
| ML-KEM-1024 decaps | 10,000 | 195,984 | 4.87, 0: pass | 20,250 | leaks (1,917) | leaks |
| ML-DSA-44 sign, key test | 2,500 | 672,528 | 5.57, 0: pass | 0 | leaks (6,155) | no points |
| ML-DSA-65 sign, key test | 1,250 | 939,728 | 5.60, 0: pass | 4 | leaks (8,399) | no points |
| ML-DSA-87 sign, key test | 1,250 | 1,271,728 | 5.20, 0: pass | 0 | leaks (11,680) | no points |
| ML-DSA-44 sign, nonce test | 2,500 | 672,528 | 5.14, 0: pass | 104,959 | none | leaks (z is public) |
| control: ML-KEM-768, masks zero | 2,500 | 155,184 | 87,511 points: flagged | | | |
| control: ML-DSA-44 key test, masks zero | 1,250 | 672,528 | 47 points: flagged | | | |
| control: ML-DSA-44 nonce test, masks zero | 1,250 | 672,528 | 366,321 points: flagged | | | |

"max |t|" is the largest in either set; a point needs both. In the value
model no masked sample leaks in any operation, and every control does.

Three findings, none of them tuned away:

- **The key is loaded unmasked.** Secret keys are stored as the
  standards encode them, so their coefficients pass through the code
  unmasked before they are split; those samples leak, as they must.
  Splitting also leaks one more first-order bit per coefficient: the
  share is formed as (v - r) mod q with a conditional addition of q,
  and the mask that selects it is the sign of v - r, whose probability
  depends on v (ML-KEM 664 points, ML-DSA-44 3,072 at step 1). Masking
  protects everything after the split, not the key at rest or its
  loading.
- **The transition model fails.** Shares of one value are written one
  after the other, so the Hamming distance between consecutive recorded
  values is often the distance between the two shares, which is the
  secret. The reference implementations avoid this with assembly and
  register scrubbing, which ISO C cannot express; noqtis does not claim
  security in the transition model, nor against glitches.
- **ML-DSA's key test is weaker than the others.** With a fresh rnd in
  both classes most values are already random whatever the key, so even
  the unmasked control is flagged only at the key's split and the masked
  hashing of K (47 points). The nonce test, whose control is flagged
  everywhere, covers y, w, z and the checks.

**What this shows and does not show.** It shows that the values the C
code computes in the masked parts are, one at a time, independent of the
secret to the resolution of these traces. It is a model, not a power
measurement: it does not see what a CPU does with the values (registers
the compiler reuses, a value and its complement on one bus, glitches,
the transitions inside a gadget), nor any leakage of the order of two or
more. It does not cover the unmasked signer and decapsulation
(`nqmdspl`, `nqmkdecp`), SLH-DSA, HQC or key generation, which are not
masked. No physical power or electromagnetic traces have been taken.

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
- Fuzzing: libFuzzer targets for every parser of untrusted bytes (DER,
  X.509, OCSP, timestamp tokens, JSON, capsules, key files, base64) and
  for the command line's arguments, 90 seconds each on every push and an
  hour weekly (`fuzz/`); OSS-Fuzz application filed.
- OpenSSL 3.5 or later: `tests/ossl/xossl.c` checks that ML-DSA, all
  twelve SLH-DSA sets and ML-KEM give the same keys, signatures,
  ciphertexts and secrets as OpenSSL from the same seeds, that the
  digests and HMACs agree, and that noqtis accepts the RSA and ECDSA
  signatures OpenSSL makes and refuses changed ones; `fuzz/ossl/fdiff.c`
  fuzzes the same comparisons, and noqtis must never accept an RSA or
  ECDSA signature that OpenSSL refuses.
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
