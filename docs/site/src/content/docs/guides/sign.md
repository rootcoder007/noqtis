---
title: Sign and verify a file
description: Detached ML-DSA and SLH-DSA signatures of single files, with contexts, deterministic signing and pre-hashing.
---

For one file, a detached signature is simpler than a capsule.

```sh
$ noqtis keygen -a ML-DSA-65 -o me
ML-DSA-65 key pair: me (secret), me.pub (public)
$ noqtis sign -k me report.pdf          # writes report.pdf.sig
$ noqtis verify -p me.pub -s report.pdf.sig report.pdf
report.pdf: OK (ML-DSA-65)
```

`verify` exits 0 when the signature is valid, 1 when it is not, 2 on a
usage or file error:

```sh
$ echo changed >> report.pdf
$ noqtis verify -p me.pub -s report.pdf.sig report.pdf; echo $?
noqtis verify: report.pdf: FAILED: the signature does not verify
1
```

The signature file is raw bytes in the standard's encoding (FIPS 204 or
205), so any conforming implementation can check it with the public key.

## Context strings

FIPS 204 and 205 sign a *context* string with the message, up to 255
bytes. A signature made for one context never verifies under another, so a
signature for "release notes" cannot be replayed as one for "invoice".

```sh
$ noqtis sign -k me -c release-2026 -o notes.sig notes.txt
$ noqtis verify -p me.pub -s notes.sig -c release-2026 notes.txt
notes.txt: OK (ML-DSA-65)
```

## Deterministic signatures

By default signing is *hedged*: fresh randomness goes into each signature,
so signing twice gives two different (both valid) signatures. `-d` uses the
standard's deterministic variant (all-zero randomness), so the same key,
file and options give the same bytes, which helps reproducible builds:

```sh
$ noqtis sign -k me -d -o a.sig notes.txt
$ noqtis sign -k me -d -o b.sig notes.txt
$ cmp a.sig b.sig && echo same
same
```

Prefer hedged signing unless you need identical bytes.

## Pre-hash (HashML-DSA, HashSLH-DSA)

`--ph <hash>` signs a digest of the file, with the hash's identifier, as the
standards' pre-hash variants define. It must be given again to verify.

```sh
$ noqtis sign -k me --ph sha512 -o big.sig big.tar
$ noqtis verify -p me.pub -s big.sig --ph sha512 big.tar
big.tar: OK (ML-DSA-65)
```

The pure variant (no `--ph`) is the default and the one capsules use.

## Standard input

```sh
$ tar cf - results | noqtis sign -k me -o results.tar.sig -
```

## In C

```c
#include <noqtis.h>

static uint8_t pk[1952], sk[4032], sig[3309];
size_t n = 0;
int rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
if (rc == NQOK)
  rc = nqsign(NQMLDSA65, sk, sizeof sk, msg, msglen, NULL, 0, 0,
              sig, sizeof sig, &n);
nqwipe(sk, sizeof sk);
if (rc == NQOK)
  rc = nqvrfy(NQMLDSA65, pk, sizeof pk, msg, msglen, NULL, 0, 0, sig, n);
/* rc == NQOK only for a valid signature */
```

See [nqsign(3)](/noqtis/reference/man/nqsign-3/) and the
[C API](/noqtis/reference/c-api/).
