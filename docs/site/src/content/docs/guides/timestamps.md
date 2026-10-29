---
title: Timestamps
description: RFC 3161 timestamps over a capsule's signature, TSA trust anchors, and the current state of timestamp support.
---

A seal says *who* signed the files; a timestamp from a time-stamping
authority (TSA) says *when*: that the signature existed at a time the TSA
vouches for. This matters when a key later leaks or an algorithm weakens:
seals timestamped before that day remain evidence.

## How it works

The optional `timestamp` field of `noqtis.sig` holds an RFC 3161
time-stamp token, base64. The token's message imprint is the hash
(SHA-256, SHA-384 or SHA-512) of the decoded `signature` bytes, so the TSA
never sees the files or the manifest, only a digest of the signature.

A checker given TSA trust anchors (the TSAs' root or issuing certificates)
passes the `timestamp` row only when:

1. the token is a strict DER RFC 3161 token;
2. its imprint is its hash of the seal's signature;
3. its signature verifies under the TSA certificate, and that certificate's
   path leads to one of the anchors and is valid at the token's `genTime`.

The row's detail then shows the `genTime`.

## Fail closed

A timestamp that cannot be checked is never passed silently:

- checked **with** anchors, a seal **without** a timestamp fails the row;
- checked **without** anchors, a seal **with** a timestamp fails the row
  (`not checked: no TSA trust anchors given`), even when its imprint
  matches.

## Current state

:::caution[Not yet in the command-line tool]
`noqtis seal --tsa <url>` is reserved: this build does not request
timestamps and the option fails with exit 2. `noqtis check` takes no TSA
anchors, so a timestamped seal fails its `timestamp` row there. Timestamp
checking is available today through the C function
[nqchkt(3)](/noqtis/reference/man/nqchkt-3/).
:::

The token parser and verifier are tested against real tokens from five
public TSAs, a local OpenSSL TSA and rmoriebricklayer's, and with an
exhaustive mutation test of every token byte.

## From C

```c
const uint8_t *anc[2] = {tsa1_der, tsa2_der};   /* DER certificates */
size_t anclen[2] = {tsa1_len, tsa2_len};
nqrep *rep = NULL;
int rc = nqchkt("results", pk, sizeof pk, anc, anclen, 2, &rep);
```

Up to 32 anchors. Use more than one TSA for important records, so that one
TSA's compromise or disappearance does not leave a seal without a trusted
time.
