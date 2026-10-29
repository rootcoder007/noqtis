---
title: Timestamps
description: RFC 3161 timestamps over a capsule's signature, from the command line or from C, and the TSA trust anchors that check them.
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

## From the command line

```sh
noqtis seal -k me --tsa http://timestamp.digicert.com \
  --tsa http://timestamp.sectigo.com results
noqtis check -p me.pub --anchor digicert.der --anchor sectigo.der results
```

`seal --tsa` builds the request over the new seal's signature (the
SHA-256 of the signature, a random nonce, and a request for the TSA's
certificate), sends it by an HTTP/1.1 POST
(`application/timestamp-query`) and checks the reply before storing it:
granted, its imprint the hash of this signature, its nonce the one sent,
and its signature valid under the TSA certificate at genTime. With
`--anchor` at seal time, that certificate must also lead to one of the
anchors.

A seal holds one timestamp. Give `--tsa` more than once for fallbacks:
they are tried in order until one gives a token that checks. When none
does, the new `noqtis.json` and `noqtis.sig` are removed and the exit
status is 2, so a folder is never left sealed without the timestamp that
was asked for. `check` accepts a token from any TSA whose anchor it is
given (`--anchor`, up to 32): one that verifies is enough.

Only `http://` URLs: the token is signed by the TSA, so TLS adds no
integrity, and noqtis links no TLS library. `https://` is refused with
that said. Most public TSAs answer on `http://`, for example
`http://timestamp.digicert.com`, `http://timestamp.sectigo.com` and
`http://freetsa.org/tsr`. There is no proxy support.

`check --anchor` takes the TSA's root or issuing certificate in DER
(convert PEM with `openssl x509 -in tsa.pem -outform DER -out tsa.der`).
The `timestamp` row then shows the genTime.

The token parser and verifier are tested against real tokens from five
public TSAs, a local OpenSSL TSA and rmoriebricklayer's, and with an
exhaustive mutation test of every token byte. The command-line tests run
`seal --tsa` against a local OpenSSL TSA over HTTP, never the network.

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

To add a timestamp from C, the library builds the request and checks the
reply; the caller sends it:

```c
uint8_t nonce[8], req[128];
size_t qn;
const char *why;
int64_t gt;
nqrand(nonce, sizeof nonce);
nqtsreq("results", nonce, sizeof nonce, req, sizeof req, &qn);
/* POST req to the TSA; rsp, rn: the body of its reply */
rc = nqtsput("results", rsp, rn, nonce, sizeof nonce, anc, anclen, 2,
             &gt, &why);   /* NQOK: stored; else why says what failed */
```

See [nqtsput(3)](/noqtis/reference/man/nqtsput-3/).
