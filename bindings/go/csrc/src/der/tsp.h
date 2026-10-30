/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RFC 3161 timestamp tokens: a CMS SignedData (RFC 5652) over a TSTInfo,
 * alone or inside a TimeStampResp, read strictly by position. Internal.
 *
 * The layout accepted, field by field (anything else is NQEDEC, or
 * NQENOSUP for a valid form this module does not handle):
 *   TimeStampResp   SEQUENCE { PKIStatusInfo (status 0 or 1, no
 *                   failInfo), token }                          optional
 *   ContentInfo     SEQUENCE { id-signedData, [0] EXPLICIT SignedData }
 *   SignedData      version 3, digestAlgorithms (exactly one, the
 *                   signer's), encapContentInfo { id-ct-TSTInfo,
 *                   [0] EXPLICIT OCTET STRING }, [0] certificates
 *                   (Certificate only), no crls, exactly one SignerInfo
 *   SignerInfo      version 1 with issuerAndSerialNumber or 3 with
 *                   [0] subjectKeyIdentifier, digestAlgorithm,
 *                   [0] signedAttrs (required, DER order), signature
 *                   algorithm, signature, no unsignedAttrs
 *   signedAttrs     exactly one contentType (id-ct-TSTInfo), exactly one
 *                   messageDigest, at most one signingTime, an ESS
 *                   signingCertificate or signingCertificateV2, no
 *                   attribute type twice
 *   TSTInfo         version 1, policy, messageImprint, serialNumber,
 *                   genTime, [accuracy], [ordering], [nonce], [0] tsa,
 *                   [1] extensions (none critical)
 */
#ifndef NQTSP_H
#define NQTSP_H

#include <stddef.h>
#include <stdint.h>

#include "der/der.h"
#include "der/x509.h"

#define NQTSCERTS 8   /* certificates a token may carry */
#define NQTSEXTRA 8   /* certificates the caller may add */
#define NQTSSA 4096   /* the largest signedAttrs */

typedef struct {
  int status;        /* PKIStatus of a TimeStampResp, -1 for a bare token */
  nqspan tok;        /* the ContentInfo */
  nqspan certs[NQTSCERTS];
  size_t ncert;
  /* SignerInfo */
  int sver;          /* 1 or 3 */
  nqspan sidiss;     /* v1: the issuer Name element */
  nqspan sidser;     /* v1: the serial INTEGER contents */
  nqspan sidski;     /* v3: the key identifier */
  nqhalg dalg;       /* digestAlgorithm */
  nqspan sattrs;     /* [0] signedAttrs as it appears */
  uint8_t sab[NQTSSA]; /* the same bytes with the SET tag: what is signed */
  size_t sabn;
  nqspan md;         /* messageDigest */
  int essv;          /* 1 or 2 (both present: 2 checked, 1 too) */
  nqhalg ess1;       /* 0: SHA-1 */
  nqspan esshash1;   /* signingCertificate certHash, or empty */
  nqspan essis1;     /* its IssuerSerial element, or empty */
  nqhalg ess2;
  nqspan esshash2;   /* signingCertificateV2 certHash, or empty */
  nqspan essis2;
  nqspan said;       /* signatureAlgorithm element */
  nqspan sig;
  /* TSTInfo */
  nqspan tst;        /* the TSTInfo DER (eContent) */
  nqspan policy;     /* OID contents */
  nqhalg ialg;
  nqspan imp;        /* hashedMessage */
  nqspan serial;     /* INTEGER contents */
  int64_t gt;        /* genTime, seconds since the epoch */
  uint32_t gtns;     /* and nanoseconds */
  int hasacc;
  int64_t accs, accms, accus;
  int ordering;
  int hasnonce;
  nqspan nonce;      /* INTEGER contents */
  nqspan tsa;        /* the GeneralName element, or empty */
} nqts;

/* Parses a TimeStampResp or a bare token spanning all n bytes. */
int nqtsprs(const uint8_t *p, size_t n, nqts *ts);

typedef struct {
  nqhalg halg;          /* the caller's hash of the data */
  const uint8_t *dig;
  size_t diglen;
  const uint8_t *nonce; /* the request's nonce (big-endian); NULL: none */
  size_t noncelen;
  const uint8_t *pol;   /* a policy OID (contents) to require, or NULL */
  size_t pollen;
  const nqcert *anc;    /* trust anchors (at least one) */
  size_t nanc;
  const nqcert *extra;  /* certificates beyond the token's */
  size_t nextra;
  int uset;             /* 1: check the path at t; 0: at genTime */
  int64_t t;
  const nqxops *ops;
  int self;             /* 1: no anchors; see nqtsvrf */
} nqtsarg;

/* Parses and verifies: the imprint is the caller's hash, the nonce and
 * policy match when given, the signer certificate (from the token or
 * extra, named by the sid, bound by the ESS attribute) signed the
 * signed attributes, which commit to this TSTInfo, its key and the
 * signature algorithm agree with the digest algorithm, the signer is a
 * TSA certificate (extendedKeyUsage critical and only timeStamping) on a
 * path to an anchor valid at genTime (or a->t), and every certificate
 * the token carries is on that path, is byte-equal to an anchor, or is
 * an alias of an anchor (the anchor's subject and SubjectPublicKeyInfo,
 * nqxalias, whoever issued it: a cross-certificate or a copy of the
 * root; it must still parse strictly, and nothing else in it is used).
 * ts gets the token's fields. NQOK
 * only when all of it holds.
 *
 * With a->self (and no anchors) no path is built: the token must still
 * pass every check up to its signer being a TSA certificate valid at
 * genTime. That shows the reply is a token over this data, not that the
 * TSA is trusted: for seal time only, never for a check. */
int nqtsvrf(const uint8_t *p, size_t n, const nqtsarg *a, nqts *ts);

#endif /* NQTSP_H */
