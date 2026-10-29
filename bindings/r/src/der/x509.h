/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X.509 certificates (RFC 5280), read by position; path checks to a
 * caller-supplied trust anchor; OCSP responses (RFC 6960) and CRLs
 * (RFC 5280 section 5). Internal.
 *
 * Nothing here verifies a signature itself: every check calls the
 * caller's nqxvfn, so the module depends on no signature code. The
 * callback gets the algorithm, the signer's key, the signed bytes, their
 * digest (for the classical algorithms) and the signature, and returns
 * NQOK only for a signature that verifies.
 *
 * Every function returns NQOK, NQEDEC for an encoding RFC 5280 does not
 * allow, NQENOSUP for an algorithm or a critical extension this module
 * does not handle, NQELIM beyond a limit, NQEARG for bad arguments, and
 * NQEVRFY for anything that parses but does not check out. */
#ifndef NQX509_H
#define NQX509_H

#include <stddef.h>
#include <stdint.h>

#include "der/der.h"
#include "noqtis.h"

/* ---- algorithms ---- */

typedef enum {
  NQXRSA = 1, /* RSASSA-PKCS1-v1_5 */
  NQXPSS,     /* RSASSA-PSS, MGF1 with the same hash, salt = hash length */
  NQXECDSA,   /* ECDSA; the signature is the DER Ecdsa-Sig-Value */
  NQXPQ       /* ML-DSA or SLH-DSA, pure, empty context */
} nqxkind;

typedef struct {
  nqxkind kind;
  nqhalg h;   /* NQS256, NQS384 or NQS512; 0 for NQXPQ */
  nqsalg pq;  /* NQXPQ only */
} nqxsig;

/* key types */
#define NQXKRSA 1   /* rsaEncryption */
#define NQXKPSS 2   /* id-RSASSA-PSS (any PSS parameters) */
#define NQXKEC 3    /* id-ecPublicKey on curve (NQXP256 ...) */
#define NQXKPQ 4    /* ML-DSA or SLH-DSA (pq) */

#define NQXP256 1
#define NQXP384 2
#define NQXP521 3

typedef struct {
  int type;      /* NQXK*, 0 when not one this module knows */
  int curve;     /* NQXP*, for NQXKEC */
  nqsalg pq;     /* for NQXKPQ */
  nqspan spki;   /* the SubjectPublicKeyInfo element */
  nqspan key;    /* subjectPublicKey, without the unused-bits octet */
} nqxkey;

/* What the callback is asked to check. */
typedef struct {
  nqxsig alg;
  const nqxkey *key;  /* the signer's key */
  nqspan msg;         /* the signed bytes */
  const uint8_t *dig; /* alg.h of msg (NULL for NQXPQ) */
  size_t diglen;
  nqspan sig;         /* the signature octets */
} nqxvreq;

typedef int (*nqxvfn)(void *user, const nqxvreq *r);
/* SHA-1, which the hash module does not provide; only OCSP CertIDs and
 * responder key hashes, RFC 3161 ESSCertID (v1) and the RFC 5280 key
 * identifier fallback use it. NULL: those forms are NQENOSUP. */
typedef int (*nqxsha1fn)(void *user, const uint8_t *in, size_t len,
                         uint8_t out[20]);

typedef struct {
  nqxvfn vrfy;
  nqxsha1fn sha1;
  void *user;
} nqxops;

/* Resolves an AlgorithmIdentifier element (the whole SEQUENCE) of a
 * signature algorithm. */
int nqxsalg(const nqdtlv *aid, nqxsig *s);
/* Resolves a digest AlgorithmIdentifier: SHA-256/384/512 (NULL or
 * absent parameters) and, when sha1ok, SHA-1 (*h then 0). */
int nqxhalg(const nqdtlv *aid, int sha1ok, nqhalg *h);
/* Digest length of h; 20 for 0 (SHA-1). */
size_t nqxhlen(nqhalg h);
/* Hashes in with h (0: SHA-1 through ops). */
int nqxdig(const nqxops *ops, nqhalg h, const uint8_t *in, size_t len,
           uint8_t *out);
/* NQOK when key can carry signatures of alg. */
int nqxkeyok(const nqxkey *key, const nqxsig *alg);
/* Verifies sig over msg with key through ops (alg checked against key
 * first). */
int nqxvrfy(const nqxops *ops, const nqxkey *key, const nqxsig *alg,
            nqspan msg, nqspan sig);
/* Reads a SubjectPublicKeyInfo element. */
int nqxspki(const nqdtlv *t, nqxkey *k);

/* ---- certificates ---- */

/* extended key usages (bits of nqcert.eku) */
#define NQXEKUSRV 0x01u   /* serverAuth */
#define NQXEKUCLI 0x02u   /* clientAuth */
#define NQXEKUCODE 0x04u  /* codeSigning */
#define NQXEKUMAIL 0x08u  /* emailProtection */
#define NQXEKUTS 0x10u    /* timeStamping */
#define NQXEKUOCSP 0x20u  /* OCSPSigning */
#define NQXEKUANY 0x40u   /* anyExtendedKeyUsage */
#define NQXEKUOTH 0x80u   /* some other purpose */

/* key usages (bits of nqcert.ku, RFC 5280 4.2.1.3 order) */
#define NQXKUSIG 0x001u   /* digitalSignature */
#define NQXKUNR 0x002u    /* nonRepudiation / contentCommitment */
#define NQXKUCERT 0x020u  /* keyCertSign */
#define NQXKUCRL 0x040u   /* cRLSign */

/* extensions present (bits of nqcert.ext) */
#define NQXHASBC 0x01u
#define NQXHASKU 0x02u
#define NQXHASEKU 0x04u
#define NQXHASSKI 0x08u
#define NQXHASAKI 0x10u

#define NQXMAXEXT 32 /* extensions in one certificate */

typedef struct {
  nqspan raw;      /* the whole Certificate */
  nqspan tbs;      /* TBSCertificate, the signed bytes */
  nqspan sigaid;   /* signatureAlgorithm (equal to tbs's signature) */
  nqxsig salg;
  nqspan sig;      /* signatureValue octets */
  int ver;         /* 1, 2 or 3 */
  nqspan serial;   /* INTEGER contents (positive, at most 20 octets) */
  nqspan issuer;   /* the Name elements */
  nqspan subject;
  int64_t nb;      /* notBefore, notAfter: seconds since the epoch */
  int64_t na;
  nqxkey key;
  unsigned ext;    /* NQXHAS* */
  int ca;          /* basicConstraints cA */
  int plen;        /* pathLenConstraint, -1 when absent */
  uint32_t ku;     /* NQXKU* */
  uint32_t eku;    /* NQXEKU* */
  int ekucrit;
  unsigned ekun;   /* key purposes listed */
  nqspan ski;      /* subjectKeyIdentifier */
  nqspan aki;      /* authorityKeyIdentifier keyIdentifier (may be empty) */
  int bad;         /* an unrecognised critical extension: unusable */
} nqcert;

/* Parses one certificate that spans all n bytes. */
int nqcprs(const uint8_t *p, size_t n, nqcert *c);

/* Name comparison (RFC 5280 7.1, the basic form): the same RDNs with
 * the same attribute types in the same order; PrintableString and
 * UTF8String values compare ASCII case-insensitively after trimming and
 * collapsing internal spaces, other values byte for byte. 1 when equal,
 * 0 when not or when a name does not parse. */
int nqxneq(nqspan a, nqspan b);

/* Checks a Name element: SEQUENCE OF non-empty SET OF { OID, value };
 * *empty gets whether it holds no RDN. */
int nqxname(const nqdtlv *t, int *empty);

/* Checks the contents of a constructed element as a non-empty SEQUENCE
 * OF Extension in which nothing is critical (the extensions of OCSP,
 * CRLs and TSTInfo, none of which this module processes): unique types,
 * DER values. NQENOSUP for a critical one. */
int nqxgext(const nqdtlv *seq);

/* ---- paths ---- */

#define NQXMAXPATH 8

typedef struct {
  const nqcert *anc;    /* trust anchors */
  size_t nanc;
  const nqcert *pool;   /* candidate intermediates */
  size_t npool;
  int64_t t;            /* the time the path must be valid at */
  uint32_t eku;         /* a purpose the leaf must list (NQXEKU*), or 0 */
  const nqxops *ops;
} nqxchk;

/* Builds and checks a path from leaf to one of the anchors: names chain,
 * every certificate is valid at k->t and usable, every issuer is a CA
 * (basicConstraints cA; keyUsage keyCertSign, which an intermediate must
 * carry), path lengths hold, every signature verifies through ops, the
 * key identifiers agree where both are present, and the leaf lists
 * k->eku (an issuer that lists purposes must list it or any). path gets
 * leaf ... anchor (*np entries, at most cap). NQEVRFY when no path
 * checks out. An intermediate that is an alias of an anchor (nqxalias)
 * ends the path at the anchor itself; the leaf is never its own
 * anchor. */
/* 1 when c stands for the trust anchor anc: the same subject Name
 * (nqxneq) and a byte-identical SubjectPublicKeyInfo (a self-signed
 * anchor's cross-certificate, say). Nothing else in c is trusted. */
int nqxalias(const nqcert *c, const nqcert *anc);

int nqchain(const nqcert *leaf, const nqxchk *k, const nqcert **path,
            size_t cap, size_t *np);

/* ---- revocation ---- */

#define NQXSKEW 300  /* seconds of clock skew allowed */
/* how old (thisUpdate) an OCSP response without nextUpdate may be */
#define NQXOCSPAGE (7 * 86400)

/* OCSP status */
#define NQXGOOD 0
#define NQXREVOKED 1
#define NQXUNKNOWN 2

/* Checks an OCSPResponse about path[i], whose issuer is path[i + 1]
 * (path as nqchain built it): status successful, a BasicOCSPResponse
 * whose single response for the certificate (CertID: hash of the issuer
 * name and key, serial) is current at t (thisUpdate <= t + skew,
 * nextUpdate >= t - skew; without nextUpdate, thisUpdate at most
 * NQXOCSPAGE before t), signed by the issuer or by a responder
 * certificate the issuer signed with OCSPSigning, valid at t, whose
 * responderID matches. *st (may be NULL) gets the status. NQOK only for
 * good; NQEVRFY for revoked, unknown or anything that does not check. */
int nqocsp(const uint8_t *p, size_t n, const nqcert *const *path,
           size_t np, size_t i, int64_t t, const nqxops *ops, int *st);

/* Whether a single OCSP response with these times is current at t:
 * producedAt and thisUpdate not in the future, and nextUpdate (if any,
 * hasnext) not before thisUpdate nor past; without one, thisUpdate at
 * most NQXOCSPAGE before t. All with NQXSKEW of clock skew. */
int nqocspnow(int64_t prod, int64_t thisu, int hasnext, int64_t nextu,
              int64_t t);

/* Checks a CRL for path[i]: it is signed by a CA in the path whose
 * subject is the CRL issuer (cA; cRLSign when it states key usages),
 * its issuer is path[i]'s issuer, thisUpdate <= t + skew and nextUpdate
 * (required) >= t - skew, it carries no critical extension this module
 * does not handle, and it does not list path[i]'s serial. NQOK when all
 * of that holds; NQEVRFY when it is revoked or the CRL does not check. */
int nqcrl(const uint8_t *p, size_t n, const nqcert *const *path,
          size_t np, size_t i, int64_t t, const nqxops *ops);

/* ---- object identifiers (contents octets) the parsers share ---- */

typedef struct {
  const uint8_t *p;
  size_t n;
} nqxoid;

extern const nqxoid nqxoidsha256, nqxoidsha384, nqxoidsha512,
    nqxoidsha1, nqxoidrsa;

int nqxoideq(const nqdtlv *t, const nqxoid *o);

#endif /* NQX509_H */
