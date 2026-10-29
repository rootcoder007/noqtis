/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Classical signature verification (internal API): RSA PKCS#1 v1.5 and
 * RSASSA-PSS (RFC 8017; moduli of 2048 to 4096 bits, odd public exponent
 * 3 to 2^32-1) and ECDSA over P-256 and P-384 (FIPS 186-5, SEC 1).
 * Verification only: no signing, no key generation, no allocation.
 *
 * Every verifier returns NQOK, NQEVRFY when the signature does not verify
 * (including a signature of the wrong length or out of range, or a DER
 * signature that is not strict DER), or NQEARG for a bad argument. The
 * key parsers return NQEDEC for input that is not strict DER or not a
 * valid key and NQENOSUP for a valid key noqtis does not handle (other
 * sizes, exponents, curves or algorithms). */
#ifndef NQCLS_H
#define NQCLS_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"
#include "cls/bn.h"

#define NQRMIN 2048 /* modulus bits */
#define NQRMAX 4096

enum { NQKRSA = 1, NQKEC };          /* key kinds */
enum { NQP256 = 1, NQP384 };         /* curves */

/* RSASSA-PSS parameters. h is the message hash; for a SHA-2 or SHA-3 h,
 * mgf is the MGF1 hash (any fixed hash); for SHAKE128 / SHAKE256
 * (RFC 8702) mgf must equal h and the mask is the SHAKE output. slen is
 * the salt length in bytes. */
typedef struct {
  nqhalg h;
  nqhalg mgf;
  size_t slen;
} nqpss;

/* A parsed public key. */
typedef struct {
  int kind;    /* NQKRSA or NQKEC */
  /* RSA */
  nqcmod n;    /* the modulus and its Montgomery constants */
  size_t bits; /* modulus bits */
  uint32_t e;
  int pss;     /* 0 any; 1 PSS only (id-RSASSA-PSS); 2 PSS with pp */
  nqpss pp;    /* the key's PSS restriction when pss == 2 */
  /* EC */
  int crv;     /* NQP256 or NQP384 */
  uint8_t x[48], y[48]; /* affine, big-endian, curve-size bytes */
} nqck;

/* DER SubjectPublicKeyInfo: rsaEncryption (NULL parameters),
 * id-RSASSA-PSS (absent parameters or RSASSA-PSS-params) or
 * id-ecPublicKey with namedCurve prime256v1 / secp384r1 and an
 * uncompressed or compressed point. */
int nqckey(nqck *k, const uint8_t *der, size_t len);
/* DER RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }. */
int nqrsapk(nqck *k, const uint8_t *der, size_t len);
/* An SEC 1 point (04 x y, or 02 / 03 x) on curve crv. */
int nqecpk(nqck *k, int crv, const uint8_t *pt, size_t len);
/* DER RSASSA-PSS-params (RFC 4055) with SHA-2 / SHA-3 hashes and MGF1;
 * the SHA-1 defaults give NQENOSUP. */
int nqpssp(nqpss *p, const uint8_t *der, size_t len);

/* RSA PKCS#1 v1.5 (EMSA-PKCS1-v1_5 with the DigestInfo of h, NULL
 * parameters): the message, or its digest (dlen == nqhlen(h)). h is any
 * SHA-2 or SHA-3 hash. */
int nqrsav(const nqck *k, nqhalg h, const uint8_t *msg, size_t mlen,
           const uint8_t *sig, size_t slen);
int nqrsavh(const nqck *k, nqhalg h, const uint8_t *dig, size_t dlen,
            const uint8_t *sig, size_t slen);

/* RSASSA-PSS with parameters p: the message, or its digest
 * (dlen == nqhlen(p->h)). */
int nqpssv(const nqck *k, const nqpss *p, const uint8_t *msg, size_t mlen,
           const uint8_t *sig, size_t slen);
int nqpssvh(const nqck *k, const nqpss *p, const uint8_t *dig,
            size_t dlen, const uint8_t *sig, size_t slen);

/* ECDSA: sig is DER (SEQUENCE { r INTEGER, s INTEGER }, strict) when raw
 * is 0, or r || s of the curve's size each (IEEE P1363) when raw is 1.
 * The message is hashed with h (any hash; SHAKE gives nqhlen(h) bytes);
 * nqecvh takes the digest itself, of any length. */
int nqecv(const nqck *k, nqhalg h, const uint8_t *msg, size_t mlen,
          const uint8_t *sig, size_t slen, int raw);
int nqecvh(const nqck *k, const uint8_t *dig, size_t dlen,
           const uint8_t *sig, size_t slen, int raw);

/* ---- internal to src/cls ---- */

#define NQEL 12 /* field limbs: 384 bits */

/* The last arc of the hash's OID under 2.16.840.1.101.3.4.2 (1 to 12),
 * 0 if none. */
unsigned nqcho(nqhalg h);
/* Splits a strict DER ECDSA-Sig-Value into the magnitudes of r and s
 * (leading zero removed); NQEDEC if it is not strict DER. */
int nqcdsig(const uint8_t *sig, size_t len, const uint8_t **r, size_t *rl,
            const uint8_t **s, size_t *sl);

#endif /* NQCLS_H */
