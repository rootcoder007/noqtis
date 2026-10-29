/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Raw hash primitives shared by the modules; not part of the public API.
 *
 * SHA-2 (FIPS 180-4): nqs2* is the SHA-256 family (SHA-224, SHA-256),
 * nqs5* the SHA-512 family (SHA-384, SHA-512, SHA-512/224, SHA-512/256).
 * Keccak (FIPS 202): nqkeccak is Keccak-f[1600]; nqk* is the sponge with
 * the SHA-3 or SHAKE padding, absorbing incrementally and squeezing as
 * often as the caller likes. nqm* is HMAC (FIPS 198-1) over any of the
 * fixed-size hashes.
 *
 * The *bit functions finish a message whose length is not a whole number
 * of bytes: nb (0..7) more bits follow the bytes absorbed so far. For
 * SHA-2 they are the nb most significant bits of last; for Keccak they
 * are the nb least significant bits of last, FIPS 202 order (bit 0
 * first). */
#ifndef NQH_H
#define NQH_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* ---- SHA-224 / SHA-256 ---- */

typedef struct {
  uint32_t h[8];
  uint64_t n;       /* bytes absorbed */
  uint8_t buf[64];
  size_t pos;       /* bytes in buf */
  size_t dlen;      /* digest bytes: 28 or 32 */
} nqs2ctx;

/* dlen 28 gives SHA-224, 32 SHA-256. */
void nqs2ini(nqs2ctx *c, size_t dlen);
void nqs2upd(nqs2ctx *c, const uint8_t *in, size_t len);
/* Writes c->dlen bytes and wipes c. */
void nqs2fin(nqs2ctx *c, uint8_t *out);
void nqs2bit(nqs2ctx *c, uint8_t last, unsigned nb, uint8_t *out);

/* ---- SHA-384 / SHA-512 / SHA-512/t ---- */

typedef struct {
  uint64_t h[8];
  uint64_t n;       /* bytes absorbed */
  uint8_t buf[128];
  size_t pos;
  size_t dlen;      /* 28, 32, 48 or 64 */
} nqs5ctx;

/* alg is NQS384, NQS512, NQS512T224 or NQS512T256. */
void nqs5ini(nqs5ctx *c, nqhalg alg);
void nqs5upd(nqs5ctx *c, const uint8_t *in, size_t len);
void nqs5fin(nqs5ctx *c, uint8_t *out);
void nqs5bit(nqs5ctx *c, uint8_t last, unsigned nb, uint8_t *out);

/* One-shot SHA-256 and SHA-512. */
void nqs256(const uint8_t *in, size_t len, uint8_t out[32]);
void nqs512(const uint8_t *in, size_t len, uint8_t out[64]);

/* ---- Keccak ---- */

void nqkeccak(uint64_t s[25]);

typedef struct {
  uint64_t s[25];
  size_t rate;      /* bytes per block */
  size_t pos;       /* bytes absorbed into, or squeezed from, the block */
  unsigned dom;     /* domain bits: 2 (SHA-3: 01) or 15 (SHAKE: 1111) */
  unsigned dnb;     /* how many: 2 or 4 */
  int sq;           /* 1 once padded and squeezing */
} nqkctx;

/* SHA3-224/256/384/512: bits 224, 256, 384 or 512. */
void nqs3ini(nqkctx *c, unsigned bits);
/* SHAKE128 / SHAKE256: bits 128 or 256. */
void nqshkini(nqkctx *c, unsigned bits);
/* Absorbs; only before the first squeeze. */
void nqkabs(nqkctx *c, const uint8_t *in, size_t len);
/* Pads after nb trailing bits of last (nb 0..7) and starts squeezing. */
void nqkpad(nqkctx *c, uint8_t last, unsigned nb);
/* Squeezes len more bytes; pads first if that has not happened. */
void nqksqz(nqkctx *c, uint8_t *out, size_t len);

/* One-shots: SHA3-bits and SHAKE-bits. */
void nqs3(unsigned bits, const uint8_t *in, size_t len, uint8_t *out);
void nqshk(unsigned bits, const uint8_t *in, size_t len, uint8_t *out,
           size_t outlen);

/* ---- any fixed-size hash, and HMAC over it ---- */

typedef struct {
  nqhalg alg;
  union {
    nqs2ctx s2;
    nqs5ctx s5;
    nqkctx k;
  } u;
} nqfctx;

/* Fixed-size algorithms only (not SHAKE); 0 for success, NQEARG if alg
 * is not one. */
int nqfini(nqfctx *c, nqhalg alg);
void nqfupd(nqfctx *c, const uint8_t *in, size_t len);
/* Writes the full digest (nqhlen(alg) bytes) and wipes c. */
void nqffin(nqfctx *c, uint8_t *out);
void nqfbit(nqfctx *c, uint8_t last, unsigned nb, uint8_t *out);
/* The block size HMAC uses; 0 for SHAKE or unknown. */
size_t nqfblk(nqhalg alg);

typedef struct {
  nqfctx in;
  nqfctx out;
} nqmctx;

/* NQOK, NQEARG (bad alg, NULL key with keylen > 0) or NQENOSUP (SHAKE). */
int nqmini(nqmctx *c, nqhalg alg, const uint8_t *key, size_t keylen);
void nqmupd(nqmctx *c, const uint8_t *in, size_t len);
/* Writes the full tag (nqhlen(alg) bytes) and wipes c. */
void nqmfin(nqmctx *c, uint8_t *out);

#define NQHMAX 64   /* the largest fixed digest */

/* ---- SHA-1 (FIPS 180-4), for verification only ---- */

/* Only for the legacy identifiers that verification has to recompute:
 * OCSP CertIDs and responder key hashes, ESS signingCertificate (v1)
 * and the RFC 5280 key identifier. Not a public hash, never a signing
 * hash: nqhash / nqhmac do not offer it. */
typedef struct {
  uint32_t h[5];
  uint64_t n;       /* bytes absorbed */
  uint8_t buf[64];
  size_t pos;
} nqs1ctx;

#define NQS1LEN 20

void nqs1ini(nqs1ctx *c);
void nqs1upd(nqs1ctx *c, const uint8_t *in, size_t len);
/* Writes 20 bytes and wipes c. */
void nqs1fin(nqs1ctx *c, uint8_t *out);
void nqs1(const uint8_t *in, size_t len, uint8_t out[20]);
/* The nqxops.sha1 hook of src/der (user unused): NQOK, or NQEARG for a
 * NULL out or a NULL in with len > 0. */
int nqs1hk(void *user, const uint8_t *in, size_t len, uint8_t out[20]);

#endif /* NQH_H */
