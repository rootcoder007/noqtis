/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HMAC (FIPS 198-1) over every fixed-size hash, and the fixed-size hash
 * context it is built on. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

int nqfini(nqfctx *c, nqhalg alg) {
  memset(c, 0, sizeof *c);
  c->alg = alg;
  switch (alg) {
  case NQS224: nqs2ini(&c->u.s2, 28); return NQOK;
  case NQS256: nqs2ini(&c->u.s2, 32); return NQOK;
  case NQS384: case NQS512: case NQS512T224: case NQS512T256:
    nqs5ini(&c->u.s5, alg);
    return NQOK;
  case NQS3224: nqs3ini(&c->u.k, 224); return NQOK;
  case NQS3256: nqs3ini(&c->u.k, 256); return NQOK;
  case NQS3384: nqs3ini(&c->u.k, 384); return NQOK;
  case NQS3512: nqs3ini(&c->u.k, 512); return NQOK;
  default: return NQEARG;
  }
}

void nqfupd(nqfctx *c, const uint8_t *in, size_t len) {
  switch (c->alg) {
  case NQS224: case NQS256: nqs2upd(&c->u.s2, in, len); break;
  case NQS384: case NQS512: case NQS512T224: case NQS512T256:
    nqs5upd(&c->u.s5, in, len);
    break;
  default: nqkabs(&c->u.k, in, len); break;
  }
}

void nqfbit(nqfctx *c, uint8_t last, unsigned nb, uint8_t *out) {
  switch (c->alg) {
  case NQS224: case NQS256: nqs2bit(&c->u.s2, last, nb, out); break;
  case NQS384: case NQS512: case NQS512T224: case NQS512T256:
    nqs5bit(&c->u.s5, last, nb, out);
    break;
  default:
    nqkpad(&c->u.k, last, nb);
    nqksqz(&c->u.k, out, nqhlen(c->alg));
    break;
  }
  nqwipe(c, sizeof *c);
}

void nqffin(nqfctx *c, uint8_t *out) {
  nqfbit(c, 0, 0, out);
}

size_t nqfblk(nqhalg alg) {
  switch (alg) {
  case NQS224: case NQS256: return 64;
  case NQS384: case NQS512: case NQS512T224: case NQS512T256: return 128;
  /* SHA-3: the rate */
  case NQS3224: return 144;
  case NQS3256: return 136;
  case NQS3384: return 104;
  case NQS3512: return 72;
  default: return 0;
  }
}

/* the largest block: SHA3-224's rate */
#define BMAX 144

int nqmini(nqmctx *c, nqhalg alg, const uint8_t *key, size_t keylen) {
  uint8_t k0[BMAX];
  size_t b = nqfblk(alg), i;
  if (alg == NQSHK128 || alg == NQSHK256) return NQENOSUP;
  if (b == 0 || (key == NULL && keylen > 0)) return NQEARG;
  memset(k0, 0, sizeof k0);
  if (keylen > b) {
    /* K0 = H(K), padded with zeros */
    nqfini(&c->in, alg);
    nqfupd(&c->in, key, keylen);
    nqffin(&c->in, k0);
  } else if (keylen > 0) {
    memcpy(k0, key, keylen);
  }
  for (i = 0; i < b; i++) k0[i] ^= 0x36;
  nqfini(&c->in, alg);
  nqfupd(&c->in, k0, b);
  for (i = 0; i < b; i++) k0[i] ^= 0x36 ^ 0x5c;
  nqfini(&c->out, alg);
  nqfupd(&c->out, k0, b);
  nqwipe(k0, sizeof k0);
  return NQOK;
}

void nqmupd(nqmctx *c, const uint8_t *in, size_t len) {
  nqfupd(&c->in, in, len);
}

void nqmfin(nqmctx *c, uint8_t *out) {
  uint8_t t[NQHMAX];
  nqffin(&c->in, t);
  nqfupd(&c->out, t, nqhlen(c->out.alg));
  nqffin(&c->out, out);
  nqwipe(t, sizeof t);
  nqwipe(c, sizeof *c);
}

int nqhmac(nqhalg alg, const uint8_t *key, size_t keylen,
           const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  nqmctx c;
  uint8_t t[NQHMAX];
  size_t d = nqhlen(alg);
  int rc;
  if (alg == NQSHK128 || alg == NQSHK256) return NQENOSUP;
  if (d == 0 || out == NULL || outlen == 0 || outlen > d ||
      (in == NULL && inlen > 0)) {
    return NQEARG;
  }
  rc = nqmini(&c, alg, key, keylen);
  if (rc != NQOK) {
    nqwipe(&c, sizeof c);
    return rc;
  }
  nqmupd(&c, in, inlen);
  nqmfin(&c, t);
  memcpy(out, t, outlen);
  nqwipe(t, sizeof t);
  return NQOK;
}
