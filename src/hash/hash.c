/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The public hash interface: one dispatch over SHA-2, SHA-3 and SHAKE. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

/* What an nqhctx holds. It is copied in and out with memcpy, so the
 * caller's uint64_t array is never read through another type. */
typedef struct {
  uint32_t mag;   /* MAG while initialised */
  int st;         /* ABS, SQZ or END */
  nqfctx f;       /* f.alg is the algorithm; SHAKE uses f.u.k */
} hst;

_Static_assert(sizeof(hst) <= sizeof(nqhctx), "nqhctx is too small");

#define MAG 0x6e716863u
#define ABS 1
#define SQZ 2
#define END 3

static int isshk(nqhalg alg) {
  return alg == NQSHK128 || alg == NQSHK256;
}

size_t nqhlen(nqhalg alg) {
  switch (alg) {
  case NQS224: case NQS512T224: case NQS3224: return 28;
  case NQS256: case NQS512T256: case NQS3256: case NQSHK128: return 32;
  case NQS384: case NQS3384: return 48;
  case NQS512: case NQS3512: case NQSHK256: return 64;
  default: return 0;
  }
}

/* The size rule for fixed digests. */
static int outchk(size_t d, const uint8_t *out, size_t outlen) {
  if (out == NULL) return NQEARG;
  if (outlen < d) return NQEBUF;
  if (outlen > d) return NQEARG;
  return NQOK;
}

int nqhash(nqhalg alg, const uint8_t *in, size_t inlen,
           uint8_t *out, size_t outlen) {
  nqfctx c;
  size_t d = nqhlen(alg);
  int rc;
  if (d == 0 || (in == NULL && inlen > 0)) return NQEARG;
  if (isshk(alg)) {
    if (out == NULL && outlen > 0) return NQEARG;
    nqshk(alg == NQSHK128 ? 128 : 256, in, inlen, out, outlen);
    return NQOK;
  }
  rc = outchk(d, out, outlen);
  if (rc != NQOK) return rc;
  nqfini(&c, alg);
  nqfupd(&c, in, inlen);
  nqffin(&c, out);
  return NQOK;
}

int nqhini(nqhctx *ctx, nqhalg alg) {
  hst s;
  if (ctx == NULL) return NQEARG;
  memset(&s, 0, sizeof s);
  if (isshk(alg)) {
    s.f.alg = alg;
    nqshkini(&s.f.u.k, alg == NQSHK128 ? 128 : 256);
  } else if (nqfini(&s.f, alg) != NQOK) {
    nqwipe(ctx, sizeof *ctx);
    return NQEARG;
  }
  s.mag = MAG;
  s.st = ABS;
  memcpy(ctx, &s, sizeof s);
  nqwipe(&s, sizeof s);
  return NQOK;
}

int nqhupd(nqhctx *ctx, const uint8_t *in, size_t inlen) {
  hst s;
  if (ctx == NULL) return NQEARG;
  memcpy(&s, ctx, sizeof s);
  if (s.mag != MAG || s.st != ABS) {
    nqwipe(&s, sizeof s);
    return NQESTATE;
  }
  if (in == NULL && inlen > 0) {
    nqwipe(&s, sizeof s);
    return NQEARG;
  }
  nqfupd(&s.f, in, inlen);
  memcpy(ctx, &s, sizeof s);
  nqwipe(&s, sizeof s);
  return NQOK;
}

int nqhfin(nqhctx *ctx, uint8_t *out, size_t outlen) {
  hst s;
  int rc = NQOK;
  if (ctx == NULL) return NQEARG;
  memcpy(&s, ctx, sizeof s);
  if (s.mag != MAG || (s.st != ABS && s.st != SQZ)) {
    rc = NQESTATE;
  } else if (isshk(s.f.alg)) {
    if (out == NULL && outlen > 0) {
      rc = NQEARG;
    } else {
      nqksqz(&s.f.u.k, out, outlen);
      s.st = SQZ;
      memcpy(ctx, &s, sizeof s);
    }
  } else {
    rc = outchk(nqhlen(s.f.alg), out, outlen);
    if (rc == NQOK) {
      /* nqffin wipes s.f; keep only the marker */
      nqffin(&s.f, out);
      memset(&s, 0, sizeof s);
      s.mag = MAG;
      s.st = END;
      nqwipe(ctx, sizeof *ctx);
      memcpy(ctx, &s, sizeof s);
    }
  }
  nqwipe(&s, sizeof s);
  return rc;
}
