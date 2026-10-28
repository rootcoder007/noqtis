/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HMAC_DRBG, NIST SP 800-90A Rev. 1 section 10.1.2, over SHA-256 and
 * SHA-512. Every branch depends only on lengths, flags and the counter,
 * never on Key, V, the entropy or the output. */
#include <string.h>

#include "core/int.h"
#include "drbg/drbg.h"

/* 1 when an input of len bytes is longer than SP 800-90A allows. */
static int big(size_t len) {
  return (uint64_t)len > NQDMAXL;
}

/* NQOK for SHA-256 and SHA-512, NQENOSUP for another known hash. */
static int chkalg(nqhalg alg) {
  if (alg == NQS256 || alg == NQS512) return NQOK;
  return nqhlen(alg) != 0 ? NQENOSUP : NQEARG;
}

/* An optional input: p may be NULL only when len is 0. */
static int chkopt(const uint8_t *p, size_t len) {
  if (p == NULL && len > 0) return NQEARG;
  return big(len) ? NQELIM : NQOK;
}

/* Entropy input: at least the security strength. */
static int chkent(const uint8_t *p, size_t len) {
  if (p == NULL || len < NQDENT) return NQEARG;
  return big(len) ? NQELIM : NQOK;
}

static void mac(nqmctx *c, const nqdrbg *d, const uint8_t *in1,
                size_t len1, const uint8_t *in2, size_t len2) {
  nqmini(c, d->alg, d->k, d->n);
  nqmupd(c, in1, len1);
  if (len2 > 0) nqmupd(c, in2, len2);
}

static void part(nqmctx *c, const uint8_t *p, size_t len) {
  if (len > 0) nqmupd(c, p, len);
}

/* HMAC_DRBG_Update (10.1.2.2) with provided_data = a || b || e. */
static void upd(nqdrbg *d, const uint8_t *a, size_t al, const uint8_t *b,
                size_t bl, const uint8_t *e, size_t el) {
  nqmctx c;
  uint8_t r;
  for (r = 0; r < 2; r++) {
    mac(&c, d, d->v, d->n, &r, 1);
    part(&c, a, al);
    part(&c, b, bl);
    part(&c, e, el);
    /* the new Key: nqmini has already taken the old one */
    nqmfin(&c, d->k);
    mac(&c, d, d->v, d->n, NULL, 0);
    nqmfin(&c, d->v);
    if (al + bl + el == 0) break;
  }
}

/* Reseed algorithm (10.1.2.4). */
static void res(nqdrbg *d, const uint8_t *ent, size_t entlen,
                const uint8_t *add, size_t addlen) {
  upd(d, ent, entlen, add, addlen, NULL, 0);
  d->rc = 1;
}

/* Generate algorithm (10.1.2.5), steps 2 to 7; the checks are done. */
static void gen(nqdrbg *d, uint8_t *out, size_t outlen, const uint8_t *add,
                size_t addlen) {
  nqmctx c;
  size_t m;
  if (addlen > 0) upd(d, add, addlen, NULL, 0, NULL, 0);
  while (outlen > 0) {
    mac(&c, d, d->v, d->n, NULL, 0);
    nqmfin(&c, d->v);
    m = outlen < d->n ? outlen : d->n;
    memcpy(out, d->v, m);
    out += m;
    outlen -= m;
  }
  upd(d, add, addlen, NULL, 0, NULL, 0);
  d->rc++;
}

static int live(const nqdrbg *d) {
  return d->ok == NQDLIVE;
}

/* The checks every generate request shares. */
static int chkgen(const nqdrbg *d, const uint8_t *out, size_t outlen,
                  const uint8_t *add, size_t addlen) {
  if (d == NULL || (out == NULL && outlen > 0)) return NQEARG;
  if (!live(d)) return NQESTATE;
  if (outlen > NQDMAXB) return NQELIM;
  return chkopt(add, addlen);
}

static int fail(uint8_t *out, size_t outlen, int rc) {
  if (out != NULL) nqwipe(out, outlen);
  return rc;
}

int nqdini(nqdrbg *d, nqhalg alg, const uint8_t *ent, size_t entlen,
           const uint8_t *non, size_t nonlen, const uint8_t *ps,
           size_t pslen, int pr) {
  int rc;
  if (d == NULL) return NQEARG;
  nqwipe(d, sizeof *d);
  rc = chkalg(alg);
  if (rc == NQOK) rc = chkent(ent, entlen);
  if (rc == NQOK && (non == NULL || nonlen < NQDNON)) rc = NQEARG;
  if (rc == NQOK && big(nonlen)) rc = NQELIM;
  if (rc == NQOK) rc = chkopt(ps, pslen);
  if (rc != NQOK) return rc;
  d->alg = alg;
  d->n = nqhlen(alg);
  memset(d->v, 1, d->n);
  upd(d, ent, entlen, non, nonlen, ps, pslen);
  d->rc = 1;
  d->pr = pr != 0;
  d->ok = NQDLIVE;
  return NQOK;
}

int nqdseed(nqdrbg *d, nqhalg alg, const uint8_t *ps, size_t pslen,
            int pr) {
  uint8_t b[48 + NQDNON];
  int rc;
  if (d == NULL) return NQEARG;
  nqwipe(d, sizeof *d);
  rc = chkalg(alg);
  if (rc == NQOK) rc = chkopt(ps, pslen);
  if (rc == NQOK) rc = nqrand(b, sizeof b);
  if (rc == NQOK) {
    rc = nqdini(d, alg, b, 48, b + 48, NQDNON, ps, pslen, pr);
  }
  if (rc == NQOK) d->own = 1;
  nqwipe(b, sizeof b);
  return rc;
}

int nqdres(nqdrbg *d, const uint8_t *ent, size_t entlen,
           const uint8_t *add, size_t addlen) {
  int rc;
  if (d == NULL) return NQEARG;
  if (!live(d)) return NQESTATE;
  rc = chkent(ent, entlen);
  if (rc == NQOK) rc = chkopt(add, addlen);
  if (rc != NQOK) return rc;
  res(d, ent, entlen, add, addlen);
  return NQOK;
}

int nqdgen(nqdrbg *d, uint8_t *out, size_t outlen, const uint8_t *add,
           size_t addlen) {
  uint8_t e[NQDENT];
  int rc = chkgen(d, out, outlen, add, addlen);
  if (rc != NQOK) return rc;
  if (d->own && (d->pr || d->rc > NQDMAXR)) {
    /* 9.3.1 step 7: reseed, then generate with no additional input */
    rc = nqrand(e, sizeof e);
    if (rc != NQOK) {
      nqwipe(e, sizeof e);
      return fail(out, outlen, rc);
    }
    res(d, e, sizeof e, add, addlen);
    nqwipe(e, sizeof e);
    add = NULL;
    addlen = 0;
  } else if (d->rc > NQDMAXR) {
    return fail(out, outlen, NQESTATE);
  }
  gen(d, out, outlen, add, addlen);
  return NQOK;
}

int nqdgenp(nqdrbg *d, uint8_t *out, size_t outlen, const uint8_t *add,
            size_t addlen, const uint8_t *ent, size_t entlen) {
  int rc = chkgen(d, out, outlen, add, addlen);
  if (rc == NQOK) rc = chkent(ent, entlen);
  if (rc != NQOK) return rc;
  if (!d->pr) return fail(out, outlen, NQESTATE);
  res(d, ent, entlen, add, addlen);
  gen(d, out, outlen, NULL, 0);
  return NQOK;
}

void nqdfree(nqdrbg *d) {
  if (d != NULL) nqwipe(d, sizeof *d);
}
