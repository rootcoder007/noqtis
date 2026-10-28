/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The SLH-DSA hash functions, FIPS 205 section 11.
 *
 * SHAKE (11.1): every function is SHAKE256 over its inputs, with the full
 * 32-byte address.
 *
 * SHA-2 (11.2): the address is compressed to 22 bytes (ADRSc), and PK.seed
 * is padded to a whole compression block. PRF and F always use SHA-256;
 * H and T_l use SHA-256 at n = 16 and SHA-512 (with a 128-byte block)
 * above it. PRF_msg is HMAC and H_msg is MGF1 over a hash, both with
 * SHA-256 at n = 16 and SHA-512 above. */
#include <string.h>

#include "slh/in.h"

/* ADRSc: layer (1 byte) || tree (low 8 bytes) || type (1 byte) || the
 * last three words. */
static void adrc(const uint8_t *a, uint8_t *c) {
  c[0] = a[3];
  memcpy(c + 1, a + 8, 8);
  c[9] = a[19];
  memcpy(c + 10, a + 20, 12);
}

void nqslini(nqslc *c, const nqslp *p, const uint8_t *pks,
             const uint8_t *sks) {
  uint8_t blk[128];
  memset(c, 0, sizeof *c);
  c->p = p;
  memcpy(c->pks, pks, p->n);
  if (sks != NULL) memcpy(c->sks, sks, p->n);
  if (p->sha2) {
    memset(blk, 0, sizeof blk);
    memcpy(blk, pks, p->n);
    nqs2ini(&c->m2, 32);
    nqs2upd(&c->m2, blk, 64);
    if (p->n > 16) {
      nqs5ini(&c->m5, NQS512);
      nqs5upd(&c->m5, blk, 128);
    }
  }
}

void nqslprf(const nqslc *c, const uint8_t *a, uint8_t *out) {
  unsigned n = c->p->n;
  if (c->p->sha2) {
    nqs2ctx s = c->m2;
    uint8_t ac[22], h[32];
    adrc(a, ac);
    nqs2upd(&s, ac, sizeof ac);
    nqs2upd(&s, c->sks, n);
    nqs2fin(&s, h);
    memcpy(out, h, n);
    nqwipe(h, sizeof h);
  } else {
    nqkctx k;
    nqshkini(&k, 256);
    nqkabs(&k, c->pks, n);
    nqkabs(&k, a, 32);
    nqkabs(&k, c->sks, n);
    nqksqz(&k, out, n);
    nqwipe(&k, sizeof k);
  }
}

void nqslth(const nqslc *c, const uint8_t *a, const uint8_t *in,
            unsigned nb, uint8_t *out) {
  unsigned n = c->p->n;
  size_t len = (size_t)nb * n;
  if (c->p->sha2) {
    uint8_t ac[22], h[64];
    adrc(a, ac);
    if (n > 16 && nb > 1) {
      nqs5ctx s = c->m5;
      nqs5upd(&s, ac, sizeof ac);
      nqs5upd(&s, in, len);
      nqs5fin(&s, h);
    } else {
      nqs2ctx s = c->m2;
      nqs2upd(&s, ac, sizeof ac);
      nqs2upd(&s, in, len);
      nqs2fin(&s, h);
    }
    memcpy(out, h, n);
    nqwipe(h, sizeof h);
  } else {
    nqkctx k;
    nqshkini(&k, 256);
    nqkabs(&k, c->pks, n);
    nqkabs(&k, a, 32);
    nqkabs(&k, in, len);
    nqksqz(&k, out, n);
    nqwipe(&k, sizeof k);
  }
}

void nqslpm(const nqslp *p, const uint8_t *skp, const uint8_t *rnd,
            const uint8_t *pre, size_t prelen, const uint8_t *msg,
            size_t msglen, uint8_t *out) {
  if (p->sha2) {
    nqmctx m;
    uint8_t t[64];
    /* cannot fail: a fixed-size hash and a key of n bytes */
    (void)nqmini(&m, p->n > 16 ? NQS512 : NQS256, skp, p->n);
    nqmupd(&m, rnd, p->n);
    if (prelen > 0) nqmupd(&m, pre, prelen);
    if (msglen > 0) nqmupd(&m, msg, msglen);
    nqmfin(&m, t);
    memcpy(out, t, p->n);
    nqwipe(t, sizeof t);
  } else {
    nqkctx k;
    nqshkini(&k, 256);
    nqkabs(&k, skp, p->n);
    nqkabs(&k, rnd, p->n);
    if (prelen > 0) nqkabs(&k, pre, prelen);
    if (msglen > 0) nqkabs(&k, msg, msglen);
    nqksqz(&k, out, p->n);
    nqwipe(&k, sizeof k);
  }
}

void nqslhm(const nqslp *p, const uint8_t *r, const uint8_t *pk,
            const uint8_t *pre, size_t prelen, const uint8_t *msg,
            size_t msglen, uint8_t *out) {
  unsigned n = p->n;
  if (p->sha2) {
    /* MGF1-SHA-x(R || PK.seed || SHA-x(R || PK.seed || PK.root || M'),
     * m) */
    nqfctx f;
    nqhalg alg = n > 16 ? NQS512 : NQS256;
    size_t hl = n > 16 ? 64 : 32, sl = 2 * (size_t)n + hl, done = 0;
    uint8_t seed[2 * NQSLNMX + 64 + 4], blk[64];
    uint32_t ctr = 0;
    (void)nqfini(&f, alg);
    nqfupd(&f, r, n);
    nqfupd(&f, pk, 2 * (size_t)n);
    if (prelen > 0) nqfupd(&f, pre, prelen);
    if (msglen > 0) nqfupd(&f, msg, msglen);
    memcpy(seed, r, n);
    memcpy(seed + n, pk, n);
    nqffin(&f, seed + 2 * n);
    while (done < p->m) {
      size_t take = p->m - done < hl ? p->m - done : hl;
      nqst32b(seed + sl, ctr++);
      (void)nqfini(&f, alg);
      nqfupd(&f, seed, sl + 4);
      nqffin(&f, blk);
      memcpy(out + done, blk, take);
      done += take;
    }
  } else {
    nqkctx k;
    nqshkini(&k, 256);
    nqkabs(&k, r, n);
    nqkabs(&k, pk, 2 * (size_t)n);
    if (prelen > 0) nqkabs(&k, pre, prelen);
    if (msglen > 0) nqkabs(&k, msg, msglen);
    nqksqz(&k, out, p->m);
    nqwipe(&k, sizeof k);
  }
}
