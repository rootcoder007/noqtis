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

#include "core/lk.h"
#include "slh/in.h"

/* ADRSc: layer (1 byte) || tree (low 8 bytes) || type (1 byte) || the
 * last three words. */
static void adrc(const uint8_t *a, uint8_t *c) {
  c[0] = a[3];
  memcpy(c + 1, a + 8, 8);
  c[9] = a[19];
  memcpy(c + 10, a + 20, 12);
}

int nqslini(nqslc *c, const nqslp *p, const uint8_t *pks,
            const uint8_t *sks) {
  uint8_t blk[128];
  unsigned i;
  int rc = NQOK;
  memset(c, 0, sizeof *c);
  c->p = p;
  c->g = &c->gs;
  memcpy(c->pks, pks, p->n);
  if (sks != NULL) {
    NQLKST(1);
    rc = nqmrini(c->g);
    nqmrb(c->g, c->s0, p->n);
    for (i = 0; i < p->n; i++) {
      NQLK(sks[i], NQLKUN);
      c->s1[i] = (uint8_t)(sks[i] ^ c->s0[i]);
    }
    NQLKST(2);
  }
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
  return rc;
}

/* the block after PK.seed's for PRF: ADRSc || SK.seed (in shares),
 * padded; 64 + 22 + n bytes in all, n at most 32, so one block */
static void prfblk(const nqslc *c, const uint8_t *a, uint8_t *b0,
                   uint8_t *b1) {
  unsigned n = c->p->n;
  memset(b0, 0, 64);
  memset(b1, 0, 64);
  adrc(a, b0);
  memcpy(b0 + 22, c->s0, n);
  memcpy(b1 + 22, c->s1, n);
  b0[22 + n] = 0x80;
  nqst64b(b0 + 56, (uint64_t)(64 + 22 + n) * 8);
}

void nqslprfn(const nqslc *c, const uint8_t *a, unsigned cnt,
              uint8_t *out) {
  unsigned n = c->p->n, i, j, k;
  if (!c->p->sha2) {
    for (i = 0; i < cnt; i++) nqslprf(c, a + 32 * (size_t)i, out + n * i);
    return;
  }
  for (i = 0; i < cnt; i += NQMSBL) {
    uint8_t b0[NQMSBL * 64], b1[NQMSBL * 64];
    uint32_t o0[NQMSBL * 8], o1[NQMSBL * 8];
    const unsigned m = cnt - i < NQMSBL ? cnt - i : NQMSBL;
    for (j = 0; j < m; j++) {
      prfblk(c, a + 32 * (size_t)(i + j), b0 + 64 * j, b1 + 64 * j);
    }
    nqms2b(c->m2.h, b0, b1, m, o0, o1, c->g);
    for (j = 0; j < m; j++) {
      uint8_t *d = out + (size_t)n * (i + j);
      for (k = 0; k < n; k += 4) {
        uint8_t w[4];
        nqst32b(w, o0[8 * j + k / 4] ^ o1[8 * j + k / 4]);
        memcpy(d + k, w, n - k < 4 ? n - k : 4);
      }
    }
    nqwipe(b0, sizeof b0);
    nqwipe(b1, sizeof b1);
    nqwipe(o0, sizeof o0);
    nqwipe(o1, sizeof o1);
  }
}

void nqslprf(const nqslc *c, const uint8_t *a, uint8_t *out) {
  unsigned n = c->p->n, i;
  if (c->p->sha2) {
    /* one compression after PK.seed's block: ADRSc || SK.seed, padded
     * (64 + 22 + n bytes in all, n at most 32: it fits one block) */
    uint8_t b0[64], b1[64];
    uint32_t o0[8], o1[8];
    prfblk(c, a, b0, b1);
    nqms2(c->m2.h, b0, b1, o0, o1, c->g);
    for (i = 0; i < n; i += 4) {
      uint8_t w[4];
      nqst32b(w, o0[i / 4] ^ o1[i / 4]);
      memcpy(out + i, w, n - i < 4 ? n - i : 4);
    }
    nqwipe(b0, sizeof b0);
    nqwipe(b1, sizeof b1);
    nqwipe(o0, sizeof o0);
    nqwipe(o1, sizeof o1);
  } else {
    /* SHAKE256(PK.seed || ADRS || SK.seed), SK.seed in shares */
    uint8_t i0[2 * NQSLNMX + 32], i1[2 * NQSLNMX + 32];
    uint8_t q0[NQSLNMX], q1[NQSLNMX];
    memset(i1, 0, sizeof i1);
    memcpy(i0, c->pks, n);
    memcpy(i0 + n, a, 32);
    memcpy(i0 + n + 32, c->s0, n);
    memcpy(i1 + n + 32, c->s1, n);
    nqmshk(q0, q1, n, i0, i1, 2 * (size_t)n + 32, c->g);
    for (i = 0; i < n; i++) out[i] = (uint8_t)(q0[i] ^ q1[i]);
    nqwipe(i0, sizeof i0);
    nqwipe(i1, sizeof i1);
    nqwipe(q0, sizeof q0);
    nqwipe(q1, sizeof q1);
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
