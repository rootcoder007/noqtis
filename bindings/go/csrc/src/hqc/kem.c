/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC-PKE and HQC-KEM (specification version 5.1 of 2026-11-09,
 * reference v5.1.0): the seed expansion, the three samplers, encryption,
 * decryption and the salted Fujisaki-Okamoto transform with implicit
 * rejection.
 *
 * Hashes: I, H, G, J are SHA3-512 / SHA3-256 / SHA3-512 / SHA3-256 of the
 * input followed by a domain byte (2, 1, 0, 3); the XOF is SHAKE256 of the
 * seed alone, squeezed as a stream. The decapsulation key is seed_kem;
 * SHAKE256(seed_kem || k) gives seed_pke and then sigma, so decapsulation
 * runs the key generation of HQC-PKE again.
 *
 * Constant time: the samplers write positions with masks; the only
 * secret-derived value that steers control flow is the one the
 * specification accepts (marked NQHQDCL): whether a draw of the
 * key-generation sampler is kept (below the rejection threshold, and not a
 * repeat of an earlier position). Since decapsulation runs key generation,
 * that also holds for decapsulation; it is a fixed property of the key. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "hash/h.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"

static const nqhqp pars[3] = {
    {17669, 46, 384, 67, 76, 76, 16, 15, 243079u, 16767881u, 277, 2209,
     276, 2208, NQHQPK1, NQHQSK1, NQHQCT1, 0x1Fu},
    {35851, 56, 640, 101, 114, 114, 24, 16, 119800u, 16742417u, 561, 4482,
     560, 4480, NQHQPK3, NQHQSK3, NQHQCT3, 0x7FFu},
    {57637, 90, 640, 132, 150, 150, 32, 29, 74517u, 16772367u, 901, 7205,
     900, 7200, NQHQPK5, NQHQSK5, NQHQCT5, 0x1FFFFFFFFFu},
};

const nqhqp *nqhqpar(nqkalg alg) {
  switch (alg) {
  case NQHQC128: return &pars[0];
  case NQHQC192: return &pars[1];
  case NQHQC256: return &pars[2];
  default: return NULL;
  }
}

static uint64_t bar64(uint64_t x) {
  volatile uint64_t y = x;
  return y;
}

/* ---- bytes and words, little-endian ---- */

static void b2w(uint64_t *w, size_t nw, const uint8_t *b, size_t nb) {
  size_t i, j;
  for (i = 0; i < nw; i++) {
    uint64_t v = 0;
    for (j = 0; j < 8 && 8 * i + j < nb; j++) {
      v |= (uint64_t)b[8 * i + j] << (8 * j);
    }
    w[i] = v;
  }
}

static void w2b(uint8_t *b, size_t nb, const uint64_t *w) {
  size_t i;
  for (i = 0; i < nb; i++) {
    b[i] = (uint8_t)(w[i / 8] >> (8 * (i % 8)));
  }
}

/* 0xFF..FF when a and b are equal, constant time */
static uint64_t eqm(const uint8_t *a, const uint8_t *b, size_t n) {
  uint64_t d = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    d |= (uint64_t)(a[i] ^ b[i]);
  }
  return bar64(0u - ((d - 1) >> 63));
}

/* ---- hashes ---- */

/* SHA3-bits of a || b || c || dom; b and c may be NULL */
static void hsh(uint8_t *out, unsigned bits, uint8_t dom,
                const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                const uint8_t *c, size_t cl) {
  nqkctx k;
  nqs3ini(&k, bits);
  nqkabs(&k, a, al);
  if (b != NULL) nqkabs(&k, b, bl);
  if (c != NULL) nqkabs(&k, c, cl);
  nqkabs(&k, &dom, 1);
  nqksqz(&k, out, bits / 8);
  nqwipe(&k, sizeof k);
}

static void xini(nqkctx *x, const uint8_t *seed, size_t len) {
  nqshkini(x, 256);
  nqkabs(x, seed, len);
}

/* the KEM's XOF: SHAKE256(seed_kem || k), k the message bytes */
static void kxini(const nqhqp *p, nqkctx *x, const uint8_t *seed) {
  const uint8_t d = (uint8_t)p->k;
  nqshkini(x, 256);
  nqkabs(x, seed, 32);
  nqkabs(x, &d, 1);
}

static void xget(nqkctx *x, uint8_t *out, size_t len) {
  nqksqz(x, out, len);
}

/* ---- sampling ---- */

/* x mod n for x < 2^24 */
static uint32_t brt(const nqhqp *p, uint32_t x) {
  uint64_t q = ((uint64_t)x * p->mu) >> 32;
  uint32_t r = x - (uint32_t)(q * p->n);
  uint32_t ge = ((r - p->n) >> 31) ^ 1u; /* r >= n */
  return r - ((0u - ge) & p->n);
}

/* 1 << k for a secret k < 64, by six fixed shifts chosen with masks */
static uint64_t oneh(uint32_t k) {
  uint64_t b = 1;
  unsigned i;
  for (i = 0; i < 6; i++) {
    uint64_t sel = 0u - (uint64_t)((k >> i) & 1u);
    b = (b & ~sel) | ((b << (1u << i)) & sel);
  }
  return b;
}

/* the vector with ones at the (secret) positions sup[0..w) */
static void wsup(const nqhqp *p, uint64_t *v, const uint32_t *sup,
                 size_t w) {
  size_t i, j;
  for (i = 0; i < p->nw; i++) {
    v[i] = 0;
  }
  for (j = 0; j < w; j++) {
    uint32_t word = sup[j] >> 6;
    uint64_t bit = oneh(sup[j] & 63u);
    for (i = 0; i < p->nw; i++) {
      uint64_t eq = (uint64_t)~nqctmask((uint32_t)i ^ word);
      v[i] |= bit & (eq | (eq << 32));
    }
  }
}

/* SampleFixedWeightVect$: uniform distinct positions by rejection of
 * 24-bit samples, 3 bytes little-endian each (key generation) */
static void fwu(const nqhqp *p, nqkctx *x, uint64_t *v, size_t w) {
  uint32_t sup[NQHQWM];
  uint8_t buf[3];
  size_t i = 0, k;
  memset(sup, 0, sizeof sup);
  while (i < w) {
    uint32_t s, keep, dup = 0;
    xget(x, buf, 3);
    s = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
        ((uint32_t)buf[2] << 16);
    keep = (s - p->thr) >> 31; /* s < thr */
    s = brt(p, s);
    for (k = 0; k < i; k++) {
      dup |= ~nqctmask(sup[k] ^ s) & 1u;
    }
    keep &= dup ^ 1u;
    sup[i] = s;
    NQHQDCL(&keep, sizeof keep);
    i += keep;
  }
  wsup(p, v, sup, w);
  nqwipe(sup, sizeof sup);
  nqwipe(buf, sizeof buf);
}

/* SampleFixedWeightVect: Sendrier's algorithm, no rejection, a
 * constant-time repair of collisions (encryption) */
static void fws(const nqhqp *p, nqkctx *x, uint64_t *v, size_t w) {
  uint32_t sup[NQHQWM];
  uint8_t buf[4 * NQHQWM];
  size_t i, j;
  xget(x, buf, 4 * w);
  for (i = 0; i < w; i++) {
    uint64_t r = (uint64_t)buf[4 * i] | ((uint64_t)buf[4 * i + 1] << 8) |
                 ((uint64_t)buf[4 * i + 2] << 16) |
                 ((uint64_t)buf[4 * i + 3] << 24);
    sup[i] = (uint32_t)(i + ((r * (p->n - i)) >> 32));
  }
  for (i = w - 1; i-- > 0;) {
    uint32_t found = 0, m;
    for (j = i + 1; j < w; j++) {
      found |= ~nqctmask(sup[j] ^ sup[i]) & 1u;
    }
    m = 0u - found;
    sup[i] = (m & (uint32_t)i) ^ (~m & sup[i]);
  }
  wsup(p, v, sup, w);
  nqwipe(sup, sizeof sup);
  nqwipe(buf, sizeof buf);
}

/* SampleVect: the public h from seed_ek */
static void pubh(const nqhqp *p, uint64_t *h, const uint8_t *seed);
void nqhqpubh(const nqhqp *p, uint64_t *h, const uint8_t *seed) {
  pubh(p, h, seed);
}

static void pubh(const nqhqp *p, uint64_t *h, const uint8_t *seed) {
  uint8_t buf[NQHQNB];
  nqkctx x;
  xini(&x, seed, 32);
  xget(&x, buf, p->nb);
  b2w(h, p->nw, buf, p->nb);
  h[p->nw - 1] &= p->top;
  nqwipe(&x, sizeof x);
}

void nqhqhek(const nqhqp *p, uint8_t hek[32], const uint8_t *ek) {
  hsh(hek, 256, 1, ek, p->pk, NULL, 0, NULL, 0);
}

/* ---- HQC-PKE ---- */

/* ek = seed_ek || s, s = x + y h; y out when ycp is not NULL */
static void pkekg(const nqhqp *p, uint8_t *ek, uint64_t *ycp,
                  const uint8_t *spke) {
  uint8_t kp[64];
  uint64_t x[NQHQNW], y[NQHQNW], h[NQHQNW];
  nqkctx dx;
  size_t i;
  hsh(kp, 512, 2, spke, 32, NULL, 0, NULL, 0); /* I */
  xini(&dx, kp, 32);
  fwu(p, &dx, y, p->w);
  fwu(p, &dx, x, p->w);
  nqwipe(&dx, sizeof dx);
  pubh(p, h, kp + 32);
  nqhqmul(p, h, y, h);
  for (i = 0; i < p->nw; i++) {
    h[i] ^= x[i];
  }
  memcpy(ek, kp + 32, 32);
  w2b(ek + 32, p->nb, h);
  if (ycp != NULL) memcpy(ycp, y, p->nw * 8);
  nqwipe(kp, sizeof kp);
  nqwipe(x, sizeof x);
  nqwipe(y, sizeof y);
}

/* (u, v) into ct, salt not included */
static void pkeenc(const nqhqp *p, uint8_t *ct, const uint8_t *ek,
                   const uint8_t *m, const uint8_t *theta) {
  uint64_t h[NQHQNW], s[NQHQNW], r1[NQHQNW], r2[NQHQNW], e[NQHQNW];
  uint64_t v[NQHQNW];
  uint8_t rsw[NQHQN1];
  nqkctx tx;
  size_t i;
  pubh(p, h, ek);
  b2w(s, p->nw, ek + 32, p->nb);
  xini(&tx, theta, 32);
  fws(p, &tx, r2, p->wr);
  fws(p, &tx, e, p->we);
  fws(p, &tx, r1, p->wr);
  nqwipe(&tx, sizeof tx);
  nqhqmul(p, h, r2, h); /* u = r1 + r2 h */
  for (i = 0; i < p->nw; i++) {
    h[i] ^= r1[i];
  }
  nqhqrse(p, rsw, m);
  nqhqrme(p, v, rsw);
  nqhqmul(p, s, r2, s); /* v = code(m) + Truncate(r2 s + e) */
  for (i = 0; i < p->vw; i++) {
    v[i] ^= s[i] ^ e[i];
  }
  w2b(ct, p->nb, h);
  w2b(ct + p->nb, p->vb, v);
  nqwipe(h, sizeof h);
  nqwipe(s, sizeof s);
  nqwipe(r1, sizeof r1);
  nqwipe(r2, sizeof r2);
  nqwipe(e, sizeof e);
  nqwipe(v, sizeof v);
  nqwipe(rsw, sizeof rsw);
}

static void pkedec(const nqhqp *p, uint8_t *m, const uint64_t *y,
                   const uint8_t *ct) {
  uint64_t u[NQHQNW], v[NQHQNW];
  uint8_t rsw[NQHQN1];
  size_t i;
  b2w(u, p->nw, ct, p->nb);
  b2w(v, p->vw, ct + p->nb, p->vb);
  nqhqmul(p, u, y, u);
  for (i = 0; i < p->vw; i++) {
    v[i] ^= u[i];
  }
  nqhqrmd(p, rsw, v);
  nqhqrsd(p, m, rsw);
  nqwipe(u, sizeof u);
  nqwipe(v, sizeof v);
  nqwipe(rsw, sizeof rsw);
}

/* ---- HQC-KEM ---- */

/* the top bits of s past n are zero */
static int ekok(const nqhqp *p, const uint8_t *ek) {
  unsigned spare = (unsigned)(8 * p->nb - p->n);
  return (ek[p->pk - 1] >> (8 - spare)) == 0;
}

/* the key pair again from dk = seed_kem: ek, y and sigma */
void nqhqexp(const nqhqp *p, const uint8_t *dk, uint8_t *ek, uint64_t *y,
             uint8_t *sig) {
  uint8_t spke[32];
  nqkctx x;
  kxini(p, &x, dk);
  xget(&x, spke, 32);
  xget(&x, sig, p->k);
  nqwipe(&x, sizeof x);
  pkekg(p, ek, y, spke);
  nqwipe(spke, sizeof spke);
}

int nqhqsz(nqkalg alg, nqksz *sz) {
  const nqhqp *p = nqhqpar(alg);
  if (p == NULL || sz == NULL) return NQEARG;
  sz->pk = p->pk;
  sz->sk = p->sk;
  sz->ct = p->ct;
  sz->ss = NQHQSS;
  return NQOK;
}

int nqhqkgd(nqkalg alg, const uint8_t *seed, size_t seedlen,
            uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen) {
  const nqhqp *p = nqhqpar(alg);
  uint8_t spke[32];
  nqkctx x;
  if (p == NULL || seed == NULL || pk == NULL || sk == NULL) {
    return NQEARG;
  }
  if (seedlen != NQHQSEED) return NQEARG;
  if (pklen < p->pk || sklen < p->sk) return NQEBUF;
  kxini(p, &x, seed);
  xget(&x, spke, 32);
  nqwipe(&x, sizeof x);
  /* sk = seed_kem */
  memmove(sk, seed, 32);
  pkekg(p, pk, NULL, spke);
  nqwipe(spke, sizeof spke);
  return NQOK;
}

int nqhqkg(nqkalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
           size_t sklen) {
  uint8_t seed[NQHQSEED];
  int r = nqrand(seed, sizeof seed);
  if (r == NQOK) {
    r = nqhqkgd(alg, seed, sizeof seed, pk, pklen, sk, sklen);
  }
  nqwipe(seed, sizeof seed);
  return r;
}

int nqhqencd(nqkalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *seed, size_t seedlen,
             uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen) {
  const nqhqp *p = nqhqpar(alg);
  uint8_t hek[32], kt[64], m[NQHQK], salt[NQHQSALT];
  if (p == NULL || pk == NULL || seed == NULL || ct == NULL ||
      ss == NULL) {
    return NQEARG;
  }
  if (seedlen != p->k + NQHQSALT) return NQEARG;
  if (pklen != p->pk || !ekok(p, pk)) return NQEDEC;
  if (ctlen < p->ct || sslen < NQHQSS) return NQEBUF;
  memcpy(m, seed, p->k);
  memcpy(salt, seed + p->k, NQHQSALT);
  hsh(hek, 256, 1, pk, p->pk, NULL, 0, NULL, 0);          /* H(ek) */
  hsh(kt, 512, 0, hek, 32, m, p->k, salt, NQHQSALT);      /* G */
  pkeenc(p, ct, pk, m, kt + 32);
  memcpy(ct + p->nb + p->vb, salt, NQHQSALT);
  memcpy(ss, kt, NQHQSS);
  nqwipe(kt, sizeof kt);
  nqwipe(m, sizeof m);
  nqwipe(salt, sizeof salt);
  return NQOK;
}

int nqhqenc(nqkalg alg, const uint8_t *pk, size_t pklen,
            uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen) {
  const nqhqp *p = nqhqpar(alg);
  uint8_t seed[NQHQK + NQHQSALT];
  size_t n;
  int r;
  if (p == NULL) return NQEARG;
  n = p->k + NQHQSALT;
  r = nqrand(seed, n);
  if (r == NQOK) {
    r = nqhqencd(alg, pk, pklen, seed, n, ct, ctlen, ss, sslen);
  }
  nqwipe(seed, sizeof seed);
  return r;
}

/* the checks both decapsulations share */
static int dchk(const nqhqp *p, const uint8_t *sk, size_t sklen,
                const uint8_t *ct, size_t ctlen, uint8_t *ss,
                size_t sslen) {
  if (p == NULL || sk == NULL || ct == NULL || ss == NULL) return NQEARG;
  if (sklen != p->sk || ctlen != p->ct) return NQEDEC;
  if (sslen < NQHQSS) return NQEBUF;
  return NQOK;
}

/* HQC.Decaps, first-order masked (mdec.c) */
int nqhqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen) {
  const nqhqp *p = nqhqpar(alg);
  int rc = dchk(p, sk, sklen, ct, ctlen, ss, sslen);
  if (rc != NQOK) return rc;
  rc = nqhqmdec(p, sk, ct, ss);
  if (rc != NQOK) nqwipe(ss, NQHQSS);
  return rc == NQOK ? NQOK : NQERNG;
}

/* HQC.Decaps, constant time but not masked */
int nqhqdecp(nqkalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen) {
  const nqhqp *p = nqhqpar(alg);
  uint8_t m[NQHQK], hek[32], kt[64], kb[32], ct2[NQHQCTM];
  uint8_t ek[NQHQPKM], sig[NQHQK];
  uint64_t y[NQHQNW];
  const uint8_t *salt;
  uint64_t keep;
  uint8_t k8;
  size_t i;
  int rc = dchk(p, sk, sklen, ct, ctlen, ss, sslen);
  if (rc != NQOK) return rc;
  salt = ct + p->nb + p->vb;
  nqhqexp(p, sk, ek, y, sig);
  pkedec(p, m, y, ct);
  hsh(hek, 256, 1, ek, p->pk, NULL, 0, NULL, 0);          /* H(ek) */
  hsh(kt, 512, 0, hek, 32, m, p->k, salt, NQHQSALT);      /* G */
  pkeenc(p, ct2, ek, m, kt + 32);
  memcpy(ct2 + p->nb + p->vb, salt, NQHQSALT);
  hsh(kb, 256, 3, hek, 32, sig, p->k, ct, p->ct);         /* J */
  keep = eqm(ct, ct2, p->ct); /* all ones when the re-encryption is c */
  k8 = (uint8_t)bar64(keep);
  for (i = 0; i < NQHQSS; i++) {
    ss[i] = (uint8_t)((kt[i] & k8) | (kb[i] & (uint8_t)~k8));
  }
  nqwipe(m, sizeof m);
  nqwipe(kt, sizeof kt);
  nqwipe(kb, sizeof kb);
  nqwipe(ct2, sizeof ct2);
  nqwipe(y, sizeof y);
  nqwipe(sig, sizeof sig);
  nqwipe(&keep, sizeof keep);
  nqwipe(&k8, sizeof k8);
  return NQOK;
}
