/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC-PKE and HQC-KEM (specification of 2025-08-22, reference v5.0.0):
 * the seed expansion, the three samplers, encryption, decryption and the
 * salted Fujisaki-Okamoto transform with implicit rejection.
 *
 * Hashes: I, H, G, J are SHA3-512 / SHA3-256 / SHA3-512 / SHA3-256 of the
 * input followed by a domain byte (2, 1, 0, 3); the XOF is SHAKE256 of the
 * seed followed by the byte 1. A request for a length that is not a
 * multiple of 8 squeezes the rounded-up length and drops the tail, as the
 * reference does (the known answers depend on it).
 *
 * Constant time: the samplers write positions with masks; the only
 * secret-derived values that steer control flow are the ones the
 * specification accepts (marked NQHQDCL): the rejection test of the
 * key-generation sampler on unused randomness, whether a draw repeated an
 * earlier position, and whether a secret key is self-consistent. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "hash/h.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"

static const nqhqp pars[3] = {
    {17669, 46, 384, 66, 75, 75, 16, 15, 243079u, 16767881u, 277, 2209,
     276, 2208, NQHQPK1, NQHQSK1, NQHQCT1, 0x1Fu},
    {35851, 56, 640, 100, 114, 114, 24, 16, 119800u, 16742417u, 561, 4482,
     560, 4480, NQHQPK3, NQHQSK3, NQHQCT3, 0x7FFu},
    {57637, 90, 640, 131, 149, 149, 32, 29, 74517u, 16772367u, 901, 7205,
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
  const uint8_t d = 1;
  nqshkini(x, 256);
  nqkabs(x, seed, len);
  nqkabs(x, &d, 1);
}

static void xget(nqkctx *x, uint8_t *out, size_t len) {
  size_t rem = len % 8;
  uint8_t t[8];
  nqksqz(x, out, len - rem);
  if (rem != 0) {
    nqksqz(x, t, 8);
    memcpy(out + len - rem, t, rem);
    nqwipe(t, sizeof t);
  }
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
 * 24-bit samples (key generation) */
static void fwu(const nqhqp *p, nqkctx *x, uint64_t *v, size_t w) {
  uint32_t sup[NQHQWM];
  uint8_t buf[3 * NQHQWM];
  size_t blen = 3 * w, i = 0, j = blen, k;
  memset(sup, 0, sizeof sup);
  while (i < w) {
    uint32_t s, rej, dup = 0;
    for (;;) {
      if (j == blen) {
        xget(x, buf, blen);
        j = 0;
      }
      s = ((uint32_t)buf[j] << 16) | ((uint32_t)buf[j + 1] << 8) |
          (uint32_t)buf[j + 2];
      j += 3;
      rej = ((s - p->thr) >> 31) ^ 1u; /* s >= thr */
      NQHQDCL(&rej, sizeof rej);
      if (rej == 0) {
        break;
      }
    }
    s = brt(p, s);
    for (k = 0; k < i; k++) {
      dup |= ~nqctmask(sup[k] ^ s) & 1u;
    }
    sup[i] = s;
    NQHQDCL(&dup, sizeof dup);
    i += 1u ^ dup;
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
static void pubh(const nqhqp *p, uint64_t *h, const uint8_t *seed) {
  uint8_t buf[NQHQNB];
  nqkctx x;
  xini(&x, seed, 32);
  xget(&x, buf, p->nb);
  b2w(h, p->nw, buf, p->nb);
  h[p->nw - 1] &= p->top;
  nqwipe(&x, sizeof x);
}

/* y from seed_dk (the first draw of key generation) */
static void secy(const nqhqp *p, uint64_t *y, const uint8_t *seed) {
  nqkctx x;
  xini(&x, seed, 32);
  fwu(p, &x, y, p->w);
  nqwipe(&x, sizeof x);
}

/* ---- HQC-PKE ---- */

/* ek = seed_ek || s, s = x + y h; seed_dk out */
static void pkekg(const nqhqp *p, uint8_t *ek, uint8_t *sdk,
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
  memcpy(sdk, kp, 32);
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

static void pkedec(const nqhqp *p, uint8_t *m, const uint8_t *sdk,
                   const uint8_t *ct) {
  uint64_t y[NQHQNW], u[NQHQNW], v[NQHQNW];
  uint8_t rsw[NQHQN1];
  size_t i;
  secy(p, y, sdk);
  b2w(u, p->nw, ct, p->nb);
  b2w(v, p->vw, ct + p->nb, p->vb);
  nqhqmul(p, u, y, u);
  for (i = 0; i < p->vw; i++) {
    v[i] ^= u[i];
  }
  nqhqrmd(p, rsw, v);
  nqhqrsd(p, m, rsw);
  nqwipe(y, sizeof y);
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

/* sk's stored seeds re-derive from its seed_kem; constant time */
static int dkok(const nqhqp *p, const uint8_t *dk) {
  uint8_t spke[32], sig[NQHQK], kp[64];
  uint64_t ok;
  nqkctx x;
  xini(&x, dk + p->pk + 32 + p->k, 32);
  xget(&x, spke, 32);
  xget(&x, sig, p->k);
  nqwipe(&x, sizeof x);
  hsh(kp, 512, 2, spke, 32, NULL, 0, NULL, 0);
  ok = eqm(kp, dk + p->pk, 32) & eqm(sig, dk + p->pk + 32, p->k) &
       eqm(kp + 32, dk, 32);
  nqwipe(spke, sizeof spke);
  nqwipe(sig, sizeof sig);
  nqwipe(kp, sizeof kp);
  NQHQDCL(&ok, sizeof ok);
  return ok != 0;
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
  uint8_t spke[32], sig[NQHQK], sdk[32];
  nqkctx x;
  if (p == NULL || seed == NULL || pk == NULL || sk == NULL) {
    return NQEARG;
  }
  if (seedlen != NQHQSEED) return NQEARG;
  if (pklen < p->pk || sklen < p->sk) return NQEBUF;
  xini(&x, seed, 32);
  xget(&x, spke, 32);
  xget(&x, sig, p->k);
  nqwipe(&x, sizeof x);
  pkekg(p, pk, sdk, spke);
  /* sk = ek || seed_dk || sigma || seed_kem */
  memmove(sk + p->pk + 32 + p->k, seed, 32);
  memcpy(sk, pk, p->pk);
  memcpy(sk + p->pk, sdk, 32);
  memcpy(sk + p->pk + 32, sig, p->k);
  nqwipe(spke, sizeof spke);
  nqwipe(sig, sizeof sig);
  nqwipe(sdk, sizeof sdk);
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

int nqhqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen) {
  const nqhqp *p = nqhqpar(alg);
  uint8_t m[NQHQK], hek[32], kt[64], kb[32], ct2[NQHQCTM];
  const uint8_t *salt;
  uint64_t keep;
  uint8_t k8;
  size_t i;
  if (p == NULL || sk == NULL || ct == NULL || ss == NULL) return NQEARG;
  if (sklen != p->sk || ctlen != p->ct) return NQEDEC;
  if (sslen < NQHQSS) return NQEBUF;
  if (!ekok(p, sk) || !dkok(p, sk)) return NQEDEC;
  salt = ct + p->nb + p->vb;
  pkedec(p, m, sk + p->pk, ct);
  hsh(hek, 256, 1, sk, p->pk, NULL, 0, NULL, 0);          /* H(ek) */
  hsh(kt, 512, 0, hek, 32, m, p->k, salt, NQHQSALT);      /* G */
  pkeenc(p, ct2, sk, m, kt + 32);
  memcpy(ct2 + p->nb + p->vb, salt, NQHQSALT);
  hsh(kb, 256, 3, hek, 32, sk + p->pk + 32, p->k, ct, p->ct); /* J */
  keep = eqm(ct, ct2, p->ct); /* all ones when the re-encryption is c */
  k8 = (uint8_t)bar64(keep);
  for (i = 0; i < NQHQSS; i++) {
    ss[i] = (uint8_t)((kt[i] & k8) | (kb[i] & (uint8_t)~k8));
  }
  nqwipe(m, sizeof m);
  nqwipe(kt, sizeof kt);
  nqwipe(kb, sizeof kb);
  nqwipe(ct2, sizeof ct2);
  nqwipe(&keep, sizeof keep);
  nqwipe(&k8, sizeof k8);
  return NQOK;
}
