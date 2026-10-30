/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-KEM (FIPS 203): the ring, K-PKE, key generation, encapsulation, the
 * plain constant-time decapsulation and the input checks of section 7.
 * The masked decapsulation is in mdec.c. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/lk.h"
#include "hash/h.h"
#include "mlkem/mlkem.h"
#include "mlkem/ring.h"

/* ---- parameters ---- */

int nqmkpar(int k, nqmkprm *p) {
  if (k < 2 || k > 4 || p == NULL) return NQEARG;
  p->k = k;
  p->eta1 = k == 2 ? 3 : 2;
  p->du = k == 4 ? 11 : 10;
  p->dv = k == 4 ? 5 : 4;
  p->ek = NQMKEK(k);
  p->dk = NQMKDK(k);
  p->ct = NQMKCT(k);
  return NQOK;
}

uint32_t nqmkop(uint32_t x) {
  volatile uint32_t v = x;
  NQLKO(x);
  return v;
}

/* ---- NTT ---- */

/* zeta^BitRev7(i) * 2^16 mod q, centred (zeta = 17), as FIPS 203
 * Appendix A orders them. */
static const int16_t zetas[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,
    1577,  182,   962,   -1202, -1474, 1468,  573,   -1325, 264,   383,
    -829,  1458,  -1602, -130,  -681,  1017,  732,   608,   -1542, 411,
    -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544,
    516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,
    -271,  830,   107,   -1421, -247,  -951,  -398,  961,   -1508, -725,
    448,   -1065, 677,   -1275, -1103, 430,   555,   843,   -1251, 871,
    1550,  105,   422,   587,   177,   -235,  -291,  -460,  1574,  1653,
    -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,
    -872,  349,   418,   329,   -156,  -75,   817,   1097,  603,   610,
    1322,  -1285, -1465, 384,   -1215, -136,  1218,  -1335, -874,  220,
    -1187, -1659, -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,
    -108,  -308,  996,   991,   958,   -1460, 1522,  1628};

/* seven layers: X^256 + 1 does not split completely mod q, so the
 * transform stops at degree-one factors */
void nqmkntt(nqmkpoly *a) {
  int16_t *r = a->c;
  unsigned k = 1, len, st, j;
  for (len = 128; len >= 2; len >>= 1) {
    for (st = 0; st < 256; st += 2 * len) {
      const int16_t z = zetas[k++];
      for (j = st; j < st + len; j++) {
        const int16_t t = nqmkmr((int32_t)z * r[j + len]);
        r[j + len] = (int16_t)(r[j] - t);
        r[j] = (int16_t)(r[j] + t);
      }
    }
  }
  for (j = 0; j < 256; j++) r[j] = nqmkbr(r[j]);
}

void nqmkint(nqmkpoly *a) {
  int16_t *r = a->c;
  unsigned k = 127, len, st, j;
  /* 2^-7 * 2^32 mod q: the 1/128 of the inverse, and the Montgomery
   * factor of the products before it */
  const int16_t f = 1441;
  for (len = 2; len <= 128; len <<= 1) {
    for (st = 0; st < 256; st += 2 * len) {
      const int16_t z = zetas[k--];
      for (j = st; j < st + len; j++) {
        const int16_t t = r[j];
        r[j] = nqmkbr((int16_t)(t + r[j + len]));
        r[j + len] = (int16_t)(r[j + len] - t);
        r[j + len] = nqmkmr((int32_t)z * r[j + len]);
      }
    }
  }
  for (j = 0; j < 256; j++) r[j] = nqmkmr((int32_t)f * r[j]);
}

/* (a0 + a1 X)(b0 + b1 X) mod (X^2 - z) */
static void bmul(int16_t r[2], const int16_t a[2], const int16_t b[2],
                 int16_t z) {
  r[0] = nqmkmr((int32_t)a[1] * b[1]);
  r[0] = nqmkmr((int32_t)r[0] * z);
  r[0] = (int16_t)(r[0] + nqmkmr((int32_t)a[0] * b[0]));
  r[1] = nqmkmr((int32_t)a[0] * b[1]);
  r[1] = (int16_t)(r[1] + nqmkmr((int32_t)a[1] * b[0]));
}

static void pmul(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b) {
  int i;
  for (i = 0; i < 64; i++) {
    bmul(&r->c[4 * i], &a->c[4 * i], &b->c[4 * i], zetas[64 + i]);
    bmul(&r->c[4 * i + 2], &a->c[4 * i + 2], &b->c[4 * i + 2],
         (int16_t)-zetas[64 + i]);
  }
}

void nqmkadd(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b) {
  int i;
  for (i = 0; i < 256; i++) r->c[i] = (int16_t)(a->c[i] + b->c[i]);
}

void nqmksub(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b) {
  int i;
  for (i = 0; i < 256; i++) r->c[i] = (int16_t)(a->c[i] - b->c[i]);
}

static void pred(nqmkpoly *a) {
  int i;
  for (i = 0; i < 256; i++) a->c[i] = nqmkbr(a->c[i]);
}

void nqmkcan(nqmkpoly *a) {
  int i;
  for (i = 0; i < 256; i++) a->c[i] = nqmkps(nqmkbr(a->c[i]));
}

void nqmkdot(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b, int k) {
  nqmkpoly t;
  int i;
  pmul(r, &a[0], &b[0]);
  for (i = 1; i < k; i++) {
    pmul(&t, &a[i], &b[i]);
    nqmkadd(r, r, &t);
  }
  pred(r);
  nqwipe(&t, sizeof t);
}

/* ---- encodings ---- */

void nqmkbe(uint8_t *out, const nqmkpoly *a, int d) {
  const uint32_t m = (1u << d) - 1u;
  uint32_t acc = 0;
  unsigned nb = 0;
  size_t o = 0;
  int i;
  for (i = 0; i < 256; i++) {
    acc |= ((uint32_t)(uint16_t)a->c[i] & m) << nb;
    nb += (unsigned)d;
    while (nb >= 8) {
      out[o++] = (uint8_t)acc;
      acc >>= 8;
      nb -= 8;
    }
  }
}

void nqmkbd(nqmkpoly *a, const uint8_t *in, int d) {
  const uint32_t m = (1u << d) - 1u;
  uint32_t acc = 0;
  unsigned nb = 0;
  size_t o = 0;
  int i;
  for (i = 0; i < 256; i++) {
    while (nb < (unsigned)d) {
      acc |= (uint32_t)in[o++] << nb;
      nb += 8;
    }
    a->c[i] = (int16_t)(acc & m);
    acc >>= d;
    nb -= (unsigned)d;
  }
}

/* the coefficients of a canonical polynomial, 12 bits each */
static void enc12(uint8_t *out, const nqmkpoly *a) {
  nqmkpoly t = *a;
  nqmkcan(&t);
  nqmkbe(out, &t, 12);
  nqwipe(&t, sizeof t);
}

/* a message bit is 0 or (q + 1) / 2 */
static void frmsg(nqmkpoly *a, const uint8_t m[32]) {
  int i, j;
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 8; j++) {
      const int16_t mk = (int16_t)-(int16_t)((m[i] >> j) & 1);
      a->c[8 * i + j] = (int16_t)(mk & ((NQMKQ + 1) / 2));
    }
  }
}

static void tomsg(uint8_t m[32], const nqmkpoly *a) {
  int i, j;
  for (i = 0; i < 32; i++) {
    unsigned b = 0;
    for (j = 0; j < 8; j++) {
      b |= (unsigned)nqmkcp(a->c[8 * i + j], 1) << j;
    }
    m[i] = (uint8_t)b;
  }
}

/* ---- sampling ---- */

/* SampleNTT(rho || i || j): rejection on public bytes */
static void sntt(nqmkpoly *a, const uint8_t rho[32], uint8_t i,
                 uint8_t j) {
  uint8_t seed[34], buf[168];
  nqkctx c;
  int n = 0;
  size_t p;
  memcpy(seed, rho, 32);
  seed[32] = i;
  seed[33] = j;
  nqshkini(&c, 128);
  nqkabs(&c, seed, sizeof seed);
  while (n < 256) {
    nqksqz(&c, buf, sizeof buf);
    for (p = 0; p + 3 <= sizeof buf && n < 256; p += 3) {
      const uint16_t d1 =
          (uint16_t)(buf[p] | ((uint16_t)(buf[p + 1] & 0x0f) << 8));
      const uint16_t d2 =
          (uint16_t)((buf[p + 1] >> 4) | ((uint16_t)buf[p + 2] << 4));
      if (d1 < NQMKQ) a->c[n++] = (int16_t)d1;
      if (d2 < NQMKQ && n < 256) a->c[n++] = (int16_t)d2;
    }
  }
  nqwipe(&c, sizeof c);
}

void nqmkmat(nqmkpoly *m, const uint8_t rho[32], int k, int tr) {
  int i, j;
  for (i = 0; i < k; i++) {
    for (j = 0; j < k; j++) {
      /* A-hat[i][j] = SampleNTT(rho || j || i) */
      if (tr) {
        sntt(&m[i * NQMKKX + j], rho, (uint8_t)i, (uint8_t)j);
      } else {
        sntt(&m[i * NQMKKX + j], rho, (uint8_t)j, (uint8_t)i);
      }
    }
  }
}

/* SamplePolyCBD_eta: a difference of two eta-bit population counts */
static void cbd(nqmkpoly *a, const uint8_t *b, int eta) {
  size_t bit = 0;
  int i, j;
  for (i = 0; i < 256; i++) {
    int x = 0, y = 0;
    for (j = 0; j < eta; j++, bit++) x += (b[bit >> 3] >> (bit & 7)) & 1;
    for (j = 0; j < eta; j++, bit++) y += (b[bit >> 3] >> (bit & 7)) & 1;
    a->c[i] = (int16_t)(x - y);
  }
}

void nqmkprf(nqmkpoly *a, const uint8_t s[32], uint8_t n, int eta) {
  uint8_t in[33], buf[192];
  memcpy(in, s, 32);
  in[32] = n;
  nqshk(256, in, sizeof in, buf, (size_t)64 * (size_t)eta);
  cbd(a, buf, eta);
  nqwipe(in, sizeof in);
  nqwipe(buf, sizeof buf);
}

/* ---- K-PKE ---- */

int nqmkekd(nqmkpoly *t, const uint8_t *ek, int k) {
  int i, j, bad = 0;
  for (i = 0; i < k; i++) {
    nqmkbd(&t[i], ek + 384 * i, 12);
    for (j = 0; j < 256; j++) bad |= t[i].c[j] >= NQMKQ;
  }
  return bad;
}

/* the secrets of key generation and encryption, wiped together */
typedef struct {
  nqmkpoly s[NQMKKX], e[NQMKKX], t[NQMKKX];
  nqmkpoly a[NQMKKX * NQMKKX];
  nqmkpoly u[NQMKKX], v, e2, mp;
  uint8_t g[64], in[64];
} pkst;

static void pkekg(const nqmkprm *p, uint8_t *ek, uint8_t *dk,
                  const uint8_t d[32], pkst *w) {
  const int k = p->k;
  int i, j;
  uint8_t n = 0;
  /* G(d || k): appending k separates the parameter sets */
  memcpy(w->in, d, 32);
  w->in[32] = (uint8_t)k;
  nqs3(512, w->in, 33, w->g);
  NQMKPUB(w->g, 32); /* rho is published in ek */
  nqmkmat(w->a, w->g, k, 0);
  for (i = 0; i < k; i++) nqmkprf(&w->s[i], w->g + 32, n++, p->eta1);
  for (i = 0; i < k; i++) nqmkprf(&w->e[i], w->g + 32, n++, p->eta1);
  for (i = 0; i < k; i++) nqmkntt(&w->s[i]);
  for (i = 0; i < k; i++) nqmkntt(&w->e[i]);
  for (i = 0; i < k; i++) {
    nqmkdot(&w->t[i], &w->a[i * NQMKKX], w->s, k);
    /* the products carry 2^-16; 2^32 mod q = 1353 removes it */
    for (j = 0; j < 256; j++) {
      w->t[i].c[j] = nqmkmr((int32_t)w->t[i].c[j] * 1353);
    }
    nqmkadd(&w->t[i], &w->t[i], &w->e[i]);
    pred(&w->t[i]);
  }
  for (i = 0; i < k; i++) enc12(ek + 384 * i, &w->t[i]);
  memcpy(ek + 384 * k, w->g, 32);
  for (i = 0; i < k; i++) enc12(dk + 384 * i, &w->s[i]);
}

static int pkenc(const nqmkprm *p, uint8_t *ct, const uint8_t *ek,
                 const uint8_t m[32], const uint8_t r[32], pkst *w) {
  const int k = p->k;
  int i, j;
  uint8_t n = 0;
  if (nqmkekd(w->t, ek, k)) return 1;
  nqmkmat(w->a, ek + 384 * k, k, 1);
  for (i = 0; i < k; i++) nqmkprf(&w->s[i], r, n++, p->eta1);
  for (i = 0; i < k; i++) nqmkprf(&w->e[i], r, n++, 2);
  nqmkprf(&w->e2, r, n++, 2);
  for (i = 0; i < k; i++) nqmkntt(&w->s[i]);
  for (i = 0; i < k; i++) {
    nqmkdot(&w->u[i], &w->a[i * NQMKKX], w->s, k);
    nqmkint(&w->u[i]);
    nqmkadd(&w->u[i], &w->u[i], &w->e[i]);
    pred(&w->u[i]);
  }
  nqmkdot(&w->v, w->t, w->s, k);
  nqmkint(&w->v);
  nqmkadd(&w->v, &w->v, &w->e2);
  frmsg(&w->mp, m);
  nqmkadd(&w->v, &w->v, &w->mp);
  pred(&w->v);
  for (i = 0; i < k; i++) {
    for (j = 0; j < 256; j++) {
      w->u[i].c[j] = (int16_t)nqmkcp(w->u[i].c[j], p->du);
    }
    nqmkbe(ct + 32 * p->du * i, &w->u[i], p->du);
  }
  for (j = 0; j < 256; j++) w->v.c[j] = (int16_t)nqmkcp(w->v.c[j], p->dv);
  nqmkbe(ct + 32 * p->du * k, &w->v, p->dv);
  return 0;
}

int nqmkpke(const nqmkprm *p, uint8_t *ct, const uint8_t *ek,
            const uint8_t m[32], const uint8_t r[32]) {
  pkst w;
  int bad = pkenc(p, ct, ek, m, r, &w);
  nqwipe(&w, sizeof w);
  return bad;
}

static void pkdec(const nqmkprm *p, uint8_t m[32], const uint8_t *dk,
                  const uint8_t *ct, pkst *w) {
  const int k = p->k;
  int i, j;
  for (i = 0; i < k; i++) {
    nqmkbd(&w->u[i], ct + 32 * p->du * i, p->du);
    for (j = 0; j < 256; j++) {
      w->u[i].c[j] = nqmkdc((uint16_t)w->u[i].c[j], p->du);
    }
    nqmkntt(&w->u[i]);
  }
  nqmkbd(&w->v, ct + 32 * p->du * k, p->dv);
  for (j = 0; j < 256; j++) {
    w->v.c[j] = nqmkdc((uint16_t)w->v.c[j], p->dv);
  }
  for (i = 0; i < k; i++) nqmkbd(&w->s[i], dk + 384 * i, 12);
  nqmkdot(&w->mp, w->s, w->u, k);
  nqmkint(&w->mp);
  nqmksub(&w->mp, &w->v, &w->mp);
  pred(&w->mp);
  tomsg(m, &w->mp);
}

/* ---- ML-KEM ---- */

int nqmkekc(int k, const uint8_t *ek, size_t eklen) {
  nqmkprm p;
  nqmkpoly t[NQMKKX];
  int bad;
  if (nqmkpar(k, &p) != NQOK || ek == NULL) return NQEARG;
  if (eklen != p.ek) return NQEDEC;
  bad = nqmkekd(t, ek, k);
  return bad ? NQEDEC : NQOK;
}

int nqmkdkc(int k, const uint8_t *dk, size_t dklen) {
  nqmkprm p;
  uint8_t h[32];
  int ok;
  if (nqmkpar(k, &p) != NQOK || dk == NULL) return NQEARG;
  if (dklen != p.dk) return NQEDEC;
  /* H(ek) == h; both are public, so the answer may be branched on */
  NQMKPUB(dk + 384 * k, p.ek + 32);
  nqs3(256, dk + 384 * k, p.ek, h);
  ok = nqcteq(h, dk + 384 * k + p.ek, 32);
  return ok ? NQOK : NQEDEC;
}

int nqmkkgd(int k, const uint8_t *seed, size_t seedlen, uint8_t *ek,
            size_t eklen, uint8_t *dk, size_t dklen) {
  nqmkprm p;
  pkst w;
  if (nqmkpar(k, &p) != NQOK || seed == NULL || ek == NULL ||
      dk == NULL) {
    return NQEARG;
  }
  if (eklen < p.ek || dklen < p.dk) {
    memset(ek, 0, eklen);
    memset(dk, 0, dklen);
    return NQEBUF;
  }
  if (seedlen != NQMKSEED) {
    memset(ek, 0, eklen);
    memset(dk, 0, dklen);
    return NQEARG;
  }
  pkekg(&p, ek, dk, seed, &w);
  nqwipe(&w, sizeof w);
  memcpy(dk + 384 * k, ek, p.ek);
  nqs3(256, ek, p.ek, dk + 384 * k + p.ek);
  /* z, the implicit-rejection secret */
  memcpy(dk + 384 * k + p.ek + 32, seed + 32, 32);
  return NQOK;
}

int nqmkkg(int k, uint8_t *ek, size_t eklen, uint8_t *dk, size_t dklen) {
  uint8_t seed[NQMKSEED];
  int rc;
  nqmkprm p;
  if (nqmkpar(k, &p) != NQOK || ek == NULL || dk == NULL) return NQEARG;
  rc = nqrand(seed, sizeof seed);
  if (rc != NQOK) {
    nqwipe(seed, sizeof seed);
    memset(ek, 0, eklen);
    memset(dk, 0, dklen);
    return rc;
  }
  rc = nqmkkgd(k, seed, sizeof seed, ek, eklen, dk, dklen);
  nqwipe(seed, sizeof seed);
  return rc;
}

int nqmkencd(int k, const uint8_t *ek, size_t eklen, const uint8_t *m,
             size_t mlen, uint8_t *ct, size_t ctlen, uint8_t *ss,
             size_t sslen) {
  nqmkprm p;
  pkst w;
  int rc = NQOK;
  if (nqmkpar(k, &p) != NQOK || ek == NULL || m == NULL || ct == NULL ||
      ss == NULL) {
    return NQEARG;
  }
  if (ctlen < p.ct || sslen < NQMKSS) {
    rc = NQEBUF;
  } else if (mlen != NQMKMSG) {
    rc = NQEARG;
  } else if (nqmkekc(k, ek, eklen) != NQOK) {
    rc = NQEDEC;
  }
  if (rc != NQOK) {
    memset(ct, 0, ctlen);
    memset(ss, 0, sslen);
    return rc;
  }
  /* (K, r) = G(m || H(ek)) */
  memcpy(w.in, m, 32);
  nqs3(256, ek, p.ek, w.in + 32);
  nqs3(512, w.in, 64, w.g);
  (void)pkenc(&p, ct, ek, m, w.g + 32, &w); /* ek checked above */
  memcpy(ss, w.g, 32);
  nqwipe(&w, sizeof w);
  return NQOK;
}

int nqmkenc(int k, const uint8_t *ek, size_t eklen, uint8_t *ct,
            size_t ctlen, uint8_t *ss, size_t sslen) {
  uint8_t m[NQMKMSG];
  int rc;
  nqmkprm p;
  if (nqmkpar(k, &p) != NQOK || ek == NULL || ct == NULL || ss == NULL) {
    return NQEARG;
  }
  rc = nqrand(m, sizeof m);
  if (rc != NQOK) {
    nqwipe(m, sizeof m);
    memset(ct, 0, ctlen);
    memset(ss, 0, sslen);
    return rc;
  }
  rc = nqmkencd(k, ek, eklen, m, sizeof m, ct, ctlen, ss, sslen);
  nqwipe(m, sizeof m);
  return rc;
}

/* plain decapsulation state */
typedef struct {
  pkst w;
  uint8_t m[32], g[64], in[64], kb[32];
  uint8_t ct2[NQMKCTX];
  uint8_t j[32 + NQMKCTX];
} dpst;

int nqmkdecp(int k, const uint8_t *dk, size_t dklen, const uint8_t *ct,
             size_t ctlen, uint8_t *ss, size_t sslen) {
  nqmkprm p;
  dpst s;
  const uint8_t *ek, *h, *z;
  uint8_t diff = 0, mk;
  unsigned nz;
  size_t i;
  int bad, rc = NQOK;
  if (nqmkpar(k, &p) != NQOK || dk == NULL || ct == NULL || ss == NULL) {
    return NQEARG;
  }
  if (sslen < NQMKSS) {
    rc = NQEBUF;
  } else if (ctlen != p.ct || nqmkdkc(k, dk, dklen) != NQOK) {
    rc = NQEDEC;
  }
  if (rc != NQOK) {
    memset(ss, 0, sslen);
    return rc;
  }
  ek = dk + 384 * k;
  h = ek + p.ek;
  z = h + 32;
  pkdec(&p, s.m, dk, ct, &s.w);
  memcpy(s.in, s.m, 32);
  memcpy(s.in + 32, h, 32);
  nqs3(512, s.in, 64, s.g);
  /* K-bar = J(z || c) */
  memcpy(s.j, z, 32);
  memcpy(s.j + 32, ct, p.ct);
  nqshk(256, s.j, 32 + p.ct, s.kb, 32);
  bad = pkenc(&p, s.ct2, ek, s.m, s.g + 32, &s.w);
  /* the re-encryption either matched or not: no branch, no early exit */
  diff = (uint8_t)bad;
  for (i = 0; i < p.ct; i++) diff = (uint8_t)(diff | (s.ct2[i] ^ ct[i]));
  nz = diff;
  nz |= nz >> 4;
  nz |= nz >> 2;
  nz |= nz >> 1;
  mk = (uint8_t)nqmkop(0u - (nz & 1u)); /* 0xff when they differ */
  for (i = 0; i < 32; i++) {
    ss[i] = (uint8_t)((s.g[i] & (uint8_t)~mk) | (s.kb[i] & mk));
  }
  nqwipe(&s, sizeof s);
  return NQOK;
}
