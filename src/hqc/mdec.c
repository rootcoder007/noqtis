/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* First-order masked HQC decapsulation (HQC v5.0.0, 2025-08-22).
 *
 * Every value that depends on the decapsulation key is held as two
 * shares, each uniform on its own: Boolean (x = x0 ^ x1) for vectors,
 * field elements and integers, arithmetic mod 2^32 (a = a0 + a1) for the
 * Reed-Muller sums. Linear steps act share by share; the others use fresh
 * randomness, so that no single value depends on the key.
 *
 *   y          split afresh into two dense shares on every call
 *   v - u y    u y0 and u y1, each with the constant-time product
 *   RM decode  each bit to arithmetic shares (Goubin, CHES 2001), the
 *              Hadamard transform share by share, back to Boolean shares
 *              by a masked addition, and the peak search with masked
 *              comparisons and selections, ties as the reference breaks
 *              them
 *   RS decode  syndromes share by share (a linear map), Berlekamp's
 *              algorithm with masked field products (Trichina's gadget
 *              over GF(256)) and its degrees and conditions as masked
 *              integers and masks, the roots by evaluating at public
 *              points (linear), the error values with masked inverses
 *   G, J       masked SHA3-512 and SHA3-256 (msk.h); J's sigma split
 *              afresh
 *   c'         Sendrier's sampler with a masked multiply-high and a
 *              masked repair of collisions, the vectors from their masked
 *              positions, the codes and the products with the public h
 *              and s share by share
 *   c' == c    the difference ORed in shares; the key selected in shares
 *              and only then unmasked
 *
 * Integers are 32-bit Boolean-shared words: addition is the Kogge-Stone
 * masked adder of msk.h, a comparison the sign of a masked difference,
 * as the reference's (a - b) >> 31. Pure C11; opaque volatile copies
 * keep the compiler from recombining shares, and in a TVLA build pass
 * each share word to the leakage hook. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/lk.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"
#include "msk/msk.h"

typedef uint32_t mw[2];

/* ---- gadgets on 32-bit words ---- */

static uint32_t op(uint32_t x) {
  volatile uint32_t v = x;
  NQLK(x, NQLKOP);
  return v;
}

static uint64_t op64(uint64_t x) {
  volatile uint64_t v = x;
  NQLK(x, NQLKKC);
  return v;
}

/* z = x & y, Trichina, y refreshed; z may alias x or y */
static void mand(mw z, const mw x, const mw y, nqmrg *g) {
  const uint32_t q = nqmr32(g), r = nqmr32(g);
  const uint32_t x0 = x[0], x1 = x[1];
  const uint32_t y0 = op(y[0] ^ q);
  uint32_t t = op(r ^ (x0 & y0)), y1;
  y1 = op(y[1] ^ q);
  t = op(t ^ (x0 & y1));
  t = op(t ^ (x1 & y0));
  t = op(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

static void mxor(mw z, const mw x, const mw y) {
  const uint32_t a = op(x[0] ^ y[0]);
  const uint32_t b = op(x[1] ^ y[1]);
  z[0] = a;
  z[1] = b;
}

/* z = x | y = ~(~x & ~y) */
static void mor(mw z, const mw x, const mw y, nqmrg *g) {
  mw a, b;
  a[0] = ~x[0];
  a[1] = x[1];
  b[0] = ~y[0];
  b[1] = y[1];
  mand(z, a, b, g);
  z[0] = ~z[0];
}

/* a public value as shares */
static void pub(mw z, uint32_t v) {
  z[0] = v;
  z[1] = 0;
}

/* all ones when x != 0: OR of the bits by folding, then replicated */
static void mnz(mw z, const mw x, unsigned bits, nqmrg *g) {
  mw t, u;
  unsigned s;
  t[0] = x[0];
  t[1] = x[1];
  for (s = 1; s < bits; s <<= 1) {
    u[0] = t[0] >> s;
    u[1] = t[1] >> s;
    mor(t, t, u, g);
  }
  z[0] = op(0u - (t[0] & 1u));
  z[1] = op(0u - (t[1] & 1u));
}

/* all ones when x == 0 */
static void mz(mw z, const mw x, unsigned bits, nqmrg *g) {
  mnz(z, x, bits, g);
  z[0] = ~z[0];
}

/* z = a - b mod 2^32 */
static void msub(mw z, const mw a, const mw b, nqmrg *g) {
  mw nb, one;
  nb[0] = ~b[0];
  nb[1] = b[1];
  nqmsadd(z, a, nb, g);
  pub(one, 1);
  nqmsadd(z, z, one, g);
}

/* all ones when the sign bit of x is set */
static void msign(mw z, const mw x) {
  z[0] = op(0u - (x[0] >> 31));
  z[1] = op(0u - (x[1] >> 31));
}

/* all ones when a < b, as the reference's 0 - ((a - b) >> 31) */
static void mlt(mw z, const mw a, const mw b, nqmrg *g) {
  mw d;
  msub(d, a, b, g);
  msign(z, d);
}

/* z = m ? x : y, as y ^ (m & (x ^ y)) */
static void mmux(mw z, const mw m, const mw x, const mw y, nqmrg *g) {
  mw d;
  mxor(d, x, y);
  mand(d, m, d, g);
  mxor(z, y, d);
}

/* ---- GF(256), the field of code.c ---- */

static uint32_t gm(uint32_t a, uint32_t b) {
  uint32_t a0 = a & 0x11u, a1 = a & 0x22u, a2 = a & 0x44u, a3 = a & 0x88u;
  uint32_t b0 = b & 0x11u, b1 = b & 0x22u, b2 = b & 0x44u, b3 = b & 0x88u;
  uint32_t p = (((a0 * b0) ^ (a1 * b3) ^ (a2 * b2) ^ (a3 * b1)) & 0x1111u) |
               (((a0 * b1) ^ (a1 * b0) ^ (a2 * b3) ^ (a3 * b2)) & 0x2222u) |
               (((a0 * b2) ^ (a1 * b1) ^ (a2 * b0) ^ (a3 * b3)) & 0x4444u) |
               (((a0 * b3) ^ (a1 * b2) ^ (a2 * b1) ^ (a3 * b0)) & 0x8888u);
  int i;
  for (i = 0; i < 2; i++) {
    uint32_t hi = p >> 8;
    p = (p & 0xFFu) ^ hi ^ (hi << 2) ^ (hi << 3) ^ (hi << 4);
  }
  return p;
}

static void gexp(uint32_t e[255]) {
  uint32_t x = 1;
  int i;
  for (i = 0; i < 255; i++) {
    e[i] = x;
    x <<= 1;
    x ^= 0x11Du & (0u - (x >> 8));
  }
}

/* z = a b in GF(256), both masked: Trichina's gadget with the field
 * product (bilinear), b refreshed; z may alias */
static void mgm(mw z, const mw a, const mw b, nqmrg *g) {
  const uint32_t q = nqmr32(g) & 0xFFu, r = nqmr32(g) & 0xFFu;
  const uint32_t a0 = a[0], a1 = a[1];
  const uint32_t b0 = op(b[0] ^ q);
  uint32_t t = op(r ^ gm(a0, b0)), b1;
  b1 = op(b[1] ^ q);
  t = op(t ^ gm(a0, b1));
  t = op(t ^ gm(a1, b0));
  t = op(t ^ gm(a1, b1));
  z[0] = r;
  z[1] = t;
}

/* z = a c for a public c: linear */
static void mgc(mw z, const mw a, uint32_t c) {
  z[0] = op(gm(a[0], c));
  z[1] = op(gm(a[1], c));
}

/* squaring is linear over GF(2) */
static void mgsq(mw z, const mw a) {
  z[0] = op(gm(a[0], a[0]));
  z[1] = op(gm(a[1], a[1]));
}

/* a^254 = a^-1 (0 for 0), the chain of code.c's ginv */
static void mginv(mw z, const mw a, nqmrg *g) {
  mw a2, a3, a4, a7, a11, a15, t;
  mgsq(a2, a);
  mgm(a3, a2, a, g);
  mgsq(a4, a2);
  mgm(a7, a4, a3, g);
  mgm(a11, a4, a7, g);
  mgm(a15, a11, a4, g);
  mgsq(t, a15);
  mgsq(t, t);
  mgsq(t, t);
  mgm(t, t, a7, g);
  mgsq(z, t);
}

/* ---- Reed-Solomon decoding on shares ---- */

typedef struct {
  mw c[NQHQN1], syn[2 * NQHQD], sg[NQHQD + 1], sgc[NQHQD + 1],
      xsp[NQHQD + 1], z[NQHQD + 1], er[NQHQN1], ev[NQHQN1], bj[NQHQD],
      ej[NQHQD];
  mw dsg, dsgp, pp, dp, d, dd, deg;
} rsst;

static void mrssyn(const nqhqp *p, rsst *s, const uint32_t *e) {
  size_t i, j;
  for (i = 0; i < 2 * p->dl; i++) {
    mw acc, t;
    acc[0] = s->c[0][0];
    acc[1] = s->c[0][1];
    for (j = 1; j < p->n1; j++) {
      mgc(t, s->c[j], e[((i + 1) * j) % 255]);
      mxor(acc, acc, t);
    }
    s->syn[i][0] = acc[0];
    s->syn[i][1] = acc[1];
  }
}

/* rselp of code.c on shares */
static void mrselp(const nqhqp *p, rsst *s, nqmrg *g) {
  const uint32_t dl = p->dl;
  uint32_t mu, i;
  mw dsgc, dx, dxsp, m1, m2, m12, t, inv;
  for (i = 0; i <= dl; i++) {
    pub(s->sgc[i], 0);
    pub(s->xsp[i], 0);
    pub(s->sg[i], 0);
  }
  pub(s->xsp[1], 1);
  pub(s->sg[0], 1);
  pub(s->dsg, 0);
  pub(s->dsgp, 0);
  pub(s->pp, 0xFFFFu);
  pub(s->dp, 1);
  s->d[0] = s->syn[0][0];
  s->d[1] = s->syn[0][1];
  for (mu = 0; mu < 2 * dl; mu++) {
    for (i = 0; i < dl; i++) {
      s->sgc[i][0] = s->sg[i][0];
      s->sgc[i][1] = s->sg[i][1];
    }
    dsgc[0] = s->dsg[0];
    dsgc[1] = s->dsg[1];
    mginv(inv, s->dp, g);
    mgm(s->dd, s->d, inv, g);
    for (i = 1; i <= mu + 1 && i <= dl; i++) {
      mgm(t, s->dd, s->xsp[i], g);
      mxor(s->sg[i], s->sg[i], t);
    }
    pub(t, mu);
    msub(dx, t, s->pp, g);
    dx[0] &= 0xFFFFu;
    dx[1] &= 0xFFFFu;
    nqmsadd(dxsp, dx, s->dsgp, g);
    dxsp[0] &= 0xFFFFu;
    dxsp[1] &= 0xFFFFu;
    mnz(m1, s->d, 8, g);
    mlt(m2, s->dsg, dxsp, g);
    mand(m12, m1, m2, g);
    mmux(s->dsg, m12, dxsp, s->dsg, g);
    if (mu == 2 * dl - 1) break;
    pub(t, mu);
    mmux(s->pp, m12, t, s->pp, g);
    mmux(s->dp, m12, s->d, s->dp, g);
    for (i = dl; i > 0; i--) {
      mmux(s->xsp[i], m12, s->sgc[i - 1], s->xsp[i - 1], g);
    }
    mmux(s->dsgp, m12, dsgc, s->dsgp, g);
    s->d[0] = s->syn[mu + 1][0];
    s->d[1] = s->syn[mu + 1][1];
    for (i = 1; i <= mu + 1 && i <= dl; i++) {
      mgm(t, s->sg[i], s->syn[mu + 1 - i], g);
      mxor(s->d, s->d, t);
    }
  }
  s->deg[0] = s->dsg[0];
  s->deg[1] = s->dsg[1];
  nqwipe(dsgc, sizeof dsgc);
  nqwipe(dx, sizeof dx);
  nqwipe(dxsp, sizeof dxsp);
  nqwipe(m12, sizeof m12);
}

/* er[j]: all ones when alpha^-j is a root of sg (Horner at a public
 * point is linear) */
static void mrsroot(const nqhqp *p, rsst *s, const uint32_t *e,
                    nqmrg *g) {
  size_t j, t;
  for (j = 0; j < p->n1; j++) {
    const uint32_t x = e[(255 - j) % 255];
    mw v, u;
    v[0] = s->sg[p->dl][0];
    v[1] = s->sg[p->dl][1];
    for (t = p->dl; t-- > 0;) {
      mgc(u, v, x);
      mxor(v, u, s->sg[t]);
    }
    mz(s->er[j], v, 8, g);
  }
}

/* the error evaluator z, rsz of code.c */
static void mrsz(const nqhqp *p, rsst *s, nqmrg *g) {
  uint32_t i, j;
  mw m, t, ip;
  pub(s->z[0], 1);
  for (i = 1; i <= p->dl; i++) {
    pub(ip, i - 1);
    mlt(m, ip, s->deg, g); /* i - 1 < deg: i <= deg */
    mand(s->z[i], m, s->sg[i], g);
  }
  mxor(s->z[1], s->z[1], s->syn[0]);
  for (i = 2; i <= p->dl; i++) {
    mw acc;
    pub(ip, i - 1);
    mlt(m, ip, s->deg, g);
    acc[0] = s->syn[i - 1][0];
    acc[1] = s->syn[i - 1][1];
    for (j = 1; j < i; j++) {
      mgm(t, s->sg[j], s->syn[i - j - 1], g);
      mxor(acc, acc, t);
    }
    mand(acc, m, acc, g);
    mxor(s->z[i], s->z[i], acc);
  }
}

/* the error values at the marked positions, rsev of code.c */
static void mrsev(const nqhqp *p, rsst *s, const uint32_t *e, nqmrg *g) {
  const uint32_t dl = p->dl;
  uint32_t i, j, k;
  mw cnt, real, m2, m12, found, t, jp;
  for (j = 0; j < dl; j++) {
    pub(s->bj[j], 0);
    pub(s->ej[j], 0);
  }
  pub(cnt, 0);
  for (i = 0; i < p->n1; i++) {
    pub(found, 0);
    for (j = 0; j < dl; j++) {
      pub(jp, j);
      mxor(t, cnt, jp);
      mz(m2, t, 8, g);
      mand(m12, s->er[i], m2, g);
      t[0] = m12[0] & e[i];
      t[1] = m12[1] & e[i];
      mxor(s->bj[j], s->bj[j], t);
      t[0] = m12[0] & 1u;
      t[1] = m12[1] & 1u;
      mxor(found, found, t);
    }
    nqmsadd(cnt, cnt, found, g);
  }
  real[0] = cnt[0];
  real[1] = cnt[1];
  for (i = 0; i < dl; i++) {
    mw t1, t2, inv, invp, u, m1, ip;
    pub(t1, 1);
    pub(t2, 1);
    pub(invp, 1);
    mginv(inv, s->bj[i], g);
    for (j = 1; j <= dl; j++) {
      mgm(invp, invp, inv, g);
      mgm(u, invp, s->z[j], g);
      mxor(t1, t1, u);
    }
    for (k = 1; k < dl; k++) {
      mgm(u, inv, s->bj[(i + k) % dl], g);
      u[0] ^= 1u;
      mgm(t2, t2, u, g);
    }
    pub(ip, i);
    mlt(m1, ip, real, g);
    mginv(u, t2, g);
    mgm(u, t1, u, g);
    mand(s->ej[i], m1, u, g);
  }
  pub(cnt, 0);
  for (i = 0; i < p->n1; i++) {
    pub(found, 0);
    pub(s->ev[i], 0);
    for (j = 0; j < dl; j++) {
      pub(jp, j);
      mxor(t, cnt, jp);
      mz(m2, t, 8, g);
      mand(m12, s->er[i], m2, g);
      mand(t, m12, s->ej[j], g);
      mxor(s->ev[i], s->ev[i], t);
      t[0] = m12[0] & 1u;
      t[1] = m12[1] & 1u;
      mxor(found, found, t);
    }
    nqmsadd(cnt, cnt, found, g);
  }
}

/* msg (k bytes, in shares) from the codeword cw (n1 bytes, in shares) */
static void mrsd(const nqhqp *p, uint8_t *m0, uint8_t *m1,
                 const uint8_t *c0, const uint8_t *c1, nqmrg *g) {
  uint32_t e[255];
  rsst s;
  size_t i;
  gexp(e);
  memset(&s, 0, sizeof s);
  for (i = 0; i < p->n1; i++) {
    s.c[i][0] = c0[i];
    s.c[i][1] = c1[i];
  }
  mrssyn(p, &s, e);
  mrselp(p, &s, g);
  mrsroot(p, &s, e, g);
  mrsz(p, &s, g);
  mrsev(p, &s, e, g);
  for (i = 0; i < p->k; i++) {
    const size_t j = 2 * p->dl + i;
    m0[i] = (uint8_t)op(s.c[j][0] ^ s.ev[j][0]);
    m1[i] = (uint8_t)op(s.c[j][1] ^ s.ev[j][1]);
  }
  nqwipe(&s, sizeof s);
}

/* ---- Reed-Muller decoding on shares ---- */

/* x = xb ^ r (32-bit words) to x = a + r mod 2^32 (Goubin, CHES 2001) */
static uint32_t b2a(uint32_t xb, uint32_t r, nqmrg *g) {
  const uint32_t gam = nqmr32(g);
  uint32_t t, a, gr;
  t = op(xb ^ gam);
  t = op(t - gam);
  t = op(t ^ xb);
  gr = op(gam ^ r);
  a = op(xb ^ gr);
  a = op(a - gr);
  return op(a ^ t);
}

/* Boolean shares of a0 + a1 (arithmetic shares), by the masked adder on
 * freshly masked operands */
static void a2b(mw z, uint32_t a0, uint32_t a1, nqmrg *g) {
  mw x, y;
  const uint32_t m = nqmr32(g), n = nqmr32(g);
  x[0] = op(a0 ^ m);
  x[1] = m;
  y[0] = op(a1 ^ n);
  y[1] = n;
  nqmsadd(z, x, y, g);
}

/* nqhqrmd of code.c on shares: cw0 ^ cw1 is the received word, the
 * bytes in shares */
static void mrmd(const nqhqp *p, uint8_t *o0, uint8_t *o1,
                 const uint64_t *cw0, const uint64_t *cw1, nqmrg *g) {
  const size_t mult = p->n2 / 128;
  uint32_t h0[2][128], h1[2][128];
  size_t i, c;
  for (i = 0; i < p->n1; i++) {
    mw bab, bv, bp, v, av, neg, gt, t, qp, pos;
    int cur = 0, pass, b;
    uint32_t q;
    for (b = 0; b < 128; b++) {
      h0[0][b] = 0;
      h1[0][b] = 0;
    }
    for (c = 0; c < mult; c++) {
      const size_t k = 2 * (i * mult + c);
      for (b = 0; b < 128; b++) {
        const size_t wi = k + (size_t)(b >> 6);
        const unsigned sh = (unsigned)(b & 63);
        const uint32_t hi = nqmr32(g) << 1;
        const uint32_t x0 = (uint32_t)((cw0[wi] >> sh) & 1u) | hi;
        const uint32_t x1 = (uint32_t)((cw1[wi] >> sh) & 1u) | hi;
        h0[0][b] += b2a(x0, x1, g);
        h1[0][b] += x1;
      }
    }
    for (pass = 0; pass < 7; pass++) {
      const uint32_t *s0 = h0[cur], *s1 = h1[cur];
      uint32_t *d0 = h0[cur ^ 1], *d1 = h1[cur ^ 1];
      for (q = 0; q < 64; q++) {
        d0[q] = s0[2 * q] + s0[2 * q + 1];
        d0[q + 64] = s0[2 * q] - s0[2 * q + 1];
        d1[q] = s1[2 * q] + s1[2 * q + 1];
        d1[q + 64] = s1[2 * q] - s1[2 * q + 1];
      }
      cur ^= 1;
    }
    h0[cur][0] -= 64u * (uint32_t)mult;
    pub(bab, 0);
    pub(bv, 0);
    pub(bp, 0);
    for (q = 0; q < 128; q++) {
      a2b(v, h0[cur][q], h1[cur][q], g);
      msign(neg, v);
      mxor(t, v, neg);
      msub(av, t, neg, g); /* |v| */
      mlt(gt, bab, av, g); /* av > bab */
      mmux(bv, gt, v, bv, g);
      pub(qp, q);
      mmux(bp, gt, qp, bp, g);
      mmux(bab, gt, av, bab, g);
    }
    pub(t, 0);
    mlt(pos, t, bv, g); /* bv > 0 as a signed value */
    o0[i] = (uint8_t)op(bp[0] ^ (pos[0] & 128u));
    o1[i] = (uint8_t)op(bp[1] ^ (pos[1] & 128u));
  }
  nqwipe(h0, sizeof h0);
  nqwipe(h1, sizeof h1);
}

/* ---- re-encryption on shares ---- */

/* 64-bit masked words */
typedef uint64_t mq[2];

static void mand64(mq z, const mq x, const mq y, nqmrg *g) {
  const uint64_t q = nqmr64(g), r = nqmr64(g);
  const uint64_t x0 = x[0], x1 = x[1];
  const uint64_t y0 = op64(y[0] ^ q);
  uint64_t t = op64(r ^ (x0 & y0)), y1;
  y1 = op64(y[1] ^ q);
  t = op64(t ^ (x0 & y1));
  t = op64(t ^ (x1 & y0));
  t = op64(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

/* z = x + y mod 2^64, Kogge-Stone (as nqmsadd, on 64 bits) */
static void madd64(mq z, const mq x, const mq y, nqmrg *g) {
  mq gg, pp, t, s;
  unsigned j;
  mand64(gg, x, y, g);
  pp[0] = op64(x[0] ^ y[0]);
  pp[1] = op64(x[1] ^ y[1]);
  s[0] = pp[0];
  s[1] = pp[1];
  for (j = 1; j < 64; j <<= 1) {
    t[0] = op64(gg[0] << j);
    t[1] = op64(gg[1] << j);
    mand64(t, pp, t, g);
    gg[0] = op64(gg[0] ^ t[0]);
    gg[1] = op64(gg[1] ^ t[1]);
    if (j < 32) {
      t[0] = op64(pp[0] << j);
      t[1] = op64(pp[1] << j);
      mand64(pp, pp, t, g);
    }
  }
  z[0] = op64(s[0] ^ (gg[0] << 1));
  z[1] = op64(s[1] ^ (gg[1] << 1));
}

/* 1 << k for a masked k < 64: six masked selections of fixed shifts */
static void moneh(mq b, const mw k, nqmrg *g) {
  unsigned i;
  b[0] = 1;
  b[1] = 0;
  for (i = 0; i < 6; i++) {
    mq sel, d;
    sel[0] = 0u - (uint64_t)((k[0] >> i) & 1u);
    sel[1] = 0u - (uint64_t)((k[1] >> i) & 1u);
    d[0] = op64(b[0] ^ (b[0] << (1u << i)));
    d[1] = op64(b[1] ^ (b[1] << (1u << i)));
    mand64(d, sel, d, g);
    b[0] = op64(b[0] ^ d[0]);
    b[1] = op64(b[1] ^ d[1]);
  }
}

/* the vector (in shares) with ones at the masked positions sup[0..w) */
static void mwsup(const nqhqp *p, uint64_t *v0, uint64_t *v1, mw *sup,
                  size_t w, nqmrg *g) {
  size_t i, j;
  for (i = 0; i < p->nw; i++) {
    v0[i] = 0;
    v1[i] = 0;
  }
  for (j = 0; j < w; j++) {
    mw word, k, eq, t;
    mq bit, e64;
    word[0] = sup[j][0] >> 6;
    word[1] = sup[j][1] >> 6;
    k[0] = sup[j][0] & 63u;
    k[1] = sup[j][1] & 63u;
    moneh(bit, k, g);
    for (i = 0; i < p->nw; i++) {
      t[0] = word[0] ^ (uint32_t)i;
      t[1] = word[1];
      mz(eq, t, 16, g);
      e64[0] = (uint64_t)eq[0] | ((uint64_t)eq[0] << 32);
      e64[1] = (uint64_t)eq[1] | ((uint64_t)eq[1] << 32);
      mand64(e64, e64, bit, g);
      v0[i] ^= e64[0];
      v1[i] ^= e64[1];
    }
  }
}

/* fws of kem.c on shares: buf0 ^ buf1 is the 4 w bytes it draws */
static void mfws(const nqhqp *p, uint64_t *v0, uint64_t *v1, size_t w,
                 const uint8_t *buf0, const uint8_t *buf1, nqmrg *g) {
  mw sup[NQHQWM];
  size_t i, j;
  for (i = 0; i < w; i++) {
    const uint32_t c = p->n - (uint32_t)i;
    mq r, acc, t;
    unsigned b;
    r[0] = nqld32l(buf0 + 4 * i);
    r[1] = nqld32l(buf1 + 4 * i);
    acc[0] = 0;
    acc[1] = 0;
    /* r * c, c public: the shifted r for each bit of c */
    for (b = 0; b < 32; b++) {
      if (((c >> b) & 1u) == 0) continue; /* c is public */
      t[0] = op64(r[0] << b);
      t[1] = op64(r[1] << b);
      madd64(acc, acc, t, g);
    }
    sup[i][0] = (uint32_t)(acc[0] >> 32);
    sup[i][1] = (uint32_t)(acc[1] >> 32);
    {
      mw ip;
      pub(ip, (uint32_t)i);
      nqmsadd(sup[i], sup[i], ip, g);
    }
  }
  for (i = w - 1; i-- > 0;) {
    mw found, t, eq, ip;
    pub(found, 0);
    for (j = i + 1; j < w; j++) {
      mxor(t, sup[j], sup[i]);
      mz(eq, t, 32, g);
      mor(found, found, eq, g);
    }
    pub(ip, (uint32_t)i);
    mmux(sup[i], found, ip, sup[i], g);
  }
  mwsup(p, v0, v1, sup, w, g);
  nqwipe(sup, sizeof sup);
}

/* the stream xget of kem.c reads: a whole number of 8-byte words, the
 * tail of a request taken from a further word */
typedef struct {
  const uint8_t *s0, *s1;
  size_t pos;
} xst;

static void xtake(xst *x, uint8_t *o0, uint8_t *o1, size_t len) {
  const size_t rem = len % 8, head = len - rem;
  memcpy(o0, x->s0 + x->pos, head);
  memcpy(o1, x->s1 + x->pos, head);
  x->pos += head;
  if (rem != 0) {
    memcpy(o0 + head, x->s0 + x->pos, rem);
    memcpy(o1 + head, x->s1 + x->pos, rem);
    x->pos += 8;
  }
}

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

/* u'(or v') xor c's words ORed into acc (shares), acc | d = ~(~acc & ~d) */
static void macc(mq acc, const uint64_t *x0, const uint64_t *x1,
                 const uint64_t *c, size_t nw, nqmrg *g) {
  size_t i;
  for (i = 0; i < nw; i++) {
    mq d;
    d[0] = op64(~(x0[i] ^ c[i]));
    d[1] = x1[i];
    acc[0] = ~acc[0];
    mand64(acc, acc, d, g);
    acc[0] = ~acc[0];
  }
}

/* the vectors one stage holds, reused stage to stage; about 60 KB with
 * the small buffers */
typedef struct {
  uint64_t p0[NQHQNW], p1[NQHQNW]; /* y; then r2 */
  uint64_t a0[NQHQNW], a1[NQHQNW]; /* u y; then r2 h, r1 */
  uint64_t b0[NQHQNW], b1[NQHQNW]; /* the codeword; then r2 s, e */
  uint64_t w[NQHQNW];              /* public: u, h, s, c */
  uint8_t rw0[NQHQN1], rw1[NQHQN1], m0[NQHQK], m1[NQHQK];
  uint8_t gi0[32 + NQHQK + NQHQSALT + 1], gi1[32 + NQHQK];
  uint8_t kt0[64], kt1[64], kb0[32], kb1[32];
  uint8_t xs0[3 * (4 * NQHQWM + 8)], xs1[3 * (4 * NQHQWM + 8)];
  uint8_t xi0[33], xi1[32];
  uint8_t fb0[4 * NQHQWM], fb1[4 * NQHQWM];
  uint8_t ji1[32 + NQHQK];
} mdst;

/* the vector of fws drawn from the stream's next 4 w bytes */
static void mdraw(const nqhqp *p, xst *x, mdst *s, uint64_t *v0,
                  uint64_t *v1, size_t w, nqmrg *g) {
  xtake(x, s->fb0, s->fb1, 4 * w);
  mfws(p, v0, v1, w, s->fb0, s->fb1, g);
}

int nqhqmdec(const nqhqp *p, const uint8_t *sk, const uint8_t *ct,
             uint8_t *ss) {
  mdst st, *s = &st;
  nqmrg gs, *g = &gs;
  const uint8_t *ek = sk, *salt = ct + p->nb + p->vb;
  const uint8_t *sig = sk + p->pk + 32;
  uint8_t hek[32], jin[32 + NQHQK + NQHQCTM + 1];
  size_t i, gl, jl;
  xst x;
  mq acc;
  mw keep;
  int rc = nqmrini(g);
  memset(s, 0, sizeof *s);
  /* ---- the key, loaded and split: y, and sigma for J ---- */
  NQLKST(1);
  nqhqsecy(p, s->p0, sk + p->pk);
  for (i = 0; i < p->nw; i++) {
    const uint64_t r =
        nqmr64(g) & (i + 1 == p->nw ? p->top : ~(uint64_t)0);
    NQLK(s->p0[i], NQLKUN);
    s->p1[i] = s->p0[i] ^ r;
    s->p0[i] = r;
  }
  memset(s->ji1, 0, sizeof s->ji1);
  nqmrb(g, s->ji1 + 32, p->k);
  for (i = 0; i < p->k; i++) {
    NQLK(sig[i], NQLKUN);
    jin[32 + i] = (uint8_t)(sig[i] ^ s->ji1[32 + i]);
  }
  NQLKST(2);
  /* ---- v - u y ---- */
  b2w(s->w, p->nw, ct, p->nb);
  nqhqmul(p, s->a0, s->p0, s->w);
  nqhqmul(p, s->a1, s->p1, s->w);
  b2w(s->b0, p->vw, ct + p->nb, p->vb);
  for (i = 0; i < p->vw; i++) {
    s->b0[i] = op64(s->b0[i] ^ s->a0[i]);
    s->b1[i] = s->a1[i];
  }
  /* ---- m' ---- */
  mrmd(p, s->rw0, s->rw1, s->b0, s->b1, g);
  mrsd(p, s->m0, s->m1, s->rw0, s->rw1, g);
  /* ---- (K', theta) = G(H(ek) || m' || salt || 0) ---- */
  nqhqhek(p, hek, ek);
  memset(s->gi1, 0, sizeof s->gi1);
  memcpy(s->gi0, hek, 32);
  memcpy(s->gi0 + 32, s->m0, p->k);
  memcpy(s->gi1 + 32, s->m1, p->k);
  gl = 32 + p->k;
  memcpy(s->gi0 + gl, salt, NQHQSALT);
  gl += NQHQSALT;
  s->gi0[gl++] = 0;
  nqmkec(s->kt0, s->kt1, 64, s->gi0, s->gi1, gl, 32 + p->k, 72, 0x06, g);
  /* ---- the XOF of theta: the bytes r2, e and r1 are drawn from ---- */
  memcpy(s->xi0, s->kt0 + 32, 32);
  memcpy(s->xi1, s->kt1 + 32, 32);
  s->xi0[32] = 1;
  jl = 2 * (4 * (size_t)p->wr + 8) + 4 * (size_t)p->we + 8;
  nqmkec(s->xs0, s->xs1, jl, s->xi0, s->xi1, 33, 32, 136, 0x1f, g);
  x.s0 = s->xs0;
  x.s1 = s->xs1;
  x.pos = 0;
  acc[0] = 0;
  acc[1] = 0;
  /* ---- u' = r1 + r2 h, against c's u ---- */
  mdraw(p, &x, s, s->p0, s->p1, p->wr, g);  /* r2 */
  nqhqpubh(p, s->w, ek);
  nqhqmul(p, s->a0, s->p0, s->w);
  nqhqmul(p, s->a1, s->p1, s->w);
  mdraw(p, &x, s, s->b0, s->b1, p->we, g);  /* e, kept in b */
  {
    /* r1 drawn into w's place would lose h; draw it into a spare pair */
    uint64_t q0[NQHQNW], q1[NQHQNW];
    mdraw(p, &x, s, q0, q1, p->wr, g);      /* r1 */
    for (i = 0; i < p->nw; i++) {
      s->a0[i] = op64(s->a0[i] ^ q0[i]);
      s->a1[i] = op64(s->a1[i] ^ q1[i]);
    }
    b2w(s->w, p->nw, ct, p->nb);
    macc(acc, s->a0, s->a1, s->w, p->nw, g);
    /* ---- v' = code(m') + Truncate(r2 s + e), against c's v ---- */
    b2w(s->w, p->nw, ek + 32, p->nb);
    nqhqmul(p, q0, s->p0, s->w);
    nqhqmul(p, q1, s->p1, s->w);
    nqhqrse(p, s->rw0, s->m0);
    nqhqrse(p, s->rw1, s->m1);
    nqhqrme(p, s->a0, s->rw0);
    nqhqrme(p, s->a1, s->rw1);
    for (i = 0; i < p->vw; i++) {
      s->a0[i] = op64(s->a0[i] ^ q0[i] ^ s->b0[i]);
      s->a1[i] = op64(s->a1[i] ^ q1[i] ^ s->b1[i]);
    }
    nqwipe(q0, sizeof q0);
    nqwipe(q1, sizeof q1);
  }
  b2w(s->w, p->vw, ct + p->nb, p->vb);
  macc(acc, s->a0, s->a1, s->w, p->vw, g);
  {
    /* keep: all ones when nothing differed */
    mw lo, hi;
    lo[0] = (uint32_t)acc[0];
    lo[1] = (uint32_t)acc[1];
    hi[0] = (uint32_t)(acc[0] >> 32);
    hi[1] = (uint32_t)(acc[1] >> 32);
    mor(lo, lo, hi, g);
    mz(keep, lo, 32, g);
  }
  /* ---- K-bar = J(H(ek) || sigma || c || 3) ---- */
  memcpy(jin, hek, 32);
  memcpy(jin + 32 + p->k, ct, p->ct);
  jin[32 + p->k + p->ct] = 3;
  nqmkec(s->kb0, s->kb1, 32, jin, s->ji1, 32 + p->k + p->ct + 1,
         32 + p->k, 136, 0x06, g);
  /* ---- K = keep ? K' : K-bar, then unmasked ---- */
  for (i = 0; i < NQHQSS; i++) {
    mw a, b, z;
    a[0] = s->kt0[i];
    a[1] = s->kt1[i];
    b[0] = s->kb0[i];
    b[1] = s->kb1[i];
    mmux(z, keep, a, b, g);
    ss[i] = (uint8_t)(z[0] ^ z[1]);
    NQLKST(10);
    NQLK(ss[i], NQLKOUT);
    NQLKST(2);
  }
  nqwipe(hek, sizeof hek);
  nqwipe(jin, sizeof jin);
  nqwipe(g, sizeof *g);
  nqwipe(s, sizeof *s);
  nqwipe(acc, sizeof acc);
  nqwipe(keep, sizeof keep);
  return rc;
}
