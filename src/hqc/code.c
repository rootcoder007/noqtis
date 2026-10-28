/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The codes of HQC: a shortened Reed-Solomon code over GF(256) (field
 * polynomial x^8 + x^4 + x^3 + x^2 + 1) concatenated with a duplicated
 * Reed-Muller code RM(1,7).
 *
 * Every operation on a codeword is constant time: field products use no
 * tables (multiply with holes), Berlekamp's algorithm, the error values
 * and the Reed-Muller peak search keep their state with masks, and tables
 * are only ever indexed by public counters. The roots of the error
 * locator are found by evaluating it at the n1 points that can be error
 * positions (the reference evaluates it at all 256 field elements with an
 * additive FFT; the values at those points are the same). */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "hqc/hqci.h"

/* an opaque copy, so a compiler cannot turn a mask back into a branch */
static uint32_t cbar(uint32_t x) {
  volatile uint32_t y = x;
  return y;
}

/* all ones when x == 0 */
static uint32_t cz(uint32_t x) {
  return ~nqctmask(x);
}

/* ---- GF(256) ---- */

/* a * b, carry-less with holes then two folds of x^8 = x^4+x^3+x^2+1 */
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

/* a^254 = a^-1, and 0 for 0 */
static uint32_t ginv(uint32_t a) {
  uint32_t a2 = gm(a, a), a3 = gm(a2, a), a4 = gm(a2, a2);
  uint32_t a7 = gm(a4, a3), a11 = gm(a4, a7), a15 = gm(a11, a4);
  uint32_t t = gm(a15, a15);
  t = gm(t, t);
  t = gm(t, t); /* a^120 */
  t = gm(t, a7); /* a^127 */
  return gm(t, t);
}

/* e[i] = alpha^i for i < 255 (public) */
static void gexp(uint32_t e[255]) {
  uint32_t x = 1;
  int i;
  for (i = 0; i < 255; i++) {
    e[i] = x;
    x <<= 1;
    x ^= 0x11Du & (0u - (x >> 8));
  }
}

/* ---- Reed-Solomon ---- */

/* the generator polynomial, prod_{i=1}^{2 dl} (x - alpha^i) */
static void rsgen(const nqhqp *p, uint32_t *g) {
  uint32_t e[255];
  uint32_t i, j, deg = 0;
  gexp(e);
  g[0] = 1;
  for (i = 1; i <= 2 * p->dl; i++) {
    for (j = deg; j > 0; j--) {
      g[j] = gm(g[j], e[i]) ^ g[j - 1];
    }
    g[0] = gm(g[0], e[i]);
    g[++deg] = 1;
  }
}

void nqhqrse(const nqhqp *p, uint8_t *cw, const uint8_t *msg) {
  uint32_t g[2 * NQHQD + 1], tmp[2 * NQHQD + 1];
  uint8_t b[NQHQN1];
  size_t r = p->n1 - p->k, i, j;
  rsgen(p, g);
  memset(b, 0, sizeof b);
  for (i = 0; i < p->k; i++) {
    uint32_t gate = (uint32_t)(msg[p->k - 1 - i] ^ b[r - 1]);
    for (j = 0; j <= r; j++) {
      tmp[j] = gm(gate, g[j]);
    }
    for (j = r - 1; j > 0; j--) {
      b[j] = (uint8_t)(b[j - 1] ^ tmp[j]);
    }
    b[0] = (uint8_t)tmp[0];
  }
  memcpy(b + r, msg, p->k);
  memcpy(cw, b, p->n1);
  nqwipe(b, sizeof b);
  nqwipe(tmp, sizeof tmp);
}

/* s[i] = c(alpha^(i+1)), i < 2 dl */
static void rssyn(const nqhqp *p, uint32_t *s, const uint32_t *c,
                  const uint32_t *e) {
  size_t i, j;
  for (i = 0; i < 2 * p->dl; i++) {
    uint32_t acc = c[0];
    for (j = 1; j < p->n1; j++) {
      acc ^= gm(c[j], e[((i + 1) * j) % 255]);
    }
    s[i] = acc;
  }
}

/* Berlekamp's error-locator polynomial sg (dl + 1 coefficients), as the
 * reference's simplified algorithm; returns its degree */
static uint32_t rselp(const nqhqp *p, uint32_t *sg, const uint32_t *syn) {
  const uint32_t dl = p->dl;
  uint32_t dsg = 0, dsgp = 0, dsgc, mu, i;
  uint32_t sgc[NQHQD + 1], xsp[NQHQD + 1];
  uint32_t pp = 0xFFFFu, dp = 1, d = syn[0];
  for (i = 0; i <= dl; i++) {
    sgc[i] = 0;
    xsp[i] = 0;
    sg[i] = 0;
  }
  xsp[1] = 1;
  sg[0] = 1;
  for (mu = 0; mu < 2 * dl; mu++) {
    uint32_t dd, dx, dxsp, m1, m2, m12;
    for (i = 0; i < dl; i++) {
      sgc[i] = sg[i];
    }
    dsgc = dsg;
    dd = gm(d, ginv(dp));
    for (i = 1; i <= mu + 1 && i <= dl; i++) {
      sg[i] ^= gm(dd, xsp[i]);
    }
    dx = (mu - pp) & 0xFFFFu;
    dxsp = (dx + dsgp) & 0xFFFFu;
    m1 = nqctmask(d);
    m2 = 0u - ((dsg - dxsp) >> 31); /* dsg < dxsp */
    m12 = cbar(m1 & m2);
    dsg ^= m12 & (dxsp ^ dsg);
    if (mu == 2 * dl - 1) {
      break;
    }
    pp ^= m12 & (mu ^ pp);
    dp ^= m12 & (d ^ dp);
    for (i = dl; i > 0; i--) {
      xsp[i] = (m12 & sgc[i - 1]) ^ (~m12 & xsp[i - 1]);
    }
    dsgp ^= m12 & (dsgc ^ dsgp);
    d = syn[mu + 1];
    for (i = 1; i <= mu + 1 && i <= dl; i++) {
      d ^= gm(sg[i], syn[mu + 1 - i]);
    }
  }
  nqwipe(sgc, sizeof sgc);
  nqwipe(xsp, sizeof xsp);
  return dsg;
}

/* er[j] = 1 when alpha^-j is a root of sg, j < n1 */
static void rsroot(const nqhqp *p, uint8_t *er, const uint32_t *sg,
                   const uint32_t *e) {
  size_t j, t;
  for (j = 0; j < p->n1; j++) {
    uint32_t x = e[(255 - j) % 255], v = sg[p->dl];
    for (t = p->dl; t-- > 0;) {
      v = gm(v, x) ^ sg[t];
    }
    er[j] = (uint8_t)(cz(v) & 1u);
  }
}

/* the error evaluator z (dl + 1 coefficients) */
static void rsz(const nqhqp *p, uint32_t *z, const uint32_t *sg,
                uint32_t deg, const uint32_t *syn) {
  uint32_t i, j;
  z[0] = 1;
  for (i = 1; i <= p->dl; i++) {
    uint32_t m = cbar(0u - ((i - deg - 1) >> 31)); /* i <= deg */
    z[i] = m & sg[i];
  }
  z[1] ^= syn[0];
  for (i = 2; i <= p->dl; i++) {
    uint32_t m = cbar(0u - ((i - deg - 1) >> 31));
    z[i] ^= m & syn[i - 1];
    for (j = 1; j < i; j++) {
      z[i] ^= m & gm(sg[j], syn[i - j - 1]);
    }
  }
}

/* the error values ev[i] at the positions er marks */
static void rsev(const nqhqp *p, uint32_t *ev, const uint32_t *z,
                 const uint8_t *er, const uint32_t *e) {
  const uint32_t dl = p->dl;
  uint32_t bj[NQHQD], ej[NQHQD];
  uint32_t cnt = 0, real, i, j, k;
  for (j = 0; j < dl; j++) {
    bj[j] = 0;
    ej[j] = 0;
  }
  for (i = 0; i < p->n1; i++) {
    uint32_t found = 0, m1 = cbar(0u - (uint32_t)er[i]);
    for (j = 0; j < dl; j++) {
      uint32_t m2 = cbar(cz(j ^ cnt));
      bj[j] += m1 & m2 & e[i];
      found += m1 & m2 & 1u;
    }
    cnt += found;
  }
  real = cnt;
  for (i = 0; i < dl; i++) {
    uint32_t t1 = 1, t2 = 1, inv = ginv(bj[i]), invp = 1, m1;
    for (j = 1; j <= dl; j++) {
      invp = gm(invp, inv);
      t1 ^= gm(invp, z[j]);
    }
    for (k = 1; k < dl; k++) {
      t2 = gm(t2, 1u ^ gm(inv, bj[(i + k) % dl]));
    }
    m1 = cbar(0u - ((i - real) >> 31)); /* i < real */
    ej[i] = m1 & gm(t1, ginv(t2));
  }
  cnt = 0;
  for (i = 0; i < p->n1; i++) {
    uint32_t found = 0, m1 = cbar(0u - (uint32_t)er[i]);
    ev[i] = 0;
    for (j = 0; j < dl; j++) {
      uint32_t m2 = cbar(cz(j ^ cnt));
      ev[i] += m1 & m2 & ej[j];
      found += m1 & m2 & 1u;
    }
    cnt += found;
  }
  nqwipe(bj, sizeof bj);
  nqwipe(ej, sizeof ej);
}

void nqhqrsd(const nqhqp *p, uint8_t *msg, const uint8_t *cw) {
  uint32_t e[255];
  uint32_t c[NQHQN1], ev[NQHQN1];
  uint32_t syn[2 * NQHQD], sg[NQHQD + 1], z[NQHQD + 1], deg;
  uint8_t er[NQHQN1], out[NQHQN1];
  size_t i;
  gexp(e);
  for (i = 0; i < p->n1; i++) {
    c[i] = cw[i];
  }
  rssyn(p, syn, c, e);
  deg = rselp(p, sg, syn);
  rsroot(p, er, sg, e);
  rsz(p, z, sg, deg, syn);
  rsev(p, ev, z, er, e);
  for (i = 0; i < p->n1; i++) {
    out[i] = (uint8_t)(c[i] ^ ev[i]);
  }
  memcpy(msg, out + 2 * p->dl, p->k);
  nqwipe(c, sizeof c);
  nqwipe(ev, sizeof ev);
  nqwipe(syn, sizeof syn);
  nqwipe(sg, sizeof sg);
  nqwipe(z, sizeof z);
  nqwipe(er, sizeof er);
  nqwipe(out, sizeof out);
  nqwipe(&deg, sizeof deg);
}

/* ---- Reed-Muller ---- */

/* the RM(1,7) codeword of one byte, two words */
static void rmbyte(uint64_t *w, uint32_t m) {
  uint32_t a, u0, u1, u2, u3;
  a = 0u - ((m >> 7) & 1u);
  a ^= (0u - (m & 1u)) & 0xaaaaaaaau;
  a ^= (0u - ((m >> 1) & 1u)) & 0xccccccccu;
  a ^= (0u - ((m >> 2) & 1u)) & 0xf0f0f0f0u;
  a ^= (0u - ((m >> 3) & 1u)) & 0xff00ff00u;
  a ^= (0u - ((m >> 4) & 1u)) & 0xffff0000u;
  u0 = a;
  a ^= 0u - ((m >> 5) & 1u);
  u1 = a;
  a ^= 0u - ((m >> 6) & 1u);
  u3 = a;
  a ^= 0u - ((m >> 5) & 1u);
  u2 = a;
  w[0] = (uint64_t)u0 | ((uint64_t)u1 << 32);
  w[1] = (uint64_t)u2 | ((uint64_t)u3 << 32);
}

/* byte i fills the copies i*mult .. i*mult + mult - 1 */
void nqhqrme(const nqhqp *p, uint64_t *cw, const uint8_t *msg) {
  size_t mult = p->n2 / 128, i, c;
  for (i = 0; i < p->n1; i++) {
    uint64_t w[2];
    rmbyte(w, msg[i]);
    for (c = 0; c < mult; c++) {
      size_t k = 2 * (i * mult + c);
      cw[k] = w[0];
      cw[k + 1] = w[1];
    }
    nqwipe(w, sizeof w);
  }
}

/* soft decoding: add the copies, Hadamard transform, take the peak */
void nqhqrmd(const nqhqp *p, uint8_t *msg, const uint64_t *cw) {
  size_t mult = p->n2 / 128, i, c;
  int32_t h[2][128];
  for (i = 0; i < p->n1; i++) {
    uint32_t bab = 0, bv = 0, bp = 0, q, pos;
    int cur = 0, pass, b;
    for (b = 0; b < 128; b++) {
      h[0][b] = 0;
    }
    for (c = 0; c < mult; c++) {
      size_t k = 2 * (i * mult + c);
      for (b = 0; b < 128; b++) {
        h[0][b] += (int32_t)((cw[k + (size_t)(b >> 6)] >> (b & 63)) & 1u);
      }
    }
    for (pass = 0; pass < 7; pass++) {
      const int32_t *s = h[cur];
      int32_t *d = h[cur ^ 1];
      for (q = 0; q < 64; q++) {
        d[q] = s[2 * q] + s[2 * q + 1];
        d[q + 64] = s[2 * q] - s[2 * q + 1];
      }
      cur ^= 1;
    }
    h[cur][0] -= 64 * (int32_t)mult;
    for (q = 0; q < 128; q++) {
      uint32_t v = (uint32_t)h[cur][q];
      uint32_t neg = 0u - (v >> 31);      /* v < 0 */
      uint32_t av = (v ^ neg) - neg;      /* |v| */
      uint32_t gt = cbar(0u - ((bab - av) >> 31)); /* av > bab */
      bv = (gt & v) | (~gt & bv);
      bp = (gt & q) | (~gt & bp);
      bab = (gt & av) | (~gt & bab);
    }
    pos = 0u - ((0u - bv) >> 31); /* bv > 0 as a signed value */
    msg[i] = (uint8_t)(bp | (pos & 128u));
    nqwipe(&bv, sizeof bv);
    nqwipe(&bp, sizeof bp);
    nqwipe(&bab, sizeof bab);
  }
  nqwipe(h, sizeof h);
}
