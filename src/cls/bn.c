/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Fixed-size bignums and Montgomery multiplication (CIOS, 32-bit limbs,
 * 64-bit products: plain C11, no compiler extensions). */
#include <string.h>

#include "cls/bn.h"
#include "core/int.h"

/* r = mask ? a : r, limb by limb */
static void csel(uint32_t *r, const uint32_t *a, uint32_t mask, size_t nl) {
  size_t i;
  for (i = 0; i < nl; i++) {
    r[i] = nqctsel(mask, a[i], r[i]);
  }
}

void nqcld(uint32_t *a, size_t nl, const uint8_t *b, size_t blen) {
  size_t i;
  memset(a, 0, nl * sizeof *a);
  for (i = 0; i < blen && i / 4 < nl; i++) {
    a[i / 4] |= (uint32_t)b[blen - 1 - i] << (8 * (i % 4));
  }
}

void nqcst(uint8_t *b, size_t blen, const uint32_t *a, size_t nl) {
  size_t i;
  for (i = 0; i < blen; i++) {
    b[blen - 1 - i] =
        i / 4 < nl ? (uint8_t)(a[i / 4] >> (8 * (i % 4))) : (uint8_t)0;
  }
}

uint32_t nqcsb(uint32_t *r, const uint32_t *a, const uint32_t *b,
               size_t nl) {
  uint32_t br = 0;
  size_t i;
  for (i = 0; i < nl; i++) {
    uint64_t d = (uint64_t)a[i] - b[i] - br;
    r[i] = (uint32_t)d;
    br = (uint32_t)(d >> 63);
  }
  return br;
}

uint32_t nqclt(const uint32_t *a, const uint32_t *b, size_t nl) {
  uint32_t br = 0;
  size_t i;
  for (i = 0; i < nl; i++) {
    uint64_t d = (uint64_t)a[i] - b[i] - br;
    br = (uint32_t)(d >> 63);
  }
  return br;
}

uint32_t nqcz(const uint32_t *a, size_t nl) {
  uint32_t x = 0;
  size_t i;
  for (i = 0; i < nl; i++) {
    x |= a[i];
  }
  return 1u & ~(nqctmask(x));
}

uint32_t nqceq(const uint32_t *a, const uint32_t *b, size_t nl) {
  uint32_t x = 0;
  size_t i;
  for (i = 0; i < nl; i++) {
    x |= a[i] ^ b[i];
  }
  return 1u & ~(nqctmask(x));
}

void nqcmset(nqcmod *m, const uint32_t *v, size_t nl) {
  uint32_t x, t[NQBL], c;
  size_t i, j;
  memset(m, 0, sizeof *m);
  memcpy(m->m, v, nl * sizeof *v);
  m->nl = nl;
  /* Newton: x = m0^-1 mod 2^32; m0 * m0 = 1 mod 8 for odd m0 */
  x = v[0];
  for (i = 0; i < 4; i++) {
    x *= 2u - v[0] * x;
  }
  m->mi = 0u - x;
  /* R^2 mod m by doubling 1, 64 nl times */
  memset(m->r2, 0, sizeof m->r2);
  m->r2[0] = 1;
  for (i = 0; i < 64 * nl; i++) {
    c = m->r2[nl - 1] >> 31;
    for (j = nl - 1; j > 0; j--) {
      m->r2[j] = (m->r2[j] << 1) | (m->r2[j - 1] >> 31);
    }
    m->r2[0] <<= 1;
    c |= nqcsb(t, m->r2, m->m, nl) ^ 1u;
    csel(m->r2, t, nqctmask(c), nl);
  }
}

void nqcmm(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m) {
  uint32_t t[NQBL + 2], d[NQBL], q, br;
  uint64_t s, c;
  size_t i, j, nl = m->nl;
  memset(t, 0, (nl + 2) * sizeof *t);
  for (i = 0; i < nl; i++) {
    c = 0;
    for (j = 0; j < nl; j++) {
      s = (uint64_t)a[j] * b[i] + t[j] + c;
      t[j] = (uint32_t)s;
      c = s >> 32;
    }
    s = (uint64_t)t[nl] + c;
    t[nl] = (uint32_t)s;
    t[nl + 1] = (uint32_t)(s >> 32);
    q = t[0] * m->mi;
    s = (uint64_t)q * m->m[0] + t[0];
    c = s >> 32;
    for (j = 1; j < nl; j++) {
      s = (uint64_t)q * m->m[j] + t[j] + c;
      t[j - 1] = (uint32_t)s;
      c = s >> 32;
    }
    s = (uint64_t)t[nl] + c;
    t[nl - 1] = (uint32_t)s;
    t[nl] = t[nl + 1] + (uint32_t)(s >> 32);
  }
  /* t < 2m: subtract m once if t >= m */
  br = nqcsb(d, t, m->m, nl);
  csel(t, d, nqctmask(t[nl] | (br ^ 1u)), nl);
  memcpy(r, t, nl * sizeof *r);
}

void nqcad(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m) {
  uint32_t s[NQBL], d[NQBL], c = 0, br;
  size_t i, nl = m->nl;
  for (i = 0; i < nl; i++) {
    uint64_t x = (uint64_t)a[i] + b[i] + c;
    s[i] = (uint32_t)x;
    c = (uint32_t)(x >> 32);
  }
  br = nqcsb(d, s, m->m, nl);
  csel(s, d, nqctmask(c | (br ^ 1u)), nl);
  memcpy(r, s, nl * sizeof *r);
}

void nqcsu(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m) {
  uint32_t d[NQBL], mk, c = 0;
  size_t i, nl = m->nl;
  mk = nqctmask(nqcsb(d, a, b, nl));
  for (i = 0; i < nl; i++) {
    uint64_t x = (uint64_t)d[i] + (m->m[i] & mk) + c;
    d[i] = (uint32_t)x;
    c = (uint32_t)(x >> 32);
  }
  memcpy(r, d, nl * sizeof *r);
}

void nqcto(uint32_t *r, const uint32_t *a, const nqcmod *m) {
  nqcmm(r, a, m->r2, m);
}

void nqcfr(uint32_t *r, const uint32_t *a, const nqcmod *m) {
  uint32_t one[NQBL];
  memset(one, 0, m->nl * sizeof *one);
  one[0] = 1;
  nqcmm(r, a, one, m);
}

void nqcpw(uint32_t *r, const uint32_t *a, const uint32_t *e, size_t el,
           const nqcmod *m) {
  uint32_t x[NQBL], one[NQBL];
  size_t i, top = 0;
  memset(one, 0, m->nl * sizeof *one);
  one[0] = 1;
  nqcto(x, one, m); /* R mod m: 1 in the Montgomery domain */
  for (i = 0; i < 32 * el; i++) {
    if ((e[i / 32] >> (i % 32)) & 1u) top = i + 1;
  }
  for (i = top; i-- > 0;) {
    nqcmm(x, x, x, m);
    if ((e[i / 32] >> (i % 32)) & 1u) nqcmm(x, x, a, m);
  }
  memcpy(r, x, m->nl * sizeof *r);
}
