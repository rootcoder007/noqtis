/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Multiplication in GF(2)[x]/(x^n - 1) for HQC.
 *
 * Karatsuba over 64-bit words down to a schoolbook of carry-less 64x64
 * products. The carry-less product is the constant-time "multiply with
 * holes": integer multiplies of operands masked to every fourth bit, so
 * at most 15 partial products meet at an output bit below 60 and no carry
 * reaches the next kept bit (BearSSL's method). The high half comes from
 * the bit-reversed operands. No table, branch or address depends on the
 * operands; the shape of the computation depends only on n.
 *
 * C11 has no templates and noqtis allows no recursion, so the Karatsuba
 * levels are separate functions, each splitting once and calling the
 * level below; eight levels take the largest operand (901 words) below
 * the schoolbook cut-off. */
#include <string.h>

#include "noqtis.h"
#include "hqc/hqci.h"

#define KCUT 8                      /* schoolbook at or below this */
#define KSCR (16 * NQHQNW + 256)    /* scratch words for every level */

/* low 64 bits of the carry-less product */
static uint64_t bm64(uint64_t x, uint64_t y) {
  const uint64_t m0 = 0x1111111111111111u, m1 = m0 << 1, m2 = m0 << 2,
                 m3 = m0 << 3;
  uint64_t x0 = x & m0, x1 = x & m1, x2 = x & m2, x3 = x & m3;
  uint64_t y0 = y & m0, y1 = y & m1, y2 = y & m2, y3 = y & m3;
  uint64_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
  uint64_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
  uint64_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
  uint64_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
  return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3);
}

static uint64_t rv64(uint64_t x) {
  x = ((x & 0x5555555555555555u) << 1) | ((x >> 1) & 0x5555555555555555u);
  x = ((x & 0x3333333333333333u) << 2) | ((x >> 2) & 0x3333333333333333u);
  x = ((x & 0x0F0F0F0F0F0F0F0Fu) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0Fu);
  x = ((x & 0x00FF00FF00FF00FFu) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFu);
  x = ((x & 0x0000FFFF0000FFFFu) << 16) |
      ((x >> 16) & 0x0000FFFF0000FFFFu);
  return (x << 32) | (x >> 32);
}

/* r (2n words) = a * b (n words each), schoolbook; t unused */
static void kb0(uint64_t *r, const uint64_t *a, const uint64_t *b,
                size_t n, uint64_t *t) {
  size_t i, j;
  (void)t;
  for (i = 0; i < 2 * n; i++) {
    r[i] = 0;
  }
  for (i = 0; i < n; i++) {
    uint64_t ra = rv64(a[i]);
    for (j = 0; j < n; j++) {
      r[i + j] ^= bm64(a[i], b[j]);
      r[i + j + 1] ^= rv64(bm64(ra, rv64(b[j]))) >> 1;
    }
  }
}

/* One Karatsuba level: t holds 8n words for this level, then the
 * scratch of the levels below. */
#define KLV(name, sub)                                                    \
  static void name(uint64_t *r, const uint64_t *a, const uint64_t *b,     \
                   size_t n, uint64_t *t) {                               \
    size_t m = n >> 1, n1 = n - m, i;                                     \
    uint64_t *z0 = t, *z2 = t + 2 * n, *zm = t + 4 * n;                   \
    uint64_t *ta = t + 6 * n, *tb = t + 7 * n, *ch = t + 8 * n;           \
    if (n <= KCUT) {                                                      \
      kb0(r, a, b, n, t);                                                 \
      return;                                                             \
    }                                                                     \
    sub(z0, a, b, m, ch);                                                 \
    sub(z2, a + m, b + m, n1, ch);                                        \
    for (i = 0; i < n1; i++) {                                            \
      ta[i] = (i < m ? a[i] : 0) ^ a[m + i];                              \
      tb[i] = (i < m ? b[i] : 0) ^ b[m + i];                              \
    }                                                                     \
    sub(zm, ta, tb, n1, ch);                                              \
    for (i = 0; i < 2 * n; i++) {                                         \
      r[i] = 0;                                                           \
    }                                                                     \
    for (i = 0; i < 2 * m; i++) {                                         \
      r[i] ^= z0[i];                                                      \
    }                                                                     \
    for (i = 0; i < 2 * n1; i++) {                                        \
      r[2 * m + i] ^= z2[i];                                              \
    }                                                                     \
    for (i = 0; i < 2 * n1; i++) {                                        \
      r[m + i] ^= zm[i] ^ (i < 2 * m ? z0[i] : 0) ^ z2[i];                \
    }                                                                     \
  }

KLV(kb1, kb0)
KLV(kb2, kb1)
KLV(kb3, kb2)
KLV(kb4, kb3)
KLV(kb5, kb4)
KLV(kb6, kb5)
KLV(kb7, kb6)
KLV(kb8, kb7)

void nqhqmul(const nqhqp *p, uint64_t *o, const uint64_t *a,
             const uint64_t *b) {
  uint64_t pr[2 * NQHQNW];
  uint64_t t[KSCR];
  size_t nw = p->nw, i;
  unsigned s = (unsigned)(p->n % 64); /* nonzero for every set */
  kb8(pr, a, b, nw, t);
  /* x^n = 1: bit n + j folds onto bit j */
  for (i = 0; i < nw; i++) {
    o[i] = pr[i] ^ (pr[i + nw - 1] >> s) ^ (pr[i + nw] << (64 - s));
  }
  o[nw - 1] &= p->top;
  nqwipe(pr, sizeof pr);
  nqwipe(t, sizeof t);
}
