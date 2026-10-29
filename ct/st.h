/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Shared by the timing (dd.c) and simulated power (tv.c) harnesses:
 * Welch's t-test on running moments, a seeded generator for the inputs
 * and the class of each measurement, and a few output helpers. */
#ifndef NQST_H
#define NQST_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* |t| at or above this is a failure, as in dudect and TVLA */
#define NQTHR 4.5
/* stands in for an infinite t (two constant classes that differ), so
 * the JSON stays finite */
#define NQTINF 1e9

/* the running mean and sum of squared deviations of one class */
typedef struct {
  double n, m, s;
} wel;

static inline void welp(wel *w, double x) {
  double d;
  w->n += 1;
  d = x - w->m;
  w->m += d / w->n;
  w->s += d * (x - w->m);
}

/* Welch's t between two classes, from counts, sums and sums of squares
 * (used where the moments are kept as integers) */
static inline double welts(double n0, double s0, double q0, double n1,
                           double s1, double q1) {
  double m0, m1, v0, v1, d;
  if (n0 < 2 || n1 < 2) return 0;
  m0 = s0 / n0;
  m1 = s1 / n1;
  v0 = (q0 - s0 * m0) / (n0 - 1);
  v1 = (q1 - s1 * m1) / (n1 - 1);
  if (v0 < 0) v0 = 0;
  if (v1 < 0) v1 = 0;
  d = v0 / n0 + v1 / n1;
  if (d <= 0) return m0 == m1 ? 0 : (m0 > m1 ? NQTINF : -NQTINF);
  return (m0 - m1) / sqrt(d);
}

static inline double welt(const wel *a, const wel *b) {
  double va, vb, d;
  if (a->n < 2 || b->n < 2) return 0;
  va = a->s / (a->n - 1);
  vb = b->s / (b->n - 1);
  d = va / a->n + vb / b->n;
  if (d <= 0) return a->m == b->m ? 0 : (a->m > b->m ? NQTINF : -NQTINF);
  return (a->m - b->m) / sqrt(d);
}

/* xoshiro256** seeded by splitmix64: the harness's own inputs and class
 * choices, reproducible from one seed (never used for keys in use) */
typedef struct {
  uint64_t s[4];
} xr;

static inline uint64_t rol64(uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}

static inline void xrs(xr *g, uint64_t seed) {
  int i;
  for (i = 0; i < 4; i++) {
    uint64_t z = (seed += 0x9e3779b97f4a7c15u);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9u;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebu;
    g->s[i] = z ^ (z >> 31);
  }
}

static inline uint64_t xr64(xr *g) {
  uint64_t *s = g->s, r = rol64(s[1] * 5, 7) * 9, t = s[1] << 17;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rol64(s[3], 45);
  return r;
}

static inline void xrfill(xr *g, uint8_t *b, size_t n) {
  uint64_t v = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    if (i % 8 == 0) v = xr64(g);
    b[i] = (uint8_t)(v >> (8 * (i % 8)));
  }
}

static inline unsigned pop64(uint64_t x) {
  unsigned n = 0;
  while (x) {
    x &= x - 1;
    n++;
  }
  return n;
}

#endif /* NQST_H */
