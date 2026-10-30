/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Fixed-size unsigned integers for the classical verifiers: little-endian
 * 32-bit limbs, at most NQBL of them (4096 bits), and Montgomery
 * arithmetic modulo an odd m. Every function runs in time that depends
 * only on the limb count, not on the values. Internal to src/cls. */
#ifndef NQBN_H
#define NQBN_H

#include <stddef.h>
#include <stdint.h>

#define NQBL 128 /* limbs: 4096 bits */

/* An odd modulus with its Montgomery constants; R = 2^(32 nl). */
typedef struct {
  uint32_t m[NQBL];
  uint32_t r2[NQBL]; /* R^2 mod m */
  uint32_t mi;       /* -m^-1 mod 2^32 */
  size_t nl;         /* limbs in use, 1..NQBL */
} nqcmod;

/* Sets up m from nl limbs v (odd, top limb nonzero or not). */
void nqcmset(nqcmod *m, const uint32_t *v, size_t nl);

/* Big-endian bytes to nl limbs (blen <= 4 nl), and back: nqcst writes
 * the low blen bytes of a. */
void nqcld(uint32_t *a, size_t nl, const uint8_t *b, size_t blen);
void nqcst(uint8_t *b, size_t blen, const uint32_t *a, size_t nl);

/* 1 when a < b, 0 otherwise; 1 when a is zero; 1 when a == b. */
uint32_t nqclt(const uint32_t *a, const uint32_t *b, size_t nl);
uint32_t nqcz(const uint32_t *a, size_t nl);
uint32_t nqceq(const uint32_t *a, const uint32_t *b, size_t nl);

/* r = a - b mod 2^(32 nl); returns the borrow. r may alias a or b. */
uint32_t nqcsb(uint32_t *r, const uint32_t *a, const uint32_t *b,
               size_t nl);

/* r = a b R^-1 mod m, for a < R and b < m (r < m). r may alias. */
void nqcmm(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m);
/* r = a + b and a - b mod m, for a, b < m. r may alias. */
void nqcad(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m);
void nqcsu(uint32_t *r, const uint32_t *a, const uint32_t *b,
           const nqcmod *m);
/* Into and out of the Montgomery domain (a < R for nqcto, a < m for
 * nqcfr). */
void nqcto(uint32_t *r, const uint32_t *a, const nqcmod *m);
void nqcfr(uint32_t *r, const uint32_t *a, const nqcmod *m);
/* r = a^e in the Montgomery domain (a and r Montgomery, a < m); e is a
 * public exponent of el limbs. Variable time in e only. */
void nqcpw(uint32_t *r, const uint32_t *a, const uint32_t *e, size_t el,
           const nqcmod *m);

#endif /* NQBN_H */
