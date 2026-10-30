/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-KEM internals shared by kem.c and mdec.c: parameters, the ring
 * Z_q[X]/(X^256 + 1) with q = 3329, its incomplete NTT, encodings,
 * compression and sampling. Not an API. */
#ifndef NQMKRING_H
#define NQMKRING_H

#include <stddef.h>
#include <stdint.h>

#define NQMKQ 3329
#define NQMKKX 4 /* the largest rank */

/* ctgrind (tests/tmlkemct.c): a value FIPS 203 publishes anyway (rho, the
 * encapsulation key inside dk) is declared defined before code branches
 * on it. A no-op otherwise. */
#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQMKPUB(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define NQMKPUB(p, n) ((void)0)
#endif

typedef struct {
  int k, eta1, du, dv;
  size_t ek, dk, ct;
} nqmkprm;

typedef struct {
  int16_t c[256];
} nqmkpoly;

/* NQOK, or NQEARG when k is not 2, 3 or 4. */
int nqmkpar(int k, nqmkprm *p);

/* a * 2^-16 mod q, for |a| < 2^15 q; result in (-q, q). */
static inline int16_t nqmkmr(int32_t a) {
  const int16_t t =
      (int16_t)(uint16_t)((uint32_t)(uint16_t)a * 62209u);
  return (int16_t)((a - (int32_t)t * NQMKQ) >> 16);
}

/* a mod q, centred. */
static inline int16_t nqmkbr(int16_t a) {
  const int32_t v = ((1 << 26) + NQMKQ / 2) / NQMKQ;
  const int32_t t = (v * a + (1 << 25)) >> 26;
  return (int16_t)(a - t * NQMKQ);
}

/* a in (-q, q) to [0, q). */
static inline int16_t nqmkps(int16_t a) {
  return (int16_t)(a + ((a >> 15) & NQMKQ));
}

/* floor(n / q) for 0 <= n < 2^23 by multiply and shift: a written
 * division compiles to a hardware divide at -O0, whose time depends on
 * the operand (KyberSlash). */
static inline uint32_t nqmkdq(uint32_t n) {
  return (uint32_t)(((uint64_t)n * 10321340u) >> 35);
}
static inline uint32_t nqmkmq(uint32_t n) {
  return n - 3329u * nqmkdq(n);
}

/* Compress_d of any int16 (reduced first), and Decompress_d. */
static inline uint16_t nqmkcp(int16_t x, int d) {
  uint32_t t = (uint32_t)nqmkps(nqmkbr(x));
  t = nqmkdq((t << d) + NQMKQ / 2) & ((1u << d) - 1u);
  return (uint16_t)t;
}
static inline int16_t nqmkdc(uint16_t x, int d) {
  return (int16_t)(((uint32_t)x * NQMKQ + (1u << (d - 1))) >> d);
}

void nqmkntt(nqmkpoly *r);
void nqmkint(nqmkpoly *r);
/* r = sum_i a[i] * b[i] in the NTT domain (times 2^-16), reduced. */
void nqmkdot(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b, int k);
void nqmkadd(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b);
void nqmksub(nqmkpoly *r, const nqmkpoly *a, const nqmkpoly *b);
/* every coefficient to [0, q) */
void nqmkcan(nqmkpoly *a);

/* ByteEncode_d of the low d bits of each coefficient, and ByteDecode_d
 * (raw d-bit values, not reduced). */
void nqmkbe(uint8_t *out, const nqmkpoly *a, int d);
void nqmkbd(nqmkpoly *a, const uint8_t *in, int d);

/* A-hat (tr 0) or its transpose (tr 1) from rho, row by row:
 * m[i * NQMKKX + j]. */
void nqmkmat(nqmkpoly *m, const uint8_t rho[32], int k, int tr);

/* SamplePolyCBD_eta(PRF_eta(s, n)). */
void nqmkprf(nqmkpoly *a, const uint8_t s[32], uint8_t n, int eta);

/* t-hat from ek; 1 when a coefficient is >= q (modulus check fails). */
int nqmkekd(nqmkpoly *t, const uint8_t *ek, int k);

/* K-PKE.Encrypt(ek, m, r) into ct; 1 (and ct unspecified) when ek fails
 * the modulus check. */
int nqmkpke(const nqmkprm *p, uint8_t *ct, const uint8_t *ek,
            const uint8_t m[32], const uint8_t r[32]);

/* An opaque copy: the compiler cannot see through it, so a 0 / all-ones
 * mask stays arithmetic rather than becoming a branch. */
uint32_t nqmkop(uint32_t x);

#endif /* NQMKRING_H */
