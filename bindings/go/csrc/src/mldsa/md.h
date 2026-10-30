/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA internals shared by the files of src/mldsa: the parameter sets,
 * the ring Z_q[X]/(X^256 + 1) with q = 8380417, its NTT, sampling,
 * rounding and the bit packings of FIPS 204. Not part of any API. */
#ifndef NQMD_H
#define NQMD_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQMDQ 8380417
#define NQMDN 256
#define NQMDK 8          /* the largest k */
#define NQMDL 7          /* the largest l */
#define NQMDTRIES 1024   /* signing gives up after this many attempts */

/* Values the standard publishes (rho, c~, hints, a rejection decision)
 * are declared public to valgrind in the constant-time check (NQCTGRIND);
 * a no-op otherwise. */
#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQMDPUB(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define NQMDPUB(p, n) ((void)(p), (void)(n))
#endif

typedef struct {
  int alg;
  unsigned k, l;
  unsigned eta;
  unsigned tau;
  int32_t beta;
  int32_t g1;      /* gamma1 */
  int32_t g2;      /* gamma2 */
  unsigned omega;
  unsigned ctl;    /* bytes of c~: lambda / 4 */
  unsigned etab;   /* bits per packed s1 / s2 coefficient: 3 or 4 */
  unsigned zb;     /* bits per packed z coefficient: 18 or 20 */
  unsigned w1b;    /* bits per packed w1 coefficient: 6 or 4 */
  size_t pk, sk, sig;
} nqmdp;

typedef struct {
  int32_t c[NQMDN];
} nqmdpl;

/* the parameter set of alg, or NULL */
const nqmdp *nqmdpar(int alg);

/* ---- arithmetic ---- */

/* a * 2^-32 mod q, in (-q, q), for |a| < 2^31 q */
static inline int32_t nqmdmr(int64_t a) {
  int32_t t = (int32_t)(uint32_t)((uint32_t)(uint64_t)a * 58728449u);
  return (int32_t)((a - (int64_t)t * NQMDQ) >> 32);
}

/* congruent to a, |r| <= 6283008, for a <= 2^31 - 2^22 - 1 */
static inline int32_t nqmdrd(int32_t a) {
  int32_t t = (a + (1 << 22)) >> 23;
  return a - t * NQMDQ;
}

/* a + q when a < 0 */
static inline int32_t nqmdcq(int32_t a) {
  return a + ((a >> 31) & NQMDQ);
}

void nqmdntt(int32_t a[NQMDN]);
/* inverse NTT, output times 2^32 (Montgomery form) */
void nqmdint(int32_t a[NQMDN]);
/* c = a * b * 2^-32, coefficient-wise */
void nqmdpw(int32_t c[NQMDN], const int32_t a[NQMDN],
            const int32_t b[NQMDN]);
/* c += a * b * 2^-32 */
void nqmdpwa(int32_t c[NQMDN], const int32_t a[NQMDN],
             const int32_t b[NQMDN]);
void nqmdred(int32_t a[NQMDN]);
void nqmdcadd(int32_t a[NQMDN]);

/* ---- sampling ---- */

/* RejNTTPoly: A[i][j] from rho, nonce = 256 i + j */
void nqmdunif(int32_t a[NQMDN], const uint8_t rho[32], uint16_t nonce);
/* RejBoundedPoly: s1 / s2 from rho' */
void nqmdeta(const nqmdp *p, int32_t a[NQMDN], const uint8_t seed[64],
             uint16_t nonce);
/* ExpandMask, one polynomial */
void nqmdmask(const nqmdp *p, int32_t a[NQMDN], const uint8_t seed[64],
              uint16_t nonce);
/* SampleInBall from c~ */
void nqmdchal(const nqmdp *p, int32_t c[NQMDN], const uint8_t *ct);

/* ---- rounding ---- */

/* Decompose: returns r1, writes r0, for a in [0, q) */
int32_t nqmddec(const nqmdp *p, int32_t *a0, int32_t a);
/* the hint bit for low part a0 and high part a1 (0 or 1) */
uint32_t nqmdmkh(const nqmdp *p, int32_t a0, int32_t a1);
/* UseHint, for a in [0, q) */
int32_t nqmduse(const nqmdp *p, int32_t a, uint32_t h);
/* nonzero when some coefficient has |a| >= b (b <= (q - 1) / 8); every
 * coefficient is read, the result is not declassified */
uint32_t nqmdchk(const int32_t a[NQMDN], int32_t b);

/* ---- packing ---- */

/* n bits per coefficient, 32 n bytes, little-endian bit order */
void nqmdbpk(uint8_t *r, const uint32_t v[NQMDN], unsigned n);
void nqmdbun(uint32_t v[NQMDN], const uint8_t *a, unsigned n);
void nqmdt1p(uint8_t *r, const int32_t a[NQMDN]);
void nqmdt1u(int32_t a[NQMDN], const uint8_t *r);
void nqmdt0p(uint8_t *r, const int32_t a[NQMDN]);
void nqmdt0u(int32_t a[NQMDN], const uint8_t *r);
void nqmdetp(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]);
void nqmdetu(const nqmdp *p, int32_t a[NQMDN], const uint8_t *r);
void nqmdzp(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]);
void nqmdzu(const nqmdp *p, int32_t a[NQMDN], const uint8_t *r);
void nqmdw1p(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]);

/* ---- the matrix ---- */

/* w[i] = sum_j A[i][j] v[j] (NTT domain, Montgomery), A from rho, and the
 * same for a second vector pair when w1 is not NULL; A is sampled one
 * entry at a time, never stored */
void nqmdmat(const nqmdp *p, const uint8_t rho[32], nqmdpl *w0,
             const nqmdpl *v0, nqmdpl *w1, const nqmdpl *v1);

/* ---- signing cores (mu already computed) ---- */

/* Each returns NQOK, NQEDEC (a malformed secret key, or no attempt
 * accepted) or NQERNG, and writes p->sig bytes on success. */
int nqmdspl(const nqmdp *p, const uint8_t *sk, const uint8_t mu[64],
            const uint8_t rnd[32], uint8_t *sig);
int nqmdsmk(const nqmdp *p, const uint8_t *sk, const uint8_t mu[64],
            const uint8_t rnd[32], uint8_t *sig);
/* rho, K, s1, s2 and t0 from sk (rho declassified); 1 when s1 or s2
 * leaves [-eta, eta] */
int nqmdsku(const nqmdp *p, const uint8_t *sk, uint8_t *rho, uint8_t *key,
            nqmdpl *s1, nqmdpl *s2, nqmdpl *t0);
/* hint encoding of h (k * 256 values 0 / 1, public) into the last
 * omega + k bytes of a signature */
void nqmdhpk(const nqmdp *p, uint8_t *r, const uint8_t *h);

#endif /* NQMD_H */
