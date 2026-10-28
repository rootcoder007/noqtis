/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC internals shared by the files of the module (and its tests). */
#ifndef NQHQI_H
#define NQHQI_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* bounds over the three parameter sets (HQC-256 is the largest) */
#define NQHQNW 901   /* 64-bit words of a vector of length n */
#define NQHQNB 7205  /* bytes of a vector of length n */
#define NQHQN1 90    /* Reed-Solomon length */
#define NQHQK 32     /* message bytes */
#define NQHQD 29     /* Reed-Solomon correcting capacity */
#define NQHQWM 149   /* the largest of w, we, wr */
#define NQHQCTM 14421

typedef struct {
  uint32_t n;      /* ambient length, a prime */
  uint32_t n1;     /* Reed-Solomon length */
  uint32_t n2;     /* duplicated Reed-Muller length */
  uint32_t w;      /* weight of x and y */
  uint32_t we;     /* weight of e */
  uint32_t wr;     /* weight of r1 and r2 */
  uint32_t k;      /* message bytes, the RS dimension */
  uint32_t dl;     /* RS correcting capacity delta */
  uint32_t mu;     /* floor(2^32 / n), for Barrett */
  uint32_t thr;    /* rejection threshold of the 24-bit samples */
  size_t nw;       /* words of a vector of length n */
  size_t nb;       /* bytes of a vector of length n */
  size_t vw;       /* words of v (n1 n2 bits, whole words) */
  size_t vb;       /* bytes of v */
  size_t pk, sk, ct;
  uint64_t top;    /* the valid bits of the last word */
} nqhqp;

/* the parameters of alg; NULL when alg is not an HQC set */
const nqhqp *nqhqpar(nqkalg alg);

/* Tells a constant-time checker that a secret-derived value may be
 * public. Used only where the specification accepts it: the rejection
 * test of the key-generation sampler, the fact that a draw repeated an
 * earlier position, and the validity of a secret key. */
#ifndef NQHQDCL
#define NQHQDCL(ptr, len) ((void)(ptr), (void)(len))
#endif

/* o = a * b mod (x^n - 1); o may be a or b. Constant time. */
void nqhqmul(const nqhqp *p, uint64_t *o, const uint64_t *a,
             const uint64_t *b);

/* Reed-Solomon over GF(256): k message bytes to n1 codeword bytes, and
 * back, correcting up to dl byte errors. */
void nqhqrse(const nqhqp *p, uint8_t *cw, const uint8_t *msg);
void nqhqrsd(const nqhqp *p, uint8_t *msg, const uint8_t *cw);

/* duplicated Reed-Muller RM(1,7): n1 bytes to vw words, and back */
void nqhqrme(const nqhqp *p, uint64_t *cw, const uint8_t *msg);
void nqhqrmd(const nqhqp *p, uint8_t *msg, const uint64_t *cw);

#endif /* NQHQI_H */
