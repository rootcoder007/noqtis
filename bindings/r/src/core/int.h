/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Internal helpers shared by the modules; not part of the public API. */
#ifndef NQINT_H
#define NQINT_H

#include <stddef.h>
#include <stdint.h>

void *nqmal(size_t size);

/* Progress for nqsetprog's hook (rand.c): a stage of total units begins,
 * n more are done, it ends. No-ops without a hook. */
void nqpbeg(int stage, uint64_t total);
void nqpstep(uint64_t n);
void nqpend(void);
/* 1 when nqsetstop's hook (rand.c) asks to stop; 0 without a hook. */
int nqstop(void);
/* Tells nqsettmp's hook (rand.c) of a temporary file: ev is NQTPRE,
 * NQTNEW, NQTNOT or NQTEND. A no-op without a hook. */
void nqtmpev(int ev, const char *path);
/* Wipes, then frees; size is the size passed to nqmal. */
void nqfree(void *ptr, size_t size);

/* ---- constant-time selection on secret values ---- */

/* A value barrier. A compiler that can prove a mask is 0 or all ones may
 * turn a masked select into a branch on it (clang did: the final
 * subtraction of nqcmm became `if (mask) copy`). Passing the mask through
 * a volatile read it cannot see through hides that, in plain C11. The
 * read costs one load per mask, not per word. */
static volatile uint32_t nqctz = 0;
static inline uint32_t nqctbar(uint32_t x) {
  return x ^ nqctz;
}

/* All ones when x != 0, all zeros otherwise. */
static inline uint32_t nqctmask(uint32_t x) {
  return nqctbar((uint32_t)0 - ((x | ((uint32_t)0 - x)) >> 31));
}

/* a when mask is all ones, b when it is all zeros. */
static inline uint32_t nqctsel(uint32_t mask, uint32_t a, uint32_t b) {
  return b ^ (mask & (a ^ b));
}

/* Copies src over dst when cond is 1, leaves dst when 0; cond is 0 or 1. */
static inline void nqcmov(uint8_t *dst, const uint8_t *src, size_t len,
                          uint8_t cond) {
  uint8_t m = (uint8_t)nqctbar((uint32_t)(0u - (unsigned int)cond));
  size_t i;
  for (i = 0; i < len; i++) {
    dst[i] = (uint8_t)(dst[i] ^ (m & (dst[i] ^ src[i])));
  }
}

/* ---- big- and little-endian loads and stores ---- */

static inline uint32_t nqld32b(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void nqst32b(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static inline uint64_t nqld64b(const uint8_t *p) {
  return ((uint64_t)nqld32b(p) << 32) | (uint64_t)nqld32b(p + 4);
}

static inline void nqst64b(uint8_t *p, uint64_t v) {
  nqst32b(p, (uint32_t)(v >> 32));
  nqst32b(p + 4, (uint32_t)v);
}

static inline uint32_t nqld32l(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static inline void nqst32l(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t nqld64l(const uint8_t *p) {
  uint64_t v = 0;
  int i;
  for (i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

static inline void nqst64l(uint8_t *p, uint64_t v) {
  int i;
  for (i = 0; i < 8; i++) {
    p[i] = (uint8_t)(v >> (8 * i));
  }
}

/* ---- releasing a signature after its checks ---- */

/* What a check that held leaves in its verdict word: one tag per check.
 * A verdict starts at 0 and gets its tag only from the check's result,
 * so a check that is skipped, or a word stuck at all zeros or all ones,
 * reads as failed. */
#define NQVTA 0x3a5c96e1u
#define NQVTB 0x9c1e4b27u
#define NQVTC 0x6b8d2f74u

/* tag when rc is NQOK, else 0, without a branch on rc */
static inline uint32_t nqvok(int rc, uint32_t tag) {
  return tag & ~nqctmask((uint32_t)rc);
}

/* tag when cond is 1, else 0; cond is 0 or 1 */
static inline uint32_t nqvif(int cond, uint32_t tag) {
  return tag & nqctbar((uint32_t)0 - ((uint32_t)cond & 1u));
}

/* Releases the n bytes at p only if every verdict v[j] holds its tag
 * t[j]: p is ANDed with a mask made from the verdicts, twice, each pass
 * reading them afresh (v is volatile), so that one skipped instruction
 * or pass does not release p. NQOK when all hold; otherwise NQEFLT,
 * with p zero. (core.c) */
int nqrel(uint8_t *p, size_t n, const volatile uint32_t *v, const uint32_t *t,
          size_t k);

/* Fault injection for the tests (tests/flt): a build with NQTEST reads
 * the bits of nqtflt where the signers check what they made. Without
 * NQTEST, NQFLT is 0 and the hooks are compiled out. */
#define NQFSIG 1u /* flip a bit of the signature before the checks */
#define NQFV1 2u  /* skip the first verdict */
#define NQFV2 4u  /* skip the second verdict */
#define NQFV3 8u  /* skip the key's own check */
#define NQFX1 16u /* skip the container's integrity value (api/sig.c) */
#define NQFX2 32u /* skip the container's public key check */
#ifdef NQTEST
extern unsigned nqtflt;
#define NQFLT(b) (nqtflt & (b))
#else
#define NQFLT(b) 0u
#endif

#endif /* NQINT_H */
