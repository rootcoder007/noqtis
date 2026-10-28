/* Internal helpers shared by the modules; not part of the public API. */
#ifndef NQINT_H
#define NQINT_H

#include <stddef.h>
#include <stdint.h>

void *nqmal(size_t size);
/* Wipes, then frees; size is the size passed to nqmal. */
void nqfree(void *ptr, size_t size);

/* ---- constant-time selection on secret values ---- */

/* All ones when x != 0, all zeros otherwise. */
static inline uint32_t nqctmask(uint32_t x) {
  return (uint32_t)0 - ((x | ((uint32_t)0 - x)) >> 31);
}

/* a when mask is all ones, b when it is all zeros. */
static inline uint32_t nqctsel(uint32_t mask, uint32_t a, uint32_t b) {
  return b ^ (mask & (a ^ b));
}

/* Copies src over dst when cond is 1, leaves dst when 0; cond is 0 or 1. */
static inline void nqcmov(uint8_t *dst, const uint8_t *src, size_t len,
                          uint8_t cond) {
  uint8_t m = (uint8_t)(0u - (unsigned int)cond);
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

#endif /* NQINT_H */
