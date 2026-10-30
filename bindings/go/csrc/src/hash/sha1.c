/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SHA-1 (FIPS 180-4 section 6.1), verify-only: see hash/h.h. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

static uint32_t rol(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32 - n));
}

/* 6.1.2: one 64-byte block. */
static void blk(uint32_t h[5], const uint8_t *p) {
  uint32_t w[16], a, b, c, d, e, f, k, t;
  unsigned i;
  for (i = 0; i < 16; i++) {
    w[i] = nqld32b(p + 4 * i);
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
  for (i = 0; i < 80; i++) {
    if (i >= 16) {
      t = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
      w[i & 15] = rol(t, 1);
    }
    if (i < 20) {
      f = (b & c) ^ (~b & d);
      k = 0x5a827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1u;
    } else if (i < 60) {
      f = (b & c) ^ (b & d) ^ (c & d);
      k = 0x8f1bbcdcu;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6u;
    }
    t = rol(a, 5) + f + e + k + w[i & 15];
    e = d; d = c; c = rol(b, 30); b = a; a = t;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
  nqwipe(w, sizeof w);
}

void nqs1ini(nqs1ctx *c) {
  c->h[0] = 0x67452301u;
  c->h[1] = 0xefcdab89u;
  c->h[2] = 0x98badcfeu;
  c->h[3] = 0x10325476u;
  c->h[4] = 0xc3d2e1f0u;
  c->n = 0;
  c->pos = 0;
}

void nqs1upd(nqs1ctx *c, const uint8_t *in, size_t len) {
  if (len == 0) {
    return;
  }
  c->n += (uint64_t)len;
  if (c->pos > 0) {
    size_t take = 64 - c->pos;
    if (take > len) {
      take = len;
    }
    memcpy(c->buf + c->pos, in, take);
    c->pos += take;
    in += take;
    len -= take;
    if (c->pos < 64) {
      return;
    }
    blk(c->h, c->buf);
    c->pos = 0;
  }
  while (len >= 64) {
    blk(c->h, in);
    in += 64;
    len -= 64;
  }
  if (len > 0) {
    memcpy(c->buf, in, len);
    c->pos = len;
  }
}

void nqs1fin(nqs1ctx *c, uint8_t *out) {
  uint64_t bits = c->n * 8u;
  unsigned i;
  c->buf[c->pos++] = 0x80;
  if (c->pos > 56) {
    memset(c->buf + c->pos, 0, 64 - c->pos);
    blk(c->h, c->buf);
    c->pos = 0;
  }
  memset(c->buf + c->pos, 0, 56 - c->pos);
  nqst64b(c->buf + 56, bits);
  blk(c->h, c->buf);
  for (i = 0; i < 5; i++) {
    nqst32b(out + 4 * i, c->h[i]);
  }
  nqwipe(c, sizeof *c);
}

void nqs1(const uint8_t *in, size_t len, uint8_t out[20]) {
  nqs1ctx c;
  nqs1ini(&c);
  nqs1upd(&c, in, len);
  nqs1fin(&c, out);
}

int nqs1hk(void *user, const uint8_t *in, size_t len, uint8_t out[20]) {
  (void)user;
  if (out == NULL || (in == NULL && len > 0)) {
    return NQEARG;
  }
  nqs1(in, len, out);
  return NQOK;
}
