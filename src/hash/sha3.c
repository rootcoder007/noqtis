/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Keccak-f[1600], SHA3-224/256/384/512 and SHAKE128/256 (FIPS 202). */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

/* iota round constants, FIPS 202 3.2.5 */
static const uint64_t rc[24] = {
    0x0000000000000001u, 0x0000000000008082u, 0x800000000000808au,
    0x8000000080008000u, 0x000000000000808bu, 0x0000000080000001u,
    0x8000000080008081u, 0x8000000000008009u, 0x000000000000008au,
    0x0000000000000088u, 0x0000000080008009u, 0x000000008000000au,
    0x000000008000808bu, 0x800000000000008bu, 0x8000000000008089u,
    0x8000000000008003u, 0x8000000000008002u, 0x8000000000000080u,
    0x000000000000800au, 0x800000008000000au, 0x8000000080008081u,
    0x8000000000008080u, 0x0000000080000001u, 0x8000000080008008u};

/* rho offsets and pi destinations, walked along the pi cycle that starts
 * at lane 1 (lane (x, y) is s[x + 5y]) */
static const unsigned rot[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                 45, 55, 2,  14, 27, 41, 56, 8,
                                 25, 43, 62, 18, 39, 61, 20, 44};
static const unsigned pil[24] = {10, 7,  11, 17, 18, 3, 5,  16,
                                 8,  21, 24, 4,  15, 23, 19, 13,
                                 12, 2,  20, 14, 22, 9, 6,  1};

static uint64_t rol(uint64_t x, unsigned n) {
  return (x << n) | (x >> (64 - n));
}

void nqkeccak(uint64_t s[25]) {
  uint64_t b[5], t, u;
  unsigned r, i, j;
  for (r = 0; r < 24; r++) {
    /* theta */
    for (i = 0; i < 5; i++) {
      b[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
    }
    for (i = 0; i < 5; i++) {
      t = b[(i + 4) % 5] ^ rol(b[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5) {
        s[i + j] ^= t;
      }
    }
    /* rho and pi */
    t = s[1];
    for (i = 0; i < 24; i++) {
      u = s[pil[i]];
      s[pil[i]] = rol(t, rot[i]);
      t = u;
    }
    /* chi */
    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; i++) {
        b[i] = s[j + i];
      }
      for (i = 0; i < 5; i++) {
        s[j + i] = b[i] ^ (~b[(i + 1) % 5] & b[(i + 2) % 5]);
      }
    }
    /* iota */
    s[0] ^= rc[r];
  }
}

static void xorb(nqkctx *c, size_t i, unsigned v) {
  c->s[i >> 3] ^= (uint64_t)(v & 0xffu) << (8 * (i & 7));
}

static void kini(nqkctx *c, size_t rate, unsigned dom, unsigned dnb) {
  memset(c, 0, sizeof *c);
  c->rate = rate;
  c->dom = dom;
  c->dnb = dnb;
}

void nqs3ini(nqkctx *c, unsigned bits) {
  /* capacity is twice the digest */
  kini(c, 200 - 2 * (size_t)(bits / 8), 2, 2);
}

void nqshkini(nqkctx *c, unsigned bits) {
  kini(c, 200 - 2 * (size_t)(bits / 8), 15, 4);
}

void nqkabs(nqkctx *c, const uint8_t *in, size_t len) {
  if (c->sq || len == 0) return;
  while (len > 0) {
    if (c->pos == 0 && len >= c->rate) {
      size_t i;
      for (i = 0; i < c->rate / 8; i++) {
        c->s[i] ^= nqld64l(in + 8 * i);
      }
      nqkeccak(c->s);
      in += c->rate;
      len -= c->rate;
      continue;
    }
    xorb(c, c->pos++, *in++);
    len--;
    if (c->pos == c->rate) {
      nqkeccak(c->s);
      c->pos = 0;
    }
  }
}

void nqkpad(nqkctx *c, uint8_t last, unsigned nb) {
  /* the trailing message bits, the domain bits, then the first 1 of
   * pad10*1 at bit t; at most 7 + 4 + 1 = 12 bits */
  unsigned t, w;
  if (c->sq) return;
  nb &= 7;
  t = nb + c->dnb;
  w = ((unsigned)last & ((1u << nb) - 1)) | (c->dom << nb) | (1u << t);
  xorb(c, c->pos, w);
  if (t >= 8) {
    if (++c->pos == c->rate) {
      nqkeccak(c->s);
      c->pos = 0;
    }
    xorb(c, c->pos, w >> 8);
    t -= 8;
  }
  /* the final 1 of pad10*1 must be a different bit from the first */
  if (c->pos == c->rate - 1 && t == 7) {
    nqkeccak(c->s);
  }
  xorb(c, c->rate - 1, 0x80);
  nqkeccak(c->s);
  c->pos = 0;
  c->sq = 1;
}

void nqksqz(nqkctx *c, uint8_t *out, size_t len) {
  if (!c->sq) nqkpad(c, 0, 0);
  while (len > 0) {
    if (c->pos == c->rate) {
      nqkeccak(c->s);
      c->pos = 0;
    }
    *out++ = (uint8_t)(c->s[c->pos >> 3] >> (8 * (c->pos & 7)));
    c->pos++;
    len--;
  }
}

void nqs3(unsigned bits, const uint8_t *in, size_t len, uint8_t *out) {
  nqkctx c;
  nqs3ini(&c, bits);
  nqkabs(&c, in, len);
  nqksqz(&c, out, bits / 8);
  nqwipe(&c, sizeof c);
}

void nqshk(unsigned bits, const uint8_t *in, size_t len, uint8_t *out,
           size_t outlen) {
  nqkctx c;
  nqshkini(&c, bits);
  nqkabs(&c, in, len);
  nqksqz(&c, out, outlen);
  nqwipe(&c, sizeof c);
}
