/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256
 * (FIPS 180-4). */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

/* FIPS 180-4 4.2.3. The SHA-256 constants (4.2.2) are the first 32 bits
 * of the first 64 of these. */
static const uint64_t k5[80] = {
    0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu,
    0xe9b5dba58189dbbcu, 0x3956c25bf348b538u, 0x59f111f1b605d019u,
    0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u, 0xd807aa98a3030242u,
    0x12835b0145706fbeu, 0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
    0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u,
    0xc19bf174cf692694u, 0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u,
    0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u, 0x2de92c6f592b0275u,
    0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
    0x983e5152ee66dfabu, 0xa831c66d2db43210u, 0xb00327c898fb213fu,
    0xbf597fc7beef0ee4u, 0xc6e00bf33da88fc2u, 0xd5a79147930aa725u,
    0x06ca6351e003826fu, 0x142929670a0e6e70u, 0x27b70a8546d22ffcu,
    0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
    0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u,
    0x92722c851482353bu, 0xa2bfe8a14cf10364u, 0xa81a664bbc423001u,
    0xc24b8b70d0f89791u, 0xc76c51a30654be30u, 0xd192e819d6ef5218u,
    0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u,
    0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u, 0x2748774cdf8eeb99u,
    0x34b0bcb5e19b48a8u, 0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu,
    0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u, 0x748f82ee5defb2fcu,
    0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
    0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u,
    0xc67178f2e372532bu, 0xca273eceea26619cu, 0xd186b8c721c0c207u,
    0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u, 0x06f067aa72176fbau,
    0x0a637dc5a2c898a6u, 0x113f9804bef90daeu, 0x1b710b35131c471bu,
    0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu,
    0x431d67c49c100d4cu, 0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au,
    0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u};

/* Initial values, 5.3.4 - 5.3.6. SHA-256 takes the first 32 bits of the
 * SHA-512 words, SHA-224 the last 32 bits of the SHA-384 words. */
static const uint64_t iv512[8] = {
    0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu, 0x3c6ef372fe94f82bu,
    0xa54ff53a5f1d36f1u, 0x510e527fade682d1u, 0x9b05688c2b3e6c1fu,
    0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u};
static const uint64_t iv384[8] = {
    0xcbbb9d5dc1059ed8u, 0x629a292a367cd507u, 0x9159015a3070dd17u,
    0x152fecd8f70e5939u, 0x67332667ffc00b31u, 0x8eb44a8768581511u,
    0xdb0c2e0d64f98fa7u, 0x47b5481dbefa4fa4u};
static const uint64_t iv5t224[8] = {
    0x8c3d37c819544da2u, 0x73e1996689dcd4d6u, 0x1dfab7ae32ff9c82u,
    0x679dd514582f9fcfu, 0x0f6d2b697bd44da8u, 0x77e36f7304c48942u,
    0x3f9d85a86a1d36c8u, 0x1112e6ad91d692a1u};
static const uint64_t iv5t256[8] = {
    0x22312194fc2bf72cu, 0x9f555fa3c84c64c2u, 0x2393b86b6f53b151u,
    0x963877195940eabdu, 0x96283ee2a88effe3u, 0xbe5e1e2553863992u,
    0x2b0199fc2c85b8aau, 0x0eb72ddc81c52ca2u};

static uint32_t ror32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

static uint64_t ror64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

/* ---- SHA-256 ---- */

static void blk2(uint32_t h[8], const uint8_t *p) {
  uint32_t w[16], a, b, c, d, e, f, g, x, t1, t2;
  unsigned i;
  for (i = 0; i < 16; i++) {
    w[i] = nqld32b(p + 4 * i);
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; x = h[7];
  for (i = 0; i < 64; i++) {
    uint32_t wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint32_t v15 = w[(i - 15) & 15], v2 = w[(i - 2) & 15];
      uint32_t s0 = ror32(v15, 7) ^ ror32(v15, 18) ^ (v15 >> 3);
      uint32_t s1 = ror32(v2, 17) ^ ror32(v2, 19) ^ (v2 >> 10);
      wi = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      w[i & 15] = wi;
    }
    t1 = x + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) +
         ((e & f) ^ (~e & g)) + (uint32_t)(k5[i] >> 32) + wi;
    t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) +
         ((a & b) ^ (a & c) ^ (b & c));
    x = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += x;
  /* under HMAC the block is the key xor a pad */
  nqwipe(w, sizeof w);
}

void nqs2ini(nqs2ctx *c, size_t dlen) {
  unsigned i;
  memset(c, 0, sizeof *c);
  for (i = 0; i < 8; i++) {
    c->h[i] = dlen == 28 ? (uint32_t)iv384[i] : (uint32_t)(iv512[i] >> 32);
  }
  c->dlen = dlen == 28 ? 28 : 32;
}

void nqs2upd(nqs2ctx *c, const uint8_t *in, size_t len) {
  if (len == 0) return;
  c->n += len;
  if (c->pos > 0) {
    size_t k = 64 - c->pos;
    if (k > len) k = len;
    memcpy(c->buf + c->pos, in, k);
    c->pos += k;
    in += k;
    len -= k;
    if (c->pos < 64) return;
    blk2(c->h, c->buf);
    c->pos = 0;
  }
  while (len >= 64) {
    blk2(c->h, in);
    in += 64;
    len -= 64;
  }
  if (len > 0) {
    memcpy(c->buf, in, len);
    c->pos = len;
  }
}

void nqs2bit(nqs2ctx *c, uint8_t last, unsigned nb, uint8_t *out) {
  uint64_t bits;
  uint8_t full[32];
  unsigned i;
  nb &= 7;
  bits = c->n * 8 + nb;
  /* the nb bits, then the single 1 bit */
  c->buf[c->pos++] = (uint8_t)((last & (0xff00u >> nb)) | (0x80u >> nb));
  if (c->pos > 56) {
    memset(c->buf + c->pos, 0, 64 - c->pos);
    blk2(c->h, c->buf);
    c->pos = 0;
  }
  memset(c->buf + c->pos, 0, 56 - c->pos);
  nqst64b(c->buf + 56, bits);
  blk2(c->h, c->buf);
  for (i = 0; i < 8; i++) {
    nqst32b(full + 4 * i, c->h[i]);
  }
  memcpy(out, full, c->dlen);
  nqwipe(full, sizeof full);
  nqwipe(c, sizeof *c);
}

void nqs2fin(nqs2ctx *c, uint8_t *out) {
  nqs2bit(c, 0, 0, out);
}

void nqs256(const uint8_t *in, size_t len, uint8_t out[32]) {
  nqs2ctx c;
  nqs2ini(&c, 32);
  nqs2upd(&c, in, len);
  nqs2fin(&c, out);
}

/* ---- SHA-512 ---- */

static void blk5(uint64_t h[8], const uint8_t *p) {
  uint64_t w[16], a, b, c, d, e, f, g, x, t1, t2;
  unsigned i;
  for (i = 0; i < 16; i++) {
    w[i] = nqld64b(p + 8 * i);
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; x = h[7];
  for (i = 0; i < 80; i++) {
    uint64_t wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint64_t v15 = w[(i - 15) & 15], v2 = w[(i - 2) & 15];
      uint64_t s0 = ror64(v15, 1) ^ ror64(v15, 8) ^ (v15 >> 7);
      uint64_t s1 = ror64(v2, 19) ^ ror64(v2, 61) ^ (v2 >> 6);
      wi = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      w[i & 15] = wi;
    }
    t1 = x + (ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41)) +
         ((e & f) ^ (~e & g)) + k5[i] + wi;
    t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)) +
         ((a & b) ^ (a & c) ^ (b & c));
    x = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += x;
  nqwipe(w, sizeof w);
}

void nqs5ini(nqs5ctx *c, nqhalg alg) {
  const uint64_t *iv;
  memset(c, 0, sizeof *c);
  switch (alg) {
  case NQS384: iv = iv384; c->dlen = 48; break;
  case NQS512T224: iv = iv5t224; c->dlen = 28; break;
  case NQS512T256: iv = iv5t256; c->dlen = 32; break;
  default: iv = iv512; c->dlen = 64; break;
  }
  memcpy(c->h, iv, sizeof c->h);
}

void nqs5upd(nqs5ctx *c, const uint8_t *in, size_t len) {
  if (len == 0) return;
  c->n += len;
  if (c->pos > 0) {
    size_t k = 128 - c->pos;
    if (k > len) k = len;
    memcpy(c->buf + c->pos, in, k);
    c->pos += k;
    in += k;
    len -= k;
    if (c->pos < 128) return;
    blk5(c->h, c->buf);
    c->pos = 0;
  }
  while (len >= 128) {
    blk5(c->h, in);
    in += 128;
    len -= 128;
  }
  if (len > 0) {
    memcpy(c->buf, in, len);
    c->pos = len;
  }
}

void nqs5bit(nqs5ctx *c, uint8_t last, unsigned nb, uint8_t *out) {
  /* the 128-bit length: n bytes is n * 8 + nb bits */
  uint64_t lo, hi = c->n >> 61;
  uint8_t full[64];
  unsigned i;
  nb &= 7;
  lo = c->n * 8 + nb;
  c->buf[c->pos++] = (uint8_t)((last & (0xff00u >> nb)) | (0x80u >> nb));
  if (c->pos > 112) {
    memset(c->buf + c->pos, 0, 128 - c->pos);
    blk5(c->h, c->buf);
    c->pos = 0;
  }
  memset(c->buf + c->pos, 0, 112 - c->pos);
  nqst64b(c->buf + 112, hi);
  nqst64b(c->buf + 120, lo);
  blk5(c->h, c->buf);
  for (i = 0; i < 8; i++) {
    nqst64b(full + 8 * i, c->h[i]);
  }
  memcpy(out, full, c->dlen);
  nqwipe(full, sizeof full);
  nqwipe(c, sizeof *c);
}

void nqs5fin(nqs5ctx *c, uint8_t *out) {
  nqs5bit(c, 0, 0, out);
}

void nqs512(const uint8_t *in, size_t len, uint8_t out[64]) {
  nqs5ctx c;
  nqs5ini(&c, NQS512);
  nqs5upd(&c, in, len);
  nqs5fin(&c, out);
}
