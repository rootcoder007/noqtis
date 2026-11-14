/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* BLAKE2b (RFC 7693): keyed and unkeyed, any digest length from 1 to 64
 * bytes. Additions, XORs and rotations of 64-bit words only, so the time
 * depends on the lengths alone, never on the key or the data. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

static const uint64_t iv[8] = {
  0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu, 0x3c6ef372fe94f82bu,
  0xa54ff53a5f1d36f1u, 0x510e527fade682d1u, 0x9b05688c2b3e6c1fu,
  0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u};

/* the message schedule, section 2.7; rounds 10 and 11 reuse 0 and 1 */
static const uint8_t sg[10][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

static uint64_t rotr(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

/* G, section 3.1 */
static void mix(uint64_t *v, unsigned a, unsigned b, unsigned c, unsigned d,
                uint64_t x, uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = rotr(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr(v[b] ^ v[c], 63);
}

/* F, section 3.2, on the block in c->buf */
static void comp(nqb2ctx *c, int last) {
  uint64_t v[16], m[16];
  unsigned i;
  for (i = 0; i < 16; i++) m[i] = nqld64l(c->buf + 8 * i);
  for (i = 0; i < 8; i++) {
    v[i] = c->h[i];
    v[i + 8] = iv[i];
  }
  v[12] ^= c->t[0];
  v[13] ^= c->t[1];
  if (last) v[14] = ~v[14];
  for (i = 0; i < 12; i++) {
    const uint8_t *s = sg[i % 10];
    mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (i = 0; i < 8; i++) c->h[i] ^= v[i] ^ v[i + 8];
  nqwipe(v, sizeof v);
  nqwipe(m, sizeof m);
}

static void count(nqb2ctx *c, size_t n) {
  c->t[0] += (uint64_t)n;
  if (c->t[0] < (uint64_t)n) c->t[1]++;
}

int nqb2ini(nqb2ctx *c, size_t olen, const uint8_t *key, size_t klen) {
  unsigned i;
  if (c == NULL || olen < 1 || olen > 64 || klen > 64 ||
      (key == NULL && klen > 0)) {
    return NQEARG;
  }
  for (i = 0; i < 8; i++) c->h[i] = iv[i];
  c->h[0] ^= 0x01010000u ^ ((uint64_t)klen << 8) ^ (uint64_t)olen;
  c->t[0] = c->t[1] = 0;
  c->pos = 0;
  c->olen = olen;
  memset(c->buf, 0, sizeof c->buf);
  if (klen > 0) {
    /* the key, padded, is the first block */
    memcpy(c->buf, key, klen);
    c->pos = 128;
  }
  return NQOK;
}

void nqb2upd(nqb2ctx *c, const uint8_t *in, size_t len) {
  while (len > 0) {
    size_t n;
    /* a full block is compressed only once more input follows: the last
     * block must go to nqb2fin, flagged as last */
    if (c->pos == 128) {
      count(c, 128);
      comp(c, 0);
      c->pos = 0;
    }
    n = 128 - c->pos;
    if (n > len) n = len;
    memcpy(c->buf + c->pos, in, n);
    c->pos += n;
    in += n;
    len -= n;
  }
}

void nqb2fin(nqb2ctx *c, uint8_t *out) {
  uint8_t d[64];
  unsigned i;
  count(c, c->pos);
  memset(c->buf + c->pos, 0, 128 - c->pos);
  comp(c, 1);
  for (i = 0; i < 8; i++) nqst64l(d + 8 * i, c->h[i]);
  memcpy(out, d, c->olen);
  nqwipe(d, sizeof d);
  nqwipe(c, sizeof *c);
}

int nqb2b(const uint8_t *key, size_t keylen, const uint8_t *in,
          size_t inlen, uint8_t *out, size_t outlen) {
  nqb2ctx c;
  int rc;
  if (out == NULL || (in == NULL && inlen > 0)) return NQEARG;
  rc = nqb2ini(&c, outlen, key, keylen);
  if (rc != NQOK) return rc;
  if (inlen > 0) nqb2upd(&c, in, inlen);
  nqb2fin(&c, out);
  return NQOK;
}
