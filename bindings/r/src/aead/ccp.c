/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ChaCha20, Poly1305 and their AEAD (RFC 8439). Poly1305 keeps the
 * accumulator in five 26-bit limbs and multiplies with 32 x 32 -> 64-bit
 * products, the layout of Andrew Moon's public-domain poly1305-donna
 * (32-bit version); only unsigned arithmetic, no branch on secrets. */
#include <string.h>

#include "aead/aead.h"
#include "core/int.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a, b, c, d)                                                      \
  do {                                                                      \
    a += b;                                                                 \
    d ^= a;                                                                 \
    d = ROTL(d, 16);                                                        \
    c += d;                                                                 \
    b ^= c;                                                                 \
    b = ROTL(b, 12);                                                        \
    a += b;                                                                 \
    d ^= a;                                                                 \
    d = ROTL(d, 8);                                                         \
    c += d;                                                                 \
    b ^= c;                                                                 \
    b = ROTL(b, 7);                                                         \
  } while (0)

/* the ChaCha20 block function (RFC 8439 section 2.3) */
static void block(const uint8_t *key, const uint8_t *nonce, uint32_t ctr,
                  uint8_t *out) {
  uint32_t s[16], x[16];
  int i;
  s[0] = 0x61707865u;
  s[1] = 0x3320646eu;
  s[2] = 0x79622d32u;
  s[3] = 0x6b206574u;
  for (i = 0; i < 8; i++) s[4 + i] = nqld32l(key + 4 * i);
  s[12] = ctr;
  for (i = 0; i < 3; i++) s[13 + i] = nqld32l(nonce + 4 * i);
  memcpy(x, s, sizeof x);
  for (i = 0; i < 10; i++) {
    QR(x[0], x[4], x[8], x[12]);
    QR(x[1], x[5], x[9], x[13]);
    QR(x[2], x[6], x[10], x[14]);
    QR(x[3], x[7], x[11], x[15]);
    QR(x[0], x[5], x[10], x[15]);
    QR(x[1], x[6], x[11], x[12]);
    QR(x[2], x[7], x[8], x[13]);
    QR(x[3], x[4], x[9], x[14]);
  }
  for (i = 0; i < 16; i++) nqst32l(out + 4 * i, x[i] + s[i]);
  nqwipe(s, sizeof s);
  nqwipe(x, sizeof x);
}

void nqcc20(const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr,
            const uint8_t *in, size_t n, uint8_t *out) {
  uint8_t ks[64];
  size_t i;
  while (n > 0) {
    size_t m = n < 64 ? n : 64;
    block(key, nonce, ctr++, ks);
    for (i = 0; i < m; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
    in += m;
    out += m;
    n -= m;
  }
  nqwipe(ks, sizeof ks);
}

/* ---- Poly1305 ---- */

#define M26 0x3ffffffu

void nqp1ini(nqp1305 *p, const uint8_t key[32]) {
  /* r is clamped (RFC 8439 section 2.5.1) as it is split into limbs */
  p->r[0] = nqld32l(key) & 0x3ffffffu;
  p->r[1] = (nqld32l(key + 3) >> 2) & 0x3ffff03u;
  p->r[2] = (nqld32l(key + 6) >> 4) & 0x3ffc0ffu;
  p->r[3] = (nqld32l(key + 9) >> 6) & 0x3f03fffu;
  p->r[4] = (nqld32l(key + 12) >> 8) & 0x00fffffu;
  memset(p->h, 0, sizeof p->h);
  p->pad[0] = nqld32l(key + 16);
  p->pad[1] = nqld32l(key + 20);
  p->pad[2] = nqld32l(key + 24);
  p->pad[3] = nqld32l(key + 28);
  p->pos = 0;
}

/* h = (h + m) * r for one 16-byte block; hi is 2^128's bit (1 << 24 in
 * the top limb) for a full block, 0 for the padded last one */
static void p1blk(nqp1305 *p, const uint8_t *m, uint32_t hi) {
  const uint32_t *r = p->r;
  uint32_t *h = p->h, s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5,
           s4 = r[4] * 5, c;
  uint64_t d0, d1, d2, d3, d4;
  h[0] += nqld32l(m) & M26;
  h[1] += (nqld32l(m + 3) >> 2) & M26;
  h[2] += (nqld32l(m + 6) >> 4) & M26;
  h[3] += (nqld32l(m + 9) >> 6) & M26;
  h[4] += (nqld32l(m + 12) >> 8) | hi;
  d0 = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * s4 + (uint64_t)h[2] * s3 +
       (uint64_t)h[3] * s2 + (uint64_t)h[4] * s1;
  d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * s4 +
       (uint64_t)h[3] * s3 + (uint64_t)h[4] * s2;
  d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] +
       (uint64_t)h[3] * s4 + (uint64_t)h[4] * s3;
  d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] +
       (uint64_t)h[3] * r[0] + (uint64_t)h[4] * s4;
  d4 = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] +
       (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];
  c = (uint32_t)(d0 >> 26);
  h[0] = (uint32_t)d0 & M26;
  d1 += c;
  c = (uint32_t)(d1 >> 26);
  h[1] = (uint32_t)d1 & M26;
  d2 += c;
  c = (uint32_t)(d2 >> 26);
  h[2] = (uint32_t)d2 & M26;
  d3 += c;
  c = (uint32_t)(d3 >> 26);
  h[3] = (uint32_t)d3 & M26;
  d4 += c;
  c = (uint32_t)(d4 >> 26);
  h[4] = (uint32_t)d4 & M26;
  h[0] += c * 5;
  c = h[0] >> 26;
  h[0] &= M26;
  h[1] += c;
}

void nqp1upd(nqp1305 *p, const uint8_t *in, size_t n) {
  while (n > 0) {
    size_t c = 16 - p->pos;
    if (c > n) c = n;
    memcpy(p->buf + p->pos, in, c);
    p->pos += c;
    in += c;
    n -= c;
    if (p->pos == 16) {
      p1blk(p, p->buf, 1u << 24);
      p->pos = 0;
    }
  }
}

void nqp1fin(nqp1305 *p, uint8_t tag[16]) {
  uint32_t *h = p->h, g[5], c, m;
  uint64_t f;
  int i;
  if (p->pos > 0) {
    p->buf[p->pos] = 1;
    for (i = (int)p->pos + 1; i < 16; i++) p->buf[i] = 0;
    p1blk(p, p->buf, 0);
  }
  /* carry fully, then h - p when h >= p = 2^130 - 5, under a mask */
  c = h[1] >> 26;
  h[1] &= M26;
  for (i = 2; i < 5; i++) {
    h[i] += c;
    c = h[i] >> 26;
    h[i] &= M26;
  }
  h[0] += c * 5;
  c = h[0] >> 26;
  h[0] &= M26;
  h[1] += c;
  g[0] = h[0] + 5;
  c = g[0] >> 26;
  g[0] &= M26;
  for (i = 1; i < 5; i++) {
    g[i] = h[i] + c;
    c = g[i] >> 26;
    g[i] &= M26;
  }
  /* c is 1 exactly when h + 5 >= 2^130 */
  m = 0u - c;
  for (i = 0; i < 5; i++) h[i] = (h[i] & ~m) | (g[i] & m);
  /* every limb below 2^26 again (only 2^128 and up may be dropped) */
  for (i = 1; i < 5; i++) {
    c = h[i - 1] >> 26;
    h[i - 1] &= M26;
    h[i] += c;
  }
  /* h mod 2^128, plus s */
  f = (uint64_t)(h[0] | (h[1] << 26)) + p->pad[0];
  nqst32l(tag, (uint32_t)f);
  f = (uint64_t)((h[1] >> 6) | (h[2] << 20)) + p->pad[1] + (f >> 32);
  nqst32l(tag + 4, (uint32_t)f);
  f = (uint64_t)((h[2] >> 12) | (h[3] << 14)) + p->pad[2] + (f >> 32);
  nqst32l(tag + 8, (uint32_t)f);
  f = (uint64_t)((h[3] >> 18) | (h[4] << 8)) + p->pad[3] + (f >> 32);
  nqst32l(tag + 12, (uint32_t)f);
  nqwipe(g, sizeof g);
  nqwipe(p, sizeof *p);
}

/* ---- the AEAD ---- */

/* the most plaintext: 2^32 - 1 blocks of 64 bytes after the key block */
#define CMAX ((((uint64_t)1 << 32) - 1) * 64)

static void pad16(nqp1305 *p, size_t n) {
  static const uint8_t z[16] = {0};
  if (n % 16 != 0) nqp1upd(p, z, 16 - n % 16);
}

static void ctag(const uint8_t *otk, const uint8_t *aad, size_t alen,
                 const uint8_t *c, size_t n, uint8_t *tag) {
  nqp1305 p;
  uint8_t l[16];
  nqp1ini(&p, otk);
  if (alen > 0) nqp1upd(&p, aad, alen);
  pad16(&p, alen);
  if (n > 0) nqp1upd(&p, c, n);
  pad16(&p, n);
  nqst32l(l, (uint32_t)alen);
  nqst32l(l + 4, (uint32_t)((uint64_t)alen >> 32));
  nqst32l(l + 8, (uint32_t)n);
  nqst32l(l + 12, (uint32_t)((uint64_t)n >> 32));
  nqp1upd(&p, l, 16);
  nqp1fin(&p, tag);
}

static int cargs(const uint8_t *key, size_t klen, const uint8_t *nonce,
                 size_t nlen, const uint8_t *aad, size_t alen,
                 const uint8_t *in, size_t n, const uint8_t *out) {
  if (key == NULL || klen != 32 || nonce == NULL || nlen != 12 ||
      (aad == NULL && alen > 0) || (n > 0 && (in == NULL || out == NULL)) ||
      (uint64_t)n > CMAX) {
    return NQEARG;
  }
  return NQOK;
}

int nqccpe(const uint8_t *key, size_t klen, const uint8_t *nonce,
           size_t nlen, const uint8_t *aad, size_t alen, const uint8_t *in,
           size_t n, uint8_t *out, uint8_t *tag) {
  uint8_t otk[64];
  if (cargs(key, klen, nonce, nlen, aad, alen, in, n, out) != NQOK ||
      tag == NULL) {
    return NQEARG;
  }
  block(key, nonce, 0, otk);
  nqcc20(key, nonce, 1, in, n, out);
  ctag(otk, aad, alen, out, n, tag);
  nqwipe(otk, sizeof otk);
  return NQOK;
}

int nqccpd(const uint8_t *key, size_t klen, const uint8_t *nonce,
           size_t nlen, const uint8_t *aad, size_t alen, const uint8_t *in,
           size_t n, const uint8_t *tag, size_t taglen, uint8_t *out) {
  uint8_t otk[64], t[16];
  int ok;
  if (cargs(key, klen, nonce, nlen, aad, alen, in, n, out) != NQOK ||
      tag == NULL || taglen != NQAEADTAG) {
    return NQEARG;
  }
  block(key, nonce, 0, otk);
  ctag(otk, aad, alen, in, n, t);
  ok = nqcteq(t, tag, 16);
  NQAEPUB(&ok, sizeof ok);
  if (ok) {
    nqcc20(key, nonce, 1, in, n, out);
  } else if (n > 0) {
    memset(out, 0, n);
  }
  nqwipe(otk, sizeof otk);
  nqwipe(t, sizeof t);
  return ok ? NQOK : NQEVRFY;
}
