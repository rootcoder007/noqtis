/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* AES-GCM (NIST SP 800-38D). GHASH multiplies in GF(2^128) one bit at a
 * time (Algorithm 1 of section 6.3), every conditional step a mask, so
 * its time depends on neither the hash key nor the data. */
#include <string.h>

#include "aead/aead.h"

/* the most bytes of plaintext (2^39 - 256 bits) and of IV accepted */
#define PMAX (((uint64_t)1 << 36) - 32)
#define IVMAX ((uint64_t)1 << 32)

/* x = x * h (both big-endian halves, GCM's reflected bit order) */
static void gfmul(uint64_t *x, const uint64_t *h) {
  uint64_t z0 = 0, z1 = 0, v0 = h[0], v1 = h[1], m;
  int i;
  for (i = 0; i < 128; i++) {
    uint64_t b = i < 64 ? x[0] >> (63 - i) : x[1] >> (127 - i);
    m = (uint64_t)0 - (b & 1u);
    z0 ^= v0 & m;
    z1 ^= v1 & m;
    m = (uint64_t)0 - (v1 & 1u);
    v1 = (v1 >> 1) | (v0 << 63);
    v0 = (v0 >> 1) ^ (UINT64_C(0xe100000000000000) & m);
  }
  x[0] = z0;
  x[1] = z1;
}

static uint64_t ld64(const uint8_t *p) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static void st64(uint8_t *p, uint64_t v) {
  int i;
  for (i = 7; i >= 0; i--) {
    p[i] = (uint8_t)v;
    v >>= 8;
  }
}

/* absorbs n bytes into the GHASH state y, zero-padding the last block */
static void ghash(uint64_t *y, const uint64_t *h, const uint8_t *p,
                  size_t n) {
  uint8_t b[16];
  while (n > 0) {
    size_t c = n < 16 ? n : 16;
    memset(b, 0, sizeof b);
    memcpy(b, p, c);
    y[0] ^= ld64(b);
    y[1] ^= ld64(b + 8);
    gfmul(y, h);
    p += c;
    n -= c;
  }
  nqwipe(b, sizeof b);
}

int nqgcmk(nqgcm *g, const uint8_t *key, size_t len) {
  uint8_t z[16];
  int rc;
  if (g == NULL) return NQEARG;
  if ((rc = nqaesk(&g->k, key, len)) != NQOK) return rc;
  memset(z, 0, sizeof z);
  nqaes1(&g->k, z, z);
  g->h[0] = ld64(z);
  g->h[1] = ld64(z + 8);
  nqwipe(z, sizeof z);
  return NQOK;
}

/* the pre-counter block J0 (section 7.1, step 2) */
static void pre(const nqgcm *g, const uint8_t *iv, size_t ivlen,
               uint8_t *j) {
  uint64_t y[2] = {0, 0};
  uint8_t l[16];
  if (ivlen == 12) {
    memcpy(j, iv, 12);
    j[12] = 0;
    j[13] = 0;
    j[14] = 0;
    j[15] = 1;
    return;
  }
  ghash(y, g->h, iv, ivlen);
  memset(l, 0, 8);
  st64(l + 8, (uint64_t)ivlen * 8);
  ghash(y, g->h, l, 16);
  st64(j, y[0]);
  st64(j + 8, y[1]);
  nqwipe(y, sizeof y);
}

/* GCTR from inc32(J0): two counter blocks per AES call */
static void gctr(const nqgcm *g, const uint8_t *j, const uint8_t *in,
                 size_t n, uint8_t *out) {
  uint8_t cb[32], ks[32];
  uint32_t c = ((uint32_t)j[12] << 24) | ((uint32_t)j[13] << 16) |
               ((uint32_t)j[14] << 8) | j[15];
  size_t i;
  memcpy(cb, j, 12);
  memcpy(cb + 16, j, 12);
  while (n > 0) {
    size_t m = n < 32 ? n : 32;
    int k;
    for (k = 0; k < 2; k++) {
      c++;
      cb[16 * k + 12] = (uint8_t)(c >> 24);
      cb[16 * k + 13] = (uint8_t)(c >> 16);
      cb[16 * k + 14] = (uint8_t)(c >> 8);
      cb[16 * k + 15] = (uint8_t)c;
    }
    nqaes2(&g->k, cb, ks);
    for (i = 0; i < m; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
    in += m;
    out += m;
    n -= m;
  }
  nqwipe(ks, sizeof ks);
  nqwipe(cb, sizeof cb);
}

/* the tag over aad and the ciphertext c */
static void gtag(const nqgcm *g, const uint8_t *j, const uint8_t *aad,
                 size_t alen, const uint8_t *c, size_t n, uint8_t *tag) {
  uint64_t y[2] = {0, 0};
  uint8_t l[16], e[16];
  size_t i;
  ghash(y, g->h, aad, alen);
  ghash(y, g->h, c, n);
  st64(l, (uint64_t)alen * 8);
  st64(l + 8, (uint64_t)n * 8);
  ghash(y, g->h, l, 16);
  st64(l, y[0]);
  st64(l + 8, y[1]);
  nqaes1(&g->k, j, e);
  for (i = 0; i < 16; i++) tag[i] = (uint8_t)(l[i] ^ e[i]);
  nqwipe(y, sizeof y);
  nqwipe(l, sizeof l);
  nqwipe(e, sizeof e);
}

static int args(const nqgcm *g, const uint8_t *iv, size_t ivlen,
                const uint8_t *aad, size_t alen, const uint8_t *in,
                size_t n, const uint8_t *out) {
  if (g == NULL || iv == NULL || ivlen == 0 || (uint64_t)ivlen > IVMAX ||
      (aad == NULL && alen > 0) || (uint64_t)alen > ((uint64_t)1 << 60) ||
      (n > 0 && (in == NULL || out == NULL)) || (uint64_t)n > PMAX) {
    return NQEARG;
  }
  return NQOK;
}

int nqgcme(const nqgcm *g, const uint8_t *iv, size_t ivlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           uint8_t *out, uint8_t *tag) {
  uint8_t j[16];
  if (args(g, iv, ivlen, aad, alen, in, n, out) != NQOK || tag == NULL) {
    return NQEARG;
  }
  pre(g, iv, ivlen, j);
  gctr(g, j, in, n, out);
  gtag(g, j, aad, alen, out, n, tag);
  nqwipe(j, sizeof j);
  return NQOK;
}

int nqgcmd(const nqgcm *g, const uint8_t *iv, size_t ivlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           const uint8_t *tag, size_t taglen, uint8_t *out) {
  uint8_t j[16], t[16];
  int ok;
  if (args(g, iv, ivlen, aad, alen, in, n, out) != NQOK || tag == NULL ||
      taglen != NQAEADTAG) {
    return NQEARG;
  }
  pre(g, iv, ivlen, j);
  gtag(g, j, aad, alen, in, n, t);
  ok = nqcteq(t, tag, 16);
  NQAEPUB(&ok, sizeof ok);
  if (ok) {
    gctr(g, j, in, n, out);
  } else if (n > 0) {
    memset(out, 0, n);
  }
  nqwipe(j, sizeof j);
  nqwipe(t, sizeof t);
  return ok ? NQOK : NQEVRFY;
}
