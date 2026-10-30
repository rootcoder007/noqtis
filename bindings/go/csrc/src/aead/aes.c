/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* AES encryption (FIPS 197), constant time and without tables. SubBytes
 * is bitsliced: the 32 bytes of two blocks become eight 32-bit words,
 * word i holding bit i of every byte, and the S-box is computed on all
 * of them at once as x^254 in GF(2^8) (the inverse, 0 for 0) followed
 * by the affine map of FIPS 197 section 5.1.1. ShiftRows, MixColumns and
 * AddRoundKey work on the bytes with masks and XORs only, so no branch
 * and no memory index depends on the key or the data. Only the forward
 * cipher: GCM and CTR never decrypt a block. */
#include <string.h>

#include "aead/aead.h"

/* r = a * b in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, bitsliced; r may
 * be a or b */
static void gmul(uint32_t *r, const uint32_t *a, const uint32_t *b) {
  uint32_t c[15];
  int i, j;
  for (i = 0; i < 15; i++) c[i] = 0;
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 8; j++) c[i + j] ^= a[i] & b[j];
  }
  /* x^k = x^(k-4) + x^(k-5) + x^(k-7) + x^(k-8), from the top down */
  for (i = 14; i >= 8; i--) {
    c[i - 4] ^= c[i];
    c[i - 5] ^= c[i];
    c[i - 7] ^= c[i];
    c[i - 8] ^= c[i];
  }
  for (i = 0; i < 8; i++) r[i] = c[i];
}

/* SubBytes on 32 bytes in place */
static void sub32(uint8_t *s) {
  uint32_t x[8], x2[8], x3[8], x12[8], t[8];
  int i, j;
  for (i = 0; i < 8; i++) {
    x[i] = 0;
    for (j = 0; j < 32; j++) x[i] |= (((uint32_t)s[j] >> i) & 1u) << j;
  }
  /* x^254 = x^(2 + 12 + 240): x^2, x^3, x^6, x^12, x^15, x^240 */
  gmul(x2, x, x);
  gmul(x3, x2, x);
  gmul(t, x3, x3);
  gmul(x12, t, t);
  gmul(t, x12, x3);
  for (i = 0; i < 4; i++) gmul(t, t, t);
  gmul(t, t, x12);
  gmul(t, t, x2);
  /* b'_i = b_i + b_(i+4) + b_(i+5) + b_(i+6) + b_(i+7) + c_i, c = 0x63 */
  for (i = 0; i < 8; i++) {
    x[i] = t[i] ^ t[(i + 4) & 7] ^ t[(i + 5) & 7] ^ t[(i + 6) & 7] ^
           t[(i + 7) & 7] ^ ((0x63u >> i) & 1u ? 0xffffffffu : 0u);
  }
  for (j = 0; j < 32; j++) {
    uint32_t v = 0;
    for (i = 0; i < 8; i++) v |= ((x[i] >> j) & 1u) << i;
    s[j] = (uint8_t)v;
  }
  nqwipe(x, sizeof x);
  nqwipe(x2, sizeof x2);
  nqwipe(x3, sizeof x3);
  nqwipe(x12, sizeof x12);
  nqwipe(t, sizeof t);
}

static uint8_t xt(uint8_t a) {
  return (uint8_t)(((unsigned)a << 1) ^ (0x1bu & (0u - ((unsigned)a >> 7))));
}

int nqaesk(nqaes *k, const uint8_t *key, size_t len) {
  uint8_t t[32], rc = 1;
  size_t nk = len / 4, i, n;
  if (k == NULL || key == NULL || (len != 16 && len != 24 && len != 32)) {
    return NQEARG;
  }
  k->nr = (unsigned)nk + 6;
  n = 4 * ((size_t)k->nr + 1);
  memcpy(k->rk, key, len);
  memset(t, 0, sizeof t);
  for (i = nk; i < n; i++) {
    memcpy(t, k->rk + 4 * (i - 1), 4);
    if (i % nk == 0) {
      uint8_t a = t[0];
      t[0] = t[1];
      t[1] = t[2];
      t[2] = t[3];
      t[3] = a;
      sub32(t);
      t[0] ^= rc;
      rc = xt(rc);
    } else if (nk > 6 && i % nk == 4) {
      sub32(t);
    }
    k->rk[4 * i] = (uint8_t)(k->rk[4 * (i - nk)] ^ t[0]);
    k->rk[4 * i + 1] = (uint8_t)(k->rk[4 * (i - nk) + 1] ^ t[1]);
    k->rk[4 * i + 2] = (uint8_t)(k->rk[4 * (i - nk) + 2] ^ t[2]);
    k->rk[4 * i + 3] = (uint8_t)(k->rk[4 * (i - nk) + 3] ^ t[3]);
  }
  nqwipe(t, sizeof t);
  return NQOK;
}

/* ShiftRows then (unless last) MixColumns on one block; byte r + 4c is
 * row r, column c */
static void mix(uint8_t *s, int last) {
  uint8_t o[16];
  int r, c;
  for (c = 0; c < 4; c++) {
    for (r = 0; r < 4; r++) o[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
  }
  for (c = 0; c < 4 && !last; c++) {
    uint8_t *a = o + 4 * c;
    uint8_t t = (uint8_t)(a[0] ^ a[1] ^ a[2] ^ a[3]), a0 = a[0];
    a[0] = (uint8_t)(a[0] ^ t ^ xt((uint8_t)(a[0] ^ a[1])));
    a[1] = (uint8_t)(a[1] ^ t ^ xt((uint8_t)(a[1] ^ a[2])));
    a[2] = (uint8_t)(a[2] ^ t ^ xt((uint8_t)(a[2] ^ a[3])));
    a[3] = (uint8_t)(a[3] ^ t ^ xt((uint8_t)(a[3] ^ a0)));
  }
  memcpy(s, o, 16);
  nqwipe(o, sizeof o);
}

void nqaes2(const nqaes *k, const uint8_t *in, uint8_t *out) {
  uint8_t s[32];
  unsigned r;
  int i;
  for (i = 0; i < 32; i++) s[i] = (uint8_t)(in[i] ^ k->rk[i & 15]);
  for (r = 1; r <= k->nr; r++) {
    sub32(s);
    mix(s, r == k->nr);
    mix(s + 16, r == k->nr);
    for (i = 0; i < 32; i++) s[i] ^= k->rk[16 * r + (unsigned)(i & 15)];
  }
  memcpy(out, s, 32);
  nqwipe(s, sizeof s);
}

void nqaes1(const nqaes *k, const uint8_t *in, uint8_t *out) {
  uint8_t b[32];
  memcpy(b, in, 16);
  memset(b + 16, 0, 16);
  nqaes2(k, b, b);
  memcpy(out, b, 16);
  nqwipe(b, sizeof b);
}
