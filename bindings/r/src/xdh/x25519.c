/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X25519 (RFC 7748): the Montgomery ladder of section 5 over
 * GF(2^255 - 19) in ten unsigned limbs, limb i of weight 2^ceil(25.5 i):
 * 26 bits for even i, 25 for odd. After a carry every limb is below
 * 2^26, so a product of two limbs, doubled and times 19, stays below
 * 2^58, and ten of them below 2^62. */
#include <string.h>

#include "core/int.h"
#include "xdh/xdh.h"

typedef uint32_t fe[10];

#define M26 0x3ffffffu
#define M25 0x1ffffffu

/* bits of limb i */
#define W(i) ((i) % 2 == 0 ? 26 : 25)

/* t (any limbs below 2^62) into h, every limb back under its width
 * (limb 1 may end up to 2^15 over: one more carry from limb 0) */
static void carry(fe h, uint64_t *t) {
  uint64_t c;
  int i;
  for (i = 0; i < 9; i++) {
    c = t[i] >> W(i);
    t[i] &= i % 2 == 0 ? M26 : M25;
    t[i + 1] += c;
  }
  c = t[9] >> 25;
  t[9] &= M25;
  t[0] += 19 * c;
  c = t[0] >> 26;
  t[0] &= M26;
  t[1] += c;
  for (i = 0; i < 10; i++) h[i] = (uint32_t)t[i];
}

static void fmul(fe h, const fe f, const fe g) {
  uint64_t t[10];
  int i, j;
  for (i = 0; i < 10; i++) t[i] = 0;
  for (i = 0; i < 10; i++) {
    for (j = 0; j < 10; j++) {
      uint64_t p = (uint64_t)f[i] * g[j];
      /* two odd limbs: weights add up to one bit less than the sum's */
      if (i % 2 == 1 && j % 2 == 1) p *= 2;
      /* 2^255 = 19 */
      if (i + j >= 10) {
        t[i + j - 10] += 19 * p;
      } else {
        t[i + j] += p;
      }
    }
  }
  carry(h, t);
}

static void fadd(fe h, const fe f, const fe g) {
  uint64_t t[10];
  int i;
  for (i = 0; i < 10; i++) t[i] = (uint64_t)f[i] + g[i];
  carry(h, t);
}

/* f - g + 4p: no limb goes negative for carried inputs */
static void fsub(fe h, const fe f, const fe g) {
  uint64_t t[10];
  int i;
  for (i = 0; i < 10; i++) {
    uint64_t q = i == 0 ? 4 * (uint64_t)(M26 - 18)
                        : 4 * (uint64_t)(i % 2 == 0 ? M26 : M25);
    t[i] = (uint64_t)f[i] + q - g[i];
  }
  carry(h, t);
}

/* swaps f and g when b is 1, leaves them when 0 */
static void fswap(fe f, fe g, uint32_t b) {
  uint32_t m = 0u - b, x;
  int i;
  for (i = 0; i < 10; i++) {
    x = m & (f[i] ^ g[i]);
    f[i] ^= x;
    g[i] ^= x;
  }
}

/* 32 bytes, little-endian, bit 255 ignored */
static void fload(fe h, const uint8_t *s) {
  int i, bits = 0;
  uint64_t acc = 0;
  size_t o = 0;
  for (i = 0; i < 10; i++) {
    while (bits < W(i)) {
      acc |= (uint64_t)s[o++] << bits;
      bits += 8;
    }
    h[i] = (uint32_t)acc & (i % 2 == 0 ? M26 : M25);
    acc >>= W(i);
    bits -= W(i);
  }
}

/* the canonical encoding of h mod p */
static void fstore(uint8_t *s, const fe f) {
  fe h;
  uint32_t q, c;
  uint64_t acc = 0;
  int i, bits = 0;
  size_t o = 0;
  memcpy(h, f, sizeof h);
  /* q = floor((h + 19) / 2^255), 1 exactly when h >= p (h < 2p) */
  q = (h[0] + 19) >> 26;
  for (i = 1; i < 10; i++) q = (h[i] + q) >> W(i);
  /* h + 19q - q 2^255 */
  h[0] += 19 * q;
  for (i = 0; i < 9; i++) {
    c = h[i] >> W(i);
    h[i] &= i % 2 == 0 ? M26 : M25;
    h[i + 1] += c;
  }
  h[9] &= M25;
  for (i = 0; i < 10; i++) {
    acc |= (uint64_t)h[i] << bits;
    bits += W(i);
    while (bits >= 8) {
      s[o++] = (uint8_t)acc;
      acc >>= 8;
      bits -= 8;
    }
  }
  s[o] = (uint8_t)acc; /* the last 7 bits */
  nqwipe(h, sizeof h);
}

/* h = z^(p - 2) = 1 / z; p - 2 = 2^255 - 21: every bit from 254 down
 * is 1 except bits 4 and 2 */
static void finv(fe h, const fe z) {
  fe r;
  int i;
  memset(r, 0, sizeof r);
  r[0] = 1;
  for (i = 254; i >= 0; i--) {
    fmul(r, r, r);
    if (i != 4 && i != 2) fmul(r, r, z);
  }
  memcpy(h, r, sizeof r);
  nqwipe(r, sizeof r);
}

int nqx25519(uint8_t *out, const uint8_t *k, const uint8_t *u) {
  static const fe a24 = {121665};
  uint8_t e[32], z = 0;
  fe x1, x2, z2, x3, z3, a, aa, b, bb, ee, c, d, da, cb;
  uint32_t sw = 0;
  int t, i;
  if (out == NULL || k == NULL || u == NULL) return NQEARG;
  memcpy(e, k, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  fload(x1, u);
  memset(x2, 0, sizeof x2);
  x2[0] = 1;
  memset(z2, 0, sizeof z2);
  memcpy(x3, x1, sizeof x3);
  memset(z3, 0, sizeof z3);
  z3[0] = 1;
  for (t = 254; t >= 0; t--) {
    uint32_t kt = (uint32_t)(e[t / 8] >> (t % 8)) & 1u;
    sw ^= kt;
    fswap(x2, x3, sw);
    fswap(z2, z3, sw);
    sw = kt;
    fadd(a, x2, z2);
    fmul(aa, a, a);
    fsub(b, x2, z2);
    fmul(bb, b, b);
    fsub(ee, aa, bb);
    fadd(c, x3, z3);
    fsub(d, x3, z3);
    fmul(da, d, a);
    fmul(cb, c, b);
    fadd(x3, da, cb);
    fmul(x3, x3, x3);
    fsub(z3, da, cb);
    fmul(z3, z3, z3);
    fmul(z3, z3, x1);
    fmul(x2, aa, bb);
    fmul(z2, a24, ee);
    fadd(z2, z2, aa);
    fmul(z2, z2, ee);
  }
  fswap(x2, x3, sw);
  fswap(z2, z3, sw);
  finv(z2, z2);
  fmul(x2, x2, z2);
  fstore(out, x2);
  for (i = 0; i < 32; i++) z |= out[i];
  nqwipe(e, sizeof e);
  nqwipe(x2, sizeof x2);
  nqwipe(z2, sizeof z2);
  nqwipe(x3, sizeof x3);
  nqwipe(z3, sizeof z3);
  nqwipe(a, sizeof a);
  nqwipe(aa, sizeof aa);
  nqwipe(b, sizeof b);
  nqwipe(bb, sizeof bb);
  nqwipe(ee, sizeof ee);
  nqwipe(c, sizeof c);
  nqwipe(d, sizeof d);
  nqwipe(da, sizeof da);
  nqwipe(cb, sizeof cb);
  NQXPUB(&z, sizeof z);
  return z == 0 ? NQEVRFY : NQOK;
}

int nqx25519b(uint8_t *pk, const uint8_t *sk) {
  static const uint8_t nine[32] = {9};
  return nqx25519(pk, sk, nine);
}
