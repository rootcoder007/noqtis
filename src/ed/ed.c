/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Ed25519 (RFC 8032) in portable C11: field elements of GF(2^255 - 19)
 * as 16 limbs of 16 bits in int64_t (no 128-bit type, so MSVC builds it
 * too), points in extended coordinates (X, Y, Z, T), a constant-time
 * ladder for every scalar multiplication. The arithmetic follows the
 * public-domain TweetNaCl, written here without shifting negative values
 * (floor division by a power of two instead): int64_t is two's
 * complement by definition, so & on it is exact. */
#include <string.h>

#include "core/int.h"
#include "ed/ed.h"
#include "hash/h.h"

typedef int64_t gf[16];

static const gf g0 = {0};
static const gf g1 = {1};
/* d = -121665/121666, 2d, sqrt(-1), and the base point's x and y */
static const gf cd = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141,
                      0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
                      0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf cd2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283,
                       0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
                       0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf ci = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f,
                      0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                      0xdf0b, 0x4fc1, 0x2480, 0x2b83};
static const gf cx = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525,
                      0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                      0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf cy = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                      0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                      0x6666, 0x6666, 0x6666, 0x6666};
/* the group order L = 2^252 + 27742317777372353535851937790883648493 */
static const int64_t cl[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12,
                               0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                               0xde, 0x14, 0,    0,    0,    0,    0,
                               0,    0,    0,    0,    0,    0,    0,
                               0,    0,    0,    0x10};

/* floor(v / 2^k), exact for negative v */
static int64_t fl(int64_t v, unsigned k) {
  int64_t m = ((int64_t)1 << k) - 1;
  return (v - (v & m)) / ((int64_t)1 << k);
}

static void fcpy(gf r, const gf a) {
  int i;
  for (i = 0; i < 16; i++) r[i] = a[i];
}

static void car(gf o) {
  int i;
  int64_t c;
  for (i = 0; i < 16; i++) {
    c = fl(o[i], 16);
    o[i] -= c * 65536;
    if (i < 15) {
      o[i + 1] += c;
    } else {
      o[0] += 38 * c;
    }
  }
}

/* p, q = q, p when b is 1; unchanged when 0; no branch on b */
static void sel(gf p, gf q, int b) {
  uint64_t c = (uint64_t)0 - (uint64_t)b, t;
  int i;
  for (i = 0; i < 16; i++) {
    t = c & ((uint64_t)p[i] ^ (uint64_t)q[i]);
    p[i] = (int64_t)((uint64_t)p[i] ^ t);
    q[i] = (int64_t)((uint64_t)q[i] ^ t);
  }
}

static int64_t b16(int64_t v) { return (int64_t)(((uint64_t)v >> 16) & 1); }

static void pack(uint8_t o[32], const gf n) {
  int i, j;
  int64_t b;
  gf m, t;
  fcpy(t, n);
  car(t);
  car(t);
  car(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - b16(m[i - 1]);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - b16(m[14]);
    b = b16(m[15]);
    m[14] &= 0xffff;
    sel(t, m, (int)(1 - b));
  }
  for (i = 0; i < 16; i++) {
    o[2 * i] = (uint8_t)(t[i] & 0xff);
    o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
  }
}

/* 1 when a and b differ, in time independent of their values */
static int neq(const gf a, const gf b) {
  uint8_t c[32], d[32];
  unsigned acc = 0;
  int i;
  pack(c, a);
  pack(d, b);
  for (i = 0; i < 32; i++) acc |= (unsigned)(c[i] ^ d[i]);
  return acc != 0;
}

static int par(const gf a) {
  uint8_t d[32];
  pack(d, a);
  return d[0] & 1;
}

static int isz(const gf a) {
  uint8_t d[32];
  unsigned acc = 0;
  int i;
  pack(d, a);
  for (i = 0; i < 32; i++) acc |= d[i];
  return acc == 0;
}

static void unpk(gf o, const uint8_t n[32]) {
  int i;
  for (i = 0; i < 16; i++) {
    o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
  }
  o[15] &= 0x7fff;
}

static void fa(gf o, const gf a, const gf b) {
  int i;
  for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void fz(gf o, const gf a, const gf b) {
  int i;
  for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void fm(gf o, const gf a, const gf b) {
  int64_t t[31];
  int i, j;
  for (i = 0; i < 31; i++) t[i] = 0;
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
  }
  for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
  for (i = 0; i < 16; i++) o[i] = t[i];
  car(o);
  car(o);
}

static void fs(gf o, const gf a) { fm(o, a, a); }

/* a^(p - 2) = 1/a */
static void finv(gf o, const gf a) {
  gf c;
  int k;
  fcpy(c, a);
  for (k = 253; k >= 0; k--) {
    fs(c, c);
    if (k != 2 && k != 4) fm(c, c, a);
  }
  fcpy(o, c);
}

/* a^((p - 5) / 8), for the square root */
static void fp58(gf o, const gf a) {
  gf c;
  int k;
  fcpy(c, a);
  for (k = 250; k >= 0; k--) {
    fs(c, c);
    if (k != 1) fm(c, c, a);
  }
  fcpy(o, c);
}

typedef gf ge[4];

static void gadd(ge p, ge q) {
  gf a, b, c, d, t, e, f, g, h;
  fz(a, p[1], p[0]);
  fz(t, q[1], q[0]);
  fm(a, a, t);
  fa(b, p[0], p[1]);
  fa(t, q[0], q[1]);
  fm(b, b, t);
  fm(c, p[3], q[3]);
  fm(c, c, cd2);
  fm(d, p[2], q[2]);
  fa(d, d, d);
  fz(e, b, a);
  fz(f, d, c);
  fa(g, d, c);
  fa(h, b, a);
  fm(p[0], e, f);
  fm(p[1], h, g);
  fm(p[2], g, f);
  fm(p[3], e, h);
}

static void gswap(ge p, ge q, int b) {
  int i;
  for (i = 0; i < 4; i++) sel(p[i], q[i], b);
}

static void gpack(uint8_t r[32], ge p) {
  gf tx, ty, zi;
  finv(zi, p[2]);
  fm(tx, p[0], zi);
  fm(ty, p[1], zi);
  pack(r, ty);
  r[31] = (uint8_t)(r[31] ^ (par(tx) << 7));
}

/* p = [s]q; q is used as scratch */
static void gmul(ge p, ge q, const uint8_t s[32]) {
  int i, b;
  fcpy(p[0], g0);
  fcpy(p[1], g1);
  fcpy(p[2], g1);
  fcpy(p[3], g0);
  for (i = 255; i >= 0; i--) {
    b = (s[i / 8] >> (i & 7)) & 1;
    gswap(p, q, b);
    gadd(q, p);
    gadd(p, p);
    gswap(p, q, b);
  }
}

static void gbase(ge p, const uint8_t s[32]) {
  ge q;
  fcpy(q[0], cx);
  fcpy(q[1], cy);
  fcpy(q[2], g1);
  fm(q[3], cx, cy);
  gmul(p, q, s);
}

/* r = x mod L, x as 64 signed limbs of 8 bits */
static void modl(uint8_t r[32], int64_t x[64]) {
  int64_t c;
  int i, j;
  for (i = 63; i >= 32; i--) {
    c = 0;
    for (j = i - 32; j < i - 12; j++) {
      x[j] += c - 16 * x[i] * cl[j - (i - 32)];
      c = fl(x[j] + 128, 8);
      x[j] -= c * 256;
    }
    x[j] += c;
    x[i] = 0;
  }
  c = 0;
  for (j = 0; j < 32; j++) {
    x[j] += c - fl(x[31], 4) * cl[j];
    c = fl(x[j], 8);
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++) x[j] -= c * cl[j];
  for (i = 0; i < 32; i++) {
    x[i + 1] += fl(x[i], 8);
    r[i] = (uint8_t)(x[i] & 255);
  }
}

/* r (64 bytes) = r mod L, in its first 32 bytes */
static void red(uint8_t r[64]) {
  int64_t x[64];
  int i;
  for (i = 0; i < 64; i++) x[i] = r[i];
  memset(r, 0, 64);
  modl(r, x);
  nqwipe(x, sizeof x);
}

/* -A from its encoding, or -1 when the encoding is not canonical or not
 * a point */
static int unneg(ge r, const uint8_t p[32]) {
  gf t, chk, num, den, den2, den4, den6;
  uint8_t c[32];
  int s = p[31] >> 7;
  fcpy(r[2], g1);
  unpk(r[1], p);
  pack(c, r[1]);
  c[31] = (uint8_t)(c[31] | (p[31] & 0x80));
  if (memcmp(c, p, 32) != 0) return -1; /* y >= 2^255 - 19 */
  fs(num, r[1]);
  fm(den, num, cd);
  fz(num, num, r[2]);
  fa(den, r[2], den);
  fs(den2, den);
  fs(den4, den2);
  fm(den6, den4, den2);
  fm(t, den6, num);
  fm(t, t, den);
  fp58(t, t);
  fm(t, t, num);
  fm(t, t, den);
  fm(t, t, den);
  fm(r[0], t, den);
  fs(chk, r[0]);
  fm(chk, chk, den);
  if (neq(chk, num)) fm(r[0], r[0], ci);
  fs(chk, r[0]);
  fm(chk, chk, den);
  if (neq(chk, num)) return -1;
  if (isz(r[0]) && s) return -1; /* x = 0 with the sign bit set */
  if (par(r[0]) == s) fz(r[0], g0, r[0]);
  fm(r[3], r[0], r[1]);
  return 0;
}

/* L as bytes, for the subgroup check */
static const uint8_t lb[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12,
                               0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                               0xde, 0x14, 0,    0,    0,    0,    0,
                               0,    0,    0,    0,    0,    0,    0,
                               0,    0,    0,    0x10};

/* 1 when the point is of prime order L (no torsion part) and not the
 * identity: [L]P is the identity and P is not. A key with a small-order
 * part lets one signature verify for several messages or keys
 * (Wycheproof's SmallOrderPublicKey and MixedOrderPublicKey cases); the
 * identity verifies anything. */
static int prime(ge a) {
  static const uint8_t id[32] = {1};
  uint8_t e[32];
  ge p, q;
  int i;
  for (i = 0; i < 4; i++) fcpy(q[i], a[i]);
  gpack(e, q);
  if (memcmp(e, id, 32) == 0) return 0;
  gmul(p, q, lb);
  gpack(e, p);
  return memcmp(e, id, 32) == 0;
}

static const char dom[] = "SigEd25519 no Ed25519 collisions";

/* SHA-512 of dom2(ph, ctx) || a || b || m */
static void hdom(uint8_t out[64], int ph, const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                 const uint8_t *m, size_t ml) {
  nqs5ctx c;
  uint8_t f[2];
  nqs5ini(&c, NQS512);
  if (ph || ctxlen > 0) {
    f[0] = (uint8_t)(ph ? 1 : 0);
    f[1] = (uint8_t)ctxlen;
    nqs5upd(&c, (const uint8_t *)dom, sizeof dom - 1);
    nqs5upd(&c, f, 2);
    if (ctxlen > 0) nqs5upd(&c, ctx, ctxlen);
  }
  if (al > 0) nqs5upd(&c, a, al);
  if (bl > 0) nqs5upd(&c, b, bl);
  if (ml > 0) nqs5upd(&c, m, ml);
  nqs5fin(&c, out);
  nqwipe(&c, sizeof c);
}

static int args(const uint8_t *msg, size_t msglen, const uint8_t *ctx,
                size_t ctxlen) {
  if ((msg == NULL && msglen > 0) || (ctx == NULL && ctxlen > 0) ||
      ctxlen > 255) {
    return NQEARG;
  }
  return NQOK;
}

int nqedkg(const uint8_t sk[NQEDSK], uint8_t pk[NQEDPK]) {
  uint8_t h[64];
  ge p;
  if (sk == NULL || pk == NULL) return NQEARG;
  nqs512(sk, NQEDSK, h);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  gbase(p, h);
  gpack(pk, p);
  nqwipe(h, sizeof h);
  nqwipe(p, sizeof p);
  return NQOK;
}

int nqedsign(const uint8_t sk[NQEDSK], const uint8_t *msg, size_t msglen,
             const uint8_t *ctx, size_t ctxlen, int ph,
             uint8_t sig[NQEDSIG]) {
  uint8_t h[64], r[64], k[64], pk[32], mh[64], out[64];
  const uint8_t *m = msg;
  size_t ml = msglen;
  int64_t x[64];
  int i, j, rc = args(msg, msglen, ctx, ctxlen);
  ge p;
  if (rc != NQOK) return rc;
  if (sk == NULL || sig == NULL) return NQEARG;
  if (ph) {
    nqs512(msg, msglen, mh);
    m = mh;
    ml = 64;
  }
  nqs512(sk, NQEDSK, h);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  gbase(p, h);
  gpack(pk, p);
  /* r = H(dom2 || prefix || M) mod L, R = [r]B */
  hdom(r, ph, ctx, ctxlen, h + 32, 32, NULL, 0, m, ml);
  red(r);
  gbase(p, r);
  gpack(out, p);
  /* k = H(dom2 || R || A || M) mod L, S = r + k a mod L */
  hdom(k, ph, ctx, ctxlen, out, 32, pk, 32, m, ml);
  red(k);
  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = r[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) x[i + j] += (int64_t)k[i] * (int64_t)h[j];
  }
  modl(out + 32, x);
  /* the whole signature at the end: sig may overlap msg */
  memcpy(sig, out, NQEDSIG);
  nqwipe(h, sizeof h);
  nqwipe(r, sizeof r);
  nqwipe(x, sizeof x);
  nqwipe(p, sizeof p);
  nqwipe(out, sizeof out);
  return NQOK;
}

int nqedvrfy(const uint8_t pk[NQEDPK], const uint8_t *msg, size_t msglen,
             const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t sig[NQEDSIG]) {
  uint8_t k[64], t[32], mh[64];
  const uint8_t *m = msg;
  size_t ml = msglen;
  int i, rc = args(msg, msglen, ctx, ctxlen);
  ge p, q;
  if (rc != NQOK) return rc;
  if (pk == NULL || sig == NULL) return NQEARG;
  if (unneg(q, pk) != 0 || !prime(q)) return NQEDEC;
  /* S < L, compared from the top byte down */
  for (i = 31; i >= 0; i--) {
    if (sig[32 + i] < cl[i]) break;
    if (sig[32 + i] > cl[i] || i == 0) return NQEVRFY;
  }
  if (ph) {
    nqs512(msg, msglen, mh);
    m = mh;
    ml = 64;
  }
  hdom(k, ph, ctx, ctxlen, sig, 32, pk, 32, m, ml);
  red(k);
  gmul(p, q, k);       /* [k](-A) */
  gbase(q, sig + 32);  /* [S]B */
  gadd(p, q);
  gpack(t, p);
  return memcmp(t, sig, 32) == 0 ? NQOK : NQEVRFY;
}
