/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* First-order masked ML-KEM decapsulation (FIPS 203 ML-KEM.Decaps).
 *
 * Every value that depends on the decapsulation key is held as two
 * shares, each uniform on its own: Boolean (x = x0 ^ x1) or arithmetic
 * mod q (a = a0 + a1). Linear steps act share by share; the non-linear
 * ones use fresh randomness so that no single intermediate value depends
 * on the secret.
 *
 *   s-hat     arithmetic shares, split afresh from dk on every call
 *   w         v - s.u, share by share (linear)
 *   m'        Boolean shares, by masked Compress_1 (Bos et al., TCHES
 *             2021)
 *   (K', r)   masked SHA3-512 of m' || h (masked Keccak, chi through
 *             Trichina's AND)
 *   K-bar     masked SHAKE256 of z || c, z split afresh
 *   c'        re-encryption under masked r: masked PRF, masked
 *             centred-binomial sampling, share-by-share arithmetic,
 *             m' converted to arithmetic shares
 *   c' == c   each coefficient of c' tested, in shares, against the
 *             public interval that compresses to c's value (Bhasin et
 *             al., TCHES 2021); the answers are ANDed in shares and the
 *             result is never unmasked
 *   K         K' or K-bar selected in shares, then unmasked
 *
 * Bitsliced Boolean arithmetic (32 coefficients to a word, Bronchain and
 * Cassiers, TCHES 2022): ripple-carry addition (Goubin 2001), comparison
 * with public constants by the sign of a masked subtraction, and
 * Boolean-to-arithmetic conversion by a masked modular subtraction of a
 * fresh arithmetic share.
 *
 * Pure C11: an opaque volatile copy keeps the compiler from recombining
 * shares. The register scrubbing and the hand-scheduled share-pair
 * assembly of the reference (which also cover the transition leakage
 * model on Cortex-M4) are not here: they are not ISO C. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/lk.h"
#include "hash/h.h"
#include "mlkem/mlkem.h"
#include "mlkem/ring.h"

/* ---- randomness: SHAKE128 seeded from nqrand ---- */

typedef struct {
  nqkctx x;
  uint8_t b[168];
  size_t pos;
} mrng;

static int rini(mrng *g) {
  uint8_t s[32];
  int rc = nqrand(s, sizeof s);
  nqshkini(&g->x, 128);
  nqkabs(&g->x, s, sizeof s);
  g->pos = sizeof g->b;
  nqwipe(s, sizeof s);
  return rc;
}

static uint32_t r32(mrng *g) {
  uint32_t v;
  if (g->pos + 4 > sizeof g->b) {
    nqksqz(&g->x, g->b, sizeof g->b);
    g->pos = 0;
  }
  v = NQLKZM(nqld32l(g->b + g->pos)); /* zero only in the TVLA control */
  g->pos += 4;
  return v;
}

static uint64_t r64(mrng *g) {
  const uint64_t h = r32(g);
  return (h << 32) | r32(g);
}

/* uniform on [0, q) from 64 random bits by multiply and shift, no loop
 * (distance from uniform below 2^-32) */
static int16_t rq(mrng *g) {
  const uint64_t r = r64(g);
  const uint64_t lo = ((r & 0xffffffffu) * NQMKQ) >> 32;
  const uint64_t hi = (r >> 32) * NQMKQ + lo;
  return (int16_t)(hi >> 32);
}

/* v + q when v < 0, without a branch */
static int16_t caddq(int32_t v) {
  const uint32_t m = nqmkop(0u - ((uint32_t)v >> 31));
  return (int16_t)(int32_t)((uint32_t)v + (NQMKQ & m));
}

static uint64_t op64(uint64_t x) {
  volatile uint64_t v = x;
  NQLK(x, NQLKKC);
  return v;
}

/* TVLA build: every coefficient of one share polynomial to the hook */
#ifdef NQTVLA
static void lkp(const nqmkpoly *a, int n) {
  int i, j;
  for (i = 0; i < n; i++) {
    for (j = 0; j < 256; j++) NQLK((uint16_t)a[i].c[j], NQLKSH);
  }
}
#define NQLKP(a, n) lkp((a), (n))
#else
#define NQLKP(a, n) ((void)0)
#endif

/* ---- share-pair gadgets: x[0], x[1] are the shares of one word ---- */

/* z = x & y, Trichina; all loads first, so z may alias x or y */
static void mand(uint32_t z[2], const uint32_t x[2], const uint32_t y[2],
                 uint32_t r) {
  const uint32_t x0 = x[0], x1 = x[1], y0 = y[0], y1 = y[1];
  uint32_t t = nqmkop(r ^ (x0 & y0));
  t = nqmkop(t ^ (x0 & y1));
  t = nqmkop(t ^ (x1 & y0));
  t = nqmkop(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

static void mxor(uint32_t z[2], const uint32_t x[2], const uint32_t y[2]) {
  const uint32_t a = nqmkop(x[0] ^ y[0]);
  const uint32_t b = nqmkop(x[1] ^ y[1]);
  z[0] = a;
  z[1] = b;
}

/* the complement flips one share */
static void mnot(uint32_t z[2], const uint32_t x[2]) {
  z[0] = nqmkop(~x[0]);
  z[1] = x[1];
}

/* ---- bitsliced numbers: bit b of 32 lanes in w[b][0] ^ w[b][1] ---- */

#define NB 14 /* two's-complement width: every value compared is < 2q */

typedef struct {
  uint32_t w[NB][2];
} bsl;

static void bsclr(bsl *z, int from) {
  int b;
  for (b = from; b < NB; b++) z->w[b][0] = z->w[b][1] = 0;
}

/* one share's 32 values, bitsliced */
static void slice(uint32_t o[NB], const int16_t v[32], int bits) {
  int b, j;
  for (b = 0; b < NB; b++) {
    uint32_t w = 0;
    if (b < bits) {
      for (j = 0; j < 32; j++) {
        w |= (((uint32_t)(uint16_t)v[j] >> b) & 1u) << j;
      }
    }
    o[b] = w;
  }
}

/* Boolean shares of one arithmetic share's values, re-masked: two
 * arithmetic shares never meet unmasked in one Boolean sharing */
static void bshare(bsl *o, const int16_t v[32], mrng *g) {
  uint32_t w[NB];
  int b;
  slice(w, v, NB);
  for (b = 0; b < NB; b++) {
    const uint32_t r = r32(g);
    o->w[b][0] = nqmkop(w[b] ^ r);
    o->w[b][1] = r;
  }
  nqwipe(w, sizeof w);
}

/* z = x + y mod 2^bits, ripple carry; z must not alias x or y */
static void sadd(bsl *z, const bsl *x, const bsl *y, int bits, mrng *g) {
  uint32_t c[2] = {0, 0}, p[2], h[2], t[2];
  int i;
  for (i = 0; i < bits; i++) {
    mxor(p, x->w[i], y->w[i]);
    mxor(z->w[i], p, c);
    if (i + 1 < bits) {
      mand(t, x->w[i], y->w[i], r32(g));
      mand(h, c, p, r32(g));
      mxor(c, t, h);
    }
  }
  bsclr(z, bits);
}

/* z = x + c mod 2^bits for public lane constants c */
static void saddp(bsl *z, const bsl *x, const int16_t c[32], int bits,
                  mrng *g) {
  uint32_t cw[NB], k[2] = {0, 0}, p[2], t[2], h[2];
  int i;
  slice(cw, c, bits);
  for (i = 0; i < bits; i++) {
    p[0] = nqmkop(x->w[i][0] ^ cw[i]);
    p[1] = x->w[i][1];
    mxor(z->w[i], p, k);
    if (i + 1 < bits) {
      NQLKKD(NQLKPB);
      t[0] = nqmkop(x->w[i][0] & cw[i]); /* x & c is linear */
      NQLKKD(NQLKPB);
      t[1] = nqmkop(x->w[i][1] & cw[i]);
      mand(h, k, p, r32(g));
      mxor(k, t, h);
    }
  }
  bsclr(z, bits);
}

/* lane-wise x < c (both below 2^(NB - 1)): the sign of x - c */
static void sless(uint32_t s[2], const bsl *x, const int16_t c[32],
                  mrng *g) {
  int16_t n[32];
  bsl d;
  int j;
  for (j = 0; j < 32; j++) n[j] = (int16_t)((1 << NB) - c[j]);
  saddp(&d, x, n, NB, g);
  s[0] = d.w[NB - 1][0];
  s[1] = d.w[NB - 1][1];
  nqwipe(&d, sizeof d);
}

static void slessc(uint32_t s[2], const bsl *x, int16_t c, mrng *g) {
  int16_t cs[32];
  int j;
  for (j = 0; j < 32; j++) cs[j] = c;
  sless(s, x, cs, g);
}

/* T = a0 + a1 in [0, 2q - 2] as Boolean shares */
static void ssum(bsl *t, const int16_t a0[32], const int16_t a1[32],
                 mrng *g) {
  bsl x, y;
  bshare(&x, a0, g);
  bshare(&y, a1, g);
  sadd(t, &x, &y, NB, g);
  nqwipe(&x, sizeof x);
  nqwipe(&y, sizeof y);
}

/* z = s ? x : y, lane-wise */
static void ssel(bsl *z, const uint32_t s[2], const bsl *x, const bsl *y,
                 mrng *g) {
  uint32_t d[2], t[2];
  int b;
  for (b = 0; b < NB; b++) {
    mxor(d, x->w[b], y->w[b]);
    mand(t, s, d, r32(g));
    mxor(z->w[b], y->w[b], t);
  }
}

/* T mod q for T in [0, 2q) */
static void sredq(bsl *o, const bsl *t, mrng *g) {
  int16_t nq[32];
  uint32_t s[2];
  bsl tm;
  int j;
  for (j = 0; j < 32; j++) nq[j] = (int16_t)((1 << NB) - NQMKQ);
  saddp(&tm, t, nq, NB, g); /* T - q */
  slessc(s, t, NQMKQ, g);   /* T < q: keep T */
  ssel(o, s, t, &tm, g);
  nqwipe(&tm, sizeof tm);
}

/* the AND of all 32 lanes, in bit 0 */
static void sall(uint32_t o[2], const uint32_t x[2], mrng *g) {
  uint32_t a[2], t[2];
  unsigned k;
  a[0] = x[0];
  a[1] = x[1];
  for (k = 16; k >= 1; k >>= 1) {
    t[0] = nqmkop(a[0] >> k);
    t[1] = nqmkop(a[1] >> k);
    mand(a, a, t, r32(g));
  }
  o[0] = a[0] & 1u;
  o[1] = a[1] & 1u;
}

/* masked Compress_1: bit 1 exactly when x in [833, 2496]; with T the
 * share sum, x is T or T - q, so [833 <= T < 2497] ^ [4162 <= T < 5826] */
static void sdec1(uint32_t b[2], const int16_t a0[32],
                  const int16_t a1[32], mrng *g) {
  static const int16_t kc[4] = {833, 2497, 4162, 5826};
  uint32_t l[4][2], n[2], p[2], q[2];
  bsl t;
  int i;
  ssum(&t, a0, a1, g);
  for (i = 0; i < 4; i++) slessc(l[i], &t, kc[i], g);
  mnot(n, l[0]);
  mand(p, n, l[1], r32(g));
  mnot(n, l[2]);
  mand(q, n, l[3], r32(g));
  mxor(b, p, q);
  nqwipe(&t, sizeof t);
  nqwipe(l, sizeof l);
}

/* lane j: (x_j - lo_j) mod q < w_j, for shares in [0, q), 0 < w <= q */
static void sint(uint32_t o[2], const int16_t a0[32], const int16_t a1[32],
                 const int16_t lo[32], const int16_t w[32], mrng *g) {
  int16_t s0[32], cq[32];
  uint32_t a[2], b[2], c[2], d[2];
  bsl t;
  int j;
  for (j = 0; j < 32; j++) {
    s0[j] = caddq((int32_t)a0[j] - (int32_t)lo[j]);
    cq[j] = (int16_t)(NQMKQ + w[j]);
  }
  ssum(&t, s0, a1, g);
  sless(a, &t, w, g);      /* T < w */
  slessc(b, &t, NQMKQ, g); /* T < q */
  sless(c, &t, cq, g);     /* T < q + w */
  mnot(b, b);
  mand(d, b, c, r32(g));
  mxor(o, a, d);
  nqwipe(s0, sizeof s0);
  nqwipe(&t, sizeof t);
}

/* Boolean (values below q) to arithmetic shares mod q: a1 fresh,
 * a0 = (v - a1) mod q computed in the Boolean domain, then recombined
 * (uniform whatever v is) */
static void sb2a(int16_t a0[32], int16_t a1[32], const bsl *v, mrng *g) {
  int16_t r[32], nr[32];
  bsl m, y, z;
  int j, b;
  for (j = 0; j < 32; j++) {
    r[j] = rq(g);
    nr[j] = (int16_t)(NQMKQ - r[j]); /* in [1, q] */
  }
  bshare(&m, nr, g);
  sadd(&y, v, &m, NB, g); /* v + q - r in [1, 2q) */
  sredq(&z, &y, g);
  for (j = 0; j < 32; j++) {
    uint32_t val = 0;
    for (b = 0; b < NB; b++) {
      val |= (((z.w[b][0] ^ z.w[b][1]) >> j) & 1u) << b;
    }
    a0[j] = (int16_t)val;
  }
  for (j = 0; j < 32; j++) a1[j] = r[j];
  nqwipe(r, sizeof r);
  nqwipe(nr, sizeof nr);
  nqwipe(&m, sizeof m);
  nqwipe(&y, sizeof y);
  nqwipe(&z, sizeof z);
}

/* masked SamplePolyCBD_eta for coefficients l0 .. l0 + 31; b0 ^ b1 is
 * the PRF output */
static void scbd(int16_t a0[32], int16_t a1[32], const uint8_t *b0,
                 const uint8_t *b1, int l0, int eta, mrng *g) {
  int16_t c[32];
  bsl ax, ay, bit, sum, ny, v1, v;
  int k, s, j, b;
  memset(&ax, 0, sizeof ax);
  memset(&ay, 0, sizeof ay);
  memset(&bit, 0, sizeof bit);
  for (k = 0; k < 2 * eta; k++) {
    bsl *acc = k < eta ? &ax : &ay;
    for (s = 0; s < 2; s++) {
      const uint8_t *buf = s ? b1 : b0;
      uint32_t w = 0;
      for (j = 0; j < 32; j++) {
        const size_t pos =
            (size_t)(2 * eta) * (size_t)(l0 + j) + (size_t)k;
        w |= (uint32_t)((buf[pos >> 3] >> (pos & 7)) & 1u) << j;
      }
      bit.w[0][s] = w;
    }
    sadd(&sum, acc, &bit, 2, g);
    for (b = 0; b < 2; b++) {
      acc->w[b][0] = sum.w[b][0];
      acc->w[b][1] = sum.w[b][1];
    }
  }
  /* x - y + eta = x + ~y + 1 + eta in 4-bit arithmetic */
  memset(&ny, 0, sizeof ny);
  for (b = 0; b < 4; b++) mnot(ny.w[b], ay.w[b]);
  sadd(&v1, &ax, &ny, 4, g);
  for (j = 0; j < 32; j++) c[j] = (int16_t)(eta + 1);
  saddp(&v, &v1, c, 4, g); /* in [0, 2 eta] */
  sb2a(a0, a1, &v, g);
  for (j = 0; j < 32; j++) a0[j] = caddq((int32_t)a0[j] - eta);
  nqwipe(&ax, sizeof ax);
  nqwipe(&ay, sizeof ay);
  nqwipe(&bit, sizeof bit);
  nqwipe(&sum, sizeof sum);
  nqwipe(&ny, sizeof ny);
  nqwipe(&v1, sizeof v1);
  nqwipe(&v, sizeof v);
}

/* ---- masked Keccak-f[1600] and sponge ---- */

static const uint64_t krc[24] = {
    0x0000000000000001u, 0x0000000000008082u, 0x800000000000808au,
    0x8000000080008000u, 0x000000000000808bu, 0x0000000080000001u,
    0x8000000080008081u, 0x8000000000008009u, 0x000000000000008au,
    0x0000000000000088u, 0x0000000080008009u, 0x000000008000000au,
    0x000000008000808bu, 0x800000000000008bu, 0x8000000000008089u,
    0x8000000000008003u, 0x8000000000008002u, 0x8000000000000080u,
    0x000000000000800au, 0x800000008000000au, 0x8000000080008081u,
    0x8000000000008080u, 0x0000000080000001u, 0x8000000080008008u};

static const unsigned krho[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55,
                                  20, 3,  10, 43, 25, 39, 41, 45, 15,
                                  21, 8,  18, 2,  61, 56, 14};

static uint64_t rotl(uint64_t x, unsigned n) {
  return n ? (x << n) | (x >> (64 - n)) : x;
}

/* theta, rho, pi on one share (linear) */
static void klin(uint64_t a[25]) {
  uint64_t c[5], b[25];
  int x, y;
  for (x = 0; x < 5; x++) {
    c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
  }
  for (x = 0; x < 5; x++) {
    const uint64_t d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
    for (y = 0; y < 25; y += 5) a[y + x] ^= d;
  }
  for (x = 0; x < 5; x++) {
    for (y = 0; y < 5; y++) {
      b[y + 5 * ((2 * x + 3 * y) % 5)] =
          rotl(a[x + 5 * y], krho[x + 5 * y]);
    }
  }
  memcpy(a, b, sizeof b);
  nqwipe(c, sizeof c);
  nqwipe(b, sizeof b);
}

/* z = ~x & y on 64-bit shares, Trichina */
static void mandn64(uint64_t z[2], uint64_t x0, uint64_t x1, uint64_t y0,
                    uint64_t y1, uint64_t r) {
  uint64_t t;
  x0 = op64(~x0);
  t = op64(r ^ (x0 & y0));
  t = op64(t ^ (x0 & y1));
  t = op64(t ^ (x1 & y0));
  t = op64(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

static void kfm(uint64_t s0[25], uint64_t s1[25], mrng *g) {
  uint64_t o0[5], o1[5], t[2];
  int r, y, x;
  for (r = 0; r < 24; r++) {
    klin(s0);
    klin(s1);
    for (y = 0; y < 25; y += 5) {
      /* chi: a ^ (~b & c) */
      for (x = 0; x < 5; x++) {
        const int i1 = y + (x + 1) % 5, i2 = y + (x + 2) % 5;
        mandn64(t, s0[i1], s1[i1], s0[i2], s1[i2], r64(g));
        o0[x] = op64(s0[y + x] ^ t[0]);
        o1[x] = op64(s1[y + x] ^ t[1]);
      }
      memcpy(s0 + y, o0, sizeof o0);
      memcpy(s1 + y, o1, sizeof o1);
    }
    s0[0] ^= krc[r]; /* iota, into one share */
  }
  nqwipe(o0, sizeof o0);
  nqwipe(o1, sizeof o1);
  nqwipe(t, sizeof t);
}

/* in0 ^ in1 is the input (in1 NULL: share 1 is zero), out0 ^ out1 the
 * output; rate in bytes, dom the padding byte (0x06 SHA-3, 0x1f SHAKE) */
static void msponge(uint8_t *out0, uint8_t *out1, size_t outlen,
                    const uint8_t *in0, const uint8_t *in1, size_t inlen,
                    size_t rate, uint8_t dom, mrng *g) {
  uint64_t s0[25], s1[25];
  size_t off = 0, pos, i;
  memset(s0, 0, sizeof s0);
  memset(s1, 0, sizeof s1);
  for (;;) {
    const size_t take = inlen - off < rate ? inlen - off : rate;
    for (i = 0; i < take; i++) {
      s0[i / 8] ^= (uint64_t)in0[off + i] << (8 * (i % 8));
    }
    if (in1 != NULL) {
      for (i = 0; i < take; i++) {
        s1[i / 8] ^= (uint64_t)in1[off + i] << (8 * (i % 8));
      }
    }
    off += take;
    if (take < rate) {
      s0[take / 8] ^= (uint64_t)dom << (8 * (take % 8));
      s0[(rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((rate - 1) % 8));
      kfm(s0, s1, g);
      break;
    }
    kfm(s0, s1, g);
  }
  for (pos = 0;;) {
    const size_t take = outlen - pos < rate ? outlen - pos : rate;
    for (i = 0; i < take; i++) {
      out0[pos + i] = (uint8_t)(s0[i / 8] >> (8 * (i % 8)));
    }
    for (i = 0; i < take; i++) {
      out1[pos + i] = (uint8_t)(s1[i / 8] >> (8 * (i % 8)));
    }
    pos += take;
    if (pos >= outlen) break;
    kfm(s0, s1, g);
  }
  nqwipe(s0, sizeof s0);
  nqwipe(s1, sizeof s1);
}

/* ---- masked decapsulation ---- */

/* everything the masked path holds, wiped together */
typedef struct {
  nqmkpoly s0[NQMKKX], s1[NQMKKX], u[NQMKKX], t[NQMKKX];
  nqmkpoly a[NQMKKX * NQMKKX];
  nqmkpoly r0[NQMKKX], r1[NQMKKX], e0[NQMKKX], e1[NQMKKX];
  nqmkpoly u0[NQMKKX], u1[NQMKKX];
  nqmkpoly v, w0, w1, f0, f1, v0, v1, raw, c;
  uint32_t mw[8][2];
  uint8_t m0[32], m1[32], gi0[64], gi1[64], g0[64], g1[64];
  uint8_t kb0[32], kb1[32], pi0[33], pi1[33], pb0[192], pb1[192];
  uint8_t j0[32 + NQMKCTX], j1[32 + NQMKCTX];
  int16_t lo[2048], wd[2048], l[32], wl[32], c0[32], c1[32];
  uint32_t all[2], o[2], ok[2], msk[2], kp[2], kq[2], d[2], x[2];
  bsl mb;
} mdst;

/* the cyclic interval of canonical x with Compress_d(x) == c, every c */
static void cint(int16_t *lo, int16_t *w, int d) {
  const int n = 1 << d;
  int c, x;
  for (c = 0; c < n; c++) lo[c] = w[c] = 0;
  for (x = 0; x < NQMKQ; x++) {
    const uint16_t cc = nqmkcp((int16_t)x, d);
    const uint16_t pv = nqmkcp((int16_t)((x + NQMKQ - 1) % NQMKQ), d);
    w[cc]++;
    if (pv != cc) lo[cc] = (int16_t)x;
  }
}

static void mprf(nqmkpoly *p0, nqmkpoly *p1, mdst *s, uint8_t n, int eta,
                 mrng *g) {
  int q;
  memcpy(s->pi0, s->g0 + 32, 32);
  memcpy(s->pi1, s->g1 + 32, 32);
  s->pi0[32] = n;
  s->pi1[32] = 0;
  msponge(s->pb0, s->pb1, (size_t)64 * (size_t)eta, s->pi0, s->pi1, 33,
          136, 0x1f, g);
  for (q = 0; q < 8; q++) {
    scbd(p0->c + 32 * q, p1->c + 32 * q, s->pb0, s->pb1, 32 * q, eta, g);
  }
}

/* o = AND over lanes of [Compress_d(x) == c] for 32 coefficients */
static void mcmp(mdst *s, const int16_t *x0, const int16_t *x1,
                 const int16_t *cv, mrng *g) {
  int j;
  for (j = 0; j < 32; j++) {
    s->l[j] = s->lo[cv[j]];
    s->wl[j] = s->wd[cv[j]];
  }
  sint(s->o, x0, x1, s->l, s->wl, g);
  mand(s->all, s->all, s->o, r32(g));
}

static void mdec(const nqmkprm *p, const uint8_t *dk, const uint8_t *ct,
                 uint8_t *ss, mdst *s, mrng *g) {
  const int k = p->k;
  const uint8_t *ek = dk + 384 * k, *h = ek + p->ek, *z = h + 32;
  int i, j, q, bad;
  uint8_t n = 0;

  /* 1. s-hat, split into fresh arithmetic shares */
  NQLKST(1);
  for (i = 0; i < k; i++) {
    nqmkbd(&s->raw, dk + 384 * i, 12);
    for (j = 0; j < 256; j++) s->s0[i].c[j] = rq(g);
    for (j = 0; j < 256; j++) {
      const int16_t v = nqmkps(nqmkbr(s->raw.c[j]));
      NQLK((uint16_t)v, NQLKUN); /* the stored key is not masked */
      s->s1[i].c[j] = caddq((int32_t)v - s->s0[i].c[j]);
    }
  }
  NQLKP(s->s0, k);
  NQLKP(s->s1, k);

  /* 2. the public ciphertext */
  for (i = 0; i < k; i++) {
    nqmkbd(&s->u[i], ct + 32 * p->du * i, p->du);
    for (j = 0; j < 256; j++) {
      s->u[i].c[j] = nqmkdc((uint16_t)s->u[i].c[j], p->du);
    }
    nqmkntt(&s->u[i]);
  }
  nqmkbd(&s->v, ct + 32 * p->du * k, p->dv);
  for (j = 0; j < 256; j++) s->v.c[j] = nqmkdc((uint16_t)s->v.c[j], p->dv);

  /* 3. w = v - s.u, share by share */
  NQLKST(3);
  nqmkdot(&s->w0, s->s0, s->u, k);
  nqmkint(&s->w0);
  nqmksub(&s->w0, &s->v, &s->w0);
  nqmkcan(&s->w0);
  nqmkdot(&s->w1, s->s1, s->u, k);
  nqmkint(&s->w1);
  for (j = 0; j < 256; j++) s->w1.c[j] = (int16_t)-s->w1.c[j];
  nqmkcan(&s->w1);
  NQLKP(&s->w0, 1);
  NQLKP(&s->w1, 1);

  /* 4. m' = Compress_1(w), Boolean shares, 32 bits a word */
  NQLKST(4);
  for (q = 0; q < 8; q++) {
    sdec1(s->mw[q], s->w0.c + 32 * q, s->w1.c + 32 * q, g);
  }
  for (q = 0; q < 8; q++) {
    for (j = 0; j < 4; j++) {
      s->m0[4 * q + j] = (uint8_t)(s->mw[q][0] >> (8 * j));
    }
  }
  for (q = 0; q < 8; q++) {
    for (j = 0; j < 4; j++) {
      s->m1[4 * q + j] = (uint8_t)(s->mw[q][1] >> (8 * j));
    }
  }

  /* 5. (K', r) = G(m' || h) */
  NQLKST(5);
  memcpy(s->gi0, s->m0, 32);
  memcpy(s->gi0 + 32, h, 32);
  memcpy(s->gi1, s->m1, 32);
  memset(s->gi1 + 32, 0, 32);
  msponge(s->g0, s->g1, 64, s->gi0, s->gi1, 64, 72, 0x06, g);

  /* 6. K-bar = J(z || c), z split afresh */
  NQLKST(6);
  for (i = 0; i < 32; i++) s->j1[i] = (uint8_t)r32(g);
  for (i = 0; i < 32; i++) {
    NQLK(z[i], NQLKUN);
    s->j0[i] = (uint8_t)(z[i] ^ s->j1[i]);
  }
  memcpy(s->j0 + 32, ct, p->ct);
  memset(s->j1 + 32, 0, p->ct);
  msponge(s->kb0, s->kb1, 32, s->j0, s->j1, 32 + p->ct, 136, 0x1f, g);

  /* 7. re-encryption of m' under r, in shares */
  NQLKST(7);
  bad = nqmkekd(s->t, ek, k); /* ek is public */
  nqmkmat(s->a, ek + 384 * k, k, 1);
  for (i = 0; i < k; i++) mprf(&s->r0[i], &s->r1[i], s, n++, p->eta1, g);
  for (i = 0; i < k; i++) mprf(&s->e0[i], &s->e1[i], s, n++, 2, g);
  mprf(&s->f0, &s->f1, s, n++, 2, g);
  for (i = 0; i < k; i++) nqmkntt(&s->r0[i]);
  for (i = 0; i < k; i++) nqmkntt(&s->r1[i]);
  for (i = 0; i < k; i++) {
    nqmkdot(&s->u0[i], &s->a[i * NQMKKX], s->r0, k);
    nqmkint(&s->u0[i]);
    nqmkadd(&s->u0[i], &s->u0[i], &s->e0[i]);
    nqmkcan(&s->u0[i]);
  }
  for (i = 0; i < k; i++) {
    nqmkdot(&s->u1[i], &s->a[i * NQMKKX], s->r1, k);
    nqmkint(&s->u1[i]);
    nqmkadd(&s->u1[i], &s->u1[i], &s->e1[i]);
    nqmkcan(&s->u1[i]);
  }
  nqmkdot(&s->v0, s->t, s->r0, k);
  nqmkint(&s->v0);
  nqmkadd(&s->v0, &s->v0, &s->f0);
  nqmkdot(&s->v1, s->t, s->r1, k);
  nqmkint(&s->v1);
  nqmkadd(&s->v1, &s->v1, &s->f1);
  /* + Decompress_1(m'): m' to arithmetic shares, times (q + 1) / 2 */
  for (q = 0; q < 8; q++) {
    memset(&s->mb, 0, sizeof s->mb);
    s->mb.w[0][0] = s->mw[q][0];
    s->mb.w[0][1] = s->mw[q][1];
    sb2a(s->c0, s->c1, &s->mb, g);
    for (j = 0; j < 32; j++) {
      const int16_t a = (int16_t)nqmkmq((uint32_t)s->c0[j] * 1665u);
      s->v0.c[32 * q + j] = nqmkbr((int16_t)(s->v0.c[32 * q + j] + a));
    }
    for (j = 0; j < 32; j++) {
      const int16_t a = (int16_t)nqmkmq((uint32_t)s->c1[j] * 1665u);
      s->v1.c[32 * q + j] = nqmkbr((int16_t)(s->v1.c[32 * q + j] + a));
    }
  }
  nqmkcan(&s->v0);
  nqmkcan(&s->v1);
  NQLKP(s->u0, k);
  NQLKP(s->u1, k);
  NQLKP(&s->v0, 1);
  NQLKP(&s->v1, 1);

  /* 8. c' == c, compared decompressed and in shares */
  NQLKST(8);
  s->all[0] = 0xffffffffu;
  s->all[1] = 0;
  cint(s->lo, s->wd, p->du);
  for (i = 0; i < k; i++) {
    nqmkbd(&s->c, ct + 32 * p->du * i, p->du);
    for (q = 0; q < 8; q++) {
      mcmp(s, s->u0[i].c + 32 * q, s->u1[i].c + 32 * q, s->c.c + 32 * q,
           g);
    }
  }
  cint(s->lo, s->wd, p->dv);
  nqmkbd(&s->c, ct + 32 * p->du * k, p->dv);
  for (q = 0; q < 8; q++) {
    mcmp(s, s->v0.c + 32 * q, s->v1.c + 32 * q, s->c.c + 32 * q, g);
  }
  sall(s->ok, s->all, g);
  /* a non-canonical ek never re-encrypts (public) */
  s->ok[0] &= (uint32_t)bad - 1u;
  s->ok[1] &= (uint32_t)bad - 1u;

  /* 9. K = ok ? K' : K-bar, in shares, then unmasked */
  NQLKST(9);
  s->msk[0] = nqmkop(0u - (s->ok[0] & 1u));
  s->msk[1] = nqmkop(0u - (s->ok[1] & 1u));
  for (i = 0; i < 8; i++) {
    uint32_t out;
    s->kp[0] = nqld32l(s->g0 + 4 * i);
    s->kp[1] = nqld32l(s->g1 + 4 * i);
    s->kq[0] = nqld32l(s->kb0 + 4 * i);
    s->kq[1] = nqld32l(s->kb1 + 4 * i);
    mxor(s->d, s->kp, s->kq);
    mand(s->x, s->msk, s->d, r32(g));
    mxor(s->d, s->kq, s->x);
    out = s->d[0] ^ s->d[1]; /* the shared secret, the output */
    NQLK(out, NQLKOUT);
    nqst32l(ss + 4 * i, out);
  }
}

int nqmkdec(int k, const uint8_t *dk, size_t dklen, const uint8_t *ct,
            size_t ctlen, uint8_t *ss, size_t sslen) {
  nqmkprm p;
  mdst s;
  mrng g;
  int rc = NQOK;
  if (nqmkpar(k, &p) != NQOK || dk == NULL || ct == NULL || ss == NULL) {
    return NQEARG;
  }
  if (sslen < NQMKSS) {
    rc = NQEBUF;
  } else if (ctlen != p.ct || nqmkdkc(k, dk, dklen) != NQOK) {
    rc = NQEDEC;
  } else {
    rc = rini(&g);
  }
  if (rc == NQOK) {
    mdec(&p, dk, ct, ss, &s, &g);
    nqwipe(&s, sizeof s);
  } else {
    memset(ss, 0, sslen);
  }
  nqwipe(&g, sizeof g);
  return rc;
}
