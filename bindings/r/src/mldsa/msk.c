/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* First-order masked ML-DSA signing (FIPS 204 ML-DSA.Sign_internal), two
 * shares.
 *
 * s1, s2, t0 and K are split into fresh arithmetic (mod q) or Boolean
 * shares as soon as they are unpacked. rho'' = H(K || rnd || mu) and y =
 * ExpandMask(rho'', kappa) come out of a masked SHAKE256 (Keccak-f with
 * chi through Trichina's AND) as Boolean shares, which are converted to
 * arithmetic shares mod q. The linear algebra (NTT, A y, c s1, c s2,
 * c t0) runs on each share alone. The non-linear steps (HighBits, the
 * norm checks, the hint) add the two shares inside the Boolean domain,
 * bitsliced 32 coefficients to a word (a ripple-carry adder over Boolean
 * shares, Goubin 2001; Bronchain and Cassiers, TCHES 2022), and compare
 * against public constants. Unmasked are only values the algorithm
 * publishes or a bit of control flow it already reveals: w1 = HighBits(w)
 * (hashed into c~, recomputed by every verifier), the three rejection
 * decisions as one bit each, HighBits(w - c s2 + c t0) (from which the
 * hint follows, also recomputed by the verifier), and z once accepted.
 *
 * The output is byte-identical to nqmdspl (the unmasked signer): the same
 * rho'', y and accept / reject decisions; the tests compare the two.
 *
 * The masks come from the operating system's CSPRNG, 4 KiB at a time.
 * This is ISO C: an opaque copy through a volatile object stops the
 * compiler from recombining shares. Register-level scrubbing between the
 * share passes (assembly in the reference this follows) is outside ISO C
 * and not done here. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"
#include "mldsa/md.h"
#include "mldsa/mldsa.h"

#define MQ NQMDQ
#define MB 25 /* width of the bitsliced arithmetic: 2q < 2^24 */
#define MX 26

/* ---- randomness ---- */

typedef struct {
  uint8_t buf[4096];
  size_t pos;
  int fail;
} rng;

static uint32_t ru(rng *r) {
  uint32_t v;
  if (r->pos + 4 > sizeof r->buf) {
    if (nqrand(r->buf, sizeof r->buf) != NQOK) r->fail = 1;
    r->pos = 0;
  }
  v = (uint32_t)r->buf[r->pos] | ((uint32_t)r->buf[r->pos + 1] << 8) |
      ((uint32_t)r->buf[r->pos + 2] << 16) |
      ((uint32_t)r->buf[r->pos + 3] << 24);
  r->pos += 4;
  return v;
}

/* uniform on [0, q) up to q / 2^64 + 2^-32, by multiply-and-shift: no
 * loop, so the time never depends on the randomness */
static int32_t rq(rng *r) {
  uint64_t h = ru(r), l = ru(r);
  uint64_t lo = (l * (uint64_t)MQ) >> 32;
  uint64_t hi = h * (uint64_t)MQ + lo;
  return (int32_t)(hi >> 32);
}

/* ---- share primitives ---- */

/* an opaque copy: the compiler cannot see through it to recombine */
static uint32_t opq(uint32_t x) {
  volatile uint32_t v = x;
  return v;
}

/* v + q when v < 0, through a mask (no conditional) */
static int32_t caddm(int32_t v) {
  uint32_t m = opq(0u - ((uint32_t)v >> 31));
  return (int32_t)((uint32_t)v + ((uint32_t)MQ & m));
}

static int32_t canon(int32_t a) {
  return nqmdcq(nqmdrd(a));
}

/* z = x & y, Trichina; z may alias x or y */
static void and2(uint32_t z[2], const uint32_t x[2], const uint32_t y[2],
                 uint32_t r) {
  uint32_t x0 = x[0], x1 = x[1], y0 = y[0], y1 = y[1];
  uint32_t t = opq(r ^ (x0 & y0));
  t = opq(t ^ (x0 & y1));
  t = opq(t ^ (x1 & y0));
  t = opq(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

static void xor2(uint32_t z[2], const uint32_t x[2], const uint32_t y[2]) {
  uint32_t a = x[0] ^ y[0], b;
  z[0] = opq(a);
  b = x[1] ^ y[1];
  z[1] = opq(b);
}

static void not2(uint32_t z[2], const uint32_t x[2]) {
  z[0] = opq(~x[0]);
  z[1] = x[1];
}

/* ---- bitsliced Boolean numbers: bit b of 32 lanes in w[b][share] ---- */

typedef struct {
  uint32_t w[MX][2];
} bs;

/* one share's 32 values, bitsliced */
static void bsl(uint32_t out[MX], const int32_t v[32], int bits) {
  int b, j;
  for (b = 0; b < bits; b++) {
    uint32_t w = 0;
    for (j = 0; j < 32; j++) {
      w |= (((uint32_t)v[j] >> b) & 1u) << j;
    }
    out[b] = w;
  }
  for (b = bits; b < MX; b++) out[b] = 0;
}

/* fresh Boolean shares of one arithmetic share's values */
static void bsh(bs *o, const int32_t v[32], rng *r) {
  uint32_t w[MX];
  int b;
  bsl(w, v, MB);
  for (b = 0; b < MB; b++) {
    uint32_t m = ru(r);
    o->w[b][0] = opq(w[b] ^ m);
    o->w[b][1] = m;
  }
  for (b = MB; b < MX; b++) o->w[b][0] = o->w[b][1] = 0;
  nqwipe(w, sizeof w);
}

static void bclr(bs *z, int bits) {
  int i;
  for (i = bits; i < MX; i++) z->w[i][0] = z->w[i][1] = 0;
}

/* z = x + y mod 2^bits; z must not alias x or y */
static void sadd(bs *z, const bs *x, const bs *y, int bits, rng *r) {
  uint32_t c[2] = {0, 0}, p[2], g[2], h[2];
  int i;
  for (i = 0; i < bits; i++) {
    xor2(p, x->w[i], y->w[i]);
    xor2(z->w[i], p, c);
    if (i + 1 < bits) {
      and2(g, x->w[i], y->w[i], ru(r));
      and2(h, c, p, ru(r));
      xor2(c, g, h);
    }
  }
  bclr(z, bits);
}

/* z = x + c mod 2^bits, c public per lane; z must not alias x */
static void saddp(bs *z, const bs *x, const int32_t c[32], int bits,
                  rng *r) {
  uint32_t cw[MX], k[2] = {0, 0}, p[2], g[2], h[2];
  int i;
  bsl(cw, c, bits);
  for (i = 0; i < bits; i++) {
    p[0] = opq(x->w[i][0] ^ cw[i]);
    p[1] = opq(x->w[i][1]);
    xor2(z->w[i], p, k);
    if (i + 1 < bits) {
      g[0] = opq(x->w[i][0] & cw[i]);
      g[1] = opq(x->w[i][1] & cw[i]);
      and2(h, k, p, ru(r));
      xor2(k, g, h);
    }
  }
  bclr(z, bits);
}

/* s = [x < c] per lane (bit j), for x and public c below 2^(MB - 1) */
static void sless(uint32_t s[2], const bs *x, const int32_t c[32], rng *r) {
  int32_t neg[32];
  bs d;
  int j;
  for (j = 0; j < 32; j++) neg[j] = (1 << MB) - c[j];
  saddp(&d, x, neg, MB, r);
  s[0] = opq(d.w[MB - 1][0]);
  s[1] = opq(d.w[MB - 1][1]);
  nqwipe(&d, sizeof d);
}

static void sless1(uint32_t s[2], const bs *x, int32_t c, rng *r) {
  int32_t cs[32];
  int j;
  for (j = 0; j < 32; j++) cs[j] = c;
  sless(s, x, cs, r);
}

/* T = a0 + a1 (in [0, 2q - 2]) as Boolean shares */
static void ssum(bs *t, const int32_t a0[32], const int32_t a1[32],
                 rng *r) {
  bs x, y;
  bsh(&x, a0, r);
  bsh(&y, a1, r);
  sadd(t, &x, &y, MB, r);
  nqwipe(&x, sizeof x);
  nqwipe(&y, sizeof y);
}

/* z = s ? x : y per lane */
static void ssel(bs *z, const uint32_t s[2], const bs *x, const bs *y,
                 rng *r) {
  uint32_t d[2], t[2];
  int b;
  for (b = 0; b < MB; b++) {
    xor2(d, x->w[b], y->w[b]);
    and2(t, s, d, ru(r));
    xor2(z->w[b], y->w[b], t);
  }
  bclr(z, MB);
}

/* T mod q for T in [0, 2q) */
static void sredq(bs *o, const bs *t, rng *r) {
  int32_t nq[32];
  uint32_t s[2];
  bs tm;
  int j;
  for (j = 0; j < 32; j++) nq[j] = (1 << MB) - MQ;
  saddp(&tm, t, nq, MB, r);
  sless1(s, t, MQ, r);
  ssel(o, s, t, &tm, r);
  nqwipe(&tm, sizeof tm);
}

/* bit 0 of o: the AND of the 32 lanes of x */
static void sall(uint32_t o[2], const uint32_t x[2], rng *r) {
  uint32_t a[2], t[2];
  unsigned k;
  a[0] = x[0];
  a[1] = x[1];
  for (k = 16; k >= 1; k >>= 1) {
    t[0] = opq(a[0] >> k);
    t[1] = opq(a[1] >> k);
    and2(a, a, t, ru(r));
  }
  o[0] = opq(a[0] & 1u);
  o[1] = opq(a[1] & 1u);
}

/* lane j: (x_j - lo_j) mod q < w_j, x shared as a0 + a1 in [0, q) */
static void sinint(uint32_t o[2], const int32_t a0[32], const int32_t a1[32],
                   const int32_t lo[32], const int32_t w[32], rng *r) {
  int32_t s0[32], cqw[32];
  uint32_t a[2], b[2], c[2], nb[2], d[2];
  bs t;
  int j;
  for (j = 0; j < 32; j++) s0[j] = caddm(a0[j] - lo[j]);
  ssum(&t, s0, a1, r);
  for (j = 0; j < 32; j++) cqw[j] = MQ + w[j];
  sless(a, &t, w, r);     /* T < w */
  sless1(b, &t, MQ, r);   /* T < q */
  sless(c, &t, cqw, r);   /* T < q + w */
  not2(nb, b);
  and2(d, nb, c, ru(r));
  xor2(o, a, d);
  nqwipe(s0, sizeof s0);
  nqwipe(&t, sizeof t);
}

/* Boolean shares of values below q to arithmetic shares mod q: a1 is
 * fresh, a0 = (v - a1) mod q is formed in the Boolean domain, and only
 * then recombined (it is uniform whatever v is) */
static void b2a(int32_t a0[32], int32_t a1[32], const bs *v, rng *r) {
  int32_t rr[32], nr[32];
  bs m, y, z;
  int j, b;
  for (j = 0; j < 32; j++) {
    rr[j] = rq(r);
    nr[j] = MQ - rr[j];
  }
  bsh(&m, nr, r);
  sadd(&y, v, &m, MB, r);
  sredq(&z, &y, r);
  for (j = 0; j < 32; j++) {
    uint32_t val = 0;
    for (b = 0; b < MB; b++) {
      val |= (((z.w[b][0] ^ z.w[b][1]) >> j) & 1u) << b;
    }
    a0[j] = (int32_t)val;
  }
  for (j = 0; j < 32; j++) a1[j] = rr[j];
  nqwipe(rr, sizeof rr);
  nqwipe(nr, sizeof nr);
  nqwipe(&m, sizeof m);
  nqwipe(&y, sizeof y);
  nqwipe(&z, sizeof z);
}

/* ---- ML-DSA gadgets ---- */

/* b' of 32 lanes of a = a0 + a1 mod q: a + gamma2 - 1, less q - 1 when
 * that reaches q - 1, so HighBits(a) = floor(b' / (2 gamma2)) for every
 * a, the interval Decompose folds to 0 included */
static void bprime(bs *bp, const int32_t *a0, const int32_t *a1,
                   int32_t g2, rng *r) {
  bs t, a, b, bm;
  int32_t c[32], nc[32];
  uint32_t s[2];
  int j;
  ssum(&t, a0, a1, r);
  sredq(&a, &t, r);
  for (j = 0; j < 32; j++) {
    c[j] = g2 - 1;
    nc[j] = (1 << MB) - (MQ - 1);
  }
  saddp(&b, &a, c, MB, r);
  saddp(&bm, &b, nc, MB, r);
  sless1(s, &b, MQ - 1, r);
  ssel(bp, s, &b, &bm, r);
  nqwipe(&t, sizeof t);
  nqwipe(&a, sizeof a);
  nqwipe(&b, sizeof b);
  nqwipe(&bm, sizeof bm);
}

/* HighBits per lane, by a binary search whose comparisons each reveal
 * one bit of the (public) result and nothing else */
static void revhb(int32_t *w1, const bs *bp, int32_t g2, rng *r) {
  const int32_t high = (MQ - 1) / (2 * g2);
  int32_t p, thr[32];
  int j;
  for (j = 0; j < 32; j++) w1[j] = 0;
  for (p = 32; p >= 1; p >>= 1) {
    uint32_t s[2], ge;
    for (j = 0; j < 32; j++) {
      int32_t c = w1[j] + p;
      thr[j] = c <= high - 1 ? 2 * c * g2 : (1 << (MB - 1)) - 1;
    }
    sless(s, bp, thr, r);
    ge = ~(s[0] ^ s[1]); /* bits of w1 */
    NQMDPUB(&ge, sizeof ge);
    for (j = 0; j < 32; j++) w1[j] += (int32_t)((ge >> j) & 1u) * p;
  }
}

/* lane j set when LowBits(v) lies inside +-(gamma2 - beta - 1), given
 * HighBits(v) = w1 (the r0 check); fails when HighBits(v) differs */
static void lowok(uint32_t o[2], const bs *bp, const int32_t *w1,
                  int32_t g2, int32_t beta, rng *r) {
  int32_t lo[32], hi[32];
  uint32_t a[2], b[2], na[2];
  int j;
  for (j = 0; j < 32; j++) {
    int32_t base = 2 * g2 * w1[j];
    lo[j] = base + (w1[j] == 0 ? beta + 1 : beta);
    hi[j] = base + 2 * g2 - beta - 1;
  }
  sless(a, bp, lo, r);
  sless(b, bp, hi, r);
  not2(na, a);
  and2(o, na, b, ru(r));
}

/* shares of an all-lanes AND over many words; okrev gives the one bit */
typedef struct {
  uint32_t a[2];
} allok;

static void okini(allok *k) {
  k->a[0] = 0xffffffffu;
  k->a[1] = 0;
}

static void okadd(allok *k, const uint32_t o[2], rng *r) {
  and2(k->a, k->a, o, ru(r));
}

static int okrev(const allok *k, rng *r) {
  uint32_t b[2];
  int ok;
  sall(b, k->a, r);
  ok = (int)((b[0] ^ b[1]) & 1u);
  NQMDPUB(&ok, sizeof ok); /* the accept / reject decision */
  return ok;
}

/* ||a||_inf < bnd (centred) over n polynomials held as shares in [0, q) */
static int normok(const nqmdpl *a0, const nqmdpl *a1, unsigned n,
                  int32_t bnd, rng *r) {
  int32_t lo[32], w[32];
  allok k;
  unsigned i, g;
  int j;
  for (j = 0; j < 32; j++) {
    lo[j] = MQ - bnd + 1;
    w[j] = 2 * bnd - 1;
  }
  okini(&k);
  for (i = 0; i < n; i++) {
    for (g = 0; g < NQMDN; g += 32) {
      uint32_t o[2];
      sinint(o, a0[i].c + g, a1[i].c + g, lo, w, r);
      okadd(&k, o, r);
    }
  }
  return okrev(&k, r);
}

/* ---- masked Keccak-f[1600] and SHAKE256 ---- */

static const uint64_t krc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const unsigned krho[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55,
                                  20, 3,  10, 43, 25, 39, 41, 45, 15,
                                  21, 8,  18, 2,  61, 56, 14};

static uint64_t rol(uint64_t x, unsigned n) {
  return n ? (x << n) | (x >> (64 - n)) : x;
}

/* theta, rho, pi on one share (linear) */
static void klin(uint64_t a[25]) {
  uint64_t c[5], b[25];
  unsigned x, y;
  for (x = 0; x < 5; x++) {
    c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
  }
  for (x = 0; x < 5; x++) {
    uint64_t d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
    for (y = 0; y < 25; y += 5) a[y + x] ^= d;
  }
  for (x = 0; x < 5; x++) {
    for (y = 0; y < 5; y++) {
      b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], krho[x + 5 * y]);
    }
  }
  for (x = 0; x < 25; x++) a[x] = b[x];
  nqwipe(c, sizeof c);
  nqwipe(b, sizeof b);
}

static void kfm(uint64_t s0[25], uint64_t s1[25], rng *r) {
  unsigned rd, y, x, h;
  for (rd = 0; rd < 24; rd++) {
    klin(s0);
    klin(s1);
    for (y = 0; y < 25; y += 5) {
      uint32_t b[10][2], o[10][2], n[2], t[2];
      for (x = 0; x < 5; x++) {
        b[2 * x][0] = (uint32_t)s0[y + x];
        b[2 * x + 1][0] = (uint32_t)(s0[y + x] >> 32);
      }
      for (x = 0; x < 5; x++) {
        b[2 * x][1] = (uint32_t)s1[y + x];
        b[2 * x + 1][1] = (uint32_t)(s1[y + x] >> 32);
      }
      /* chi: a ^ (~b & c), on each 32-bit half */
      for (x = 0; x < 5; x++) {
        for (h = 0; h < 2; h++) {
          unsigned i0 = 2 * x + h, i1 = 2 * ((x + 1) % 5) + h;
          unsigned i2 = 2 * ((x + 2) % 5) + h;
          not2(n, b[i1]);
          and2(t, n, b[i2], ru(r));
          xor2(o[i0], b[i0], t);
        }
      }
      for (x = 0; x < 5; x++) {
        s0[y + x] = (uint64_t)o[2 * x][0] | ((uint64_t)o[2 * x + 1][0] << 32);
      }
      for (x = 0; x < 5; x++) {
        s1[y + x] = (uint64_t)o[2 * x][1] | ((uint64_t)o[2 * x + 1][1] << 32);
      }
      nqwipe(b, sizeof b);
      nqwipe(o, sizeof o);
      nqwipe(n, sizeof n);
      nqwipe(t, sizeof t);
    }
    s0[0] ^= krc[rd]; /* iota, into one share */
  }
}

/* masked SHAKE256: in0 ^ in1 is the input (in1 NULL: share 1 is zero),
 * out0 ^ out1 the output */
static void spm(uint8_t *out0, uint8_t *out1, size_t outlen,
                const uint8_t *in0, const uint8_t *in1, size_t inlen,
                rng *r) {
  const size_t rate = 136;
  uint64_t s0[25], s1[25];
  size_t off = 0, pos = 0, i;
  memset(s0, 0, sizeof s0);
  memset(s1, 0, sizeof s1);
  for (;;) {
    size_t take = inlen - off < rate ? inlen - off : rate;
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
      s0[take / 8] ^= (uint64_t)0x1f << (8 * (take % 8));
      s0[(rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((rate - 1) % 8));
      kfm(s0, s1, r);
      break;
    }
    kfm(s0, s1, r);
  }
  for (;;) {
    size_t take = outlen - pos < rate ? outlen - pos : rate;
    for (i = 0; i < take; i++) {
      out0[pos + i] = (uint8_t)(s0[i / 8] >> (8 * (i % 8)));
    }
    for (i = 0; i < take; i++) {
      out1[pos + i] = (uint8_t)(s1[i / 8] >> (8 * (i % 8)));
    }
    pos += take;
    if (pos >= outlen) break;
    kfm(s0, s1, r);
  }
  nqwipe(s0, sizeof s0);
  nqwipe(s1, sizeof s1);
}

/* ---- the masked signer ---- */

/* y for one polynomial: SHAKE256(rho'' || nonce) through the masked
 * sponge, unpacked bit by bit on each share (linear over GF(2)),
 * converted to arithmetic shares and mapped to gamma1 - value */
static void mg1(const nqmdp *p, int32_t *a0, int32_t *a1,
                const uint8_t rp0[64], const uint8_t rp1[64],
                uint16_t nonce, rng *r) {
  uint8_t in0[66], in1[66], b0[640], b1[640];
  int32_t c0[32], c1[32];
  bs v;
  unsigned g, s, b, j;
  memcpy(in0, rp0, 64);
  memcpy(in1, rp1, 64);
  in0[64] = (uint8_t)nonce;
  in0[65] = (uint8_t)(nonce >> 8);
  in1[64] = in1[65] = 0;
  spm(b0, b1, 32 * (size_t)p->zb, in0, in1, sizeof in0, r);
  for (g = 0; g < 8; g++) {
    for (s = 0; s < 2; s++) {
      const uint8_t *buf = s ? b1 : b0;
      for (b = 0; b < p->zb; b++) {
        uint32_t w = 0;
        for (j = 0; j < 32; j++) {
          size_t pos = (size_t)(32 * g + j) * p->zb + b;
          w |= (((uint32_t)buf[pos >> 3] >> (pos & 7u)) & 1u) << j;
        }
        v.w[b][s] = w;
      }
      for (b = p->zb; b < MX; b++) v.w[b][s] = 0;
    }
    b2a(c0, c1, &v, r);
    for (j = 0; j < 32; j++) a0[32 * g + j] = caddm(p->g1 - c0[j]);
    for (j = 0; j < 32; j++) a1[32 * g + j] = caddm(-c1[j]);
  }
  nqwipe(in0, sizeof in0);
  nqwipe(in1, sizeof in1);
  nqwipe(b0, sizeof b0);
  nqwipe(b1, sizeof b1);
  nqwipe(c0, sizeof c0);
  nqwipe(c1, sizeof c1);
  nqwipe(&v, sizeof v);
}

/* fresh arithmetic shares of n polynomials, in place: v[1] holds the
 * values on entry */
static void split(nqmdpl *v0, nqmdpl *v1, unsigned n, rng *r) {
  unsigned i, j;
  for (i = 0; i < n; i++) {
    for (j = 0; j < NQMDN; j++) v0[i].c[j] = rq(r);
    for (j = 0; j < NQMDN; j++) {
      v1[i].c[j] = caddm(canon(v1[i].c[j]) - v0[i].c[j]);
    }
  }
}

typedef struct {
  nqmdpl s1[2][NQMDL], s2[2][NQMDK], t0[2][NQMDK];
  nqmdpl y[2][NQMDL], z[2][NQMDL], w[2][NQMDK], u[2][NQMDK];
  nqmdpl w1[NQMDK], cp;
  bs bp;
  uint8_t hb[NQMDK * NQMDN], wb[NQMDK * 192];
  uint8_t rho[32], key[32], k0[32], k1[32], in0[128], in1[128];
  uint8_t rp0[64], rp1[64];
  nqkctx c;
  rng r;
} smws;

/* every polynomial of a vector through one share's linear step:
 * d = intt(c * a) (+ e unless NULL, - when neg), canonical */
static void lin(nqmdpl *d, const nqmdpl *cp, const nqmdpl *a,
                const nqmdpl *e, int neg, unsigned n) {
  nqmdpl t;
  unsigned i, j;
  for (i = 0; i < n; i++) {
    nqmdpw(t.c, cp->c, a[i].c);
    nqmdint(t.c);
    for (j = 0; j < NQMDN; j++) {
      int32_t x = t.c[j];
      if (e != NULL) x = neg ? e[i].c[j] - x : e[i].c[j] + x;
      d[i].c[j] = canon(x);
    }
  }
  nqwipe(&t, sizeof t);
}

static int smk(const nqmdp *p, const uint8_t *sk, const uint8_t mu[64],
               const uint8_t rnd[32], uint8_t *sig, smws *W) {
  unsigned i, j, g, s, att;
  size_t w1len = (size_t)p->k * 32 * p->w1b;
  rng *r = &W->r;
  r->pos = sizeof r->buf;
  r->fail = 0;
  if (nqmdsku(p, sk, W->rho, W->key, W->s1[1], W->s2[1], W->t0[1])) {
    return NQEDEC;
  }
  split(W->s1[0], W->s1[1], p->l, r);
  split(W->s2[0], W->s2[1], p->k, r);
  split(W->t0[0], W->t0[1], p->k, r);
  for (i = 0; i < 32; i++) W->k0[i] = (uint8_t)ru(r);
  for (i = 0; i < 32; i++) W->k1[i] = (uint8_t)(W->key[i] ^ W->k0[i]);
  nqwipe(W->key, sizeof W->key);
  /* rho'' = H(K || rnd || mu), K masked; rnd and mu ride on share 0 */
  memcpy(W->in0, W->k0, 32);
  memcpy(W->in0 + 32, rnd, 32);
  memcpy(W->in0 + 64, mu, 64);
  memcpy(W->in1, W->k1, 32);
  memset(W->in1 + 32, 0, 96);
  spm(W->rp0, W->rp1, 64, W->in0, W->in1, 128, r);
  for (s = 0; s < 2; s++) {
    for (i = 0; i < p->l; i++) nqmdntt(W->s1[s][i].c);
    for (i = 0; i < p->k; i++) {
      nqmdntt(W->s2[s][i].c);
      nqmdntt(W->t0[s][i].c);
    }
  }
  for (att = 0; att < NQMDTRIES; att++) {
    allok ok;
    unsigned n = 0;
    for (i = 0; i < p->l; i++) {
      mg1(p, W->y[0][i].c, W->y[1][i].c, W->rp0, W->rp1,
          (uint16_t)(att * p->l + i), r);
    }
    /* w = A y */
    for (s = 0; s < 2; s++) {
      for (i = 0; i < p->l; i++) {
        W->z[s][i] = W->y[s][i];
        nqmdntt(W->z[s][i].c);
      }
    }
    nqmdmat(p, W->rho, W->w[0], W->z[0], W->w[1], W->z[1]);
    for (s = 0; s < 2; s++) {
      for (i = 0; i < p->k; i++) {
        nqmdred(W->w[s][i].c);
        nqmdint(W->w[s][i].c);
        for (j = 0; j < NQMDN; j++) W->w[s][i].c[j] = canon(W->w[s][i].c[j]);
      }
    }
    /* w1 = HighBits(w), revealed */
    for (i = 0; i < p->k; i++) {
      for (g = 0; g < NQMDN; g += 32) {
        bprime(&W->bp, W->w[0][i].c + g, W->w[1][i].c + g, p->g2, r);
        revhb(W->w1[i].c + g, &W->bp, p->g2, r);
      }
      nqmdw1p(p, W->wb + i * 32 * p->w1b, W->w1[i].c);
    }
    nqshkini(&W->c, 256);
    nqkabs(&W->c, mu, NQMDMU);
    nqkabs(&W->c, W->wb, w1len);
    nqksqz(&W->c, sig, p->ctl);
    NQMDPUB(sig, p->ctl); /* c~ is the signature's first field */
    nqmdchal(p, W->cp.c, sig);
    nqmdntt(W->cp.c);
    /* z = y + c s1 */
    for (s = 0; s < 2; s++) lin(W->z[s], &W->cp, W->s1[s], W->y[s], 0, p->l);
    if (!normok(W->z[0], W->z[1], p->l, p->g1 - p->beta, r)) continue;
    /* v = w - c s2 (in w), and the r0 check on its low bits */
    for (s = 0; s < 2; s++) lin(W->w[s], &W->cp, W->s2[s], W->w[s], 1, p->k);
    okini(&ok);
    for (i = 0; i < p->k; i++) {
      for (g = 0; g < NQMDN; g += 32) {
        uint32_t o[2];
        bprime(&W->bp, W->w[0][i].c + g, W->w[1][i].c + g, p->g2, r);
        lowok(o, &W->bp, W->w1[i].c + g, p->g2, p->beta, r);
        okadd(&ok, o, r);
      }
    }
    if (!okrev(&ok, r)) continue;
    /* c t0 */
    for (s = 0; s < 2; s++) lin(W->u[s], &W->cp, W->t0[s], NULL, 0, p->k);
    if (!normok(W->u[0], W->u[1], p->k, p->g2, r)) continue;
    /* the hint: HighBits(w - c s2 + c t0) against w1 */
    for (s = 0; s < 2; s++) {
      for (i = 0; i < p->k; i++) {
        for (j = 0; j < NQMDN; j++) {
          W->u[s][i].c[j] = canon(W->w[s][i].c[j] + W->u[s][i].c[j]);
        }
      }
    }
    for (i = 0; i < p->k; i++) {
      for (g = 0; g < NQMDN; g += 32) {
        int32_t hu[32];
        bprime(&W->bp, W->u[0][i].c + g, W->u[1][i].c + g, p->g2, r);
        revhb(hu, &W->bp, p->g2, r);
        for (j = 0; j < 32; j++) {
          uint8_t b = (uint8_t)(hu[j] != W->w1[i].c[g + j]);
          W->hb[i * NQMDN + g + j] = b;
          n += (unsigned)b;
        }
      }
    }
    if (n > p->omega) continue;
    /* accepted: z is part of the signature */
    for (i = 0; i < p->l; i++) {
      for (j = 0; j < NQMDN; j++) {
        int32_t zz = caddm(W->z[0][i].c[j] + W->z[1][i].c[j] - MQ);
        zz -= MQ & (((MQ - 1) / 2 - zz) >> 31);
        W->y[0][i].c[j] = zz;
      }
      NQMDPUB(W->y[0][i].c, sizeof W->y[0][i].c);
      nqmdzp(p, sig + p->ctl + (size_t)i * 32 * p->zb, W->y[0][i].c);
    }
    nqmdhpk(p, sig + p->ctl + (size_t)p->l * 32 * p->zb, W->hb);
    return r->fail ? NQERNG : NQOK;
  }
  return r->fail ? NQERNG : NQEDEC;
}

int nqmdsmk(const nqmdp *p, const uint8_t *sk, const uint8_t mu[64],
            const uint8_t rnd[32], uint8_t *sig) {
  smws W;
  int rc = smk(p, sk, mu, rnd, sig, &W);
  nqwipe(&W, sizeof W);
  return rc;
}
