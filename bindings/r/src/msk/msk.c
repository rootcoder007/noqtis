/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* First-order Boolean masking: see msk.h. */
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/lk.h"
#include "msk/msk.h"

/* ---- masks ---- */

#define QR(a, b, c, d)                                                   \
  (a += b, d ^= a, d = (d << 16) | (d >> 16), c += d, b ^= c,           \
   b = (b << 12) | (b >> 20), a += b, d ^= a, d = (d << 8) | (d >> 24), \
   c += d, b ^= c, b = (b << 7) | (b >> 25))

/* the ChaCha block function (RFC 8439 2.3) with 12 rounds, as Rust's
 * StdRng uses: the masks need only be unpredictable; nonce zero */
static void refill(nqmrg *g) {
  uint32_t x[16], s[16];
  int i;
  s[0] = 0x61707865u;
  s[1] = 0x3320646eu;
  s[2] = 0x79622d32u;
  s[3] = 0x6b206574u;
  for (i = 0; i < 8; i++) s[4 + i] = nqld32l(g->k + 4 * i);
  s[12] = g->ctr++;
  s[13] = s[14] = s[15] = 0;
  memcpy(x, s, sizeof x);
  for (i = 0; i < 6; i++) {
    QR(x[0], x[4], x[8], x[12]);
    QR(x[1], x[5], x[9], x[13]);
    QR(x[2], x[6], x[10], x[14]);
    QR(x[3], x[7], x[11], x[15]);
    QR(x[0], x[5], x[10], x[15]);
    QR(x[1], x[6], x[11], x[12]);
    QR(x[2], x[7], x[8], x[13]);
    QR(x[3], x[4], x[9], x[14]);
  }
  for (i = 0; i < 16; i++) nqst32l(g->b + 4 * i, x[i] + s[i]);
  g->pos = 0;
  nqwipe(x, sizeof x);
  nqwipe(s, sizeof s);
}

int nqmrini(nqmrg *g) {
  int rc = nqrand(g->k, sizeof g->k);
  g->ctr = 0;
  refill(g);
  return rc;
}

uint32_t nqmr32(nqmrg *g) {
  uint32_t v;
  if (g->pos + 4 > sizeof g->b) {
    if (g->ctr == 0xffffffffu) (void)nqrand(g->k, sizeof g->k);
    refill(g);
  }
  v = NQLKZM(nqld32l(g->b + g->pos)); /* zero only in the TVLA control */
  g->pos += 4;
  return v;
}

uint64_t nqmr64(nqmrg *g) {
  uint64_t v;
  if (g->pos + 8 > sizeof g->b) {
    if (g->ctr == 0xffffffffu) (void)nqrand(g->k, sizeof g->k);
    refill(g);
  }
  v = NQLKZM(nqld64l(g->b + g->pos)); /* zero only in the TVLA control */
  g->pos += 8;
  return v;
}

void nqmrb(nqmrg *g, uint8_t *out, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) out[i] = (uint8_t)nqmr32(g);
}

static uint32_t op32(uint32_t x) {
  volatile uint32_t v = x;
  NQLK(x, NQLKOP);
  return v;
}

static uint64_t op64(uint64_t x) {
  volatile uint64_t v = x;
  NQLK(x, NQLKKC);
  return v;
}

/* ---- masked Keccak-f[1600] ---- */

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

static void kfm(uint64_t s0[25], uint64_t s1[25], nqmrg *g) {
  uint64_t o0[5], o1[5], t[2];
  int r, y, x;
  for (r = 0; r < 24; r++) {
    klin(s0);
    klin(s1);
    for (y = 0; y < 25; y += 5) {
      /* chi: a ^ (~b & c) */
      for (x = 0; x < 5; x++) {
        const int i1 = y + (x + 1) % 5, i2 = y + (x + 2) % 5;
        mandn64(t, s0[i1], s1[i1], s0[i2], s1[i2], nqmr64(g));
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

void nqmkec(uint8_t *out0, uint8_t *out1, size_t outlen,
            const uint8_t *in0, const uint8_t *in1, size_t inlen,
            size_t in1len, size_t rate, uint8_t dom, nqmrg *g) {
  uint64_t s0[25], s1[25];
  size_t off = 0, pos, i;
  /* the zero state as random shares, so that no lane, not even one of
   * only public input, is ever held in one share alone */
  for (i = 0; i < 25; i++) {
    s0[i] = nqmr64(g);
    s1[i] = s0[i];
  }
  for (;;) {
    const size_t take = inlen - off < rate ? inlen - off : rate;
    for (i = 0; i < take; i++) {
      s0[i / 8] ^= (uint64_t)in0[off + i] << (8 * (i % 8));
    }
    if (in1 != NULL) {
      for (i = 0; i < take && off + i < in1len; i++) {
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

void nqmshk(uint8_t *out0, uint8_t *out1, size_t outlen,
            const uint8_t *in0, const uint8_t *in1, size_t inlen,
            nqmrg *g) {
  nqmkec(out0, out1, outlen, in0, in1, inlen, inlen, 136, 0x1f, g);
}

/* ---- 32-bit share-pair gadgets ---- */

typedef uint32_t mw[2];

/* z = x & y, Trichina; y refreshed first; z may alias x or y */
static void mand(mw z, const mw x, const mw y, nqmrg *g) {
  const uint32_t q = nqmr32(g), r = nqmr32(g);
  const uint32_t x0 = x[0], x1 = x[1];
  const uint32_t y0 = op32(y[0] ^ q), y1 = op32(y[1] ^ q);
  uint32_t t = op32(r ^ (x0 & y0));
  t = op32(t ^ (x0 & y1));
  t = op32(t ^ (x1 & y0));
  t = op32(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

static void mxor(mw z, const mw x, const mw y) {
  const uint32_t a = op32(x[0] ^ y[0]), b = op32(x[1] ^ y[1]);
  z[0] = a;
  z[1] = b;
}

static void mshl(mw z, const mw x, unsigned j) {
  z[0] = op32(x[0] << j);
  z[1] = op32(x[1] << j);
}

static uint32_t ror32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

/* the SHA-256 sigmas, share by share (linear) */
static void msig(mw z, const mw x, unsigned a, unsigned b, unsigned c,
                 int shift) {
  int i;
  for (i = 0; i < 2; i++) {
    const uint32_t v = x[i];
    z[i] = op32(ror32(v, a) ^ ror32(v, b) ^ (shift ? v >> c : ror32(v, c)));
  }
}

void nqmsadd(uint32_t z[2], const uint32_t x[2], const uint32_t y[2],
             nqmrg *g) {
  mw gg, p, t, s;
  unsigned j;
  mand(gg, x, y, g); /* generate */
  mxor(p, x, y);     /* propagate */
  mxor(s, x, y);
  for (j = 1; j < 32; j <<= 1) {
    mshl(t, gg, j);
    mand(t, p, t, g);
    mxor(gg, gg, t);
    if (j < 16) {
      mshl(t, p, j);
      mand(p, p, t, g);
    }
  }
  mshl(t, gg, 1);
  mxor(z, s, t);
  nqwipe(gg, sizeof gg);
  nqwipe(p, sizeof p);
  nqwipe(t, sizeof t);
  nqwipe(s, sizeof s);
}

/* the first 32 bits of the cube roots of the first 64 primes */
static const uint32_t k2[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

/* everything the masked compression holds, wiped together */
typedef struct {
  mw w[16], st[8], t1, t2, u, v, k;
} m2st;

void nqms2(const uint32_t h[8], const uint8_t b0[64], const uint8_t b1[64],
           uint32_t o0[8], uint32_t o1[8], nqmrg *g) {
  m2st m;
  unsigned i;
  for (i = 0; i < 16; i++) {
    m.w[i][0] = nqld32b(b0 + 4 * i);
    m.w[i][1] = nqld32b(b1 + 4 * i);
  }
  /* the chaining value is public: share 1 starts at zero */
  for (i = 0; i < 8; i++) {
    m.st[i][0] = h[i];
    m.st[i][1] = 0;
  }
  for (i = 0; i < 64; i++) {
    mw *s = m.st; /* a b c d e f g h */
    mw *wi = &m.w[i & 15];
    if (i >= 16) {
      /* w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]) */
      msig(m.u, m.w[(i - 15) & 15], 7, 18, 3, 1);
      nqmsadd(*wi, *wi, m.u, g);
      nqmsadd(*wi, *wi, m.w[(i - 7) & 15], g);
      msig(m.u, m.w[(i - 2) & 15], 17, 19, 10, 1);
      nqmsadd(*wi, *wi, m.u, g);
    }
    /* t1 = h + S1(e) + Ch(e, f, g) + K[i] + w[i] */
    msig(m.u, s[4], 6, 11, 25, 0);
    nqmsadd(m.t1, s[7], m.u, g);
    mand(m.u, s[4], s[5], g); /* e & f */
    m.v[0] = op32(~s[4][0]);  /* ~e */
    m.v[1] = s[4][1];
    mand(m.v, m.v, s[6], g); /* ~e & g */
    mxor(m.u, m.u, m.v);
    nqmsadd(m.t1, m.t1, m.u, g);
    m.k[0] = k2[i];
    m.k[1] = 0;
    nqmsadd(m.t1, m.t1, m.k, g);
    nqmsadd(m.t1, m.t1, *wi, g);
    /* t2 = S0(a) + Maj(a, b, c), Maj = (a & (b ^ c)) ^ (b & c) */
    msig(m.t2, s[0], 2, 13, 22, 0);
    mxor(m.u, s[1], s[2]);
    mand(m.u, s[0], m.u, g);
    mand(m.v, s[1], s[2], g);
    mxor(m.u, m.u, m.v);
    nqmsadd(m.t2, m.t2, m.u, g);
    memmove(&s[1], &s[0], 7 * sizeof(mw));
    nqmsadd(s[4], s[4], m.t1, g); /* e = d + t1 (d moved to s[4]) */
    nqmsadd(s[0], m.t1, m.t2, g); /* a = t1 + t2 */
  }
  for (i = 0; i < 8; i++) {
    m.k[0] = h[i];
    m.k[1] = 0;
    nqmsadd(m.st[i], m.st[i], m.k, g);
    o0[i] = m.st[i][0];
    o1[i] = m.st[i][1];
  }
  nqwipe(&m, sizeof m);
}

/* ---- bitsliced masked SHA-256: 64 compressions at once ---- */

/* a masked word of the 64 lanes: w[s][b] is bit b of share s, one bit
 * per lane */
typedef uint64_t bsw[2][32];

/* z = x & y on one bit-plane of each share, Trichina, y refreshed:
 * for operands whose sharings may be related. The steps alternate so
 * that no two values handled one after the other are the two shares of
 * one value (their transition would be that value). */
static void band(uint64_t z[2], uint64_t x0, uint64_t x1, uint64_t y0,
                 uint64_t y1, nqmrg *g) {
  const uint64_t q = nqmr64(g), r = nqmr64(g);
  uint64_t t;
  y0 = op64(y0 ^ q);
  t = op64(r ^ (x0 & y0));
  y1 = op64(y1 ^ q);
  t = op64(t ^ (x0 & y1));
  t = op64(t ^ (x1 & y0));
  t = op64(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

/* the same without the refresh, for a carry c, whose shares are the
 * fresh output of the AND before, against another word's bits */
static void bandc(uint64_t z[2], uint64_t x0, uint64_t x1, uint64_t y0,
                  uint64_t y1, nqmrg *g) {
  const uint64_t r = nqmr64(g);
  uint64_t t;
  t = op64(r ^ (x0 & y0));
  t = op64(t ^ (x0 & y1));
  t = op64(t ^ (x1 & y0));
  t = op64(t ^ (x1 & y1));
  z[0] = r;
  z[1] = t;
}

/* z = x + y mod 2^32, ripple carry: the carry is (x & y) ^ (c & (x ^ y)),
 * a XOR because generate and propagate are disjoint; z may alias. The
 * carry starts as a masked zero, and each carry share is formed next to
 * a value of the other share's side, never next to its sibling. */
static void badd(bsw z, bsw x, bsw y, nqmrg *g) {
  bsw s;
  const uint64_t r0 = nqmr64(g);
  uint64_t c0, c1, t[2] = {r0, 0}, u[2] = {0, r0};
  int i;
  for (i = 0; i < 32; i++) {
    const uint64_t p0 = op64(x[0][i] ^ y[0][i]);
    uint64_t p1;
    c0 = op64(t[0] ^ u[0]);
    s[0][i] = op64(p0 ^ c0);
    p1 = op64(x[1][i] ^ y[1][i]);
    c1 = op64(t[1] ^ u[1]);
    s[1][i] = op64(p1 ^ c1);
    if (i == 31) break;
    band(t, x[0][i], x[1][i], y[0][i], y[1][i], g);
    bandc(u, c0, c1, p0, p1, g);
  }
  memcpy(z, s, sizeof s);
  nqwipe(s, sizeof s);
}

/* z = x + k for a constant k, the same in every lane: the generate term
 * x & k is linear in the shares, so only the carry needs an AND */
static void baddk(bsw z, bsw x, uint32_t k, nqmrg *g) {
  bsw s;
  const uint64_t r0 = nqmr64(g);
  uint64_t c0, c1, t[2] = {r0, 0}, u[2] = {0, r0};
  int i;
  for (i = 0; i < 32; i++) {
    const uint64_t kb = ((k >> i) & 1u) ? ~(uint64_t)0 : 0;
    const uint64_t p0 = op64(x[0][i] ^ kb), p1 = x[1][i];
    c0 = op64(t[0] ^ u[0]);
    s[0][i] = op64(p0 ^ c0);
    c1 = op64(t[1] ^ u[1]);
    s[1][i] = op64(p1 ^ c1);
    if (i == 31) break;
    t[0] = op64(x[0][i] & kb);
    t[1] = op64(x[1][i] & kb);
    bandc(u, c0, c1, p0, p1, g);
  }
  memcpy(z, s, sizeof s);
  nqwipe(s, sizeof s);
}

static void bxor(bsw z, bsw x, bsw y) {
  int i, k;
  for (k = 0; k < 2; k++) {
    for (i = 0; i < 32; i++) z[k][i] = op64(x[k][i] ^ y[k][i]);
  }
}

static void bandw(bsw z, bsw x, bsw y, nqmrg *g) {
  int i;
  for (i = 0; i < 32; i++) {
    uint64_t t[2];
    band(t, x[0][i], x[1][i], y[0][i], y[1][i], g);
    z[0][i] = t[0];
    z[1][i] = t[1];
  }
}

/* z = ror(x, a) ^ ror(x, b) ^ (shift ? x >> c : ror(x, c)): planes
 * renamed, share by share */
static void bsig(bsw z, bsw x, unsigned a, unsigned b, unsigned c,
                 int shift) {
  unsigned i, k;
  for (k = 0; k < 2; k++) {
    for (i = 0; i < 32; i++) {
      uint64_t v = x[k][(i + a) % 32] ^ x[k][(i + b) % 32];
      if (!shift) {
        v ^= x[k][(i + c) % 32];
      } else if (i + c < 32) {
        v ^= x[k][i + c];
      }
      z[k][i] = op64(v);
    }
  }
}

/* a public word, the same in every lane, as shares (planes, 0) */
static void bpub(bsw z, uint32_t v) {
  int i;
  for (i = 0; i < 32; i++) {
    z[0][i] = ((v >> i) & 1u) ? ~(uint64_t)0 : 0;
    z[1][i] = 0;
  }
}

typedef struct {
  bsw w[16], st[8], t1, t2, u, v, k;
} b2st;

static uint32_t ror(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

void nqms2b(const uint32_t h[8], const uint8_t *b0, const uint8_t *b1,
            unsigned cnt, unsigned pre, uint32_t *o0, uint32_t *o1,
            nqmrg *g) {
  b2st mm, *m = &mm; /* about 15 KB of stack */
  unsigned i, l, b, k;
  memset(m, 0, sizeof *m);
  /* transpose the blocks, share by share */
  for (l = 0; l < cnt; l++) {
    for (i = 0; i < 16; i++) {
      const uint32_t v0 = nqld32b(b0 + 64 * (size_t)l + 4 * i);
      const uint32_t v1 = nqld32b(b1 + 64 * (size_t)l + 4 * i);
      for (b = 0; b < 32; b++) {
        m->w[i][0][b] |= (uint64_t)((v0 >> b) & 1u) << l;
        m->w[i][1][b] |= (uint64_t)((v1 >> b) & 1u) << l;
      }
    }
  }
  for (i = 0; i < 8; i++) bpub(m->st[i], h[i]);
  if (pre > 0) {
    /* the first pre rounds read only words of share 0 that are public
     * (share 1 is zero there): each lane's state after them, in the
     * clear, is public too */
    for (b = 0; b < 32; b++) {
      for (i = 0; i < 8; i++) m->st[i][0][b] = 0;
    }
    for (l = 0; l < cnt; l++) {
      uint32_t v[8], t1, t2;
      for (i = 0; i < 8; i++) v[i] = h[i];
      for (i = 0; i < pre; i++) {
        const uint32_t w = nqld32b(b0 + 64 * (size_t)l + 4 * i);
        t1 = v[7] + (ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25)) +
             ((v[4] & v[5]) ^ (~v[4] & v[6])) + k2[i] + w;
        t2 = (ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22)) +
             ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3] + t1;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = t1 + t2;
      }
      for (i = 0; i < 8; i++) {
        for (b = 0; b < 32; b++) {
          m->st[i][0][b] |= (uint64_t)((v[i] >> b) & 1u) << l;
        }
      }
    }
  }
  for (i = pre; i < 64; i++) {
    bsw *s = m->st;
    bsw *wi = &m->w[i & 15];
    if (i >= 16) {
      bsig(m->u, m->w[(i - 15) & 15], 7, 18, 3, 1);
      badd(*wi, *wi, m->u, g);
      badd(*wi, *wi, m->w[(i - 7) & 15], g);
      bsig(m->u, m->w[(i - 2) & 15], 17, 19, 10, 1);
      badd(*wi, *wi, m->u, g);
    }
    bsig(m->u, s[4], 6, 11, 25, 0);
    badd(m->t1, s[7], m->u, g);
    bandw(m->u, s[4], s[5], g); /* e & f */
    memcpy(m->v, s[4], sizeof(bsw));
    for (b = 0; b < 32; b++) m->v[0][b] = op64(~m->v[0][b]); /* ~e */
    bandw(m->v, m->v, s[6], g);
    bxor(m->u, m->u, m->v);
    badd(m->t1, m->t1, m->u, g);
    baddk(m->t1, m->t1, k2[i], g);
    badd(m->t1, m->t1, *wi, g);
    bsig(m->t2, s[0], 2, 13, 22, 0);
    bxor(m->u, s[1], s[2]);
    bandw(m->u, s[0], m->u, g);
    bandw(m->v, s[1], s[2], g);
    bxor(m->u, m->u, m->v);
    badd(m->t2, m->t2, m->u, g);
    memmove(&s[1], &s[0], 7 * sizeof(bsw));
    badd(s[4], s[4], m->t1, g);
    badd(s[0], m->t1, m->t2, g);
  }
  for (i = 0; i < 8; i++) baddk(m->st[i], m->st[i], h[i], g);
  /* back to one word per lane, share by share */
  for (l = 0; l < cnt; l++) {
    for (i = 0; i < 8; i++) {
      uint32_t v0 = 0, v1 = 0;
      for (k = 0; k < 32; k++) {
        v0 |= (uint32_t)((m->st[i][0][k] >> l) & 1u) << k;
        v1 |= (uint32_t)((m->st[i][1][k] >> l) & 1u) << k;
      }
      o0[8 * (size_t)l + i] = v0;
      o1[8 * (size_t)l + i] = v1;
    }
  }
  nqwipe(m, sizeof *m);
}
