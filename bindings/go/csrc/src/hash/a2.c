/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Argon2 (RFC 9106, version 0x13) on BLAKE2b: Argon2id for noqtis.h,
 * and Argon2d and Argon2i, which differ from it only in how a block
 * chooses the block it mixes with, for the RFC's other test vectors.
 *
 * The lanes are filled one after another in one thread, slice by slice,
 * which gives the bytes the RFC's parallel order gives: a segment reads
 * only its own lane's earlier blocks and other lanes' finished slices.
 * The memory (m KiB, rounded down to 4p blocks as the RFC says) is
 * allocated once with nqmal, wiped and freed with nqfree before return;
 * the working blocks live in one structure on the stack, wiped once at
 * the end. Argon2id's second half chooses blocks by the data, as the
 * RFC designs it: its memory access pattern (a cache side channel)
 * depends on the password there, the trade the RFC makes against
 * time-memory attacks. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"

#define QW 128   /* 64-bit words in a block of 1024 bytes */
#define A2VER 0x13

typedef struct {
  uint64_t v[QW];
} blk;

typedef struct {
  blk *b;          /* m' blocks: lane l, column j at b[l * q + j] */
  uint32_t q;      /* columns per lane */
  uint32_t mm;     /* m', the number of blocks */
  uint32_t t, p;
  int y;
  blk r, z, adr, inp, zero;  /* G's working blocks, addresses */
  uint64_t g[16];
  uint8_t by[1024];
  uint8_t h0[72];  /* H0 || LE32(column) || LE32(lane) */
} a2w;

static uint64_t rotr(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

/* BLAKE2b's addition with the multiplication of the low halves (fBlaMka) */
static uint64_t fbl(uint64_t a, uint64_t b) {
  return a + b + 2 * (a & 0xffffffffu) * (b & 0xffffffffu);
}

static void gb(uint64_t *v, unsigned a, unsigned b, unsigned c, unsigned d) {
  v[a] = fbl(v[a], v[b]);
  v[d] = rotr(v[d] ^ v[a], 32);
  v[c] = fbl(v[c], v[d]);
  v[b] = rotr(v[b] ^ v[c], 24);
  v[a] = fbl(v[a], v[b]);
  v[d] = rotr(v[d] ^ v[a], 16);
  v[c] = fbl(v[c], v[d]);
  v[b] = rotr(v[b] ^ v[c], 63);
}

/* P, section 3.6, on 16 words */
static void perm(uint64_t *v) {
  gb(v, 0, 4, 8, 12);
  gb(v, 1, 5, 9, 13);
  gb(v, 2, 6, 10, 14);
  gb(v, 3, 7, 11, 15);
  gb(v, 0, 5, 10, 15);
  gb(v, 1, 6, 11, 12);
  gb(v, 2, 7, 8, 13);
  gb(v, 3, 4, 9, 14);
}

/* out = G(x, y), or out ^= G(x, y) with xr (version 0x13's later
 * passes). out may be x or y. */
static void gfn(a2w *w, const blk *x, const blk *y, blk *out, int xr) {
  unsigned i, j;
  for (i = 0; i < QW; i++) w->r.v[i] = x->v[i] ^ y->v[i];
  w->z = w->r;
  /* rows: 16 words each */
  for (i = 0; i < 8; i++) perm(w->z.v + 16 * i);
  /* columns: words 2i and 2i + 1 of each row */
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 8; j++) {
      w->g[2 * j] = w->z.v[2 * i + 16 * j];
      w->g[2 * j + 1] = w->z.v[2 * i + 1 + 16 * j];
    }
    perm(w->g);
    for (j = 0; j < 8; j++) {
      w->z.v[2 * i + 16 * j] = w->g[2 * j];
      w->z.v[2 * i + 1 + 16 * j] = w->g[2 * j + 1];
    }
  }
  if (xr) {
    for (i = 0; i < QW; i++) out->v[i] ^= w->z.v[i] ^ w->r.v[i];
  } else {
    for (i = 0; i < QW; i++) out->v[i] = w->z.v[i] ^ w->r.v[i];
  }
}

/* H' (section 3.3): t bytes of x (n bytes) */
static void hp(uint8_t *out, uint32_t t, const uint8_t *x, size_t n) {
  nqb2ctx c;
  uint8_t v[64], l[4];
  uint32_t r, i;
  nqst32l(l, t);
  if (t <= 64) {
    (void)nqb2ini(&c, t, NULL, 0);
    nqb2upd(&c, l, 4);
    nqb2upd(&c, x, n);
    nqb2fin(&c, out);
    return;
  }
  r = (t + 31) / 32 - 2;
  (void)nqb2ini(&c, 64, NULL, 0);
  nqb2upd(&c, l, 4);
  nqb2upd(&c, x, n);
  nqb2fin(&c, v);
  memcpy(out, v, 32);
  out += 32;
  for (i = 2; i <= r; i++) {
    (void)nqb2ini(&c, 64, NULL, 0);
    nqb2upd(&c, v, 64);
    nqb2fin(&c, v);
    memcpy(out, v, 32);
    out += 32;
  }
  (void)nqb2ini(&c, t - 32 * r, NULL, 0);
  nqb2upd(&c, v, 64);
  nqb2fin(&c, out);
  nqwipe(v, sizeof v);
}

static void ldblk(blk *b, const uint8_t *p) {
  unsigned i;
  for (i = 0; i < QW; i++) b->v[i] = nqld64l(p + 8 * i);
}

static void stblk(uint8_t *p, const blk *b) {
  unsigned i;
  for (i = 0; i < QW; i++) nqst64l(p + 8 * i, b->v[i]);
}

/* the next block of addresses (data-independent addressing) */
static void nxt(a2w *w) {
  w->inp.v[6]++;
  gfn(w, &w->zero, &w->inp, &w->adr, 0);
  gfn(w, &w->zero, &w->adr, &w->adr, 0);
}

/* one segment: pass r, slice s, lane l (section 3.4) */
static void seg(a2w *w, uint32_t r, uint32_t s, uint32_t l) {
  uint32_t sl = w->q / 4, i, st = 0;
  int di = w->y == 1 || (w->y == 2 && r == 0 && s < 2);
  if (di) {
    memset(&w->inp, 0, sizeof w->inp);
    w->inp.v[0] = r;
    w->inp.v[1] = l;
    w->inp.v[2] = s;
    w->inp.v[3] = w->mm;
    w->inp.v[4] = w->t;
    w->inp.v[5] = (uint64_t)w->y;
  }
  if (r == 0 && s == 0) {
    st = 2; /* the first two columns are made from H0 */
    if (di) nxt(w);
  }
  for (i = st; i < sl; i++) {
    uint32_t col = s * sl + i, cur = l * w->q + col;
    uint32_t prv = col == 0 ? l * w->q + w->q - 1 : cur - 1;
    uint32_t rl, area, start;
    uint64_t rnd, x;
    if (di) {
      if (i % QW == 0) nxt(w);
      rnd = w->adr.v[i % QW];
    } else {
      rnd = w->b[prv].v[0];
    }
    rl = r == 0 && s == 0 ? l : (uint32_t)((rnd >> 32) % w->p);
    /* the blocks it may reference (section 3.4.1.2) */
    if (r == 0) {
      area = rl == l ? col - 1 : s * sl - (uint32_t)(i == 0);
    } else {
      area = rl == l ? w->q - sl + i - 1 : w->q - sl - (uint32_t)(i == 0);
    }
    x = rnd & 0xffffffffu;
    x = (x * x) >> 32;
    x = ((uint64_t)area * x) >> 32;
    start = r == 0 || s == 3 ? 0 : (s + 1) * sl;
    gfn(w, &w->b[prv],
        &w->b[rl * w->q + (start + (area - 1 - (uint32_t)x)) % w->q],
        &w->b[cur], r > 0);
  }
}

static void a32(nqb2ctx *c, size_t v) {
  uint8_t b[4];
  nqst32l(b, (uint32_t)v);
  nqb2upd(c, b, 4);
}

/* whether n needs more than 32 bits (shifts that are defined for a
 * 32-bit size_t too) */
static int big(size_t n) {
  return ((n >> 16) >> 16) != 0;
}

int nqa2(int y, const uint8_t *pw, size_t pwlen, const uint8_t *salt,
         size_t slen, const uint8_t *key, size_t klen, const uint8_t *ad,
         size_t alen, uint32_t t, uint32_t m, uint32_t p, uint8_t *out,
         size_t outlen) {
  a2w w;
  nqb2ctx c;
  size_t bytes;
  uint32_t l, r, s;
  if (out == NULL || (pw == NULL && pwlen > 0) || salt == NULL ||
      (key == NULL && klen > 0) || (ad == NULL && alen > 0) || y < 0 ||
      y > 2) {
    return NQEARG;
  }
  if (outlen < NQA2OMIN || outlen > NQA2OMAX || t < 1 || t > NQA2TMAX ||
      p < 1 || p > NQA2PMAX || m < 8 * p || m > NQA2MMAX ||
      slen < NQA2SMIN || big(pwlen) || big(slen) || big(klen) ||
      big(alen)) {
    return NQEARG;
  }
  memset(&w, 0, sizeof w);
  w.p = p;
  w.t = t;
  w.y = y;
  w.q = m / (4 * p) * 4;
  w.mm = w.q * p;
  /* m KiB must fit in a size_t (not so on a 32-bit platform for 4 GiB) */
  bytes = (size_t)w.mm * sizeof(blk);
  if (bytes / sizeof(blk) != w.mm) return NQELIM;
  w.b = (blk *)nqmal(bytes);
  if (w.b == NULL) return NQEMEM;
  /* H0 (section 3.2) */
  (void)nqb2ini(&c, 64, NULL, 0);
  a32(&c, p);
  a32(&c, outlen);
  a32(&c, m);
  a32(&c, t);
  a32(&c, A2VER);
  a32(&c, (size_t)y);
  a32(&c, pwlen);
  if (pwlen > 0) nqb2upd(&c, pw, pwlen);
  a32(&c, slen);
  nqb2upd(&c, salt, slen);
  a32(&c, klen);
  if (klen > 0) nqb2upd(&c, key, klen);
  a32(&c, alen);
  if (alen > 0) nqb2upd(&c, ad, alen);
  nqb2fin(&c, w.h0);
  for (l = 0; l < p; l++) {
    nqst32l(w.h0 + 68, l);
    nqst32l(w.h0 + 64, 0);
    hp(w.by, 1024, w.h0, 72);
    ldblk(&w.b[l * w.q], w.by);
    nqst32l(w.h0 + 64, 1);
    hp(w.by, 1024, w.h0, 72);
    ldblk(&w.b[l * w.q + 1], w.by);
  }
  for (r = 0; r < t; r++) {
    for (s = 0; s < 4; s++) {
      for (l = 0; l < p; l++) seg(&w, r, s, l);
    }
  }
  /* C, the XOR of the last column, and the tag H'(C) */
  w.r = w.b[w.q - 1];
  for (l = 1; l < p; l++) {
    unsigned i;
    for (i = 0; i < QW; i++) w.r.v[i] ^= w.b[l * w.q + w.q - 1].v[i];
  }
  stblk(w.by, &w.r);
  hp(out, (uint32_t)outlen, w.by, sizeof w.by);
  nqfree(w.b, bytes);
  nqwipe(&w, sizeof w);
  return NQOK;
}

int nqa2id(const uint8_t *pw, size_t pwlen, const uint8_t *salt,
           size_t slen, const uint8_t *key, size_t klen, const uint8_t *ad,
           size_t alen, uint32_t t, uint32_t m, uint32_t p, uint8_t *out,
           size_t outlen) {
  return nqa2(2, pw, pwlen, salt, slen, key, klen, ad, alen, t, m, p, out,
              outlen);
}
