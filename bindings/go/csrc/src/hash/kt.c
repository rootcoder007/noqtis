/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* TurboSHAKE128/256 and KangarooTwelve (KT128, KT256), RFC 9861.
 *
 * TurboSHAKE is the sponge of SHAKE over Keccak-p[1600, 12], the last 12
 * rounds of the permutation of FIPS 202, with a domain byte D (01 to 7F)
 * that carries the first padding bit. KangarooTwelve hashes a long input
 * as a tree: the input, its customization string and the length of that
 * string are one string S, cut into chunks of 8192 bytes; every chunk
 * after the first is hashed alone to a chaining value, and the final node
 * is the first chunk followed by those values. An input of one chunk is
 * hashed directly. Nothing here depends on the data in its timing, and
 * nothing allocates. */
#include <string.h>

#include "hash/h.h"

#define KTCHUNK 8192u

/* ---- TurboSHAKE ---- */

static void tsxor(nqtsctx *c, size_t i, uint8_t v) {
  c->s[i / 8] ^= (uint64_t)v << (8 * (i % 8));
}

void nqtsini(nqtsctx *c, unsigned bits) {
  memset(c, 0, sizeof *c);
  c->rate = bits == 128 ? 168 : 136;
}

void nqtsabs(nqtsctx *c, const uint8_t *in, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    tsxor(c, c->pos++, in[i]);
    if (c->pos == c->rate) {
      nqkeccak12(c->s);
      c->pos = 0;
    }
  }
}

void nqtspad(nqtsctx *c, uint8_t d) {
  /* pos is below the rate: a full block was permuted as it filled */
  tsxor(c, c->pos, d);
  tsxor(c, c->rate - 1, 0x80);
  nqkeccak12(c->s);
  c->pos = 0;
}

void nqtssqz(nqtsctx *c, uint8_t *out, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (c->pos == c->rate) {
      nqkeccak12(c->s);
      c->pos = 0;
    }
    out[i] = (uint8_t)(c->s[c->pos / 8] >> (8 * (c->pos % 8)));
    c->pos++;
  }
}

void nqtshk(unsigned bits, const uint8_t *in, size_t len, uint8_t d,
          uint8_t *out, size_t outlen) {
  nqtsctx c;
  nqtsini(&c, bits);
  nqtsabs(&c, in, len);
  nqtspad(&c, d);
  nqtssqz(&c, out, outlen);
  nqwipe(&c, sizeof c);
}

/* ---- KangarooTwelve ---- */

typedef struct {
  nqtsctx fin;   /* the final node */
  nqtsctx leaf;  /* the chunk being hashed, after the first */
  unsigned bits;
  size_t cv;     /* bytes of a chaining value: 32 or 64 */
  size_t pos;    /* bytes of S in the current chunk */
  uint64_t n;    /* chunks after the first that are closed */
  int big;       /* S is longer than one chunk */
  int rest;      /* the first chunk is closed */
} ktctx;

/* the chunk after the first that is full, or the last: its chaining
 * value goes into the final node */
static void ktleaf(ktctx *k) {
  uint8_t cv[64];
  nqtspad(&k->leaf, 0x0b);
  nqtssqz(&k->leaf, cv, k->cv);
  nqtsabs(&k->fin, cv, k->cv);
  nqwipe(cv, sizeof cv);
  k->n++;
  k->pos = 0;
  nqtsini(&k->leaf, k->bits);
}

/* len more bytes of S */
static void ktput(ktctx *k, const uint8_t *p, size_t len) {
  static const uint8_t mark[8] = {0x03, 0, 0, 0, 0, 0, 0, 0};
  while (len > 0) {
    size_t room = KTCHUNK - k->pos, m = len < room ? len : room;
    if (!k->rest) {
      nqtsabs(&k->fin, p, m);
    } else {
      nqtsabs(&k->leaf, p, m);
    }
    k->pos += m;
    p += m;
    len -= m;
    if (k->pos == KTCHUNK) {
      if (!k->rest) {
        /* the first chunk ends here only when more of S follows */
        if (!k->big)
          return;
        nqtsabs(&k->fin, mark, sizeof mark);
        k->rest = 1;
        k->pos = 0;
        nqtsini(&k->leaf, k->bits);
      } else {
        ktleaf(k);
      }
    }
  }
}

/* length_encode(x): x in base 256, most significant byte first and
 * without leading zeros, then the number of those bytes; at most 9 bytes */
static size_t ktlen(uint64_t x, uint8_t *out) {
  size_t n = 0, i;
  uint64_t t = x;
  while (t > 0) {
    n++;
    t >>= 8;
  }
  for (i = 0; i < n; i++) out[i] = (uint8_t)(x >> (8 * (n - 1 - i)));
  out[n] = (uint8_t)n;
  return n + 1;
}

int nqkt(unsigned bits, const uint8_t *in, size_t inlen,
         const uint8_t *custom, size_t clen, uint8_t *out, size_t outlen) {
  static const uint8_t ff[2] = {0xff, 0xff};
  ktctx k;
  uint8_t le[9];
  size_t ll, total;
  if ((bits != 128 && bits != 256) || out == NULL || outlen == 0 ||
      (in == NULL && inlen > 0) || (custom == NULL && clen > 0))
    return NQEARG;
  ll = ktlen((uint64_t)clen, le);
  /* the length of S, which decides between one node and a tree */
  if (inlen > SIZE_MAX - clen || inlen + clen > SIZE_MAX - ll)
    return NQELIM;
  total = inlen + clen + ll;
  memset(&k, 0, sizeof k);
  k.bits = bits;
  k.cv = bits == 128 ? 32 : 64;
  k.big = total > KTCHUNK;
  nqtsini(&k.fin, bits);
  if (inlen > 0) ktput(&k, in, inlen);
  if (clen > 0) ktput(&k, custom, clen);
  ktput(&k, le, ll);
  if (!k.big) {
    nqtspad(&k.fin, 0x07);
  } else {
    if (k.pos > 0) ktleaf(&k);
    ll = ktlen(k.n, le);
    nqtsabs(&k.fin, le, ll);
    nqtsabs(&k.fin, ff, sizeof ff);
    nqtspad(&k.fin, 0x06);
  }
  nqtssqz(&k.fin, out, outlen);
  nqwipe(&k, sizeof k);
  return NQOK;
}
