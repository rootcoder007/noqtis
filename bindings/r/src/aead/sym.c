/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The ChaCha20 stream (RFC 8439), AES-SIV (RFC 5297) and AES-GCM-SIV
 * (RFC 8452), on the constant-time AES and ChaCha20 of this directory.
 *
 * AES-SIV: the key is two AES keys. S2V, a CMAC over the associated
 * strings and the plaintext, gives the 16-byte synthetic IV, which is
 * both the tag and, with two bits cleared, the counter of AES-CTR under
 * the second key. The same input always gives the same output, and no
 * nonce is needed.
 *
 * AES-GCM-SIV: per nonce, an authentication key and an encryption key
 * are derived from the key; POLYVAL over the associated data and the
 * plaintext, mixed with the nonce and encrypted, is the tag, and the tag
 * is the counter of AES-CTR. A nonce used twice shows only whether the
 * two messages were equal.
 *
 * Constant time in the keys and the data: AES is the bitsliced one of
 * aes.c, POLYVAL and the doubling of CMAC multiply bit by bit under
 * masks, and the tags are compared with nqcteq. Nothing allocates. */
#include <string.h>

#include "aead/aead.h"

#define BLK 16u

/* a > b on 64 bits: a size_t compared with a bound past 2^32 directly is
 * always false where size_t has 32 bits, which -Wtype-limits refuses */
static int gt64(uint64_t a, uint64_t b) {
  return a > b;
}

/* ---- ChaCha20 ---- */

int nqcha20(const uint8_t *key, size_t keylen, const uint8_t *nonce,
            size_t nlen, uint32_t ctr, const uint8_t *in, size_t inlen,
            uint8_t *out) {
  if (key == NULL || keylen != 32 || nonce == NULL || nlen != 12 ||
      ((in == NULL || out == NULL) && inlen > 0))
    return NQEARG;
  /* the block counter is 32 bits: 64 bytes for each value left of it */
  if (gt64(inlen, ((uint64_t)0x100000000u - ctr) * 64u))
    return NQELIM;
  if (inlen > 0) nqcc20(key, nonce, ctr, in, inlen, out);
  return NQOK;
}

/* ---- CMAC (RFC 4493) and S2V ---- */

/* b = 2 * b in GF(2^128), most significant byte first, modulo
 * x^128 + x^7 + x^2 + x + 1 */
static void dbl(uint8_t *b) {
  unsigned top = b[0] >> 7, i;
  for (i = 0; i < BLK - 1; i++)
    b[i] = (uint8_t)(((unsigned)b[i] << 1) | ((unsigned)b[i + 1] >> 7));
  b[BLK - 1] = (uint8_t)(((unsigned)b[BLK - 1] << 1) ^ (0x87u & (0u - top)));
}

typedef struct {
  const nqaes *k;
  uint8_t k1[BLK], k2[BLK];  /* the subkeys of the last block */
  uint8_t x[BLK];            /* the chaining value */
  uint8_t buf[BLK];          /* input not yet processed: 1 to 16 bytes */
  size_t pos;
} cmac;

static void cmini(cmac *c, const nqaes *k) {
  memset(c, 0, sizeof *c);
  c->k = k;
  nqaes1(k, c->k1, c->k1);
  dbl(c->k1);
  memcpy(c->k2, c->k1, BLK);
  dbl(c->k2);
}

/* the same key, a new message */
static void cmnew(cmac *c) {
  memset(c->x, 0, BLK);
  c->pos = 0;
}

static void cmupd(cmac *c, const uint8_t *in, size_t n) {
  size_t i;
  while (n > 0) {
    /* a full buffer is processed only when more follows: the last block
     * is treated apart */
    if (c->pos == BLK) {
      for (i = 0; i < BLK; i++) c->x[i] ^= c->buf[i];
      nqaes1(c->k, c->x, c->x);
      c->pos = 0;
    }
    i = BLK - c->pos;
    if (i > n) i = n;
    memcpy(c->buf + c->pos, in, i);
    c->pos += i;
    in += i;
    n -= i;
  }
}

static void cmfin(cmac *c, uint8_t *tag) {
  size_t i;
  if (c->pos == BLK) {
    for (i = 0; i < BLK; i++) c->x[i] ^= c->buf[i] ^ c->k1[i];
  } else {
    c->buf[c->pos] = 0x80;
    memset(c->buf + c->pos + 1, 0, BLK - c->pos - 1);
    for (i = 0; i < BLK; i++) c->x[i] ^= c->buf[i] ^ c->k2[i];
  }
  nqaes1(c->k, c->x, tag);
}

/* CMAC (the OMAC1 of EAX) of pre followed by in, for the other modes
 * of this directory */
void nqcmacp(const nqaes *k, const uint8_t *pre, size_t pn,
             const uint8_t *in, size_t n, uint8_t *tag) {
  cmac c;
  cmini(&c, k);
  if (pn > 0) cmupd(&c, pre, pn);
  if (n > 0) cmupd(&c, in, n);
  cmfin(&c, tag);
  nqwipe(&c, sizeof c);
}

/* S2V of RFC 5297 section 2.4 over the nad strings of ad and then the
 * plaintext p, the last string */
static void s2v(const nqaes *k, const uint8_t *const *ad,
                const size_t *adlen, size_t nad, const uint8_t *p,
                size_t n, uint8_t *v) {
  cmac c;
  uint8_t d[BLK], t[BLK];
  size_t i, j;
  cmini(&c, k);
  memset(d, 0, BLK);
  cmupd(&c, d, BLK);
  cmfin(&c, d);
  for (i = 0; i < nad; i++) {
    dbl(d);
    cmnew(&c);
    if (adlen[i] > 0) cmupd(&c, ad[i], adlen[i]);
    cmfin(&c, t);
    for (j = 0; j < BLK; j++) d[j] ^= t[j];
  }
  cmnew(&c);
  if (n >= BLK) {
    /* d is XORed into the last 16 bytes of p */
    if (n > BLK) cmupd(&c, p, n - BLK);
    for (j = 0; j < BLK; j++) t[j] = p[n - BLK + j] ^ d[j];
  } else {
    dbl(d);
    memset(t, 0, BLK);
    if (n > 0) memcpy(t, p, n);
    t[n] = 0x80;
    for (j = 0; j < BLK; j++) t[j] ^= d[j];
  }
  cmupd(&c, t, BLK);
  cmfin(&c, v);
  nqwipe(&c, sizeof c);
  nqwipe(d, sizeof d);
  nqwipe(t, sizeof t);
}

/* AES-CTR with a 128-bit big-endian counter that starts at q */
static void ctrbe(const nqaes *k, const uint8_t *q, const uint8_t *in,
                  size_t n, uint8_t *out) {
  uint8_t ctr[BLK], ks[BLK];
  size_t i, m;
  unsigned carry;
  memcpy(ctr, q, BLK);
  while (n > 0) {
    nqaes1(k, ctr, ks);
    m = n < BLK ? n : BLK;
    for (i = 0; i < m; i++) out[i] = in[i] ^ ks[i];
    in += m;
    out += m;
    n -= m;
    carry = 1;
    for (i = BLK; i-- > 0;) {
      carry += ctr[i];
      ctr[i] = (uint8_t)carry;
      carry >>= 8;
    }
  }
  nqwipe(ks, sizeof ks);
}

void nqctrbe(const nqaes *k, const uint8_t *q, const uint8_t *in, size_t n,
             uint8_t *out) {
  ctrbe(k, q, in, n, out);
}

/* the two keys of AES-SIV; NQEARG for a length that is not twice an AES
 * key or for strings that cannot be */
static int sivk(nqaes *k1, nqaes *k2, const uint8_t *key, size_t keylen,
                const uint8_t *const *ad, const size_t *adlen, size_t nad) {
  size_t i;
  if (key == NULL || (keylen != 32 && keylen != 48 && keylen != 64) ||
      nad > NQSIVADMAX || (nad > 0 && (ad == NULL || adlen == NULL)))
    return NQEARG;
  for (i = 0; i < nad; i++) {
    if (ad[i] == NULL && adlen[i] > 0) return NQEARG;
  }
  if (nqaesk(k1, key, keylen / 2) != NQOK ||
      nqaesk(k2, key + keylen / 2, keylen / 2) != NQOK)
    return NQEARG;
  return NQOK;
}

int nqsivenc(const uint8_t *key, size_t keylen, const uint8_t *const *ad,
             const size_t *adlen, size_t nad, const uint8_t *in,
             size_t inlen, uint8_t *out, size_t outlen) {
  nqaes k1, k2;
  uint8_t q[BLK];
  int rc;
  if (out == NULL || (in == NULL && inlen > 0) || inlen > SIZE_MAX - BLK ||
      outlen != inlen + BLK)
    return NQEARG;
  rc = sivk(&k1, &k2, key, keylen, ad, adlen, nad);
  if (rc == NQOK) {
    s2v(&k1, ad, adlen, nad, in, inlen, out);
    memcpy(q, out, BLK);
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    if (inlen > 0) ctrbe(&k2, q, in, inlen, out + BLK);
  }
  nqwipe(&k1, sizeof k1);
  nqwipe(&k2, sizeof k2);
  nqwipe(q, sizeof q);
  return rc;
}

int nqsivdec(const uint8_t *key, size_t keylen, const uint8_t *const *ad,
             const size_t *adlen, size_t nad, const uint8_t *in,
             size_t inlen, uint8_t *out, size_t outlen) {
  nqaes k1, k2;
  uint8_t q[BLK], v[BLK];
  size_t n;
  int rc, ok;
  if (in == NULL || inlen < BLK || outlen != inlen - BLK ||
      (out == NULL && outlen > 0))
    return NQEARG;
  n = inlen - BLK;
  rc = sivk(&k1, &k2, key, keylen, ad, adlen, nad);
  if (rc == NQOK) {
    memcpy(q, in, BLK);
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    if (n > 0) ctrbe(&k2, q, in + BLK, n, out);
    s2v(&k1, ad, adlen, nad, out, n, v);
    ok = nqcteq(v, in, BLK);
    NQAEPUB(&ok, sizeof ok);
    if (!ok) {
      /* nothing of a forgery leaves this function */
      if (n > 0) nqwipe(out, n);
      rc = NQEVRFY;
    }
  }
  nqwipe(&k1, sizeof k1);
  nqwipe(&k2, sizeof k2);
  nqwipe(q, sizeof q);
  nqwipe(v, sizeof v);
  return rc;
}

/* ---- POLYVAL and AES-GCM-SIV ---- */

/* An element of GF(2^128) modulo x^128 + x^127 + x^126 + x^121 + 1, bit
 * i of the 128-bit little-endian number the coefficient of x^i. */
typedef struct {
  uint64_t lo, hi;
} gf;

/* r = a * b, bit by bit under masks; r may be a */
static void gfmul(gf *r, const gf *a, const gf *b) {
  gf z = {0, 0}, v = *b;
  unsigned i;
  for (i = 0; i < 128; i++) {
    uint64_t bit = ((i < 64 ? a->lo >> i : a->hi >> (i - 64)) & 1u);
    uint64_t m = 0u - bit, top = v.hi >> 63;
    z.lo ^= v.lo & m;
    z.hi ^= v.hi & m;
    /* v = v * x: x^128 = x^127 + x^126 + x^121 + 1 */
    v.hi = (v.hi << 1) | (v.lo >> 63);
    v.lo <<= 1;
    v.lo ^= (uint64_t)1 & (0u - top);
    v.hi ^= ((uint64_t)0xc2 << 56) & (0u - top);
  }
  *r = z;
}

static uint64_t le64(const uint8_t *p) {
  uint64_t x = 0;
  unsigned i;
  for (i = 0; i < 8; i++) x |= (uint64_t)p[i] << (8 * i);
  return x;
}

static void put64(uint8_t *p, uint64_t x) {
  unsigned i;
  for (i = 0; i < 8; i++) p[i] = (uint8_t)(x >> (8 * i));
}

/* s = (s + block) * h * x^-128, POLYVAL's step, with hx = h * x^-128 */
static void pvblk(gf *s, const gf *hx, const uint8_t *b) {
  s->lo ^= le64(b);
  s->hi ^= le64(b + 8);
  gfmul(s, s, hx);
}

/* whole blocks of p, then the rest padded with zeros */
static void pvpad(gf *s, const gf *hx, const uint8_t *p, size_t n) {
  uint8_t t[BLK];
  while (n >= BLK) {
    pvblk(s, hx, p);
    p += BLK;
    n -= BLK;
  }
  if (n > 0) {
    memset(t, 0, BLK);
    memcpy(t, p, n);
    pvblk(s, hx, t);
    nqwipe(t, sizeof t);
  }
}

typedef struct {
  nqaes enc;
  gf hx;
} gsiv;

/* the keys of one nonce, RFC 8452 section 4 */
static int gsivk(gsiv *g, const uint8_t *key, size_t keylen,
                 const uint8_t *nonce, size_t nlen) {
  /* x^-128 = x^127 + x^124 + x^121 + x^114 + 1 (RFC 8452 section 3) */
  static const gf xinv = {1, ((uint64_t)0x92 << 56) | ((uint64_t)1 << 50)};
  nqaes k;
  uint8_t in[BLK], o[BLK], mk[BLK], ek[32];
  gf h;
  unsigned i, nb;
  if (key == NULL || (keylen != 16 && keylen != 32) || nonce == NULL ||
      nlen != 12 || nqaesk(&k, key, keylen) != NQOK)
    return NQEARG;
  nb = keylen == 16 ? 4 : 6;
  memcpy(in + 4, nonce, 12);
  for (i = 0; i < nb; i++) {
    in[0] = (uint8_t)i;
    in[1] = in[2] = in[3] = 0;
    nqaes1(&k, in, o);
    if (i < 2) {
      memcpy(mk + 8 * i, o, 8);
    } else {
      memcpy(ek + 8 * (i - 2), o, 8);
    }
  }
  h.lo = le64(mk);
  h.hi = le64(mk + 8);
  gfmul(&g->hx, &h, &xinv);
  (void)nqaesk(&g->enc, ek, keylen);
  nqwipe(&k, sizeof k);
  nqwipe(o, sizeof o);
  nqwipe(mk, sizeof mk);
  nqwipe(ek, sizeof ek);
  nqwipe(&h, sizeof h);
  return NQOK;
}

/* the tag of RFC 8452 section 4 over the associated data and plaintext */
static void gsivtag(const gsiv *g, const uint8_t *nonce, const uint8_t *ad,
                    size_t alen, const uint8_t *p, size_t n, uint8_t *tag) {
  gf s = {0, 0};
  uint8_t b[BLK];
  unsigned i;
  pvpad(&s, &g->hx, ad, alen);
  pvpad(&s, &g->hx, p, n);
  put64(b, (uint64_t)alen * 8);
  put64(b + 8, (uint64_t)n * 8);
  pvblk(&s, &g->hx, b);
  put64(b, s.lo);
  put64(b + 8, s.hi);
  for (i = 0; i < 12; i++) b[i] ^= nonce[i];
  b[15] &= 0x7f;
  nqaes1(&g->enc, b, tag);
  nqwipe(&s, sizeof s);
  nqwipe(b, sizeof b);
}

/* AES-CTR of RFC 8452: the tag with its top bit set is the first counter
 * block, whose first four bytes count up, little-endian, modulo 2^32 */
static void ctrle(const nqaes *k, const uint8_t *tag, const uint8_t *in,
                  size_t n, uint8_t *out) {
  uint8_t ctr[BLK], ks[BLK];
  uint32_t c;
  size_t i, m;
  memcpy(ctr, tag, BLK);
  ctr[15] |= 0x80;
  c = (uint32_t)ctr[0] | ((uint32_t)ctr[1] << 8) | ((uint32_t)ctr[2] << 16) |
      ((uint32_t)ctr[3] << 24);
  while (n > 0) {
    nqaes1(k, ctr, ks);
    m = n < BLK ? n : BLK;
    for (i = 0; i < m; i++) out[i] = in[i] ^ ks[i];
    in += m;
    out += m;
    n -= m;
    c++;
    ctr[0] = (uint8_t)c;
    ctr[1] = (uint8_t)(c >> 8);
    ctr[2] = (uint8_t)(c >> 16);
    ctr[3] = (uint8_t)(c >> 24);
  }
  nqwipe(ks, sizeof ks);
}

/* the limit of RFC 8452 section 6 on each of the two lengths: 2^36 bytes */
static int gsivlim(size_t alen, size_t n) {
  return !gt64(alen, (uint64_t)1 << 36) && !gt64(n, (uint64_t)1 << 36);
}

int nqgsivenc(const uint8_t *key, size_t keylen, const uint8_t *nonce,
              size_t nlen, const uint8_t *ad, size_t adlen,
              const uint8_t *in, size_t inlen, uint8_t *out,
              size_t outlen) {
  gsiv g;
  uint8_t tag[BLK];
  int rc;
  if (out == NULL || (in == NULL && inlen > 0) || (ad == NULL && adlen > 0) ||
      inlen > SIZE_MAX - BLK || outlen != inlen + BLK)
    return NQEARG;
  if (!gsivlim(adlen, inlen)) return NQELIM;
  rc = gsivk(&g, key, keylen, nonce, nlen);
  if (rc == NQOK) {
    gsivtag(&g, nonce, ad, adlen, in, inlen, tag);
    if (inlen > 0) ctrle(&g.enc, tag, in, inlen, out);
    memcpy(out + inlen, tag, BLK);
  }
  nqwipe(&g, sizeof g);
  nqwipe(tag, sizeof tag);
  return rc;
}

int nqgsivdec(const uint8_t *key, size_t keylen, const uint8_t *nonce,
              size_t nlen, const uint8_t *ad, size_t adlen,
              const uint8_t *in, size_t inlen, uint8_t *out,
              size_t outlen) {
  gsiv g;
  uint8_t tag[BLK];
  size_t n;
  int rc, ok;
  if (in == NULL || inlen < BLK || outlen != inlen - BLK ||
      (out == NULL && outlen > 0) || (ad == NULL && adlen > 0))
    return NQEARG;
  n = inlen - BLK;
  if (!gsivlim(adlen, n)) return NQELIM;
  rc = gsivk(&g, key, keylen, nonce, nlen);
  if (rc == NQOK) {
    if (n > 0) ctrle(&g.enc, in + n, in, n, out);
    gsivtag(&g, nonce, ad, adlen, out, n, tag);
    ok = nqcteq(tag, in + n, BLK);
    NQAEPUB(&ok, sizeof ok);
    if (!ok) {
      if (n > 0) nqwipe(out, n);
      rc = NQEVRFY;
    }
  }
  nqwipe(&g, sizeof g);
  nqwipe(tag, sizeof tag);
  return rc;
}
