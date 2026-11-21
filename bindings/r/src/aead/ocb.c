/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* AES-OCB (RFC 7253) and AES-EAX, both with a 128-bit tag: the two
 * AEAD modes OpenPGP (RFC 9580) names beside GCM. OCB takes a nonce of
 * 1 to 15 bytes, EAX one of any length; OpenPGP gives them 15 and 16.
 * In place is allowed (in may be out). */
#include <string.h>

#include "aead/aead.h"

#define BLK 16

static void dbl(uint8_t *b) {
  unsigned c = b[0] >> 7, i;
  for (i = 0; i < BLK - 1; i++)
    b[i] = (uint8_t)(((unsigned)b[i] << 1) | ((unsigned)b[i + 1] >> 7));
  b[BLK - 1] = (uint8_t)(((unsigned)b[BLK - 1] << 1) ^ (0x87u & (0u - c)));
}

static void xorb(uint8_t *d, const uint8_t *s) {
  int i;
  for (i = 0; i < BLK; i++) d[i] ^= s[i];
}

typedef struct {
  nqaes k;
  uint8_t ls[BLK]; /* L_* */
  uint8_t ld[BLK]; /* L_$ */
  uint8_t l[BLK];  /* L_i, doubled on the way to the one asked for */
} ocb;

/* L_{ntz(i)} into out: block numbers are public, so is this loop */
static void lntz(const ocb *o, uint64_t i, uint8_t *out) {
  memcpy(out, o->l, BLK);
  for (; (i & 1) == 0; i >>= 1) dbl(out);
}

static int oini(ocb *o, const uint8_t *key, size_t klen) {
  int rc = nqaesk(&o->k, key, klen);
  if (rc != NQOK) return rc;
  memset(o->ls, 0, BLK);
  nqaes1(&o->k, o->ls, o->ls);
  memcpy(o->ld, o->ls, BLK);
  dbl(o->ld);
  memcpy(o->l, o->ld, BLK);
  dbl(o->l);
  return NQOK;
}

/* HASH(K, A) of RFC 7253 section 4.1 */
static void ohash(const ocb *o, const uint8_t *a, size_t n, uint8_t *sum) {
  uint8_t off[BLK], t[BLK], li[BLK];
  uint64_t i;
  memset(sum, 0, BLK);
  memset(off, 0, BLK);
  for (i = 1; n >= BLK; i++, a += BLK, n -= BLK) {
    lntz(o, i, li);
    xorb(off, li);
    memcpy(t, a, BLK);
    xorb(t, off);
    nqaes1(&o->k, t, t);
    xorb(sum, t);
  }
  if (n > 0) {
    xorb(off, o->ls);
    memset(t, 0, BLK);
    memcpy(t, a, n);
    t[n] = 0x80;
    xorb(t, off);
    nqaes1(&o->k, t, t);
    xorb(sum, t);
  }
  nqwipe(t, sizeof t);
}

/* Offset_0 from the nonce (section 4.2) */
static void ooff(const ocb *o, const uint8_t *nonce, size_t nlen,
                 uint8_t *off) {
  uint8_t nb[BLK], st[24];
  unsigned bottom, by, bi, i;
  memset(nb, 0, BLK);
  nb[BLK - 1 - nlen] = 0x01;
  memcpy(nb + BLK - nlen, nonce, nlen);
  bottom = nb[BLK - 1] & 0x3fu;
  nb[BLK - 1] &= 0xc0u;
  nqaes1(&o->k, nb, st);
  for (i = 0; i < 8; i++) st[16 + i] = (uint8_t)(st[i] ^ st[i + 1]);
  by = bottom / 8;
  bi = bottom % 8;
  for (i = 0; i < BLK; i++) {
    unsigned v = (unsigned)st[by + i] << bi;
    if (bi != 0) v |= (unsigned)st[by + i + 1] >> (8 - bi);
    off[i] = (uint8_t)v;
  }
  nqwipe(st, sizeof st);
  nqwipe(nb, sizeof nb);
}

static int oargs(const uint8_t *key, const uint8_t *nonce, size_t nlen,
                 const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
                 const uint8_t *out, const uint8_t *tag) {
  if (key == NULL || nonce == NULL || tag == NULL || nlen < 1 || nlen > 15 ||
      (aad == NULL && alen != 0) || ((in == NULL || out == NULL) && n != 0))
    return NQEARG;
  return NQOK;
}

/* the text of both directions: dec 0 encrypts in to out, 1 decrypts;
 * the tag over the plaintext into tag */
static void ocrypt(const ocb *o, const uint8_t *nonce, size_t nlen,
                   const uint8_t *aad, size_t alen, const uint8_t *in,
                   size_t n, uint8_t *out, uint8_t *tag, int dec) {
  uint8_t off[BLK], sum[BLK], t[BLK], li[BLK], h[BLK];
  uint64_t i;
  ooff(o, nonce, nlen, off);
  memset(sum, 0, BLK);
  for (i = 1; n >= BLK; i++, in += BLK, out += BLK, n -= BLK) {
    lntz(o, i, li);
    xorb(off, li);
    memcpy(t, in, BLK);
    if (!dec) xorb(sum, t);
    xorb(t, off);
    if (dec)
      nqaesd1(&o->k, t, t);
    else
      nqaes1(&o->k, t, t);
    xorb(t, off);
    if (dec) xorb(sum, t);
    memcpy(out, t, BLK);
  }
  if (n > 0) {
    uint8_t pad[BLK], p[BLK];
    size_t j;
    xorb(off, o->ls);
    nqaes1(&o->k, off, pad);
    memset(p, 0, BLK);
    for (j = 0; j < n; j++) {
      uint8_t c = (uint8_t)(in[j] ^ pad[j]);
      p[j] = dec ? c : in[j];
      out[j] = c;
    }
    p[n] = 0x80;
    xorb(sum, p);
    nqwipe(pad, sizeof pad);
    nqwipe(p, sizeof p);
  }
  xorb(sum, off);
  xorb(sum, o->ld);
  nqaes1(&o->k, sum, tag);
  ohash(o, aad, alen, h);
  xorb(tag, h);
  nqwipe(sum, sizeof sum);
  nqwipe(t, sizeof t);
  nqwipe(off, sizeof off);
}

int nqocbe(const uint8_t *key, size_t klen, const uint8_t *nonce, size_t nlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           uint8_t *out, uint8_t *tag) {
  ocb o;
  int rc = oargs(key, nonce, nlen, aad, alen, in, n, out, tag);
  if (rc == NQOK) rc = oini(&o, key, klen);
  if (rc != NQOK) return rc;
  ocrypt(&o, nonce, nlen, aad, alen, in, n, out, tag, 0);
  nqwipe(&o, sizeof o);
  return NQOK;
}

int nqocbd(const uint8_t *key, size_t klen, const uint8_t *nonce, size_t nlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           const uint8_t *tag, uint8_t *out) {
  ocb o;
  uint8_t t[BLK];
  int rc = oargs(key, nonce, nlen, aad, alen, in, n, out, tag);
  if (rc == NQOK) rc = oini(&o, key, klen);
  if (rc != NQOK) return rc;
  ocrypt(&o, nonce, nlen, aad, alen, in, n, out, t, 1);
  nqwipe(&o, sizeof o);
  if (!nqcteq(t, tag, BLK)) {
    /* nothing of a text whose tag is wrong is given out */
    if (n > 0) nqwipe(out, n);
    nqwipe(t, sizeof t);
    return NQEVRFY;
  }
  return NQOK;
}

/* ---- EAX: N' = OMAC^0(N), H' = OMAC^1(A), C = CTR_N'(M),
 * tag = N' + H' + OMAC^2(C) ---- */

static void omac(const nqaes *k, uint8_t t, const uint8_t *in, size_t n,
                 uint8_t *out) {
  uint8_t pre[BLK];
  memset(pre, 0, BLK);
  pre[BLK - 1] = t;
  nqcmacp(k, pre, BLK, in, n, out);
}

static int eargs(const uint8_t *key, const uint8_t *nonce, size_t nlen,
                 const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
                 const uint8_t *out, const uint8_t *tag) {
  if (key == NULL || tag == NULL || (nonce == NULL && nlen != 0) ||
      (aad == NULL && alen != 0) || ((in == NULL || out == NULL) && n != 0))
    return NQEARG;
  return NQOK;
}

int nqeaxe(const uint8_t *key, size_t klen, const uint8_t *nonce, size_t nlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           uint8_t *out, uint8_t *tag) {
  nqaes k;
  uint8_t np[BLK], h[BLK], c[BLK];
  int rc = eargs(key, nonce, nlen, aad, alen, in, n, out, tag), i;
  if (rc == NQOK) rc = nqaesk(&k, key, klen);
  if (rc != NQOK) return rc;
  omac(&k, 0, nonce, nlen, np);
  omac(&k, 1, aad, alen, h);
  if (n > 0) nqctrbe(&k, np, in, n, out);
  omac(&k, 2, out, n, c);
  for (i = 0; i < BLK; i++) tag[i] = (uint8_t)(np[i] ^ h[i] ^ c[i]);
  nqwipe(&k, sizeof k);
  return NQOK;
}

int nqeaxd(const uint8_t *key, size_t klen, const uint8_t *nonce, size_t nlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           const uint8_t *tag, uint8_t *out) {
  nqaes k;
  uint8_t np[BLK], h[BLK], c[BLK], t[BLK];
  int rc = eargs(key, nonce, nlen, aad, alen, in, n, out, tag), i;
  if (rc == NQOK) rc = nqaesk(&k, key, klen);
  if (rc != NQOK) return rc;
  omac(&k, 0, nonce, nlen, np);
  omac(&k, 1, aad, alen, h);
  omac(&k, 2, in, n, c);
  for (i = 0; i < BLK; i++) t[i] = (uint8_t)(np[i] ^ h[i] ^ c[i]);
  /* the tag first: the text is decrypted only when it is right */
  rc = nqcteq(t, tag, BLK) ? NQOK : NQEVRFY;
  if (rc == NQOK && n > 0) nqctrbe(&k, np, in, n, out);
  nqwipe(&k, sizeof k);
  nqwipe(t, sizeof t);
  return rc;
}
