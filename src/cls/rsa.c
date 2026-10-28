/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RSA signature verification (RFC 8017): RSAVP1 by Montgomery
 * exponentiation, then EMSA-PKCS1-v1_5 by building the one valid
 * encoding and comparing it whole (no parsing of the recovered block),
 * or EMSA-PSS-VERIFY with MGF1 or SHAKE (RFC 8702). */
#include <string.h>

#include "cls/cls.h"
#include "core/int.h"
#include "hash/h.h"

#define KB (NQRMAX / 8)

static int isshk(nqhalg h) { return h == NQSHK128 || h == NQSHK256; }

/* A SHA-2 or SHA-3 hash. */
static int isfix(nqhalg h) { return nqhlen(h) != 0 && !isshk(h); }

/* out = h(a || b || c), olen bytes (nqhlen(h) for a fixed hash, any for
 * SHAKE). */
static void hsh(nqhalg h, const uint8_t *a, size_t al, const uint8_t *b,
                size_t bl, const uint8_t *c, size_t cl, uint8_t *out,
                size_t olen) {
  nqhctx x;
  nqhini(&x, h);
  if (al > 0) nqhupd(&x, a, al);
  if (bl > 0) nqhupd(&x, b, bl);
  if (cl > 0) nqhupd(&x, c, cl);
  nqhfin(&x, out, olen);
}

/* RSAVP1: em = sig^e mod n as k bytes, k the modulus size. */
static int vp1(const nqck *k, const uint8_t *sig, size_t slen, uint8_t *em,
               size_t *kb) {
  uint32_t s[NQBL];
  size_t nl = k->n.nl;
  *kb = (k->bits + 7) / 8;
  if (slen != *kb) return NQEVRFY;
  nqcld(s, nl, sig, slen);
  if (!nqclt(s, k->n.m, nl)) return NQEVRFY;
  nqcto(s, s, &k->n);
  nqcpw(s, s, &k->e, 1, &k->n);
  nqcfr(s, s, &k->n);
  nqcst(em, *kb, s, nl);
  return NQOK;
}

int nqrsavh(const nqck *k, nqhalg h, const uint8_t *dig, size_t dlen,
            const uint8_t *sig, size_t slen) {
  static const uint8_t pre[] = {0x30, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                0x00, 0x05, 0x00, 0x04, 0x00};
  uint8_t em[KB], ex[KB];
  size_t kb, tl;
  int rc;
  if (k == NULL || k->kind != NQKRSA || dig == NULL || sig == NULL) {
    return NQEARG;
  }
  if (k->pss != 0) return NQEARG; /* an id-RSASSA-PSS key */
  if (!isfix(h)) return NQENOSUP;
  if (dlen != nqhlen(h)) return NQEARG;
  rc = vp1(k, sig, slen, em, &kb);
  if (rc != NQOK) return rc;
  /* EM = 00 01 FF..FF 00 DigestInfo; kb >= 256 leaves room for it */
  tl = sizeof pre + dlen;
  ex[0] = 0x00;
  ex[1] = 0x01;
  memset(ex + 2, 0xff, kb - tl - 3);
  ex[kb - tl - 1] = 0x00;
  memcpy(ex + kb - tl, pre, sizeof pre);
  ex[kb - tl + 1] = (uint8_t)(tl - 2);
  ex[kb - tl + 14] = (uint8_t)nqcho(h);
  ex[kb - tl + 18] = (uint8_t)dlen;
  memcpy(ex + kb - dlen, dig, dlen);
  return nqcteq(em, ex, kb) ? NQOK : NQEVRFY;
}

int nqrsav(const nqck *k, nqhalg h, const uint8_t *msg, size_t mlen,
           const uint8_t *sig, size_t slen) {
  uint8_t d[NQHMAX];
  if (msg == NULL && mlen > 0) return NQEARG;
  if (!isfix(h)) return k == NULL ? NQEARG : NQENOSUP;
  hsh(h, msg, mlen, NULL, 0, NULL, 0, d, nqhlen(h));
  return nqrsavh(k, h, d, nqhlen(h), sig, slen);
}

/* The PSS mask: MGF1 with hash g, or the SHAKE output for SHAKE. */
static void mgf(nqhalg g, const uint8_t *seed, size_t sl, uint8_t *out,
                size_t ol) {
  uint8_t c[4], b[NQHMAX];
  size_t gl = nqhlen(g), i, n;
  uint32_t ctr;
  if (isshk(g)) {
    hsh(g, seed, sl, NULL, 0, NULL, 0, out, ol);
    return;
  }
  for (i = 0, ctr = 0; i < ol; i += n, ctr++) {
    nqst32b(c, ctr);
    hsh(g, seed, sl, c, 4, NULL, 0, b, gl);
    n = ol - i < gl ? ol - i : gl;
    memcpy(out + i, b, n);
  }
}

static int pssok(const nqpss *p) {
  if (p == NULL || nqhlen(p->h) == 0) return 0;
  return isshk(p->h) ? p->mgf == p->h : isfix(p->mgf);
}

int nqpssvh(const nqck *k, const nqpss *p, const uint8_t *dig,
            size_t dlen, const uint8_t *sig, size_t slen) {
  static const uint8_t z8[8] = {0};
  uint8_t em[KB], db[KB], hh[NQHMAX];
  const uint8_t *e, *hs;
  size_t kb, hl, el, dl, zb, ps, i;
  uint32_t bad;
  int rc;
  if (k == NULL || k->kind != NQKRSA || dig == NULL || sig == NULL) {
    return NQEARG;
  }
  if (!pssok(p)) return p == NULL ? NQEARG : NQENOSUP;
  hl = nqhlen(p->h);
  if (dlen != hl) return NQEARG;
  /* the key's own parameters bind the signature (RFC 4055 3.1) */
  if (k->pss == 2 && (p->h != k->pp.h || p->mgf != k->pp.mgf ||
                      p->slen < k->pp.slen)) {
    return NQEVRFY;
  }
  rc = vp1(k, sig, slen, em, &kb);
  if (rc != NQOK) return rc;
  /* emBits = modBits - 1; when that is a multiple of 8 the first of the
   * kb bytes is outside EM and must be zero */
  el = (k->bits - 1 + 7) / 8;
  e = em + (kb - el);
  bad = kb > el ? em[0] : 0;
  if (p->slen > el || el < hl + p->slen + 2) return NQEVRFY;
  dl = el - hl - 1;
  hs = e + dl;
  zb = 8 * el - (k->bits - 1);
  bad |= e[el - 1] ^ 0xbcu;
  bad |= e[0] & (0xffu << (8 - zb)) & 0xffu;
  mgf(p->mgf, hs, hl, db, dl);
  for (i = 0; i < dl; i++) {
    db[i] ^= e[i];
  }
  db[0] &= (uint8_t)(0xffu >> zb);
  ps = dl - p->slen - 1;
  for (i = 0; i < ps; i++) {
    bad |= db[i];
  }
  bad |= db[ps] ^ 0x01u;
  hsh(p->h, z8, 8, dig, dlen, db + ps + 1, p->slen, hh, hl);
  bad |= (uint32_t)(nqcteq(hh, hs, hl) ^ 1);
  return bad == 0 ? NQOK : NQEVRFY;
}

int nqpssv(const nqck *k, const nqpss *p, const uint8_t *msg, size_t mlen,
           const uint8_t *sig, size_t slen) {
  uint8_t d[NQHMAX];
  if (msg == NULL && mlen > 0) return NQEARG;
  if (!pssok(p)) return p == NULL || k == NULL ? NQEARG : NQENOSUP;
  hsh(p->h, msg, mlen, NULL, 0, NULL, 0, d, nqhlen(p->h));
  return nqpssvh(k, p, d, nqhlen(p->h), sig, slen);
}
