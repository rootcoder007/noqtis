/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SLH-DSA (FIPS 205): parameter sets, key generation, the internal and
 * external signing and verification interfaces, and HashSLH-DSA. */
#include <string.h>

#include "slh/in.h"

/* n, h, d, h', a, k, m (FIPS 205 table 2); len = 2n + 3; pk = 2n,
 * sk = 4n, sig = (1 + k(a + 1) + h + d len) n. */
#define NQSLROW(nm, al, s2, n, h, d, a, k, m)                              \
  {nm, al, s2, n, h, d, (h) / (d), a, k, m, 2 * (n) + 3, 2 * (n), 4 * (n), \
   (size_t)(n) * (1 + (k) * ((a) + 1) + (h) + (d) * (2 * (n) + 3))}

const nqslp nqsltab[NQSLNSET] = {
    NQSLROW("SLH-DSA-SHA2-128s", NQSLH128S, 1, 16, 63, 7, 12, 14, 30),
    NQSLROW("SLH-DSA-SHA2-128f", NQSLH128F, 1, 16, 66, 22, 6, 33, 34),
    NQSLROW("SLH-DSA-SHA2-192s", NQSLH192S, 1, 24, 63, 7, 14, 17, 39),
    NQSLROW("SLH-DSA-SHA2-192f", NQSLH192F, 1, 24, 66, 22, 8, 33, 42),
    NQSLROW("SLH-DSA-SHA2-256s", NQSLH256S, 1, 32, 64, 8, 14, 22, 47),
    NQSLROW("SLH-DSA-SHA2-256f", NQSLH256F, 1, 32, 68, 17, 9, 35, 49),
    NQSLROW("SLH-DSA-SHAKE-128s", NQSLHK128S, 0, 16, 63, 7, 12, 14, 30),
    NQSLROW("SLH-DSA-SHAKE-128f", NQSLHK128F, 0, 16, 66, 22, 6, 33, 34),
    NQSLROW("SLH-DSA-SHAKE-192s", NQSLHK192S, 0, 24, 63, 7, 14, 17, 39),
    NQSLROW("SLH-DSA-SHAKE-192f", NQSLHK192F, 0, 24, 66, 22, 8, 33, 42),
    NQSLROW("SLH-DSA-SHAKE-256s", NQSLHK256S, 0, 32, 64, 8, 14, 22, 47),
    NQSLROW("SLH-DSA-SHAKE-256f", NQSLHK256F, 0, 32, 68, 17, 9, 35, 49),
};

const nqslp *nqslpar(nqsalg alg) {
  if (alg < NQSLH128S || alg > NQSLHK256F) return NULL;
  return &nqsltab[alg - NQSLH128S];
}

const nqslp *nqslfind(const char *name) {
  size_t i;
  if (name == NULL) return NULL;
  for (i = 0; i < NQSLNSET; i++) {
    if (strcmp(name, nqsltab[i].name) == 0) return &nqsltab[i];
  }
  return NULL;
}

/* ---- key generation ---- */

int nqslkgd(nqsalg alg, const uint8_t *seed, size_t seedlen,
            uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen) {
  const nqslp *p = nqslpar(alg);
  nqslc c;
  uint8_t a[32], root[NQSLNMX];
  unsigned n;
  if (p == NULL || seed == NULL || pk == NULL || sk == NULL) return NQEARG;
  n = p->n;
  if (seedlen != 3 * (size_t)n) return NQEARG;
  if (pklen < p->pk || sklen < p->sk) return NQEBUF;
  if (pklen > p->pk || sklen > p->sk) return NQEARG;
  /* algorithm 18: the root of the top XMSS tree */
  nqslini(&c, p, seed + 2 * n, seed);
  memset(a, 0, sizeof a);
  nqsalay(a, p->d - 1);
  nqsltrh(&c, 0, a, 0, p->hp, 0, root, NULL);
  memmove(sk, seed, 3 * (size_t)n);
  memcpy(sk + 3 * n, root, n);
  memcpy(pk, sk + 2 * n, 2 * (size_t)n);
  nqwipe(&c, sizeof c);
  nqwipe(root, sizeof root);
  return NQOK;
}

int nqslkg(nqsalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
           size_t sklen) {
  const nqslp *p = nqslpar(alg);
  uint8_t seed[3 * NQSLNMX];
  int rc;
  if (p == NULL) return NQEARG;
  rc = nqrand(seed, 3 * (size_t)p->n);
  if (rc == NQOK) {
    rc = nqslkgd(alg, seed, 3 * (size_t)p->n, pk, pklen, sk, sklen);
  }
  nqwipe(seed, sizeof seed);
  return rc;
}

/* ---- the internal algorithms (19 and 20) on M' = pre || msg ---- */

/* The digest's three parts: md (the FORS message), the tree index and
 * the leaf index (algorithm 19 lines 7 to 12). */
static void dsplit(const nqslp *p, const uint8_t *dg, uint64_t *tree,
                   uint32_t *leaf) {
  unsigned ka = (p->k * p->a + 7) / 8, tb = (p->h - p->hp + 7) / 8;
  unsigned lb = (p->hp + 7) / 8, i, tbits = p->h - p->hp;
  uint64_t t = 0;
  uint32_t l = 0;
  for (i = 0; i < tb; i++) t = (t << 8) | dg[ka + i];
  for (i = 0; i < lb; i++) l = (l << 8) | dg[ka + tb + i];
  if (tbits < 64) t &= ((uint64_t)1 << tbits) - 1u;
  *tree = t;
  *leaf = l & (((uint32_t)1 << p->hp) - 1u);
}

/* sk is checked; rnd is opt_rand (n bytes); sig holds p->sig bytes. */
static void sgn(const nqslp *p, const uint8_t *sk, const uint8_t *pre,
                size_t prelen, const uint8_t *msg, size_t msglen,
                const uint8_t *rnd, uint8_t *sig) {
  nqslc c;
  uint8_t pk[2 * NQSLNMX], dg[NQSLMMX], a[32], fpk[NQSLNMX];
  uint64_t tree;
  uint32_t leaf;
  unsigned n = p->n;
  /* PK.seed || PK.root are the public key, published anyway */
  memcpy(pk, sk + 2 * n, 2 * (size_t)n);
  NQSLDECL(pk, 2 * (size_t)n);
  nqslini(&c, p, pk, sk);
  nqslpm(p, sk + n, rnd, pre, prelen, msg, msglen, sig);
  /* R is the signature's first field; every index below derives from it
   * and the public message */
  NQSLDECL(sig, n);
  nqslhm(p, sig, pk, pre, prelen, msg, msglen, dg);
  dsplit(p, dg, &tree, &leaf);
  memset(a, 0, sizeof a);
  nqsatree(a, tree);
  nqsatype(a, NQSLFT);
  nqsakp(a, leaf);
  nqslfsg(&c, dg, a, sig + n, fpk);
  /* the FORS public key is what a verifier recomputes */
  NQSLDECL(fpk, n);
  nqslhsg(&c, fpk, tree, leaf, sig + n + (size_t)p->k * (p->a + 1) * n);
  nqwipe(&c, sizeof c);
  nqwipe(dg, sizeof dg);
  nqwipe(fpk, sizeof fpk);
}

/* 1 when sig (p->sig bytes) verifies; pk checked. */
static int vfy(const nqslp *p, const uint8_t *pk, const uint8_t *pre,
               size_t prelen, const uint8_t *msg, size_t msglen,
               const uint8_t *sig) {
  nqslc c;
  uint8_t dg[NQSLMMX], a[32], fpk[NQSLNMX];
  uint64_t tree;
  uint32_t leaf;
  unsigned n = p->n;
  nqslini(&c, p, pk, NULL);
  nqslhm(p, sig, pk, pre, prelen, msg, msglen, dg);
  dsplit(p, dg, &tree, &leaf);
  memset(a, 0, sizeof a);
  nqsatree(a, tree);
  nqsatype(a, NQSLFT);
  nqsakp(a, leaf);
  nqslffs(&c, sig + n, dg, a, fpk);
  return nqslhvf(&c, fpk, sig + n + (size_t)p->k * (p->a + 1) * n, tree,
                 leaf, pk + n);
}

/* The checks every signing call shares. */
static int sgchk(const nqslp *p, const uint8_t *sk, size_t sklen,
                 const uint8_t *msg, size_t msglen, uint8_t *sig,
                 size_t siglen) {
  if (p == NULL || sk == NULL || sig == NULL) return NQEARG;
  if (msg == NULL && msglen > 0) return NQEARG;
  if (sklen != p->sk) return NQEDEC;
  if (siglen < p->sig) return NQEBUF;
  return NQOK;
}

static int vfchk(const nqslp *p, const uint8_t *pk, size_t pklen,
                 const uint8_t *msg, size_t msglen, const uint8_t *sig,
                 size_t siglen) {
  if (p == NULL || pk == NULL || sig == NULL) return NQEARG;
  if (msg == NULL && msglen > 0) return NQEARG;
  if (pklen != p->pk || siglen != p->sig) return NQEDEC;
  return NQOK;
}

int nqslsigi(nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *msg, size_t msglen, const uint8_t *addrnd,
             size_t rndlen, uint8_t *sig, size_t siglen, size_t *outlen) {
  const nqslp *p = nqslpar(alg);
  int rc = sgchk(p, sk, sklen, msg, msglen, sig, siglen);
  if (rc != NQOK) return rc;
  if (addrnd == NULL ? rndlen != 0 : rndlen != p->n) return NQEARG;
  sgn(p, sk, NULL, 0, msg, msglen,
      addrnd != NULL ? addrnd : sk + 2 * p->n, sig);
  if (outlen != NULL) *outlen = p->sig;
  return NQOK;
}

int nqslvrfi(nqsalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *msg, size_t msglen, const uint8_t *sig,
             size_t siglen) {
  const nqslp *p = nqslpar(alg);
  int rc = vfchk(p, pk, pklen, msg, msglen, sig, siglen);
  if (rc != NQOK) return rc;
  return vfy(p, pk, NULL, 0, msg, msglen, sig) ? NQOK : NQEVRFY;
}

/* ---- the external interface: M' (algorithms 22 to 25) ---- */

/* HashSLH-DSA (section 10.2.2): the hashes, and the last byte of each
 * one's OID 2.16.840.1.101.3.4.2.x, DER 06 09 60 86 48 01 65 03 04 02 x */
typedef struct {
  nqhalg alg;
  uint8_t oid;
} phent;

static const phent phtab[] = {
    {NQS256, 0x01},     {NQS384, 0x02},     {NQS512, 0x03},
    {NQS224, 0x04},     {NQS512T224, 0x05}, {NQS512T256, 0x06},
    {NQS3224, 0x07},    {NQS3256, 0x08},    {NQS3384, 0x09},
    {NQS3512, 0x0a},    {NQSHK128, 0x0b},   {NQSHK256, 0x0c},
};

#define PREMAX (2 + 255 + 11 + 64)

/* Builds the prefix of M': 0 || |ctx| || ctx for pure SLH-DSA, or
 * 1 || |ctx| || ctx || OID || PH(msg) for HashSLH-DSA, in which case the
 * message itself drops out of M' (*use 0). */
static int mpre(const uint8_t *ctx, size_t ctxlen, int ph,
                const uint8_t *msg, size_t msglen, uint8_t *pre,
                size_t *prelen, int *use) {
  static const uint8_t oid[10] = {0x06, 0x09, 0x60, 0x86, 0x48,
                                  0x01, 0x65, 0x03, 0x04, 0x02};
  size_t i, at;
  if (ctx == NULL && ctxlen > 0) return NQEARG;
  if (ctxlen > 255) return NQEARG;
  pre[0] = ph != 0;
  pre[1] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(pre + 2, ctx, ctxlen);
  at = 2 + ctxlen;
  *use = 1;
  if (ph != 0) {
    for (i = 0; i < sizeof phtab / sizeof phtab[0]; i++) {
      if ((int)phtab[i].alg == ph) break;
    }
    if (i == sizeof phtab / sizeof phtab[0]) return NQEARG;
    memcpy(pre + at, oid, sizeof oid);
    pre[at + 10] = phtab[i].oid;
    at += 11;
    if (nqhash(phtab[i].alg, msg, msglen, pre + at,
               nqhlen(phtab[i].alg)) != NQOK) {
      return NQEARG;
    }
    at += nqhlen(phtab[i].alg);
    *use = 0;
  }
  *prelen = at;
  return NQOK;
}

/* rnd: n bytes; zero selects PK.seed when zdet. */
static int ext(nqsalg alg, const uint8_t *sk, size_t sklen,
               const uint8_t *msg, size_t msglen, const uint8_t *ctx,
               size_t ctxlen, int ph, const uint8_t *rnd, int zdet,
               uint8_t *sig, size_t siglen, size_t *outlen) {
  const nqslp *p = nqslpar(alg);
  uint8_t pre[PREMAX], r[NQSLNMX];
  size_t prelen = 0;
  int use = 1, rc = sgchk(p, sk, sklen, msg, msglen, sig, siglen);
  if (rc != NQOK) return rc;
  rc = mpre(ctx, ctxlen, ph, msg, msglen, pre, &prelen, &use);
  if (rc != NQOK) return rc;
  if (rnd == NULL) {
    memcpy(r, sk + 2 * p->n, p->n);
  } else {
    unsigned i;
    uint32_t z = 0;
    memcpy(r, rnd, p->n);
    if (zdet) {
      for (i = 0; i < p->n; i++) z |= r[i];
      /* all zero: take PK.seed, without a branch on the randomness */
      nqcmov(r, sk + 2 * p->n, p->n, (uint8_t)(1u + nqctmask(z)));
    }
  }
  sgn(p, sk, pre, prelen, use ? msg : NULL, use ? msglen : 0, r, sig);
  nqwipe(r, sizeof r);
  if (outlen != NULL) *outlen = p->sig;
  return NQOK;
}

int nqslsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
              const uint8_t *msg, size_t msglen, const uint8_t *ctx,
              size_t ctxlen, int ph, const uint8_t *rnd, size_t rndlen,
              uint8_t *sig, size_t siglen, size_t *outlen) {
  const nqslp *p = nqslpar(alg);
  if (p == NULL) return NQEARG;
  if (rnd == NULL ? rndlen != 0 : rndlen != p->n) return NQEARG;
  return ext(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, rnd, 1, sig,
             siglen, outlen);
}

int nqslsign(nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *msg, size_t msglen, const uint8_t *ctx,
             size_t ctxlen, int ph, uint8_t *sig, size_t siglen,
             size_t *outlen) {
  const nqslp *p = nqslpar(alg);
  uint8_t r[NQSLNMX];
  int rc = sgchk(p, sk, sklen, msg, msglen, sig, siglen);
  if (rc != NQOK) return rc;
  rc = nqrand(r, p->n);
  if (rc == NQOK) {
    rc = ext(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, r, 0, sig,
             siglen, outlen);
  }
  nqwipe(r, sizeof r);
  return rc;
}

int nqslvrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *msg, size_t msglen, const uint8_t *ctx,
             size_t ctxlen, int ph, const uint8_t *sig, size_t siglen) {
  const nqslp *p = nqslpar(alg);
  uint8_t pre[PREMAX];
  size_t prelen = 0;
  int use = 1, rc = vfchk(p, pk, pklen, msg, msglen, sig, siglen);
  if (rc != NQOK) return rc;
  rc = mpre(ctx, ctxlen, ph, msg, msglen, pre, &prelen, &use);
  if (rc != NQOK) return rc;
  return vfy(p, pk, pre, prelen, use ? msg : NULL, use ? msglen : 0, sig)
             ? NQOK
             : NQEVRFY;
}
