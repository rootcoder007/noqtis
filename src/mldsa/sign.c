/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA (FIPS 204): key generation, the unmasked signer, verification,
 * the message representative mu (pure, pre-hash, internal, external mu)
 * and the module's entry points. The masked signer is in msk.c. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"
#include "mldsa/md.h"
#include "mldsa/mldsa.h"

int nqmdsz(int alg, nqssz *sz) {
  const nqmdp *p = nqmdpar(alg);
  if (p == NULL || sz == NULL) return NQEARG;
  sz->pk = p->pk;
  sz->sk = p->sk;
  sz->sig = p->sig;
  return NQOK;
}

/* ---- keys ---- */

/* Power2Round: a = a1 2^13 + a0, -2^12 < a0 <= 2^12 */
static void p2r(int32_t a[NQMDN], int32_t a0[NQMDN]) {
  unsigned i;
  for (i = 0; i < NQMDN; i++) {
    int32_t a1 = (a[i] + (1 << 12) - 1) >> 13;
    a0[i] = a[i] - a1 * (1 << 13);
    a[i] = a1;
  }
}

typedef struct {
  uint8_t sb[128];   /* rho || rho' || K */
  uint8_t pre[34];
  nqmdpl s1[NQMDL], s1h[NQMDL], s2[NQMDK], t[NQMDK], t0[NQMDK];
} kgws;

static void kgint(const nqmdp *p, const uint8_t *xi, uint8_t *pk,
                  uint8_t *sk) {
  kgws w;
  const uint8_t *rho = w.sb, *rhop = w.sb + 32, *key = w.sb + 96;
  uint8_t *q;
  unsigned i;
  memcpy(w.pre, xi, 32);
  w.pre[32] = (uint8_t)p->k;
  w.pre[33] = (uint8_t)p->l;
  nqshk(256, w.pre, sizeof w.pre, w.sb, sizeof w.sb);
  NQMDPUB(w.sb, 32); /* rho is in the public key */
  for (i = 0; i < p->l; i++) nqmdeta(p, w.s1[i].c, rhop, (uint16_t)i);
  for (i = 0; i < p->k; i++) {
    nqmdeta(p, w.s2[i].c, rhop, (uint16_t)(p->l + i));
  }
  for (i = 0; i < p->l; i++) {
    w.s1h[i] = w.s1[i];
    nqmdntt(w.s1h[i].c);
  }
  nqmdmat(p, rho, w.t, w.s1h, NULL, NULL);
  for (i = 0; i < p->k; i++) {
    unsigned j;
    nqmdred(w.t[i].c);
    nqmdint(w.t[i].c);
    for (j = 0; j < NQMDN; j++) w.t[i].c[j] += w.s2[i].c[j];
    nqmdcadd(w.t[i].c);
    p2r(w.t[i].c, w.t0[i].c);
  }
  memcpy(pk, rho, 32);
  for (i = 0; i < p->k; i++) nqmdt1p(pk + 32 + 320 * i, w.t[i].c);
  /* sk = rho || K || tr || s1 || s2 || t0 */
  memcpy(sk, rho, 32);
  memcpy(sk + 32, key, 32);
  nqshk(256, pk, p->pk, sk + 64, 64);
  q = sk + 128;
  for (i = 0; i < p->l; i++, q += 32 * p->etab) nqmdetp(p, q, w.s1[i].c);
  for (i = 0; i < p->k; i++, q += 32 * p->etab) nqmdetp(p, q, w.s2[i].c);
  for (i = 0; i < p->k; i++, q += 416) nqmdt0p(q, w.t0[i].c);
  nqwipe(&w, sizeof w);
}

int nqmdkgd(int alg, const uint8_t *xi, size_t xilen, uint8_t *pk,
            size_t pklen, uint8_t *sk, size_t sklen) {
  const nqmdp *p = nqmdpar(alg);
  if (p == NULL || xi == NULL || pk == NULL || sk == NULL) return NQEARG;
  if (xilen != NQMDSEED) return NQEARG;
  if (pklen < p->pk || sklen < p->sk) return NQEBUF;
  kgint(p, xi, pk, sk);
  return NQOK;
}

int nqmdkg(int alg, uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen) {
  uint8_t xi[NQMDSEED];
  const nqmdp *p = nqmdpar(alg);
  int rc;
  if (p == NULL || pk == NULL || sk == NULL) return NQEARG;
  if (pklen < p->pk || sklen < p->sk) return NQEBUF;
  rc = nqrand(xi, sizeof xi);
  if (rc == NQOK) kgint(p, xi, pk, sk);
  nqwipe(xi, sizeof xi);
  return rc;
}

/* ---- mu ---- */

static const uint8_t oids[12] = {4, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12};

int nqmdoid(int ph, uint8_t *oid) {
  static const uint8_t pfx[10] = {0x06, 0x09, 0x60, 0x86, 0x48,
                                  0x01, 0x65, 0x03, 0x04, 0x02};
  if (oid == NULL || ph < (int)NQS224 || ph > (int)NQSHK256) return NQEARG;
  memcpy(oid, pfx, sizeof pfx);
  oid[10] = oids[ph - (int)NQS224];
  return NQOK;
}

/* SHAKE256(tr || pre || m, 64) */
static void mucalc(const uint8_t *tr, const uint8_t *pre, size_t prelen,
                   const uint8_t *m, size_t mlen, uint8_t *mu) {
  nqkctx c;
  nqshkini(&c, 256);
  nqkabs(&c, tr, 64);
  nqkabs(&c, pre, prelen);
  nqkabs(&c, m, mlen);
  nqksqz(&c, mu, NQMDMU);
  nqwipe(&c, sizeof c);
}

/* mu for the pure (ph 0) or pre-hash interface, from tr */
static int mufmt(const uint8_t *tr, const uint8_t *msg, size_t msglen,
                 const uint8_t *ctx, size_t ctxlen, int ph, uint8_t *mu) {
  uint8_t pre[2 + NQMDCTX + NQMDOID], dig[NQHMAX];
  size_t n = 2 + ctxlen;
  int rc;
  if ((msg == NULL && msglen > 0) || (ctx == NULL && ctxlen > 0)) {
    return NQEARG;
  }
  if (ctxlen > NQMDCTX) return NQEARG;
  pre[0] = (uint8_t)(ph != 0);
  pre[1] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(pre + 2, ctx, ctxlen);
  if (ph == 0) {
    mucalc(tr, pre, n, msg, msglen, mu);
    return NQOK;
  }
  rc = nqmdoid(ph, pre + n);
  if (rc != NQOK) return rc;
  n += NQMDOID;
  rc = nqhash((nqhalg)ph, msg, msglen, dig, nqhlen((nqhalg)ph));
  if (rc == NQOK) {
    mucalc(tr, pre, n, dig, nqhlen((nqhalg)ph), mu);
  }
  nqwipe(dig, sizeof dig);
  return rc;
}

int nqmdmu(int alg, const uint8_t *pk, size_t pklen, const uint8_t *msg,
           size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
           uint8_t *mu) {
  uint8_t tr[64];
  const nqmdp *p = nqmdpar(alg);
  if (p == NULL || pk == NULL || mu == NULL) return NQEARG;
  if (pklen != p->pk) return NQEDEC;
  nqshk(256, pk, p->pk, tr, sizeof tr);
  return mufmt(tr, msg, msglen, ctx, ctxlen, ph, mu);
}

/* ---- the unmasked signer ---- */

void nqmdhpk(const nqmdp *p, uint8_t *r, const uint8_t *h) {
  unsigned i, j, n = 0;
  memset(r, 0, p->omega + p->k);
  for (i = 0; i < p->k; i++) {
    for (j = 0; j < NQMDN; j++) {
      if (h[i * NQMDN + j]) r[n++] = (uint8_t)j;
    }
    r[p->omega + i] = (uint8_t)n;
  }
}

/* rho, K, s1, s2 and t0 from sk; 1 when s1 or s2 leaves [-eta, eta] */
int nqmdsku(const nqmdp *p, const uint8_t *sk, uint8_t *rho,
                uint8_t *key, nqmdpl *s1, nqmdpl *s2, nqmdpl *t0) {
  const uint8_t *q = sk + 128;
  uint32_t bad = 0;
  unsigned i;
  int r;
  memcpy(rho, sk, 32);
  memcpy(key, sk + 32, 32);
  NQMDPUB(rho, 32); /* rho is in the public key */
  for (i = 0; i < p->l; i++, q += 32 * p->etab) {
    nqmdetu(p, s1[i].c, q);
    bad |= nqmdchk(s1[i].c, (int32_t)p->eta + 1);
  }
  for (i = 0; i < p->k; i++, q += 32 * p->etab) {
    nqmdetu(p, s2[i].c, q);
    bad |= nqmdchk(s2[i].c, (int32_t)p->eta + 1);
  }
  for (i = 0; i < p->k; i++, q += 416) nqmdt0u(t0[i].c, q);
  /* a malformed key is reported, as the standard's sk checks would */
  r = bad != 0;
  NQMDPUB(&r, sizeof r);
  return r;
}

typedef struct {
  uint8_t rho[32], key[32], rhop[64], wb[NQMDK * 192];
  nqmdpl s1[NQMDL], s2[NQMDK], t0[NQMDK];
  nqmdpl y[NQMDL], z[NQMDL], w1[NQMDK], w0[NQMDK], h[NQMDK], cp;
  uint8_t hb[NQMDK * NQMDN];
  nqkctx c;
} spws;

/* 1 when the vector of n polynomials has a coefficient |a| >= b; the
 * decision (to reject the attempt) is public */
static int vchk(const nqmdpl *v, unsigned n, int32_t b) {
  uint32_t bad = 0;
  unsigned i;
  int r;
  for (i = 0; i < n; i++) bad |= nqmdchk(v[i].c, b);
  r = bad != 0;
  NQMDPUB(&r, sizeof r);
  return r;
}

int nqmdspl(const nqmdp *p, const uint8_t *sk, const uint8_t mu[64],
            const uint8_t rnd[32], uint8_t *sig) {
  spws w;
  unsigned i, j, att;
  size_t w1len = (size_t)p->k * 32 * p->w1b;
  int rc = NQEDEC;
  if (nqmdsku(p, sk, w.rho, w.key, w.s1, w.s2, w.t0)) goto out;
  /* rho'' = H(K || rnd || mu) */
  nqshkini(&w.c, 256);
  nqkabs(&w.c, w.key, 32);
  nqkabs(&w.c, rnd, 32);
  nqkabs(&w.c, mu, NQMDMU);
  nqksqz(&w.c, w.rhop, 64);
  for (i = 0; i < p->l; i++) nqmdntt(w.s1[i].c);
  for (i = 0; i < p->k; i++) {
    nqmdntt(w.s2[i].c);
    nqmdntt(w.t0[i].c);
  }
  for (att = 0; att < NQMDTRIES; att++) {
    unsigned n = 0;
    for (i = 0; i < p->l; i++) {
      nqmdmask(p, w.y[i].c, w.rhop, (uint16_t)(att * p->l + i));
      w.z[i] = w.y[i];
      nqmdntt(w.z[i].c);
    }
    nqmdmat(p, w.rho, w.w1, w.z, NULL, NULL);
    for (i = 0; i < p->k; i++) {
      nqmdred(w.w1[i].c);
      nqmdint(w.w1[i].c);
      nqmdcadd(w.w1[i].c);
      for (j = 0; j < NQMDN; j++) {
        w.w1[i].c[j] = nqmddec(p, &w.w0[i].c[j], w.w1[i].c[j]);
      }
      nqmdw1p(p, w.wb + i * 32 * p->w1b, w.w1[i].c);
    }
    /* c~ = H(mu || w1Encode(w1)) */
    nqshkini(&w.c, 256);
    nqkabs(&w.c, mu, NQMDMU);
    nqkabs(&w.c, w.wb, w1len);
    nqksqz(&w.c, sig, p->ctl);
    NQMDPUB(sig, p->ctl); /* c~ is the signature's first field */
    nqmdchal(p, w.cp.c, sig);
    nqmdntt(w.cp.c);
    /* z = y + c s1 */
    for (i = 0; i < p->l; i++) {
      nqmdpw(w.z[i].c, w.cp.c, w.s1[i].c);
      nqmdint(w.z[i].c);
      for (j = 0; j < NQMDN; j++) w.z[i].c[j] += w.y[i].c[j];
      nqmdred(w.z[i].c);
    }
    if (vchk(w.z, p->l, p->g1 - p->beta)) continue;
    /* r0 = LowBits(w - c s2) */
    for (i = 0; i < p->k; i++) {
      nqmdpw(w.h[i].c, w.cp.c, w.s2[i].c);
      nqmdint(w.h[i].c);
      for (j = 0; j < NQMDN; j++) w.w0[i].c[j] -= w.h[i].c[j];
      nqmdred(w.w0[i].c);
    }
    if (vchk(w.w0, p->k, p->g2 - p->beta)) continue;
    /* c t0 */
    for (i = 0; i < p->k; i++) {
      nqmdpw(w.h[i].c, w.cp.c, w.t0[i].c);
      nqmdint(w.h[i].c);
      nqmdred(w.h[i].c);
    }
    if (vchk(w.h, p->k, p->g2)) continue;
    for (i = 0; i < p->k; i++) {
      for (j = 0; j < NQMDN; j++) {
        uint32_t b = nqmdmkh(p, w.w0[i].c[j] + w.h[i].c[j], w.w1[i].c[j]);
        w.hb[i * NQMDN + j] = (uint8_t)b;
        n += b;
      }
    }
    /* the hint and its weight are published (or the attempt rejected) */
    NQMDPUB(w.hb, sizeof w.hb);
    NQMDPUB(&n, sizeof n);
    if (n > p->omega) continue;
    for (i = 0; i < p->l; i++) {
      nqmdzp(p, sig + p->ctl + (size_t)i * 32 * p->zb, w.z[i].c);
    }
    nqmdhpk(p, sig + p->ctl + (size_t)p->l * 32 * p->zb, w.hb);
    rc = NQOK;
    break;
  }
out:
  nqwipe(&w, sizeof w);
  return rc;
}

/* ---- verification ---- */

/* HintBitUnpack; 1 when the encoding is not the canonical one */
static int hun(const nqmdp *p, uint8_t *h, const uint8_t *y) {
  unsigned i, j, idx = 0;
  memset(h, 0, (size_t)p->k * NQMDN);
  for (i = 0; i < p->k; i++) {
    unsigned end = y[p->omega + i], first = idx;
    if (end < idx || end > p->omega) return 1;
    for (j = idx; j < end; j++) {
      if (j > first && y[j - 1] >= y[j]) return 1;
      h[i * NQMDN + y[j]] = 1;
    }
    idx = end;
  }
  for (j = idx; j < p->omega; j++) {
    if (y[j] != 0) return 1;
  }
  return 0;
}

typedef struct {
  uint8_t wb[NQMDK * 192], c2[64], hb[NQMDK * NQMDN];
  nqmdpl z[NQMDL], t1[NQMDK], w[NQMDK], cp;
  nqkctx c;
} vws;

static int vmu(const nqmdp *p, const uint8_t *pk, const uint8_t *mu,
               const uint8_t *sig) {
  vws w;
  unsigned i, j;
  size_t w1len = (size_t)p->k * 32 * p->w1b;
  const uint8_t *hs = sig + p->ctl + (size_t)p->l * 32 * p->zb;
  int rc = NQEVRFY;
  if (hun(p, w.hb, hs)) return NQEDEC;
  for (i = 0; i < p->l; i++) {
    nqmdzu(p, w.z[i].c, sig + p->ctl + (size_t)i * 32 * p->zb);
  }
  if (vchk(w.z, p->l, p->g1 - p->beta)) return NQEVRFY;
  for (i = 0; i < p->k; i++) nqmdt1u(w.t1[i].c, pk + 32 + 320 * i);
  nqmdchal(p, w.cp.c, sig);
  nqmdntt(w.cp.c);
  for (i = 0; i < p->l; i++) nqmdntt(w.z[i].c);
  nqmdmat(p, pk, w.w, w.z, NULL, NULL);
  for (i = 0; i < p->k; i++) {
    for (j = 0; j < NQMDN; j++) w.t1[i].c[j] *= 1 << 13;
    nqmdntt(w.t1[i].c);
    nqmdpw(w.t1[i].c, w.cp.c, w.t1[i].c);
    for (j = 0; j < NQMDN; j++) w.w[i].c[j] -= w.t1[i].c[j];
    nqmdred(w.w[i].c);
    nqmdint(w.w[i].c);
    nqmdcadd(w.w[i].c);
    for (j = 0; j < NQMDN; j++) {
      w.w[i].c[j] = nqmduse(p, w.w[i].c[j], w.hb[i * NQMDN + j]);
    }
    nqmdw1p(p, w.wb + i * 32 * p->w1b, w.w[i].c);
  }
  nqshkini(&w.c, 256);
  nqkabs(&w.c, mu, NQMDMU);
  nqkabs(&w.c, w.wb, w1len);
  nqksqz(&w.c, w.c2, p->ctl);
  if (nqcteq(w.c2, sig, p->ctl)) rc = NQOK;
  return rc;
}

/* ---- entry points ---- */

static int sgchk(const nqmdp *p, const uint8_t *sk, size_t sklen,
                 const uint8_t *rnd, size_t rndlen, uint8_t *sig,
                 size_t siglen) {
  if (p == NULL || sk == NULL || sig == NULL) return NQEARG;
  if (rnd != NULL && rndlen != NQMDRND) return NQEARG;
  if (sklen != p->sk) return NQEDEC;
  if (siglen < p->sig) return NQEBUF;
  return NQOK;
}

/* signs mu; rnd NULL draws it from nqrand */
static int sgmu(const nqmdp *p, const uint8_t *sk, const uint8_t *mu,
                const uint8_t *rnd, int msk, uint8_t *sig,
                size_t *outlen) {
  uint8_t r[NQMDRND];
  int rc = NQOK;
  if (rnd == NULL) {
    rc = nqrand(r, sizeof r);
  } else {
    memcpy(r, rnd, sizeof r);
  }
  if (rc == NQOK) {
    rc = msk == NQMDPLAIN ? nqmdspl(p, sk, mu, r, sig)
                          : nqmdsmk(p, sk, mu, r, sig);
  }
  nqwipe(r, sizeof r);
  if (rc != NQOK) {
    memset(sig, 0, p->sig);
  } else if (outlen != NULL) {
    *outlen = p->sig;
  }
  return rc;
}

int nqmdsmu(int alg, const uint8_t *sk, size_t sklen, const uint8_t *mu,
            const uint8_t *rnd, size_t rndlen, int msk, uint8_t *sig,
            size_t siglen, size_t *outlen) {
  const nqmdp *p = nqmdpar(alg);
  int rc = sgchk(p, sk, sklen, rnd, rndlen, sig, siglen);
  if (rc != NQOK) return rc;
  if (mu == NULL || (msk != NQMDPLAIN && msk != NQMDMASK)) return NQEARG;
  return sgmu(p, sk, mu, rnd, msk, sig, outlen);
}

int nqmdsigi(int alg, const uint8_t *sk, size_t sklen, const uint8_t *m,
             size_t mlen, const uint8_t *rnd, size_t rndlen, uint8_t *sig,
             size_t siglen, size_t *outlen) {
  uint8_t mu[NQMDMU];
  const nqmdp *p = nqmdpar(alg);
  int rc = sgchk(p, sk, sklen, rnd, rndlen, sig, siglen);
  if (rc != NQOK) return rc;
  if (m == NULL && mlen > 0) return NQEARG;
  mucalc(sk + 64, NULL, 0, m, mlen, mu);
  return sgmu(p, sk, mu, rnd, NQMDMASK, sig, outlen);
}

int nqmdsign(int alg, const uint8_t *sk, size_t sklen, const uint8_t *msg,
             size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t *rnd, size_t rndlen, uint8_t *sig,
             size_t siglen, size_t *outlen) {
  uint8_t mu[NQMDMU];
  const nqmdp *p = nqmdpar(alg);
  int rc = sgchk(p, sk, sklen, rnd, rndlen, sig, siglen);
  if (rc != NQOK) return rc;
  rc = mufmt(sk + 64, msg, msglen, ctx, ctxlen, ph, mu);
  if (rc != NQOK) return rc;
  return sgmu(p, sk, mu, rnd, NQMDMASK, sig, outlen);
}

static int vfchk(const nqmdp *p, const uint8_t *pk, size_t pklen,
                 const uint8_t *sig, size_t siglen) {
  if (p == NULL || pk == NULL || sig == NULL) return NQEARG;
  if (pklen != p->pk || siglen != p->sig) return NQEDEC;
  return NQOK;
}

int nqmdvmu(int alg, const uint8_t *pk, size_t pklen, const uint8_t *mu,
            const uint8_t *sig, size_t siglen) {
  const nqmdp *p = nqmdpar(alg);
  int rc = vfchk(p, pk, pklen, sig, siglen);
  if (rc != NQOK) return rc;
  if (mu == NULL) return NQEARG;
  return vmu(p, pk, mu, sig);
}

int nqmdvfyi(int alg, const uint8_t *pk, size_t pklen, const uint8_t *m,
             size_t mlen, const uint8_t *sig, size_t siglen) {
  uint8_t tr[64], mu[NQMDMU];
  const nqmdp *p = nqmdpar(alg);
  int rc = vfchk(p, pk, pklen, sig, siglen);
  if (rc != NQOK) return rc;
  if (m == NULL && mlen > 0) return NQEARG;
  nqshk(256, pk, p->pk, tr, sizeof tr);
  mucalc(tr, NULL, 0, m, mlen, mu);
  return vmu(p, pk, mu, sig);
}

int nqmdvrfy(int alg, const uint8_t *pk, size_t pklen, const uint8_t *msg,
             size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t *sig, size_t siglen) {
  uint8_t tr[64], mu[NQMDMU];
  const nqmdp *p = nqmdpar(alg);
  int rc = vfchk(p, pk, pklen, sig, siglen);
  if (rc != NQOK) return rc;
  nqshk(256, pk, p->pk, tr, sizeof tr);
  rc = mufmt(tr, msg, msglen, ctx, ctxlen, ph, mu);
  if (rc != NQOK) return rc;
  return vmu(p, pk, mu, sig);
}
