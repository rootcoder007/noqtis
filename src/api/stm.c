/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Streaming signatures (nqsini, nqvini, nqsupd, nqsfin, nqvfin): the
 * message in pieces, the signature the one-call functions give.
 *
 * Pure ML-DSA streams because mu = SHAKE256(tr || 0 || |ctx| || ctx ||
 * M) is one pass over M: tr and the prefix are absorbed at the start,
 * the pieces as they come, and the final step signs or checks mu
 * through the external-mu path. The pre-hash variants (HashML-DSA,
 * HashSLH-DSA, Ed25519ph and the hybrids with SHA-512) stream the hash
 * of M and finish as the one-call functions do from it. Pure SLH-DSA
 * and pure Ed25519 (alone or in a hybrid) pass over M twice (the
 * randomiser or nonce first, then the digest), so they cannot stream:
 * NQENOSUP.
 *
 * The context is copied in and out with memcpy, as nqhctx is, and
 * checked before use; it holds no pointer. The key is given again at
 * the end and must be the one given at the start (its SHA3-256 is
 * kept). */
#include <string.h>

#include "core/int.h"
#include "ed/ed.h"
#include "hash/h.h"
#include "mldsa/mldsa.h"
#include "slh/slh.h"

#define MAG 0x6e717374u
#define SGN 1
#define VFY 2
#define CTXMAX 255
#define HYB "noqtis-hybrid:"
#define HYBL (sizeof HYB - 1)

typedef struct {
  uint32_t mag;
  int st;            /* SGN or VFY while open */
  nqsalg alg;
  int ph;
  size_t ctxlen;
  uint8_t ctx[CTXMAX];  /* the context the parts sign with */
  uint8_t kh[32];    /* SHA3-256 of the key given at the start */
  nqhctx mu;         /* ML-DSA (pure or pre-hash): SHAKE256 for mu */
  nqhctx h;          /* the pre-hash of the message */
} sst;

_Static_assert(sizeof(sst) <= sizeof(nqsctx), "nqsctx is too small");

static int ismd(nqsalg a) {
  return a == NQMLDSA44 || a == NQMLDSA65 || a == NQMLDSA87;
}
static int ishy(nqsalg a) {
  return a == NQMDED44 || a == NQMDED65 || a == NQMDED87;
}
static nqsalg mdof(nqsalg a) {
  return a == NQMDED44 ? NQMLDSA44 : (a == NQMDED65 ? NQMLDSA65 : NQMLDSA87);
}

/* the start, for sec 1 (sk) or 0 (pk) */
static int ini(nqsctx *c, nqsalg alg, const uint8_t *key, size_t klen,
               const uint8_t *ctx, size_t ctxlen, int ph, int sec) {
  sst s;
  nqssz z;
  uint8_t tr[64], oid[NQMDOID];
  int rc;
  if (c == NULL) return NQEARG;
  nqwipe(c, sizeof *c);
  rc = nqssize(alg, &z);
  if (rc != NQOK) return rc;
  if (key == NULL || (ctx == NULL && ctxlen > 0) || ctxlen > CTXMAX ||
      (ishy(alg) && ctxlen > CTXMAX - HYBL)) {
    return NQEARG;
  }
  if (klen != (sec ? z.sk : z.pk)) return NQEDEC;
  /* what cannot stream: pure SLH-DSA and pure Ed25519, and Ed25519ph
   * (alone or in a hybrid) with a hash other than SHA-512 */
  if (ph == 0 && !ismd(alg)) return NQENOSUP;
  if ((alg == NQED25519 || ishy(alg)) && ph != 0 && ph != (int)NQS512) {
    return NQENOSUP;
  }
  if (ph != 0 && nqmdoid(ph, oid) != NQOK) return NQEARG;
  memset(&s, 0, sizeof s);
  s.alg = alg;
  s.ph = ph;
  if (ishy(alg)) {
    memcpy(s.ctx, HYB, HYBL);
    if (ctxlen > 0) memcpy(s.ctx + HYBL, ctx, ctxlen);
    s.ctxlen = HYBL + ctxlen;
  } else {
    if (ctxlen > 0) memcpy(s.ctx, ctx, ctxlen);
    s.ctxlen = ctxlen;
  }
  rc = nqhash(NQS3256, key, klen, s.kh, sizeof s.kh);
  if (rc == NQOK && ph != 0) rc = nqhini(&s.h, (nqhalg)ph);
  if (rc == NQOK && (ismd(alg) || ishy(alg))) {
    /* mu's prefix: tr || ph? || |ctx| || ctx (|| OID) */
    nqssz mz;
    uint8_t pre[2];
    (void)nqssize(ismd(alg) ? alg : mdof(alg), &mz);
    if (sec) {
      memcpy(tr, key + 64, 64);
    } else {
      rc = nqhash(NQSHK256, key, mz.pk, tr, sizeof tr);
    }
    pre[0] = (uint8_t)(ph != 0);
    pre[1] = (uint8_t)s.ctxlen;
    if (rc == NQOK) rc = nqhini(&s.mu, NQSHK256);
    if (rc == NQOK) rc = nqhupd(&s.mu, tr, sizeof tr);
    if (rc == NQOK) rc = nqhupd(&s.mu, pre, 2);
    if (rc == NQOK) rc = nqhupd(&s.mu, s.ctx, s.ctxlen);
    if (rc == NQOK && ph != 0) rc = nqhupd(&s.mu, oid, sizeof oid);
  }
  if (rc == NQOK) {
    s.mag = MAG;
    s.st = sec ? SGN : VFY;
    memcpy(c, &s, sizeof s);
  }
  nqwipe(&s, sizeof s);
  nqwipe(tr, sizeof tr);
  return rc;
}

int nqsini(nqsctx *c, nqsalg alg, const uint8_t *sk, size_t sklen,
           const uint8_t *ctx, size_t ctxlen, int ph) {
  return ini(c, alg, sk, sklen, ctx, ctxlen, ph, 1);
}

int nqvini(nqsctx *c, nqsalg alg, const uint8_t *pk, size_t pklen,
           const uint8_t *ctx, size_t ctxlen, int ph) {
  return ini(c, alg, pk, pklen, ctx, ctxlen, ph, 0);
}

/* the context out of c, checked: NQESTATE for one ini did not leave */
static int load(const nqsctx *c, sst *s, int st) {
  nqssz z;
  memcpy(s, c, sizeof *s);
  if (s->mag != MAG || (s->st != st && st != 0) ||
      (s->st != SGN && s->st != VFY) || nqssize(s->alg, &z) != NQOK ||
      s->ctxlen > CTXMAX || (s->ph == 0 && !ismd(s->alg))) {
    nqwipe(s, sizeof *s);
    return NQESTATE;
  }
  return NQOK;
}

int nqsupd(nqsctx *c, const uint8_t *msg, size_t n) {
  sst s;
  int rc;
  if (c == NULL) return NQEARG;
  rc = load(c, &s, 0);
  if (rc != NQOK) return rc;
  if (msg == NULL && n > 0) {
    rc = NQEARG;
  } else if (s.ph != 0) {
    rc = nqhupd(&s.h, msg, n);
  } else {
    rc = nqhupd(&s.mu, msg, n);
  }
  if (rc == NQOK) memcpy(c, &s, sizeof s);
  nqwipe(&s, sizeof s);
  return rc;
}

/* the end of the message: mu (ML-DSA and the hybrids' ML-DSA part) and
 * the pre-hash dig (*dl bytes; 0 for pure ML-DSA) */
static int fin(sst *s, uint8_t mu[NQMDMU], uint8_t dig[NQHMAX],
               size_t *dl) {
  int rc = NQOK;
  *dl = 0;
  if (s->ph != 0) {
    *dl = nqhlen((nqhalg)s->ph);
    rc = nqhfin(&s->h, dig, *dl);
    if (rc == NQOK && (ismd(s->alg) || ishy(s->alg))) {
      rc = nqhupd(&s->mu, dig, *dl);
    }
  }
  if (rc == NQOK && (ismd(s->alg) || ishy(s->alg))) {
    rc = nqhfin(&s->mu, mu, NQMDMU);
  }
  return rc;
}

/* M' of HashSLH-DSA: 1 || |ctx| || ctx || OID || PH(M) */
static size_t mprime(const sst *s, const uint8_t *dig, size_t dl,
                     uint8_t *m) {
  m[0] = 1;
  m[1] = (uint8_t)s->ctxlen;
  memcpy(m + 2, s->ctx, s->ctxlen);
  (void)nqmdoid(s->ph, m + 2 + s->ctxlen);
  memcpy(m + 2 + s->ctxlen + NQMDOID, dig, dl);
  return 2 + s->ctxlen + NQMDOID + dl;
}

/* the key given at the end is the one given at the start */
static int samekey(const sst *s, const uint8_t *key, size_t klen) {
  uint8_t h[32];
  int ok = key != NULL && nqhash(NQS3256, key, klen, h, 32) == NQOK &&
           nqcteq(h, s->kh, 32);
  return ok;
}

int nqsfin(nqsctx *c, const uint8_t *sk, size_t sklen, const uint8_t *rnd,
           size_t rndlen, uint8_t *sig, size_t siglen, size_t *outlen) {
  sst s;
  nqssz z;
  uint8_t mu[NQMDMU], dig[NQHMAX], m[2 + CTXMAX + NQMDOID + NQHMAX];
  uint8_t r[32], es[NQEDSIG];
  size_t dl = 0, n = 0, want;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (c == NULL) return NQEARG;
  rc = load(c, &s, SGN);
  if (rc != NQOK) return rc;
  (void)nqssize(s.alg, &z);
  /* rnd as nqsignd's (and for Ed25519 any pointer with rndlen 0 asks
   * for RFC 8032's deterministic signature); NULL is nqsign's hedging */
  want = ismd(s.alg) || ishy(s.alg) ? NQMDRND
         : s.alg == NQED25519      ? 0
                                   : nqslpar(s.alg)->n;
  if (sig == NULL || (rnd == NULL && rndlen != 0) ||
      (rnd != NULL && rndlen != want)) {
    rc = NQEARG;
  } else if (!samekey(&s, sk, sklen)) {
    rc = NQEARG;
  } else if (siglen < z.sig) {
    rc = NQEBUF;
  } else {
    rc = fin(&s, mu, dig, &dl);
  }
  if (rc == NQOK && ismd(s.alg)) {
    rc = nqmdsmu((int)s.alg, sk, sklen, mu, rnd, rndlen, NQMDMASK, sig,
                 z.sig, &n);
  } else if (rc == NQOK && s.alg == NQED25519) {
    rc = rnd == NULL ? nqrand(r, 32) : NQOK;
    if (rc == NQOK) {
      rc = nqedsignz(sk, dig, dl, s.ctx, s.ctxlen, 2, rnd == NULL ? r : NULL,
                     sig);
    }
    n = NQEDSIG;
  } else if (rc == NQOK && ishy(s.alg)) {
    size_t ms = z.sk - NQEDSK, mg = z.sig - NQEDSIG;
    rc = rnd == NULL ? nqrand(r, 32) : NQOK;
    if (rc == NQOK) {
      rc = nqedsignz(sk + ms, dig, dl, s.ctx, s.ctxlen, 2,
                     rnd == NULL ? r : NULL, es);
    }
    if (rc == NQOK) {
      rc = nqmdsmu((int)mdof(s.alg), sk, ms, mu, rnd, rndlen, NQMDMASK, sig,
                   mg, &n);
    }
    if (rc == NQOK) {
      memcpy(sig + mg, es, NQEDSIG);
      n += NQEDSIG;
    }
  } else if (rc == NQOK) {
    /* HashSLH-DSA through the internal interface on M'; rnd zero is
     * the deterministic variant (PK.seed), chosen without a branch */
    const nqslp *p = nqslpar(s.alg);
    size_t ml = mprime(&s, dig, dl, m);
    if (rnd == NULL) {
      rc = nqrand(r, p->n);
    } else {
      uint32_t zz = 0;
      unsigned i;
      memcpy(r, rnd, p->n);
      for (i = 0; i < p->n; i++) zz |= r[i];
      nqcmov(r, sk + 2 * p->n, p->n, (uint8_t)(1u + nqctmask(zz)));
    }
    if (rc == NQOK) {
      rc = nqslsigi(s.alg, sk, sklen, m, ml, r, p->n, sig, z.sig, &n);
    }
  }
  nqwipe(&s, sizeof s);
  nqwipe(mu, sizeof mu);
  nqwipe(r, sizeof r);
  nqwipe(es, sizeof es);
  /* the context is used up, whatever happened */
  nqwipe(c, sizeof *c);
  if (rc != NQOK) {
    if (sig != NULL) nqwipe(sig, siglen < z.sig ? siglen : z.sig);
    return rc;
  }
  if (outlen != NULL) *outlen = n;
  return NQOK;
}

int nqvfin(nqsctx *c, const uint8_t *pk, size_t pklen, const uint8_t *sig,
           size_t siglen) {
  sst s;
  nqssz z;
  uint8_t mu[NQMDMU], dig[NQHMAX], m[2 + CTXMAX + NQMDOID + NQHMAX];
  size_t dl = 0;
  int rc;
  if (c == NULL) return NQEARG;
  rc = load(c, &s, VFY);
  if (rc != NQOK) return rc;
  (void)nqssize(s.alg, &z);
  if (sig == NULL || !samekey(&s, pk, pklen)) {
    rc = NQEARG;
  } else if (siglen != z.sig) {
    rc = NQEDEC;
  } else {
    rc = fin(&s, mu, dig, &dl);
  }
  if (rc == NQOK && ismd(s.alg)) {
    rc = nqmdvmu((int)s.alg, pk, pklen, mu, sig, siglen);
  } else if (rc == NQOK && s.alg == NQED25519) {
    rc = nqedvrfy(pk, dig, dl, s.ctx, s.ctxlen, 2, sig);
  } else if (rc == NQOK && ishy(s.alg)) {
    size_t mp = z.pk - NQEDPK, mg = z.sig - NQEDSIG;
    /* both parts, always, as nqvrfy */
    int r1 = nqmdvmu((int)mdof(s.alg), pk, mp, mu, sig, mg);
    int r2 = nqedvrfy(pk + mp, dig, dl, s.ctx, s.ctxlen, 2, sig + mg);
    rc = r1 != NQOK ? r1 : r2;
  } else if (rc == NQOK) {
    size_t ml = mprime(&s, dig, dl, m);
    rc = nqslvrfi(s.alg, pk, pklen, m, ml, sig, siglen);
  }
  nqwipe(&s, sizeof s);
  nqwipe(c, sizeof *c);
  return rc == NQOK ? NQOK : (rc < 0 ? rc : NQEVRFY);
}
