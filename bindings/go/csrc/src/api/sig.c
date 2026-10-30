/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The public signature functions of noqtis.h: dispatch onto ML-DSA
 * (src/mldsa), SLH-DSA (src/slh), Ed25519 (src/ed) and the hybrid
 * ML-DSA + Ed25519 sets, which run both and join their keys and
 * signatures.
 *
 * The checks every function makes here, before the module runs, so that
 * all algorithms answer alike: an alg noqtis does not know is NQEARG; a
 * NULL pointer with a nonzero length (or a NULL output) is NQEARG; a
 * context over 255 bytes (241 for a hybrid) is NQEARG; an output buffer
 * smaller than the algorithm's size is NQEBUF (a larger one is fine: only
 * the defined number of bytes is written, and the module sees the exact
 * size). Input keys and signatures of the wrong length are left to the
 * module (NQEDEC). */
#include <string.h>

#include "core/int.h"
#include "ed/ed.h"
#include "mldsa/mldsa.h"
#include "slh/slh.h"

#define CTXMAX 255
/* the hybrid parts' context prefix */
#define HYB "noqtis-hybrid:"
#define HYBL (sizeof HYB - 1)

static int ismd(nqsalg alg) {
  return alg == NQMLDSA44 || alg == NQMLDSA65 || alg == NQMLDSA87;
}

static int ishy(nqsalg alg) {
  return alg == NQMDED44 || alg == NQMDED65 || alg == NQMDED87;
}

/* the ML-DSA set of a hybrid */
static nqsalg mdof(nqsalg alg) {
  return alg == NQMDED44 ? NQMLDSA44
                         : (alg == NQMDED65 ? NQMLDSA65 : NQMLDSA87);
}

/* NQOK with the sizes of alg, or NQEARG. */
static int sizes(nqsalg alg, nqssz *sz) {
  const nqslp *p;
  int rc;
  if (ismd(alg)) {
    return nqmdsz((int)alg, sz);
  }
  if (alg == NQED25519) {
    sz->pk = NQEDPK;
    sz->sk = NQEDSK;
    sz->sig = NQEDSIG;
    return NQOK;
  }
  if (ishy(alg)) {
    rc = nqmdsz((int)mdof(alg), sz);
    sz->pk += NQEDPK;
    sz->sk += NQEDSK;
    sz->sig += NQEDSIG;
    return rc;
  }
  p = nqslpar(alg);
  if (p == NULL) {
    return NQEARG;
  }
  sz->pk = p->pk;
  sz->sk = p->sk;
  sz->sig = p->sig;
  return NQOK;
}

int nqssize(nqsalg alg, nqssz *sz) {
  nqssz s;
  int rc;
  if (sz == NULL) {
    return NQEARG;
  }
  rc = sizes(alg, &s);
  if (rc == NQOK) {
    *sz = s;
  }
  return rc;
}

const char *nqsname(nqsalg alg) {
  const nqslp *p;
  switch (alg) {
  case NQMLDSA44:
    return "ML-DSA-44";
  case NQMLDSA65:
    return "ML-DSA-65";
  case NQMLDSA87:
    return "ML-DSA-87";
  case NQED25519:
    return "Ed25519";
  case NQMDED44:
    return "ML-DSA-44+Ed25519";
  case NQMDED65:
    return "ML-DSA-65+Ed25519";
  case NQMDED87:
    return "ML-DSA-87+Ed25519";
  default:
    break;
  }
  p = nqslpar(alg);
  return p == NULL ? NULL : p->name;
}

int nqsfind(const char *name, nqsalg *alg) {
  static const nqsalg own[7] = {NQMLDSA44, NQMLDSA65, NQMLDSA87, NQED25519,
                                NQMDED44,  NQMDED65,  NQMDED87};
  const nqslp *p;
  unsigned i;
  if (name == NULL || alg == NULL) {
    return NQEARG;
  }
  for (i = 0; i < 7; i++) {
    if (strcmp(name, nqsname(own[i])) == 0) {
      *alg = own[i];
      return NQOK;
    }
  }
  p = nqslfind(name);
  if (p == NULL) {
    return NQENOSUP;
  }
  *alg = p->alg;
  return NQOK;
}

/* Output key buffers: NULL is NQEARG, too small NQEBUF. */
static int kbuf(nqsalg alg, const uint8_t *pk, size_t pklen,
                const uint8_t *sk, size_t sklen, nqssz *sz) {
  int rc = sizes(alg, sz);
  if (rc != NQOK) {
    return rc;
  }
  if (pk == NULL || sk == NULL) {
    return NQEARG;
  }
  if (pklen < sz->pk || sklen < sz->sk) {
    return NQEBUF;
  }
  return NQOK;
}

/* clears the outputs a failed keygen was given, as the KEM functions
 * do, so no caller reads a half-written key */
static int kfail(int rc, uint8_t *pk, size_t pklen, uint8_t *sk,
                 size_t sklen) {
  if (pk != NULL) {
    nqwipe(pk, pklen);
  }
  if (sk != NULL) {
    nqwipe(sk, sklen);
  }
  return rc;
}

/* A hybrid key pair from ML-DSA's xi (32 bytes, or NULL for a fresh one)
 * and the Ed25519 private key (32 bytes, or NULL for a fresh one). */
static int hykg(nqsalg alg, const uint8_t *xi, const uint8_t *es,
                uint8_t *pk, uint8_t *sk, const nqssz *sz) {
  nqsalg md = mdof(alg);
  size_t mp = sz->pk - NQEDPK, ms = sz->sk - NQEDSK;
  int rc;
  rc = xi != NULL ? nqmdkgd((int)md, xi, 32, pk, mp, sk, ms)
                  : nqmdkg((int)md, pk, mp, sk, ms);
  if (rc != NQOK) return rc;
  if (es != NULL) {
    memcpy(sk + ms, es, NQEDSK);
  } else {
    rc = nqrand(sk + ms, NQEDSK);
    if (rc != NQOK) return rc;
  }
  return nqedkg(sk + ms, pk + mp);
}

int nqskg(nqsalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
          size_t sklen) {
  nqssz sz;
  int rc = kbuf(alg, pk, pklen, sk, sklen, &sz);
  if (rc != NQOK) {
    return kfail(rc, pk, pklen, sk, sklen);
  }
  if (ismd(alg)) {
    rc = nqmdkg((int)alg, pk, sz.pk, sk, sz.sk);
  } else if (alg == NQED25519) {
    rc = nqrand(sk, NQEDSK);
    if (rc == NQOK) rc = nqedkg(sk, pk);
  } else if (ishy(alg)) {
    rc = hykg(alg, NULL, NULL, pk, sk, &sz);
  } else {
    rc = nqslkg(alg, pk, sz.pk, sk, sz.sk);
  }
  return rc == NQOK ? NQOK : kfail(rc, pk, sz.pk, sk, sz.sk);
}

int nqskgd(nqsalg alg, const uint8_t *seed, size_t seedlen, uint8_t *pk,
           size_t pklen, uint8_t *sk, size_t sklen) {
  nqssz sz;
  /* the longest seed is SLH-DSA's 3n = 96 bytes; a copy, so the seed may
   * overlap pk or sk */
  uint8_t sd[96];
  int rc = kbuf(alg, pk, pklen, sk, sklen, &sz);
  if (rc != NQOK) {
    return kfail(rc, pk, pklen, sk, sklen);
  }
  if (seed == NULL || seedlen > sizeof sd) {
    return kfail(NQEARG, pk, sz.pk, sk, sz.sk);
  }
  memcpy(sd, seed, seedlen);
  if (ismd(alg)) {
    rc = nqmdkgd((int)alg, sd, seedlen, pk, sz.pk, sk, sz.sk);
  } else if (alg == NQED25519) {
    if (seedlen != NQEDSK) {
      rc = NQEARG;
    } else {
      memcpy(sk, sd, NQEDSK);
      rc = nqedkg(sk, pk);
    }
  } else if (ishy(alg)) {
    rc = seedlen == 32 + NQEDSK ? hykg(alg, sd, sd + 32, pk, sk, &sz)
                                : NQEARG;
  } else {
    rc = nqslkgd(alg, sd, seedlen, pk, sz.pk, sk, sz.sk);
  }
  nqwipe(sd, sizeof sd);
  return rc == NQOK ? NQOK : kfail(rc, pk, sz.pk, sk, sz.sk);
}

/* The common checks of sign and verify. key is sk or pk; out is the
 * signature buffer (sign) or NULL (verify). */
static int args(nqsalg alg, const uint8_t *key, const uint8_t *msg,
                size_t msglen, const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sig, nqssz *sz) {
  int rc = sizes(alg, sz);
  if (rc != NQOK) {
    return rc;
  }
  if (key == NULL || sig == NULL || (msg == NULL && msglen > 0) ||
      (ctx == NULL && ctxlen > 0) || ctxlen > CTXMAX ||
      (ishy(alg) && ctxlen > CTXMAX - HYBL)) {
    return NQEARG;
  }
  return NQOK;
}

/* Ed25519's pre-hash flag from ph: 0, or SHA-512 for Ed25519ph; any
 * other hash is NQENOSUP (-1 here). */
static int edph(int ph) {
  if (ph == 0) return 0;
  return ph == (int)NQS512 ? 1 : -1;
}

/* "noqtis-hybrid:" || ctx, the parts' context */
static size_t hyctx(uint8_t out[CTXMAX], const uint8_t *ctx, size_t ctxlen) {
  memcpy(out, HYB, HYBL);
  if (ctxlen > 0) memcpy(out + HYBL, ctx, ctxlen);
  return HYBL + ctxlen;
}

/* rnd NULL: hedged (fresh randomness inside the module). */
static int sign(nqsalg alg, const uint8_t *sk, size_t sklen,
                const uint8_t *msg, size_t msglen, const uint8_t *ctx,
                size_t ctxlen, int ph, const uint8_t *rnd, size_t rndlen,
                uint8_t *sig, size_t siglen, size_t *outlen) {
  nqssz sz;
  size_t n = 0;
  int rc;
  if (outlen != NULL) {
    *outlen = 0;
  }
  rc = args(alg, sk, msg, msglen, ctx, ctxlen, sig, &sz);
  if (rc != NQOK) {
    return rc;
  }
  if (siglen < sz.sig) {
    return NQEBUF;
  }
  if (ismd(alg)) {
    rc = nqmdsign((int)alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, rnd,
                  rndlen, sig, sz.sig, &n);
  } else if (alg == NQED25519) {
    int e = edph(ph);
    if (e < 0) {
      rc = NQENOSUP;
    } else if (sklen != NQEDSK) {
      rc = NQEDEC;
    } else {
      rc = nqedsign(sk, msg, msglen, ctx, ctxlen, e, sig);
      n = NQEDSIG;
    }
  } else if (ishy(alg)) {
    uint8_t hc[CTXMAX], es[NQEDSIG];
    size_t hl = hyctx(hc, ctx, ctxlen), ms = sz.sk - NQEDSK,
           mg = sz.sig - NQEDSIG;
    int e = edph(ph);
    if (e < 0) {
      rc = NQENOSUP;
    } else if (sklen != sz.sk) {
      rc = NQEDEC;
    } else {
      /* Ed25519 first, while msg is whole: sig may overlap msg, and
       * ML-DSA signs in place */
      rc = nqedsign(sk + ms, msg, msglen, hc, hl, e, es);
      if (rc == NQOK) {
        rc = nqmdsign((int)mdof(alg), sk, ms, msg, msglen, hc, hl, ph, rnd,
                      rndlen, sig, mg, &n);
      }
      if (rc == NQOK) {
        memcpy(sig + mg, es, NQEDSIG);
        n += NQEDSIG;
      }
    }
    nqwipe(es, sizeof es);
  } else if (rnd == NULL) {
    rc = nqslsign(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, sig,
                  sz.sig, &n);
  } else {
    rc = nqslsignd(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, rnd,
                   rndlen, sig, sz.sig, &n);
  }
  if (rc != NQOK) {
    nqwipe(sig, sz.sig);
    return rc;
  }
  if (outlen != NULL) {
    *outlen = n;
  }
  return NQOK;
}

int nqsign(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *msg,
           size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
           uint8_t *sig, size_t siglen, size_t *outlen) {
  return sign(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, NULL, 0, sig,
              siglen, outlen);
}

int nqsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *msg, size_t msglen, const uint8_t *ctx,
            size_t ctxlen, int ph, const uint8_t *rnd, size_t rndlen,
            uint8_t *sig, size_t siglen, size_t *outlen) {
  const nqslp *p = nqslpar(alg);
  size_t want;
  if (outlen != NULL) {
    *outlen = 0;
  }
  if (ismd(alg) || ishy(alg)) {
    want = NQMDRND;
  } else if (alg == NQED25519) {
    want = 0;
  } else if (p != NULL) {
    want = p->n;
  } else {
    return NQEARG;
  }
  /* rnd is required here, and exactly the standard's length (Ed25519 has
   * none: rnd may be NULL) */
  if ((rnd == NULL && want > 0) || rndlen != want) {
    return NQEARG;
  }
  return sign(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph,
              alg == NQED25519 ? NULL : rnd, rndlen, sig, siglen, outlen);
}

int nqvrfy(nqsalg alg, const uint8_t *pk, size_t pklen, const uint8_t *msg,
           size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
           const uint8_t *sig, size_t siglen) {
  nqssz sz;
  int rc = args(alg, pk, msg, msglen, ctx, ctxlen, sig, &sz);
  if (rc != NQOK) {
    return rc;
  }
  if (ismd(alg)) {
    rc = nqmdvrfy((int)alg, pk, pklen, msg, msglen, ctx, ctxlen, ph, sig,
                  siglen);
  } else if (alg == NQED25519) {
    int e = edph(ph);
    if (e < 0) {
      rc = NQENOSUP;
    } else if (pklen != NQEDPK || siglen != NQEDSIG) {
      rc = NQEDEC;
    } else {
      rc = nqedvrfy(pk, msg, msglen, ctx, ctxlen, e, sig);
    }
  } else if (ishy(alg)) {
    uint8_t hc[CTXMAX];
    size_t hl = hyctx(hc, ctx, ctxlen), mp = sz.pk - NQEDPK,
           mg = sz.sig - NQEDSIG;
    int e = edph(ph);
    if (e < 0) {
      rc = NQENOSUP;
    } else if (pklen != sz.pk || siglen != sz.sig) {
      rc = NQEDEC;
    } else {
      /* both parts, always: no early exit that would tell which failed */
      int r1 = nqmdvrfy((int)mdof(alg), pk, mp, msg, msglen, hc, hl, ph, sig,
                        mg);
      int r2 = nqedvrfy(pk + mp, msg, msglen, hc, hl, e, sig + mg);
      rc = r1 != NQOK ? r1 : r2;
    }
  } else {
    rc = nqslvrfy(alg, pk, pklen, msg, msglen, ctx, ctxlen, ph, sig,
                  siglen);
  }
  /* fail closed: nothing but the module's NQOK is a success */
  return rc == NQOK ? NQOK : (rc < 0 ? rc : NQEVRFY);
}
