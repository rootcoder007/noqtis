/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The public signature functions of noqtis.h: dispatch onto ML-DSA
 * (src/mldsa) and SLH-DSA (src/slh).
 *
 * The checks every function makes here, before the module runs, so that
 * all algorithms answer alike: an alg noqtis does not know is NQEARG; a
 * NULL pointer with a nonzero length (or a NULL output) is NQEARG; a
 * context over 255 bytes is NQEARG; an output buffer smaller than the
 * algorithm's size is NQEBUF (a larger one is fine: only the defined
 * number of bytes is written, and the module sees the exact size). Input
 * keys and signatures of the wrong length are left to the module
 * (NQEDEC). */
#include <string.h>

#include "core/int.h"
#include "mldsa/mldsa.h"
#include "slh/slh.h"

#define CTXMAX 255

static int ismd(nqsalg alg) {
  return alg == NQMLDSA44 || alg == NQMLDSA65 || alg == NQMLDSA87;
}

/* NQOK with the sizes of alg, or NQEARG. */
static int sizes(nqsalg alg, nqssz *sz) {
  const nqslp *p;
  if (ismd(alg)) {
    return nqmdsz((int)alg, sz);
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
  default:
    break;
  }
  p = nqslpar(alg);
  return p == NULL ? NULL : p->name;
}

int nqsfind(const char *name, nqsalg *alg) {
  static const nqsalg md[3] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};
  const nqslp *p;
  unsigned i;
  if (name == NULL || alg == NULL) {
    return NQEARG;
  }
  for (i = 0; i < 3; i++) {
    if (strcmp(name, nqsname(md[i])) == 0) {
      *alg = md[i];
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

int nqskg(nqsalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
          size_t sklen) {
  nqssz sz;
  int rc = kbuf(alg, pk, pklen, sk, sklen, &sz);
  if (rc != NQOK) {
    return kfail(rc, pk, pklen, sk, sklen);
  }
  if (ismd(alg)) {
    rc = nqmdkg((int)alg, pk, sz.pk, sk, sz.sk);
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
      (ctx == NULL && ctxlen > 0) || ctxlen > CTXMAX) {
    return NQEARG;
  }
  return NQOK;
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
  if (outlen != NULL) {
    *outlen = 0;
  }
  if (!ismd(alg) && p == NULL) {
    return NQEARG;
  }
  /* rnd is required here, and exactly the standard's length */
  if (rnd == NULL ||
      rndlen != (ismd(alg) ? (size_t)NQMDRND : (size_t)p->n)) {
    return NQEARG;
  }
  return sign(alg, sk, sklen, msg, msglen, ctx, ctxlen, ph, rnd, rndlen,
              sig, siglen, outlen);
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
  } else {
    rc = nqslvrfy(alg, pk, pklen, msg, msglen, ctx, ctxlen, ph, sig,
                  siglen);
  }
  /* fail closed: nothing but the module's NQOK is a success */
  return rc == NQOK ? NQOK : (rc < 0 ? rc : NQEVRFY);
}
