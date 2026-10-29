/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for ML-DSA (FIPS 204; ACVP algorithm ML-DSA, revision
 * FIPS204): keyGen, sigGen and sigVer for ML-DSA-44/65/87, with the
 * external interface (pure and pre-hash, with a context) and the
 * internal one (the message as given, or an external mu); deterministic
 * and hedged signing. Signing is the library's masked signer.
 *
 *   acvmd <request.json> <response.json> [<expected.json>] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "mldsa/mldsa.h"

static int salg(const char *s) {
  if (s == NULL) return 0;
  if (strcmp(s, "ML-DSA-44") == 0) return NQMLDSA44;
  if (strcmp(s, "ML-DSA-65") == 0) return NQMLDSA65;
  if (strcmp(s, "ML-DSA-87") == 0) return NQMLDSA87;
  return 0;
}

static int keygen(acvw *w, int alg, const nqjs *t) {
  static uint8_t pk[NQMDPKMAX], sk[NQMDSKMAX];
  nqssz sz = {0};
  size_t n;
  uint8_t *seed = acvhex(nqjget(t, "seed"), &n);
  int ok = seed != NULL && nqmdsz(alg, &sz) == NQOK &&
           nqmdkgd(alg, seed, n, pk, sizeof pk, sk, sizeof sk) == NQOK;
  free(seed);
  if (ok) {
    acvkhex(w, "pk", pk, sz.pk);
    acvkhex(w, "sk", sk, sz.sk);
  }
  nqwipe(sk, sizeof sk);
  return ok;
}

/* the group's interface: 0 external, 1 internal, 2 internal with mu */
typedef struct {
  int alg, ifc, pre, det;
} grp;

static int siggen(acvw *w, const grp *gp, const nqjs *g, const nqjs *t) {
  static uint8_t sig[NQMDSIGMAX];
  size_t skn, mn, cn, rn, mun, out = 0;
  uint8_t *sk, *m, *ctx, *rnd, *mu, zero[NQMDRND];
  int rc = NQEARG, ph = 0;
  sk = acvhex(acvfld(t, g, "sk"), &skn);
  m = acvhex(nqjget(t, "message"), &mn);
  ctx = acvhex(nqjget(t, "context"), &cn);
  rnd = acvhex(nqjget(t, "rnd"), &rn);
  mu = acvhex(nqjget(t, "mu"), &mun);
  memset(zero, 0, sizeof zero);
  if (gp->pre) ph = acvhalg(acvs(t, "hashAlg"));
  if (sk != NULL && ph >= 0 && (gp->det || rnd != NULL) &&
      (gp->ifc == 2 ? mu != NULL : m != NULL)) {
    const uint8_t *r = gp->det ? zero : rnd;
    size_t rl = gp->det ? sizeof zero : rn;
    if (gp->ifc == 0) {
      rc = nqmdsign(gp->alg, sk, skn, m, mn, ctx, ctx ? cn : 0, ph, r, rl,
                    sig, sizeof sig, &out);
    } else if (gp->ifc == 2) {
      rc = mun == NQMDMU ? nqmdsmu(gp->alg, sk, skn, mu, r, rl, NQMDMASK,
                                   sig, sizeof sig, &out)
                         : NQEARG;
    } else {
      rc = nqmdsigi(gp->alg, sk, skn, m, mn, r, rl, sig, sizeof sig, &out);
    }
  }
  if (rc == NQOK) acvkhex(w, "signature", sig, out);
  if (sk != NULL) nqwipe(sk, skn);
  free(sk);
  free(m);
  free(ctx);
  free(rnd);
  free(mu);
  return rc == NQOK;
}

static int sigver(acvw *w, const grp *gp, const nqjs *g, const nqjs *t) {
  size_t pkn, mn, cn, sn, mun;
  uint8_t *pk, *m, *ctx, *s, *mu;
  int rc = NQEARG, ph = 0, ok = 0;
  pk = acvhex(acvfld(t, g, "pk"), &pkn);
  m = acvhex(nqjget(t, "message"), &mn);
  ctx = acvhex(nqjget(t, "context"), &cn);
  s = acvhex(nqjget(t, "signature"), &sn);
  mu = acvhex(nqjget(t, "mu"), &mun);
  if (gp->pre) ph = acvhalg(acvs(t, "hashAlg"));
  if (pk != NULL && s != NULL && ph >= 0 &&
      (gp->ifc == 2 ? mu != NULL : m != NULL)) {
    if (gp->ifc == 0) {
      rc = nqmdvrfy(gp->alg, pk, pkn, m, mn, ctx, ctx ? cn : 0, ph, s, sn);
    } else if (gp->ifc == 2) {
      rc = mun == NQMDMU ? nqmdvmu(gp->alg, pk, pkn, mu, s, sn) : NQEDEC;
    } else {
      rc = nqmdvfyi(gp->alg, pk, pkn, m, mn, s, sn);
    }
    /* anything but NQOK fails: no verify, no decode, a bad length */
    acvkbool(w, "testPassed", rc == NQOK);
    ok = 1;
  }
  free(pk);
  free(m);
  free(ctx);
  free(s);
  free(mu);
  return ok;
}

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *vs = acvset(pr), *gs = acvgrps(pr);
  const char *mode = acvs(vs, "mode");
  int fn;
  size_t i, j;
  (void)omit;
  if (!acvis(vs, "algorithm", "ML-DSA") || mode == NULL) {
    fprintf(stderr, "acvmd: not an ML-DSA request\n");
    return NQENOSUP;
  }
  fn = strcmp(mode, "keyGen") == 0   ? 0
       : strcmp(mode, "sigGen") == 0 ? 1
       : strcmp(mode, "sigVer") == 0 ? 2
                                     : -1;
  if (fn < 0) {
    fprintf(stderr, "acvmd: mode %s is not keyGen, sigGen or sigVer\n", mode);
    return NQENOSUP;
  }
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *ifc = acvs(g, "signatureInterface");
    uint64_t tg = 0;
    grp gp;
    gp.alg = salg(acvs(g, "parameterSet"));
    gp.ifc = ifc != NULL && strcmp(ifc, "internal") == 0
                 ? (nqjbool(nqjget(g, "externalMu")) == 1 ? 2 : 1)
                 : 0;
    gp.pre = acvis(g, "preHash", "preHash");
    gp.det = nqjbool(nqjget(g, "deterministic"));
    if (!acvu(g, "tgId", &tg) || ts == NULL || gp.alg == 0 ||
        (fn == 1 && gp.det < 0) ||
        (fn > 0 && ifc == NULL)) {
      fprintf(stderr, "acvmd: group %lu: malformed or unknown parameters\n",
              (unsigned long)i);
      return NQEDEC;
    }
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      int ok;
      if (!acvu(t, "tcId", &tc)) return NQEDEC;
      acvtbeg(w, tc);
      ok = fn == 0   ? keygen(w, gp.alg, t)
           : fn == 1 ? siggen(w, &gp, g, t)
                     : sigver(w, &gp, g, t);
      if (!ok) {
        fprintf(stderr, "acvmd: tgId %llu tcId %llu (%s): cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc, mode);
        return NQEDEC;
      }
      acvtend(w);
    }
    acvgend(w);
  }
  return NQOK;
}

int main(int argc, char **argv) {
  return acvmain(argc, argv, "acvmd", run);
}
