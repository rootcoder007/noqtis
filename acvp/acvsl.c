/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for SLH-DSA (FIPS 205; ACVP algorithm SLH-DSA, revision
 * FIPS205): keyGen, sigGen and sigVer for all twelve parameter sets,
 * the external interface (pure and pre-hash, with a context) and the
 * internal one, deterministic and hedged signing.
 *
 *   acvsl <request.json> <response.json> [<expected.json>]
 *
 * Signing an "s" set takes seconds, so the test suite samples as
 * tests/tslh.c does: NQFAST=1 answers every 4th sigGen test of the "s"
 * sets; NQSLSUB=k answers every k-th sigGen test of any set and every
 * k-th keyGen and sigVer test. Either leaves the response incomplete;
 * with neither (as for a lab), every test is answered. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "slh/slh.h"

static int fast = 0;   /* NQFAST=1 */
static long sub = 0;   /* NQSLSUB=k */
static long sseen = 0; /* "s" sigGen tests seen (NQFAST) */
static long vseen = 0; /* tests seen (NQSLSUB) */

static int keygen(acvw *w, const nqslp *sp, const nqjs *t) {
  size_t l1 = 0, l2 = 0, l3 = 0;
  uint8_t *a, *b, *c, seed[96], pk[64], sk[128];
  int ok = 0;
  a = acvhex(nqjget(t, "skSeed"), &l1);
  b = acvhex(nqjget(t, "skPrf"), &l2);
  c = acvhex(nqjget(t, "pkSeed"), &l3);
  if (a != NULL && b != NULL && c != NULL && l1 == sp->n && l2 == sp->n &&
      l3 == sp->n) {
    memcpy(seed, a, sp->n);
    memcpy(seed + sp->n, b, sp->n);
    memcpy(seed + 2 * sp->n, c, sp->n);
    ok = nqslkgd(sp->alg, seed, 3 * sp->n, pk, sp->pk, sk, sp->sk) == NQOK;
  }
  if (ok) {
    acvkhex(w, "pk", pk, sp->pk);
    acvkhex(w, "sk", sk, sp->sk);
  }
  nqwipe(seed, sizeof seed);
  nqwipe(sk, sizeof sk);
  free(a);
  free(b);
  free(c);
  return ok;
}

typedef struct {
  const nqslp *sp;
  int inl, pre, det;
} grp;

static int siggen(acvw *w, const grp *gp, const nqjs *g, const nqjs *t) {
  const nqslp *sp = gp->sp;
  size_t skn = 0, mn = 0, cn = 0, rn = 0, outl = 0;
  uint8_t *sk, *m, *cx = NULL, *rnd = NULL, *sig;
  int ph = 0, rc = NQEARG;
  sk = acvhex(acvfld(t, g, "sk"), &skn);
  m = acvhex(nqjget(t, "message"), &mn);
  if (!gp->inl) cx = acvhex(nqjget(t, "context"), &cn);
  if (!gp->det) rnd = acvhex(nqjget(t, "additionalRandomness"), &rn);
  if (gp->pre) ph = acvhalg(acvs(t, "hashAlg"));
  sig = (uint8_t *)malloc(sp->sig);
  if (sk != NULL && m != NULL && sig != NULL && (gp->inl || cx != NULL) &&
      (gp->det || rnd != NULL) && ph >= 0) {
    if (gp->inl) {
      rc = nqslsigi(sp->alg, sk, skn, m, mn, rnd, gp->det ? 0 : rn, sig,
                    sp->sig, &outl);
    } else {
      rc = nqslsignd(sp->alg, sk, skn, m, mn, cx, cn, ph, rnd,
                     gp->det ? 0 : rn, sig, sp->sig, &outl);
    }
  }
  if (rc == NQOK) acvkhex(w, "signature", sig, outl);
  if (sk != NULL) nqwipe(sk, skn);
  free(sk);
  free(m);
  free(cx);
  free(rnd);
  free(sig);
  return rc == NQOK;
}

static int sigver(acvw *w, const grp *gp, const nqjs *g, const nqjs *t) {
  const nqslp *sp = gp->sp;
  size_t pn = 0, mn = 0, cn = 0, sn = 0;
  uint8_t *pk, *m, *cx = NULL, *sig;
  int ph = 0, rc, ok = 0;
  pk = acvhex(acvfld(t, g, "pk"), &pn);
  m = acvhex(nqjget(t, "message"), &mn);
  sig = acvhex(nqjget(t, "signature"), &sn);
  if (!gp->inl) cx = acvhex(nqjget(t, "context"), &cn);
  if (gp->pre) ph = acvhalg(acvs(t, "hashAlg"));
  if (pk != NULL && m != NULL && sig != NULL && (gp->inl || cx != NULL) &&
      ph >= 0) {
    rc = gp->inl ? nqslvrfi(sp->alg, pk, pn, m, mn, sig, sn)
                 : nqslvrfy(sp->alg, pk, pn, m, mn, cx, cn, ph, sig, sn);
    acvkbool(w, "testPassed", rc == NQOK);
    ok = 1;
  }
  free(pk);
  free(m);
  free(cx);
  free(sig);
  return ok;
}

/* 1 when the test is left out by the sampling */
static int skip(int fn, const nqslp *sp) {
  if (sub > 0) return vseen++ % sub != 0;
  if (fast && fn == 1 && sp->name[strlen(sp->name) - 1] == 's') {
    return sseen++ % 4 != 0;
  }
  return 0;
}

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *vs = acvset(pr), *gs = acvgrps(pr);
  const char *mode = acvs(vs, "mode");
  int fn;
  size_t i, j;
  if (!acvis(vs, "algorithm", "SLH-DSA") || mode == NULL) {
    fprintf(stderr, "acvsl: not an SLH-DSA request\n");
    return NQENOSUP;
  }
  fn = strcmp(mode, "keyGen") == 0   ? 0
       : strcmp(mode, "sigGen") == 0 ? 1
       : strcmp(mode, "sigVer") == 0 ? 2
                                     : -1;
  if (fn < 0) {
    fprintf(stderr, "acvsl: mode %s is not keyGen, sigGen or sigVer\n", mode);
    return NQENOSUP;
  }
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *ifc = acvs(g, "signatureInterface");
    uint64_t tg = 0;
    long left = 0;
    grp gp;
    gp.sp = nqslfind(acvs(g, "parameterSet"));
    gp.inl = ifc != NULL && strcmp(ifc, "internal") == 0;
    gp.pre = acvis(g, "preHash", "preHash");
    gp.det = nqjbool(nqjget(g, "deterministic"));
    if (!acvu(g, "tgId", &tg) || ts == NULL || gp.sp == NULL ||
        (fn == 1 && gp.det < 0) || (fn > 0 && ifc == NULL) ||
        (fn > 0 && !gp.inl && !gp.pre && !acvis(g, "preHash", "pure"))) {
      fprintf(stderr, "acvsl: group %lu: malformed or unknown parameters\n",
              (unsigned long)i);
      return NQEDEC;
    }
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      int ok;
      if (!acvu(t, "tcId", &tc)) return NQEDEC;
      if (skip(fn, gp.sp)) {
        left++;
        continue;
      }
      acvtbeg(w, tc);
      ok = fn == 0   ? keygen(w, gp.sp, t)
           : fn == 1 ? siggen(w, &gp, g, t)
                     : sigver(w, &gp, g, t);
      if (!ok) {
        fprintf(stderr, "acvsl: tgId %llu tcId %llu (%s): cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc, mode);
        return NQEDEC;
      }
      acvtend(w);
    }
    acvgend(w);
    if (left > 0) {
      fprintf(stderr, "acvsl: tgId %llu: %ld of %lu tests left out (%s)\n",
              (unsigned long long)tg, left, (unsigned long)ts->n,
              sub > 0 ? "NQSLSUB" : "NQFAST=1");
      *omit += left;
    }
  }
  return NQOK;
}

int main(int argc, char **argv) {
  const char *e = getenv("NQFAST");
  fast = e != NULL && e[0] == '1';
  e = getenv("NQSLSUB");
  if (e != NULL) sub = strtol(e, NULL, 10);
  return acvmain(argc, argv, "acvsl", run);
}
