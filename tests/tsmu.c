/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA with an external mu, through the public API (nqsmu, nqsignmu,
 * nqvrfymu): every NIST ACVP sigGen and sigVer test of the internal
 * interface with externalMu true, for the three parameter sets
 * (vectors/acvp/ML-DSA-sig*-FIPS204); nqsignmu on nqsmu's mu gives
 * nqsignd's bytes (pure and pre-hash, with and without a context), and
 * nqvrfymu and nqvrfy agree, on many messages; and the errors. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "nqt.h"
#include "tvec.h"

static nqsalg salg(const char *ps) {
  if (ps == NULL) return (nqsalg)0;
  if (strcmp(ps, "ML-DSA-44") == 0) return NQMLDSA44;
  if (strcmp(ps, "ML-DSA-65") == 0) return NQMLDSA65;
  if (strcmp(ps, "ML-DSA-87") == 0) return NQMLDSA87;
  return (nqsalg)0;
}

static const nqjs *tgroup(const nqjs *gs, int64_t tg) {
  size_t i;
  for (i = 0; gs != NULL && i < gs->n; i++) {
    int64_t v;
    if (nqjint(nqjget(nqjat(gs, i), "tgId"), &v) == NQOK && v == tg) {
      return nqjat(gs, i);
    }
  }
  return NULL;
}

static const nqjs *tcase(const nqjs *g, int64_t tc) {
  const nqjs *ts = nqjget(g, "tests");
  size_t i;
  for (i = 0; ts != NULL && i < ts->n; i++) {
    int64_t v;
    if (nqjint(nqjget(nqjat(ts, i), "tcId"), &v) == NQOK && v == tc) {
      return nqjat(ts, i);
    }
  }
  return NULL;
}

static int hexeq(const nqjs *v, const uint8_t *b, size_t n) {
  size_t m;
  uint8_t *w = tvhex(v, &m);
  int ok = w != NULL && m == n && memcmp(w, b, n) == 0;
  free(w);
  return ok;
}

/* the ACVP set's externalMu groups; sg 1 for sigGen, 0 for sigVer */
static void tacvp(int sg) {
  const char *pf = sg ? "vectors/acvp/ML-DSA-sigGen-FIPS204/prompt.json"
                      : "vectors/acvp/ML-DSA-sigVer-FIPS204/prompt.json";
  const char *ef = sg
      ? "vectors/acvp/ML-DSA-sigGen-FIPS204/expectedResults.json"
      : "vectors/acvp/ML-DSA-sigVer-FIPS204/expectedResults.json";
  static uint8_t sig[8192];
  nqjs *pr = tvjs(pf), *ex = tvjs(ef);
  const nqjs *pg, *eg;
  long run = 0, pass = 0, sets[4] = {0, 0, 0, 0};
  size_t i, j;
  NQTCHK(pr != NULL && ex != NULL);
  if (pr == NULL || ex == NULL) goto out;
  pg = nqjget(pr, "testGroups");
  eg = nqjget(ex, "testGroups");
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests"), *e;
    nqsalg alg = salg(nqjstr(nqjget(g, "parameterSet")));
    int64_t tg = 0;
    int det = nqjbool(nqjget(g, "deterministic"));
    if (nqjbool(nqjget(g, "externalMu")) != 1) continue;
    (void)nqjint(nqjget(g, "tgId"), &tg);
    e = tgroup(eg, tg);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *r;
      int64_t tc = 0;
      size_t kn, mn, rn, sn, on = 0;
      uint8_t *k, *mu, *rnd, *s, zero[32];
      int ok = 0, rc;
      (void)nqjint(nqjget(t, "tcId"), &tc);
      r = tcase(e, tc);
      k = tvhex(nqjget(t, sg ? "sk" : "pk"), &kn);
      mu = tvhex(nqjget(t, "mu"), &mn);
      rnd = tvhex(nqjget(t, "rnd"), &rn);
      s = tvhex(nqjget(t, "signature"), &sn);
      memset(zero, 0, sizeof zero);
      run++;
      if (alg != 0 && k != NULL && mu != NULL && r != NULL) {
        if (sg) {
          rc = nqsignmu(alg, k, kn, mu, mn, det == 1 ? zero : rnd,
                        det == 1 ? sizeof zero : rn, sig, sizeof sig, &on);
          ok = rc == NQOK && hexeq(nqjget(r, "signature"), sig, on);
        } else if (s != NULL) {
          int want = nqjbool(nqjget(r, "testPassed"));
          rc = nqvrfymu(alg, k, kn, mu, mn, s, sn);
          ok = want == 1 ? rc == NQOK : (want == 0 && rc != NQOK);
        }
      }
      if (ok) {
        pass++;
        sets[alg - NQMLDSA44 + 1]++;
      } else {
        fprintf(stderr, "external mu %s tg %ld tc %ld fails\n",
                sg ? "sigGen" : "sigVer", (long)tg, (long)tc);
      }
      free(k);
      free(mu);
      free(rnd);
      free(s);
    }
  }
  printf("ACVP external-mu %s: %ld run, %ld passed (44: %ld, 65: %ld, "
         "87: %ld)\n",
         sg ? "sigGen" : "sigVer", run, pass, sets[1], sets[2], sets[3]);
  NQTCHK(run > 0 && sets[1] > 0 && sets[2] > 0 && sets[3] > 0);
  NQTEQI(pass, run);
out:
  nqjfree(pr);
  nqjfree(ex);
}

/* nqsignmu(nqsmu(...)) is nqsignd, and verifies both ways */
static void tsame(void) {
  static uint8_t pk[2592], sk[4896], s1[4627], s2[4627], msg[600];
  static const nqsalg al[3] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};
  static const int phs[3] = {0, NQS256, NQSHK128};
  uint8_t seed[32], rnd[32], mu[NQMU], ctx[16];
  size_t a, i;
  for (i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 31 + 7);
  for (a = 0; a < 3; a++) {
    nqssz z;
    NQTEQI(nqssize(al[a], &z), NQOK);
    memset(seed, (int)(a + 1), sizeof seed);
    NQTEQI(nqskgd(al[a], seed, 32, pk, z.pk, sk, z.sk), NQOK);
    for (i = 0; i < 12; i++) {
      size_t ml = i * 50, cl = i % 3 == 0 ? 0 : i, o1 = 0, o2 = 0;
      int ph = phs[i % 3];
      memset(ctx, (int)i, sizeof ctx);
      memset(rnd, i % 2 == 0 ? 0 : (int)(i + 3), sizeof rnd);
      NQTEQI(nqsmu(al[a], pk, z.pk, msg, ml, ctx, cl, ph, mu, NQMU), NQOK);
      NQTEQI(nqsignmu(al[a], sk, z.sk, mu, NQMU, rnd, 32, s1, sizeof s1,
                      &o1),
             NQOK);
      NQTEQI(nqsignd(al[a], sk, z.sk, msg, ml, ctx, cl, ph, rnd, 32, s2,
                     sizeof s2, &o2),
             NQOK);
      NQTEQI(o1, z.sig);
      NQTEQI(o2, z.sig);
      NQTEQM(s1, s2, z.sig);
      NQTEQI(nqvrfy(al[a], pk, z.pk, msg, ml, ctx, cl, ph, s1, o1), NQOK);
      NQTEQI(nqvrfymu(al[a], pk, z.pk, mu, NQMU, s2, o2), NQOK);
      /* hedged: another signature, still valid */
      NQTEQI(nqsignmu(al[a], sk, z.sk, mu, NQMU, NULL, 0, s1, sizeof s1,
                      &o1),
             NQOK);
      NQTEQI(nqvrfymu(al[a], pk, z.pk, mu, NQMU, s1, o1), NQOK);
      mu[i] ^= 1;
      NQTEQI(nqvrfymu(al[a], pk, z.pk, mu, NQMU, s1, o1), NQEVRFY);
    }
  }
}

static void terr(void) {
  static uint8_t pk[1312], sk[2560], sig[2420];
  uint8_t seed[32], mu[NQMU + 1], rnd[33];
  size_t on = 1;
  memset(seed, 3, sizeof seed);
  memset(mu, 0, sizeof mu);
  memset(rnd, 0, sizeof rnd);
  NQTEQI(nqskgd(NQMLDSA44, seed, 32, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqsmu(NQSLH128F, pk, 32, NULL, 0, NULL, 0, 0, mu, NQMU), NQENOSUP);
  NQTEQI(nqsmu(NQMDED44, pk, 32, NULL, 0, NULL, 0, 0, mu, NQMU), NQENOSUP);
  NQTEQI(nqsmu(NQED25519, pk, 32, NULL, 0, NULL, 0, 0, mu, NQMU), NQENOSUP);
  NQTEQI(nqsmu((nqsalg)99, pk, 32, NULL, 0, NULL, 0, 0, mu, NQMU), NQEARG);
  NQTEQI(nqsmu(NQMLDSA44, pk, sizeof pk, NULL, 0, NULL, 0, 0, mu, 63),
         NQEARG);
  NQTEQI(nqsmu(NQMLDSA44, pk, sizeof pk, NULL, 1, NULL, 0, 0, mu, NQMU),
         NQEARG);
  NQTEQI(nqsmu(NQMLDSA44, pk, sizeof pk, NULL, 0, mu, 256, 0, mu, NQMU),
         NQEARG);
  NQTEQI(nqsmu(NQMLDSA44, pk, sizeof pk - 1, NULL, 0, NULL, 0, 0, mu, NQMU),
         NQEDEC);
  NQTEQI(nqsmu(NQMLDSA44, pk, sizeof pk, NULL, 0, NULL, 0, 999, mu, NQMU),
         NQEARG);
  NQTEQI(nqsignmu(NQSLH128F, sk, 64, mu, NQMU, NULL, 0, sig, sizeof sig,
                  &on),
         NQENOSUP);
  NQTEQI(on, 0);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk, mu, NQMU + 1, NULL, 0, sig,
                  sizeof sig, &on),
         NQEARG);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk, mu, NQMU, rnd, 33, sig,
                  sizeof sig, &on),
         NQEARG);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk, mu, NQMU, NULL, 32, sig,
                  sizeof sig, &on),
         NQEARG);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk, mu, NQMU, NULL, 0, sig,
                  sizeof sig - 1, &on),
         NQEBUF);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk - 1, mu, NQMU, NULL, 0, sig,
                  sizeof sig, &on),
         NQEDEC);
  NQTEQI(nqsignmu(NQMLDSA44, sk, sizeof sk, mu, NQMU, rnd, 32, sig,
                  sizeof sig, &on),
         NQOK);
  NQTEQI(nqvrfymu(NQMLDSA44, pk, sizeof pk, mu, NQMU, sig, sizeof sig - 1),
         NQEDEC);
  NQTEQI(nqvrfymu(NQMLDSA44, pk, sizeof pk, mu, 0, sig, sizeof sig),
         NQEARG);
  NQTEQI(nqvrfymu(NQMDED65, pk, sizeof pk, mu, NQMU, sig, sizeof sig),
         NQENOSUP);
  NQTEQI(nqvrfymu(NQMLDSA44, pk, sizeof pk, mu, NQMU, sig, sizeof sig),
         NQOK);
}

int main(void) {
  tacvp(1);
  tacvp(0);
  tsame();
  terr();
  return nqtdone("tsmu");
}
