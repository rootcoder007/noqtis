/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Drift statistics against R (tests/nqd/drift.R made
 * vectors/nqd/drift/expect.txt from ks.test, chisq.test and the
 * definitions written out), the summaries nqdstats keeps, nqddrift's
 * rows and levels, and the sketch's KS error against the exact one. */
#include "nqd/int.h"
#include "nqt.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

static double ex(const char *key) {
  char *b, *p;
  size_t n, kl = strlen(key);
  double v = NAN;
  if (qdread("vectors/nqd/drift/expect.txt", 1 << 20, &b, &n) != NQOK)
    return NAN;
  for (p = b; p != NULL && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1
                                                   : NULL) {
    if (strncmp(p, key, kl) == 0 && p[kl] == ' ') {
      v = strtod(p + kl + 1, NULL);
      break;
    }
  }
  qdfree(b);
  return v;
}

/* |a - b| within tol, relative when b is not near 0 */
#define NEAR(a, b, tol)                                                     \
  do {                                                                      \
    double a_ = (a), b_ = (b);                                              \
    double e_ = fabs(a_ - b_) / (fabs(b_) > 1e-300 ? fabs(b_) : 1);         \
    nqtn++;                                                                 \
    if (!(e_ <= (tol))) {                                                   \
      nqtfail++;                                                            \
      fprintf(stderr, "%s:%d: %s = %.17g, expected %.17g\n", __FILE__,      \
              __LINE__, #a, a_, b_);                                        \
    }                                                                       \
  } while (0)

static void dists(void) {
  double a[3] = {1, 1, 0}, b[3] = {1, 0, 1}, psi, js, x2, df;
  double want;
  NEAR(qdchisq(3.841458820694124, 1), 0.05, 1e-12);
  NEAR(qdchisq(18.307038053275146, 10), 0.05, 1e-12);
  NEAR(qdchisq(0, 3), 1, 0);
  /* P(K > 1.3580986393225505) = 0.05 */
  NEAR(qdkolm(1.3580986393225505), 0.049999999999992398, 1e-12);
  NEAR(qdkolm(0.5), 0.96394524366487511, 1e-12); /* R's own value */
  /* PSI and JS by hand: p = (1/2, 1/2, 0), q = (1/2, 0, 1/2) */
  qdpsi(a, b, 3, &psi, &js);
  want = (0.5 - 1e-6) * log(0.5 / 1e-6) + (1e-6 - 0.5) * log(1e-6 / 0.5);
  NEAR(psi, want, 1e-14);
  NEAR(js, 0.5 * log(2), 1e-14); /* (1/4)ln2 + 0 + ... = ln2 / 2 */
  /* homogeneity of a 2 x 2 table without correction: (10,20; 30,40) */
  {
    double r1[2] = {10, 20}, r2[2] = {30, 40};
    NEAR(qdhomog(r1, r2, 2, &x2, &df), 0.3729984836134872, 1e-12);
    NEAR(x2, 50.0 / 63, 1e-14);
    NEAR(df, 1, 0);
  }
  /* Benford on Benford's own proportions: X^2 0, p 1 */
  {
    double d[9];
    int i;
    for (i = 0; i < 9; i++)
      d[i] = 1e6 * log10(1 + 1.0 / (i + 1));
    NEAR(qdbenf(d, &x2), 1, 1e-12);
  }
  NQTEQI(qdfdig("-0.00321", 8), 3);
  NQTEQI(qdfdig("0", 1), 0);
  NQTEQI(qdfdig("5e-7", 4), 5);
}

/* the JSON of the drift row of column name in rep */
static djs *rowj(const nqdrep *rep, const char *name) {
  size_t i;
  for (i = 0; i < nqdrepn(rep); i++) {
    const char *j = nqdrepj(rep, i);
    djs *v = NULL;
    char why[100];
    if (j == NULL || qdjparse(j, strlen(j), &v, why, sizeof why) != NQOK)
      continue;
    if (strcmp(qdjget(v, "name")->s, name) == 0)
      return v;
    qdjfree(v);
  }
  return NULL;
}

static double jd(const djs *v, const char *k) {
  const djs *x = qdjget(v, k);
  return x != NULL && x->t == DJNUM ? x->d : NAN;
}

static int drift(const char *ref, const char *cur, const nqddopt *d,
                 nqdrep **rep) {
  char out[1 << 16], why[300], p[200];
  size_t n;
  int rc = nqdstats("vectors/nqd/drift", ref, NULL, out, sizeof out, &n, why,
                    sizeof why);
  if (rc != NQOK) {
    fprintf(stderr, "nqdstats %s: %s\n", ref, why);
    return rc;
  }
  snprintf(p, sizeof p, "vectors/nqd/drift/%s", cur);
  return nqddrift(out, n, p, NULL, d, rep);
}

static void small(void) {
  nqdrep *rep = NULL;
  djs *x, *c, *b;
  size_t i;
  int rc = drift("ref.csv", "cur.csv", NULL, &rep);
  NQTCHK(rep != NULL);
  if (rep == NULL)
    return;
  NQTEQI(rc, NQOK); /* fewer than 1,000 values: PSI warns, never fails */
  x = rowj(rep, "x");
  c = rowj(rep, "c");
  b = rowj(rep, "b");
  NQTCHK(x != NULL && c != NULL && b != NULL);
  if (x != NULL) {
    NEAR(jd(x, "ksd"), ex("ks.d"), 1e-14);
    NEAR(jd(x, "ksp"), ex("ks.p"), 1e-9);
    NQTCHK(qdjget(x, "ksexact")->t == DJTRUE);
    NEAR(jd(x, "kserr"), 0, 0);
    NEAR(jd(x, "psi"), ex("psi"), 1e-12);
    NEAR(jd(x, "js"), ex("js"), 1e-12);
    NQTCHK(strcmp(qdjget(x, "level")->s, "warn") == 0);
  }
  if (c != NULL) {
    NEAR(jd(c, "chisq"), ex("chi.x2"), 1e-12);
    NEAR(jd(c, "df"), ex("chi.df"), 0);
    NEAR(jd(c, "chisqp"), ex("chi.p"), 1e-10);
    NEAR(jd(c, "psi"), ex("cat.psi"), 1e-12);
  }
  if (b != NULL) {
    NEAR(jd(b, "benfordx2"), ex("ben.x2"), 1e-12);
    NEAR(jd(b, "benfordp"), ex("ben.p"), 1e-10);
  }
  qdjfree(x);
  qdjfree(c);
  qdjfree(b);
  for (i = 0; i < nqdrepn(rep); i++) {
    const char *k, *d;
    int ok;
    nqdrepi(rep, i, &k, &ok, &d);
    if (getenv("NQDVERB") != NULL)
      fprintf(stderr, "  %s %d %s\n", k, ok, d);
  }
  nqdrepfree(rep);
  /* the same file against itself: nothing drifts */
  NQTEQI(drift("ref.csv", "ref.csv", NULL, &rep), NQOK);
  x = rowj(rep, "x");
  NQTCHK(x != NULL && jd(x, "ksd") == 0 && jd(x, "psi") == 0 &&
         strcmp(qdjget(x, "level")->s, "ok") == 0);
  qdjfree(x);
  nqdrepfree(rep);
  /* with min-n 1, the PSI of x fails it */
  {
    nqddopt d;
    d.psiwarn = 0.1;
    d.psifail = 0.25;
    d.alpha = 0.001;
    d.minn = 1;
    d.benford = 1;
    NQTEQI(drift("ref.csv", "cur.csv", &d, &rep), NQEVRFY);
    nqdrepfree(rep);
  }
}

static void big(void) {
  nqdrep *rep = NULL;
  djs *y;
  double dr = ex("big.d"), dk, err;
  NQTEQI(drift("bigref.csv", "bigcur.csv", NULL, &rep), NQOK);
  y = rowj(rep, "y");
  NQTCHK(y != NULL);
  if (y != NULL) {
    dk = jd(y, "ksd");
    err = jd(y, "kserr");
    /* the sketch's D is within its stated error of the exact one */
    NQTCHK(fabs(dk - dr) <= err + 1e-15);
    NQTCHK(err > 0 && err <= 0.0011);
    NQTCHK(qdjget(y, "ksexact")->t == DJFALSE);
    printf("tddft: KS from the sketch %.6f, exact %.6f, |difference| %.6f, "
           "stated error %.6f\n",
           dk, dr, fabs(dk - dr), err);
    NEAR(jd(y, "psi"), ex("big.psi"), 1e-12);
    NEAR(jd(y, "js"), ex("big.js"), 1e-12);
    qdjfree(y);
  }
  /* R's asymptotic p from R's D */
  NEAR(qdkolm(sqrt(3000.0 * 2500 / 5500) * dr), ex("big.p"), 1e-9);
  nqdrepfree(rep);
}

static void refusals(void) {
  nqdrep *rep = NULL;
  /* a numeric reference against text (column name of a.csv) */
  static const char *st =
      "{\"path\":\"a\",\"rows\":2,\"columns\":[{\"name\":\"name\","
      "\"n\":2,\"q\":[[1,1],[2,2]],\"edges\":[1,2],\"counts\":[1,1,0]}]}";
  NQTEQI(nqddrift(st, strlen(st), "vectors/nqd/cap/data/a.csv", NULL, NULL,
                  &rep),
         NQEVRFY);
  nqdrepfree(rep);
  NQTEQI(nqddrift("{}", 2, "vectors/nqd/cap/data/a.csv", NULL, NULL, &rep),
         NQEVRFY);
  nqdrepfree(rep);
}

int main(void) {
  dists();
  small();
  big();
  refusals();
  return nqtdone("tddft");
}
