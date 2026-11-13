/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Drift: the summaries a record keeps of a CSV file ("stats", made by
 * nqdstats) and the comparison of a later file with them (nqddrift):
 * the two-sample Kolmogorov-Smirnov test from a quantile sketch, the
 * population stability index and Jensen-Shannon divergence over the
 * reference's bins or categories, the chi-square test of homogeneity
 * for categorical columns and Benford's first-digit test. The tests are
 * written out from their definitions (noqtis-drift(1)) and checked
 * against R's stats::ks.test and chisq.test (tests/nqd/drift.R). */
#include "int.h"

#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define QDPI 3.141592653589793238462643383279502884
#define QDSKN 1000 /* quantile sketch: 1,001 points, exact up to that */
#define QDBINS 10  /* PSI bins of a numeric column */
#define QDCATS 1000 /* categories kept */
#define QDEPS 1e-6  /* PSI floor of an empty bin */

/* ---- distributions ---- */

/* Q(a, x), the regularised upper incomplete gamma function: a series
 * for P below a + 1, a continued fraction (modified Lentz) above */
static double gamq(double a, double x) {
  double lg = lgamma(a);
  int i;
  if (x <= 0)
    return 1;
  if (x < a + 1) {
    double ap = a, sum = 1 / a, del = sum;
    for (i = 0; i < 10000; i++) {
      ap += 1;
      del *= x / ap;
      sum += del;
      if (fabs(del) < fabs(sum) * 1e-17)
        break;
    }
    return 1 - sum * exp(-x + a * log(x) - lg);
  } else {
    double b = x + 1 - a, c = 1 / DBL_MIN, d = 1 / b, h = d;
    for (i = 1; i < 10000; i++) {
      double an = -i * (i - a), del;
      b += 2;
      d = an * d + b;
      if (fabs(d) < DBL_MIN)
        d = DBL_MIN;
      c = b + an / c;
      if (fabs(c) < DBL_MIN)
        c = DBL_MIN;
      d = 1 / d;
      del = d * c;
      h *= del;
      if (fabs(del - 1) < 1e-17)
        break;
    }
    return exp(-x + a * log(x) - lg) * h;
  }
}

double qdchisq(double x2, double df) {
  return df <= 0 ? 1 : gamq(df / 2, x2 / 2);
}

/* P(K > x) of the Kolmogorov distribution, as R's
 * pkolmogorov_two_limit with tol 1e-6 */
double qdkolm(double x) {
  const double tol = 1e-6;
  int k, kmax = (int)sqrt(2 - log(tol));
  double p;
  if (x <= 0)
    return 1;
  if (x < 1) {
    double z = -(QDPI / 2 * QDPI / 4) / (x * x), w = log(x), s = 0;
    for (k = 1; k < kmax; k += 2)
      s += exp(k * k * z - w);
    p = s * sqrt(2 * QDPI);
  } else {
    double z = -2 * x * x, s = -1, old = 0, nw = 1;
    k = 1;
    while (fabs(old - nw) > tol) {
      old = nw;
      nw += 2 * s * exp(z * k * k);
      s *= -1;
      k++;
    }
    p = nw;
  }
  return 1 - p;
}

/* P(D >= d) for two samples of m and n with no ties, exactly (the
 * recursion of R's psmirnov2x before R 4.3) */
double qdsmir(double d, int m, int n) {
  double md, nd, q, *u, w, r;
  int i, j;
  if (m > n) {
    i = n;
    n = m;
    m = i;
  }
  md = m;
  nd = n;
  q = (0.5 + floor(d * md * nd - 1e-7)) / (md * nd);
  u = (double *)qdmal((size_t)(n + 1) * sizeof *u);
  if (u == NULL)
    return -1;
  for (j = 0; j <= n; j++)
    u[j] = (j / nd > q) ? 0 : 1;
  for (i = 1; i <= m; i++) {
    w = (double)i / (double)(i + n);
    u[0] = (i / md > q) ? 0 : w * u[0];
    for (j = 1; j <= n; j++)
      u[j] = fabs(i / md - j / nd) > q ? 0 : w * u[j] + u[j - 1];
  }
  r = u[n];
  qdfree(u);
  r = 1 - r;
  return r < 0 ? 0 : r;
}

/* chi-square test of homogeneity of a 2 x k table (rows a and b),
 * columns empty on both sides left out; df the columns left less 1 */
double qdhomog(const double *a, const double *b, size_t k, double *x2,
               double *df) {
  double na = 0, nb = 0, n;
  size_t i, c = 0;
  *x2 = 0;
  for (i = 0; i < k; i++) {
    na += a[i];
    nb += b[i];
  }
  n = na + nb;
  for (i = 0; i < k; i++) {
    double t = a[i] + b[i], ea, eb;
    if (t <= 0)
      continue;
    c++;
    ea = na * t / n;
    eb = nb * t / n;
    *x2 += (a[i] - ea) * (a[i] - ea) / ea + (b[i] - eb) * (b[i] - eb) / eb;
  }
  *df = c > 1 && na > 0 && nb > 0 ? (double)(c - 1) : 0;
  return qdchisq(*x2, *df);
}

/* Benford's law against nine first-digit counts: X^2 on 8 df */
double qdbenf(const double *d, double *x2) {
  double n = 0;
  int i;
  *x2 = 0;
  for (i = 0; i < 9; i++)
    n += d[i];
  if (n <= 0)
    return 1;
  for (i = 0; i < 9; i++) {
    double e = n * log10(1 + 1.0 / (i + 1));
    *x2 += (d[i] - e) * (d[i] - e) / e;
  }
  return qdchisq(*x2, 8);
}

/* the first significant digit of a number's text, 0 for zero */
int qdfdig(const char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (c == 'e' || c == 'E')
      break;
    if (c >= '1' && c <= '9')
      return c - '0';
  }
  return 0;
}

/* ---- columns of a file ---- */

typedef struct {
  char *k;
  size_t kl;
  uint64_t n;
} qdcat;

typedef struct {
  char *name;
  int num; /* still numeric (every value so far) */
  uint64_t n, nulls, bad;
  double *v;
  size_t nv, cv;
  qdcat *h; /* category counts, open addressing */
  size_t nh, ch;
  double dig[9];
  int err;
} qdccol;

static uint64_t fnv(const char *s, size_t n) {
  uint64_t h = 1469598103934665603u;
  size_t i;
  for (i = 0; i < n; i++)
    h = (h ^ (unsigned char)s[i]) * 1099511628211u;
  return h;
}

static void catadd(qdccol *c, const char *s, size_t n) {
  size_t i, m;
  if (c->err)
    return;
  if (2 * (c->nh + 1) > c->ch) {
    size_t nc = c->ch ? c->ch * 2 : 64, j;
    qdcat *nh;
    if (nc > ((size_t)1 << 25)) {
      c->err = NQELIM;
      return;
    }
    nh = (qdcat *)qdmal(nc * sizeof *nh);
    if (nh == NULL) {
      c->err = NQEMEM;
      return;
    }
    memset(nh, 0, nc * sizeof *nh);
    for (j = 0; j < c->ch; j++) {
      if (c->h[j].k == NULL)
        continue;
      for (i = (size_t)fnv(c->h[j].k, c->h[j].kl) & (nc - 1);
           nh[i].k != NULL; i = (i + 1) & (nc - 1))
        ;
      nh[i] = c->h[j];
    }
    qdfree(c->h);
    c->h = nh;
    c->ch = nc;
  }
  m = c->ch - 1;
  for (i = (size_t)fnv(s, n) & m;; i = (i + 1) & m) {
    if (c->h[i].k == NULL) {
      if ((c->h[i].k = qddup(s, n)) == NULL) {
        c->err = NQEMEM;
        return;
      }
      c->h[i].kl = n;
      c->h[i].n = 1;
      c->nh++;
      return;
    }
    if (c->h[i].kl == n && memcmp(c->h[i].k, s, n) == 0) {
      c->h[i].n++;
      return;
    }
  }
}

static uint64_t catget(const qdccol *c, const char *s, size_t n) {
  size_t i, m;
  if (c->ch == 0)
    return 0;
  m = c->ch - 1;
  for (i = (size_t)fnv(s, n) & m; c->h[i].k != NULL; i = (i + 1) & m)
    if (c->h[i].kl == n && memcmp(c->h[i].k, s, n) == 0)
      return c->h[i].n;
  return 0;
}

static void numadd(qdccol *c, double d) {
  if (c->err)
    return;
  if (c->nv == c->cv) {
    size_t nc = c->cv ? c->cv * 2 : 256, i;
    double *nv;
    if (nc > ((size_t)1 << 31)) {
      c->err = NQELIM;
      return;
    }
    nv = (double *)qdmal(nc * sizeof *nv);
    if (nv == NULL) {
      c->err = NQEMEM;
      return;
    }
    for (i = 0; i < c->nv; i++)
      nv[i] = c->v[i];
    qdfree(c->v);
    c->v = nv;
    c->cv = nc;
  }
  c->v[c->nv++] = d;
}

static void colfree(qdccol *c, size_t n) {
  size_t i, j;
  if (c == NULL)
    return;
  for (i = 0; i < n; i++) {
    for (j = 0; j < c[i].ch; j++)
      qdfree(c[i].h[j].k);
    qdfree(c[i].h);
    qdfree(c[i].v);
    qdfree(c[i].name);
  }
  qdfree(c);
}

static int dcmp(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

/* reads the CSV file at p into columns: every value is counted as a
 * category and, while the column stays numeric, kept as a number.
 * ponytail: holds every number of the file in memory (8 bytes each)
 * to sort it; a merging quantile sketch (KLL) would bound that. */
static int readcols(const char *p, const nqdcsvopt *o, qdccol **out,
                    size_t *nc, uint64_t *rows, char *why, size_t wcap) {
  qdcsv c;
  int rc, got, header = o == NULL || !o->noheader;
  char delim = o != NULL && o->delim ? o->delim : ',';
  qdccol *cs = NULL;
  size_t n = 0, i;
  *out = NULL;
  *rows = 0;
  if (qdcsvfile(&c, p, delim) != NQOK) {
    qdwhy(why, wcap, "%s: cannot be read", p);
    return NQEIO;
  }
  if ((rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  if (!got) {
    qdwhy(why, wcap, "%s: empty", p);
    rc = NQEDEC;
    goto out;
  }
  n = c.nf;
  cs = (qdccol *)qdmal(n * sizeof *cs);
  if (cs == NULL) {
    rc = NQEMEM;
    goto out;
  }
  memset(cs, 0, n * sizeof *cs);
  for (i = 0; i < n; i++) {
    char g[32];
    const char *nm = qdcsvf(&c, i, NULL);
    snprintf(g, sizeof g, "V%lu", (unsigned long)i + 1);
    cs[i].name = header ? qddup(nm, strlen(nm)) : qddup(g, strlen(g));
    cs[i].num = 1;
    if (cs[i].name == NULL) {
      rc = NQEMEM;
      goto out;
    }
  }
  if (header && (rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  while (got) {
    if (c.nf != n) {
      qdwhy(why, wcap, "%s: line %llu has %lu fields, the first line %lu",
            p, (unsigned long long)c.recline, (unsigned long)c.nf,
            (unsigned long)n);
      rc = NQEDEC;
      goto out;
    }
    (*rows)++;
    for (i = 0; i < n; i++) {
      size_t l;
      const char *v = qdcsvf(&c, i, &l);
      double d;
      if (l == 0 || (l == 2 && v[0] == 'N' && v[1] == 'A')) {
        cs[i].nulls++;
        continue;
      }
      cs[i].n++;
      catadd(&cs[i], v, l);
      if (qdvclass(v, l, &d) & QDTREAL) {
        if (cs[i].num) {
          int fd = qdfdig(v, l);
          numadd(&cs[i], d);
          if (fd)
            cs[i].dig[fd - 1]++;
        }
      } else {
        /* one value that is not a number makes the column categorical */
        cs[i].bad++;
        cs[i].num = 0;
      }
      if (cs[i].err) {
        rc = cs[i].err;
        qdwhy(why, wcap, "%s: column %s: too many values to summarise",
              p, cs[i].name);
        goto out;
      }
    }
    if ((rc = qdcsvnext(&c, &got)) != NQOK)
      goto bad;
  }
  for (i = 0; i < n; i++)
    if (cs[i].nv > 1)
      qsort(cs[i].v, cs[i].nv, sizeof *cs[i].v, dcmp);
  *out = cs;
  *nc = n;
  cs = NULL;
  rc = NQOK;
  goto out;
bad:
  qdwhy(why, wcap, "%s: %s", p, c.why[0] ? c.why : nqerr(rc));
out:
  colfree(cs, n);
  qdcsvclose(&c);
  return rc;
}

/* ---- the summaries ---- */

/* the number of values at most v in the sorted x[0..n) */
static size_t upto(const double *x, size_t n, double v) {
  size_t lo = 0, hi = n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (x[mid] <= v)
      lo = mid + 1;
    else
      hi = mid;
  }
  return lo;
}

static int pair(djs *a, djs *x, double c) {
  djs *p = qdjnew(DJARR);
  if (p == NULL || qdjadd(p, x) != NQOK || qdjadd(p, qdjnum(c)) != NQOK) {
    qdjfree(p);
    return NQEMEM;
  }
  return qdjadd(a, p);
}

static int numstats(djs *o, const qdccol *c) {
  djs *q = qdjnew(DJARR), *e = qdjnew(DJARR), *k = qdjnew(DJARR);
  djs *dg = qdjnew(DJARR);
  const double *x = c->v;
  size_t n = c->nv, j, nd = 0, last = 0;
  double ed[QDBINS + 1], cnt[QDBINS + 2];
  int rc = NQOK;
  if (q == NULL || e == NULL || k == NULL || dg == NULL)
    rc = NQEMEM;
  /* the sketch: every distinct value up to 1,001 values, else the
   * order statistics of ranks ceil(j n / 1000), j 0..1000 */
  for (j = 0; j <= QDSKN && rc == NQOK; j++) {
    size_t r, cu;
    if (n <= QDSKN + 1) {
      if (j >= n)
        break;
      r = j + 1;
    } else {
      r = j == 0 ? 1 : (size_t)((j * (uint64_t)n + QDSKN - 1) / QDSKN);
    }
    cu = upto(x, n, x[r - 1]);
    if (cu == last)
      continue;
    last = cu;
    rc = pair(q, qdjnum(x[r - 1]), (double)cu);
  }
  /* the PSI bins: with at most 10 distinct values, one bin each and an
   * open one above; else the type-1 deciles, ties merged */
  for (j = 0; j < n && nd <= QDBINS; j++)
    if (j == 0 || x[j] != x[j - 1])
      nd++;
  if (nd <= QDBINS) {
    size_t m = 0;
    for (j = 0; j < n; j++)
      if (j == 0 || x[j] != x[j - 1])
        ed[m++] = x[j];
    nd = m;
  } else {
    size_t m = 0, i;
    for (i = 1; i < QDBINS; i++) {
      size_t r = (size_t)((i * (uint64_t)n + QDBINS - 1) / QDBINS);
      double v = x[r - 1];
      if (m == 0 || v != ed[m - 1])
        ed[m++] = v;
    }
    nd = m;
  }
  memset(cnt, 0, sizeof cnt);
  for (j = 0; j < n; j++) {
    size_t lo = 0, hi = nd;
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (x[j] <= ed[mid])
        hi = mid;
      else
        lo = mid + 1;
    }
    cnt[lo]++;
  }
  for (j = 0; j < nd && rc == NQOK; j++)
    rc = qdjadd(e, qdjnum(ed[j]));
  for (j = 0; j <= nd && rc == NQOK; j++)
    rc = qdjadd(k, qdjnum(cnt[j]));
  for (j = 0; j < 9 && rc == NQOK; j++)
    rc = qdjadd(dg, qdjnum(c->dig[j]));
  if (rc == NQOK && n > 0) {
    rc = qdjset(o, "q", q);
    q = NULL;
    if (rc == NQOK && nd > 0) {
      rc = qdjset(o, "edges", e);
      e = NULL;
      if (rc == NQOK) {
        rc = qdjset(o, "counts", k);
        k = NULL;
      }
    }
    if (rc == NQOK) {
      rc = qdjset(o, "digits", dg);
      dg = NULL;
    }
  }
  qdjfree(q);
  qdjfree(e);
  qdjfree(k);
  qdjfree(dg);
  return rc;
}

static int catcmpn(const void *a, const void *b) {
  const qdcat *x = (const qdcat *)a, *y = (const qdcat *)b;
  int c;
  size_t l;
  if (x->n != y->n)
    return x->n > y->n ? -1 : 1;
  l = x->kl < y->kl ? x->kl : y->kl;
  c = memcmp(x->k, y->k, l);
  return c ? c : (x->kl > y->kl) - (x->kl < y->kl);
}

static int catcmpk(const void *a, const void *b) {
  const qdcat *x = (const qdcat *)a, *y = (const qdcat *)b;
  return strcmp(x->k, y->k);
}

static int catstats(djs *o, const qdccol *c) {
  qdcat *t;
  size_t i, m = 0, keep;
  uint64_t other = 0;
  djs *a;
  int rc = NQOK;
  if (c->nh == 0)
    return NQOK;
  t = (qdcat *)qdmal(c->nh * sizeof *t);
  a = qdjnew(DJARR);
  if (t == NULL || a == NULL) {
    qdfree(t);
    qdjfree(a);
    return NQEMEM;
  }
  for (i = 0; i < c->ch; i++)
    if (c->h[i].k != NULL)
      t[m++] = c->h[i];
  qsort(t, m, sizeof *t, catcmpn);
  keep = m < QDCATS ? m : QDCATS;
  for (i = keep; i < m; i++)
    other += t[i].n;
  qsort(t, keep, sizeof *t, catcmpk);
  for (i = 0; i < keep && rc == NQOK; i++)
    rc = pair(a, qdjstrn(t[i].k, t[i].kl), (double)t[i].n);
  if (rc == NQOK)
    rc = qdjset(o, "cats", a);
  else
    qdjfree(a);
  if (rc == NQOK)
    rc = qdjset(o, "other", qdjnum((double)other));
  qdfree(t);
  return rc;
}

int nqdstats(const char *dir, const char *path, const nqdcsvopt *o,
             char *out, size_t cap, size_t *outlen, char *why, size_t wcap) {
  char p[4200];
  qdccol *cs = NULL;
  size_t nc = 0, i;
  uint64_t rows;
  djs *e = NULL, *cols = NULL;
  dbuf b;
  int rc;
  if (why != NULL && wcap)
    why[0] = '\0';
  if (path == NULL)
    return NQEARG;
  if ((rc = qdjoin(dir, path, p, sizeof p)) != NQOK) {
    qdwhy(why, wcap, "%s: not a path a capsule holds", path);
    return rc;
  }
  if ((rc = readcols(p, o, &cs, &nc, &rows, why, wcap)) != NQOK)
    return rc;
  e = qdjnew(DJOBJ);
  cols = qdjnew(DJARR);
  if (e == NULL || cols == NULL ||
      qdjset(e, "path", qdjstr(path)) != NQOK ||
      qdjset(e, "rows", qdjnum((double)rows)) != NQOK) {
    rc = NQEMEM;
    goto out;
  }
  /* how the file was read, when not the default, so that it can be
   * read the same way again (nqdchk, nqddrift) */
  if (o != NULL && o->delim && o->delim != ',') {
    char dd[2];
    dd[0] = o->delim;
    dd[1] = '\0';
    if (qdjset(e, "delim", qdjstr(dd)) != NQOK) {
      rc = NQEMEM;
      goto out;
    }
  }
  if (o != NULL && o->noheader &&
      qdjset(e, "header", qdjnew(DJFALSE)) != NQOK) {
    rc = NQEMEM;
    goto out;
  }
  for (i = 0; i < nc && rc == NQOK; i++) {
    djs *k = qdjnew(DJOBJ);
    if (k == NULL || qdjset(k, "name", qdjstr(cs[i].name)) != NQOK ||
        qdjset(k, "n", qdjnum((double)cs[i].n)) != NQOK ||
        qdjset(k, "nulls", qdjnum((double)cs[i].nulls)) != NQOK) {
      qdjfree(k);
      rc = NQEMEM;
      break;
    }
    rc = cs[i].num && cs[i].n > 0 ? numstats(k, &cs[i]) : catstats(k, &cs[i]);
    if (rc == NQOK)
      rc = qdjadd(cols, k);
    else
      qdjfree(k);
  }
  if (rc == NQOK && nc > 0) {
    rc = qdjset(e, "columns", cols);
    cols = NULL;
  }
  if (rc == NQOK)
    rc = qdelemok("stats", e, why, wcap);
  if (rc == NQOK) {
    memset(&b, 0, sizeof b);
    qdjwrite(e, &b);
    rc = qdbout(&b, out, cap, outlen);
    qdbfree(&b);
  }
out:
  qdjfree(cols);
  qdjfree(e);
  colfree(cs, nc);
  return rc;
}

/* ---- the comparison ---- */

typedef struct {
  double d, p, err;
  int exact;
} qdks;

/* KS between the sketch q (pairs of value and count of values at most
 * it, n in all) and the sorted sample y[0..m) */
static int ksk(const djs *q, double n, const double *y, size_t m, qdks *r) {
  size_t i = 0, j = 0, k = q->n;
  double fd = 0, gd = 0, dmax = 0, gap = 0;
  int ties = 0, exact = n <= QDSKN + 1;
  if (k == 0 || m == 0)
    return NQEARG;
  for (i = 0; i < k; i++) {
    double c = q->k[i]->k[1]->d, pc = i ? q->k[i - 1]->k[1]->d : 0;
    if (c - pc > 1)
      ties = 1;
    if (i && (c - pc - 1) / n > gap)
      gap = (c - pc - 1) / n;
  }
  for (j = 1; j < m; j++)
    if (y[j] == y[j - 1])
      ties = 1;
  i = j = 0;
  while (i < k || j < m) {
    double v;
    if (j >= m || (i < k && q->k[i]->k[0]->d <= y[j]))
      v = q->k[i]->k[0]->d;
    else
      v = y[j];
    while (i < k && q->k[i]->k[0]->d <= v) {
      if (q->k[i]->k[0]->d == v && j < m && y[j] == v)
        ties = 1;
      fd = q->k[i]->k[1]->d / n;
      i++;
    }
    while (j < m && y[j] <= v)
      j++;
    gd = (double)j / (double)m;
    if (fabs(fd - gd) > dmax)
      dmax = fabs(fd - gd);
  }
  r->d = dmax;
  r->err = exact ? 0 : gap;
  r->exact = exact && !ties && n * (double)m < 10000;
  if (r->exact) {
    r->p = qdsmir(dmax, (int)n, (int)m);
    if (r->p < 0)
      return NQEMEM;
  } else {
    r->p = qdkolm(sqrt(n * (double)m / (n + (double)m)) * dmax);
  }
  if (r->p > 1)
    r->p = 1;
  return NQOK;
}

static const char *lvl(int l) {
  return l == 2 ? "fail" : l == 1 ? "warn" : "ok";
}

static void jnum(dbuf *b, const char *k, double v) {
  char t[40];
  qdbstr(b, ",\"");
  qdbstr(b, k);
  qdbstr(b, "\":");
  if (qdnumfmt(v, t) != NQOK)
    strcpy(t, "null");
  qdbstr(b, t);
}

static int addrow(nqdrep *rep, int level, const char *json,
                  const char *fmt, const char *a, const char *b) {
  char m[600];
  int rc;
  snprintf(m, sizeof m, fmt, a, b);
  rc = qdrepadd(rep, level == 1 ? "drift.warn" : "drift", level != 2, "%s",
                m);
  if (rc == NQOK && json != NULL)
    rc = qdrepjson(rep, json);
  return rc;
}

static int dcol(nqdrep *rep, const char *path, const djs *st,
                const qdccol *c, double ncur, const nqddopt *d) {
  const char *name = qdjget(st, "name")->s;
  const djs *q = qdjget(st, "q"), *ed = qdjget(st, "edges");
  const djs *cn = qdjget(st, "counts"), *dg = qdjget(st, "digits");
  const djs *cats = qdjget(st, "cats"), *oth = qdjget(st, "other");
  const djs *nn = qdjget(st, "n"), *nu = qdjget(st, "nulls");
  double nref = nn->d, psi = 0, js = 0, x2 = 0, df = 0, pc = 1, bp = 1;
  double bx = 0, bref = 1, bxr = 0;
  double nulr = nu != NULL ? nu->d / (nref + nu->d) : 0;
  double nulc = c->n + c->nulls > 0
                    ? (double)c->nulls / (double)(c->n + c->nulls)
                    : 0;
  int level = 0, rc = NQOK, minn;
  qdks ks;
  dbuf b;
  char det[400], ps[64];
  (void)ncur;
  memset(&b, 0, sizeof b);
  memset(&ks, 0, sizeof ks);
  minn = nref >= d->minn && (double)c->n >= d->minn;
  qdbstr(&b, "{\"path\":");
  {
    djs *t = qdjstr(path);
    qdjwrite(t, &b);
    qdjfree(t);
    qdbstr(&b, ",\"name\":");
    t = qdjstr(name);
    qdjwrite(t, &b);
    qdjfree(t);
  }
  jnum(&b, "nref", nref);
  jnum(&b, "ncur", (double)c->n);
  jnum(&b, "nullsref", nulr);
  jnum(&b, "nullscur", nulc);
  if (q != NULL) {
    /* numeric */
    double *a = NULL, *bb = NULL;
    size_t k = cn != NULL ? cn->n : 0, i, j;
    qdbstr(&b, ",\"kind\":\"num\"");
    if (c->bad > 0 || c->nv == 0) {
      snprintf(det, sizeof det,
               "%s: %llu values are not numbers, %llu are; the reference "
               "is numeric",
               name, (unsigned long long)c->bad,
               (unsigned long long)c->nv);
      qdbstr(&b, ",\"level\":\"fail\"}");
      rc = addrow(rep, 2, b.b, "%s: %s", path, det);
      qdbfree(&b);
      return rc;
    }
    if ((rc = ksk(q, nref, c->v, c->nv, &ks)) != NQOK) {
      qdbfree(&b);
      return rc;
    }
    if (k > 0) {
      a = (double *)qdmal(k * sizeof *a);
      bb = (double *)qdmal(k * sizeof *bb);
      if (a == NULL || bb == NULL) {
        qdfree(a);
        qdfree(bb);
        qdbfree(&b);
        return NQEMEM;
      }
      for (i = 0; i < k; i++) {
        a[i] = cn->k[i]->d;
        bb[i] = 0;
      }
      for (j = 0; j < c->nv; j++) {
        size_t lo = 0, hi = ed->n;
        while (lo < hi) {
          size_t mid = (lo + hi) / 2;
          if (c->v[j] <= ed->k[mid]->d)
            hi = mid;
          else
            lo = mid + 1;
        }
        bb[lo]++;
      }
      qdpsi(a, bb, k, &psi, &js);
      qdfree(a);
      qdfree(bb);
    }
    if (dg != NULL) {
      double r[9];
      for (i = 0; i < 9; i++)
        r[i] = dg->k[i]->d;
      bref = qdbenf(r, &bxr);
    }
    bp = qdbenf(c->dig, &bx);
    jnum(&b, "ksd", ks.d);
    jnum(&b, "ksp", ks.p);
    jnum(&b, "kserr", ks.err);
    qdbstr(&b, ks.exact ? ",\"ksexact\":true" : ",\"ksexact\":false");
    jnum(&b, "psi", psi);
    jnum(&b, "js", js);
    jnum(&b, "benfordx2", bx);
    jnum(&b, "benfordp", bp);
    jnum(&b, "benfordpref", bref);
    if ((psi >= d->psifail && minn))
      level = 2;
    else if (psi >= d->psiwarn || psi >= d->psifail || ks.p < d->alpha ||
             (d->benford && bp < d->alpha))
      level = 1;
    snprintf(ps, sizeof ps, "%.3g", ks.p);
    if (ks.err > 0)
      snprintf(ps + strlen(ps), sizeof ps - strlen(ps),
               "; from the sketch, D within %.4f", ks.err);
    snprintf(det, sizeof det,
             "%s: n %.0f then %lu; KS D %.4f (%s, p %s), PSI %.4f, JS "
             "%.4f, Benford p %.3g",
             name, nref, (unsigned long)c->nv, ks.d,
             ks.exact ? "exact" : "asymptotic", ps, psi, js, bp);
  } else {
    /* categorical */
    size_t k = cats != NULL ? cats->n : 0, i;
    double *a = (double *)qdmal((k + 1) * sizeof *a);
    double *bb = (double *)qdmal((k + 1) * sizeof *bb);
    double seen = 0, pr;
    if (a == NULL || bb == NULL) {
      qdfree(a);
      qdfree(bb);
      qdbfree(&b);
      return NQEMEM;
    }
    qdbstr(&b, ",\"kind\":\"cat\"");
    for (i = 0; i < k; i++) {
      const djs *e = cats->k[i];
      a[i] = e->k[1]->d;
      bb[i] = (double)catget(c, e->k[0]->s, e->k[0]->sl);
      seen += bb[i];
    }
    a[k] = oth != NULL ? oth->d : 0;
    bb[k] = (double)c->n - seen;
    qdpsi(a, bb, k + 1, &psi, &js);
    pr = qdhomog(a, bb, k + 1, &x2, &df);
    pc = pr;
    jnum(&b, "psi", psi);
    jnum(&b, "js", js);
    jnum(&b, "chisq", x2);
    jnum(&b, "df", df);
    jnum(&b, "chisqp", pc);
    jnum(&b, "unseen", c->n ? bb[k] / (double)c->n : 0);
    qdfree(a);
    qdfree(bb);
    if (psi >= d->psifail && minn)
      level = 2;
    else if (psi >= d->psiwarn || pc < d->alpha)
      level = 1;
    snprintf(det, sizeof det,
             "%s: n %.0f then %llu; chi-square %.4g on %.0f df (p %.3g), "
             "PSI %.4f, JS %.4f, %.4f of values outside the reference's "
             "categories",
             name, nref, (unsigned long long)c->n, x2, df, pc, psi, js,
             c->n ? (double)((double)c->n - seen) / (double)c->n : 0.0);
  }
  qdbstr(&b, ",\"level\":\"");
  qdbstr(&b, lvl(level));
  qdbstr(&b, "\"}");
  if (b.err) {
    rc = b.err;
    qdbfree(&b);
    return rc;
  }
  rc = addrow(rep, level, b.b, "%s: %s", path, det);
  qdbfree(&b);
  return rc;
}

int nqddrift(const char *stats, size_t n, const char *file,
             const nqdcsvopt *o, const nqddopt *dopt, nqdrep **out) {
  djs *st = NULL;
  nqdrep *rep;
  qdccol *cs = NULL;
  size_t nc = 0, i, j;
  uint64_t rows = 0;
  char why[600];
  int rc, bad = 0;
  const djs *cols;
  nqddopt d;
  nqdcsvopt co;
  if (stats == NULL || file == NULL || out == NULL)
    return NQEARG;
  *out = NULL;
  d.psiwarn = 0.1;
  d.psifail = 0.25;
  d.alpha = 0.001;
  d.benford = 0;
  d.minn = 1000;
  if (dopt != NULL)
    d = *dopt;
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  rc = qdjparse(stats, n, &st, why, sizeof why);
  if (rc == NQOK)
    rc = qdelemok("stats", st, why, sizeof why);
  if (rc != NQOK) {
    qdjfree(st);
    if (rc == NQEMEM) {
      nqdrepfree(rep);
      return rc;
    }
    qdrepadd(rep, "drift", 0, "not a stats element: %s", why);
    *out = rep;
    return NQEVRFY;
  }
  /* the file is read as the reference was, unless the caller says */
  memset(&co, 0, sizeof co);
  if (o != NULL)
    co = *o;
  {
    const djs *dl = qdjget(st, "delim"), *hd = qdjget(st, "header");
    if (!co.delim && dl != NULL)
      co.delim = dl->s[0];
    if (hd != NULL && hd->t == DJFALSE)
      co.noheader = 1;
  }
  rc = readcols(file, &co, &cs, &nc, &rows, why, sizeof why);
  if (rc != NQOK) {
    qdjfree(st);
    if (rc == NQEMEM) {
      nqdrepfree(rep);
      return rc;
    }
    qdrepadd(rep, "drift", 0, "%s", why);
    *out = rep;
    return NQEVRFY;
  }
  {
    const char *path = qdjget(st, "path")->s;
    int64_t rref = 0;
    qdjint(qdjget(st, "rows"), &rref);
    qdrepadd(rep, "drift", 1, "%s: %lld rows then %llu", path,
             (long long)rref, (unsigned long long)rows);
    cols = qdjget(st, "columns");
    for (i = 0; cols != NULL && i < cols->n; i++) {
      const char *name = qdjget(cols->k[i], "name")->s;
      for (j = 0; j < nc; j++)
        if (strcmp(cs[j].name, name) == 0)
          break;
      if (j == nc) {
        addrow(rep, 2, NULL, "%s: %s: the column is gone", path, name);
        continue;
      }
      if ((rc = dcol(rep, path, cols->k[i], &cs[j], (double)rows, &d)) !=
          NQOK)
        break;
    }
    for (j = 0; j < nc && rc == NQOK; j++) {
      for (i = 0; cols != NULL && i < cols->n; i++)
        if (strcmp(qdjget(cols->k[i], "name")->s, cs[j].name) == 0)
          break;
      if (cols == NULL || i == cols->n)
        addrow(rep, 1, NULL, "%s: %s: a new column, not in the reference",
               path, cs[j].name);
    }
  }
  colfree(cs, nc);
  qdjfree(st);
  if (rc != NQOK) {
    nqdrepfree(rep);
    return rc;
  }
  for (i = 0; i < nqdrepn(rep); i++) {
    int ok;
    nqdrepi(rep, i, NULL, &ok, NULL);
    bad |= !ok;
  }
  *out = rep;
  return bad ? NQEVRFY : NQOK;
}
