/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqddiff: what changed between two capsules: the files their
 * manifests list (through nqfiles), and their data records member by
 * member: sources, schemas (columns, types, rows), summaries (counts,
 * medians, PSI between the two), the environment, steps, checks,
 * commitments and citation. */
#include "int.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* PSI and JS over two count vectors of k entries; an empty bin counts
 * as 1e-6 in the PSI (only), so one empty bin does not make it
 * infinite */
void qdpsi(const double *a, const double *b, size_t k, double *psi,
           double *js) {
  double na = 0, nb = 0;
  size_t i;
  *psi = 0;
  *js = 0;
  for (i = 0; i < k; i++) {
    na += a[i];
    nb += b[i];
  }
  if (na <= 0 || nb <= 0)
    return;
  for (i = 0; i < k; i++) {
    double p = a[i] / na, q = b[i] / nb, m = (p + q) / 2;
    double pf = p > 0 ? p : 1e-6, qf = q > 0 ? q : 1e-6;
    *psi += (pf - qf) * log(pf / qf);
    if (p > 0)
      *js += 0.5 * p * log(p / m);
    if (q > 0)
      *js += 0.5 * q * log(q / m);
  }
}

typedef struct {
  char *path;
  char sha[65];
  uint64_t size;
} qdmf;

/* the files of the manifest in dir, in manifest order (sorted by path);
 * NQEIO when dir is not a sealed capsule that reads */
static int mfiles(const char *dir, qdmf **out, size_t *n) {
  nqrep *r = NULL;
  size_t i, k = 0, m;
  qdmf *f;
  int rc = nqfiles(dir, &r);
  *out = NULL;
  *n = 0;
  if (rc != NQOK) {
    if (r != NULL)
      nqrepfree(r);
    return rc == NQEMEM ? rc : NQEIO;
  }
  m = nqrepn(r);
  f = (qdmf *)qdmal((m + 1) * sizeof *f);
  if (f == NULL) {
    nqrepfree(r);
    return NQEMEM;
  }
  for (i = 0; i < m; i++) {
    const char *c, *d, *s1, *s2;
    int ok;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || strcmp(c, "info.file") != 0)
      continue;
    /* "<size> <sha256> <path>" */
    s1 = strchr(d, ' ');
    s2 = s1 != NULL ? strchr(s1 + 1, ' ') : NULL;
    if (s2 == NULL || s2 - s1 - 1 != 64)
      continue;
    f[k].size = strtoull(d, NULL, 10);
    memcpy(f[k].sha, s1 + 1, 64);
    f[k].sha[64] = '\0';
    if ((f[k].path = qddup(s2 + 1, strlen(s2 + 1))) == NULL) {
      rc = NQEMEM;
      break;
    }
    k++;
  }
  nqrepfree(r);
  if (rc != NQOK) {
    for (i = 0; i < k; i++)
      qdfree(f[i].path);
    qdfree(f);
    return rc;
  }
  *out = f;
  *n = k;
  return NQOK;
}

static void mfree(qdmf *f, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    qdfree(f[i].path);
  qdfree(f);
}

/* canonical text of v (NULL: "") into a new buffer */
static char *ctext(const djs *v) {
  dbuf b;
  memset(&b, 0, sizeof b);
  if (v == NULL)
    return qddup("", 0);
  qdjwrite(v, &b);
  if (b.err) {
    qdbfree(&b);
    return NULL;
  }
  return b.b != NULL ? b.b : qddup("", 0);
}

static int same(const djs *a, const djs *b) {
  char *x = ctext(a), *y = ctext(b);
  int s = x != NULL && y != NULL && strcmp(x, y) == 0;
  qdfree(x);
  qdfree(y);
  return s;
}

/* a short form of a scalar for a detail: its JSON, cut at 60 bytes */
static void brief(const djs *v, char *out, size_t cap) {
  char *t = ctext(v);
  snprintf(out, cap, "%.60s%s", v == NULL ? "(none)" : t != NULL ? t : "?",
           t != NULL && strlen(t) > 60 ? "..." : "");
  qdfree(t);
}

/* the members of a and b (objects) that differ, as "k old -> new, ..." */
static void fields(const djs *a, const djs *b, char *out, size_t cap) {
  size_t i, o = 0;
  const djs *s[2];
  int pass;
  out[0] = '\0';
  s[0] = a;
  s[1] = b;
  for (pass = 0; pass < 2; pass++) {
    const djs *x = s[pass];
    for (i = 0; x != NULL && i < x->n; i++) {
      const char *k = x->key[i];
      const djs *va = qdjget(a, k), *vb = qdjget(b, k);
      char ba[80], bb[80];
      if (pass == 1 && va != NULL)
        continue; /* seen in the first pass */
      if (same(va, vb))
        continue;
      brief(va, ba, sizeof ba);
      brief(vb, bb, sizeof bb);
      if (o < cap)
        o += (size_t)snprintf(out + o, cap - o, "%s%s %s -> %s",
                              o ? "; " : "", k, ba, bb);
    }
  }
}

static const char *keyed(const char *m) {
  if (strcmp(m, "checks") == 0)
    return "name";
  return "path";
}

/* the median of a sketch: the first value with at least half the
 * values at most it */
static double median(const djs *q, double n) {
  size_t i;
  for (i = 0; q != NULL && i < q->n; i++)
    if (q->k[i]->k[1]->d >= n / 2)
      return q->k[i]->k[0]->d;
  return NAN;
}

static void statcol(nqdrep *rep, const char *path, const djs *a,
                    const djs *b) {
  const char *name = qdjget(a, "name")->s;
  double na = qdjget(a, "n")->d, nb = qdjget(b, "n")->d;
  const djs *ea = qdjget(a, "edges"), *eb = qdjget(b, "edges");
  const djs *ca = qdjget(a, "cats"), *cb = qdjget(b, "cats");
  char m[400];
  size_t o;
  if (same(a, b))
    return;
  o = (size_t)snprintf(m, sizeof m, "%s: %s: n %.0f -> %.0f", path, name,
                       na, nb);
  if (qdjget(a, "q") != NULL && qdjget(b, "q") != NULL)
    o += (size_t)snprintf(m + o, sizeof m - o, ", median %.6g -> %.6g",
                          median(qdjget(a, "q"), na),
                          median(qdjget(b, "q"), nb));
  if (ea != NULL && eb != NULL && same(ea, eb)) {
    const djs *ka = qdjget(a, "counts"), *kb = qdjget(b, "counts");
    size_t i, k = ka->n;
    double *x = (double *)qdmal((k + 1) * sizeof *x);
    double *y = (double *)qdmal((k + 1) * sizeof *y), psi, js;
    if (x != NULL && y != NULL) {
      for (i = 0; i < k; i++) {
        x[i] = ka->k[i]->d;
        y[i] = kb->k[i]->d;
      }
      qdpsi(x, y, k, &psi, &js);
      snprintf(m + o, sizeof m - o, ", PSI %.4f over the same bins", psi);
    }
    qdfree(x);
    qdfree(y);
  } else if (ea != NULL || eb != NULL) {
    snprintf(m + o, sizeof m - o, ", bins differ");
  } else if (ca != NULL && cb != NULL) {
    /* PSI over the categories of either, the rest in "other" */
    size_t i = 0, j = 0, k = 0, cap = ca->n + cb->n + 1;
    double *x = (double *)qdmal(cap * sizeof *x);
    double *y = (double *)qdmal(cap * sizeof *y), psi, js;
    if (x != NULL && y != NULL) {
      while (i < ca->n || j < cb->n) {
        int c = i >= ca->n   ? 1
                : j >= cb->n ? -1
                             : strcmp(ca->k[i]->k[0]->s, cb->k[j]->k[0]->s);
        x[k] = c <= 0 ? ca->k[i]->k[1]->d : 0;
        y[k] = c >= 0 ? cb->k[j]->k[1]->d : 0;
        if (c <= 0)
          i++;
        if (c >= 0)
          j++;
        k++;
      }
      x[k] = qdjget(a, "other") != NULL ? qdjget(a, "other")->d : 0;
      y[k] = qdjget(b, "other") != NULL ? qdjget(b, "other")->d : 0;
      qdpsi(x, y, k + 1, &psi, &js);
      snprintf(m + o, sizeof m - o, ", PSI %.4f over the categories", psi);
    }
    qdfree(x);
    qdfree(y);
  }
  qdrepadd(rep, "stats", 0, "%s", m);
}

static void schcols(nqdrep *rep, const char *path, const djs *a,
                    const djs *b) {
  const djs *ca = qdjget(a, "columns"), *cb = qdjget(b, "columns");
  size_t i, j;
  char m[300];
  for (i = 0; ca != NULL && i < ca->n; i++) {
    const char *n = qdjget(ca->k[i], "name")->s;
    const djs *f = NULL;
    for (j = 0; cb != NULL && j < cb->n && f == NULL; j++)
      if (strcmp(qdjget(cb->k[j], "name")->s, n) == 0)
        f = cb->k[j];
    if (f == NULL) {
      qdrepadd(rep, "schema", 0, "%s: column %s removed", path, n);
    } else if (!same(ca->k[i], f)) {
      fields(ca->k[i], f, m, sizeof m);
      qdrepadd(rep, "schema", 0, "%s: column %s: %s", path, n, m);
    }
  }
  for (j = 0; cb != NULL && j < cb->n; j++) {
    const char *n = qdjget(cb->k[j], "name")->s;
    int f = 0;
    for (i = 0; ca != NULL && i < ca->n && !f; i++)
      f = strcmp(qdjget(ca->k[i], "name")->s, n) == 0;
    if (!f)
      qdrepadd(rep, "schema", 0, "%s: column %s added", path, n);
  }
}

static void keyedm(nqdrep *rep, const char *m, const djs *a, const djs *b) {
  const char *k = keyed(m);
  size_t i = 0, j = 0, na = a != NULL ? a->n : 0, nb = b != NULL ? b->n : 0;
  char row[16], det[500];
  snprintf(row, sizeof row, "%.*s", (int)strlen(m) - 1, m); /* singular */
  while (i < na || j < nb) {
    const char *ka = i < na ? qdjget(a->k[i], k)->s : NULL;
    const char *kb = j < nb ? qdjget(b->k[j], k)->s : NULL;
    int c = ka == NULL ? 1 : kb == NULL ? -1 : strcmp(ka, kb);
    if (c < 0) {
      qdrepadd(rep, row, 0, "%s removed", ka);
      i++;
    } else if (c > 0) {
      qdrepadd(rep, row, 0, "%s added", kb);
      j++;
    } else {
      const djs *x = a->k[i], *y = b->k[j];
      if (!same(x, y)) {
        if (strcmp(m, "stats") == 0) {
          const djs *cx = qdjget(x, "columns"), *cy = qdjget(y, "columns");
          size_t p, q;
          int64_t rx = 0, ry = 0;
          qdjint(qdjget(x, "rows"), &rx);
          qdjint(qdjget(y, "rows"), &ry);
          if (rx != ry)
            qdrepadd(rep, "stats", 0, "%s: rows %lld -> %lld", ka,
                     (long long)rx, (long long)ry);
          for (p = 0; cx != NULL && p < cx->n; p++)
            for (q = 0; cy != NULL && q < cy->n; q++)
              if (strcmp(qdjget(cx->k[p], "name")->s,
                         qdjget(cy->k[q], "name")->s) == 0)
                statcol(rep, ka, cx->k[p], cy->k[q]);
        } else if (strcmp(m, "schemas") == 0) {
          djs *xa = qdjcopy(x), *ya = qdjcopy(y);
          schcols(rep, ka, x, y);
          if (xa != NULL && ya != NULL) {
            qdjdel(xa, "columns");
            qdjdel(ya, "columns");
            if (!same(xa, ya)) {
              fields(xa, ya, det, sizeof det);
              qdrepadd(rep, "schema", 0, "%s: %s", ka, det);
            }
          }
          qdjfree(xa);
          qdjfree(ya);
        } else {
          fields(x, y, det, sizeof det);
          qdrepadd(rep, row, 0, "%s: %s", ka, det);
        }
      }
      i++;
      j++;
    }
  }
}

static void recdiff(nqdrep *rep, const djs *a, const djs *b) {
  static const char *const km[] = {"sources", "schemas", "stats", "chunks",
                                   "checks"};
  static const char *const om[] = {"env", "cite"};
  static const char *const sm[] = {"steps", "commits"};
  char det[600];
  size_t i;
  for (i = 0; i < sizeof km / sizeof km[0]; i++)
    keyedm(rep, km[i], qdjget(a, km[i]), qdjget(b, km[i]));
  for (i = 0; i < 2; i++) {
    const djs *x = qdjget(a, om[i]), *y = qdjget(b, om[i]);
    if (same(x, y))
      continue;
    if (x != NULL && y != NULL) {
      fields(x, y, det, sizeof det);
      qdrepadd(rep, om[i], 0, "%s", det);
    } else {
      qdrepadd(rep, om[i], 0, "%s", x == NULL ? "added" : "removed");
    }
  }
  for (i = 0; i < 2; i++) {
    const djs *x = qdjget(a, sm[i]), *y = qdjget(b, sm[i]);
    size_t nx = x != NULL ? x->n : 0, ny = y != NULL ? y->n : 0, k;
    if (same(x, y))
      continue;
    for (k = 0; k < nx && k < ny && same(x->k[k], y->k[k]); k++)
      ;
    qdrepadd(rep, sm[i], 0, "%lu then %lu; the first that differs is "
             "number %lu", (unsigned long)nx, (unsigned long)ny,
             (unsigned long)k + 1);
  }
}

int nqddiff(const char *a, const char *b, nqdrep **out) {
  nqdrep *rep;
  qdmf *fa = NULL, *fb = NULL;
  size_t na = 0, nb = 0, i = 0, j = 0, n, k;
  nqdrec *ra = NULL, *rb = NULL;
  char why[600];
  int ma, mb, la, lb, rc = NQOK, bad = 0;
  if (a == NULL || b == NULL || out == NULL)
    return NQEARG;
  *out = NULL;
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  ma = mfiles(a, &fa, &na);
  mb = mfiles(b, &fb, &nb);
  if (ma == NQEMEM || mb == NQEMEM) {
    rc = NQEMEM;
    goto out;
  }
  if (ma == NQOK && mb == NQOK) {
    qdrepadd(rep, "manifest", 1, "%lu files, then %lu", (unsigned long)na,
             (unsigned long)nb);
    while (i < na || j < nb) {
      int c = i >= na ? 1 : j >= nb ? -1 : strcmp(fa[i].path, fb[j].path);
      if (c < 0) {
        qdrepadd(rep, "file", 0, "%s removed", fa[i++].path);
      } else if (c > 0) {
        qdrepadd(rep, "file", 0, "%s added", fb[j++].path);
      } else {
        if (fa[i].size != fb[j].size || strcmp(fa[i].sha, fb[j].sha) != 0)
          qdrepadd(rep, "file", 0,
                   "%s changed: %llu -> %llu bytes, SHA-256 %.12s... -> "
                   "%.12s...",
                   fa[i].path, (unsigned long long)fa[i].size,
                   (unsigned long long)fb[j].size, fa[i].sha, fb[j].sha);
        i++;
        j++;
      }
    }
  } else {
    qdrepadd(rep, "manifest", 1,
             "%s not sealed (or its seal does not read): files not compared",
             ma != NQOK && mb != NQOK ? "neither is"
             : ma != NQOK             ? "the first is"
                                      : "the second is");
  }
  la = nqdload(a, &ra, why, sizeof why);
  lb = nqdload(b, &rb, why, sizeof why);
  if (la == NQEMEM || lb == NQEMEM) {
    rc = NQEMEM;
    goto out;
  }
  if (la == NQOK && lb == NQOK)
    recdiff(rep, qdrectree(ra), qdrectree(rb));
  else if (la == NQOK || lb == NQOK)
    qdrepadd(rep, "record", 0, "only the %s has a data record (that reads)",
             la == NQOK ? "first" : "second");
  n = nqdrepn(rep);
  for (k = 0; k < n; k++) {
    int ok;
    nqdrepi(rep, k, NULL, &ok, NULL);
    bad |= !ok;
  }
out:
  mfree(fa, na);
  mfree(fb, nb);
  nqdrfree(ra);
  nqdrfree(rb);
  if (rc != NQOK) {
    nqdrepfree(rep);
    return rc;
  }
  *out = rep;
  return bad ? NQEVRFY : NQOK;
}
