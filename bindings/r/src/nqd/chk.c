/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqdchk: the record in a folder against the files beside it. */
#include "int.h"

#include <math.h>
#include <string.h>

/* " [synthetic]" when the source of path is marked synthetic */
static const char *synth(const djs *root, const char *path) {
  const djs *s = qdjget(root, "sources");
  size_t i;
  if (s == NULL)
    return "";
  for (i = 0; i < s->n; i++) {
    const djs *p = qdjget(s->k[i], "path"), *y = qdjget(s->k[i], "synthetic");
    if (p != NULL && strcmp(p->s, path) == 0)
      return y != NULL && y->t == DJTRUE ? " [synthetic]" : "";
  }
  return "";
}

static int srcrow(nqdrep *rep, const char *dir, const djs *e) {
  const char *path = qdjget(e, "path")->s;
  const char *want = qdjget(e, "sha256")->s;
  const djs *y = qdjget(e, "synthetic");
  const char *sy = y != NULL && y->t == DJTRUE ? " [synthetic]" : "";
  int64_t size = 0;
  char p[4200], hx[65];
  uint8_t h[32], w[32];
  uint64_t got;
  size_t i;
  int rc;
  qdjint(qdjget(e, "size"), &size);
  if (qdjoin(dir, path, p, sizeof p) != NQOK)
    return qdrepadd(rep, "source", 0, "%s%s: not a path in the folder", path,
                   sy);
  rc = qdsha(p, h, &got);
  if (rc != NQOK)
    return qdrepadd(rep, "source", 0, "%s%s: missing or unreadable", path, sy);
  for (i = 0; i < 32; i++) {
    unsigned hi = (unsigned)(want[2 * i] <= '9' ? want[2 * i] - '0'
                                                : want[2 * i] - 'a' + 10);
    unsigned lo = (unsigned)(want[2 * i + 1] <= '9'
                                 ? want[2 * i + 1] - '0'
                                 : want[2 * i + 1] - 'a' + 10);
    w[i] = (uint8_t)(hi << 4 | lo);
  }
  qdhex(h, 32, hx);
  if (!nqcteq(h, w, 32))
    return qdrepadd(rep, "source", 0,
                   "%s%s: SHA-256 is %.16s..., the record says %.16s...",
                   path, sy, hx, want);
  if ((uint64_t)size != got)
    return qdrepadd(rep, "source", 0, "%s%s: %llu bytes, the record says %lld",
                   path, sy, (unsigned long long)got, (long long)size);
  return qdrepadd(rep, "source", 1, "%s%s: SHA-256 and size match", path, sy);
}

/* a recorded check: with expected and observed both numbers (or both
 * strings) the result is recomputed: |observed - expected| <= tol (tol
 * 0 when not given), or the two strings equal; one recorded as pass
 * that does not hold fails, as does one recorded as fail */
static int chkrow(nqdrep *rep, const djs *e) {
  const char *name = qdjget(e, "name")->s, *st = qdjget(e, "status")->s;
  const djs *ex = qdjget(e, "expected"), *ob = qdjget(e, "observed");
  const djs *tl = qdjget(e, "tol");
  char a[40], b[40], t[40];
  int holds, pass = strcmp(st, "pass") == 0;
  if (ex == NULL || ob == NULL || ex->t != ob->t)
    return qdrepadd(rep, "recorded", strcmp(st, "fail") != 0, "%s: %s",
                    name, st);
  if (ex->t == DJNUM) {
    double tol = tl != NULL ? tl->d : 0;
    holds = fabs(ob->d - ex->d) <= tol;
    if (qdnumfmt(ob->d, a) != NQOK || qdnumfmt(ex->d, b) != NQOK ||
        qdnumfmt(tol, t) != NQOK)
      return NQEARG;
    if (pass && !holds)
      return qdrepadd(rep, "recorded", 0,
                      "%s: recorded as pass, but observed %s and expected "
                      "%s differ by more than %s",
                      name, a, b, t);
    return qdrepadd(rep, "recorded", strcmp(st, "fail") != 0,
                    "%s: %s (observed %s, expected %s, tolerance %s: %s)",
                    name, st, a, b, t, holds ? "holds" : "does not hold");
  }
  holds = ex->sl == ob->sl && memcmp(ex->s, ob->s, ex->sl) == 0;
  if (pass && !holds)
    return qdrepadd(rep, "recorded", 0,
                    "%s: recorded as pass, but observed \"%.60s\" is not "
                    "expected \"%.60s\"",
                    name, ob->s, ex->s);
  return qdrepadd(rep, "recorded", strcmp(st, "fail") != 0,
                  "%s: %s (observed and expected %s)", name, st,
                  holds ? "equal" : "differ");
}

/* a step with a script (a mapping, a program) in the folder and its
 * SHA-256: the file must still have it */
static int steprow(nqdrep *rep, const char *dir, const djs *e, size_t i) {
  const djs *sc = qdjget(e, "script"), *h = qdjget(e, "sha256");
  const djs *fr = qdjget(e, "from"), *to = qdjget(e, "to");
  char p[4200], hx[65], who[400];
  uint8_t d[32];
  uint64_t n;
  if (sc == NULL || h == NULL)
    return NQOK;
  qdwhy(who, sizeof who, "step %lu (%s%s%.80s%s%.80s)", (unsigned long)i + 1,
        qdjget(e, "kind")->s, fr != NULL ? " " : "", fr != NULL ? fr->s : "",
        to != NULL ? " -> " : "", to != NULL ? to->s : "");
  if (qdjoin(dir, sc->s, p, sizeof p) != NQOK || qdsha(p, d, &n) != NQOK)
    return qdrepadd(rep, "step", 0, "%s: %s missing or unreadable", who,
                    sc->s);
  qdhex(d, 32, hx);
  if (strcmp(hx, h->s) != 0)
    return qdrepadd(rep, "step", 0,
                    "%s: %s has SHA-256 %.16s..., the record says %.16s...",
                    who, sc->s, hx, h->s);
  return qdrepadd(rep, "step", 1, "%s: %s has its recorded SHA-256", who,
                  sc->s);
}

/* the canonical text of a stats element without its calibration */
static int stattext(const djs *e, dbuf *b) {
  djs *c = qdjcopy(e);
  djs *cols;
  size_t i;
  if (c == NULL)
    return NQEMEM;
  qdjdel(c, "cal");
  if ((cols = qdjgetw(c, "columns")) != NULL)
    for (i = 0; i < cols->n; i++)
      qdjdel(cols->k[i], "cal");
  qdjwrite(c, b);
  qdjfree(c);
  return b->err ? b->err : NQOK;
}

/* the summaries of a stats element made again from its file, read as
 * the element (or else the file's schema) says, must be the same */
static int statrow(nqdrep *rep, const char *dir, const djs *root,
                   const djs *e, const char *sy) {
  const char *path = qdjget(e, "path")->s;
  const djs *sch = NULL, *a = qdjget(root, "schemas"), *dl, *hd;
  nqdcsvopt o;
  char why[600], *buf = NULL;
  size_t n = 0, i;
  djs *re = NULL;
  dbuf x, y;
  int rc, same;
  for (i = 0; a != NULL && i < a->n && sch == NULL; i++)
    if (strcmp(qdjget(a->k[i], "path")->s, path) == 0)
      sch = a->k[i];
  memset(&o, 0, sizeof o);
  dl = qdjget(e, "delim");
  hd = qdjget(e, "header");
  if (dl == NULL && sch != NULL)
    dl = qdjget(sch, "delim");
  if (hd == NULL && sch != NULL)
    hd = qdjget(sch, "header");
  if (dl != NULL)
    o.delim = dl->s[0];
  o.noheader = hd != NULL && hd->t == DJFALSE;
  rc = nqdstats(dir, path, &o, NULL, 0, &n, why, sizeof why);
  if (rc == NQEBUF) {
    if ((buf = (char *)qdmal(n + 1)) == NULL)
      return NQEMEM;
    rc = nqdstats(dir, path, &o, buf, n + 1, &n, why, sizeof why);
  }
  if (rc == NQOK)
    rc = qdjparse(buf, n, &re, why, sizeof why);
  qdfree(buf);
  if (rc == NQEMEM)
    return rc;
  if (rc != NQOK)
    return qdrepadd(rep, "stats", 0, "%s%s: %s", path, sy, why);
  memset(&x, 0, sizeof x);
  memset(&y, 0, sizeof y);
  rc = stattext(e, &x);
  if (rc == NQOK)
    rc = stattext(re, &y);
  same = rc == NQOK && x.n == y.n && memcmp(x.b, y.b, x.n) == 0;
  qdbfree(&x);
  qdbfree(&y);
  if (rc == NQOK && !same) {
    const djs *ca = qdjget(e, "columns"), *cb = qdjget(re, "columns");
    const char *col = NULL;
    for (i = 0; ca != NULL && cb != NULL && i < ca->n && col == NULL; i++) {
      dbuf p, q;
      memset(&p, 0, sizeof p);
      memset(&q, 0, sizeof q);
      if (i >= cb->n) {
        col = qdjget(ca->k[i], "name")->s;
        break;
      }
      stattext(ca->k[i], &p);
      stattext(cb->k[i], &q);
      if (p.err || q.err || p.n != q.n || memcmp(p.b, q.b, p.n) != 0)
        col = qdjget(ca->k[i], "name")->s;
      qdbfree(&p);
      qdbfree(&q);
    }
    rc = qdrepadd(rep, "stats", 0,
                  "%s%s: the recorded summaries are not those of the file "
                  "(%s%s%s)",
                  path, sy, col != NULL ? "column " : "",
                  col != NULL ? col : "rows or columns",
                  col != NULL ? " first" : "");
  } else if (rc == NQOK) {
    rc = qdrepadd(rep, "stats", 1, "%s%s: the summaries recompute from the "
                  "file", path, sy);
  }
  qdjfree(re);
  return rc;
}

int nqdchk(const char *dir, nqdrep **out) {
  nqdrep *rep;
  nqdrec *r = NULL;
  const djs *root, *a;
  char why[600];
  size_t i, n, bad = 0;
  int rc;
  if (dir == NULL || out == NULL)
    return NQEARG;
  *out = NULL;
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  rc = nqdload(dir, &r, why, sizeof why);
  if (rc == NQEMEM) {
    nqdrepfree(rep);
    return rc;
  }
  if (rc != NQOK) {
    qdrepadd(rep, "record", 0, "%s", why);
    *out = rep;
    return NQEVRFY;
  }
  root = qdrectree(r);
  qdrepadd(rep, "record", 1, NQDFMT ", canonical: %lu sources, %lu schemas",
          (unsigned long)nqdlen(r, "sources"),
          (unsigned long)nqdlen(r, "schemas"));
  if ((a = qdjget(root, "sources")) != NULL)
    for (i = 0; i < a->n; i++)
      srcrow(rep, dir, a->k[i]);
  if ((a = qdjget(root, "schemas")) != NULL)
    for (i = 0; i < a->n; i++)
      qdschk(rep, dir, a->k[i], synth(root, qdjget(a->k[i], "path")->s));
  if ((a = qdjget(root, "stats")) != NULL)
    for (i = 0; i < a->n && rc == NQOK; i++)
      rc = statrow(rep, dir, root, a->k[i],
                   synth(root, qdjget(a->k[i], "path")->s));
  if ((a = qdjget(root, "steps")) != NULL)
    for (i = 0; i < a->n && rc == NQOK; i++)
      rc = steprow(rep, dir, a->k[i], i);
  if ((a = qdjget(root, "checks")) != NULL)
    for (i = 0; i < a->n && rc == NQOK; i++)
      rc = chkrow(rep, a->k[i]);
  if (rc != NQOK) {
    nqdrfree(r);
    nqdrepfree(rep);
    return rc;
  }
  nqdrfree(r);
  n = nqdrepn(rep);
  for (i = 0; i < n; i++) {
    int ok = 0;
    nqdrepi(rep, i, NULL, &ok, NULL);
    bad += !ok;
  }
  *out = rep;
  return bad ? NQEVRFY : NQOK;
}
