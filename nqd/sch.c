/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Schemas of CSV files: inference (nqdinfer), the check of a file
 * against a schema and its rules (nqdschk, and nqdchk's schema rows). */
#include "int.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ---- values ---- */

unsigned qdvclass(const char *s, size_t n, double *d) {
  unsigned m = 0;
  size_t i = 0, dg;
  *d = 0;
  if ((n == 4 && (memcmp(s, "true", 4) == 0 || memcmp(s, "TRUE", 4) == 0 ||
                  memcmp(s, "True", 4) == 0)) ||
      (n == 5 && (memcmp(s, "false", 5) == 0 || memcmp(s, "FALSE", 5) == 0 ||
                  memcmp(s, "False", 5) == 0)))
    return QDTBOOL;
  if (qddate(s, n))
    return QDTDATE;
  if (n > 0 && s[0] == '-')
    i = 1;
  for (dg = i; dg < n && s[dg] >= '0' && s[dg] <= '9'; dg++)
    ;
  if (dg == n && n > i && n - i <= 18 && (s[i] != '0' || n - i == 1))
    m |= QDTINT;
  if (qdnumrd(s, n, 1, d) == NQOK && (m || dg != n))
    m |= QDTREAL;
  return m;
}

static const char *const nadef[] = {"", "NA"};

static int isna(const djs *na, const char *s, size_t n) {
  size_t i;
  if (na == NULL) {
    for (i = 0; i < 2; i++)
      if (strlen(nadef[i]) == n && memcmp(nadef[i], s, n) == 0)
        return 1;
    return 0;
  }
  for (i = 0; i < na->n; i++)
    if (na->k[i]->sl == n && memcmp(na->k[i]->s, s, n) == 0)
      return 1;
  return 0;
}

static const char *const tnames[] = {"bool", "int", "real", "date", "text"};

static unsigned tbit(const char *t) {
  if (strcmp(t, "bool") == 0)
    return QDTBOOL;
  if (strcmp(t, "int") == 0)
    return QDTINT;
  if (strcmp(t, "real") == 0)
    return QDTREAL;
  if (strcmp(t, "date") == 0)
    return QDTDATE;
  return 0;
}

/* ---- a set of 16-byte digests (unique and distinct rules) ---- */

typedef struct {
  uint8_t *k;
  size_t n, cap;
  int err;
} qdhs;

#define QDHSMAX ((size_t)1 << 26)

static int hsadd(qdhs *h, const uint8_t d[16]) {
  size_t i, m;
  if (h->err)
    return 0;
  if (2 * (h->n + 1) > h->cap) {
    size_t nc = h->cap ? h->cap * 2 : 1024, j;
    uint8_t *nk;
    if (nc > QDHSMAX) {
      h->err = NQELIM;
      return 0;
    }
    nk = (uint8_t *)qdmal(nc * 16);
    if (nk == NULL) {
      h->err = NQEMEM;
      return 0;
    }
    memset(nk, 0, nc * 16);
    for (j = 0; j < h->cap; j++) {
      static const uint8_t z[16];
      const uint8_t *e = h->k + 16 * j;
      if (memcmp(e, z, 16) == 0)
        continue;
      for (i = (size_t)qdld64(e) & (nc - 1);
           memcmp(nk + 16 * i, z, 16) != 0; i = (i + 1) & (nc - 1))
        ;
      memcpy(nk + 16 * i, e, 16);
    }
    qdfree(h->k);
    h->k = nk;
    h->cap = nc;
  }
  m = h->cap - 1;
  for (i = (size_t)qdld64(d) & m;; i = (i + 1) & m) {
    static const uint8_t z[16];
    uint8_t *e = h->k + 16 * i;
    if (memcmp(e, z, 16) == 0) {
      memcpy(e, d, 16);
      h->n++;
      return 1;
    }
    if (memcmp(e, d, 16) == 0)
      return 0;
  }
}

uint64_t qdld64(const uint8_t *p) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++)
    v = (v << 8) | p[i];
  return v;
}

/* the digest of fields: SHA-256 of each length (8 bytes) and its bytes,
 * the first 16 bytes, never all zero (the set's empty mark) */
static void fdig(const qdcsv *c, const size_t *ix, size_t n, uint8_t d[16]) {
  nqhctx h;
  uint8_t o[32];
  size_t i;
  nqhini(&h, NQS256);
  for (i = 0; i < n; i++) {
    size_t l;
    const char *f = qdcsvf(c, ix[i], &l);
    uint8_t ln[8];
    int k;
    for (k = 0; k < 8; k++)
      ln[k] = (uint8_t)((uint64_t)l >> (56 - 8 * k));
    nqhupd(&h, ln, 8);
    nqhupd(&h, (const uint8_t *)f, l);
  }
  nqhfin(&h, o, 32);
  memcpy(d, o, 16);
  d[15] |= 1;
}

/* ---- the check ---- */

typedef struct {
  const char *name;
  unsigned t; /* QDT* bit; 0 for text */
  int nulls;
  const djs *min, *max, *set;
  size_t at; /* its field in the file */
} qdcol;

typedef struct {
  const djs *r;
  const char *kind;
  size_t ix[64];
  size_t nix;
  qdhs hs;
  uint64_t bad, first, nn;
  int prev;
  double pd;
  char *ps;
  int ok; /* 0: the rule cannot run (a column it names is not there) */
} qdrule;

#define QDSHOW 10

typedef struct {
  nqdrep *rep;
  const char *path;
  const char *sy;
  uint64_t probs;
} qdctx;

static void prob(qdctx *x, const char *fmt, const char *a, const char *b,
                 uint64_t line) {
  char m[400];
  x->probs++;
  if (x->probs > QDSHOW)
    return;
  snprintf(m, sizeof m, fmt, a, b);
  qdrepadd(x->rep, "schema", 0, "%s%s: line %llu: %s", x->path, x->sy,
           (unsigned long long)line, m);
}

static size_t colat(const qdcol *cols, size_t nc, const char *name) {
  size_t i;
  for (i = 0; i < nc; i++)
    if (strcmp(cols[i].name, name) == 0)
      return i;
  return (size_t)-1;
}

/* a value of column c, not missing: its type, range and set */
static void cval(qdctx *x, const qdcol *c, const char *v, size_t n,
                 uint64_t line) {
  double d;
  unsigned m = qdvclass(v, n, &d);
  size_t i;
  char q[80];
  snprintf(q, sizeof q, "\"%.60s%s\"", v, n > 60 ? "..." : "");
  if (c->t != 0 && !(m & c->t)) {
    prob(x, "column %s: %s is not a value of its type", c->name, q, line);
    return;
  }
  if (c->t == QDTINT || c->t == QDTREAL) {
    if ((c->min != NULL && d < c->min->d) ||
        (c->max != NULL && d > c->max->d))
      prob(x, "column %s: %s is outside its range", c->name, q, line);
  } else if (c->t == QDTDATE) {
    if ((c->min != NULL && strcmp(v, c->min->s) < 0) ||
        (c->max != NULL && strcmp(v, c->max->s) > 0))
      prob(x, "column %s: %s is outside its range", c->name, q, line);
  }
  if (c->set != NULL) {
    for (i = 0; i < c->set->n; i++)
      if (c->set->k[i]->sl == n && memcmp(c->set->k[i]->s, v, n) == 0)
        return;
    prob(x, "column %s: %s is not one of its values", c->name, q, line);
  }
}

static void rulestep(qdrule *u, const qdcsv *c, const djs *na,
                     uint64_t line) {
  size_t l;
  const char *v;
  double d;
  if (!u->ok || u->nix == 0)
    return;
  if (strcmp(u->kind, "unique") == 0 || strcmp(u->kind, "distinct") == 0) {
    uint8_t dg[16];
    if (strcmp(u->kind, "distinct") == 0) {
      v = qdcsvf(c, u->ix[0], &l);
      if (isna(na, v, l))
        return;
    }
    fdig(c, u->ix, u->nix, dg);
    if (!hsadd(&u->hs, dg) && !u->hs.err && u->kind[0] == 'u') {
      if (u->bad++ == 0)
        u->first = line;
    }
    return;
  }
  v = qdcsvf(c, u->ix[0], &l);
  if (isna(na, v, l)) {
    if (strcmp(u->kind, "notnull") == 0 && u->bad++ == 0)
      u->first = line;
    return;
  }
  u->nn++;
  if (strcmp(u->kind, "range") == 0) {
    const djs *mn = qdjget(u->r, "min"), *mx = qdjget(u->r, "max");
    if (!(qdvclass(v, l, &d) & QDTREAL) || (mn != NULL && d < mn->d) ||
        (mx != NULL && d > mx->d)) {
      if (u->bad++ == 0)
        u->first = line;
    }
  } else if (strcmp(u->kind, "set") == 0) {
    const djs *s = qdjget(u->r, "set");
    size_t i;
    for (i = 0; i < s->n; i++)
      if (s->k[i]->sl == l && memcmp(s->k[i]->s, v, l) == 0)
        break;
    if (i == s->n && u->bad++ == 0)
      u->first = line;
  } else if (strcmp(u->kind, "incr") == 0) {
    int num = (qdvclass(v, l, &d) & QDTREAL) != 0;
    if (u->prev) {
      int down = num && u->ps == NULL ? d < u->pd
                                      : (u->ps != NULL && strcmp(v, u->ps) < 0);
      if (down && u->bad++ == 0)
        u->first = line;
    }
    u->prev = 1;
    qdfree(u->ps);
    u->ps = NULL;
    if (num)
      u->pd = d;
    else
      u->ps = qddup(v, l);
  }
}

static int rulesetup(qdrule *u, const djs *r, const qdcol *cols, size_t nc,
                     qdctx *x) {
  const djs *col = qdjget(r, "col"), *cs = qdjget(r, "cols");
  size_t i;
  memset(u, 0, sizeof *u);
  u->r = r;
  u->kind = qdjget(r, "kind")->s;
  u->ok = 1;
  if (col != NULL) {
    u->ix[0] = colat(cols, nc, col->s);
    u->nix = 1;
  } else if (cs != NULL) {
    if (cs->n == 0 || cs->n > 64) {
      u->ok = 0;
      return qdrepadd(x->rep, "rule", 0,
                      "%s%s: unique: cols names 1 to 64 columns", x->path,
                      x->sy);
    }
    for (i = 0; i < cs->n; i++)
      u->ix[i] = colat(cols, nc, cs->k[i]->s);
    u->nix = cs->n;
  }
  for (i = 0; i < u->nix; i++) {
    if (u->ix[i] == (size_t)-1) {
      u->ok = 0;
      return qdrepadd(x->rep, "rule", 0,
                      "%s%s: %s: names a column the schema does not have",
                      x->path, x->sy, u->kind);
    }
    u->ix[i] = cols[u->ix[i]].at;
  }
  return NQOK;
}

static void ruleend(qdrule *u, qdctx *x, uint64_t rows, size_t ncol) {
  const djs *col = qdjget(u->r, "col");
  const djs *mn = qdjget(u->r, "min"), *mx = qdjget(u->r, "max");
  char who[300];
  int ok = 1;
  char m[200];
  m[0] = '\0';
  snprintf(who, sizeof who, "%s%s: %s(%s)", x->path, x->sy, u->kind,
           col != NULL ? col->s : "");
  if (!u->ok)
    return;
  if (u->hs.err) {
    qdrepadd(x->rep, "rule", 0, "%s: too many distinct values to check",
             who);
    goto out;
  }
  if (strcmp(u->kind, "rows") == 0 || strcmp(u->kind, "cols") == 0 ||
      strcmp(u->kind, "distinct") == 0) {
    double v = u->kind[0] == 'r'   ? (double)rows
               : u->kind[0] == 'c' ? (double)ncol
                                   : (double)u->hs.n;
    ok = !(mn != NULL && v < mn->d) && !(mx != NULL && v > mx->d);
    snprintf(m, sizeof m, "%.0f", v);
    qdrepadd(x->rep, "rule", ok, "%s: %s%s", who, m,
             ok ? "" : ", outside its bounds");
    goto out;
  }
  if (strcmp(u->kind, "complete") == 0) {
    double s = rows ? (double)u->nn / (double)rows : 1;
    double want = qdjget(u->r, "share")->d;
    ok = s >= want;
    qdrepadd(x->rep, "rule", ok, "%s: %.4f of rows not missing%s", who, s,
             ok ? "" : ", below its share");
    goto out;
  }
  if (u->bad)
    qdrepadd(x->rep, "rule", 0, "%s: %llu rows fail, the first at line %llu",
             who, (unsigned long long)u->bad, (unsigned long long)u->first);
  else
    qdrepadd(x->rep, "rule", 1, "%s: holds", who);
out:
  qdfree(u->hs.k);
  qdfree(u->ps);
}

int qdschk(nqdrep *rep, const char *dir, const djs *sch, const char *sy) {
  const char *path = qdjget(sch, "path")->s;
  const djs *dl = qdjget(sch, "delim"), *hd = qdjget(sch, "header");
  const djs *na = qdjget(sch, "na"), *cj = qdjget(sch, "columns");
  const djs *rr = qdjget(sch, "rows"), *rl = qdjget(sch, "rules");
  int header = hd == NULL || hd->t == DJTRUE, rc, got;
  size_t nc = cj != NULL ? cj->n : 0, nr = rl != NULL ? rl->n : 0, i;
  qdcol *cols = NULL;
  qdrule *ru = NULL;
  qdcsv c;
  qdctx x;
  char p[4200];
  uint64_t rows = 0;
  size_t nf = 0;
  int rowsbad = 0;
  char **own = NULL;
  size_t nown = 0, ncr = nc;
  x.rep = rep;
  x.path = path;
  x.sy = sy;
  x.probs = 0;
  if (qdjoin(dir, path, p, sizeof p) != NQOK)
    return qdrepadd(rep, "schema", 0, "%s%s: not a path in the folder", path,
                    sy);
  if (qdcsvfile(&c, p, dl != NULL ? dl->s[0] : ',') != NQOK)
    return qdrepadd(rep, "schema", 0, "%s%s: missing or unreadable", path,
                    sy);
  cols = (qdcol *)qdmal((nc + 1) * sizeof *cols);
  ru = (qdrule *)qdmal((nr + 1) * sizeof *ru);
  if (cols == NULL || ru == NULL) {
    rc = NQEMEM;
    goto done;
  }
  memset(ru, 0, (nr + 1) * sizeof *ru);
  for (i = 0; i < nc; i++) {
    const djs *e = cj->k[i], *nu = qdjget(e, "nulls");
    cols[i].name = qdjget(e, "name")->s;
    cols[i].t = tbit(qdjget(e, "type")->s);
    cols[i].nulls = nu == NULL || nu->t == DJTRUE;
    cols[i].min = qdjget(e, "min");
    cols[i].max = qdjget(e, "max");
    cols[i].set = qdjget(e, "set");
    cols[i].at = i;
  }
  /* the header */
  if ((rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  if (!got) {
    qdrepadd(rep, "schema", 0, "%s%s: empty: no header and no rows", path,
             sy);
    rc = NQOK;
    goto done;
  }
  nf = c.nf;
  if (nc == 0) {
    /* no columns pinned: the file's own, as text, for the rules */
    qdfree(cols);
    cols = (qdcol *)qdmal((nf + 1) * sizeof *cols);
    own = (char **)qdmal((nf + 1) * sizeof *own);
    if (cols == NULL || own == NULL) {
      rc = NQEMEM;
      goto done;
    }
    memset(own, 0, (nf + 1) * sizeof *own);
    nown = nf;
    for (i = 0; i < nf; i++) {
      char g[32];
      const char *nm = qdcsvf(&c, i, NULL);
      snprintf(g, sizeof g, "V%lu", (unsigned long)i + 1);
      if ((own[i] = header ? qddup(nm, strlen(nm)) : qddup(g, strlen(g))) ==
          NULL) {
        rc = NQEMEM;
        goto done;
      }
      memset(&cols[i], 0, sizeof cols[i]);
      cols[i].name = own[i];
      cols[i].nulls = 1;
      cols[i].at = i;
    }
    ncr = nf;
  } else if (header) {
    for (i = 0; i < nc && i < c.nf; i++) {
      if (strcmp(qdcsvf(&c, i, NULL), cols[i].name) != 0)
        break;
    }
    if (i < nc || c.nf != nc) {
      if (i < nc && i < c.nf)
        qdrepadd(rep, "schema", 0,
                 "%s%s: header column %lu is \"%.80s\", the schema says "
                 "\"%.80s\"",
                 path, sy, (unsigned long)i + 1, qdcsvf(&c, i, NULL),
                 cols[i].name);
      else
        qdrepadd(rep, "schema", 0,
                 "%s%s: the header has %lu columns, the schema %lu", path, sy,
                 (unsigned long)c.nf, (unsigned long)nc);
      rc = NQOK;
      goto done;
    }
  }
  for (i = 0; i < nr; i++)
    rulesetup(&ru[i], rl->k[i], cols, ncr, &x);
  /* with a header, the first data record comes next */
  if (header && (rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  while (got) {
    size_t k;
    rows++;
    if (nc > 0 && c.nf != nc) {
      char a[24], b[24];
      snprintf(a, sizeof a, "%lu", (unsigned long)c.nf);
      snprintf(b, sizeof b, "%lu", (unsigned long)nc);
      prob(&x, "%s fields, the schema has %s columns", a, b, c.recline);
    } else {
      for (k = 0; k < nc; k++) {
        size_t l;
        const char *v = qdcsvf(&c, k, &l);
        if (isna(na, v, l)) {
          if (!cols[k].nulls)
            prob(&x, "column %s: a missing value%s", cols[k].name, "",
                 c.recline);
        } else {
          cval(&x, &cols[k], v, l, c.recline);
        }
      }
      for (k = 0; k < nr; k++)
        rulestep(&ru[k], &c, na, c.recline);
    }
    if ((rc = qdcsvnext(&c, &got)) != NQOK)
      goto bad;
  }
  if (rr != NULL) {
    int64_t lo = -1, hi = -1;
    qdjint(qdjget(rr, "min"), &lo);
    qdjint(qdjget(rr, "max"), &hi);
    if ((lo >= 0 && rows < (uint64_t)lo) ||
        (hi >= 0 && rows > (uint64_t)hi)) {
      rowsbad = 1;
      qdrepadd(rep, "schema", 0,
               "%s%s: %llu rows, the schema allows %s%lld to %s%lld", path,
               sy, (unsigned long long)rows, lo >= 0 ? "" : "any ",
               (long long)(lo >= 0 ? lo : 0), hi >= 0 ? "" : "any ",
               (long long)(hi >= 0 ? hi : 0));
    }
  }
  if (x.probs > QDSHOW)
    qdrepadd(rep, "schema", 0, "%s%s: %llu problems in all (the first %d "
             "shown)", path, sy, (unsigned long long)x.probs, QDSHOW);
  if (x.probs == 0 && !rowsbad)
    qdrepadd(rep, "schema", 1, "%s%s: %llu rows, %lu columns as the schema "
             "says", path, sy, (unsigned long long)rows,
             (unsigned long)(nc ? nc : nf));
  for (i = 0; i < nr; i++)
    ruleend(&ru[i], &x, rows, nc ? nc : nf);
  nr = 0;
  rc = NQOK;
  goto done;
bad:
  qdrepadd(rep, "schema", 0, "%s%s: %s", path, sy,
           c.why[0] ? c.why : nqerr(rc));
  rc = NQOK;
done:
  for (i = 0; i < nr; i++) {
    qdfree(ru[i].hs.k);
    qdfree(ru[i].ps);
  }
  for (i = 0; i < nown; i++)
    qdfree(own[i]);
  qdfree(own);
  qdfree(cols);
  qdfree(ru);
  qdcsvclose(&c);
  return rc;
}

int nqdschk(const char *dir, const char *schema, size_t n, nqdrep **out) {
  djs *e = NULL;
  nqdrep *rep;
  char why[600];
  size_t i;
  int rc, bad = 0;
  if (dir == NULL || out == NULL || (schema == NULL && n))
    return NQEARG;
  *out = NULL;
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  rc = qdjparse(schema, n, &e, why, sizeof why);
  if (rc == NQOK)
    rc = qdelemok("schemas", e, why, sizeof why);
  if (rc != NQOK) {
    qdjfree(e);
    if (rc == NQEMEM) {
      nqdrepfree(rep);
      return rc;
    }
    qdrepadd(rep, "schema", 0, "not a schema: %s", why);
    *out = rep;
    return NQEVRFY;
  }
  rc = qdschk(rep, dir, e, "");
  qdjfree(e);
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

/* ---- inference ---- */

typedef struct {
  unsigned m;
  uint64_t nulls, n;
  double lo, hi;
  char dlo[11], dhi[11];
} qdinf;

int nqdinfer(const char *dir, const char *path, const nqdcsvopt *o,
             char *out, size_t cap, size_t *outlen, char *why, size_t wcap) {
  char p[4200];
  qdcsv c;
  int rc, got, header = o == NULL || !o->noheader;
  int ranges = o != NULL && o->ranges;
  char delim = o != NULL && o->delim ? o->delim : ',';
  size_t nc = 0, i, j;
  uint64_t rows = 0;
  qdinf *in = NULL;
  char **names = NULL;
  djs *e = NULL, *cols;
  dbuf b;
  if (why != NULL && wcap)
    why[0] = '\0';
  if (path == NULL)
    return NQEARG;
  if (delim == '"' || delim == '\r' || delim == '\n') {
    qdwhy(why, wcap, "the delimiter cannot be a quote or a line break");
    return NQEARG;
  }
  if ((rc = qdjoin(dir, path, p, sizeof p)) != NQOK) {
    qdwhy(why, wcap, "%s: not a path a capsule holds", path);
    return rc;
  }
  if (qdcsvfile(&c, p, delim) != NQOK) {
    qdwhy(why, wcap, "%s: cannot be read", p);
    return NQEIO;
  }
  if ((rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  if (!got) {
    qdwhy(why, wcap, "%s: empty", path);
    rc = NQEDEC;
    goto out;
  }
  nc = c.nf;
  in = (qdinf *)qdmal(nc * sizeof *in);
  names = (char **)qdmal(nc * sizeof *names);
  if (in == NULL || names == NULL) {
    rc = NQEMEM;
    goto out;
  }
  memset(names, 0, nc * sizeof *names);
  for (i = 0; i < nc; i++) {
    char g[32];
    memset(&in[i], 0, sizeof in[i]);
    in[i].m = QDTBOOL | QDTINT | QDTREAL | QDTDATE;
    in[i].lo = HUGE_VAL;
    in[i].hi = -HUGE_VAL;
    snprintf(g, sizeof g, "V%lu", (unsigned long)i + 1);
    names[i] = header ? qddup(qdcsvf(&c, i, NULL), strlen(qdcsvf(&c, i,
                                                                   NULL)))
                      : qddup(g, strlen(g));
    if (names[i] == NULL) {
      rc = NQEMEM;
      goto out;
    }
    for (j = 0; j < i; j++) {
      if (strcmp(names[i], names[j]) == 0) {
        qdwhy(why, wcap, "%s: the header names column \"%.80s\" twice", path,
              names[i]);
        rc = NQEDEC;
        goto out;
      }
    }
  }
  if (header && (rc = qdcsvnext(&c, &got)) != NQOK)
    goto bad;
  while (got) {
    if (c.nf != nc) {
      qdwhy(why, wcap, "%s: line %llu has %lu fields, the first line %lu",
            path, (unsigned long long)c.recline, (unsigned long)c.nf,
            (unsigned long)nc);
      rc = NQEDEC;
      goto out;
    }
    rows++;
    for (i = 0; i < nc; i++) {
      size_t l;
      const char *v = qdcsvf(&c, i, &l);
      double d;
      unsigned m;
      if (isna(NULL, v, l)) {
        in[i].nulls++;
        continue;
      }
      m = qdvclass(v, l, &d);
      in[i].m &= m;
      in[i].n++;
      if (m & QDTREAL) {
        if (d < in[i].lo)
          in[i].lo = d;
        if (d > in[i].hi)
          in[i].hi = d;
      }
      if (m & QDTDATE) {
        if (in[i].dlo[0] == 0 || strcmp(v, in[i].dlo) < 0)
          memcpy(in[i].dlo, v, 11);
        if (in[i].dhi[0] == 0 || strcmp(v, in[i].dhi) > 0)
          memcpy(in[i].dhi, v, 11);
      }
    }
    if ((rc = qdcsvnext(&c, &got)) != NQOK)
      goto bad;
  }
  /* the element */
  e = qdjnew(DJOBJ);
  cols = qdjnew(DJARR);
  if (e == NULL || cols == NULL) {
    qdjfree(cols);
    rc = NQEMEM;
    goto out;
  }
  rc = qdjset(e, "path", qdjstr(path));
  if (rc == NQOK)
    rc = qdjset(e, "kind", qdjstr("csv"));
  if (rc == NQOK && delim != ',') {
    char dd[2];
    dd[0] = delim;
    dd[1] = 0;
    rc = qdjset(e, "delim", qdjstr(dd));
  }
  if (rc == NQOK && !header)
    rc = qdjset(e, "header", qdjnew(DJFALSE));
  if (rc == NQOK) {
    djs *rg = qdjnew(DJOBJ);
    if (rg != NULL && qdjset(rg, "min", qdjnum((double)rows)) == NQOK &&
        qdjset(rg, "max", qdjnum((double)rows)) == NQOK)
      rc = qdjset(e, "rows", rg);
    else {
      qdjfree(rg);
      rc = NQEMEM;
    }
  }
  for (i = 0; i < nc && rc == NQOK; i++) {
    djs *k = qdjnew(DJOBJ);
    unsigned m = in[i].n ? in[i].m : 0;
    const char *t = m & QDTBOOL   ? tnames[0]
                    : m & QDTINT  ? tnames[1]
                    : m & QDTREAL ? tnames[2]
                    : m & QDTDATE ? tnames[3]
                                  : tnames[4];
    if (k == NULL || qdjset(k, "name", qdjstr(names[i])) != NQOK ||
        qdjset(k, "type", qdjstr(t)) != NQOK ||
        qdjset(k, "nulls", qdjnew(in[i].nulls ? DJTRUE : DJFALSE)) != NQOK) {
      qdjfree(k);
      rc = NQEMEM;
      break;
    }
    if (ranges && (m & (QDTINT | QDTREAL)) && !(m & QDTBOOL)) {
      if (qdjset(k, "min", qdjnum(in[i].lo)) != NQOK ||
          qdjset(k, "max", qdjnum(in[i].hi)) != NQOK)
        rc = NQEMEM;
    } else if (ranges && (m & QDTDATE)) {
      if (qdjset(k, "min", qdjstr(in[i].dlo)) != NQOK ||
          qdjset(k, "max", qdjstr(in[i].dhi)) != NQOK)
        rc = NQEMEM;
    }
    if (rc == NQOK)
      rc = qdjadd(cols, k);
    else
      qdjfree(k);
  }
  if (rc == NQOK)
    rc = qdjset(e, "columns", cols);
  else
    qdjfree(cols);
  if (rc == NQOK)
    rc = qdelemok("schemas", e, why, wcap);
  if (rc == NQOK) {
    memset(&b, 0, sizeof b);
    qdjwrite(e, &b);
    rc = qdbout(&b, out, cap, outlen);
    qdbfree(&b);
  }
  goto out;
bad:
  qdwhy(why, wcap, "%s: %s", path, c.why[0] ? c.why : nqerr(rc));
out:
  if (names != NULL)
    for (i = 0; i < nc; i++)
      qdfree(names[i]);
  qdfree(names);
  qdfree(in);
  qdjfree(e);
  qdcsvclose(&c);
  return rc;
}
