/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqdrpt: a report of a capsule, its check and what its data record
 * says, in Markdown or in plain text. */
#include "int.h"

#include <string.h>

typedef struct {
  dbuf *b;
  int md;
} qdrp;

/* s[0..n) inside a line or a table cell: a line break or another
 * control character is a space, so a value never ends its line; in
 * Markdown a backslash goes once before each character Markdown could
 * read as markup (a '|' would end the cell) */
static void put(qdrp *r, const char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c == 0x7f) {
      if (c == '\r' && i + 1 < n && s[i + 1] == '\n')
        i++;
      qdbch(r->b, ' ');
      continue;
    }
    if (r->md && strchr("\\`*_[]<>|#~&!", (int)c) != NULL)
      qdbch(r->b, '\\');
    qdbch(r->b, (char)c);
  }
}

static void puts1(qdrp *r, const char *s) {
  put(r, s, strlen(s));
}

/* a value of the record: a string, a number as the record writes it,
 * true or false, an array's elements joined by commas */
static void val(qdrp *r, const djs *v) {
  char t[40];
  size_t i;
  if (v == NULL) {
    qdbstr(r->b, r->md ? "" : "-");
    return;
  }
  switch (v->t) {
  case DJSTR:
    put(r, v->s, v->sl);
    break;
  case DJNUM:
    if (qdnumfmt(v->d, t) != NQOK)
      strcpy(t, "?");
    qdbstr(r->b, t);
    break;
  case DJTRUE:
    qdbstr(r->b, "true");
    break;
  case DJFALSE:
    qdbstr(r->b, "false");
    break;
  case DJARR:
    for (i = 0; i < v->n; i++) {
      if (i)
        qdbstr(r->b, ", ");
      val(r, v->k[i]);
    }
    break;
  default:
    qdbstr(r->b, "...");
    break;
  }
}

static void head(qdrp *r, int level, const char *t) {
  if (r->md) {
    /* one blank line before a heading */
    if (!(r->b->n >= 2 && r->b->b[r->b->n - 1] == '\n' &&
          r->b->b[r->b->n - 2] == '\n'))
      qdbch(r->b, '\n');
    qdbstr(r->b, level == 2 ? "## " : "### ");
    qdbstr(r->b, t);
    qdbstr(r->b, "\n\n");
  } else {
    qdbstr(r->b, level == 2 ? "\n" : "\n  ");
    qdbstr(r->b, t);
    qdbstr(r->b, ":\n");
  }
}

/* a table: its header, then rows of cells */
static void thead(qdrp *r, const char *const *h, size_t n) {
  size_t i;
  if (!r->md)
    return;
  for (i = 0; i < n; i++) {
    qdbstr(r->b, i ? " | " : "| ");
    qdbstr(r->b, h[i]);
  }
  qdbstr(r->b, " |\n");
  for (i = 0; i < n; i++)
    qdbstr(r->b, "|---");
  qdbstr(r->b, "|\n");
}

static void cell(qdrp *r, int first) {
  if (r->md)
    qdbstr(r->b, first ? "| " : " | ");
  else
    qdbstr(r->b, first ? "    " : "  ");
}

static void rowend(qdrp *r) {
  qdbstr(r->b, r->md ? " |\n" : "\n");
}

/* one row of fields of e */
static void row(qdrp *r, const djs *e, const char *const *k, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    cell(r, i == 0);
    val(r, qdjget(e, k[i]));
  }
  rowend(r);
}

/* a member of the record as a table of some of its fields */
static void table(qdrp *r, const djs *root, const char *m, const char *t,
                  const char *const *k, size_t n) {
  const djs *a = qdjget(root, m);
  size_t i;
  if (a == NULL)
    return;
  head(r, 3, t);
  thead(r, k, n);
  for (i = 0; i < a->n; i++)
    row(r, a->k[i], k, n);
}

/* the rows of a check: ok or FAIL, the check and its detail */
static size_t rows(qdrp *r, size_t n, const char *pre,
                   int (*get)(const void *, size_t, const char **, int *,
                              const char **),
                   const void *rep) {
  static const char *const h[] = {"result", "check", "detail"};
  size_t i, bad = 0;
  thead(r, h, 3);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (get(rep, i, &c, &ok, &d) != NQOK || c == NULL)
      continue;
    bad += !ok;
    cell(r, 1);
    qdbstr(r->b, ok ? "ok" : "FAIL");
    cell(r, 0);
    puts1(r, pre);
    puts1(r, c);
    cell(r, 0);
    puts1(r, d != NULL ? d : "");
    rowend(r);
  }
  return bad;
}

static int capget(const void *rep, size_t i, const char **c, int *ok,
                  const char **d) {
  return nqrepi((const nqrep *)rep, i, c, ok, d);
}

static int datget(const void *rep, size_t i, const char **c, int *ok,
                  const char **d) {
  return nqdrepi((const nqdrep *)rep, i, c, ok, d);
}

static void kv(qdrp *r, const char *k, const djs *v) {
  if (v == NULL)
    return;
  if (r->md) {
    qdbstr(r->b, "- ");
    qdbstr(r->b, k);
    qdbstr(r->b, ": ");
  } else {
    qdbstr(r->b, "    ");
    qdbstr(r->b, k);
    qdbstr(r->b, ": ");
  }
  val(r, v);
  qdbch(r->b, '\n');
}

static void count(qdrp *r, const char *k, size_t n) {
  char t[40];
  qdbstr(r->b, r->md ? "- " : "    ");
  qdbstr(r->b, k);
  qdbstr(r->b, ": ");
  qdnumfmt((double)n, t);
  qdbstr(r->b, t);
  qdbch(r->b, '\n');
}

/* the data record: what it says, then nqdchk's rows */
static size_t data(qdrp *r, const char *dir, const nqdrep *given,
                   size_t *nrow, int *err) {
  static const char *const ksrc[] = {"path", "size", "sha256", "url",
                                     "publisher", "licence", "retrieved",
                                     "synthetic"};
  static const char *const kst[] = {"path", "rows", "delim"};
  static const char *const kstep[] = {"kind", "from", "to", "script",
                                      "sha256", "note"};
  static const char *const kchk[] = {"name", "status", "expected",
                                     "observed", "tol", "note"};
  static const char *const kcmt[] = {"kind", "label", "created", "after",
                                     "digest"};
  nqdrec *rec = NULL;
  nqdrep *rep = NULL;
  const djs *root, *a, *e;
  char why[600];
  size_t i, j, bad = 0;
  int rc;
  head(r, 2, "Data");
  rc = nqdload(dir, &rec, why, sizeof why);
  if (rc == NQEIO) {
    qdbstr(r->b, r->md ? "No data record (`" NQDFILE "`).\n"
                       : "  No data record (" NQDFILE ").\n");
    return 0;
  }
  if (rc == NQEMEM) {
    *err = rc;
    return 0;
  }
  root = rc == NQOK ? qdrectree(rec) : NULL;
  if (root != NULL) {
    table(r, root, "sources", "Sources", ksrc, 8);
    if ((a = qdjget(root, "schemas")) != NULL) {
      static const char *const h[] = {"path", "columns", "rows", "rules"};
      head(r, 3, "Schemas");
      thead(r, h, 4);
      for (i = 0; i < a->n; i++) {
        const djs *c = qdjget(a->k[i], "columns"), *rr = qdjget(a->k[i],
                                                                "rows");
        const djs *ru = qdjget(a->k[i], "rules");
        cell(r, 1);
        val(r, qdjget(a->k[i], "path"));
        cell(r, 0);
        if (c != NULL) {
          for (j = 0; j < c->n; j++) {
            if (j)
              qdbstr(r->b, ", ");
            val(r, qdjget(c->k[j], "name"));
            qdbstr(r->b, " (");
            val(r, qdjget(c->k[j], "type"));
            qdbch(r->b, ')');
          }
        }
        cell(r, 0);
        if (rr != NULL) {
          val(r, qdjget(rr, "min"));
          qdbstr(r->b, " to ");
          val(r, qdjget(rr, "max"));
        }
        cell(r, 0);
        if (ru != NULL) {
          for (j = 0; j < ru->n; j++) {
            const djs *col = qdjget(ru->k[j], "col");
            if (j)
              qdbstr(r->b, ", ");
            val(r, qdjget(ru->k[j], "kind"));
            if (col != NULL) {
              qdbch(r->b, '(');
              val(r, col);
              qdbch(r->b, ')');
            }
          }
        } else {
          qdbstr(r->b, r->md ? "" : "-");
        }
        rowend(r);
      }
    }
    if ((a = qdjget(root, "stats")) != NULL) {
      static const char *const h[] = {"path", "rows", "delim", "columns",
                                      "calibrated"};
      head(r, 3, "Drift summaries");
      thead(r, h, 5);
      for (i = 0; i < a->n; i++) {
        const djs *c = qdjget(a->k[i], "columns"), *cal = NULL;
        for (j = 0; j < 3; j++) {
          cell(r, j == 0);
          val(r, qdjget(a->k[i], kst[j]));
        }
        cell(r, 0);
        for (j = 0; c != NULL && j < c->n; j++) {
          if (j)
            qdbstr(r->b, ", ");
          val(r, qdjget(c->k[j], "name"));
          if (cal == NULL)
            cal = qdjget(c->k[j], "cal");
        }
        cell(r, 0);
        if (cal != NULL) {
          qdbstr(r->b, "on ");
          val(r, qdjget(cal, "n"));
          qdbstr(r->b, " files");
        } else {
          qdbstr(r->b, "no");
        }
        rowend(r);
      }
    }
    if ((e = qdjget(root, "env")) != NULL) {
      const djs *rt = qdjget(e, "runtime"), *rg = qdjget(e, "rng");
      static const char *const ke[] = {"os", "arch", "kernel", "cpu",
                                       "locale", "tz", "noqtis", "build"};
      head(r, 3, "Environment");
      for (i = 0; i < 8; i++)
        kv(r, ke[i], qdjget(e, ke[i]));
      if (rt != NULL) {
        kv(r, "runtime", qdjget(rt, "language"));
        kv(r, "runtime version", qdjget(rt, "version"));
        if ((a = qdjget(rt, "packages")) != NULL)
          count(r, "packages", a->n);
      }
      if (rg != NULL) {
        kv(r, "random number generator", qdjget(rg, "kind"));
        kv(r, "seed", qdjget(rg, "seed"));
      }
      if ((a = qdjget(e, "locks")) != NULL) {
        qdbstr(r->b, r->md ? "- lock files: " : "    lock files: ");
        for (j = 0; j < a->n; j++) {
          if (j)
            qdbstr(r->b, ", ");
          val(r, qdjget(a->k[j], "path"));
        }
        qdbch(r->b, '\n');
      }
    }
    table(r, root, "steps", "Steps", kstep, 6);
    table(r, root, "checks", "Recorded checks", kchk, 6);
    table(r, root, "commits", "Commitments", kcmt, 5);
    if ((e = qdjget(root, "cite")) != NULL) {
      static const char *const kc[] = {"title", "authors", "year", "version",
                                       "doi", "url", "licence"};
      head(r, 3, "Citation");
      for (i = 0; i < 7; i++)
        kv(r, kc[i], qdjget(e, kc[i]));
    }
  }
  if (given == NULL) {
    rc = nqdchk(dir, &rep);
    if (rep == NULL) {
      nqdrfree(rec);
      *err = rc;
      return 0;
    }
    given = rep;
  }
  head(r, 3, "Checks");
  bad = rows(r, nqdrepn(given), "data.", datget, given);
  *nrow = nqdrepn(given);
  nqdrepfree(rep);
  nqdrfree(rec);
  return bad;
}

int nqdrpt(const char *dir, const nqrep *crep, const nqdrep *drep, int fmt,
           char *out, size_t cap, size_t *outlen) {
  dbuf b, body;
  qdrp r;
  size_t bad = 0, n = 0, nd = 0;
  int err = NQOK, rc;
  char t[40];
  if (dir == NULL || (fmt != NQDMD && fmt != NQDTXT))
    return NQEARG;
  memset(&b, 0, sizeof b);
  memset(&body, 0, sizeof body);
  r.md = fmt == NQDMD;
  /* the body first: the result line above it counts its rows */
  r.b = &body;
  head(&r, 2, "Capsule");
  if (crep != NULL) {
    n = nqrepn(crep);
    bad += rows(&r, n, "", capget, crep);
  } else {
    /* a report of a capsule: a folder not sealed fails */
    qdbstr(&body, r.md ? "Not sealed: no `noqtis.sig`, nothing to check.\n"
                       : "  FAIL  seal  not sealed: no noqtis.sig\n");
    bad++;
    n++;
  }
  bad += data(&r, dir, drep, &nd, &err);
  if (err != NQOK) {
    qdbfree(&body);
    return err;
  }
  n += nd;
  r.b = &b;
  qdbstr(&b, r.md ? "# noqtis report: " : "noqtis report: ");
  puts1(&r, dir);
  qdbstr(&b, r.md ? "\n\n**" : "\n");
  qdbstr(&b, bad ? "Failed" : "Passed");
  qdbstr(&b, r.md ? "**: " : ": ");
  qdnumfmt((double)bad, t);
  qdbstr(&b, t);
  qdbstr(&b, " of ");
  qdnumfmt((double)n, t);
  qdbstr(&b, t);
  qdbstr(&b, n == 1 ? " check failed" : " checks failed");
  qdbstr(&b, crep == NULL ? " (not sealed)\n" : "\n");
  qdbput(&b, body.b != NULL ? body.b : "", body.n);
  qdbfree(&body);
  if (b.err) {
    rc = b.err;
    qdbfree(&b);
    return rc;
  }
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}
