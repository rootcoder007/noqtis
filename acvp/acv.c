/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The ACVP harnesses' shared code: see acv.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"

/* ---- reading ---- */

nqjs *acvld(const char *path) {
  char *buf = NULL;
  size_t len = 0, off = 0;
  nqjs *v = NULL;
  int rc = nqreadf(path, (size_t)1 << 30, &buf, &len);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot read (%s)\n", path, nqerr(rc));
    return NULL;
  }
  rc = nqjparse(buf, len, &v, &off);
  nqfree(buf, len + 1);
  if (rc != NQOK) {
    fprintf(stderr, "%s: not JSON at byte %lu (%s)\n", path,
            (unsigned long)off, nqerr(rc));
    return NULL;
  }
  return v;
}

const nqjs *acvset(const nqjs *v) {
  if (v != NULL && v->type == NQJARR) return nqjat(v, 1);
  return v;
}

const nqjs *acvgrps(const nqjs *v) {
  const nqjs *g = nqjget(acvset(v), "testGroups");
  return g != NULL && g->type == NQJARR ? g : NULL;
}

const nqjs *acvfld(const nqjs *t, const nqjs *g, const char *key) {
  const nqjs *v = nqjget(t, key);
  return v != NULL ? v : nqjget(g, key);
}

int acvu(const nqjs *o, const char *key, uint64_t *out) {
  const nqjs *v = nqjget(o, key);
  const char *s;
  int64_t x;
  uint64_t r = 0;
  if (v == NULL) return 0;
  if (v->type == NQJNUM) {
    if (nqjint(v, &x) != NQOK || x < 0) return 0;
    *out = (uint64_t)x;
    return 1;
  }
  s = nqjstr(v);
  if (s == NULL || *s == 0) return 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9' || r > UINT64_MAX / 10 - 1) return 0;
    r = r * 10 + (uint64_t)(*s - '0');
  }
  *out = r;
  return 1;
}

const char *acvs(const nqjs *o, const char *key) {
  return nqjstr(nqjget(o, key));
}

int acvis(const nqjs *o, const char *key, const char *val) {
  const char *s = acvs(o, key);
  return s != NULL && strcmp(s, val) == 0;
}

uint8_t *acvhex(const nqjs *v, size_t *n) {
  const char *s = nqjstr(v);
  size_t len;
  uint8_t *b;
  *n = 0;
  if (s == NULL) return NULL;
  len = strlen(s);
  b = (uint8_t *)calloc(len / 2 + 1, 1);
  if (b == NULL) return NULL;
  if (nqunhex(s, len, b, len / 2 + 1, n) != NQOK) {
    free(b);
    return NULL;
  }
  return b;
}

int acvhalg(const char *name) {
  static const struct {
    const char *n;
    nqhalg a;
  } t[] = {{"SHA2-224", NQS224},         {"SHA2-256", NQS256},
           {"SHA2-384", NQS384},         {"SHA2-512", NQS512},
           {"SHA2-512/224", NQS512T224}, {"SHA2-512/256", NQS512T256},
           {"SHA3-224", NQS3224},        {"SHA3-256", NQS3256},
           {"SHA3-384", NQS3384},        {"SHA3-512", NQS3512},
           {"SHAKE-128", NQSHK128},      {"SHAKE-256", NQSHK256}};
  size_t i;
  if (name == NULL) return -1;
  for (i = 0; i < sizeof t / sizeof t[0]; i++) {
    if (strcmp(name, t[i].n) == 0) return (int)t[i].a;
  }
  return -1;
}

/* ---- writing ---- */

static void sep(acvw *w) {
  if (!w->first[w->d]) nqcput(&w->b, ",", 1);
  w->first[w->d] = 0;
}

static void key(acvw *w, const char *k) {
  sep(w);
  if (k != NULL) {
    nqcjstr(&w->b, k, strlen(k));
    nqcput(&w->b, ":", 1);
  }
}

static void open1(acvw *w, const char *k, char c) {
  key(w, k);
  nqcput(&w->b, &c, 1);
  if (w->d + 1 < (int)(sizeof w->first / sizeof w->first[0])) w->d++;
  w->first[w->d] = 1;
}

void acvobj(acvw *w, const char *k) { open1(w, k, '{'); }

void acvarr(acvw *w, const char *k) { open1(w, k, '['); }

void acvclose(acvw *w, char c) {
  nqcput(&w->b, &c, 1);
  if (w->d > 0) w->d--;
}

/* a field of the request copied as it is */
static void copy(acvw *w, const nqjs *o, const char *k) {
  const nqjs *v = nqjget(o, k);
  if (v == NULL) return;
  key(w, k);
  if (nqcjval(&w->b, v) != NQOK) w->b.err = NQEDEC;
}

void acvbeg(acvw *w, const nqjs *pr) {
  const nqjs *vs = acvset(pr);
  memset(w, 0, sizeof *w);
  w->first[0] = 1;
  w->wrap = pr->type == NQJARR;
  if (w->wrap) {
    acvarr(w, NULL);
    acvobj(w, NULL);
    copy(w, nqjat(pr, 0), "acvVersion");
    acvclose(w, '}');
  }
  acvobj(w, NULL);
  copy(w, vs, "vsId");
  copy(w, vs, "algorithm");
  copy(w, vs, "mode");
  copy(w, vs, "revision");
  copy(w, vs, "isSample");
  acvarr(w, "testGroups");
}

void acvgbeg(acvw *w, uint64_t tg) {
  acvobj(w, NULL);
  acvkint(w, "tgId", tg);
  acvarr(w, "tests");
}

void acvgend(acvw *w) {
  acvclose(w, ']');
  acvclose(w, '}');
}

void acvtbeg(acvw *w, uint64_t tc) {
  acvobj(w, NULL);
  acvkint(w, "tcId", tc);
}

void acvtend(acvw *w) { acvclose(w, '}'); }

void acvkhex(acvw *w, const char *k, const uint8_t *p, size_t n) {
  static const char dg[] = "0123456789ABCDEF";
  char buf[256];
  size_t i, o = 0;
  key(w, k);
  nqcput(&w->b, "\"", 1);
  for (i = 0; i < n; i++) {
    buf[o++] = dg[p[i] >> 4];
    buf[o++] = dg[p[i] & 15];
    if (o == sizeof buf) {
      nqcput(&w->b, buf, o);
      o = 0;
    }
  }
  nqcput(&w->b, buf, o);
  nqcput(&w->b, "\"", 1);
}

void acvkbool(acvw *w, const char *k, int b) {
  key(w, k);
  nqcputs(&w->b, b ? "true" : "false");
}

void acvkint(acvw *w, const char *k, uint64_t v) {
  key(w, k);
  nqcjint(&w->b, v);
}

/* closes what acvbeg opened and writes the file */
static int fin(acvw *w, const char *path) {
  FILE *f;
  int ok;
  acvclose(w, ']');
  acvclose(w, '}');
  if (w->wrap) acvclose(w, ']');
  nqcput(&w->b, "\n", 1);
  if (w->b.err != NQOK) {
    fprintf(stderr, "%s: cannot build the response (%s)\n", path,
            nqerr(w->b.err));
    return 0;
  }
  f = fopen(path, "wb");
  if (f == NULL) {
    fprintf(stderr, "%s: cannot create\n", path);
    return 0;
  }
  ok = fwrite(w->b.p, 1, w->b.n, f) == w->b.n;
  ok = fclose(f) == 0 && ok;
  if (!ok) fprintf(stderr, "%s: cannot write\n", path);
  return ok;
}

/* ---- comparing ---- */

static int ishex(const char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return 0;
    }
  }
  return 1;
}

static int lc(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* 1 when a and b are the same value (see acvcmp) */
static int same(const nqjs *a, const nqjs *b, int depth) {
  size_t i;
  if (a == NULL || b == NULL || depth > NQJDEPTH) return 0;
  if (a->type != b->type) return 0;
  switch (a->type) {
  case NQJNULL:
  case NQJTRUE:
  case NQJFALSE:
    return 1;
  case NQJNUM:
    return a->len == b->len && memcmp(a->str, b->str, a->len) == 0;
  case NQJSTR:
    if (a->len != b->len) return 0;
    if (memcmp(a->str, b->str, a->len) == 0) return 1;
    if (!ishex(a->str, a->len) || !ishex(b->str, b->len)) return 0;
    for (i = 0; i < a->len; i++) {
      if (lc(a->str[i]) != lc(b->str[i])) return 0;
    }
    return 1;
  case NQJARR:
    if (a->n != b->n) return 0;
    for (i = 0; i < a->n; i++) {
      if (!same(a->kids[i], b->kids[i], depth + 1)) return 0;
    }
    return 1;
  case NQJOBJ:
    if (a->n != b->n) return 0;
    for (i = 0; i < a->n; i++) {
      size_t j;
      for (j = 0; j < b->n; j++) {
        if (b->klen[j] == a->klen[i] &&
            memcmp(b->keys[j], a->keys[i], a->klen[i]) == 0) {
          break;
        }
      }
      if (j == b->n || !same(a->kids[i], b->kids[j], depth + 1)) return 0;
    }
    return 1;
  }
  return 0;
}

/* the test tgId/tcId of groups g, or NULL */
static const nqjs *find(const nqjs *g, uint64_t tg, uint64_t tc) {
  size_t i, j;
  uint64_t x;
  for (i = 0; g != NULL && i < g->n; i++) {
    const nqjs *ts;
    if (!acvu(nqjat(g, i), "tgId", &x) || x != tg) continue;
    ts = nqjget(nqjat(g, i), "tests");
    for (j = 0; ts != NULL && j < ts->n; j++) {
      if (acvu(nqjat(ts, j), "tcId", &x) && x == tc) return nqjat(ts, j);
    }
  }
  return NULL;
}

static long ndiff = 0;

static void diff(uint64_t tg, uint64_t tc, const char *what) {
  if (ndiff++ < 20) {
    fprintf(stderr, "tgId %llu tcId %llu: %s\n", (unsigned long long)tg,
            (unsigned long long)tc, what);
  }
}

long acvcmp(const nqjs *exp, const nqjs *resp, long *match, long *miss) {
  const nqjs *eg = acvgrps(exp), *rg = acvgrps(resp);
  const nqjs *ev = nqjget(acvset(exp), "vsId");
  const nqjs *rv = nqjget(acvset(resp), "vsId");
  size_t i, j;
  ndiff = 0;
  *match = 0;
  *miss = 0;
  if (eg == NULL || rg == NULL) {
    fprintf(stderr, "no testGroups\n");
    return 1;
  }
  if (!same(ev, rv, 0)) diff(0, 0, "vsId differs");
  for (i = 0; i < eg->n; i++) {
    const nqjs *ts = nqjget(nqjat(eg, i), "tests");
    uint64_t tg = 0, tc = 0;
    acvu(nqjat(eg, i), "tgId", &tg);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *e = nqjat(ts, j), *r;
      acvu(e, "tcId", &tc);
      r = find(rg, tg, tc);
      if (r == NULL) {
        (*miss)++;
      } else if (same(e, r, 0)) {
        (*match)++;
      } else {
        diff(tg, tc, "differs");
      }
    }
  }
  /* and nothing the expected results do not have */
  for (i = 0; i < rg->n; i++) {
    const nqjs *ts = nqjget(nqjat(rg, i), "tests");
    uint64_t tg = 0, tc = 0;
    acvu(nqjat(rg, i), "tgId", &tg);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      acvu(nqjat(ts, j), "tcId", &tc);
      if (find(eg, tg, tc) == NULL) diff(tg, tc, "not in the expected results");
    }
  }
  return ndiff;
}

/* ---- the program ---- */

int acvmain(int argc, char **argv, const char *name, acvfn run) {
  nqjs *pr, *ex = NULL, *re = NULL;
  acvw w;
  long omit = 0, match = 0, miss = 0, nd;
  int rc, ok = 0;
  if (argc != 3 && argc != 4) {
    fprintf(stderr,
            "usage: %s <request.json> <response.json> [<expected.json>]\n",
            name);
    return 1;
  }
  pr = acvld(argv[1]);
  if (pr == NULL) return 1;
  if (acvgrps(pr) == NULL) {
    fprintf(stderr, "%s: %s has no testGroups\n", name, argv[1]);
    nqjfree(pr);
    return 1;
  }
  acvbeg(&w, pr);
  rc = run(pr, &w, &omit);
  if (rc != NQOK) {
    fprintf(stderr, "%s: %s: %s\n", name, argv[1], nqerr(rc));
    goto out;
  }
  if (!fin(&w, argv[2])) goto out;
  if (omit > 0) {
    fprintf(stderr, "%s: %ld tests omitted: %s is not a complete response\n",
            name, omit, argv[2]);
  }
  if (argc == 3) {
    ok = 1;
    goto out;
  }
  ex = acvld(argv[3]);
  re = acvld(argv[2]);
  if (ex == NULL || re == NULL) goto out;
  nd = acvcmp(ex, re, &match, &miss);
  printf("%s: %s: %ld tests match, %ld omitted, %ld differ\n", name,
         argv[1], match, miss, nd);
  ok = nd == 0 && match > 0 && miss == omit;
  if (miss != omit) {
    fprintf(stderr, "%s: %ld expected tests missing, %ld omitted\n", name,
            miss, omit);
  }
out:
  nqcbfree(&w.b);
  nqjfree(pr);
  nqjfree(ex);
  nqjfree(re);
  return ok ? 0 : 1;
}
