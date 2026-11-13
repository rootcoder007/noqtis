/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqdsyn: a synthetic CSV file made from a schema (its recipe), the same
 * bytes for the same seed, and recorded as synthetic. */
#include "int.h"

#include <math.h>
#include <string.h>

#define QDSYNMAX ((size_t)1 << 30) /* bytes in a synthetic file */

/* the stream: SHA-256("noqtis-syn-1" || 0x00 || seed || block), seed and
 * block 8 bytes big-endian, read as 64-bit big-endian words */
typedef struct {
  uint8_t seed[8];
  uint64_t blk;
  uint8_t b[32];
  size_t at;
} qdsr;

static uint64_t word(qdsr *s) {
  uint64_t v;
  if (s->at == 32) {
    static const char tag[] = "noqtis-syn-1";
    uint8_t c[8];
    nqhctx h;
    int i;
    for (i = 0; i < 8; i++)
      c[i] = (uint8_t)(s->blk >> (56 - 8 * i));
    nqhini(&h, NQS256);
    nqhupd(&h, (const uint8_t *)tag, sizeof tag); /* with its NUL */
    nqhupd(&h, s->seed, 8);
    nqhupd(&h, c, 8);
    nqhfin(&h, s->b, 32);
    s->blk++;
    s->at = 0;
  }
  v = qdld64(s->b + s->at);
  s->at += 8;
  return v;
}

/* uniform on 0 .. k-1 (k >= 1), by rejection: no bias */
static uint64_t uni(qdsr *s, uint64_t k) {
  uint64_t rem, x;
  if (k <= 1)
    return 0;
  rem = (UINT64_MAX % k + 1) % k; /* 2^64 mod k */
  do
    x = word(s);
  while (x > UINT64_MAX - rem);
  return x % k;
}

/* days since 1970-01-01 of a date and back (proleptic Gregorian) */
static int64_t days(int64_t y, int64_t m, int64_t d) {
  int64_t era, yoe, doy, doe;
  y -= m <= 2;
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = y - era * 400;
  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

static void civil(int64_t z, char out[11]) {
  int64_t era, doe, yoe, y, doy, mp, d, m;
  int i;
  z += 719468;
  era = (z >= 0 ? z : z - 146096) / 146097;
  doe = z - era * 146097;
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = yoe + era * 400;
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp + (mp < 10 ? 3 : -9);
  y += m <= 2;
  for (i = 3; i >= 0; i--, y /= 10)
    out[i] = (char)('0' + y % 10);
  out[4] = '-';
  out[5] = (char)('0' + m / 10);
  out[6] = (char)('0' + m % 10);
  out[7] = '-';
  out[8] = (char)('0' + d / 10);
  out[9] = (char)('0' + d % 10);
  out[10] = '\0';
}

static int64_t dayof(const char *s) {
  int64_t y = 0, m, d;
  int i;
  for (i = 0; i < 4; i++)
    y = y * 10 + (s[i] - '0');
  m = (s[5] - '0') * 10 + (s[6] - '0');
  d = (s[8] - '0') * 10 + (s[9] - '0');
  return days(y, m, d);
}

/* a field, quoted when it holds the delimiter, a quote or a line break */
static void field(dbuf *b, const char *v, size_t n, char dl) {
  size_t i;
  int q = 0;
  for (i = 0; i < n && !q; i++)
    q = v[i] == dl || v[i] == '"' || v[i] == '\r' || v[i] == '\n';
  if (!q) {
    qdbput(b, v, n);
    return;
  }
  qdbch(b, '"');
  for (i = 0; i < n; i++) {
    if (v[i] == '"')
      qdbch(b, '"');
    qdbch(b, v[i]);
  }
  qdbch(b, '"');
}

/* one value of column c */
static int value(qdsr *s, const djs *c, dbuf *b, char dl, char *why,
                 size_t wcap) {
  const char *t = qdjget(c, "type")->s;
  const djs *mn = qdjget(c, "min"), *mx = qdjget(c, "max");
  const djs *set = qdjget(c, "set");
  char o[40];
  if (strcmp(t, "bool") == 0) {
    qdbstr(b, uni(s, 2) ? "true" : "false");
  } else if (strcmp(t, "int") == 0) {
    double lo = mn != NULL ? ceil(mn->d) : 0, hi = mx != NULL ? floor(mx->d)
                                                                : 1000;
    if (!(lo <= hi) || hi - lo >= 9007199254740992.0 ||
        fabs(lo) > 9007199254740992.0 || fabs(hi) > 9007199254740992.0) {
      qdwhy(why, wcap, "column %s: no whole numbers from min to max, or "
            "more than 2^53 of them", qdjget(c, "name")->s);
      return NQEARG;
    }
    if (qdnumfmt(lo + (double)uni(s, (uint64_t)(hi - lo) + 1), o) != NQOK)
      return NQEARG;
    qdbstr(b, o);
  } else if (strcmp(t, "real") == 0) {
    double lo = mn != NULL ? mn->d : 0, hi = mx != NULL ? mx->d : 1, u, v;
    u = (double)(word(s) >> 11) * (1.0 / 9007199254740992.0);
    v = lo + (hi - lo) * u;
    if (v > hi) /* rounding */
      v = hi;
    if (!isfinite(v) || qdnumfmt(v, o) != NQOK) {
      qdwhy(why, wcap, "column %s: min to max is too wide",
            qdjget(c, "name")->s);
      return NQEARG;
    }
    qdbstr(b, o);
  } else if (strcmp(t, "date") == 0) {
    int64_t lo = mn != NULL ? dayof(mn->s) : days(2000, 1, 1);
    int64_t hi = mx != NULL ? dayof(mx->s) : days(2025, 12, 31);
    if (lo > hi) {
      qdwhy(why, wcap, "column %s: min is after max", qdjget(c, "name")->s);
      return NQEARG;
    }
    civil(lo + (int64_t)uni(s, (uint64_t)(hi - lo) + 1), o);
    qdbstr(b, o);
  } else if (set != NULL && set->n > 0) {
    const djs *e = set->k[uni(s, set->n)];
    field(b, e->s, e->sl, dl);
  } else {
    int i;
    for (i = 0; i < 8; i++)
      o[i] = (char)('a' + uni(s, 26));
    qdbput(b, o, 8);
  }
  return NQOK;
}

int nqdsyn(nqdrec *r, const char *dir, const char *path, uint64_t seed,
           uint64_t rows, char *why, size_t wcap) {
  const djs *root, *a, *sch = NULL, *src = NULL, *cols, *dlj, *hd, *na, *rr;
  char p[4200], dl;
  uint8_t h[32];
  uint64_t sz;
  qdsr s;
  dbuf b;
  uint64_t i;
  size_t k;
  int rc = NQOK;
  if (why != NULL && wcap)
    why[0] = '\0';
  if (r == NULL || dir == NULL || path == NULL)
    return NQEARG;
  root = qdrectree(r);
  for (a = qdjget(root, "schemas"), k = 0; a != NULL && k < a->n; k++)
    if (strcmp(qdjget(a->k[k], "path")->s, path) == 0)
      sch = a->k[k];
  for (a = qdjget(root, "sources"), k = 0; a != NULL && k < a->n; k++)
    if (strcmp(qdjget(a->k[k], "path")->s, path) == 0)
      src = a->k[k];
  if (sch == NULL || (cols = qdjget(sch, "columns")) == NULL) {
    qdwhy(why, wcap, "%s: the record has no schema with columns for it, "
          "the recipe", path);
    return NQEARG;
  }
  if (qdjoin(dir, path, p, sizeof p) != NQOK) {
    qdwhy(why, wcap, "%s: not a path a capsule holds", path);
    return NQEARG;
  }
  /* never in place of data that is not marked synthetic */
  if (src != NULL ? (qdjget(src, "synthetic") == NULL ||
                     qdjget(src, "synthetic")->t != DJTRUE)
                  : qdsha(p, h, &sz) == NQOK) {
    qdwhy(why, wcap, "%s: %s; a synthetic file is written only in place "
          "of nothing or of another synthetic one", path,
          src != NULL ? "its source is not marked synthetic"
                      : "the file is there and not recorded as synthetic");
    return NQEARG;
  }
  dlj = qdjget(sch, "delim");
  hd = qdjget(sch, "header");
  na = qdjget(sch, "na");
  rr = qdjget(sch, "rows");
  dl = dlj != NULL ? dlj->s[0] : ',';
  if (rows == 0) {
    int64_t lo = 0;
    rows = rr != NULL && qdjint(qdjget(rr, "min"), &lo) && lo > 0
               ? (uint64_t)lo
               : 100;
  }
  for (k = 0; k < 8; k++)
    s.seed[k] = (uint8_t)(seed >> (56 - 8 * k));
  s.blk = 0;
  s.at = 32;
  memset(&b, 0, sizeof b);
  b.max = QDSYNMAX;
  if (hd == NULL || hd->t == DJTRUE) {
    for (k = 0; k < cols->n; k++) {
      const djs *nm = qdjget(cols->k[k], "name");
      if (k)
        qdbch(&b, dl);
      field(&b, nm->s, nm->sl, dl);
    }
    qdbch(&b, '\n');
  }
  for (i = 0; i < rows && rc == NQOK && !b.err; i++) {
    for (k = 0; k < cols->n && rc == NQOK; k++) {
      const djs *c = cols->k[k], *nu = qdjget(c, "nulls");
      if (k)
        qdbch(&b, dl);
      /* with nulls true, a value is missing one time in ten */
      if (nu != NULL && nu->t == DJTRUE && uni(&s, 10) == 0) {
        if (na != NULL && na->n > 0)
          field(&b, na->k[0]->s, na->k[0]->sl, dl);
        continue;
      }
      rc = value(&s, c, &b, dl, why, wcap);
    }
    qdbch(&b, '\n');
  }
  if (rc == NQOK && b.err) {
    qdwhy(why, wcap, "%s: over %lu bytes", path, (unsigned long)QDSYNMAX);
    rc = b.err;
  }
  if (rc == NQOK && (rc = qdwrite(p, b.b != NULL ? b.b : "", b.n)) != NQOK)
    qdwhy(why, wcap, "%s: cannot be written", p);
  qdbfree(&b);
  if (rc == NQOK)
    rc = nqdsrc(r, dir, path, why, wcap);
  if (rc == NQOK)
    rc = nqdset(r, "sources", path, "synthetic", "true", 4, why, wcap);
  return rc;
}
