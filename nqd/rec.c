/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The data record, noqtis-data-1 (noqtis-data(5)): its members as
 * tables, the strict check of a parsed record against them, and the
 * record API (nqdnew ... nqddel, nqdsrc). */
#include "int.h"

#include <math.h>
#include <string.h>

/* member types */
enum {
  VSTR = 1, /* a string of at most 65536 bytes */
  VPATH,    /* a capsule path */
  VHEX,     /* 64 lower-case hex digits */
  VINT,     /* a whole number from 0 to 2^53 */
  VNUM,     /* any number */
  VNS,      /* a number or a string */
  VBOOL,
  VTIME,    /* YYYY-MM-DDTHH:MM:SSZ */
  VENUM,    /* one of the strings in sub */
  VFMT,     /* the string NQDFMT */
  VOBJ,     /* an object of kind sub */
  VARR,     /* an array of objects of kind sub */
  VSARR,    /* an array of strings */
  VNARR,    /* an array of numbers */
  VIARR,    /* an array of whole numbers */
  VPNI,     /* an array of [number, whole number] pairs */
  VPSI      /* an array of [string, whole number] pairs */
};

typedef struct dkind dkind;
typedef struct {
  const char *k;
  int t;
  int req;
  const void *sub;
  const char *akey; /* VARR: the member that keys the elements */
  int amode;        /* VARR: 1 sorted by akey, unique; 2 unique only */
} dfld;

struct dkind {
  const dfld *f;
  size_t nf;
  int (*extra)(const djs *o, char *why, size_t cap, const char *at);
};

#define N(a) (sizeof a / sizeof a[0])

static const char *const ekind[] = {"direct", "ckan", "socrata", "arcgis",
                                    "wayback", NULL};
static const char *const eschk[] = {"csv", NULL};
static const char *const etype[] = {"int", "real", "text", "date", "bool",
                                    NULL};
static const char *const erule[] = {"unique", "notnull", "range", "set",
                                    "rows", "cols", "incr", "complete",
                                    "distinct", NULL};
static const char *const estep[] = {"recode", "filter", "derive", "script",
                                    "other", NULL};
static const char *const estat[] = {"pass", "warn", "fail", NULL};
static const char *const ecmt[] = {"randomisation", "preregistration",
                                   "other", NULL};
static const char *const ealg[] = {"sha3-256", NULL};

static int xsch(const djs *o, char *why, size_t cap, const char *at);
static int xstc(const djs *o, char *why, size_t cap, const char *at);
static int xrule(const djs *o, char *why, size_t cap, const char *at);
static int xcol(const djs *o, char *why, size_t cap, const char *at);

static const dfld frng[] = {{"max", VINT, 0, NULL, NULL, 0},
                            {"min", VINT, 0, NULL, NULL, 0}};
static const dkind krng = {frng, N(frng), NULL};
static const dfld farc[] = {{"time", VTIME, 0, NULL, NULL, 0},
                            {"url", VSTR, 1, NULL, NULL, 0}};
static const dkind karc = {farc, N(farc), NULL};
static const dfld frslv[] = {{"base", VSTR, 0, NULL, NULL, 0},
                             {"format", VSTR, 0, NULL, NULL, 0},
                             {"id", VSTR, 0, NULL, NULL, 0},
                             {"kind", VENUM, 1, ekind, NULL, 0},
                             {"layer", VINT, 0, NULL, NULL, 0},
                             {"resource", VSTR, 0, NULL, NULL, 0}};
static const dkind krslv = {frslv, N(frslv), NULL};
static const dfld fsrc[] = {
    {"archived", VOBJ, 0, &karc, NULL, 0},
    {"etag", VSTR, 0, NULL, NULL, 0},
    {"licence", VSTR, 0, NULL, NULL, 0},
    {"mirrors", VSARR, 0, NULL, NULL, 0},
    {"modified", VSTR, 0, NULL, NULL, 0},
    {"path", VPATH, 1, NULL, NULL, 0},
    {"publisher", VSTR, 0, NULL, NULL, 0},
    {"resolver", VOBJ, 0, &krslv, NULL, 0},
    {"retrieved", VTIME, 0, NULL, NULL, 0},
    {"sha256", VHEX, 1, NULL, NULL, 0},
    {"size", VINT, 1, NULL, NULL, 0},
    {"synthetic", VBOOL, 0, NULL, NULL, 0},
    {"title", VSTR, 0, NULL, NULL, 0},
    {"url", VSTR, 0, NULL, NULL, 0}};
static const dkind ksrc = {fsrc, N(fsrc), NULL};
static const dfld fcol[] = {{"max", VNS, 0, NULL, NULL, 0},
                            {"min", VNS, 0, NULL, NULL, 0},
                            {"name", VSTR, 1, NULL, NULL, 0},
                            {"nulls", VBOOL, 0, NULL, NULL, 0},
                            {"set", VSARR, 0, NULL, NULL, 0},
                            {"type", VENUM, 1, etype, NULL, 0}};
static const dkind kcol = {fcol, N(fcol), xcol};
static const dfld frule[] = {{"col", VSTR, 0, NULL, NULL, 0},
                             {"cols", VSARR, 0, NULL, NULL, 0},
                             {"kind", VENUM, 1, erule, NULL, 0},
                             {"max", VNUM, 0, NULL, NULL, 0},
                             {"min", VNUM, 0, NULL, NULL, 0},
                             {"set", VSARR, 0, NULL, NULL, 0},
                             {"share", VNUM, 0, NULL, NULL, 0}};
static const dkind krule = {frule, N(frule), xrule};
static const dfld fsch[] = {{"columns", VARR, 0, &kcol, "name", 2},
                            {"delim", VSTR, 0, NULL, NULL, 0},
                            {"header", VBOOL, 0, NULL, NULL, 0},
                            {"kind", VENUM, 1, eschk, NULL, 0},
                            {"na", VSARR, 0, NULL, NULL, 0},
                            {"path", VPATH, 1, NULL, NULL, 0},
                            {"rows", VOBJ, 0, &krng, NULL, 0},
                            {"rules", VARR, 0, &krule, NULL, 0}};
static const dkind ksch = {fsch, N(fsch), xsch};
static const dfld fstc[] = {{"cats", VPSI, 0, NULL, NULL, 0},
                            {"counts", VIARR, 0, NULL, NULL, 0},
                            {"digits", VIARR, 0, NULL, NULL, 0},
                            {"edges", VNARR, 0, NULL, NULL, 0},
                            {"n", VINT, 1, NULL, NULL, 0},
                            {"name", VSTR, 1, NULL, NULL, 0},
                            {"nulls", VINT, 0, NULL, NULL, 0},
                            {"other", VINT, 0, NULL, NULL, 0},
                            {"q", VPNI, 0, NULL, NULL, 0}};
static const dkind kstc = {fstc, N(fstc), xstc};
static const dfld fst[] = {{"columns", VARR, 0, &kstc, "name", 2},
                           {"path", VPATH, 1, NULL, NULL, 0},
                           {"rows", VINT, 1, NULL, NULL, 0}};
static const dkind kst = {fst, N(fst), NULL};
static const dfld fpkg[] = {{"name", VSTR, 1, NULL, NULL, 0},
                            {"source", VSTR, 0, NULL, NULL, 0},
                            {"version", VSTR, 0, NULL, NULL, 0}};
static const dkind kpkg = {fpkg, N(fpkg), NULL};
static const dfld frt[] = {{"language", VSTR, 1, NULL, NULL, 0},
                           {"packages", VARR, 0, &kpkg, "name", 1},
                           {"version", VSTR, 0, NULL, NULL, 0}};
static const dkind krt = {frt, N(frt), NULL};
static const dfld flock[] = {{"path", VPATH, 1, NULL, NULL, 0},
                             {"sha256", VHEX, 1, NULL, NULL, 0}};
static const dkind klock = {flock, N(flock), NULL};
static const dfld frngk[] = {{"kind", VSTR, 1, NULL, NULL, 0},
                             {"seed", VNS, 0, NULL, NULL, 0}};
static const dkind krngk = {frngk, N(frngk), NULL};
static const dfld fenv[] = {{"arch", VSTR, 0, NULL, NULL, 0},
                            {"build", VSTR, 0, NULL, NULL, 0},
                            {"cpu", VSTR, 0, NULL, NULL, 0},
                            {"kernel", VSTR, 0, NULL, NULL, 0},
                            {"locale", VSTR, 0, NULL, NULL, 0},
                            {"locks", VARR, 0, &klock, "path", 1},
                            {"noqtis", VSTR, 0, NULL, NULL, 0},
                            {"os", VSTR, 0, NULL, NULL, 0},
                            {"rng", VOBJ, 0, &krngk, NULL, 0},
                            {"runtime", VOBJ, 0, &krt, NULL, 0},
                            {"tz", VSTR, 0, NULL, NULL, 0}};
static const dkind kenv = {fenv, N(fenv), NULL};
static const dfld fstep[] = {{"from", VSTR, 0, NULL, NULL, 0},
                             {"kind", VENUM, 1, estep, NULL, 0},
                             {"note", VSTR, 0, NULL, NULL, 0},
                             {"script", VPATH, 0, NULL, NULL, 0},
                             {"sha256", VHEX, 0, NULL, NULL, 0},
                             {"to", VSTR, 0, NULL, NULL, 0}};
static const dkind kstep = {fstep, N(fstep), NULL};
static const dfld fchk[] = {{"expected", VNS, 0, NULL, NULL, 0},
                            {"name", VSTR, 1, NULL, NULL, 0},
                            {"note", VSTR, 0, NULL, NULL, 0},
                            {"observed", VNS, 0, NULL, NULL, 0},
                            {"status", VENUM, 1, estat, NULL, 0},
                            {"tol", VNUM, 0, NULL, NULL, 0}};
static const dkind kchk = {fchk, N(fchk), NULL};
static const dfld fcmt[] = {{"after", VTIME, 0, NULL, NULL, 0},
                            {"alg", VENUM, 1, ealg, NULL, 0},
                            {"created", VTIME, 1, NULL, NULL, 0},
                            {"digest", VHEX, 1, NULL, NULL, 0},
                            {"kind", VENUM, 1, ecmt, NULL, 0},
                            {"label", VSTR, 0, NULL, NULL, 0}};
static const dkind kcmt = {fcmt, N(fcmt), NULL};
static const dfld fcite[] = {{"authors", VSARR, 0, NULL, NULL, 0},
                             {"doi", VSTR, 0, NULL, NULL, 0},
                             {"licence", VSTR, 0, NULL, NULL, 0},
                             {"title", VSTR, 1, NULL, NULL, 0},
                             {"url", VSTR, 0, NULL, NULL, 0},
                             {"version", VSTR, 0, NULL, NULL, 0},
                             {"year", VINT, 0, NULL, NULL, 0}};
static const dkind kcite = {fcite, N(fcite), NULL};
static const dfld frec[] = {{"checks", VARR, 0, &kchk, "name", 1},
                            {"cite", VOBJ, 0, &kcite, NULL, 0},
                            {"commits", VARR, 0, &kcmt, NULL, 0},
                            {"env", VOBJ, 0, &kenv, NULL, 0},
                            {"format", VFMT, 1, NULL, NULL, 0},
                            {"schemas", VARR, 0, &ksch, "path", 1},
                            {"sources", VARR, 0, &ksrc, "path", 1},
                            {"stats", VARR, 0, &kst, "path", 1},
                            {"steps", VARR, 0, &kstep, NULL, 0}};
static const dkind krec = {frec, N(frec), NULL};

/* ---- scalar checks ---- */

static int hex64(const djs *v) {
  size_t i;
  if (v->t != DJSTR || v->sl != 64)
    return 0;
  for (i = 0; i < 64; i++) {
    char c = v->s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
  }
  return 1;
}

static int digits(const char *s, int n, int lo, int hi) {
  int v = 0, i;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return -1;
    v = v * 10 + (s[i] - '0');
  }
  return v >= lo && v <= hi ? v : -1;
}

int qddate(const char *s, size_t n) {
  static const int md[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int y, m, d;
  if (n != 10 || s[4] != '-' || s[7] != '-')
    return 0;
  y = digits(s, 4, 0, 9999);
  m = digits(s + 5, 2, 1, 12);
  d = digits(s + 8, 2, 1, 31);
  if (y < 0 || m < 0 || d < 0 || d > md[m - 1])
    return 0;
  if (m == 2 && d == 29 && !((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
    return 0;
  return 1;
}

static int timeok(const djs *v) {
  const char *s = v->s;
  if (v->t != DJSTR || v->sl != 20 || !qddate(s, 10) || s[10] != 'T' ||
      s[13] != ':' || s[16] != ':' || s[19] != 'Z')
    return 0;
  return digits(s + 11, 2, 0, 23) >= 0 && digits(s + 14, 2, 0, 59) >= 0 &&
         digits(s + 17, 2, 0, 60) >= 0;
}

static int pathok(const djs *v) {
  char b[4200];
  static const char *const res[] = {"noqtis.json", "noqtis.sig",
                                    "noqtis.ers", NQDFILE};
  size_t i;
  if (v->t != DJSTR || qdjoin(".", v->s, b, sizeof b) != NQOK)
    return 0;
  for (i = 0; i < N(res); i++)
    if (strcmp(v->s, res[i]) == 0)
      return 0;
  return 1;
}

static int isint(const djs *v) {
  int64_t x;
  return qdjint(v, &x) && x >= 0;
}

/* every element of type t (DJSTR, DJNUM), or a count when t is 0 */
static int arrof(const djs *v, int t) {
  size_t i;
  if (v->t != DJARR)
    return 0;
  for (i = 0; i < v->n; i++) {
    if (t == 0 ? !isint(v->k[i]) : v->k[i]->t != t)
      return 0;
    if (t == DJSTR && v->k[i]->sl > 65536)
      return 0;
  }
  return 1;
}

static int pairs(const djs *v, int first) {
  size_t i;
  if (v->t != DJARR)
    return 0;
  for (i = 0; i < v->n; i++) {
    const djs *p = v->k[i];
    if (p->t != DJARR || p->n != 2 || p->k[0]->t != first ||
        !isint(p->k[1]))
      return 0;
  }
  return 1;
}

static const char *tname(int t) {
  switch (t) {
  case VSTR: return "a string";
  case VPATH:
    return "a capsule path (relative, '/' between folders, no '.' or "
           "'..', no backslash, colon or control character, not a noqtis "
           "file)";
  case VHEX: return "64 lower-case hex digits";
  case VINT: return "a whole number from 0 to 2^53";
  case VNUM: return "a number";
  case VNS: return "a number or a string";
  case VBOOL: return "true or false";
  case VTIME: return "a UTC time YYYY-MM-DDTHH:MM:SSZ";
  case VENUM: return "one of the names noqtis-data(5) lists";
  case VFMT: return "\"" NQDFMT "\"";
  case VOBJ: return "an object";
  case VARR: return "an array of objects";
  case VSARR: return "an array of strings";
  case VNARR: return "an array of numbers";
  case VIARR: return "an array of whole numbers";
  case VPNI: return "an array of [number, count] pairs";
  default: return "an array of [string, count] pairs";
  }
}

/* ---- arrays keyed by a member ---- */

static const char *keyof(const djs *e, const char *k) {
  const djs *v = qdjget(e, k);
  return v != NULL && v->t == DJSTR ? v->s : "";
}

/* stable merge sort of a->k by the string member k (byte order) */
static int ksort(djs *a, const char *k) {
  djs **t;
  size_t w, i;
  if (a->n < 2)
    return NQOK;
  t = (djs **)qdmal(a->n * sizeof *t);
  if (t == NULL)
    return NQEMEM;
  for (w = 1; w < a->n; w *= 2) {
    for (i = 0; i < a->n; i += 2 * w) {
      size_t lo = i, mid = i + w < a->n ? i + w : a->n,
             hi = i + 2 * w < a->n ? i + 2 * w : a->n, x = lo, y = mid,
             o = lo;
      while (x < mid && y < hi)
        t[o++] = strcmp(keyof(a->k[x], k), keyof(a->k[y], k)) <= 0
                     ? a->k[x++]
                     : a->k[y++];
      while (x < mid)
        t[o++] = a->k[x++];
      while (y < hi)
        t[o++] = a->k[y++];
    }
    memcpy(a->k, t, a->n * sizeof *t);
  }
  qdfree(t);
  return NQOK;
}

/* ---- objects ---- */

static int vobj(djs *o, const dkind *kd, int fix, char *why, size_t cap,
                const char *at);

static int vfield(djs *v, const dfld *f, int fix, char *why, size_t cap,
                  const char *at) {
  int ok = 1;
  size_t i;
  char sub[512];
  switch (f->t) {
  case VSTR: ok = v->t == DJSTR && v->sl <= 65536; break;
  case VPATH: ok = pathok(v); break;
  case VHEX: ok = hex64(v); break;
  case VINT: ok = isint(v); break;
  case VNUM: ok = v->t == DJNUM; break;
  case VNS: ok = v->t == DJNUM || (v->t == DJSTR && v->sl <= 65536); break;
  case VBOOL: ok = v->t == DJTRUE || v->t == DJFALSE; break;
  case VTIME: ok = timeok(v); break;
  case VFMT: ok = v->t == DJSTR && strcmp(v->s, NQDFMT) == 0; break;
  case VENUM: {
    const char *const *e = (const char *const *)f->sub;
    ok = 0;
    if (v->t == DJSTR)
      for (; *e != NULL && !ok; e++)
        ok = strcmp(*e, v->s) == 0;
    if (!ok) {
      dbuf b;
      memset(&b, 0, sizeof b);
      for (e = (const char *const *)f->sub; *e != NULL; e++) {
        qdbstr(&b, b.n ? ", " : "");
        qdbstr(&b, *e);
      }
      qdwhy(why, cap, "%s: must be one of %s", at, b.b != NULL ? b.b : "");
      qdbfree(&b);
      return NQEDEC;
    }
    break;
  }
  case VOBJ:
    if (v->t != DJOBJ)
      break;
    return vobj(v, (const dkind *)f->sub, fix, why, cap, at);
  case VARR:
    if (v->t != DJARR) {
      ok = 0;
      break;
    }
    if (v->n == 0) {
      /* one form for "none": the member left out */
      qdwhy(why, cap, "%s: empty: leave the member out instead", at);
      return NQEDEC;
    }
    for (i = 0; i < v->n; i++) {
      int rc;
      snprintf(sub, sizeof sub, "%.400s[%lu]", at, (unsigned long)i);
      if (v->k[i]->t != DJOBJ) {
        qdwhy(why, cap, "%s: must be an object", sub);
        return NQEDEC;
      }
      if ((rc = vobj(v->k[i], (const dkind *)f->sub, fix, why, cap, sub)) !=
          NQOK)
        return rc;
    }
    if (f->amode == 1 && fix && ksort(v, f->akey) != NQOK)
      return NQEMEM;
    for (i = 1; i < v->n && f->amode != 0; i++) {
      size_t j;
      const char *a = keyof(v->k[i], f->akey);
      if (f->amode == 1) {
        int c = strcmp(keyof(v->k[i - 1], f->akey), a);
        if (c >= 0) {
          qdwhy(why, cap,
               c == 0 ? "%s[%lu]: %s \"%s\" is there twice"
                      : "%s[%lu]: not sorted by %s (\"%s\" comes earlier)",
               at, (unsigned long)i, f->akey, a);
          return NQEDEC;
        }
      } else if (f->amode == 2) {
        for (j = 0; j < i; j++) {
          if (strcmp(keyof(v->k[j], f->akey), a) == 0) {
            qdwhy(why, cap, "%s[%lu]: %s \"%s\" is there twice", at,
                 (unsigned long)i, f->akey, a);
            return NQEDEC;
          }
        }
      }
    }
    return NQOK;
  case VSARR: ok = arrof(v, DJSTR); break;
  case VNARR: ok = arrof(v, DJNUM); break;
  case VIARR: ok = arrof(v, 0); break;
  case VPNI: ok = pairs(v, DJNUM); break;
  default: ok = pairs(v, DJSTR); break;
  }
  if (!ok) {
    qdwhy(why, cap, "%s: must be %s", at, tname(f->t));
    return NQEDEC;
  }
  return NQOK;
}

static int vobj(djs *o, const dkind *kd, int fix, char *why, size_t cap,
                const char *at) {
  size_t i, j;
  char sub[512];
  for (i = 0; i < o->n; i++) {
    const dfld *f = NULL;
    int rc;
    for (j = 0; j < kd->nf && f == NULL; j++)
      if (strcmp(kd->f[j].k, o->key[i]) == 0)
        f = &kd->f[j];
    snprintf(sub, sizeof sub, "%.400s%s%.80s", at, *at ? "." : "", o->key[i]);
    if (f == NULL) {
      qdwhy(why, cap,
           "%s: not a member of " NQDFMT " here (a misspelt name, or a "
           "record of a later format: remove it, or use a noqtis that "
           "reads that format)",
           sub);
      return NQEDEC;
    }
    if ((rc = vfield(o->k[i], f, fix, why, cap, sub)) != NQOK)
      return rc;
  }
  for (j = 0; j < kd->nf; j++) {
    if (kd->f[j].req && qdjget(o, kd->f[j].k) == NULL) {
      qdwhy(why, cap, "%s%s%s: required, and missing", at, *at ? "." : "",
           kd->f[j].k);
      return NQEDEC;
    }
  }
  return kd->extra != NULL ? kd->extra(o, why, cap, at) : NQOK;
}

/* ---- checks across members ---- */

static int xsch(const djs *o, char *why, size_t cap, const char *at) {
  const djs *d = qdjget(o, "delim");
  const djs *r = qdjget(o, "rows");
  if (d != NULL && (d->sl != 1 || d->s[0] == '"' || d->s[0] == '\r' ||
                    d->s[0] == '\n')) {
    qdwhy(why, cap,
         "%s.delim: one byte, not a quote or a line break (\",\", \";\", "
         "\"\\t\", \"|\")",
         at);
    return NQEDEC;
  }
  if (r != NULL) {
    int64_t lo = 0, hi = 0;
    if (qdjint(qdjget(r, "min"), &lo) && qdjint(qdjget(r, "max"), &hi) &&
        lo > hi) {
      qdwhy(why, cap, "%s.rows: min is above max", at);
      return NQEDEC;
    }
  }
  return NQOK;
}

static int xcol(const djs *o, char *why, size_t cap, const char *at) {
  const char *t = qdjget(o, "type")->s;
  const djs *mn = qdjget(o, "min"), *mx = qdjget(o, "max");
  int num = strcmp(t, "int") == 0 || strcmp(t, "real") == 0;
  int date = strcmp(t, "date") == 0;
  const djs *b[2];
  int i;
  b[0] = mn;
  b[1] = mx;
  for (i = 0; i < 2; i++) {
    if (b[i] == NULL)
      continue;
    if (!(num && b[i]->t == DJNUM) &&
        !(date && b[i]->t == DJSTR && qddate(b[i]->s, b[i]->sl))) {
      qdwhy(why, cap,
           "%s.%s: a number for an int or real column, a date "
           "YYYY-MM-DD for a date column, and none for text or bool",
           at, i ? "max" : "min");
      return NQEDEC;
    }
  }
  if (mn != NULL && mx != NULL &&
      (num ? mn->d > mx->d : strcmp(mn->s, mx->s) > 0)) {
    qdwhy(why, cap, "%s: min is above max", at);
    return NQEDEC;
  }
  if (qdjget(o, "set") != NULL && strcmp(t, "text") != 0) {
    qdwhy(why, cap, "%s.set: only a text column has a set of values", at);
    return NQEDEC;
  }
  return NQOK;
}

static int xrule(const djs *o, char *why, size_t cap, const char *at) {
  const char *k = qdjget(o, "kind")->s;
  const djs *col = qdjget(o, "col"), *cols = qdjget(o, "cols");
  const djs *mn = qdjget(o, "min"), *mx = qdjget(o, "max");
  const djs *set = qdjget(o, "set"), *sh = qdjget(o, "share");
  int tab = strcmp(k, "rows") == 0 || strcmp(k, "cols") == 0;
  if (tab ? (col != NULL || cols != NULL)
          : strcmp(k, "unique") == 0 ? (col == NULL) == (cols == NULL)
                                     : (col == NULL || cols != NULL)) {
    qdwhy(why, cap,
         "%s: a %s rule takes %s", at, k,
         tab ? "no col or cols"
             : strcmp(k, "unique") == 0 ? "col or cols (one of them)"
                                        : "col (and not cols)");
    return NQEDEC;
  }
  if ((strcmp(k, "range") == 0 || tab || strcmp(k, "distinct") == 0) &&
      mn == NULL && mx == NULL) {
    qdwhy(why, cap, "%s: a %s rule needs min, max or both", at, k);
    return NQEDEC;
  }
  if (mn != NULL && mx != NULL && mn->d > mx->d) {
    qdwhy(why, cap, "%s: min is above max", at);
    return NQEDEC;
  }
  if ((strcmp(k, "set") == 0) != (set != NULL)) {
    qdwhy(why, cap, "%s: set belongs to a set rule, which needs it", at);
    return NQEDEC;
  }
  if (strcmp(k, "complete") == 0
          ? sh == NULL || sh->d < 0 || sh->d > 1
          : sh != NULL) {
    qdwhy(why, cap,
         "%s: share (from 0 to 1) belongs to a complete rule, which needs "
         "it",
         at);
    return NQEDEC;
  }
  return NQOK;
}

static int xstc(const djs *o, char *why, size_t cap, const char *at) {
  const djs *q = qdjget(o, "q"), *e = qdjget(o, "edges");
  const djs *c = qdjget(o, "counts"), *d = qdjget(o, "digits");
  const djs *cats = qdjget(o, "cats");
  size_t i;
  if (q != NULL) {
    for (i = 1; i < q->n; i++) {
      if (q->k[i]->k[0]->d <= q->k[i - 1]->k[0]->d ||
          q->k[i]->k[1]->d <= q->k[i - 1]->k[1]->d) {
        qdwhy(why, cap,
             "%s.q[%lu]: values and counts must both increase", at,
             (unsigned long)i);
        return NQEDEC;
      }
    }
  }
  if (e != NULL) {
    for (i = 1; i < e->n; i++) {
      if (e->k[i]->d <= e->k[i - 1]->d) {
        qdwhy(why, cap, "%s.edges[%lu]: edges must increase", at,
             (unsigned long)i);
        return NQEDEC;
      }
    }
  }
  if ((e == NULL) != (c == NULL) ||
      (e != NULL && c->n != e->n + 1)) {
    qdwhy(why, cap, "%s: counts has one entry more than edges, and they "
                   "come together", at);
    return NQEDEC;
  }
  if (d != NULL && d->n != 9) {
    qdwhy(why, cap, "%s.digits: nine counts, for first digits 1 to 9", at);
    return NQEDEC;
  }
  if (cats != NULL) {
    for (i = 1; i < cats->n; i++) {
      const djs *a = cats->k[i - 1]->k[0], *b = cats->k[i]->k[0];
      if (strcmp(a->s, b->s) >= 0) {
        qdwhy(why, cap, "%s.cats[%lu]: sorted by value, each once", at,
             (unsigned long)i);
        return NQEDEC;
      }
    }
  }
  return NQOK;
}

int qdrecok(const djs *r, char *why, size_t cap) {
  if (r->t != DJOBJ) {
    qdwhy(why, cap, "a record is a JSON object");
    return NQEDEC;
  }
  return vobj((djs *)(uintptr_t)r, &krec, 0, why, cap, "");
}

static const dfld *member(const char *m) {
  size_t i;
  for (i = 0; i < N(frec); i++)
    if (strcmp(frec[i].k, m) == 0 && frec[i].t != VFMT)
      return &frec[i];
  return NULL;
}

int qdelemok(const char *m, const djs *e, char *why, size_t cap) {
  const dfld *f = member(m);
  if (f == NULL)
    return NQEARG;
  if (e->t != DJOBJ) {
    qdwhy(why, cap, "%s: an element is a JSON object", m);
    return NQEDEC;
  }
  return vobj((djs *)(uintptr_t)e, (const dkind *)f->sub, 1, why, cap, m);
}

/* ---- the API ---- */

struct nqdrec {
  djs *root;
};

int nqdnew(nqdrec **r) {
  nqdrec *n;
  if (r == NULL)
    return NQEARG;
  *r = NULL;
  n = (nqdrec *)qdmal(sizeof *n);
  if (n == NULL)
    return NQEMEM;
  n->root = qdjnew(DJOBJ);
  if (n->root == NULL || qdjset(n->root, "format", qdjstr(NQDFMT)) != NQOK) {
    qdjfree(n->root);
    qdfree(n);
    return NQEMEM;
  }
  *r = n;
  return NQOK;
}

static int parse(const char *json, size_t n, int fix, nqdrec **r, char *why,
                 size_t cap) {
  djs *v = NULL;
  int rc;
  nqdrec *x;
  if (r == NULL || (json == NULL && n))
    return NQEARG;
  *r = NULL;
  if (why != NULL && cap)
    why[0] = '\0';
  if (n > NQDMAX) {
    qdwhy(why, cap, "a record is at most 64 MiB");
    return NQELIM;
  }
  if ((rc = qdjparse(json, n, &v, why, cap)) != NQOK)
    return rc;
  if (v->t != DJOBJ) {
    qdjfree(v);
    qdwhy(why, cap, "a record is a JSON object");
    return NQEDEC;
  }
  if (qdjget(v, "format") == NULL || qdjget(v, "format")->t != DJSTR) {
    qdjfree(v);
    qdwhy(why, cap, "format: required: \"" NQDFMT "\"");
    return NQEDEC;
  }
  if (strcmp(qdjget(v, "format")->s, NQDFMT) != 0) {
    qdwhy(why, cap,
         "format: \"%s\" is not " NQDFMT " (a later format needs a later "
         "noqtis)",
         qdjget(v, "format")->s);
    qdjfree(v);
    return NQEDEC;
  }
  if ((rc = vobj(v, &krec, fix, why, cap, "")) != NQOK) {
    qdjfree(v);
    return rc;
  }
  x = (nqdrec *)qdmal(sizeof *x);
  if (x == NULL) {
    qdjfree(v);
    return NQEMEM;
  }
  x->root = v;
  *r = x;
  return NQOK;
}

int nqdparse(const char *json, size_t n, nqdrec **r, char *why, size_t cap) {
  return parse(json, n, 1, r, why, cap);
}

int nqdjson(const nqdrec *r, char *out, size_t cap, size_t *outlen) {
  dbuf b;
  int rc;
  if (r == NULL)
    return NQEARG;
  memset(&b, 0, sizeof b);
  qdjwrite(r->root, &b);
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}

int nqdload(const char *dir, nqdrec **r, char *why, size_t cap) {
  char p[4200], *buf;
  size_t n;
  int rc;
  dbuf b;
  if (r == NULL || dir == NULL)
    return NQEARG;
  *r = NULL;
  if ((size_t)snprintf(p, sizeof p, "%s/%s", dir, NQDFILE) >= sizeof p)
    return NQELIM;
  if ((rc = qdread(p, NQDMAX, &buf, &n)) != NQOK) {
    qdwhy(why, cap, rc == NQELIM ? NQDFILE " is over 64 MiB"
                                : NQDFILE " is missing or unreadable");
    return rc;
  }
  rc = parse(buf, n, 0, r, why, cap);
  if (rc == NQOK) {
    memset(&b, 0, sizeof b);
    qdjwrite((*r)->root, &b);
    if (b.err || b.n != n || memcmp(b.b, buf, n) != 0) {
      rc = b.err ? b.err : NQEDEC;
      qdwhy(why, cap,
           NQDFILE " is not in canonical form (edited by hand?): rewrite "
                   "it with `noqtis data fmt`");
      nqdrfree(*r);
      *r = NULL;
    }
    qdbfree(&b);
  }
  qdfree(buf);
  return rc;
}

int nqdsave(const nqdrec *r, const char *dir) {
  char p[4200];
  dbuf b;
  int rc;
  if (r == NULL || dir == NULL)
    return NQEARG;
  if ((size_t)snprintf(p, sizeof p, "%s/%s", dir, NQDFILE) >= sizeof p)
    return NQELIM;
  memset(&b, 0, sizeof b);
  qdjwrite(r->root, &b);
  rc = b.err ? b.err : qdwrite(p, b.b, b.n);
  qdbfree(&b);
  return rc;
}

void nqdrfree(nqdrec *r) {
  if (r != NULL) {
    qdjfree(r->root);
    qdfree(r);
  }
}

size_t nqdlen(const nqdrec *r, const char *member_) {
  const djs *v;
  if (r == NULL || member_ == NULL || member(member_) == NULL)
    return 0;
  v = qdjget(r->root, member_);
  if (v == NULL)
    return 0;
  return v->t == DJARR ? v->n : 1;
}

int nqdat(const nqdrec *r, const char *m, size_t i, char *out, size_t cap,
           size_t *outlen) {
  const djs *v;
  dbuf b;
  int rc;
  if (r == NULL || m == NULL || member(m) == NULL)
    return NQEARG;
  v = qdjget(r->root, m);
  if (v == NULL)
    return NQEIO;
  if (v->t == DJARR) {
    if (i >= v->n)
      return NQEIO;
    v = v->k[i];
  } else if (i != 0) {
    return NQEIO;
  }
  memset(&b, 0, sizeof b);
  qdjwrite(v, &b);
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}

int nqdkey(const nqdrec *r, const char *m, const char *key, char *out,
           size_t cap, size_t *outlen) {
  const dfld *f;
  const djs *a;
  size_t i;
  if (r == NULL || m == NULL || key == NULL || (f = member(m)) == NULL ||
      f->akey == NULL)
    return NQEARG;
  a = qdjget(r->root, m);
  for (i = 0; a != NULL && i < a->n; i++)
    if (strcmp(keyof(a->k[i], f->akey), key) == 0)
      return nqdat(r, m, i, out, cap, outlen);
  return NQEIO;
}

int nqdput(nqdrec *r, const char *m, const char *json, size_t n, char *why,
           size_t cap) {
  const dfld *f;
  djs *e = NULL, *a;
  int rc;
  size_t i;
  if (why != NULL && cap)
    why[0] = '\0';
  if (r == NULL || m == NULL || (json == NULL && n))
    return NQEARG;
  if ((f = member(m)) == NULL) {
    qdwhy(why, cap,
         "%s: not a member (sources, schemas, stats, steps, checks, "
         "commits, env, cite)",
         m);
    return NQEARG;
  }
  if (n > NQDMAX) {
    qdwhy(why, cap, "an element is at most 64 MiB");
    return NQELIM;
  }
  if ((rc = qdjparse(json, n, &e, why, cap)) != NQOK)
    return rc;
  if ((rc = qdelemok(m, e, why, cap)) != NQOK) {
    qdjfree(e);
    return rc;
  }
  if (f->t == VOBJ)
    return qdjset(r->root, m, e);
  a = qdjgetw(r->root, m);
  if (a == NULL) {
    if ((rc = qdjset(r->root, m, qdjnew(DJARR))) != NQOK) {
      qdjfree(e);
      return rc;
    }
    a = qdjgetw(r->root, m);
  }
  if (f->akey == NULL)
    return qdjadd(a, e);
  /* keyed: replace, or insert in order */
  {
    const char *k = keyof(e, f->akey);
    for (i = 0; i < a->n; i++) {
      int c = strcmp(keyof(a->k[i], f->akey), k);
      if (c == 0) {
        qdjfree(a->k[i]);
        a->k[i] = e;
        return NQOK;
      }
      if (c > 0)
        break;
    }
    if ((rc = qdjadd(a, e)) != NQOK)
      return rc;
    {
      size_t j;
      for (j = a->n - 1; j > i; j--)
        a->k[j] = a->k[j - 1];
      a->k[i] = e;
    }
  }
  return NQOK;
}

int nqddel(nqdrec *r, const char *m, const char *key) {
  const dfld *f;
  djs *a;
  size_t i;
  if (r == NULL || m == NULL || (f = member(m)) == NULL)
    return NQEARG;
  if (key == NULL)
    return qdjdel(r->root, m) ? NQOK : NQEIO;
  a = qdjgetw(r->root, m);
  if (a == NULL || f->akey == NULL)
    return a == NULL ? NQEIO : NQEARG;
  for (i = 0; i < a->n; i++) {
    if (strcmp(keyof(a->k[i], f->akey), key) == 0) {
      qdjrm(a, i);
      if (a->n == 0)
        qdjdel(r->root, m);
      return NQOK;
    }
  }
  return NQEIO;
}

/* the element of member m with key (NULL: the object member itself) */
static djs *find(nqdrec *r, const char *m, const char *key, size_t *at) {
  const dfld *f = member(m);
  djs *a = qdjgetw(r->root, m);
  size_t i;
  if (f == NULL || a == NULL)
    return NULL;
  if (f->t == VOBJ)
    return key == NULL ? a : NULL;
  if (key == NULL || f->akey == NULL)
    return NULL;
  for (i = 0; i < a->n; i++) {
    if (strcmp(keyof(a->k[i], f->akey), key) == 0) {
      *at = i;
      return a->k[i];
    }
  }
  return NULL;
}

int nqdset(nqdrec *r, const char *m, const char *key, const char *field,
           const char *json, size_t n, char *why, size_t cap) {
  const dfld *f;
  djs *e, *c, *v = NULL;
  size_t at = 0;
  int rc;
  if (why != NULL && cap)
    why[0] = '\0';
  if (r == NULL || m == NULL || field == NULL || (f = member(m)) == NULL)
    return NQEARG;
  if ((e = find(r, m, key, &at)) == NULL) {
    qdwhy(why, cap, "%s: no element %s", m, key != NULL ? key : "");
    return NQEIO;
  }
  if (f->akey != NULL && strcmp(field, f->akey) == 0) {
    qdwhy(why, cap, "%s: the key %s cannot be changed", m, f->akey);
    return NQEARG;
  }
  if (json != NULL && (rc = qdjparse(json, n, &v, why, cap)) != NQOK)
    return rc;
  if ((c = qdjcopy(e)) == NULL) {
    qdjfree(v);
    return NQEMEM;
  }
  if (v != NULL ? (rc = qdjset(c, field, v)) != NQOK : (qdjdel(c, field), 0)) {
    qdjfree(c);
    return rc;
  }
  if ((rc = qdelemok(m, c, why, cap)) != NQOK) {
    qdjfree(c);
    return rc;
  }
  if (f->t == VOBJ)
    return qdjset(r->root, m, c);
  qdjfree(e);
  qdjgetw(r->root, m)->k[at] = c;
  return NQOK;
}

int nqdsrc(nqdrec *r, const char *dir, const char *path, char *why,
           size_t cap) {
  char p[4200], hx[65];
  uint8_t h[32];
  uint64_t size;
  djs *pv, *o;
  size_t at = 0;
  dbuf b;
  int rc;
  if (why != NULL && cap)
    why[0] = '\0';
  if (r == NULL || path == NULL)
    return NQEARG;
  if ((pv = qdjstr(path)) == NULL)
    return NQEMEM;
  rc = pathok(pv) ? qdjoin(dir, path, p, sizeof p) : NQEARG;
  qdjfree(pv);
  if (rc != NQOK) {
    qdwhy(why, cap,
         "%s: not a path a capsule holds (relative, '/' between folders, "
         "no '.' or '..', not a noqtis file)",
         path);
    return rc;
  }
  if ((rc = qdsha(p, h, &size)) != NQOK) {
    qdwhy(why, cap, "%s: cannot be read", p);
    return rc;
  }
  qdhex(h, 32, hx);
  o = find(r, "sources", path, &at);
  o = o != NULL ? qdjcopy(o) : qdjnew(DJOBJ);
  if (o == NULL || qdjset(o, "path", qdjstr(path)) != NQOK ||
      qdjset(o, "sha256", qdjstr(hx)) != NQOK ||
      qdjset(o, "size", qdjnum((double)size)) != NQOK) {
    qdjfree(o);
    return NQEMEM;
  }
  memset(&b, 0, sizeof b);
  qdjwrite(o, &b);
  qdjfree(o);
  rc = b.err ? b.err : nqdput(r, "sources", b.b, b.n, why, cap);
  qdbfree(&b);
  return rc;
}

const djs *qdrectree(const nqdrec *r) {
  return r != NULL ? r->root : NULL;
}
