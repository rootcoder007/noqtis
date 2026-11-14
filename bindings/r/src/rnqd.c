/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The R interface to nqd, the data layer: .Call entry points over
 * nqd.h. Records and their elements go in and out as JSON text, so R
 * builds the same bytes as every other binding. Registered in rnq.c. */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

#include <string.h>

#include "nqd.h"

SEXP Cdload(SEXP dir);
SEXP Cdput(SEXP dir, SEXP member, SEXP json);
SEXP Cdadd(SEXP dir, SEXP paths, SEXP fields, SEXP vals);
SEXP Cddel(SEXP dir, SEXP member, SEXP key);
SEXP Cdkey(SEXP dir, SEXP member, SEXP key);
SEXP Cdchk(SEXP dir);
SEXP Cdinfer(SEXP dir, SEXP path, SEXP delim, SEXP noh, SEXP ranges);
SEXP Cdstats(SEXP dir, SEXP path, SEXP delim, SEXP noh);
SEXP Cddrift(SEXP stats, SEXP file, SEXP delim, SEXP noh, SEXP lv);
SEXP Cddiff(SEXP a, SEXP b);
SEXP Cdaddr(SEXP dir, SEXP path);
SEXP Cdvrfy(SEXP dir, SEXP path, SEXP raw);
SEXP Cdfld(SEXP dir, SEXP member, SEXP i, SEXP field);
SEXP Cdrslv(SEXP rslv);
SEXP Cdrsp(SEXP rslv, SEXP reply);
SEXP Cdwb(SEXP url);
SEXP Cdparse(SEXP text);
SEXP Cdschk(SEXP dir, SEXP schema);
SEXP Cdsyn(SEXP dir, SEXP path, SEXP seed, SEXP rows);
SEXP Cdcal(SEXP stats, SEXP files, SEXP delim, SEXP noh);
SEXP Cdchunk(SEXP dir, SEXP path, SEXP chunk);
SEXP Cdpiece(SEXP elem, SEXP piece, SEXP off);
SEXP Cdcommit(SEXP salt, SEXP m);
SEXP Cdreveal(SEXP dir, SEXP salt, SEXP m);
SEXP Cdcite(SEXP dir, SEXP fmt);
SEXP Cdrpt(SEXP dir, SEXP pk, SEXP fmt, SEXP sealed, SEXP hasrec);
SEXP Cdpack(SEXP dir, SEXP files, SEXP file);
SEXP Cdunpack(SEXP file, SEXP dir, SEXP rm);
SEXP Cdchain(SEXP dirs, SEXP pk);

static const char *s1(SEXP x, const char *what) {
  if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 || STRING_ELT(x, 0) == NA_STRING)
    Rf_error("'%s' must be one string", what);
  return Rf_translateCharUTF8(STRING_ELT(x, 0));
}

/* a path: UTF-8 on Windows, the native encoding elsewhere */
static const char *pth(SEXP x, const char *what) {
  if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 || STRING_ELT(x, 0) == NA_STRING)
    Rf_error("'%s' must be one path", what);
#if defined(_WIN32)
  return Rf_translateCharUTF8(STRING_ELT(x, 0));
#else
  return Rf_translateChar(STRING_ELT(x, 0));
#endif
}

static void dfail(int rc, const char *what, const char *why) {
  if (why != NULL && why[0] != '\0')
    Rf_error("noqtis: %s: %s", what, why);
  Rf_error("noqtis: %s: %s", what, nqerr(rc));
}

/* the record of dir, or a new one when there is none and mk; the
 * external pointer p frees it if R errors */
static void recfin(SEXP p) {
  nqdrec *r = (nqdrec *)R_ExternalPtrAddr(p);
  if (r != NULL) {
    nqdrfree(r);
    R_ClearExternalPtr(p);
  }
}

static nqdrec *rec(const char *d, int mk, SEXP p) {
  nqdrec *r = NULL;
  char why[600];
  int rc = nqdload(d, &r, why, sizeof why);
  if (rc == NQEIO && mk)
    rc = nqdnew(&r);
  if (rc != NQOK)
    dfail(rc, "the data record", why);
  R_SetExternalPtrAddr(p, r);
  return r;
}

static SEXP holder(void) {
  SEXP p = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, recfin, TRUE);
  return p;
}

/* a string the library writes with the two-call size pattern */
static SEXP jout(int (*f)(const nqdrec *, char *, size_t, size_t *),
                 const nqdrec *r) {
  size_t n = 0;
  char *b;
  int rc = f(r, NULL, 0, &n);
  if (rc != NQEBUF)
    dfail(rc, "the data record", NULL);
  b = R_alloc(n + 1, 1);
  if ((rc = f(r, b, n + 1, &n)) != NQOK)
    dfail(rc, "the data record", NULL);
  return Rf_mkCharLenCE(b, (int)n, CE_UTF8);
}

SEXP Cdload(SEXP dir) {
  SEXP p = holder(), out;
  nqdrec *r = rec(pth(dir, "dir"), 0, p);
  out = PROTECT(Rf_ScalarString(jout(nqdjson, r)));
  recfin(p);
  UNPROTECT(2);
  return out;
}

SEXP Cdput(SEXP dir, SEXP member, SEXP json) {
  const char *d = pth(dir, "dir"), *m = s1(member, "member");
  const char *j = s1(json, "json");
  char why[600];
  SEXP p = holder();
  nqdrec *r = rec(d, 1, p);
  int rc = nqdput(r, m, j, strlen(j), why, sizeof why);
  if (rc != NQOK)
    dfail(rc, m, why);
  if ((rc = nqdsave(r, d)) != NQOK)
    dfail(rc, "cannot write " NQDFILE, NULL);
  recfin(p);
  UNPROTECT(1);
  return R_NilValue;
}

/* each path a source, then fields[i] set to the JSON vals[i] */
SEXP Cdadd(SEXP dir, SEXP paths, SEXP fields, SEXP vals) {
  const char *d = pth(dir, "dir");
  char why[600];
  R_xlen_t i, k;
  SEXP p;
  nqdrec *r;
  int rc;
  if (TYPEOF(paths) != STRSXP || TYPEOF(fields) != STRSXP ||
      TYPEOF(vals) != STRSXP || XLENGTH(fields) != XLENGTH(vals))
    Rf_error("'files' must be paths, and each field have a value");
  p = holder();
  r = rec(d, 1, p);
  for (i = 0; i < XLENGTH(paths); i++) {
    const char *f;
    if (STRING_ELT(paths, i) == NA_STRING)
      Rf_error("'files' must not hold NA");
    f = Rf_translateCharUTF8(STRING_ELT(paths, i));
    if ((rc = nqdsrc(r, d, f, why, sizeof why)) != NQOK)
      dfail(rc, f, why);
    for (k = 0; k < XLENGTH(fields); k++) {
      const char *fl = Rf_translateCharUTF8(STRING_ELT(fields, k));
      const char *v = Rf_translateCharUTF8(STRING_ELT(vals, k));
      if ((rc = nqdset(r, "sources", f, fl, v, strlen(v), why,
                       sizeof why)) != NQOK)
        dfail(rc, fl, why);
    }
  }
  if ((rc = nqdsave(r, d)) != NQOK)
    dfail(rc, "cannot write " NQDFILE, NULL);
  recfin(p);
  UNPROTECT(1);
  return R_NilValue;
}

SEXP Cddel(SEXP dir, SEXP member, SEXP key) {
  const char *d = pth(dir, "dir"), *m = s1(member, "member");
  const char *k = key == R_NilValue ? NULL : s1(key, "key");
  SEXP p = holder();
  nqdrec *r = rec(d, 0, p);
  int rc = nqddel(r, m, k);
  if (rc == NQEIO)
    Rf_error("noqtis: the record has no %s %s", m, k != NULL ? k : "");
  if (rc != NQOK)
    dfail(rc, m, NULL);
  if ((rc = nqdsave(r, d)) != NQOK)
    dfail(rc, "cannot write " NQDFILE, NULL);
  recfin(p);
  UNPROTECT(1);
  return R_NilValue;
}

/* the element of member with key as JSON, or NULL when there is none */
SEXP Cdkey(SEXP dir, SEXP member, SEXP key) {
  const char *m = s1(member, "member"), *k = s1(key, "key");
  SEXP p = holder(), out = R_NilValue;
  nqdrec *r = rec(pth(dir, "dir"), 0, p);
  size_t n = 0;
  int rc = nqdkey(r, m, k, NULL, 0, &n);
  if (rc == NQEBUF) {
    char *b = R_alloc(n + 1, 1);
    if ((rc = nqdkey(r, m, k, b, n + 1, &n)) != NQOK)
      dfail(rc, m, NULL);
    out = Rf_mkString(b);
  } else if (rc != NQEIO) {
    dfail(rc, m, NULL);
  }
  PROTECT(out);
  recfin(p);
  UNPROTECT(2);
  return out;
}

static void repfin(SEXP p) {
  nqdrep *r = (nqdrep *)R_ExternalPtrAddr(p);
  if (r != NULL) {
    nqdrepfree(r);
    R_ClearExternalPtr(p);
  }
}

/* list(rc, check, ok, detail, json) of a report, freed here; held by an
 * external pointer while R allocates, so an error cannot leak it */
static SEXP drep(int rc, nqdrep *r) {
  size_t n, i;
  SEXP out, ck, ok, dt, js, p;
  if (r == NULL)
    dfail(rc, "check", NULL);
  p = PROTECT(R_MakeExternalPtr(r, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, repfin, TRUE);
  n = nqdrepn(r);
  out = PROTECT(Rf_allocVector(VECSXP, 5));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  ck = Rf_allocVector(STRSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 1, ck);
  ok = Rf_allocVector(LGLSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 2, ok);
  dt = Rf_allocVector(STRSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 3, dt);
  js = Rf_allocVector(STRSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 4, js);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL, *j = nqdrepj(r, i);
    int o = 0;
    nqdrepi(r, i, &c, &o, &d);
    SET_STRING_ELT(ck, (R_xlen_t)i, Rf_mkCharCE(c ? c : "", CE_UTF8));
    LOGICAL(ok)[i] = o != 0;
    SET_STRING_ELT(dt, (R_xlen_t)i, Rf_mkCharCE(d ? d : "", CE_UTF8));
    SET_STRING_ELT(js, (R_xlen_t)i,
                   j != NULL ? Rf_mkCharCE(j, CE_UTF8) : NA_STRING);
  }
  repfin(p);
  UNPROTECT(2);
  return out;
}

SEXP Cdchk(SEXP dir) {
  nqdrep *r = NULL;
  int rc = nqdchk(pth(dir, "dir"), &r);
  return drep(rc, r);
}

static void csvo(nqdcsvopt *o, SEXP delim, SEXP noh, SEXP ranges) {
  const char *dl = s1(delim, "delim");
  memset(o, 0, sizeof *o);
  if (strlen(dl) != 1)
    Rf_error("'delim' must be one byte");
  o->delim = dl[0];
  o->noheader = Rf_asLogical(noh) == 1;
  o->ranges = ranges != R_NilValue && Rf_asLogical(ranges) == 1;
}

/* f writes JSON for dir/path with the two-call size pattern */
typedef int (*jfn)(const char *, const char *, const nqdcsvopt *, char *,
                   size_t, size_t *, char *, size_t);

static SEXP jfile(jfn f, SEXP dir, SEXP path, const nqdcsvopt *o) {
  const char *d = pth(dir, "dir"), *pa = s1(path, "file");
  char why[600], *b;
  size_t n = 0;
  int rc = f(d, pa, o, NULL, 0, &n, why, sizeof why);
  if (rc != NQEBUF)
    dfail(rc, pa, why);
  b = R_alloc(n + 1, 1);
  if ((rc = f(d, pa, o, b, n + 1, &n, why, sizeof why)) != NQOK)
    dfail(rc, pa, why);
  return Rf_mkString(b);
}

SEXP Cdinfer(SEXP dir, SEXP path, SEXP delim, SEXP noh, SEXP ranges) {
  nqdcsvopt o;
  csvo(&o, delim, noh, ranges);
  return jfile(nqdinfer, dir, path, &o);
}

SEXP Cdstats(SEXP dir, SEXP path, SEXP delim, SEXP noh) {
  nqdcsvopt o;
  csvo(&o, delim, noh, R_NilValue);
  return jfile(nqdstats, dir, path, &o);
}

/* lv: c(psiwarn, psifail, alpha, minn, benford) */
SEXP Cddrift(SEXP stats, SEXP file, SEXP delim, SEXP noh, SEXP lv) {
  const char *s = s1(stats, "stats");
  nqdcsvopt o;
  nqddopt d;
  nqdrep *r = NULL;
  int rc;
  if (TYPEOF(lv) != REALSXP || XLENGTH(lv) != 5)
    Rf_error("the drift levels must be five numbers");
  csvo(&o, delim, noh, R_NilValue);
  d.psiwarn = REAL(lv)[0];
  d.psifail = REAL(lv)[1];
  d.alpha = REAL(lv)[2];
  d.minn = REAL(lv)[3];
  d.benford = REAL(lv)[4] != 0;
  rc = nqddrift(s, strlen(s), pth(file, "current"), &o, &d, &r);
  return drep(rc, r);
}

SEXP Cddiff(SEXP a, SEXP b) {
  nqdrep *r = NULL;
  const char *x = pth(a, "a"), *y = pth(b, "b");
  int rc = nqddiff(x, y, &r);
  return drep(rc, r);
}

/* ---- sources (nqdaddr(3)) ---- */

/* list(kind, url) of the source path's addresses; none for a synthetic
 * one */
SEXP Cdaddr(SEXP dir, SEXP path) {
  const char *f = s1(path, "file");
  SEXP p = holder(), out, k, u;
  nqdrec *r = rec(pth(dir, "dir"), 0, p);
  size_t i, c = 0;
  char b[4400];
  for (;; c++) {
    size_t n = 0;
    int rc = nqdaddr(r, f, c, NULL, b, sizeof b, &n);
    if (rc == NQEARG || (rc == NQEIO && c > 0)) break;
    if (rc != NQOK) dfail(rc, f, NULL);
  }
  k = PROTECT(Rf_allocVector(INTSXP, (R_xlen_t)c));
  u = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t)c));
  for (i = 0; i < c; i++) {
    size_t n = 0;
    int kd = 0;
    if (nqdaddr(r, f, i, &kd, b, sizeof b, &n) != NQOK)
      dfail(NQEIO, f, NULL);
    INTEGER(k)[i] = kd;
    SET_STRING_ELT(u, (R_xlen_t)i, Rf_mkCharLenCE(b, (int)n, CE_UTF8));
  }
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, k);
  SET_VECTOR_ELT(out, 1, u);
  recfin(p);
  UNPROTECT(4);
  return out;
}

SEXP Cdvrfy(SEXP dir, SEXP path, SEXP raw) {
  const char *f = s1(path, "file");
  SEXP p = holder();
  nqdrec *r = rec(pth(dir, "dir"), 0, p);
  int rc;
  if (TYPEOF(raw) != RAWSXP) Rf_error("'bytes' must be a raw vector");
  rc = nqdvrfy(r, f, RAW(raw), (size_t)XLENGTH(raw));
  recfin(p);
  UNPROTECT(1);
  if (rc != NQOK && rc != NQEVRFY) dfail(rc, f, NULL);
  return Rf_ScalarLogical(rc == NQOK);
}

SEXP Cdfld(SEXP dir, SEXP member, SEXP i, SEXP field) {
  const char *m = s1(member, "member"), *f = s1(field, "field");
  SEXP p = holder(), out = R_NilValue;
  nqdrec *r = rec(pth(dir, "dir"), 0, p);
  double x = Rf_asReal(i);
  size_t n = 0;
  int rc;
  if (!(x >= 0 && x < 9e15)) Rf_error("'i' must be a count");
  rc = nqdfld(r, m, (size_t)x, f, NULL, 0, &n);
  if (rc == NQEBUF) {
    char *b = R_alloc(n + 1, 1);
    if ((rc = nqdfld(r, m, (size_t)x, f, b, n + 1, &n)) != NQOK)
      dfail(rc, m, NULL);
    out = Rf_ScalarString(Rf_mkCharLenCE(b, (int)n, CE_UTF8));
  } else if (rc != NQEIO) {
    dfail(rc, m, NULL);
  }
  PROTECT(out);
  recfin(p);
  UNPROTECT(2);
  return out;
}

SEXP Cdrslv(SEXP rslv) {
  const char *j = s1(rslv, "resolver");
  char b[4400], why[600];
  size_t n = 0;
  int rc;
  why[0] = '\0';
  if ((rc = nqdrslv(j, strlen(j), b, sizeof b, &n, why, sizeof why)) != NQOK)
    dfail(rc, "the resolver", why);
  return Rf_ScalarString(Rf_mkCharLenCE(b, (int)n, CE_UTF8));
}

SEXP Cdrsp(SEXP rslv, SEXP reply) {
  const char *j = s1(rslv, "resolver");
  char b[4400], why[600], tm[21];
  size_t n = 0;
  int rc;
  SEXP out;
  if (TYPEOF(reply) != RAWSXP) Rf_error("'reply' must be a raw vector");
  why[0] = '\0';
  rc = nqdrsp(j, strlen(j), (const char *)RAW(reply), (size_t)XLENGTH(reply),
              b, sizeof b, &n, tm, why, sizeof why);
  if (rc != NQOK) dfail(rc, "the reply", why);
  out = PROTECT(Rf_allocVector(STRSXP, 2));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE(b, (int)n, CE_UTF8));
  SET_STRING_ELT(out, 1, Rf_mkChar(tm));
  UNPROTECT(1);
  return out;
}

SEXP Cdwb(SEXP url) {
  char b[4400];
  size_t n = 0;
  int rc = nqdwb(s1(url, "url"), b, sizeof b, &n);
  if (rc != NQOK) dfail(rc, "the address", NULL);
  return Rf_ScalarString(Rf_mkCharLenCE(b, (int)n, CE_UTF8));
}

/* ---- the rest of nqd.h --------------------------------------------- */

/* the canonical text of a record's JSON text */
SEXP Cdparse(SEXP text) {
  const char *t = s1(text, "json");
  nqdrec *r = NULL;
  char why[600];
  SEXP p, out;
  int rc;
  why[0] = '\0';
  rc = nqdparse(t, strlen(t), &r, why, sizeof why);
  if (rc != NQOK) dfail(rc, "the record", why);
  p = PROTECT(R_MakeExternalPtr(r, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, recfin, TRUE);
  out = PROTECT(Rf_ScalarString(jout(nqdjson, r)));
  recfin(p);
  UNPROTECT(2);
  return out;
}

SEXP Cdschk(SEXP dir, SEXP schema) {
  const char *s = s1(schema, "schema");
  nqdrep *r = NULL;
  int rc = nqdschk(pth(dir, "dir"), s, strlen(s), &r);
  return drep(rc, r);
}

/* the stand-in written and recorded */
SEXP Cdsyn(SEXP dir, SEXP path, SEXP seed, SEXP rows) {
  const char *d = pth(dir, "dir"), *pa = s1(path, "file");
  char why[600];
  SEXP p;
  nqdrec *r;
  int rc;
  if (TYPEOF(seed) != REALSXP || TYPEOF(rows) != REALSXP)
    Rf_error("'seed' and 'rows' must be numbers");
  p = holder();
  r = rec(d, 0, p);
  why[0] = '\0';
  rc = nqdsyn(r, d, pa, (uint64_t)REAL(seed)[0], (uint64_t)REAL(rows)[0], why,
              sizeof why);
  if (rc != NQOK) dfail(rc, pa, why);
  if ((rc = nqdsave(r, d)) != NQOK) dfail(rc, "the data record", NULL);
  recfin(p);
  UNPROTECT(1);
  return R_NilValue;
}

SEXP Cdcal(SEXP stats, SEXP files, SEXP delim, SEXP noh) {
  const char *s = s1(stats, "stats"), **fs;
  nqdcsvopt o;
  char why[600], *b;
  size_t n = 0, k, i;
  int rc;
  if (TYPEOF(files) != STRSXP || XLENGTH(files) == 0)
    Rf_error("'known' must name files");
  k = (size_t)XLENGTH(files);
  fs = (const char **)R_alloc(k, sizeof *fs);
  for (i = 0; i < k; i++) {
    if (STRING_ELT(files, (R_xlen_t)i) == NA_STRING)
      Rf_error("'known' must not hold NA");
#if defined(_WIN32)
    fs[i] = Rf_translateCharUTF8(STRING_ELT(files, (R_xlen_t)i));
#else
    fs[i] = Rf_translateChar(STRING_ELT(files, (R_xlen_t)i));
#endif
  }
  csvo(&o, delim, noh, R_NilValue);
  why[0] = '\0';
  rc = nqddcal(s, strlen(s), fs, k, &o, NULL, 0, &n, why, sizeof why);
  if (rc != NQEBUF) dfail(rc, "calibration", why);
  b = R_alloc(n + 1, 1);
  rc = nqddcal(s, strlen(s), fs, k, &o, b, n + 1, &n, why, sizeof why);
  if (rc != NQOK) dfail(rc, "calibration", why);
  return Rf_mkString(b);
}

SEXP Cdchunk(SEXP dir, SEXP path, SEXP chunk) {
  const char *d = pth(dir, "dir"), *pa = s1(path, "file");
  char why[600], *b;
  size_t n = 0;
  uint64_t ch;
  int rc;
  if (TYPEOF(chunk) != REALSXP || XLENGTH(chunk) != 1)
    Rf_error("'chunk' must be one number");
  ch = (uint64_t)REAL(chunk)[0];
  why[0] = '\0';
  rc = nqdchunk(d, pa, ch, NULL, 0, &n, why, sizeof why);
  if (rc != NQEBUF) dfail(rc, pa, why);
  b = R_alloc(n + 1, 1);
  if ((rc = nqdchunk(d, pa, ch, b, n + 1, &n, why, sizeof why)) != NQOK)
    dfail(rc, pa, why);
  return Rf_mkString(b);
}

SEXP Cdpiece(SEXP elem, SEXP piece, SEXP off) {
  const char *e = s1(elem, "chunks");
  nqdrep *r = NULL;
  int rc;
  if (TYPEOF(off) != REALSXP || XLENGTH(off) != 1)
    Rf_error("'off' must be one number");
  rc = nqdpiece(e, strlen(e), pth(piece, "piece"), (uint64_t)REAL(off)[0],
                &r);
  return drep(rc, r);
}

SEXP Cdcommit(SEXP salt, SEXP m) {
  char hx[65];
  int rc;
  if (TYPEOF(salt) != RAWSXP || TYPEOF(m) != RAWSXP)
    Rf_error("'salt' and the content must be raw vectors");
  rc = nqdcommit(XLENGTH(salt) ? RAW(salt) : NULL, (size_t)XLENGTH(salt),
                 XLENGTH(m) ? RAW(m) : NULL, (size_t)XLENGTH(m), hx);
  if (rc != NQOK) dfail(rc, "the commitment", NULL);
  return Rf_mkString(hx);
}

/* the index (from 0) of the matching commitment, or NA */
SEXP Cdreveal(SEXP dir, SEXP salt, SEXP m) {
  SEXP p;
  nqdrec *r;
  size_t i = 0;
  int rc;
  if (TYPEOF(salt) != RAWSXP || TYPEOF(m) != RAWSXP)
    Rf_error("'salt' and the content must be raw vectors");
  p = holder();
  r = rec(pth(dir, "dir"), 0, p);
  rc = nqdreveal(r, XLENGTH(salt) ? RAW(salt) : NULL, (size_t)XLENGTH(salt),
                 XLENGTH(m) ? RAW(m) : NULL, (size_t)XLENGTH(m), &i);
  recfin(p);
  UNPROTECT(1);
  if (rc == NQEVRFY) return Rf_ScalarInteger(NA_INTEGER);
  if (rc != NQOK) dfail(rc, "the reveal", NULL);
  return Rf_ScalarInteger((int)i);
}

SEXP Cdcite(SEXP dir, SEXP fmt) {
  SEXP p;
  nqdrec *r;
  char *b;
  size_t n = 0;
  int f = Rf_asInteger(fmt), rc;
  p = holder();
  r = rec(pth(dir, "dir"), 0, p);
  rc = nqdcite(r, f, NULL, 0, &n);
  if (rc != NQEBUF) dfail(rc, "the citation", NULL);
  b = R_alloc(n + 1, 1);
  if ((rc = nqdcite(r, f, b, n + 1, &n)) != NQOK)
    dfail(rc, "the citation", NULL);
  recfin(p);
  UNPROTECT(1);
  return Rf_ScalarString(Rf_mkCharLenCE(b, (int)n, CE_UTF8));
}

static void crfin(SEXP p) {
  nqrep *r = (nqrep *)R_ExternalPtrAddr(p);
  if (r != NULL) {
    nqrepfree(r);
    R_ClearExternalPtr(p);
  }
}

/* the report: the capsule checked (nqchkx, with pk) when sealed, the
 * record (nqdchk) when there is one */
SEXP Cdrpt(SEXP dir, SEXP pk, SEXP fmt, SEXP sealed, SEXP hasrec) {
  const char *d = pth(dir, "dir");
  nqcopt o;
  nqrep *cr = NULL;
  nqdrep *dr = NULL;
  SEXP pc, pd;
  char *b;
  size_t n = 0;
  int f = Rf_asInteger(fmt), rc;
  memset(&o, 0, sizeof o);
  if (pk != R_NilValue) {
    if (TYPEOF(pk) != RAWSXP) Rf_error("'pk' must be a raw vector");
    o.trust = XLENGTH(pk) ? RAW(pk) : NULL;
    o.trustlen = (size_t)XLENGTH(pk);
  }
  pc = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(pc, crfin, TRUE);
  pd = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(pd, repfin, TRUE);
  if (Rf_asLogical(sealed)) {
    rc = nqchkx(d, &o, &cr);
    if (cr == NULL) dfail(rc, "the capsule", NULL);
    R_SetExternalPtrAddr(pc, cr);
  }
  if (Rf_asLogical(hasrec)) {
    rc = nqdchk(d, &dr);
    if (dr == NULL) dfail(rc, "the data record", NULL);
    R_SetExternalPtrAddr(pd, dr);
  }
  rc = nqdrpt(d, cr, dr, f, NULL, 0, &n);
  if (rc != NQEBUF) dfail(rc, "the report", NULL);
  b = R_alloc(n + 1, 1);
  if ((rc = nqdrpt(d, cr, dr, f, b, n + 1, &n)) != NQOK)
    dfail(rc, "the report", NULL);
  crfin(pc);
  repfin(pd);
  UNPROTECT(2);
  return Rf_ScalarString(Rf_mkCharLenCE(b, (int)n, CE_UTF8));
}

SEXP Cdpack(SEXP dir, SEXP files, SEXP file) {
  int rc = nqdpack(pth(dir, "dir"), Rf_asLogical(files), pth(file, "file"));
  if (rc != NQOK) dfail(rc, "the bundle", NULL);
  return R_NilValue;
}

SEXP Cdunpack(SEXP file, SEXP dir, SEXP rm) {
  char why[600];
  int rc;
  why[0] = '\0';
  rc = nqdunpack(pth(file, "file"), pth(dir, "dir"), Rf_asLogical(rm), why,
                 sizeof why);
  if (rc != NQOK) dfail(rc, "the bundle", why);
  return R_NilValue;
}

/* list(report, head) */
SEXP Cdchain(SEXP dirs, SEXP pk) {
  const char **ds;
  size_t k, i;
  nqcopt o;
  uint8_t head[32];
  nqdrep *r = NULL;
  SEXP out, rep, h;
  int rc;
  if (TYPEOF(dirs) != STRSXP || XLENGTH(dirs) == 0)
    Rf_error("'dirs' must name capsule folders");
  k = (size_t)XLENGTH(dirs);
  ds = (const char **)R_alloc(k, sizeof *ds);
  for (i = 0; i < k; i++) {
    if (STRING_ELT(dirs, (R_xlen_t)i) == NA_STRING)
      Rf_error("'dirs' must not hold NA");
#if defined(_WIN32)
    ds[i] = Rf_translateCharUTF8(STRING_ELT(dirs, (R_xlen_t)i));
#else
    ds[i] = Rf_translateChar(STRING_ELT(dirs, (R_xlen_t)i));
#endif
  }
  memset(&o, 0, sizeof o);
  if (pk != R_NilValue) {
    if (TYPEOF(pk) != RAWSXP) Rf_error("'pk' must be a raw vector");
    o.trust = XLENGTH(pk) ? RAW(pk) : NULL;
    o.trustlen = (size_t)XLENGTH(pk);
  }
  memset(head, 0, sizeof head);
  rc = nqdchain(ds, k, &o, head, &r);
  rep = PROTECT(drep(rc, r));
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, rep);
  h = Rf_allocVector(RAWSXP, 32);
  SET_VECTOR_ELT(out, 1, h);
  memcpy(RAW(h), head, 32);
  UNPROTECT(2);
  return out;
}
