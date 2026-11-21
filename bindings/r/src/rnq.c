/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The R interface to noqtis: .Call entry points over the public API in
 * noqtis.h. Raw vectors in and out; every output vector is allocated by R
 * and written by the library in place, so the glue keeps no buffer of its
 * own and an R error never leaks memory. Randomness comes from nqrand()
 * (the operating system's CSPRNG), never from R's random number generator.
 */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <string.h>

#include "noqtis.h"

/* NULL for an empty vector, so the library never sees R's placeholder
 * pointer for zero-length data. */
static const uint8_t *rp(SEXP x) {
  if (x == R_NilValue || XLENGTH(x) == 0) return NULL;
  return (const uint8_t *)RAW(x);
}

static size_t rn(SEXP x) {
  return x == R_NilValue ? 0 : (size_t)XLENGTH(x);
}

static void chkraw(SEXP x, const char *what, int null) {
  if (null && x == R_NilValue) return;
  if (TYPEOF(x) != RAWSXP) Rf_error("'%s' must be a raw vector", what);
}

static int ival(SEXP x, const char *what) {
  if (TYPEOF(x) != INTSXP || XLENGTH(x) != 1 || INTEGER(x)[0] == NA_INTEGER)
    Rf_error("'%s' must be one integer", what);
  return INTEGER(x)[0];
}

NORET static void fail(int rc, const char *what) {
  Rf_error("noqtis: %s: %s", what, nqerr(rc));
}

static SEXP rawn(size_t n) {
  return Rf_allocVector(RAWSXP, (R_xlen_t)n);
}

/* A file path in the encoding the library expects: UTF-8 on Windows (it
 * converts to UTF-16 there), the native encoding elsewhere. */
static const char *rpath(SEXP x) {
  if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 || STRING_ELT(x, 0) == NA_STRING)
    Rf_error("'dir' must be one path");
#if defined(_WIN32)
  return Rf_translateCharUTF8(STRING_ELT(x, 0));
#else
  return Rf_translateChar(STRING_ELT(x, 0));
#endif
}

/* ---- algorithms ---------------------------------------------------- */

static SEXP Cver(void) { return Rf_mkString(nqver()); }

static SEXP Cself(void) {
  int rc = nqselftest();
  if (rc != NQOK) fail(rc, "self-test");
  return Rf_ScalarLogical(1);
}

/* list(kind, id, name, pk, sk, sig, ct, ss) over every algorithm */
static SEXP Calgs(void) {
  int ns = 0, nk = 0, i, j;
  SEXP kind, id, name, pk, sk, sig, ct, ss, out;
  nqssz s;
  nqksz k;
  for (i = 1; nqsname((nqsalg)i) != NULL; i++) ns++;
  for (i = 1; nqkname((nqkalg)i) != NULL; i++) nk++;
  out = PROTECT(Rf_allocVector(VECSXP, 8));
  kind = Rf_allocVector(STRSXP, ns + nk);
  SET_VECTOR_ELT(out, 0, kind);
  id = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 1, id);
  name = Rf_allocVector(STRSXP, ns + nk);
  SET_VECTOR_ELT(out, 2, name);
  pk = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 3, pk);
  sk = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 4, sk);
  sig = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 5, sig);
  ct = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 6, ct);
  ss = Rf_allocVector(INTSXP, ns + nk);
  SET_VECTOR_ELT(out, 7, ss);
  for (i = 0; i < ns; i++) {
    if (nqssize((nqsalg)(i + 1), &s) != NQOK) fail(NQEARG, "nqssize");
    SET_STRING_ELT(kind, i, Rf_mkChar("sig"));
    INTEGER(id)[i] = i + 1;
    SET_STRING_ELT(name, i, Rf_mkChar(nqsname((nqsalg)(i + 1))));
    INTEGER(pk)[i] = (int)s.pk;
    INTEGER(sk)[i] = (int)s.sk;
    INTEGER(sig)[i] = (int)s.sig;
    INTEGER(ct)[i] = NA_INTEGER;
    INTEGER(ss)[i] = NA_INTEGER;
  }
  for (j = 0; j < nk; j++) {
    i = ns + j;
    if (nqksize((nqkalg)(j + 1), &k) != NQOK) fail(NQEARG, "nqksize");
    SET_STRING_ELT(kind, i, Rf_mkChar("kem"));
    INTEGER(id)[i] = j + 1;
    SET_STRING_ELT(name, i, Rf_mkChar(nqkname((nqkalg)(j + 1))));
    INTEGER(pk)[i] = (int)k.pk;
    INTEGER(sk)[i] = (int)k.sk;
    INTEGER(sig)[i] = NA_INTEGER;
    INTEGER(ct)[i] = (int)k.ct;
    INTEGER(ss)[i] = (int)k.ss;
  }
  UNPROTECT(1);
  return out;
}

/* ---- randomness ---------------------------------------------------- */

static SEXP Crand(SEXP n) {
  int len = ival(n, "n"), rc;
  SEXP out;
  if (len < 0) Rf_error("'n' must not be negative");
  out = PROTECT(rawn((size_t)len));
  rc = nqrand(len > 0 ? RAW(out) : NULL, (size_t)len);
  if (rc != NQOK) fail(rc, "nqrand");
  UNPROTECT(1);
  return out;
}

/* ---- hashes -------------------------------------------------------- */

static SEXP Chash(SEXP alg, SEXP x, SEXP len) {
  int a = ival(alg, "alg"), n = ival(len, "len"), rc;
  SEXP out;
  chkraw(x, "x", 0);
  if (n < 0) Rf_error("'len' must not be negative");
  out = PROTECT(rawn((size_t)n));
  rc = nqhash((nqhalg)a, rp(x), rn(x), n > 0 ? RAW(out) : NULL, (size_t)n);
  if (rc != NQOK) fail(rc, "nqhash");
  UNPROTECT(1);
  return out;
}

/* The streaming context lives in a raw vector of sizeof(nqhctx) bytes;
 * every step returns a fresh copy, so no R object is changed in place. */
static SEXP Chini(SEXP alg) {
  int rc;
  SEXP out = PROTECT(rawn(sizeof(nqhctx)));
  nqhctx c;
  rc = nqhini(&c, (nqhalg)ival(alg, "alg"));
  if (rc != NQOK) fail(rc, "nqhini");
  memcpy(RAW(out), &c, sizeof c);
  nqwipe(&c, sizeof c);
  UNPROTECT(1);
  return out;
}

static void getctx(SEXP ctx, nqhctx *c) {
  chkraw(ctx, "ctx", 0);
  if (XLENGTH(ctx) != (R_xlen_t)sizeof *c) Rf_error("bad hash context");
  memcpy(c, RAW(ctx), sizeof *c);
}

static SEXP Chupd(SEXP ctx, SEXP x) {
  int rc;
  nqhctx c;
  SEXP out;
  chkraw(x, "x", 0);
  getctx(ctx, &c);
  out = PROTECT(rawn(sizeof c));
  rc = nqhupd(&c, rp(x), rn(x));
  memcpy(RAW(out), &c, sizeof c);
  nqwipe(&c, sizeof c);
  if (rc != NQOK) fail(rc, "nqhupd");
  UNPROTECT(1);
  return out;
}

static SEXP Chfin(SEXP ctx, SEXP len) {
  int n = ival(len, "len"), rc;
  nqhctx c;
  SEXP out;
  if (n < 0) Rf_error("'len' must not be negative");
  getctx(ctx, &c);
  out = PROTECT(rawn((size_t)n));
  rc = nqhfin(&c, n > 0 ? RAW(out) : NULL, (size_t)n);
  nqwipe(&c, sizeof c);
  if (rc != NQOK) fail(rc, "nqhfin");
  UNPROTECT(1);
  return out;
}

static SEXP Chmac(SEXP alg, SEXP key, SEXP x) {
  int a = ival(alg, "alg"), rc;
  size_t d = nqhlen((nqhalg)a);
  SEXP out;
  chkraw(key, "key", 0);
  chkraw(x, "x", 0);
  if (d == 0) fail(NQEARG, "nqhmac");
  out = PROTECT(rawn(d));
  rc = nqhmac((nqhalg)a, rp(key), rn(key), rp(x), rn(x), RAW(out), d);
  if (rc != NQOK) fail(rc, "nqhmac");
  UNPROTECT(1);
  return out;
}

/* ---- signatures ---------------------------------------------------- */

static nqssz ssz(int a) {
  nqssz s;
  int rc = nqssize((nqsalg)a, &s);
  if (rc != NQOK) fail(rc, "nqssize");
  return s;
}

static nqksz ksz(int a) {
  nqksz s;
  int rc = nqksize((nqkalg)a, &s);
  if (rc != NQOK) fail(rc, "nqksize");
  return s;
}

/* list(pk, sk); kem selects the KEM table; seed NULL draws from nqrand */
static SEXP Ckg(SEXP kem, SEXP alg, SEXP seed) {
  int k = ival(kem, "kem"), a = ival(alg, "alg"), rc;
  size_t pn, sn;
  SEXP pk, sk, out;
  chkraw(seed, "seed", 1);
  if (k) {
    nqksz s = ksz(a);
    pn = s.pk;
    sn = s.sk;
  } else {
    nqssz s = ssz(a);
    pn = s.pk;
    sn = s.sk;
  }
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  pk = rawn(pn);
  SET_VECTOR_ELT(out, 0, pk);
  sk = rawn(sn);
  SET_VECTOR_ELT(out, 1, sk);
  if (k && seed == R_NilValue) {
    rc = nqkkg((nqkalg)a, RAW(pk), pn, RAW(sk), sn);
  } else if (k) {
    rc = nqkkgd((nqkalg)a, rp(seed), rn(seed), RAW(pk), pn, RAW(sk), sn);
  } else if (seed == R_NilValue) {
    rc = nqskg((nqsalg)a, RAW(pk), pn, RAW(sk), sn);
  } else {
    rc = nqskgd((nqsalg)a, rp(seed), rn(seed), RAW(pk), pn, RAW(sk), sn);
  }
  if (rc != NQOK) fail(rc, "key generation");
  UNPROTECT(1);
  return out;
}

/* rnd NULL: hedged signing with fresh randomness from nqrand */
static SEXP Csign(SEXP alg, SEXP sk, SEXP msg, SEXP ctx, SEXP ph, SEXP rnd) {
  int a = ival(alg, "alg"), h = ival(ph, "ph"), rc;
  nqssz s = ssz(a);
  size_t n = 0;
  SEXP sig;
  chkraw(sk, "sk", 0);
  chkraw(msg, "msg", 0);
  chkraw(ctx, "ctx", 1);
  chkraw(rnd, "rnd", 1);
  sig = PROTECT(rawn(s.sig));
  if (rnd == R_NilValue) {
    rc = nqsign((nqsalg)a, rp(sk), rn(sk), rp(msg), rn(msg), rp(ctx),
                rn(ctx), h, RAW(sig), s.sig, &n);
  } else {
    rc = nqsignd((nqsalg)a, rp(sk), rn(sk), rp(msg), rn(msg), rp(ctx),
                 rn(ctx), h, rp(rnd), rn(rnd), RAW(sig), s.sig, &n);
  }
  if (rc != NQOK) fail(rc, "nqsign");
  /* n is s.sig: every algorithm's signatures have one fixed size */
  UNPROTECT(1);
  return sig;
}

/* The library's return code: NQOK, NQEVRFY, or another error. An empty
 * key or signature is passed as a valid pointer with length 0, so it is
 * judged by its length (a failed verification), not as a NULL argument. */
static SEXP Cvrfy(SEXP alg, SEXP pk, SEXP msg, SEXP sig, SEXP ctx, SEXP ph) {
  static const uint8_t z[1] = {0};
  int a = ival(alg, "alg"), h = ival(ph, "ph");
  const uint8_t *kp, *sp;
  chkraw(pk, "pk", 0);
  chkraw(msg, "msg", 0);
  chkraw(sig, "sig", 0);
  chkraw(ctx, "ctx", 1);
  kp = rn(pk) > 0 ? rp(pk) : z;
  sp = rn(sig) > 0 ? rp(sig) : z;
  return Rf_ScalarInteger(nqvrfy((nqsalg)a, kp, rn(pk), rp(msg), rn(msg),
                                 rp(ctx), rn(ctx), h, sp, rn(sig)));
}

/* ---- key encapsulation --------------------------------------------- */

static SEXP Cenc(SEXP alg, SEXP pk, SEXP seed) {
  int a = ival(alg, "alg"), rc;
  nqksz s = ksz(a);
  SEXP ct, ss, out;
  chkraw(pk, "pk", 0);
  chkraw(seed, "seed", 1);
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  ct = rawn(s.ct);
  SET_VECTOR_ELT(out, 0, ct);
  ss = rawn(s.ss);
  SET_VECTOR_ELT(out, 1, ss);
  if (seed == R_NilValue) {
    rc = nqenc((nqkalg)a, rp(pk), rn(pk), RAW(ct), s.ct, RAW(ss), s.ss);
  } else {
    rc = nqencd((nqkalg)a, rp(pk), rn(pk), rp(seed), rn(seed), RAW(ct),
                s.ct, RAW(ss), s.ss);
  }
  if (rc != NQOK) fail(rc, "nqenc");
  UNPROTECT(1);
  return out;
}

static SEXP Cdec(SEXP alg, SEXP sk, SEXP ct) {
  int a = ival(alg, "alg"), rc;
  nqksz s = ksz(a);
  SEXP ss;
  chkraw(sk, "sk", 0);
  chkraw(ct, "ct", 0);
  ss = PROTECT(rawn(s.ss));
  rc = nqdec((nqkalg)a, rp(sk), rn(sk), rp(ct), rn(ct), RAW(ss), s.ss);
  if (rc != NQOK) fail(rc, "nqdec");
  UNPROTECT(1);
  return ss;
}

/* ---- capsules ------------------------------------------------------ */

static SEXP Cseal(SEXP dir, SEXP alg, SEXP sk, SEXP pk, SEXP meta) {
  int a = ival(alg, "alg"), rc;
  const char *m = NULL, *d;
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  if (meta != R_NilValue) {
    if (TYPEOF(meta) != STRSXP || XLENGTH(meta) != 1 ||
        STRING_ELT(meta, 0) == NA_STRING)
      Rf_error("'meta' must be one string of JSON text");
    m = Rf_translateCharUTF8(STRING_ELT(meta, 0));
  }
  d = rpath(dir);
  rc = nqseal(d, (nqsalg)a, rp(sk), rn(sk), rp(pk), rn(pk), m, NULL);
  if (rc != NQOK) fail(rc, "nqseal");
  return Rf_ScalarInteger(rc);
}

static void repfin(SEXP p) {
  nqrep *r = (nqrep *)R_ExternalPtrAddr(p);
  if (r != NULL) {
    nqrepfree(r);
    R_ClearExternalPtr(p);
  }
}

/* A path in the encoding the library expects, as rpath. */
static const char *rpathe(SEXP x) {
#if defined(_WIN32)
  return Rf_translateCharUTF8(x);
#else
  return Rf_translateChar(x);
#endif
}

/* A character vector as an array of C strings, R_alloc'd (freed when the
 * .Call returns, also on error); utf8 for manifest paths, else paths in
 * the native encoding. NULL for NULL or an empty vector. */
static const char **strs(SEXP x, const char *what, int utf8, size_t *n) {
  const char **p;
  R_xlen_t i, k;
  *n = 0;
  if (x == R_NilValue) return NULL;
  if (TYPEOF(x) != STRSXP) Rf_error("'%s' must be a character vector", what);
  k = XLENGTH(x);
  if (k == 0) return NULL;
  p = (const char **)R_alloc((size_t)k, sizeof *p);
  for (i = 0; i < k; i++) {
    SEXP e = STRING_ELT(x, i);
    if (e == NA_STRING) Rf_error("'%s' must not hold NA", what);
    p[i] = utf8 ? Rf_translateCharUTF8(e) : rpathe(e);
  }
  *n = (size_t)k;
  return p;
}

/* A list of raw vectors as pointer and length arrays, R_alloc'd. */
static size_t raws(SEXP x, const char *what, size_t max,
                   const uint8_t ***p, size_t **l) {
  size_t i, k;
  *p = NULL;
  *l = NULL;
  if (x == R_NilValue) return 0;
  if (TYPEOF(x) != VECSXP) Rf_error("'%s' must be a list", what);
  k = (size_t)XLENGTH(x);
  if (k > max) Rf_error("at most %d %s", (int)max, what);
  if (k == 0) return 0;
  *p = (const uint8_t **)R_alloc(k, sizeof **p);
  *l = (size_t *)R_alloc(k, sizeof **l);
  for (i = 0; i < k; i++) {
    SEXP e = VECTOR_ELT(x, (R_xlen_t)i);
    chkraw(e, what, 0);
    (*p)[i] = rp(e);
    (*l)[i] = rn(e);
  }
  return k;
}

/* list(rc, check, ok, detail) from a report that p (an external pointer
 * with a finalizer, protected by the caller) holds, so an allocation
 * error cannot leak it; frees it. */
static SEXP repout(int rc, nqrep *r, SEXP p, const char *what) {
  size_t n, i;
  const char *c, *t;
  int ok;
  SEXP out, ck, okv, dt;
  if (r == NULL) fail(rc == NQOK ? NQEMEM : rc, what);
  n = nqrepn(r);
  out = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  ck = Rf_allocVector(STRSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 1, ck);
  okv = Rf_allocVector(LGLSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 2, okv);
  dt = Rf_allocVector(STRSXP, (R_xlen_t)n);
  SET_VECTOR_ELT(out, 3, dt);
  for (i = 0; i < n; i++) {
    c = NULL;
    t = NULL;
    ok = 0;
    nqrepi(r, i, &c, &ok, &t);
    SET_STRING_ELT(ck, (R_xlen_t)i, Rf_mkCharCE(c ? c : "", CE_UTF8));
    LOGICAL(okv)[i] = ok != 0;
    SET_STRING_ELT(dt, (R_xlen_t)i, Rf_mkCharCE(t ? t : "", CE_UTF8));
  }
  repfin(p);
  UNPROTECT(1);
  return out;
}

/* nqchkx, or nqchkp with a proof (dir then NULL or the folder of the
 * proven files): list(rc, check, ok, detail) */
static SEXP Cchk(SEXP dir, SEXP pk, SEXP anc, SEXP only, SEXP lin,
                 SEXP stmt, SEXP proof) {
  nqcopt o;
  const uint8_t **ap, **sp;
  const char *d = NULL;
  size_t *al, *sl;
  nqrep *r = NULL;
  int rc;
  SEXP p, out;
  memset(&o, 0, sizeof o);
  chkraw(pk, "pk", 1);
  chkraw(proof, "proof", 1);
  o.trust = rp(pk);
  o.trustlen = rn(pk);
  o.nanc = raws(anc, "anchors", 32, &ap, &al);
  o.anc = ap;
  o.anclen = al;
  o.only = strs(only, "only", 1, &o.nonly);
  o.lin = strs(lin, "lineage", 0, &o.nlin);
  o.nstmt = raws(stmt, "keys", 32, &sp, &sl);
  o.stmt = (const char *const *)sp;
  o.stmtlen = sl;
  if (dir != R_NilValue) d = rpath(dir);
  p = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, repfin, TRUE);
  if (proof != R_NilValue) {
    rc = nqchkp((const char *)rp(proof), rn(proof), &o, d, &r);
  } else {
    rc = nqchkx(d, &o, &r);
  }
  R_SetExternalPtrAddr(p, r);
  out = repout(rc, r, p, "nqchk");
  UNPROTECT(1);
  return out;
}

static SEXP Cfiles(SEXP dir) {
  nqrep *r = NULL;
  int rc;
  const char *d = rpath(dir);
  SEXP p, out;
  p = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, repfin, TRUE);
  rc = nqfiles(d, &r);
  R_SetExternalPtrAddr(p, r);
  out = repout(rc, r, p, "nqfiles");
  UNPROTECT(1);
  return out;
}

/* ids: a list of 32-byte raw vectors; names: their names */
static SEXP Cseal2(SEXP dir, SEXP alg, SEXP sk, SEXP pk, SEXP meta,
                   SEXP ids, SEXP names) {
  int a = ival(alg, "alg"), rc;
  const char *m = NULL, *d;
  const char **nm;
  size_t n, i, k;
  nqcin *in = NULL;
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  if (meta != R_NilValue) {
    if (TYPEOF(meta) != STRSXP || XLENGTH(meta) != 1 ||
        STRING_ELT(meta, 0) == NA_STRING)
      Rf_error("'meta' must be one string of JSON text");
    m = Rf_translateCharUTF8(STRING_ELT(meta, 0));
  }
  nm = strs(names, "names", 1, &n);
  if (TYPEOF(ids) != VECSXP || (size_t)XLENGTH(ids) != n)
    Rf_error("'inputs': one id per name");
  if (n > 1024) Rf_error("at most 1024 inputs");
  if (n > 0) in = (nqcin *)R_alloc(n, sizeof *in);
  for (i = 0; i < n; i++) {
    SEXP e = VECTOR_ELT(ids, (R_xlen_t)i);
    chkraw(e, "inputs", 0);
    if (XLENGTH(e) != 32) Rf_error("an input id is 32 bytes");
    for (k = 0; k < 32; k++) in[i].id[k] = RAW(e)[k];
    in[i].name = nm[i];
  }
  d = rpath(dir);
  rc = nqseal2(d, (nqsalg)a, rp(sk), rn(sk), rp(pk), rn(pk), m, in, n);
  if (rc != NQOK) fail(rc, "nqseal2");
  return Rf_ScalarInteger(rc);
}

static SEXP Ccapid(SEXP dir) {
  int rc;
  SEXP out = PROTECT(rawn(32));
  rc = nqcapid(rpath(dir), RAW(out));
  if (rc != NQOK) fail(rc, "nqcapid");
  UNPROTECT(1);
  return out;
}

/* The bytes a call writes that sets *outlen also with NQEBUF: tried with
 * cap bytes, then once more with the size it asked for. */
typedef int (*outfn)(void *a, char *out, size_t cap, size_t *outlen);

static SEXP grow(outfn f, void *a, size_t cap, const char *what) {
  size_t on = 0;
  int rc = NQEBUF, k;
  char *b = NULL;
  SEXP out;
  for (k = 0; k < 2; k++) {
    b = R_alloc(cap > 0 ? cap : 1, 1);
    rc = f(a, b, cap, &on);
    if (rc == NQEBUF && on > cap && k == 0) {
      cap = on;
      continue;
    }
    break;
  }
  if (rc != NQOK) fail(rc, what);
  out = rawn(on);
  if (on > 0) memcpy(RAW(out), b, on);
  return out;
}

typedef struct {
  const char *dir;
  const char **p;
  size_t n;
} prvarg;

static int prvcall(void *v, char *out, size_t cap, size_t *outlen) {
  prvarg *a = (prvarg *)v;
  return nqprove(a->dir, a->p, a->n, out, cap, outlen);
}

static SEXP Cprove(SEXP dir, SEXP paths) {
  prvarg a;
  a.p = strs(paths, "paths", 1, &a.n);
  if (a.n == 0) Rf_error("'paths' must name at least one file");
  a.dir = rpath(dir);
  return grow(prvcall, &a, 65536, "nqprove");
}

typedef struct {
  int alg, nalg;
  SEXP sk, pk, nsk, npk;
  const char *why;
  int64_t at;
} ksarg;

static int kscall(void *v, char *out, size_t cap, size_t *outlen) {
  ksarg *a = (ksarg *)v;
  /* nalg -1: the statement that the key expires (nqkexp) */
  if (a->nalg == -1)
    return nqkexp((nqsalg)a->alg, rp(a->sk), rn(a->sk), rp(a->pk), rn(a->pk),
                  a->at, a->why, out, cap, outlen);
  return nqkstmt((nqsalg)a->alg, rp(a->sk), rn(a->sk), rp(a->pk),
                 rn(a->pk), (nqsalg)a->nalg, rp(a->nsk), rn(a->nsk),
                 rp(a->npk), rn(a->npk), a->at, a->why, out, cap, outlen);
}

/* nsk and npk NULL for a revocation; at in seconds since 1970 */
static SEXP Ckstmt(SEXP alg, SEXP sk, SEXP pk, SEXP nalg, SEXP nsk, SEXP npk,
                   SEXP at, SEXP reason) {
  ksarg a;
  double t;
  a.alg = ival(alg, "alg");
  a.nalg = ival(nalg, "nalg");
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  chkraw(nsk, "nsk", 1);
  chkraw(npk, "npk", 1);
  a.sk = sk;
  a.pk = pk;
  a.nsk = nsk;
  a.npk = npk;
  if (TYPEOF(at) != REALSXP || XLENGTH(at) != 1 || !R_FINITE(REAL(at)[0]))
    Rf_error("'at' must be one time");
  t = REAL(at)[0];
  if (t < 0 || t > 253402300799.0) Rf_error("'at' must be 1970 to 9999");
  a.at = (int64_t)t;
  a.why = NULL;
  if (reason != R_NilValue) {
    if (TYPEOF(reason) != STRSXP || XLENGTH(reason) != 1 ||
        STRING_ELT(reason, 0) == NA_STRING)
      Rf_error("'reason' must be NULL or one string");
    a.why = Rf_translateCharUTF8(STRING_ELT(reason, 0));
  }
  return grow(kscall, &a, 4 * (rn(pk) + rn(npk)) + 16384, "nqkstmt");
}

typedef struct {
  int alg;
  SEXP sk, pk, pl;
  const char *type;
} dsarg;

static int dscall(void *v, char *out, size_t cap, size_t *outlen) {
  dsarg *a = (dsarg *)v;
  return nqdsse((nqsalg)a->alg, rp(a->sk), rn(a->sk), rp(a->pk), rn(a->pk),
                a->type, rp(a->pl), rn(a->pl), out, cap, outlen);
}

static SEXP Cdsse(SEXP alg, SEXP sk, SEXP pk, SEXP type, SEXP pl) {
  dsarg a;
  a.alg = ival(alg, "alg");
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  chkraw(pl, "payload", 0);
  if (TYPEOF(type) != STRSXP || XLENGTH(type) != 1 ||
      STRING_ELT(type, 0) == NA_STRING)
    Rf_error("'type' must be one string");
  a.sk = sk;
  a.pk = pk;
  a.pl = pl;
  a.type = Rf_translateCharUTF8(STRING_ELT(type, 0));
  return grow(dscall, &a, 2 * rn(pl) + 65536, "nqdsse");
}

/* list(rc, type, payload): NQOK, NQEVRFY or NQEDEC (type and payload
 * NULL then); any other code is an error */
static SEXP Cdssevrfy(SEXP alg, SEXP pk, SEXP env) {
  int a = ival(alg, "alg"), rc;
  size_t on = 0, n;
  char type[256];
  uint8_t *b;
  SEXP out, pl;
  chkraw(pk, "pk", 0);
  chkraw(env, "env", 0);
  n = rn(env);
  /* the payload is the decoding of base64 inside env: shorter than it */
  b = (uint8_t *)R_alloc(n > 0 ? n : 1, 1);
  rc = nqdssevrfy((nqsalg)a, rp(pk), rn(pk), (const char *)rp(env), n, b,
                  n, &on, type);
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) fail(rc, "nqdssevrfy");
  out = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) {
    SET_VECTOR_ELT(out, 1, Rf_mkString(type));
    pl = rawn(on);
    SET_VECTOR_ELT(out, 2, pl);
    if (on > 0) memcpy(RAW(pl), b, on);
  }
  UNPROTECT(1);
  return out;
}

typedef struct {
  int alg;
  SEXP sk, pk;
  const char *f[5]; /* name, orcid, email, url, affil */
  int64_t at;
} cdarg;

static int cdcall(void *v, char *out, size_t cap, size_t *outlen) {
  cdarg *a = (cdarg *)v;
  return nqcard((nqsalg)a->alg, rp(a->sk), rn(a->sk), rp(a->pk), rn(a->pk),
                a->f[0], a->f[1], a->f[2], a->f[3], a->f[4], a->at, out,
                cap, outlen);
}

/* each field NULL or one string (checked in R); at in seconds since 1970 */
static SEXP Ccard(SEXP alg, SEXP sk, SEXP pk, SEXP name, SEXP orcid,
                  SEXP email, SEXP url, SEXP affil, SEXP at) {
  SEXP fs[5];
  cdarg a;
  double t;
  int i;
  fs[0] = name;
  fs[1] = orcid;
  fs[2] = email;
  fs[3] = url;
  fs[4] = affil;
  a.alg = ival(alg, "alg");
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  a.sk = sk;
  a.pk = pk;
  for (i = 0; i < 5; i++) {
    a.f[i] = NULL;
    if (fs[i] == R_NilValue && i > 0) continue;
    if (TYPEOF(fs[i]) != STRSXP || XLENGTH(fs[i]) != 1 ||
        STRING_ELT(fs[i], 0) == NA_STRING)
      Rf_error("a card's fields must be NULL or one string");
    a.f[i] = Rf_translateCharUTF8(STRING_ELT(fs[i], 0));
  }
  if (TYPEOF(at) != REALSXP || XLENGTH(at) != 1 || !R_FINITE(REAL(at)[0]))
    Rf_error("'at' must be one time");
  t = REAL(at)[0];
  if (t < 0 || t > 253402300799.0) Rf_error("'at' must be 1970 to 9999");
  a.at = (int64_t)t;
  return grow(cdcall, &a, 4 * rn(pk) + 65536, "nqcard");
}

static SEXP utf8(const char *s) {
  return Rf_ScalarString(Rf_mkCharCE(s, CE_UTF8));
}

/* list(rc, fields): NQOK with the card's fields, or NQEVRFY or NQEDEC
 * (fields NULL then); any other code is an error */
static SEXP Ccardvrfy(SEXP card, SEXP pk) {
  static const char *const nm[] = {"name", "orcid", "email", "url",
                                   "affil", "created", "alg", "pk",
                                   "key_sha256"};
  nqcardf *f;
  int rc, i;
  char hx[65];
  SEXP out, fl, names, k;
  chkraw(card, "card", 0);
  chkraw(pk, "pk", 1);
  f = (nqcardf *)R_alloc(1, sizeof *f);
  rc = nqcardvrfy((const char *)rp(card), rn(card), rp(pk), rn(pk), f);
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) fail(rc, "nqcardvrfy");
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) {
    static const char d[] = "0123456789abcdef";
    for (i = 0; i < 32; i++) {
      hx[2 * i] = d[f->fp[i] >> 4];
      hx[2 * i + 1] = d[f->fp[i] & 15];
    }
    hx[64] = 0;
    fl = PROTECT(Rf_allocVector(VECSXP, 9));
    names = PROTECT(Rf_allocVector(STRSXP, 9));
    for (i = 0; i < 9; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
    SET_VECTOR_ELT(fl, 0, utf8(f->name));
    SET_VECTOR_ELT(fl, 1, utf8(f->orcid));
    SET_VECTOR_ELT(fl, 2, utf8(f->email));
    SET_VECTOR_ELT(fl, 3, utf8(f->url));
    SET_VECTOR_ELT(fl, 4, utf8(f->affil));
    SET_VECTOR_ELT(fl, 5, utf8(f->utc));
    SET_VECTOR_ELT(fl, 6, utf8(nqsname(f->alg)));
    k = rawn(f->pklen);
    SET_VECTOR_ELT(fl, 7, k);
    memcpy(RAW(k), f->pk, f->pklen);
    SET_VECTOR_ELT(fl, 8, utf8(hx));
    Rf_setAttrib(fl, R_NamesSymbol, names);
    SET_VECTOR_ELT(out, 1, fl);
    UNPROTECT(2);
  }
  UNPROTECT(1);
  return out;
}

static SEXP Cerr(SEXP rc) {
  return Rf_mkString(nqerr(ival(rc, "rc")));
}

/* ---- registration -------------------------------------------------- */

/* through void (*)(void), the generic function pointer type the compilers
 * accept a cast from without -Wcast-function-type */
/* the data layer's entry points, in rnqd.c */
/* ---- BLAKE2b, Argon2id, constant-time comparison ------------------- */

static SEXP Cb2b(SEXP key, SEXP x, SEXP len) {
  int n = ival(len, "n"), rc;
  SEXP out;
  chkraw(key, "key", 1);
  chkraw(x, "x", 0);
  if (n < 1 || n > 64) Rf_error("'n' must be 1 to 64");
  out = PROTECT(rawn((size_t)n));
  rc = nqb2b(rp(key), rn(key), rp(x), rn(x), RAW(out), (size_t)n);
  if (rc != NQOK) fail(rc, "nqb2b");
  UNPROTECT(1);
  return out;
}

/* ---- KangarooTwelve, ChaCha20, AES-SIV, AES-GCM-SIV ----------------- */

static SEXP Ckt(SEXP bits, SEXP x, SEXP custom, SEXP len) {
  int b = ival(bits, "bits"), n = ival(len, "n"), rc;
  SEXP out;
  chkraw(x, "x", 0);
  chkraw(custom, "custom", 1);
  if (n < 1) Rf_error("'n' must be 1 or more");
  out = PROTECT(rawn((size_t)n));
  rc = nqkt((unsigned)b, rp(x), rn(x), rp(custom), rn(custom), RAW(out),
            (size_t)n);
  if (rc != NQOK) fail(rc, "nqkt");
  UNPROTECT(1);
  return out;
}

/* ctr: one number from 0 to 2^32 - 1, as a double */
static SEXP Ccha20(SEXP key, SEXP nonce, SEXP ctr, SEXP x) {
  double c;
  SEXP out;
  int rc;
  chkraw(key, "key", 0);
  chkraw(nonce, "nonce", 0);
  chkraw(x, "x", 0);
  if (TYPEOF(ctr) != REALSXP || XLENGTH(ctr) != 1) Rf_error("'counter' must be one number");
  c = REAL(ctr)[0];
  if (!(c >= 0 && c <= 4294967295.0) || c != (double)(uint32_t)c)
    Rf_error("'counter' must be a whole number from 0 to 2^32 - 1");
  out = PROTECT(rawn(rn(x)));
  rc = nqcha20(rp(key), rn(key), rp(nonce), rn(nonce), (uint32_t)c, rp(x),
               rn(x), rn(x) > 0 ? RAW(out) : NULL);
  if (rc != NQOK) fail(rc, "nqcha20");
  UNPROTECT(1);
  return out;
}

/* dec: 0 to encrypt, 1 to decrypt; ad: a list of raw vectors */
static SEXP Csiv(SEXP dec, SEXP key, SEXP ad, SEXP x) {
  const uint8_t *adp[NQSIVADMAX];
  size_t adl[NQSIVADMAX], nad, i, n, on;
  int d = ival(dec, "dec"), rc;
  SEXP out;
  chkraw(key, "key", 0);
  chkraw(x, "x", 0);
  if (TYPEOF(ad) != VECSXP) Rf_error("'ad' must be a list of raw vectors");
  nad = (size_t)XLENGTH(ad);
  if (nad > NQSIVADMAX) Rf_error("'ad' holds more than %u strings", NQSIVADMAX);
  for (i = 0; i < nad; i++) {
    SEXP e = VECTOR_ELT(ad, (R_xlen_t)i);
    if (TYPEOF(e) != RAWSXP) Rf_error("'ad' must be a list of raw vectors");
    adp[i] = rp(e);
    adl[i] = rn(e);
  }
  n = rn(x);
  if (d && n < 16) Rf_error("'x' is shorter than the 16 bytes of the IV");
  on = d ? n - 16 : n + 16;
  out = PROTECT(rawn(on));
  rc = d ? nqsivdec(rp(key), rn(key), adp, adl, nad, rp(x), n,
                    on > 0 ? RAW(out) : NULL, on)
         : nqsivenc(rp(key), rn(key), adp, adl, nad, rp(x), n, RAW(out), on);
  if (rc != NQOK) fail(rc, d ? "nqsivdec" : "nqsivenc");
  UNPROTECT(1);
  return out;
}

static SEXP Cgsiv(SEXP dec, SEXP key, SEXP nonce, SEXP ad, SEXP x) {
  size_t n, on;
  int d = ival(dec, "dec"), rc;
  SEXP out;
  chkraw(key, "key", 0);
  chkraw(nonce, "nonce", 0);
  chkraw(ad, "ad", 1);
  chkraw(x, "x", 0);
  n = rn(x);
  if (d && n < 16) Rf_error("'x' is shorter than the 16 bytes of the tag");
  on = d ? n - 16 : n + 16;
  out = PROTECT(rawn(on));
  rc = d ? nqgsivdec(rp(key), rn(key), rp(nonce), rn(nonce), rp(ad), rn(ad),
                     rp(x), n, on > 0 ? RAW(out) : NULL, on)
         : nqgsivenc(rp(key), rn(key), rp(nonce), rn(nonce), rp(ad), rn(ad),
                     rp(x), n, RAW(out), on);
  if (rc != NQOK) fail(rc, d ? "nqgsivdec" : "nqgsivenc");
  UNPROTECT(1);
  return out;
}

/* tmp: c(t, m, p) */
static SEXP Ca2id(SEXP pw, SEXP salt, SEXP key, SEXP ad, SEXP tmp,
                  SEXP len) {
  int n = ival(len, "n"), rc;
  SEXP out;
  chkraw(pw, "pw", 0);
  chkraw(salt, "salt", 0);
  chkraw(key, "key", 1);
  chkraw(ad, "ad", 1);
  if (TYPEOF(tmp) != REALSXP || XLENGTH(tmp) != 3)
    Rf_error("the cost must be three numbers");
  if (n < 4 || n > 1024) Rf_error("'n' must be 4 to 1024");
  out = PROTECT(rawn((size_t)n));
  rc = nqa2id(rp(pw), rn(pw), rp(salt), rn(salt), rp(key), rn(key), rp(ad),
              rn(ad), (uint32_t)REAL(tmp)[0], (uint32_t)REAL(tmp)[1],
              (uint32_t)REAL(tmp)[2], RAW(out), (size_t)n);
  if (rc != NQOK) {
    nqwipe(RAW(out), (size_t)n);
    fail(rc, "nqa2id");
  }
  UNPROTECT(1);
  return out;
}

static SEXP Ccteq(SEXP a, SEXP b) {
  chkraw(a, "a", 0);
  chkraw(b, "b", 0);
  if (rn(a) != rn(b)) return Rf_ScalarLogical(0);
  if (rn(a) == 0) return Rf_ScalarLogical(1);
  return Rf_ScalarLogical(nqcteq(RAW(a), RAW(b), rn(a)));
}

/* ---- passphrase key files ------------------------------------------ */

/* mtp: c(m, t, p), 0 for the defaults */
static SEXP Cpwenc(SEXP pw, SEXP ad, SEXP mtp, SEXP sk) {
  SEXP out;
  size_t n = 0;
  int rc;
  chkraw(pw, "pass", 0);
  chkraw(ad, "ad", 1);
  chkraw(sk, "sk", 0);
  if (TYPEOF(mtp) != REALSXP || XLENGTH(mtp) != 3)
    Rf_error("the cost must be three numbers");
  if (rn(sk) > NQPWMAX) Rf_error("'sk' is over %u bytes", NQPWMAX);
  out = PROTECT(rawn(rn(sk) + NQPWOVH));
  rc = nqpwenc(rp(pw), rn(pw), rp(ad), rn(ad), (uint32_t)REAL(mtp)[0],
               (uint32_t)REAL(mtp)[1], (uint32_t)REAL(mtp)[2], rp(sk),
               rn(sk), RAW(out), rn(sk) + NQPWOVH, &n);
  if (rc != NQOK) fail(rc, "nqpwenc");
  UNPROTECT(1);
  return out;
}

static SEXP Cpwdec(SEXP pw, SEXP ad, SEXP in) {
  SEXP out;
  size_t cap, n = 0;
  int rc;
  chkraw(pw, "pass", 0);
  chkraw(ad, "ad", 1);
  chkraw(in, "data", 0);
  cap = rn(in) > NQPWOVH ? rn(in) - NQPWOVH : 1;
  out = PROTECT(rawn(cap));
  rc = nqpwdec(rp(pw), rn(pw), rp(ad), rn(ad), rp(in), rn(in), RAW(out), cap,
               &n);
  if (rc != NQOK) fail(rc, "the passphrase-protected key");
  /* n is cap: nqpwdec refuses anything shorter than NQPWOVH + 1 bytes and
   * returns the n - NQPWOVH bytes it decrypts */
  UNPROTECT(1);
  return out;
}

/* ---- ML-DSA with an external mu ------------------------------------ */

static SEXP Csmu(SEXP alg, SEXP pk, SEXP msg, SEXP ctx, SEXP ph) {
  int a = ival(alg, "alg"), rc;
  SEXP out;
  chkraw(pk, "pk", 0);
  chkraw(msg, "msg", 0);
  chkraw(ctx, "ctx", 1);
  out = PROTECT(rawn(NQMU));
  rc = nqsmu((nqsalg)a, rp(pk), rn(pk), rp(msg), rn(msg), rp(ctx), rn(ctx),
             ival(ph, "ph"), RAW(out), NQMU);
  if (rc != NQOK) fail(rc, "nqsmu");
  UNPROTECT(1);
  return out;
}

static SEXP Csignmu(SEXP alg, SEXP sk, SEXP mu, SEXP rnd) {
  int a = ival(alg, "alg"), rc;
  nqssz z = ssz(a);
  size_t n = 0;
  SEXP out, r;
  chkraw(sk, "sk", 0);
  chkraw(mu, "mu", 0);
  chkraw(rnd, "rnd", 1);
  out = PROTECT(rawn(z.sig));
  rc = nqsignmu((nqsalg)a, rp(sk), rn(sk), rp(mu), rn(mu), rp(rnd), rn(rnd),
                RAW(out), z.sig, &n);
  if (rc != NQOK) fail(rc, "nqsignmu");
  r = PROTECT(rawn(n));
  memcpy(RAW(r), RAW(out), n);
  UNPROTECT(2);
  return r;
}

static SEXP Cvrfymu(SEXP alg, SEXP pk, SEXP mu, SEXP sig) {
  int rc;
  chkraw(pk, "pk", 0);
  chkraw(mu, "mu", 0);
  chkraw(sig, "sig", 0);
  rc = nqvrfymu((nqsalg)ival(alg, "alg"), rp(pk), rn(pk), rp(mu), rn(mu),
                rp(sig), rn(sig));
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) fail(rc, "nqvrfymu");
  return Rf_ScalarLogical(rc == NQOK);
}

/* ---- contexts: streaming signatures and sealed streams ------------- */

/* A context in R_Calloc memory held by an external pointer whose tag is
 * its size; the finalizer (and the end of the stream) wipes and frees it. */
static void ctxfin(SEXP p) {
  void *c = R_ExternalPtrAddr(p);
  if (c != NULL) {
    nqwipe(c, (size_t)Rf_asInteger(R_ExternalPtrTag(p)));
    R_Free(c);
    R_ClearExternalPtr(p);
  }
}

static SEXP ctxnew(size_t n, void **c) {
  SEXP p;
  *c = R_Calloc(n, char);
  p = PROTECT(R_MakeExternalPtr(*c, Rf_ScalarInteger((int)n), R_NilValue));
  R_RegisterCFinalizerEx(p, ctxfin, TRUE);
  UNPROTECT(1);
  return p;
}

static void *ctxget(SEXP p) {
  void *c;
  if (TYPEOF(p) != EXTPTRSXP) Rf_error("not a noqtis stream");
  c = R_ExternalPtrAddr(p);
  if (c == NULL) Rf_error("noqtis: %s", nqerr(NQESTATE));
  return c;
}

/* Cctxbad(p) is for the package's tests only (tests/testthat/
 * test-alloc.R): it overwrites the streaming context p holds with zeros,
 * so that the library's state check (the context's magic number, read
 * by nqsupd, nqsfin and nqvfin) refuses it with NQESTATE. A context
 * damaged in memory is the only way nqsupd fails, and R cannot reach
 * that memory otherwise; no exported function calls this. */
static SEXP Cctxbad(SEXP p) {
  memset(ctxget(p), 0, (size_t)Rf_asInteger(R_ExternalPtrTag(p)));
  return R_NilValue;
}

static SEXP Csini(SEXP alg, SEXP key, SEXP ctx, SEXP ph, SEXP vrfy) {
  int a = ival(alg, "alg"), v = Rf_asLogical(vrfy), rc;
  void *c;
  SEXP p;
  chkraw(key, "key", 0);
  chkraw(ctx, "ctx", 1);
  p = PROTECT(ctxnew(sizeof(nqsctx), &c));
  rc = v ? nqvini((nqsctx *)c, (nqsalg)a, rp(key), rn(key), rp(ctx), rn(ctx),
                  ival(ph, "ph"))
         : nqsini((nqsctx *)c, (nqsalg)a, rp(key), rn(key), rp(ctx), rn(ctx),
                  ival(ph, "ph"));
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, v ? "nqvini" : "nqsini");
  }
  UNPROTECT(1);
  return p;
}

static SEXP Csupd(SEXP p, SEXP x) {
  int rc;
  chkraw(x, "x", 0);
  rc = nqsupd((nqsctx *)ctxget(p), rp(x), rn(x));
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, "nqsupd");
  }
  return R_NilValue;
}

static SEXP Csfin(SEXP p, SEXP alg, SEXP sk, SEXP rnd) {
  int a = ival(alg, "alg"), rc;
  nqssz z = ssz(a);
  size_t n = 0;
  SEXP out, r;
  static const uint8_t none[1] = {0};
  nqsctx *c = (nqsctx *)ctxget(p);
  chkraw(sk, "sk", 0);
  chkraw(rnd, "rnd", 1);
  out = PROTECT(rawn(z.sig));
  /* a present but empty rnd is not NULL: Ed25519's deterministic one */
  rc = nqsfin(c, rp(sk), rn(sk),
              rnd == R_NilValue ? NULL : rn(rnd) == 0 ? none : RAW(rnd),
              rn(rnd), RAW(out), z.sig, &n);
  ctxfin(p);
  if (rc != NQOK) fail(rc, "nqsfin");
  r = PROTECT(rawn(n));
  memcpy(RAW(r), RAW(out), n);
  UNPROTECT(2);
  return r;
}

static SEXP Cvfin(SEXP p, SEXP pk, SEXP sig) {
  int rc;
  nqsctx *c = (nqsctx *)ctxget(p);
  chkraw(pk, "pk", 0);
  chkraw(sig, "sig", 0);
  rc = nqvfin(c, rp(pk), rn(pk), rp(sig), rn(sig));
  ctxfin(p);
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) fail(rc, "nqvfin");
  return Rf_ScalarLogical(rc == NQOK);
}

static SEXP Ckseal(SEXP alg, SEXP pk, SEXP ctx, SEXP msg) {
  int a = ival(alg, "alg"), rc;
  nqksz z = ksz(a);
  size_t n = 0, cap;
  SEXP out;
  chkraw(pk, "pk", 0);
  chkraw(ctx, "ctx", 1);
  chkraw(msg, "msg", 0);
  if (rn(msg) > NQKSMAX) fail(NQELIM, "nqkseal");
  cap = NQKSOVH + z.ct + rn(msg);
  out = PROTECT(rawn(cap));
  rc = nqkseal((nqkalg)a, rp(pk), rn(pk), rp(ctx), rn(ctx), rp(msg), rn(msg),
               RAW(out), cap, &n);
  if (rc != NQOK) fail(rc, "nqkseal");
  UNPROTECT(1);
  return out;
}

static SEXP Ckopen(SEXP alg, SEXP sk, SEXP ctx, SEXP in) {
  int a = ival(alg, "alg"), rc;
  size_t n = 0, cap;
  SEXP out, r;
  chkraw(sk, "sk", 0);
  chkraw(ctx, "ctx", 1);
  chkraw(in, "data", 0);
  cap = rn(in) > 0 ? rn(in) : 1;
  out = PROTECT(rawn(cap));
  rc = nqkopen((nqkalg)a, rp(sk), rn(sk), rp(ctx), rn(ctx), rp(in), rn(in),
               RAW(out), cap, &n);
  if (rc != NQOK) fail(rc, "nqkopen");
  r = PROTECT(rawn(n));
  if (n > 0) memcpy(RAW(r), RAW(out), n);
  nqwipe(RAW(out), cap);
  UNPROTECT(2);
  return r;
}

/* list(context, header) */
static SEXP Ckfeini(SEXP alg, SEXP pk, SEXP ctx, SEXP chunk) {
  int a = ival(alg, "alg"), ch = ival(chunk, "chunk"), rc;
  uint8_t h[NQKFHDR + 1568];
  size_t hl = 0;
  void *c;
  SEXP p, out, hd;
  chkraw(pk, "pk", 0);
  chkraw(ctx, "ctx", 1);
  if (ch < 0) Rf_error("'chunk' must not be negative");
  p = PROTECT(ctxnew(sizeof(nqkfctx), &c));
  rc = nqkfeini((nqkfctx *)c, (nqkalg)a, rp(pk), rn(pk), rp(ctx), rn(ctx),
                (uint32_t)ch, h, sizeof h, &hl);
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, "nqkfeini");
  }
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, p);
  hd = rawn(hl);
  SET_VECTOR_ELT(out, 1, hd);
  memcpy(RAW(hd), h, hl);
  UNPROTECT(2);
  return out;
}

/* list(context, chunk) */
static SEXP Ckfdini(SEXP alg, SEXP sk, SEXP ctx, SEXP hdr) {
  int a = ival(alg, "alg"), rc;
  uint32_t ch = 0;
  void *c;
  SEXP p, out;
  chkraw(sk, "sk", 0);
  chkraw(ctx, "ctx", 1);
  chkraw(hdr, "header", 0);
  p = PROTECT(ctxnew(sizeof(nqkfctx), &c));
  rc = nqkfdini((nqkfctx *)c, (nqkalg)a, rp(sk), rn(sk), rp(ctx), rn(ctx),
                rp(hdr), rn(hdr), &ch);
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, "the stream's header");
  }
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, p);
  SET_VECTOR_ELT(out, 1, Rf_ScalarInteger((int)ch));
  UNPROTECT(2);
  return out;
}

/* one chunk, sealed (op 0) or opened (op 1); last for the stream's end */
static SEXP Ckfupd(SEXP p, SEXP x, SEXP last, SEXP op, SEXP chunk) {
  int l = Rf_asLogical(last), o = Rf_asLogical(op),
      ch = ival(chunk, "chunk"), rc;
  size_t cap = o ? (size_t)ch : (size_t)ch + 16, n = 0;
  nqkfctx *c = (nqkfctx *)ctxget(p);
  SEXP out, r;
  chkraw(x, "x", 0);
  out = PROTECT(rawn(cap > 0 ? cap : 1));
  if (o)
    rc = l ? nqkfdfin(c, rp(x), rn(x), RAW(out), cap, &n)
           : nqkfdupd(c, rp(x), rn(x), RAW(out), cap, &n);
  else
    rc = l ? nqkfefin(c, rp(x), rn(x), RAW(out), cap, &n)
           : nqkfeupd(c, rp(x), rn(x), RAW(out), cap, &n);
  if (l || rc != NQOK) ctxfin(p);
  if (rc != NQOK)
    fail(rc, rc == NQEVRFY ? "the sealed stream (changed, cut or not for "
                             "this key or context)"
                           : "the sealed stream");
  r = PROTECT(rawn(n));
  if (n > 0) memcpy(RAW(r), RAW(out), n);
  if (o) nqwipe(RAW(out), cap);
  UNPROTECT(2);
  return r;
}

/* ---- a stream to several keys, signed or not (noqtis-kstream-2) ---- */

/* c(header length, signature algorithm, recipients) of a stream's first
 * NQKMFIX bytes */
static SEXP Ckmpeek(SEXP x) {
  size_t hl = 0, nr = 0;
  nqsalg sg = (nqsalg)0;
  int rc;
  SEXP out;
  chkraw(x, "x", 0);
  rc = nqkmpeek(rp(x), rn(x), &hl, &sg, &nr);
  if (rc != NQOK)
    fail(rc, rc == NQEDEC ? "the stream's header (not a stream to several "
                            "keys, or cut short)"
                          : "the stream's header");
  out = PROTECT(Rf_allocVector(INTSXP, 3));
  INTEGER(out)[0] = (int)hl;
  INTEGER(out)[1] = (int)sg;
  INTEGER(out)[2] = (int)nr;
  UNPROTECT(1);
  return out;
}

/* list(context, header); algs an integer vector, pks a list of raw
 * vectors of the same length */
static SEXP Ckmeini(SEXP algs, SEXP pks, SEXP sig, SEXP ctx, SEXP chunk) {
  int sg = ival(sig, "sig"), ch = ival(chunk, "chunk"), rc;
  nqkrcp r[NQKMRCP];
  size_t hl = 0, n, i;
  void *c;
  SEXP p, out, hd;
  chkraw(ctx, "ctx", 1);
  if (ch < 0) Rf_error("'chunk' must not be negative");
  if (TYPEOF(algs) != INTSXP || TYPEOF(pks) != VECSXP ||
      XLENGTH(algs) != XLENGTH(pks))
    Rf_error("'pks' must be a list of keys, one for each algorithm");
  n = (size_t)XLENGTH(pks);
  if (n < 1 || n > NQKMRCP) Rf_error("1 to %u recipients", NQKMRCP);
  for (i = 0; i < n; i++) {
    SEXP k = VECTOR_ELT(pks, (R_xlen_t)i);
    chkraw(k, "pk", 0);
    r[i].alg = (nqkalg)INTEGER(algs)[i];
    r[i].pk = rp(k);
    r[i].pklen = rn(k);
  }
  rc = nqkmhlen(r, n, &hl);
  if (rc != NQOK) fail(rc, "the recipients' keys");
  p = PROTECT(ctxnew(sizeof(nqkmctx), &c));
  hd = PROTECT(rawn(hl));
  rc = nqkmeini((nqkmctx *)c, r, n, (nqsalg)sg, rp(ctx), rn(ctx),
                (uint32_t)ch, RAW(hd), hl, &hl);
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, "nqkmeini");
  }
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, p);
  SET_VECTOR_ELT(out, 1, hd);
  UNPROTECT(3);
  return out;
}

/* list(context, chunk, signature algorithm) */
static SEXP Ckmdini(SEXP alg, SEXP sk, SEXP ctx, SEXP hdr) {
  int a = ival(alg, "alg"), rc;
  uint32_t ch = 0;
  nqsalg sg = (nqsalg)0;
  void *c;
  SEXP p, out;
  chkraw(sk, "sk", 0);
  chkraw(ctx, "ctx", 1);
  chkraw(hdr, "header", 0);
  p = PROTECT(ctxnew(sizeof(nqkmctx), &c));
  rc = nqkmdini((nqkmctx *)c, (nqkalg)a, rp(sk), rn(sk), rp(ctx), rn(ctx),
                rp(hdr), rn(hdr), &ch, &sg);
  if (rc != NQOK) {
    ctxfin(p);
    fail(rc, rc == NQEVRFY ? "the stream's header (not sealed to this key, "
                             "or another context)"
                           : "the stream's header");
  }
  out = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(out, 0, p);
  SET_VECTOR_ELT(out, 1, Rf_ScalarInteger((int)ch));
  SET_VECTOR_ELT(out, 2, Rf_ScalarInteger((int)sg));
  UNPROTECT(2);
  return out;
}

/* one chunk, sealed (op 0) or opened (op 1), into cap bytes; last for
 * the stream's end, where key is the sender's secret key (sealing) or
 * public key (opening), or NULL */
static SEXP Ckmupd(SEXP p, SEXP x, SEXP last, SEXP op, SEXP cap, SEXP key) {
  int l = Rf_asLogical(last), o = Rf_asLogical(op), cp = ival(cap, "cap"),
      rc;
  size_t n = 0;
  nqkmctx *c = (nqkmctx *)ctxget(p);
  SEXP out, r;
  chkraw(x, "x", 0);
  chkraw(key, "key", 1);
  if (cp < 0) Rf_error("'cap' must not be negative");
  out = PROTECT(rawn(cp > 0 ? (size_t)cp : 1));
  if (o)
    rc = l ? nqkmdfin(c, rp(x), rn(x), rp(key), rn(key), RAW(out),
                      (size_t)cp, &n)
           : nqkmdupd(c, rp(x), rn(x), RAW(out), (size_t)cp, &n);
  else
    rc = l ? nqkmefin(c, rp(x), rn(x), rp(key), rn(key), RAW(out),
                      (size_t)cp, &n)
           : nqkmeupd(c, rp(x), rn(x), RAW(out), (size_t)cp, &n);
  if (l || rc != NQOK) ctxfin(p);
  if (rc != NQOK)
    fail(rc, rc == NQEVRFY ? "the sealed stream (changed or cut, or not "
                             "signed by the sender's key)"
                           : "the sealed stream");
  r = PROTECT(rawn(n));
  if (n > 0) memcpy(RAW(r), RAW(out), n);
  if (o) nqwipe(RAW(out), (size_t)cp);
  UNPROTECT(2);
  return r;
}

/* ---- inspect, why a seal was refused, timestamps ------------------- */

static SEXP Cinsp(SEXP dir) {
  nqrep *r = NULL;
  int rc;
  const char *d = rpath(dir);
  SEXP p, out;
  p = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, repfin, TRUE);
  rc = nqinsp(d, &r);
  R_SetExternalPtrAddr(p, r);
  out = repout(rc, r, p, "nqinsp");
  UNPROTECT(1);
  return out;
}

/* list(why, path) */
static SEXP Csealwhy(SEXP dir) {
  char path[4200];
  int why = 0, rc;
  SEXP out;
  path[0] = '\0';
  rc = nqsealwhy(rpath(dir), &why, path, sizeof path);
  if (rc != NQOK) fail(rc, "nqsealwhy");
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(why));
  SET_VECTOR_ELT(out, 1, Rf_ScalarString(Rf_mkCharCE(path, CE_UTF8)));
  UNPROTECT(1);
  return out;
}

NORET static void whyfail(int rc, const char *what, const char *why) {
  if (why != NULL) Rf_error("noqtis: %s: %s: %s", what, nqerr(rc), why);
  fail(rc, what);
}

/* nqtsreq, or nqersreq with ers (h its hash, 0 for the record's) */
static SEXP Ctsreq(SEXP dir, SEXP nonce, SEXP ers, SEXP h) {
  uint8_t q[256];
  size_t n = 0;
  const char *w = NULL;
  int e = Rf_asLogical(ers), rc;
  SEXP out;
  chkraw(nonce, "nonce", 1);
  rc = e ? nqersreq(rpath(dir), (nqhalg)ival(h, "hash"), rp(nonce),
                    rn(nonce), q, sizeof q, &n, &w)
         : nqtsreq(rpath(dir), rp(nonce), rn(nonce), q, sizeof q, &n);
  if (rc != NQOK) whyfail(rc, e ? "nqersreq" : "nqtsreq", w);
  out = PROTECT(rawn(n));
  memcpy(RAW(out), q, n);
  UNPROTECT(1);
  return out;
}

/* c(genTime, how): nqtsput (how 0), or nqersput with ers */
static SEXP Ctsput(SEXP dir, SEXP rsp, SEXP nonce, SEXP anc, SEXP ers,
                   SEXP h) {
  const uint8_t **ap;
  size_t *al, na;
  int64_t gt = 0;
  int how = 0, e = Rf_asLogical(ers), rc;
  const char *w = NULL;
  SEXP out;
  chkraw(rsp, "reply", 0);
  chkraw(nonce, "nonce", 1);
  na = raws(anc, "anchors", 32, &ap, &al);
  rc = e ? nqersput(rpath(dir), (nqhalg)ival(h, "hash"), rp(rsp), rn(rsp),
                    rp(nonce), rn(nonce), ap, al, na, &gt, &how, &w)
         : nqtsput(rpath(dir), rp(rsp), rn(rsp), rp(nonce), rn(nonce), ap, al,
                   na, &gt, &w);
  if (rc != NQOK) whyfail(rc, e ? "nqersput" : "nqtsput", w);
  out = PROTECT(Rf_allocVector(REALSXP, 2));
  REAL(out)[0] = (double)gt;
  REAL(out)[1] = how;
  UNPROTECT(1);
  return out;
}

SEXP Cdload(SEXP dir);
SEXP Cdput(SEXP dir, SEXP member, SEXP json);
SEXP Cdadd(SEXP dir, SEXP paths, SEXP fields, SEXP vals);
SEXP Cddel(SEXP dir, SEXP member, SEXP key);
SEXP Cdkey(SEXP dir, SEXP member, SEXP key);
SEXP Cdaddr(SEXP dir, SEXP path);
SEXP Cdvrfy(SEXP dir, SEXP path, SEXP raw);
SEXP Cdfld(SEXP dir, SEXP member, SEXP i, SEXP field);
SEXP Cdrslv(SEXP rslv);
SEXP Cdrsp(SEXP rslv, SEXP reply);
SEXP Cdwb(SEXP url);
SEXP Cdchk(SEXP dir);
SEXP Cdinfer(SEXP dir, SEXP path, SEXP delim, SEXP noh, SEXP ranges);
SEXP Cdstats(SEXP dir, SEXP path, SEXP delim, SEXP noh);
SEXP Cddrift(SEXP stats, SEXP dir, SEXP file, SEXP delim, SEXP noh,
             SEXP lv);
SEXP Cdsha(SEXP dir, SEXP path);
SEXP Cddiff(SEXP a, SEXP b);
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
SEXP Calfail(SEXP n);

/* ---- armor, certificates, CMS and S/MIME, OpenPGP, the key store,
 * tokens ---- */

/* buffers come from R_alloc, which R frees also after an error */
static uint8_t *xbuf(size_t n) {
  return (uint8_t *)R_alloc(n > 0 ? n : 1, 1);
}

static SEXP rawof(const uint8_t *b, size_t n) {
  SEXP r = rawn(n);
  if (n > 0) memcpy(RAW(r), b, n);
  return r;
}

/* raw bytes that are text, as one string */
static SEXP strof(const uint8_t *b, size_t n) {
  return Rf_ScalarString(Rf_mkCharLenCE((const char *)b, (int)n, CE_UTF8));
}

/* one string in UTF-8, or NULL for R's NULL */
static const char *sval(SEXP x, const char *what) {
  if (x == R_NilValue) return NULL;
  if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 || STRING_ELT(x, 0) == NA_STRING)
    Rf_error("'%s' must be one string", what);
  return Rf_translateCharUTF8(STRING_ELT(x, 0));
}

/* a time in seconds since 1970 */
static int64_t tval(SEXP at) {
  double t;
  if (TYPEOF(at) != REALSXP || XLENGTH(at) != 1 || !R_FINITE(REAL(at)[0]))
    Rf_error("a time must be one number");
  t = REAL(at)[0];
  if (t < 0 || t > 253402300799.0) Rf_error("a time must be 1970 to 9999");
  return (int64_t)t;
}

static int lval(SEXP x, const char *what) {
  if (TYPEOF(x) != LGLSXP || XLENGTH(x) != 1 || LOGICAL(x)[0] == NA_LOGICAL)
    Rf_error("'%s' must be TRUE or FALSE", what);
  return LOGICAL(x)[0];
}

/* a list of raw vectors as arrays of pointers and lengths */
static size_t rlist(SEXP l, const char *what, const uint8_t ***p,
                    size_t **n) {
  R_xlen_t i, k;
  if (TYPEOF(l) != VECSXP) Rf_error("'%s' must be a list of raw vectors", what);
  k = XLENGTH(l);
  *p = (const uint8_t **)R_alloc((size_t)(k > 0 ? k : 1), sizeof **p);
  *n = (size_t *)R_alloc((size_t)(k > 0 ? k : 1), sizeof **n);
  for (i = 0; i < k; i++) {
    SEXP e = VECTOR_ELT(l, i);
    if (TYPEOF(e) != RAWSXP)
      Rf_error("'%s' must be a list of raw vectors", what);
    (*p)[i] = rp(e);
    (*n)[i] = rn(e);
  }
  return (size_t)k;
}

static size_t lsum(const size_t *l, size_t n) {
  size_t i, s = 0;
  for (i = 0; i < n; i++) s += l[i];
  return s;
}

/* a named list of n elements, protected by the caller */
static SEXP nlist(const char *const *nm, int n) {
  SEXP l = PROTECT(Rf_allocVector(VECSXP, n)), names;
  int i;
  names = PROTECT(Rf_allocVector(STRSXP, n));
  for (i = 0; i < n; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
  Rf_setAttrib(l, R_NamesSymbol, names);
  UNPROTECT(2);
  return l;
}

static SEXP x5list(const nqx5f *f, SEXP der) {
  static const char *const nm[] = {"alg", "kem", "fingerprint", "notbefore",
                                   "notafter", "ca", "name", "email", "pk"};
  const char *an = f->alg == 0 ? ""
                   : f->kem   ? nqkname((nqkalg)f->alg)
                              : nqsname((nqsalg)f->alg);
  SEXP l = PROTECT(nlist(nm, 9));
  SET_VECTOR_ELT(l, 0, Rf_mkString(an != NULL ? an : ""));
  SET_VECTOR_ELT(l, 1, Rf_ScalarLogical(f->kem != 0));
  SET_VECTOR_ELT(l, 2, rawof(f->fp, 32));
  SET_VECTOR_ELT(l, 3, Rf_ScalarReal((double)f->nb));
  SET_VECTOR_ELT(l, 4, Rf_ScalarReal((double)f->na));
  SET_VECTOR_ELT(l, 5, Rf_ScalarLogical(f->ca != 0));
  SET_VECTOR_ELT(l, 6, utf8(f->name));
  SET_VECTOR_ELT(l, 7, utf8(f->email));
  if (der != R_NilValue && f->pkoff + f->pklen <= rn(der))
    SET_VECTOR_ELT(l, 8, rawof(rp(der) + f->pkoff, f->pklen));
  else
    SET_VECTOR_ELT(l, 8, rawn(0));
  UNPROTECT(1);
  return l;
}

static SEXP Carmor(SEXP label, SEXP data) {
  const char *lab = sval(label, "label");
  size_t need = 0, on = 0;
  uint8_t *b;
  int rc;
  chkraw(data, "data", 0);
  if (lab == NULL) Rf_error("'label' must be one string");
  rc = nqarmlen(lab, rn(data), &need);
  if (rc != NQOK) fail(rc, "nqarmenc");
  b = xbuf(need);
  rc = nqarmenc(lab, rp(data), rn(data), (char *)b, need, &on);
  if (rc != NQOK) fail(rc, "nqarmenc");
  return strof(b, on);
}

static SEXP Cdearmor(SEXP text) {
  static const char *const nm[] = {"label", "data"};
  char lab[NQARMLAB];
  size_t on = 0;
  uint8_t *b;
  SEXP l;
  int rc;
  chkraw(text, "text", 0);
  b = xbuf(rn(text));
  lab[0] = '\0';
  rc = nqarmdec((const char *)rp(text), rn(text), lab, sizeof lab, b,
                rn(text), &on);
  if (rc != NQOK) fail(rc, "nqarmdec");
  l = PROTECT(nlist(nm, 2));
  SET_VECTOR_ELT(l, 0, Rf_mkString(lab));
  SET_VECTOR_ELT(l, 1, rawof(b, on));
  UNPROTECT(1);
  return l;
}

static SEXP Cx5self(SEXP alg, SEXP sk, SEXP pk, SEXP name, SEXP email,
                    SEXP nb, SEXP na) {
  const char *n = sval(name, "name"), *e = sval(email, "email");
  nqssz z;
  size_t cap, on = 0;
  uint8_t *b;
  int a = ival(alg, "alg"), rc;
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  if (n == NULL) Rf_error("'name' must be one string");
  if (nqssize((nqsalg)a, &z) != NQOK) fail(NQENOSUP, "nqx5self");
  cap = rn(pk) + z.sig + 2048;
  b = xbuf(cap);
  rc = nqx5self((nqsalg)a, rp(sk), rn(sk), rp(pk), rn(pk), n, e, tval(nb),
                tval(na), b, cap, &on);
  if (rc != NQOK) fail(rc, "nqx5self");
  return rawof(b, on);
}

static SEXP Cx5kem(SEXP ialg, SEXP isk, SEXP icert, SEXP alg, SEXP pk,
                   SEXP nb, SEXP na) {
  nqssz z;
  size_t cap, on = 0;
  uint8_t *b;
  int ia = ival(ialg, "issueralg"), a = ival(alg, "alg"), rc;
  chkraw(isk, "issuersk", 0);
  chkraw(icert, "issuercert", 0);
  chkraw(pk, "pk", 0);
  if (nqssize((nqsalg)ia, &z) != NQOK) fail(NQENOSUP, "nqx5kem");
  cap = rn(pk) + rn(icert) + z.sig + 2048;
  b = xbuf(cap);
  rc = nqx5kem((nqsalg)ia, rp(isk), rn(isk), rp(icert), rn(icert), (nqkalg)a,
               rp(pk), rn(pk), tval(nb), tval(na), b, cap, &on);
  if (rc != NQOK) fail(rc, "nqx5kem");
  return rawof(b, on);
}

static SEXP Cx5info(SEXP cert) {
  nqx5f f;
  int rc;
  chkraw(cert, "cert", 0);
  rc = nqx5info(rp(cert), rn(cert), &f);
  if (rc != NQOK) fail(rc, "nqx5info");
  return x5list(&f, cert);
}

/* mime: the S/MIME form, msg then the MIME entity */
static SEXP Ccmssign(SEXP alg, SEXP sk, SEXP cert, SEXP msg, SEXP detached,
                     SEXP at, SEXP mime) {
  nqssz z;
  size_t cap, on = 0;
  uint8_t *b;
  int a = ival(alg, "alg"), det = lval(detached, "detached"),
      mm = lval(mime, "mime"), rc;
  chkraw(sk, "sk", 0);
  chkraw(cert, "cert", 0);
  chkraw(msg, "msg", 0);
  if (nqssize((nqsalg)a, &z) != NQOK) fail(NQENOSUP, "nqcmssign");
  cap = 3 * rn(msg) + 2 * (rn(cert) + z.sig) + 8192;
  b = xbuf(cap);
  rc = mm ? nqsmsign((nqsalg)a, rp(sk), rn(sk), rp(cert), rn(cert),
                     (const char *)rp(msg), rn(msg), det, tval(at),
                     (char *)b, cap, &on)
          : nqcmssign((nqsalg)a, rp(sk), rn(sk), rp(cert), rn(cert), rp(msg),
                      rn(msg), det, tval(at), b, cap, &on);
  if (rc != NQOK) fail(rc, mm ? "nqsmsign" : "nqcmssign");
  return rawof(b, on);
}

/* list(rc, content, signer): NQOK, or NQEVRFY with NULLs */
static SEXP Ccmsvrfy(SEXP cms, SEXP msg, SEXP anchors, SEXP at, SEXP mime) {
  const uint8_t **ap;
  size_t *al, an, cap, on = 0;
  uint8_t *b;
  nqx5f f;
  SEXP out;
  int mm = lval(mime, "mime"), rc;
  chkraw(cms, "cms", 0);
  chkraw(msg, "msg", 1);
  an = rlist(anchors, "anchors", &ap, &al);
  memset(&f, 0, sizeof f);
  cap = rn(cms) + rn(msg) + 1;
  b = xbuf(cap);
  rc = mm ? nqsmvrfy((const char *)rp(cms), rn(cms), ap, al, an, tval(at),
                     (char *)b, cap, &on, &f)
          : nqcmsvrfy(rp(cms), rn(cms), rp(msg), rn(msg), ap, al, an,
                      tval(at), b, cap, &on, &f);
  if (rc != NQOK && rc != NQEVRFY) fail(rc, mm ? "nqsmvrfy" : "nqcmsvrfy");
  out = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) {
    SET_VECTOR_ELT(out, 1, rawof(b, on));
    SET_VECTOR_ELT(out, 2, x5list(&f, R_NilValue));
  }
  UNPROTECT(1);
  return out;
}

static SEXP Ccmsenc(SEXP certs, SEXP msg, SEXP mime) {
  const uint8_t **cp;
  size_t *cl, cn, cap, on = 0;
  uint8_t *b;
  int mm = lval(mime, "mime"), rc;
  chkraw(msg, "msg", 0);
  cn = rlist(certs, "certs", &cp, &cl);
  cap = 3 * rn(msg) + 2 * lsum(cl, cn) + 4096 * cn + 8192;
  b = xbuf(cap);
  rc = mm ? nqsmenc(cp, cl, cn, (const char *)rp(msg), rn(msg), (char *)b,
                    cap, &on)
          : nqcmsenc(cp, cl, cn, rp(msg), rn(msg), b, cap, &on);
  if (rc != NQOK) fail(rc, mm ? "nqsmenc" : "nqcmsenc");
  return rawof(b, on);
}

/* list(rc, content): NQOK, or NQEVRFY with NULL */
static SEXP Ccmsdec(SEXP alg, SEXP sk, SEXP cert, SEXP cms, SEXP mime) {
  size_t cap, on = 0;
  uint8_t *b;
  SEXP out;
  int a = ival(alg, "alg"), mm = lval(mime, "mime"), rc;
  chkraw(sk, "sk", 0);
  chkraw(cert, "cert", 1);
  chkraw(cms, "cms", 0);
  cap = rn(cms) + 1;
  b = xbuf(cap);
  rc = mm ? nqsmdec((nqkalg)a, rp(sk), rn(sk), rp(cert), rn(cert),
                    (const char *)rp(cms), rn(cms), (char *)b, cap, &on)
          : nqcmsdec((nqkalg)a, rp(sk), rn(sk), rp(cert), rn(cert), rp(cms),
                     rn(cms), b, cap, &on);
  if (rc != NQOK && rc != NQEVRFY) fail(rc, mm ? "nqsmdec" : "nqcmsdec");
  out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) SET_VECTOR_ELT(out, 1, rawof(b, on));
  UNPROTECT(1);
  return out;
}

#define PGPKEY ((size_t)1 << 18)

static SEXP Cpgpgen(SEXP sigalg, SEXP encalg, SEXP uid, SEXP created,
                    SEXP pw) {
  static const char *const nm[] = {"sec", "pub"};
  const char *u = sval(uid, "userid");
  uint8_t *s = xbuf(PGPKEY), *p = xbuf(PGPKEY);
  size_t sn = 0, pn = 0;
  SEXP l;
  int rc;
  chkraw(pw, "passphrase", 1);
  if (u == NULL) Rf_error("'userid' must be one string");
  rc = nqpgpgen(ival(sigalg, "alg"), ival(encalg, "encalg"), u, tval(created),
                rp(pw), rn(pw), s, PGPKEY, &sn, p, PGPKEY, &pn);
  if (rc != NQOK) {
    nqwipe(s, PGPKEY);
    fail(rc, "nqpgpgen");
  }
  l = PROTECT(nlist(nm, 2));
  SET_VECTOR_ELT(l, 0, rawof(s, sn));
  SET_VECTOR_ELT(l, 1, rawof(p, pn));
  nqwipe(s, PGPKEY);
  UNPROTECT(1);
  return l;
}

static SEXP Cpgpinfo(SEXP key) {
  static const char *const nm[] = {"alg", "encalg", "secret", "locked",
                                   "fingerprint", "encfingerprint",
                                   "created", "expires", "userid"};
  nqpgpk f;
  SEXP l;
  int rc;
  chkraw(key, "key", 0);
  rc = nqpgpinfo(rp(key), rn(key), &f);
  if (rc != NQOK) fail(rc, "nqpgpinfo");
  l = PROTECT(nlist(nm, 9));
  SET_VECTOR_ELT(l, 0, Rf_ScalarInteger(f.alg));
  SET_VECTOR_ELT(l, 1, Rf_ScalarInteger(f.encalg));
  SET_VECTOR_ELT(l, 2, Rf_ScalarLogical(f.secret != 0));
  SET_VECTOR_ELT(l, 3, Rf_ScalarLogical(f.locked != 0));
  SET_VECTOR_ELT(l, 4, rawof(f.fp, 32));
  SET_VECTOR_ELT(l, 5, f.encalg != 0 ? rawof(f.encfp, 32) : R_NilValue);
  SET_VECTOR_ELT(l, 6, Rf_ScalarReal((double)f.created));
  SET_VECTOR_ELT(l, 7, f.expires != 0 ? Rf_ScalarReal((double)f.expires)
                                      : R_NilValue);
  SET_VECTOR_ELT(l, 8, utf8(f.uid));
  UNPROTECT(1);
  return l;
}

static SEXP Cpgpsign(SEXP key, SEXP pw, SEXP msg, SEXP mode, SEXP at) {
  size_t cap, on = 0;
  uint8_t *b;
  int rc;
  chkraw(key, "key", 0);
  chkraw(pw, "passphrase", 1);
  chkraw(msg, "msg", 0);
  cap = 3 * rn(msg) + ((size_t)1 << 17);
  b = xbuf(cap);
  rc = nqpgpsign(rp(key), rn(key), rp(pw), rn(pw), rp(msg), rn(msg),
                 ival(mode, "mode"), tval(at), b, cap, &on);
  if (rc != NQOK) fail(rc, "nqpgpsign");
  return rawof(b, on);
}

/* list(rc, data, at): NQOK, or NQEVRFY with NULLs */
static SEXP Cpgpvrfy(SEXP cert, SEXP sig, SEXP msg) {
  size_t cap, on = 0;
  uint8_t *b;
  int64_t at = 0;
  SEXP out;
  int rc;
  chkraw(cert, "cert", 0);
  chkraw(sig, "sig", 0);
  chkraw(msg, "msg", 1);
  cap = rn(sig) + rn(msg) + 1;
  b = xbuf(cap);
  /* a raw(0) message is still a message: R's NULL alone means none */
  rc = nqpgpvrfy(rp(cert), rn(cert), rp(sig), rn(sig),
                 msg == R_NilValue ? NULL
                 : rn(msg) > 0     ? rp(msg)
                                   : (const uint8_t *)"",
                 rn(msg), b, cap, &on, &at);
  if (rc != NQOK && rc != NQEVRFY) fail(rc, "nqpgpvrfy");
  out = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) {
    SET_VECTOR_ELT(out, 1, rawof(b, on));
    SET_VECTOR_ELT(out, 2, Rf_ScalarReal((double)at));
  }
  UNPROTECT(1);
  return out;
}

static SEXP Cpgpenc(SEXP certs, SEXP pw, SEXP signer, SEXP spw, SEXP msg,
                    SEXP at) {
  const uint8_t **cp;
  size_t *cl, cn, cap, on = 0;
  uint8_t *b;
  int rc;
  chkraw(pw, "passphrase", 1);
  chkraw(signer, "signer", 1);
  chkraw(spw, "signerpass", 1);
  chkraw(msg, "msg", 0);
  cn = rlist(certs, "certs", &cp, &cl);
  cap = rn(msg) + rn(msg) / 512 + 2048 * cn + ((size_t)1 << 17);
  b = xbuf(cap);
  rc = nqpgpenc(cp, cl, cn, rp(pw), rn(pw), rp(signer), rn(signer), rp(spw),
                rn(spw), rp(msg), rn(msg), tval(at), b, cap, &on);
  if (rc != NQOK) fail(rc, "nqpgpenc");
  return rawof(b, on);
}

/* list(rc, data, signed, at): NQOK, or NQEVRFY with NULLs */
static SEXP Cpgpdec(SEXP key, SEXP pw, SEXP signer, SEXP msg) {
  size_t cap, on = 0;
  uint8_t *b;
  int64_t at = 0;
  SEXP out;
  int sb = 0, rc;
  chkraw(key, "key", 1);
  chkraw(pw, "passphrase", 1);
  chkraw(signer, "signer", 1);
  chkraw(msg, "msg", 0);
  cap = rn(msg) + 1;
  b = xbuf(cap);
  rc = nqpgpdec(rp(key), rn(key), rp(pw), rn(pw), rp(signer), rn(signer),
                rp(msg), rn(msg), b, cap, &on, &sb, &at);
  if (rc != NQOK && rc != NQEVRFY) fail(rc, "nqpgpdec");
  out = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
  if (rc == NQOK) {
    SET_VECTOR_ELT(out, 1, rawof(b, on));
    SET_VECTOR_ELT(out, 2, Rf_ScalarLogical(sb != 0));
    SET_VECTOR_ELT(out, 3, Rf_ScalarReal((double)at));
  }
  UNPROTECT(1);
  return out;
}

static SEXP Cpgparm(SEXP kind, SEXP data) {
  size_t need = 0, on = 0;
  uint8_t *b;
  int k = ival(kind, "kind"), rc;
  chkraw(data, "data", 0);
  rc = nqpgparm(k, rp(data), rn(data), NULL, 0, &need);
  if (rc != NQOK) fail(rc, "nqpgparm");
  b = xbuf(need);
  rc = nqpgparm(k, rp(data), rn(data), (char *)b, need, &on);
  if (rc != NQOK) fail(rc, "nqpgparm");
  return strof(b, on);
}

static SEXP Cpgpdearm(SEXP text) {
  static const char *const nm[] = {"kind", "data"};
  size_t on = 0;
  uint8_t *b;
  SEXP l;
  int kind = 0, rc;
  chkraw(text, "text", 0);
  b = xbuf(rn(text));
  rc = nqpgpdearm((const char *)rp(text), rn(text), &kind, b, rn(text), &on);
  if (rc != NQOK) fail(rc, "nqpgpdearm");
  l = PROTECT(nlist(nm, 2));
  SET_VECTOR_ELT(l, 0, Rf_ScalarInteger(kind));
  SET_VECTOR_ELT(l, 1, rawof(b, on));
  UNPROTECT(1);
  return l;
}

/* a fingerprint: a raw vector of 32 */
static const uint8_t *fpval(SEXP fp) {
  if (TYPEOF(fp) != RAWSXP || XLENGTH(fp) != 32)
    Rf_error("'fingerprint' must be a raw vector of 32 bytes");
  return RAW(fp);
}

static SEXP Cksadd(SEXP dir, SEXP kem, SEXP alg, SEXP pk, SEXP name,
                   SEXP email, SEXP card) {
  const char *d = rpath(dir), *n = sval(name, "name"),
             *e = sval(email, "email");
  uint8_t fp[32];
  int rc;
  chkraw(pk, "pk", 0);
  chkraw(card, "card", 1);
  if (n == NULL) Rf_error("'name' must be one string");
  rc = nqksadd(d, lval(kem, "kem"), ival(alg, "alg"), rp(pk), rn(pk), n, e,
               (const char *)rp(card), rn(card), fp);
  if (rc != NQOK) fail(rc, "nqksadd");
  return rawof(fp, 32);
}

/* list(kem, alg, fingerprint, name, email, card, trust, valid, certs),
 * one element a key in each */
static SEXP Ckslist(SEXP dir, SEXP q) {
  const char *d = rpath(dir), *qs = sval(q, "query");
  nqkse *e = NULL;
  size_t n = 0, cap, i;
  SEXP out, c[9];
  int rc, j;
  rc = nqkslist(d, qs, NULL, 0, &n);
  if (rc != NQOK && rc != NQEBUF) fail(rc, "nqkslist");
  cap = n;
  if (cap > 0) {
    e = (nqkse *)R_alloc(cap, sizeof *e);
    rc = nqkslist(d, qs, e, cap, &n);
    if (rc != NQOK && rc != NQEBUF) fail(rc, "nqkslist");
    if (n > cap) n = cap;
  }
  out = PROTECT(Rf_allocVector(VECSXP, 9));
  for (j = 0; j < 9; j++) {
    c[j] = Rf_allocVector(j == 0 || j == 5   ? LGLSXP
                          : j == 1 || j >= 6 ? INTSXP
                          : j == 2           ? VECSXP
                                             : STRSXP,
                          (R_xlen_t)n);
    SET_VECTOR_ELT(out, j, c[j]);
  }
  for (i = 0; i < n; i++) {
    const char *an = e[i].kem ? nqkname((nqkalg)e[i].alg)
                              : nqsname((nqsalg)e[i].alg);
    LOGICAL(c[0])[i] = e[i].kem != 0;
    INTEGER(c[1])[i] = e[i].alg;
    SET_VECTOR_ELT(c[2], (R_xlen_t)i, rawof(e[i].fp, 32));
    SET_STRING_ELT(c[3], (R_xlen_t)i, Rf_mkCharCE(e[i].name, CE_UTF8));
    SET_STRING_ELT(c[4], (R_xlen_t)i, Rf_mkCharCE(e[i].email, CE_UTF8));
    LOGICAL(c[5])[i] = e[i].card != 0;
    INTEGER(c[6])[i] = e[i].trust;
    INTEGER(c[7])[i] = e[i].valid;
    INTEGER(c[8])[i] = (int)e[i].ncert;
    (void)an;
  }
  UNPROTECT(1);
  return out;
}

static SEXP Cksget(SEXP dir, SEXP fp) {
  static const char *const nm[] = {"kem", "alg", "pk"};
  const char *d = rpath(dir);
  uint8_t *b = xbuf(65536);
  size_t on = 0;
  SEXP l;
  int kem = 0, alg = 0, rc;
  rc = nqksget(d, fpval(fp), &kem, &alg, b, 65536, &on);
  if (rc != NQOK) fail(rc, "nqksget");
  l = PROTECT(nlist(nm, 3));
  SET_VECTOR_ELT(l, 0, Rf_ScalarLogical(kem != 0));
  SET_VECTOR_ELT(l, 1, Rf_ScalarInteger(alg));
  SET_VECTOR_ELT(l, 2, rawof(b, on));
  UNPROTECT(1);
  return l;
}

static SEXP Ckscert(SEXP dir, SEXP alg, SEXP sk, SEXP pk, SEXP fp, SEXP at) {
  const char *d = rpath(dir);
  nqssz z;
  size_t cap, on = 0;
  uint8_t *b;
  int a = ival(alg, "alg"), rc;
  chkraw(sk, "sk", 0);
  chkraw(pk, "pk", 0);
  if (nqssize((nqsalg)a, &z) != NQOK) fail(NQENOSUP, "nqkscert");
  cap = 2 * z.sig + 4096;
  b = xbuf(cap);
  rc = nqkscert(d, (nqsalg)a, rp(sk), rn(sk), rp(pk), rn(pk), fpval(fp),
                tval(at), (char *)b, cap, &on);
  if (rc != NQOK) fail(rc, "nqkscert");
  return strof(b, on);
}

/* op 0: a certification into the store (a its text); 1: trust of the
 * key a at level; 2: the key a removed */
static SEXP Cksop(SEXP op, SEXP dir, SEXP a, SEXP level) {
  const char *d = rpath(dir);
  int o = ival(op, "op"), rc;
  if (o == 0) {
    chkraw(a, "cert", 0);
    rc = nqkscput(d, (const char *)rp(a), rn(a));
  } else if (o == 1) {
    rc = nqkstrust(d, fpval(a), ival(level, "level"));
  } else {
    rc = nqksdel(d, fpval(a));
  }
  if (rc != NQOK)
    fail(rc, o == 0 ? "nqkscput" : o == 1 ? "nqkstrust" : "nqksdel");
  return R_NilValue;
}

static SEXP Cksexp(SEXP dir, SEXP fp) {
  const char *d = rpath(dir);
  const uint8_t *f = fpval(fp);
  size_t need = 0, on = 0;
  uint8_t *b;
  int rc = nqksexp(d, f, NULL, 0, &need);
  if (rc != NQOK && rc != NQEBUF) fail(rc, "nqksexp");
  b = xbuf(need + 1);
  rc = nqksexp(d, f, (char *)b, need + 1, &on);
  if (rc != NQOK) fail(rc, "nqksexp");
  return strof(b, on);
}

static SEXP Cksimp(SEXP dir, SEXP bundle, SEXP email) {
  static const char *const nm[] = {"fingerprint", "keys"};
  const char *d = rpath(dir), *e = sval(email, "email");
  uint8_t fp[32];
  size_t n = 0;
  SEXP l;
  int rc;
  chkraw(bundle, "bundle", 0);
  memset(fp, 0, sizeof fp);
  rc = nqksimp(d, (const char *)rp(bundle), rn(bundle), e, fp, &n);
  if (rc != NQOK) fail(rc, "nqksimp");
  l = PROTECT(nlist(nm, 2));
  SET_VECTOR_ELT(l, 0, rawof(fp, 32));
  SET_VECTOR_ELT(l, 1, Rf_ScalarInteger((int)n));
  UNPROTECT(1);
  return l;
}

static SEXP Cksurl(SEXP email) {
  const char *e = sval(email, "email");
  char u[512];
  int rc;
  if (e == NULL) Rf_error("'email' must be one string");
  rc = nqksurl(e, u, sizeof u);
  if (rc != NQOK) fail(rc, "nqksurl");
  return Rf_mkString(u);
}

/* a token handle: an external pointer, closed by nqp11close or when
 * collected */
static void p11fin(SEXP x) {
  nqp11 *p = (nqp11 *)R_ExternalPtrAddr(x);
  if (p != NULL) {
    nqp11close(p);
    R_ClearExternalPtr(x);
  }
}

static nqp11 *p11of(SEXP x) {
  nqp11 *p;
  if (TYPEOF(x) != EXTPTRSXP) Rf_error("'token' is not a token");
  p = (nqp11 *)R_ExternalPtrAddr(x);
  if (p == NULL) Rf_error("the token is closed");
  return p;
}

NORET static void p11fail(nqp11 *p, int rc, const char *what) {
  if (rc == NQEIO || rc == NQENOSUP)
    Rf_error("noqtis: %s: %s (CKR 0x%lx)", what, nqerr(rc), nqp11why(p));
  fail(rc, what);
}

static SEXP Cp11open(SEXP module) {
  const char *m = rpath(module);
  nqp11 *p = NULL;
  SEXP x;
  int rc = nqp11open(m, &p);
  if (rc != NQOK) fail(rc, "nqp11open");
  x = PROTECT(R_MakeExternalPtr(p, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(x, p11fin, TRUE);
  UNPROTECT(1);
  return x;
}

static SEXP Cp11close(SEXP x) {
  if (TYPEOF(x) != EXTPTRSXP) Rf_error("'token' is not a token");
  p11fin(x);
  return R_NilValue;
}

/* list(slot, label, maker, model, serial, login) */
static SEXP Cp11toks(SEXP x) {
  nqp11 *p = p11of(x);
  nqp11t *t = (nqp11t *)R_alloc(64, sizeof *t);
  size_t n = 0, i;
  SEXP out, c[6];
  int rc = nqp11toks(p, t, 64, &n), j;
  if (rc != NQOK) p11fail(p, rc, "nqp11toks");
  if (n > 64) n = 64;
  out = PROTECT(Rf_allocVector(VECSXP, 6));
  for (j = 0; j < 6; j++) {
    c[j] = Rf_allocVector(j == 0 ? REALSXP : j == 5 ? LGLSXP : STRSXP,
                          (R_xlen_t)n);
    SET_VECTOR_ELT(out, j, c[j]);
  }
  for (i = 0; i < n; i++) {
    REAL(c[0])[i] = (double)t[i].slot;
    SET_STRING_ELT(c[1], (R_xlen_t)i, Rf_mkChar(t[i].label));
    SET_STRING_ELT(c[2], (R_xlen_t)i, Rf_mkChar(t[i].maker));
    SET_STRING_ELT(c[3], (R_xlen_t)i, Rf_mkChar(t[i].model));
    SET_STRING_ELT(c[4], (R_xlen_t)i, Rf_mkChar(t[i].serial));
    LOGICAL(c[5])[i] = t[i].login != 0;
  }
  UNPROTECT(1);
  return out;
}

static unsigned long ulval(SEXP x, const char *what) {
  double v;
  if (TYPEOF(x) != REALSXP || XLENGTH(x) != 1 || !R_FINITE(REAL(x)[0]))
    Rf_error("'%s' must be one number", what);
  v = REAL(x)[0];
  if (v < 0 || v > 4294967295.0 || v != (double)(unsigned long)v)
    Rf_error("'%s' must be a whole number from 0", what);
  return (unsigned long)v;
}

static SEXP Cp11login(SEXP x, SEXP slot, SEXP pin) {
  nqp11 *p = p11of(x);
  const char *pn = sval(pin, "pin");
  int rc = nqp11login(p, ulval(slot, "slot"), pn, pn != NULL ? strlen(pn) : 0);
  if (rc != NQOK) p11fail(p, rc, "nqp11login");
  return R_NilValue;
}

/* list(kem, alg, handle, label, id) of n keys */
static SEXP p11klist(const nqp11k *k, size_t n) {
  SEXP out = PROTECT(Rf_allocVector(VECSXP, 5)), c[5];
  size_t i;
  int j;
  for (j = 0; j < 5; j++) {
    c[j] = Rf_allocVector(j == 0   ? LGLSXP
                          : j == 1 ? INTSXP
                          : j == 2 ? REALSXP
                          : j == 3 ? STRSXP
                                   : VECSXP,
                          (R_xlen_t)n);
    SET_VECTOR_ELT(out, j, c[j]);
  }
  for (i = 0; i < n; i++) {
    LOGICAL(c[0])[i] = k[i].kem != 0;
    INTEGER(c[1])[i] = k[i].alg;
    REAL(c[2])[i] = (double)k[i].h;
    SET_STRING_ELT(c[3], (R_xlen_t)i, Rf_mkCharCE(k[i].label, CE_UTF8));
    SET_VECTOR_ELT(c[4], (R_xlen_t)i, rawof(k[i].id, k[i].idlen));
  }
  UNPROTECT(1);
  return out;
}

static SEXP Cp11keys(SEXP x) {
  nqp11 *p = p11of(x);
  nqp11k *k = (nqp11k *)R_alloc(64, sizeof *k);
  size_t n = 0;
  int rc = nqp11keys(p, k, 64, &n);
  if (rc != NQOK && rc != NQEBUF) p11fail(p, rc, "nqp11keys");
  return p11klist(k, n > 64 ? 64 : n);
}

/* op 0: the public key; 1: a signature of data under ctx; 2: the
 * shared secret of the ciphertext data */
static SEXP Cp11use(SEXP x, SEXP op, SEXP kem, SEXP alg, SEXP h, SEXP id,
                    SEXP data, SEXP ctx) {
  nqp11 *p = p11of(x);
  nqp11k k;
  nqssz z;
  nqksz kz;
  size_t on = 0;
  uint8_t *b;
  int o = ival(op, "op"), rc;
  chkraw(id, "id", 0);
  chkraw(data, "data", 1);
  chkraw(ctx, "ctx", 1);
  memset(&k, 0, sizeof k);
  k.kem = lval(kem, "kem");
  k.alg = ival(alg, "alg");
  k.h = ulval(h, "handle");
  if (rn(id) > sizeof k.id) Rf_error("'id' is at most 32 bytes");
  if (rn(id) > 0) memcpy(k.id, rp(id), rn(id));
  k.idlen = rn(id);
  if (o == 0) {
    b = xbuf(4096);
    rc = nqp11pub(p, &k, b, 4096, &on);
    if (rc != NQOK) p11fail(p, rc, "nqp11pub");
  } else if (o == 1) {
    if (k.kem || nqssize((nqsalg)k.alg, &z) != NQOK)
      Rf_error("the key is not a signature key");
    b = xbuf(z.sig);
    rc = nqp11sign(p, &k, rp(data), rn(data), rp(ctx), rn(ctx), b, z.sig, &on);
    if (rc != NQOK) p11fail(p, rc, "nqp11sign");
  } else {
    if (!k.kem || nqksize((nqkalg)k.alg, &kz) != NQOK)
      Rf_error("the key is not a KEM key");
    b = xbuf(kz.ss);
    rc = nqp11dec(p, &k, rp(data), rn(data), b, kz.ss);
    if (rc != NQOK) p11fail(p, rc, "nqp11dec");
    on = kz.ss;
  }
  return rawof(b, on);
}

static SEXP Cp11gen(SEXP x, SEXP kem, SEXP alg, SEXP label) {
  nqp11 *p = p11of(x);
  const char *l = sval(label, "label");
  nqp11k k;
  int rc;
  if (l == NULL) Rf_error("'label' must be one string");
  rc = nqp11gen(p, lval(kem, "kem"), ival(alg, "alg"), l, &k);
  if (rc != NQOK) p11fail(p, rc, "nqp11gen");
  return p11klist(&k, 1);
}

#define CDEF(f, n) {#f, (DL_FUNC)(void (*)(void))&f, n}

static const R_CallMethodDef calls[] = {
  CDEF(Cver, 0),  CDEF(Cself, 0), CDEF(Calgs, 0), CDEF(Crand, 1), CDEF(Chash, 3),
  CDEF(Chini, 1), CDEF(Chupd, 2), CDEF(Chfin, 2), CDEF(Chmac, 3),
  CDEF(Ckg, 3),   CDEF(Csign, 6), CDEF(Cvrfy, 6), CDEF(Cenc, 3),
  CDEF(Cdec, 3),  CDEF(Cseal, 5), CDEF(Cchk, 7),  CDEF(Cerr, 1),
  CDEF(Cseal2, 7), CDEF(Ccapid, 1), CDEF(Cprove, 2), CDEF(Cfiles, 1),
  CDEF(Ckstmt, 8), CDEF(Cdsse, 5), CDEF(Cdssevrfy, 3),
  CDEF(Ccard, 9), CDEF(Ccardvrfy, 2),
  CDEF(Cdload, 1), CDEF(Cdput, 3), CDEF(Cdadd, 4), CDEF(Cddel, 3),
  CDEF(Cdkey, 3), CDEF(Cdaddr, 2), CDEF(Cdvrfy, 3), CDEF(Cdfld, 4),
  CDEF(Cdrslv, 1), CDEF(Cdrsp, 2), CDEF(Cdwb, 1), CDEF(Cdchk, 1), CDEF(Cdinfer, 5), CDEF(Cdstats, 4),
  CDEF(Cddrift, 6), CDEF(Cdsha, 2), CDEF(Cddiff, 2),
  CDEF(Cb2b, 3), CDEF(Ca2id, 6), CDEF(Ccteq, 2), CDEF(Cpwenc, 4),
  CDEF(Ckt, 4), CDEF(Ccha20, 4), CDEF(Csiv, 4), CDEF(Cgsiv, 5),
  CDEF(Cpwdec, 3), CDEF(Csmu, 5), CDEF(Csignmu, 4), CDEF(Cvrfymu, 4),
  CDEF(Csini, 5), CDEF(Csupd, 2), CDEF(Csfin, 4), CDEF(Cvfin, 3),
  CDEF(Ckseal, 4), CDEF(Ckopen, 4), CDEF(Ckfeini, 4), CDEF(Ckfdini, 4),
  CDEF(Ckfupd, 5), CDEF(Ckmpeek, 1), CDEF(Ckmeini, 5), CDEF(Ckmdini, 4),
  CDEF(Ckmupd, 6), CDEF(Cinsp, 1), CDEF(Csealwhy, 1), CDEF(Ctsreq, 4),
  CDEF(Ctsput, 6), CDEF(Cdparse, 1), CDEF(Cdschk, 2), CDEF(Cdsyn, 4),
  CDEF(Cdcal, 4), CDEF(Cdchunk, 3), CDEF(Cdpiece, 3), CDEF(Cdcommit, 2),
  CDEF(Cdreveal, 3), CDEF(Cdcite, 2), CDEF(Cdrpt, 5), CDEF(Cdpack, 3),
  CDEF(Cdunpack, 3), CDEF(Cdchain, 2), CDEF(Calfail, 1),
  CDEF(Cctxbad, 1),
  CDEF(Carmor, 2), CDEF(Cdearmor, 1), CDEF(Cx5self, 7), CDEF(Cx5kem, 7),
  CDEF(Cx5info, 1), CDEF(Ccmssign, 7), CDEF(Ccmsvrfy, 5), CDEF(Ccmsenc, 3),
  CDEF(Ccmsdec, 5), CDEF(Cpgpgen, 5), CDEF(Cpgpinfo, 1), CDEF(Cpgpsign, 5),
  CDEF(Cpgpvrfy, 3), CDEF(Cpgpenc, 6), CDEF(Cpgpdec, 4), CDEF(Cpgparm, 2),
  CDEF(Cpgpdearm, 1), CDEF(Cksadd, 7), CDEF(Ckslist, 2), CDEF(Cksget, 2),
  CDEF(Ckscert, 6), CDEF(Cksop, 4), CDEF(Cksexp, 2), CDEF(Cksimp, 3),
  CDEF(Cksurl, 1), CDEF(Cp11open, 1), CDEF(Cp11close, 1), CDEF(Cp11toks, 1),
  CDEF(Cp11login, 3), CDEF(Cp11keys, 1), CDEF(Cp11use, 8), CDEF(Cp11gen, 4),
  {NULL, NULL, 0}
};

void R_init_noqtis(DllInfo *dll);

void R_init_noqtis(DllInfo *dll) {
  R_registerRoutines(dll, NULL, calls, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}
