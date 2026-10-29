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

static void fail(int rc, const char *what) {
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
  SEXP sig, out;
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
  if (n == s.sig) {
    UNPROTECT(1);
    return sig;
  }
  out = rawn(n);
  if (n > 0) memcpy(RAW(out), RAW(sig), n);
  UNPROTECT(1);
  return out;
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

/* list(rc, check, ok, detail); the report is held by an external pointer
 * with a finalizer while R vectors are allocated, so an allocation error
 * cannot leak it. */
static SEXP Cchk(SEXP dir, SEXP pk, SEXP anc) {
  const uint8_t *ap[32];
  size_t al[32], n, i, na = 0;
  const char *d, *c, *t;
  nqrep *r = NULL;
  int rc, ok;
  SEXP p, out, ck, okv, dt;
  chkraw(pk, "pk", 1);
  if (anc != R_NilValue) {
    if (TYPEOF(anc) != VECSXP) Rf_error("'anchors' must be a list");
    na = (size_t)XLENGTH(anc);
    if (na > 32) Rf_error("at most 32 anchors");
    for (i = 0; i < na; i++) {
      SEXP e = VECTOR_ELT(anc, (R_xlen_t)i);
      chkraw(e, "anchors[[i]]", 0);
      ap[i] = rp(e);
      al[i] = rn(e);
    }
  }
  d = rpath(dir);
  p = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(p, repfin, TRUE);
  if (na > 0) {
    rc = nqchkt(d, rp(pk), rn(pk), ap, al, na, &r);
  } else {
    rc = nqchk(d, rp(pk), rn(pk), &r);
  }
  R_SetExternalPtrAddr(p, r);
  if (r == NULL) {
    UNPROTECT(1);
    fail(rc == NQOK ? NQEMEM : rc, "nqchk");
  }
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
  UNPROTECT(2);
  return out;
}

static SEXP Cerr(SEXP rc) {
  return Rf_mkString(nqerr(ival(rc, "rc")));
}

/* ---- registration -------------------------------------------------- */

/* through void (*)(void), the generic function pointer type the compilers
 * accept a cast from without -Wcast-function-type */
#define CDEF(f, n) {#f, (DL_FUNC)(void (*)(void))&f, n}

static const R_CallMethodDef calls[] = {
  CDEF(Cver, 0),  CDEF(Calgs, 0), CDEF(Crand, 1), CDEF(Chash, 3),
  CDEF(Chini, 1), CDEF(Chupd, 2), CDEF(Chfin, 2), CDEF(Chmac, 3),
  CDEF(Ckg, 3),   CDEF(Csign, 6), CDEF(Cvrfy, 6), CDEF(Cenc, 3),
  CDEF(Cdec, 3),  CDEF(Cseal, 5), CDEF(Cchk, 3),  CDEF(Cerr, 1),
  {NULL, NULL, 0}
};

void R_init_noqtis(DllInfo *dll);

void R_init_noqtis(DllInfo *dll) {
  R_registerRoutines(dll, NULL, calls, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}
