/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis._noqtis: the C side of the Python package, on the public API of
 * noqtis.h only. The limited API (abi3, Python 3.9+): inputs arrive as
 * bytes (the Python layer copies bytearray and memoryview), outputs are
 * new bytes objects the library writes into, and every library call runs
 * with the GIL released. Errors raise the class the Python layer
 * registered for the NQE* code (see noqtis/_err.py).
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <string.h>

#include "noqtis.h"
#include "nqd.h"

static PyObject *errmap; /* {code: class}, from setup() */

/* the class for code c, borrowed; NULL if none */
static PyObject *ecls(long c) {
  PyObject *k, *cls;
  if (errmap == NULL) return NULL;
  k = PyLong_FromLong(c);
  if (k == NULL) return NULL;
  cls = PyDict_GetItem(errmap, k);
  Py_DECREF(k);
  return cls;
}

static PyObject *fail(int rc) {
  PyObject *cls, *e;
  const char *m = nqerr(rc);
  if (PyErr_Occurred()) return NULL;
  cls = ecls(rc);
  if (cls == NULL) cls = ecls(0); /* the base class */
  if (cls == NULL) {
    PyErr_Format(PyExc_RuntimeError, "noqtis: %s (%d)", m ? m : "?", rc);
    return NULL;
  }
  e = PyObject_CallFunction(cls, "is", rc, m ? m : "unknown error");
  if (e == NULL) return NULL;
  PyErr_SetObject(cls, e);
  Py_DECREF(e);
  return NULL;
}

/* a new bytes object of n bytes for the library to fill */
static PyObject *obuf(size_t n, uint8_t **p) {
  PyObject *b = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)n);
  if (b == NULL) return NULL;
  *p = (uint8_t *)PyBytes_AsString(b);
  if (*p == NULL) {
    Py_DECREF(b);
    return NULL;
  }
  memset(*p, 0, n);
  return b;
}

/* drops a secret output after wiping it */
static void sdrop(PyObject *b) {
  char *p;
  if (b == NULL) return;
  p = PyBytes_AsString(b);
  if (p != NULL) nqwipe(p, (size_t)PyBytes_Size(b));
  Py_DECREF(b);
}

#define U8(p) ((const uint8_t *)(p))
#define SZ(n) ((size_t)(n))

static PyObject *psetup(PyObject *self, PyObject *arg) {
  (void)self;
  if (!PyDict_Check(arg)) {
    PyErr_SetString(PyExc_TypeError, "setup: a dict");
    return NULL;
  }
  Py_INCREF(arg);
  Py_XDECREF(errmap);
  errmap = arg;
  Py_RETURN_NONE;
}

static PyObject *pver(PyObject *self, PyObject *noarg) {
  (void)self;
  (void)noarg;
  return PyUnicode_FromString(nqver());
}

static PyObject *pself(PyObject *self, PyObject *noarg) {
  int rc;
  (void)self;
  (void)noarg;
  Py_BEGIN_ALLOW_THREADS
  rc = nqselftest();
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* [(id, name, pk, sk, sig)] */
static PyObject *psalgs(PyObject *self, PyObject *noarg) {
  PyObject *l = PyList_New(0), *t;
  int i;
  (void)self;
  (void)noarg;
  if (l == NULL) return NULL;
  for (i = 1; i < 64; i++) {
    nqssz z;
    const char *n = nqsname((nqsalg)i);
    if (n == NULL || nqssize((nqsalg)i, &z) != NQOK) break;
    t = Py_BuildValue("(isnnn)", i, n, (Py_ssize_t)z.pk, (Py_ssize_t)z.sk,
                      (Py_ssize_t)z.sig);
    if (t == NULL || PyList_Append(l, t) != 0) {
      Py_XDECREF(t);
      Py_DECREF(l);
      return NULL;
    }
    Py_DECREF(t);
  }
  return l;
}

/* [(id, name, pk, sk, ct, ss)] */
static PyObject *pkalgs(PyObject *self, PyObject *noarg) {
  PyObject *l = PyList_New(0), *t;
  int i;
  (void)self;
  (void)noarg;
  if (l == NULL) return NULL;
  for (i = 1; i < 64; i++) {
    nqksz z;
    const char *n = nqkname((nqkalg)i);
    if (n == NULL || nqksize((nqkalg)i, &z) != NQOK) break;
    t = Py_BuildValue("(isnnnn)", i, n, (Py_ssize_t)z.pk, (Py_ssize_t)z.sk,
                      (Py_ssize_t)z.ct, (Py_ssize_t)z.ss);
    if (t == NULL || PyList_Append(l, t) != 0) {
      Py_XDECREF(t);
      Py_DECREF(l);
      return NULL;
    }
    Py_DECREF(t);
  }
  return l;
}

/* ---- signatures ---- */

/* skg(alg, seed or None) -> (pk, sk) */
static PyObject *pskg(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *seed = NULL;
  Py_ssize_t sl = 0;
  nqssz z;
  PyObject *pk, *sk;
  uint8_t *p, *s;
  (void)self;
  if (!PyArg_ParseTuple(args, "iz#", &alg, &seed, &sl)) return NULL;
  rc = nqssize((nqsalg)alg, &z);
  if (rc != NQOK) return fail(rc);
  pk = obuf(z.pk, &p);
  if (pk == NULL) return NULL;
  sk = obuf(z.sk, &s);
  if (sk == NULL) {
    Py_DECREF(pk);
    return NULL;
  }
  Py_BEGIN_ALLOW_THREADS
  if (seed != NULL)
    rc = nqskgd((nqsalg)alg, U8(seed), SZ(sl), p, z.pk, s, z.sk);
  else
    rc = nqskg((nqsalg)alg, p, z.pk, s, z.sk);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(pk);
    sdrop(sk);
    return fail(rc);
  }
  return Py_BuildValue("(NN)", pk, sk);
}

/* sign(alg, sk, msg, ctx, ph, rnd or None) -> sig */
static PyObject *psign(PyObject *self, PyObject *args) {
  int alg, ph, rc;
  const char *sk, *msg, *ctx, *rnd = NULL;
  Py_ssize_t skl, ml, cl, rl = 0;
  size_t on = 0;
  nqssz z;
  PyObject *sig, *r;
  uint8_t *o;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#iz#", &alg, &sk, &skl, &msg, &ml,
                        &ctx, &cl, &ph, &rnd, &rl))
    return NULL;
  rc = nqssize((nqsalg)alg, &z);
  if (rc != NQOK) return fail(rc);
  sig = obuf(z.sig, &o);
  if (sig == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  if (rnd != NULL)
    rc = nqsignd((nqsalg)alg, U8(sk), SZ(skl), U8(msg), SZ(ml), U8(ctx),
                 SZ(cl), ph, U8(rnd), SZ(rl), o, z.sig, &on);
  else
    rc = nqsign((nqsalg)alg, U8(sk), SZ(skl), U8(msg), SZ(ml), U8(ctx),
                SZ(cl), ph, o, z.sig, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(sig);
    return fail(rc);
  }
  if (on == z.sig) return sig;
  r = PyBytes_FromStringAndSize((const char *)o, (Py_ssize_t)on);
  Py_DECREF(sig);
  return r;
}

/* vrfy(alg, pk, msg, ctx, ph, sig) -> NQOK, NQEVRFY or NQEDEC; any other
 * code raises */
static PyObject *pvrfy(PyObject *self, PyObject *args) {
  int alg, ph, rc;
  const char *pk, *msg, *ctx, *sig;
  Py_ssize_t pl, ml, cl, sl;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#iy#", &alg, &pk, &pl, &msg, &ml,
                        &ctx, &cl, &ph, &sig, &sl))
    return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqvrfy((nqsalg)alg, U8(pk), SZ(pl), U8(msg), SZ(ml), U8(ctx),
              SZ(cl), ph, U8(sig), SZ(sl));
  Py_END_ALLOW_THREADS
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) return fail(rc);
  return PyLong_FromLong(rc);
}

/* ---- key encapsulation ---- */

/* kkg(alg, seed or None) -> (pk, sk) */
static PyObject *pkkg(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *seed = NULL;
  Py_ssize_t sl = 0;
  nqksz z;
  PyObject *pk, *sk;
  uint8_t *p, *s;
  (void)self;
  if (!PyArg_ParseTuple(args, "iz#", &alg, &seed, &sl)) return NULL;
  rc = nqksize((nqkalg)alg, &z);
  if (rc != NQOK) return fail(rc);
  pk = obuf(z.pk, &p);
  if (pk == NULL) return NULL;
  sk = obuf(z.sk, &s);
  if (sk == NULL) {
    Py_DECREF(pk);
    return NULL;
  }
  Py_BEGIN_ALLOW_THREADS
  if (seed != NULL)
    rc = nqkkgd((nqkalg)alg, U8(seed), SZ(sl), p, z.pk, s, z.sk);
  else
    rc = nqkkg((nqkalg)alg, p, z.pk, s, z.sk);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(pk);
    sdrop(sk);
    return fail(rc);
  }
  return Py_BuildValue("(NN)", pk, sk);
}

/* enc(alg, pk, seed or None) -> (ct, ss) */
static PyObject *penc(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *pk, *seed = NULL;
  Py_ssize_t pl, sl = 0;
  nqksz z;
  PyObject *ct, *ss;
  uint8_t *c, *s;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#z#", &alg, &pk, &pl, &seed, &sl))
    return NULL;
  rc = nqksize((nqkalg)alg, &z);
  if (rc != NQOK) return fail(rc);
  ct = obuf(z.ct, &c);
  if (ct == NULL) return NULL;
  ss = obuf(z.ss, &s);
  if (ss == NULL) {
    Py_DECREF(ct);
    return NULL;
  }
  Py_BEGIN_ALLOW_THREADS
  if (seed != NULL)
    rc = nqencd((nqkalg)alg, U8(pk), SZ(pl), U8(seed), SZ(sl), c, z.ct, s,
                z.ss);
  else
    rc = nqenc((nqkalg)alg, U8(pk), SZ(pl), c, z.ct, s, z.ss);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(ct);
    sdrop(ss);
    return fail(rc);
  }
  return Py_BuildValue("(NN)", ct, ss);
}

/* dec(alg, sk, ct) -> ss */
static PyObject *pdec(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *sk, *ct;
  Py_ssize_t kl, cl;
  nqksz z;
  PyObject *ss;
  uint8_t *s;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#", &alg, &sk, &kl, &ct, &cl))
    return NULL;
  rc = nqksize((nqkalg)alg, &z);
  if (rc != NQOK) return fail(rc);
  ss = obuf(z.ss, &s);
  if (ss == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdec((nqkalg)alg, U8(sk), SZ(kl), U8(ct), SZ(cl), s, z.ss);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(ss);
    return fail(rc);
  }
  return ss;
}

/* ---- hashes ---- */

/* hlen(alg) -> digest size, 0 if unknown */
static PyObject *phlen(PyObject *self, PyObject *args) {
  int alg;
  (void)self;
  if (!PyArg_ParseTuple(args, "i", &alg)) return NULL;
  return PyLong_FromSize_t(nqhlen((nqhalg)alg));
}

/* hash(alg, data, n) -> n bytes of digest */
static PyObject *phash(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *in;
  Py_ssize_t il, n;
  PyObject *o;
  uint8_t *p;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#n", &alg, &in, &il, &n)) return NULL;
  if (n < 0) return fail(NQEARG);
  o = obuf(SZ(n), &p);
  if (o == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqhash((nqhalg)alg, U8(in), SZ(il), p, SZ(n));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* hmac(alg, key, data, n) -> n bytes of tag */
static PyObject *phmac(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *k, *in;
  Py_ssize_t kl, il, n;
  PyObject *o;
  uint8_t *p;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#n", &alg, &k, &kl, &in, &il, &n))
    return NULL;
  if (n < 0) return fail(NQEARG);
  o = obuf(SZ(n), &p);
  if (o == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqhmac((nqhalg)alg, U8(k), SZ(kl), U8(in), SZ(il), p, SZ(n));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* ---- capsules ---- */

/* seal(dir, alg, sk, pk, meta or None) -> None */
static PyObject *pseal(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *dir, *sk, *pk, *meta = NULL;
  Py_ssize_t kl, pl;
  (void)self;
  if (!PyArg_ParseTuple(args, "yiy#y#z", &dir, &alg, &sk, &kl, &pk, &pl,
                        &meta))
    return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqseal(dir, (nqsalg)alg, U8(sk), SZ(kl), U8(pk), SZ(pl), meta,
              NULL);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

static PyObject *rows(const nqrep *r) {
  size_t i, n = nqrepn(r);
  PyObject *l = PyList_New(0);
  if (l == NULL) return NULL;
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    PyObject *cs, *ds, *t;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK) break;
    if (c == NULL) c = "";
    if (d == NULL) d = "";
    cs = PyUnicode_DecodeUTF8(c, (Py_ssize_t)strlen(c), "replace");
    ds = PyUnicode_DecodeUTF8(d, (Py_ssize_t)strlen(d), "replace");
    t = (cs && ds) ? Py_BuildValue("(OOO)", cs, ok ? Py_True : Py_False, ds)
                   : NULL;
    Py_XDECREF(cs);
    Py_XDECREF(ds);
    if (t == NULL || PyList_Append(l, t) != 0) {
      Py_XDECREF(t);
      Py_DECREF(l);
      return NULL;
    }
    Py_DECREF(t);
  }
  return l;
}

/* (code, rows) for a report; raises when the library made none */
static PyObject *done(int rc, nqrep *r) {
  PyObject *l;
  if (r == NULL) return fail(rc == NQOK ? NQESTATE : rc);
  l = rows(r);
  nqrepfree(r);
  if (l == NULL) return NULL;
  return Py_BuildValue("(iN)", rc, l);
}

/* A tuple of bytes as arrays the library takes: p[i] and n[i] point into
 * the tuple's items, which the caller's argument tuple keeps alive. Free
 * both with PyMem_Free; on error both are NULL. */
static int blist(PyObject *t, size_t max, const char ***p, size_t **n,
                 size_t *cnt) {
  Py_ssize_t k = PyTuple_Size(t), i;
  *p = NULL;
  *n = NULL;
  *cnt = 0;
  if (k < 0) return -1;
  if ((size_t)k > max) {
    fail(NQELIM);
    return -1;
  }
  if (k == 0) return 0;
  *p = (const char **)PyMem_Malloc(sizeof **p * (size_t)k);
  *n = (size_t *)PyMem_Malloc(sizeof **n * (size_t)k);
  if (*p == NULL || *n == NULL) goto bad;
  for (i = 0; i < k; i++) {
    char *b;
    Py_ssize_t bl;
    if (PyBytes_AsStringAndSize(PyTuple_GetItem(t, i), &b, &bl) != 0)
      goto bad;
    (*p)[i] = b;
    (*n)[i] = SZ(bl);
  }
  *cnt = (size_t)k;
  return 0;
bad:
  if (!PyErr_Occurred()) PyErr_NoMemory();
  PyMem_Free((void *)*p);
  PyMem_Free(*n);
  *p = NULL;
  *n = NULL;
  return -1;
}

#define NANC 32
#define NONLY 2000000
#define NLIN 1024
#define NSTMT 32

/* chk(dir or None, pk or None, anchors, only, lineage, statements,
 * proof or None) -> (code, rows), every list a tuple of bytes: nqchkx, or
 * nqchkp with a proof (dir then the folder its files are in, or None) */
static PyObject *pchk(PyObject *self, PyObject *args) {
  const char *dir = NULL, *pk = NULL, *pf = NULL;
  Py_ssize_t pl = 0, fl = 0;
  PyObject *dv, *anc, *only, *lin, *stm, *out = NULL;
  const char **ap = NULL, **op = NULL, **lp = NULL, **sp = NULL;
  size_t *al = NULL, *ol = NULL, *ll = NULL, *sl = NULL;
  nqcopt o;
  nqrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oz#O!O!O!O!z#", &dv, &pk, &pl,
                        &PyTuple_Type, &anc, &PyTuple_Type, &only,
                        &PyTuple_Type, &lin, &PyTuple_Type, &stm, &pf, &fl))
    return NULL;
  if (dv != Py_None && (dir = PyBytes_AsString(dv)) == NULL) return NULL;
  memset(&o, 0, sizeof o);
  if (blist(anc, NANC, &ap, &al, &o.nanc) != 0 ||
      blist(only, NONLY, &op, &ol, &o.nonly) != 0 ||
      blist(lin, NLIN, &lp, &ll, &o.nlin) != 0 ||
      blist(stm, NSTMT, &sp, &sl, &o.nstmt) != 0)
    goto out;
  o.trust = U8(pk);
  o.trustlen = SZ(pl);
  o.anc = (const uint8_t *const *)ap;
  o.anclen = al;
  o.only = op;
  o.lin = lp;
  o.stmt = sp;
  o.stmtlen = sl;
  Py_BEGIN_ALLOW_THREADS
  if (pf != NULL)
    rc = nqchkp(pf, SZ(fl), &o, dir, &r);
  else
    rc = nqchkx(dir, &o, &r);
  Py_END_ALLOW_THREADS
  out = done(rc, r);
out:
  PyMem_Free((void *)ap);
  PyMem_Free(al);
  PyMem_Free((void *)op);
  PyMem_Free(ol);
  PyMem_Free((void *)lp);
  PyMem_Free(ll);
  PyMem_Free((void *)sp);
  PyMem_Free(sl);
  return out;
}

/* seal2(dir, alg, sk, pk, meta or None, ((id, name), ...)) -> None */
static PyObject *pseal2(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *dir, *sk, *pk, *meta = NULL;
  Py_ssize_t kl, pl, k, i;
  PyObject *ins;
  nqcin *in = NULL;
  (void)self;
  if (!PyArg_ParseTuple(args, "yiy#y#zO!", &dir, &alg, &sk, &kl, &pk, &pl,
                        &meta, &PyTuple_Type, &ins))
    return NULL;
  k = PyTuple_Size(ins);
  if (k < 0) return NULL;
  if (k > NLIN) return fail(NQELIM);
  if (k > 0) {
    in = (nqcin *)PyMem_Malloc(sizeof *in * (size_t)k);
    if (in == NULL) return PyErr_NoMemory();
  }
  for (i = 0; i < k; i++) {
    const char *id, *nm;
    Py_ssize_t il;
    if (!PyArg_ParseTuple(PyTuple_GetItem(ins, i), "y#y", &id, &il, &nm)) {
      PyMem_Free(in);
      return NULL;
    }
    if (il != 32) {
      PyMem_Free(in);
      return fail(NQEARG);
    }
    memcpy(in[i].id, id, 32);
    in[i].name = nm;
  }
  Py_BEGIN_ALLOW_THREADS
  rc = nqseal2(dir, (nqsalg)alg, U8(sk), SZ(kl), U8(pk), SZ(pl), meta, in,
               SZ(k));
  Py_END_ALLOW_THREADS
  PyMem_Free(in);
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* capid(dir) -> 32 bytes */
static PyObject *pcapid(PyObject *self, PyObject *args) {
  const char *dir;
  uint8_t id[32];
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqcapid(dir, id);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  return PyBytes_FromStringAndSize((const char *)id, 32);
}

/* The output of a call that sets *outlen also with NQEBUF: tried with
 * cap bytes, then once more with the size it asked for. */
typedef int (*outfn)(void *a, char *out, size_t cap, size_t *outlen);

static PyObject *grow(outfn f, void *a, size_t cap) {
  char *b;
  size_t on = 0;
  int rc, k;
  PyObject *r;
  for (k = 0; k < 2; k++) {
    b = (char *)PyMem_Malloc(cap > 0 ? cap : 1);
    if (b == NULL) return PyErr_NoMemory();
    Py_BEGIN_ALLOW_THREADS
    rc = f(a, b, cap, &on);
    Py_END_ALLOW_THREADS
    if (rc == NQEBUF && on > cap && k == 0) {
      PyMem_Free(b);
      cap = on;
      continue;
    }
    if (rc != NQOK) {
      PyMem_Free(b);
      return fail(rc);
    }
    r = PyBytes_FromStringAndSize(b, (Py_ssize_t)on);
    PyMem_Free(b);
    return r;
  }
  return fail(NQEBUF);
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

/* prove(dir, (path, ...)) -> proof */
static PyObject *pprove(PyObject *self, PyObject *args) {
  prvarg a;
  PyObject *ps, *r;
  size_t *pn = NULL;
  (void)self;
  if (!PyArg_ParseTuple(args, "yO!", &a.dir, &PyTuple_Type, &ps))
    return NULL;
  if (blist(ps, NONLY, &a.p, &pn, &a.n) != 0) return NULL;
  r = grow(prvcall, &a, 65536);
  PyMem_Free((void *)a.p);
  PyMem_Free(pn);
  return r;
}

typedef struct {
  int alg, nalg;
  const char *sk, *pk, *nsk, *npk, *why;
  Py_ssize_t skl, pkl, nskl, npkl;
  long long at;
} ksarg;

static int kscall(void *v, char *out, size_t cap, size_t *outlen) {
  ksarg *a = (ksarg *)v;
  /* nalg -1: the statement that the key expires (nqkexp) */
  if (a->nalg == -1)
    return nqkexp((nqsalg)a->alg, U8(a->sk), SZ(a->skl), U8(a->pk),
                  SZ(a->pkl), (int64_t)a->at, a->why, out, cap, outlen);
  return nqkstmt((nqsalg)a->alg, U8(a->sk), SZ(a->skl), U8(a->pk),
                 SZ(a->pkl), (nqsalg)a->nalg, U8(a->nsk), SZ(a->nskl),
                 U8(a->npk), SZ(a->npkl), (int64_t)a->at, a->why, out, cap,
                 outlen);
}

/* kstmt(alg, sk, pk, nalg, nsk or None, npk or None, at, reason or None)
 * -> statement; nalg -1 for an expiry */
static PyObject *pkstmt(PyObject *self, PyObject *args) {
  ksarg a;
  (void)self;
  memset(&a, 0, sizeof a);
  if (!PyArg_ParseTuple(args, "iy#y#iz#z#Lz", &a.alg, &a.sk, &a.skl, &a.pk,
                        &a.pkl, &a.nalg, &a.nsk, &a.nskl, &a.npk, &a.npkl,
                        &a.at, &a.why))
    return NULL;
  return grow(kscall, &a, 4 * SZ(a.pkl + a.npkl) + 16384);
}

typedef struct {
  int alg;
  const char *sk, *pk, *type, *pl;
  Py_ssize_t skl, pkl, n;
} dsarg;

static int dscall(void *v, char *out, size_t cap, size_t *outlen) {
  dsarg *a = (dsarg *)v;
  return nqdsse((nqsalg)a->alg, U8(a->sk), SZ(a->skl), U8(a->pk),
                SZ(a->pkl), a->type, U8(a->pl), SZ(a->n), out, cap, outlen);
}

/* dsse(alg, sk, pk, type, payload) -> envelope */
static PyObject *pdsse(PyObject *self, PyObject *args) {
  dsarg a;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#yy#", &a.alg, &a.sk, &a.skl, &a.pk,
                        &a.pkl, &a.type, &a.pl, &a.n))
    return NULL;
  return grow(dscall, &a, 2 * SZ(a.n) + 65536);
}

/* dssevrfy(alg, pk, env) -> (code, type, payload): NQOK, NQEVRFY or
 * NQEDEC (type and payload None then); any other code raises */
static PyObject *pdssevrfy(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *pk, *env;
  Py_ssize_t pl, n;
  size_t on = 0;
  char type[256];
  uint8_t *b;
  PyObject *r;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#", &alg, &pk, &pl, &env, &n))
    return NULL;
  /* the payload is the decoding of base64 inside env: shorter than it */
  b = (uint8_t *)PyMem_Malloc(n > 0 ? SZ(n) : 1);
  if (b == NULL) return PyErr_NoMemory();
  Py_BEGIN_ALLOW_THREADS
  rc = nqdssevrfy((nqsalg)alg, U8(pk), SZ(pl), env, SZ(n), b, SZ(n), &on,
                  type);
  Py_END_ALLOW_THREADS
  if (rc == NQEVRFY || rc == NQEDEC) {
    PyMem_Free(b);
    return Py_BuildValue("(iOO)", rc, Py_None, Py_None);
  }
  if (rc != NQOK) {
    PyMem_Free(b);
    return fail(rc);
  }
  r = Py_BuildValue("(isy#)", rc, type, (const char *)b, (Py_ssize_t)on);
  PyMem_Free(b);
  return r;
}

typedef struct {
  int alg;
  const char *sk, *pk, *name, *orcid, *email, *url, *affil;
  Py_ssize_t skl, pkl;
  long long at;
} cdarg;

static int cdcall(void *v, char *out, size_t cap, size_t *outlen) {
  cdarg *a = (cdarg *)v;
  return nqcard((nqsalg)a->alg, U8(a->sk), SZ(a->skl), U8(a->pk),
                SZ(a->pkl), a->name, a->orcid, a->email, a->url, a->affil,
                (int64_t)a->at, out, cap, outlen);
}

/* card(alg, sk, pk, name, orcid, email, url, affil, at) -> card; each
 * optional field None or a str */
static PyObject *pcard(PyObject *self, PyObject *args) {
  cdarg a;
  (void)self;
  memset(&a, 0, sizeof a);
  if (!PyArg_ParseTuple(args, "iy#y#szzzzL", &a.alg, &a.sk, &a.skl, &a.pk,
                        &a.pkl, &a.name, &a.orcid, &a.email, &a.url,
                        &a.affil, &a.at))
    return NULL;
  return grow(cdcall, &a, 4 * SZ(a.pkl) + 65536);
}

/* cardvrfy(card, pk or None) -> (code, fields): NQOK with (alg, pk,
 * sha256, created, utc, name, orcid, email, url, affil), or NQEVRFY or
 * NQEDEC with None; any other code raises */
static PyObject *pcardvrfy(PyObject *self, PyObject *args) {
  const char *c, *pk = NULL;
  Py_ssize_t n, pl = 0;
  nqcardf *f;
  int rc;
  PyObject *r;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#z#", &c, &n, &pk, &pl)) return NULL;
  f = (nqcardf *)PyMem_Malloc(sizeof *f);
  if (f == NULL) return PyErr_NoMemory();
  Py_BEGIN_ALLOW_THREADS
  rc = nqcardvrfy(c, SZ(n), U8(pk), SZ(pl), f);
  Py_END_ALLOW_THREADS
  if (rc == NQEVRFY || rc == NQEDEC) {
    PyMem_Free(f);
    return Py_BuildValue("(iO)", rc, Py_None);
  }
  if (rc != NQOK) {
    PyMem_Free(f);
    return fail(rc);
  }
  r = Py_BuildValue("(i(iy#y#Lssssss))", rc, (int)f->alg,
                    (const char *)f->pk, (Py_ssize_t)f->pklen,
                    (const char *)f->fp, (Py_ssize_t)32,
                    (long long)f->created, f->utc, f->name, f->orcid,
                    f->email, f->url, f->affil);
  PyMem_Free(f);
  return r;
}

/* files(dir) -> (code, rows): nqfiles */
static PyObject *pfiles(PyObject *self, PyObject *args) {
  const char *dir;
  nqrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqfiles(dir, &r);
  Py_END_ALLOW_THREADS
  return done(rc, r);
}

/* ---- the data layer (nqd.h): records and elements as JSON text ---- */

/* raises the error class of rc with why as its message, when there is one */
static PyObject *dfail(int rc, const char *why) {
  PyObject *cls, *e;
  if (why == NULL || why[0] == '\0') return fail(rc);
  if (PyErr_Occurred()) return NULL;
  cls = ecls(rc);
  if (cls == NULL) cls = ecls(0);
  if (cls == NULL) {
    PyErr_Format(PyExc_RuntimeError, "noqtis: %s (%d)", why, rc);
    return NULL;
  }
  e = PyObject_CallFunction(cls, "is", rc, why);
  if (e == NULL) return NULL;
  PyErr_SetObject(cls, e);
  Py_DECREF(e);
  return NULL;
}

/* the record of dir, or a new one when there is none and mk */
static nqdrec *drec(const char *dir, int mk) {
  nqdrec *r = NULL;
  char why[600];
  int rc;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = nqdload(dir, &r, why, sizeof why);
  if (rc == NQEIO && mk) rc = nqdnew(&r);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    dfail(rc, why);
    return NULL;
  }
  return r;
}

static PyObject *dsave(nqdrec *r, const char *dir) {
  int rc;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdsave(r, dir);
  Py_END_ALLOW_THREADS
  nqdrfree(r);
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* a str of what f writes with the two-call size pattern */
static PyObject *jstr(int (*f)(const nqdrec *, char *, size_t, size_t *),
                      const nqdrec *r) {
  size_t n = 0;
  char *b;
  PyObject *o;
  int rc = f(r, NULL, 0, &n);
  if (rc != NQEBUF) return fail(rc);
  b = (char *)PyMem_Malloc(n + 1);
  if (b == NULL) return PyErr_NoMemory();
  rc = f(r, b, n + 1, &n);
  o = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n) : fail(rc);
  PyMem_Free(b);
  return o;
}

static PyObject *pdload(PyObject *self, PyObject *args) {
  const char *dir;
  nqdrec *r;
  PyObject *o;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  o = jstr(nqdjson, r);
  nqdrfree(r);
  return o;
}

static PyObject *pdput(PyObject *self, PyObject *args) {
  const char *dir, *m, *j;
  char why[600];
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yss", &dir, &m, &j)) return NULL;
  if ((r = drec(dir, 1)) == NULL) return NULL;
  rc = nqdput(r, m, j, strlen(j), why, sizeof why);
  if (rc != NQOK) {
    nqdrfree(r);
    return dfail(rc, why);
  }
  return dsave(r, dir);
}

/* each path a source, then fields[i] set to the JSON vals[i]; all UTF-8
 * bytes (the limited API of 3.9 has no PyUnicode_AsUTF8AndSize) */
static PyObject *pdadd(PyObject *self, PyObject *args) {
  const char *dir;
  PyObject *paths, *fields, *vals;
  Py_ssize_t i, k;
  char why[600];
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yOOO", &dir, &paths, &fields, &vals))
    return NULL;
  if (!PyTuple_Check(paths) || !PyTuple_Check(fields) ||
      !PyTuple_Check(vals) || PyTuple_Size(fields) != PyTuple_Size(vals)) {
    PyErr_SetString(PyExc_TypeError, "tuples of paths, fields and values");
    return NULL;
  }
  if ((r = drec(dir, 1)) == NULL) return NULL;
  for (i = 0; i < PyTuple_Size(paths); i++) {
    const char *f = PyBytes_AsString(PyTuple_GetItem(paths, i));
    if (f == NULL) goto bad;
    if ((rc = nqdsrc(r, dir, f, why, sizeof why)) != NQOK) {
      dfail(rc, why);
      goto bad;
    }
    for (k = 0; k < PyTuple_Size(fields); k++) {
      const char *fl = PyBytes_AsString(PyTuple_GetItem(fields, k));
      const char *v = PyBytes_AsString(PyTuple_GetItem(vals, k));
      if (fl == NULL || v == NULL) goto bad;
      if ((rc = nqdset(r, "sources", f, fl, v, strlen(v), why,
                       sizeof why)) != NQOK) {
        dfail(rc, why);
        goto bad;
      }
    }
  }
  return dsave(r, dir);
bad:
  nqdrfree(r);
  return NULL;
}

static PyObject *pddel(PyObject *self, PyObject *args) {
  const char *dir, *m, *k = NULL;
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysz", &dir, &m, &k)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  rc = nqddel(r, m, k);
  if (rc != NQOK) {
    nqdrfree(r);
    return fail(rc);
  }
  return dsave(r, dir);
}

static PyObject *pdkey(PyObject *self, PyObject *args) {
  const char *dir, *m, *k;
  nqdrec *r;
  size_t n = 0;
  char *b;
  PyObject *o;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yss", &dir, &m, &k)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  rc = nqdkey(r, m, k, NULL, 0, &n);
  if (rc == NQEIO) {
    nqdrfree(r);
    Py_RETURN_NONE;
  }
  if (rc != NQEBUF) {
    nqdrfree(r);
    return fail(rc);
  }
  b = (char *)PyMem_Malloc(n + 1);
  if (b == NULL) {
    nqdrfree(r);
    return PyErr_NoMemory();
  }
  rc = nqdkey(r, m, k, b, n + 1, &n);
  o = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n) : fail(rc);
  PyMem_Free(b);
  nqdrfree(r);
  return o;
}

/* ---- sources (nqdaddr(3)) ---- */

/* [(kind, address)] of the source path: [] for a synthetic one */
static PyObject *pdaddr(PyObject *self, PyObject *args) {
  const char *dir, *p;
  nqdrec *r;
  PyObject *l;
  size_t i;
  (void)self;
  if (!PyArg_ParseTuple(args, "ys", &dir, &p)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  if ((l = PyList_New(0)) == NULL) {
    nqdrfree(r);
    return NULL;
  }
  for (i = 0;; i++) {
    char b[4400];
    size_t n = 0;
    int k = 0, rc = nqdaddr(r, p, i, &k, b, sizeof b, &n);
    PyObject *t;
    if (rc == NQEIO && i > 0) break;
    if (rc == NQEARG) break; /* synthetic: no address */
    if (rc != NQOK) {
      Py_DECREF(l);
      nqdrfree(r);
      return rc == NQEIO ? fail(rc) : fail(rc);
    }
    t = Py_BuildValue("(is#)", k, b, (Py_ssize_t)n);
    if (t == NULL || PyList_Append(l, t) != 0) {
      Py_XDECREF(t);
      Py_DECREF(l);
      nqdrfree(r);
      return NULL;
    }
    Py_DECREF(t);
  }
  nqdrfree(r);
  return l;
}

static PyObject *pdvrfy(PyObject *self, PyObject *args) {
  const char *dir, *p, *b;
  Py_ssize_t bn;
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysy#", &dir, &p, &b, &bn)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  rc = nqdvrfy(r, p, (const uint8_t *)b, (size_t)bn);
  nqdrfree(r);
  if (rc == NQOK) Py_RETURN_TRUE;
  if (rc == NQEVRFY) Py_RETURN_FALSE;
  return fail(rc);
}

static PyObject *pdfld(PyObject *self, PyObject *args) {
  const char *dir, *m, *f;
  Py_ssize_t i;
  nqdrec *r;
  size_t n = 0;
  char *b;
  PyObject *o;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysns", &dir, &m, &i, &f)) return NULL;
  if (i < 0) return fail(NQEARG);
  if ((r = drec(dir, 0)) == NULL) return NULL;
  rc = nqdfld(r, m, (size_t)i, f, NULL, 0, &n);
  if (rc == NQEIO) {
    nqdrfree(r);
    Py_RETURN_NONE;
  }
  if (rc != NQEBUF) {
    nqdrfree(r);
    return fail(rc);
  }
  if ((b = (char *)PyMem_Malloc(n + 1)) == NULL) {
    nqdrfree(r);
    return PyErr_NoMemory();
  }
  rc = nqdfld(r, m, (size_t)i, f, b, n + 1, &n);
  o = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n) : fail(rc);
  PyMem_Free(b);
  nqdrfree(r);
  return o;
}

static PyObject *pdrslv(PyObject *self, PyObject *args) {
  const char *rs;
  Py_ssize_t rl;
  char b[4400], why[600];
  size_t n = 0;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "s#", &rs, &rl)) return NULL;
  why[0] = '\0';
  rc = nqdrslv(rs, (size_t)rl, b, sizeof b, &n, why, sizeof why);
  if (rc != NQOK) return dfail(rc, why);
  return PyUnicode_FromStringAndSize(b, (Py_ssize_t)n);
}

static PyObject *pdrsp(PyObject *self, PyObject *args) {
  const char *rs, *rp;
  Py_ssize_t rl, rpl;
  char b[4400], why[600], tm[21];
  size_t n = 0;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "s#y#", &rs, &rl, &rp, &rpl)) return NULL;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = nqdrsp(rs, (size_t)rl, rp, (size_t)rpl, b, sizeof b, &n, tm, why,
              sizeof why);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return dfail(rc, why);
  return Py_BuildValue("(s#s)", b, (Py_ssize_t)n, tm);
}

static PyObject *pdwb(PyObject *self, PyObject *args) {
  const char *u;
  char b[4400];
  size_t n = 0;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "s", &u)) return NULL;
  rc = nqdwb(u, b, sizeof b, &n);
  if (rc != NQOK) return fail(rc);
  return PyUnicode_FromStringAndSize(b, (Py_ssize_t)n);
}

/* (rc, [(check, ok, detail, json or None)]) of a report, freed here */
static PyObject *ddone(int rc, nqdrep *r) {
  size_t i, n;
  PyObject *l;
  if (r == NULL) return fail(rc == NQOK ? NQESTATE : rc);
  n = nqdrepn(r);
  l = PyList_New((Py_ssize_t)n);
  for (i = 0; l != NULL && i < n; i++) {
    const char *c = "", *d = "", *j = nqdrepj(r, i);
    int ok = 0;
    PyObject *t;
    nqdrepi(r, i, &c, &ok, &d);
    t = j != NULL ? Py_BuildValue("(sNss)", c, PyBool_FromLong(ok), d, j)
                  : Py_BuildValue("(sNsO)", c, PyBool_FromLong(ok), d,
                                  Py_None);
    if (t == NULL) {
      Py_DECREF(l);
      l = NULL;
      break;
    }
    PyList_SetItem(l, (Py_ssize_t)i, t);
  }
  nqdrepfree(r);
  if (l == NULL) return NULL;
  return Py_BuildValue("(iN)", rc, l);
}

static PyObject *pdchk(PyObject *self, PyObject *args) {
  const char *dir;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdchk(dir, &r);
  Py_END_ALLOW_THREADS
  return ddone(rc, r);
}

typedef int (*djfn)(const char *, const char *, const nqdcsvopt *, char *,
                    size_t, size_t *, char *, size_t);

static PyObject *djfile(djfn f, const char *dir, const char *p,
                        const nqdcsvopt *o) {
  char why[600], *b;
  size_t n = 0;
  int rc;
  PyObject *s;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = f(dir, p, o, NULL, 0, &n, why, sizeof why);
  Py_END_ALLOW_THREADS
  if (rc != NQEBUF) return dfail(rc, why);
  b = (char *)PyMem_Malloc(n + 1);
  if (b == NULL) return PyErr_NoMemory();
  Py_BEGIN_ALLOW_THREADS
  rc = f(dir, p, o, b, n + 1, &n, why, sizeof why);
  Py_END_ALLOW_THREADS
  s = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n)
                 : dfail(rc, why);
  PyMem_Free(b);
  return s;
}

static PyObject *pdinfer(PyObject *self, PyObject *args) {
  const char *dir, *p;
  int dl, noh, rng;
  nqdcsvopt o;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysCpp", &dir, &p, &dl, &noh, &rng))
    return NULL;
  memset(&o, 0, sizeof o);
  o.delim = (char)dl;
  o.noheader = noh;
  o.ranges = rng;
  return djfile(nqdinfer, dir, p, &o);
}

static PyObject *pdstats(PyObject *self, PyObject *args) {
  const char *dir, *p;
  int dl, noh;
  nqdcsvopt o;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysCp", &dir, &p, &dl, &noh)) return NULL;
  memset(&o, 0, sizeof o);
  o.delim = (char)dl;
  o.noheader = noh;
  return djfile(nqdstats, dir, p, &o);
}

/* the SHA-256 of the file p in dir, never opened through a link */
static PyObject *pdsha(PyObject *self, PyObject *args) {
  const char *dir, *p;
  uint8_t h[32];
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ys", &dir, &p)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdsha(dir, p, h, NULL);
  Py_END_ALLOW_THREADS
  if (rc != NQOK)
    return dfail(rc, rc == NQEARG ? "a link or not a plain file, refused"
                                  : "cannot be read");
  return PyBytes_FromStringAndSize((const char *)h, 32);
}

/* dir None: file is the caller's, by its path; else file is a member
 * of dir, never opened through a link */
static PyObject *pddrift(PyObject *self, PyObject *args) {
  const char *st, *file, *dir = NULL;
  PyObject *od;
  int dl, noh, ben;
  nqdcsvopt o;
  nqddopt d;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "sOyCpddddp", &st, &od, &file, &dl, &noh,
                        &d.psiwarn, &d.psifail, &d.alpha, &d.minn, &ben))
    return NULL;
  if (od != Py_None && (dir = PyBytes_AsString(od)) == NULL)
    return NULL;
  memset(&o, 0, sizeof o);
  o.delim = (char)dl;
  o.noheader = noh;
  d.benford = ben;
  Py_BEGIN_ALLOW_THREADS
  rc = nqddriftat(st, strlen(st), dir, file, &o, &d, &r);
  Py_END_ALLOW_THREADS
  return ddone(rc, r);
}

static PyObject *pddiff(PyObject *self, PyObject *args) {
  const char *a, *b;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yy", &a, &b)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqddiff(a, b, &r);
  Py_END_ALLOW_THREADS
  return ddone(rc, r);
}

/* ---- utilities, BLAKE2b and Argon2id ---- */

/* rand(n) -> n bytes from the OS CSPRNG */
static PyObject *prand(PyObject *self, PyObject *args) {
  Py_ssize_t n;
  PyObject *b;
  uint8_t *p;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "n", &n)) return NULL;
  if (n < 0) return fail(NQEARG);
  if ((b = obuf(SZ(n), &p)) == NULL) return NULL;
  rc = nqrand(p, SZ(n));
  if (rc != NQOK) {
    sdrop(b);
    return fail(rc);
  }
  return b;
}

/* cteq(a, b) -> bool, in time that depends only on the length */
static PyObject *pcteq(PyObject *self, PyObject *args) {
  const char *a, *b;
  Py_ssize_t al, bl;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#", &a, &al, &b, &bl)) return NULL;
  if (al != bl) Py_RETURN_FALSE;
  return PyBool_FromLong(nqcteq(a, b, SZ(al)));
}

/* b2b(key, data, n) -> digest */
static PyObject *pb2b(PyObject *self, PyObject *args) {
  const char *k, *d;
  Py_ssize_t kl, dl, n;
  PyObject *o;
  uint8_t *p;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#n", &k, &kl, &d, &dl, &n)) return NULL;
  if (n < 1 || n > 64) return fail(NQEARG);
  if ((o = obuf(SZ(n), &p)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqb2b(U8(k), SZ(kl), U8(d), SZ(dl), p, SZ(n));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* kt(bits, data, custom, n) -> n bytes of KT128 or KT256 */
static PyObject *pkt(PyObject *self, PyObject *args) {
  const char *d, *c;
  Py_ssize_t dl, cl, n;
  unsigned long bits;
  PyObject *o;
  uint8_t *p;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ky#y#n", &bits, &d, &dl, &c, &cl, &n))
    return NULL;
  if (n < 1 || (bits != 128 && bits != 256)) return fail(NQEARG);
  if ((o = obuf(SZ(n), &p)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqkt((unsigned)bits, U8(d), SZ(dl), U8(c), SZ(cl), p, SZ(n));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  return o;
}

/* cha20(key, nonce, ctr, data) -> data XORed with the key stream */
static PyObject *pcha20(PyObject *self, PyObject *args) {
  const char *k, *nc, *d;
  Py_ssize_t kl, nl, dl;
  unsigned long ctr;
  PyObject *o;
  uint8_t *p;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#ky#", &k, &kl, &nc, &nl, &ctr, &d, &dl))
    return NULL;
  if (ctr > 0xffffffffUL) return fail(NQEARG);
  if ((o = obuf(SZ(dl), &p)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqcha20(U8(k), SZ(kl), U8(nc), SZ(nl), (uint32_t)ctr, U8(d), SZ(dl),
               p);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  return o;
}

/* siv(dec, key, ads, data): AES-SIV; ads is a tuple of bytes objects */
static PyObject *psiv(PyObject *self, PyObject *args) {
  const char *k, *d;
  Py_ssize_t kl, dl, nad, i, sl;
  int dec, rc;
  PyObject *ads, *o;
  const uint8_t *ad[NQSIVADMAX];
  size_t adl[NQSIVADMAX], ol;
  uint8_t *p;
  char *s;
  (void)self;
  if (!PyArg_ParseTuple(args, "py#O!y#", &dec, &k, &kl, &PyTuple_Type, &ads,
                        &d, &dl))
    return NULL;
  nad = PyTuple_Size(ads);
  if (nad < 0) return NULL;
  if (nad > (Py_ssize_t)NQSIVADMAX || (dec && dl < 16)) return fail(NQEARG);
  for (i = 0; i < nad; i++) {
    PyObject *it = PyTuple_GetItem(ads, i);
    if (it == NULL || PyBytes_AsStringAndSize(it, &s, &sl) < 0) return NULL;
    ad[i] = U8(s);
    adl[i] = SZ(sl);
  }
  ol = dec ? SZ(dl) - 16 : SZ(dl) + 16;
  if ((o = obuf(ol, &p)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = dec ? nqsivdec(U8(k), SZ(kl), ad, adl, SZ(nad), U8(d), SZ(dl), p, ol)
           : nqsivenc(U8(k), SZ(kl), ad, adl, SZ(nad), U8(d), SZ(dl), p, ol);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  return o;
}

/* gsiv(dec, key, nonce, ad, data): AES-GCM-SIV */
static PyObject *pgsiv(PyObject *self, PyObject *args) {
  const char *k, *nc, *a, *d;
  Py_ssize_t kl, nl, al, dl;
  int dec, rc;
  PyObject *o;
  size_t ol;
  uint8_t *p;
  (void)self;
  if (!PyArg_ParseTuple(args, "py#y#y#y#", &dec, &k, &kl, &nc, &nl, &a, &al,
                        &d, &dl))
    return NULL;
  if (dec && dl < 16) return fail(NQEARG);
  ol = dec ? SZ(dl) - 16 : SZ(dl) + 16;
  if ((o = obuf(ol, &p)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = dec ? nqgsivdec(U8(k), SZ(kl), U8(nc), SZ(nl), U8(a), SZ(al), U8(d),
                       SZ(dl), p, ol)
           : nqgsivenc(U8(k), SZ(kl), U8(nc), SZ(nl), U8(a), SZ(al), U8(d),
                       SZ(dl), p, ol);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  return o;
}

/* a2id(pw, salt, key, ad, t, m, p, n) -> tag (secret) */
static PyObject *pa2id(PyObject *self, PyObject *args) {
  const char *pw, *s, *k, *a;
  Py_ssize_t pl, sl, kl, al, n;
  unsigned long t, m, p;
  PyObject *o;
  uint8_t *q;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#y#y#kkkn", &pw, &pl, &s, &sl, &k, &kl, &a,
                        &al, &t, &m, &p, &n))
    return NULL;
  if (n < (Py_ssize_t)NQA2OMIN || n > (Py_ssize_t)NQA2OMAX ||
      t > 0xffffffffUL || m > 0xffffffffUL || p > 0xffffffffUL)
    return fail(NQEARG);
  if ((o = obuf(SZ(n), &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqa2id(U8(pw), SZ(pl), U8(s), SZ(sl), U8(k), SZ(kl), U8(a), SZ(al),
              (uint32_t)t, (uint32_t)m, (uint32_t)p, q, SZ(n));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  return o;
}

/* ---- passphrase key files ---- */

/* pwenc(pw, ad, m, t, p, sk) -> bytes */
static PyObject *ppwenc(PyObject *self, PyObject *args) {
  const char *pw, *ad, *sk;
  Py_ssize_t pl, al, kl;
  unsigned long m, t, p;
  size_t on = 0;
  PyObject *o;
  uint8_t *q;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#kkky#", &pw, &pl, &ad, &al, &m, &t, &p,
                        &sk, &kl))
    return NULL;
  if (m > 0xffffffffUL || t > 0xffffffffUL || p > 0xffffffffUL ||
      SZ(kl) > NQPWMAX)
    return fail(NQEARG);
  if ((o = obuf(SZ(kl) + NQPWOVH, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqpwenc(U8(pw), SZ(pl), U8(ad), SZ(al), (uint32_t)m, (uint32_t)t,
               (uint32_t)p, U8(sk), SZ(kl), q, SZ(kl) + NQPWOVH, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* pwdec(pw, ad, data) -> the key (secret) */
static PyObject *ppwdec(PyObject *self, PyObject *args) {
  const char *pw, *ad, *in;
  Py_ssize_t pl, al, il;
  size_t on = 0, cap;
  PyObject *o, *r;
  uint8_t *q;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#y#", &pw, &pl, &ad, &al, &in, &il))
    return NULL;
  cap = SZ(il) > NQPWOVH ? SZ(il) - NQPWOVH : 1;
  if ((o = obuf(cap, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqpwdec(U8(pw), SZ(pl), U8(ad), SZ(al), U8(in), SZ(il), q, cap, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  if (on == cap) return o;
  r = PyBytes_FromStringAndSize((const char *)q, (Py_ssize_t)on);
  sdrop(o);
  return r;
}

/* ---- ML-DSA with an external mu ---- */

/* smu(alg, pk, msg, ctx, ph) -> mu */
static PyObject *psmu(PyObject *self, PyObject *args) {
  int alg, ph, rc;
  const char *pk, *msg, *ctx;
  Py_ssize_t pl, ml, cl;
  PyObject *o;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#i", &alg, &pk, &pl, &msg, &ml, &ctx,
                        &cl, &ph))
    return NULL;
  if ((o = obuf(NQMU, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqsmu((nqsalg)alg, U8(pk), SZ(pl), U8(msg), SZ(ml), U8(ctx), SZ(cl),
             ph, q, NQMU);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* signmu(alg, sk, mu, rnd or None) -> sig */
static PyObject *psignmu(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *sk, *mu, *rnd = NULL;
  Py_ssize_t kl, ml, rl = 0;
  size_t on = 0;
  nqssz z;
  PyObject *o;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#z#", &alg, &sk, &kl, &mu, &ml, &rnd, &rl))
    return NULL;
  if ((rc = nqssize((nqsalg)alg, &z)) != NQOK) return fail(rc);
  if ((o = obuf(z.sig, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqsignmu((nqsalg)alg, U8(sk), SZ(kl), U8(mu), SZ(ml), U8(rnd), SZ(rl),
                q, z.sig, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* vrfymu(alg, pk, mu, sig) -> NQOK, NQEVRFY or NQEDEC */
static PyObject *pvrfymu(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *pk, *mu, *sig;
  Py_ssize_t pl, ml, sl;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#", &alg, &pk, &pl, &mu, &ml, &sig, &sl))
    return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqvrfymu((nqsalg)alg, U8(pk), SZ(pl), U8(mu), SZ(ml), U8(sig), SZ(sl));
  Py_END_ALLOW_THREADS
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) return fail(rc);
  return PyLong_FromLong(rc);
}

/* ---- contexts: streaming hashes, signatures and sealed streams ---- */

/* A context lives in PyMem memory held by a capsule of its name; the
 * capsule's destructor wipes it. */
static void cfree(PyObject *c) {
  const char *n = PyCapsule_GetName(c);
  void *p = PyCapsule_GetPointer(c, n);
  size_t sz = (size_t)(uintptr_t)PyCapsule_GetContext(c);
  if (p != NULL) {
    nqwipe(p, sz);
    PyMem_Free(p);
  }
}

static PyObject *cnew(const char *name, size_t sz, void **p) {
  PyObject *c;
  *p = PyMem_Malloc(sz);
  if (*p == NULL) return PyErr_NoMemory();
  memset(*p, 0, sz);
  c = PyCapsule_New(*p, name, cfree);
  if (c == NULL) {
    PyMem_Free(*p);
    return NULL;
  }
  if (PyCapsule_SetContext(c, (void *)(uintptr_t)sz) != 0) {
    Py_DECREF(c);
    return NULL;
  }
  return c;
}

static void *cget(PyObject *c, const char *name) {
  return PyCapsule_GetPointer(c, name);
}

#define CH "noqtis.hctx"
#define CS "noqtis.sctx"
#define CK "noqtis.kfctx"

/* hini(alg) -> context */
static PyObject *phini(PyObject *self, PyObject *args) {
  int alg, rc;
  void *p;
  PyObject *c;
  (void)self;
  if (!PyArg_ParseTuple(args, "i", &alg)) return NULL;
  if ((c = cnew(CH, sizeof(nqhctx), &p)) == NULL) return NULL;
  if ((rc = nqhini((nqhctx *)p, (nqhalg)alg)) != NQOK) {
    Py_DECREF(c);
    return fail(rc);
  }
  return c;
}

/* hupd(ctx, data) */
static PyObject *phupd(PyObject *self, PyObject *args) {
  PyObject *c;
  const char *d;
  Py_ssize_t dl;
  nqhctx *h;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oy#", &c, &d, &dl)) return NULL;
  if ((h = (nqhctx *)cget(c, CH)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqhupd(h, U8(d), SZ(dl));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* hfin(ctx, n) -> n bytes */
static PyObject *phfin(PyObject *self, PyObject *args) {
  PyObject *c, *o;
  Py_ssize_t n;
  nqhctx *h;
  uint8_t *q;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "On", &c, &n)) return NULL;
  if ((h = (nqhctx *)cget(c, CH)) == NULL) return NULL;
  if (n < 0) return fail(NQEARG);
  if ((o = obuf(SZ(n), &q)) == NULL) return NULL;
  rc = nqhfin(h, q, SZ(n));
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* sini(alg, key, ctx, ph, verify) -> context: nqsini, or nqvini */
static PyObject *psini(PyObject *self, PyObject *args) {
  int alg, ph, v, rc;
  const char *k, *cx;
  Py_ssize_t kl, cl;
  void *p;
  PyObject *c;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#ip", &alg, &k, &kl, &cx, &cl, &ph, &v))
    return NULL;
  if ((c = cnew(CS, sizeof(nqsctx), &p)) == NULL) return NULL;
  if (v)
    rc = nqvini((nqsctx *)p, (nqsalg)alg, U8(k), SZ(kl), U8(cx), SZ(cl), ph);
  else
    rc = nqsini((nqsctx *)p, (nqsalg)alg, U8(k), SZ(kl), U8(cx), SZ(cl), ph);
  if (rc != NQOK) {
    Py_DECREF(c);
    return fail(rc);
  }
  return c;
}

/* supd(ctx, data) */
static PyObject *psupd(PyObject *self, PyObject *args) {
  PyObject *c;
  const char *d;
  Py_ssize_t dl;
  nqsctx *s;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oy#", &c, &d, &dl)) return NULL;
  if ((s = (nqsctx *)cget(c, CS)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqsupd(s, U8(d), SZ(dl));
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* sfin(ctx, alg, sk, rnd or None) -> sig */
static PyObject *psfin(PyObject *self, PyObject *args) {
  PyObject *c, *o;
  int alg, rc;
  const char *sk, *rnd = NULL;
  Py_ssize_t kl, rl = 0;
  size_t on = 0;
  nqssz z;
  nqsctx *s;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oiy#z#", &c, &alg, &sk, &kl, &rnd, &rl))
    return NULL;
  if ((s = (nqsctx *)cget(c, CS)) == NULL) return NULL;
  if ((rc = nqssize((nqsalg)alg, &z)) != NQOK) return fail(rc);
  if ((o = obuf(z.sig, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqsfin(s, U8(sk), SZ(kl), U8(rnd), SZ(rl), q, z.sig, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  if (on == z.sig) return o;
  c = PyBytes_FromStringAndSize((const char *)q, (Py_ssize_t)on);
  Py_DECREF(o);
  return c;
}

/* vfin(ctx, pk, sig) -> NQOK, NQEVRFY or NQEDEC */
static PyObject *pvfin(PyObject *self, PyObject *args) {
  PyObject *c;
  const char *pk, *sig;
  Py_ssize_t pl, sl;
  nqsctx *s;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oy#y#", &c, &pk, &pl, &sig, &sl)) return NULL;
  if ((s = (nqsctx *)cget(c, CS)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqvfin(s, U8(pk), SZ(pl), U8(sig), SZ(sl));
  Py_END_ALLOW_THREADS
  if (rc != NQOK && rc != NQEVRFY && rc != NQEDEC) return fail(rc);
  return PyLong_FromLong(rc);
}

/* ---- messages and streams sealed to an ML-KEM key ---- */

/* kseal(alg, pk, ctx, msg) -> bytes */
static PyObject *pkseal(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *pk, *cx, *m;
  Py_ssize_t pl, cl, ml;
  size_t on = 0, cap;
  nqksz z;
  PyObject *o;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#", &alg, &pk, &pl, &cx, &cl, &m, &ml))
    return NULL;
  if ((rc = nqksize((nqkalg)alg, &z)) != NQOK) return fail(rc);
  if (SZ(ml) > NQKSMAX) return fail(NQELIM);
  cap = NQKSOVH + z.ct + SZ(ml);
  if ((o = obuf(cap, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqkseal((nqkalg)alg, U8(pk), SZ(pl), U8(cx), SZ(cl), U8(m), SZ(ml), q,
               cap, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    Py_DECREF(o);
    return fail(rc);
  }
  return o;
}

/* kopen(alg, sk, ctx, data) -> the message */
static PyObject *pkopen(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *sk, *cx, *in;
  Py_ssize_t kl, cl, il;
  size_t on = 0, cap;
  PyObject *o, *r;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#", &alg, &sk, &kl, &cx, &cl, &in, &il))
    return NULL;
  cap = SZ(il) > 0 ? SZ(il) : 1;
  if ((o = obuf(cap, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqkopen((nqkalg)alg, U8(sk), SZ(kl), U8(cx), SZ(cl), U8(in), SZ(il), q,
               cap, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  r = PyBytes_FromStringAndSize((const char *)q, (Py_ssize_t)on);
  sdrop(o);
  return r;
}

/* kfeini(alg, pk, ctx, chunk) -> (context, header) */
static PyObject *pkfeini(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *pk, *cx;
  Py_ssize_t pl, cl;
  unsigned long ch;
  uint8_t h[NQKFHDR + 1568];
  size_t hl = 0;
  void *p;
  PyObject *c;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#k", &alg, &pk, &pl, &cx, &cl, &ch))
    return NULL;
  if (ch > 0xffffffffUL) return fail(NQELIM);
  if ((c = cnew(CK, sizeof(nqkfctx), &p)) == NULL) return NULL;
  rc = nqkfeini((nqkfctx *)p, (nqkalg)alg, U8(pk), SZ(pl), U8(cx), SZ(cl),
                (uint32_t)ch, h, sizeof h, &hl);
  if (rc != NQOK) {
    Py_DECREF(c);
    return fail(rc);
  }
  return Py_BuildValue("(Ny#)", c, (const char *)h, (Py_ssize_t)hl);
}

/* kfdini(alg, sk, ctx, header) -> (context, chunk) */
static PyObject *pkfdini(PyObject *self, PyObject *args) {
  int alg, rc;
  const char *sk, *cx, *h;
  Py_ssize_t kl, cl, hl;
  uint32_t ch = 0;
  void *p;
  PyObject *c;
  (void)self;
  if (!PyArg_ParseTuple(args, "iy#y#y#", &alg, &sk, &kl, &cx, &cl, &h, &hl))
    return NULL;
  if ((c = cnew(CK, sizeof(nqkfctx), &p)) == NULL) return NULL;
  rc = nqkfdini((nqkfctx *)p, (nqkalg)alg, U8(sk), SZ(kl), U8(cx), SZ(cl),
                U8(h), SZ(hl), &ch);
  if (rc != NQOK) {
    Py_DECREF(c);
    return fail(rc);
  }
  return Py_BuildValue("(Nk)", c, (unsigned long)ch);
}

/* kfupd(ctx, data, last, open, chunk) -> bytes: one chunk sealed
 * (nqkfeupd, nqkfefin) or opened (nqkfdupd, nqkfdfin) */
static PyObject *pkfupd(PyObject *self, PyObject *args) {
  PyObject *c, *o, *r;
  const char *d;
  Py_ssize_t dl;
  int last, op, rc;
  unsigned long ch;
  size_t on = 0, cap;
  nqkfctx *k;
  uint8_t *q;
  (void)self;
  if (!PyArg_ParseTuple(args, "Oy#ppk", &c, &d, &dl, &last, &op, &ch))
    return NULL;
  if ((k = (nqkfctx *)cget(c, CK)) == NULL) return NULL;
  cap = op ? (size_t)ch : (size_t)ch + 16;
  if ((o = obuf(cap > 0 ? cap : 1, &q)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  if (op)
    rc = last ? nqkfdfin(k, U8(d), SZ(dl), q, cap, &on)
              : nqkfdupd(k, U8(d), SZ(dl), q, cap, &on);
  else
    rc = last ? nqkfefin(k, U8(d), SZ(dl), q, cap, &on)
              : nqkfeupd(k, U8(d), SZ(dl), q, cap, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    sdrop(o);
    return fail(rc);
  }
  r = PyBytes_FromStringAndSize((const char *)q, (Py_ssize_t)on);
  if (op)
    sdrop(o);
  else
    Py_DECREF(o);
  return r;
}

/* ---- capsules: inspect, why a seal was refused, timestamps ---- */

static PyObject *pinsp(PyObject *self, PyObject *args) {
  const char *dir;
  nqrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqinsp(dir, &r);
  Py_END_ALLOW_THREADS
  return done(rc, r);
}

/* sealwhy(dir) -> (why, path) */
static PyObject *psealwhy(PyObject *self, PyObject *args) {
  const char *dir;
  char p[4200];
  int why = 0, rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y", &dir)) return NULL;
  p[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = nqsealwhy(dir, &why, p, sizeof p);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  return Py_BuildValue("(is)", why, p);
}

/* tsreq(dir, nonce or None, ers, h) -> the TimeStampReq: nqtsreq, or
 * nqersreq with ers */
static PyObject *ptsreq(PyObject *self, PyObject *args) {
  const char *dir, *nc = NULL, *w = NULL;
  Py_ssize_t nl = 0;
  int ers, h, rc;
  uint8_t q[256];
  size_t on = 0;
  (void)self;
  if (!PyArg_ParseTuple(args, "yz#pi", &dir, &nc, &nl, &ers, &h)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  if (ers)
    rc = nqersreq(dir, (nqhalg)h, U8(nc), SZ(nl), q, sizeof q, &on, &w);
  else
    rc = nqtsreq(dir, U8(nc), SZ(nl), q, sizeof q, &on);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return dfail(rc, w);
  return PyBytes_FromStringAndSize((const char *)q, (Py_ssize_t)on);
}

/* tsput(dir, reply, nonce or None, anchors, ers, h) -> (gt, how): nqtsput
 * (how 0), or nqersput with ers */
static PyObject *ptsput(PyObject *self, PyObject *args) {
  const char *dir, *rsp, *nc = NULL, *w = NULL, **ap = NULL;
  Py_ssize_t rl, nl = 0;
  PyObject *anc;
  size_t *al = NULL, na = 0;
  int ers, h, how = 0, rc;
  int64_t gt = 0;
  (void)self;
  if (!PyArg_ParseTuple(args, "yy#z#O!pi", &dir, &rsp, &rl, &nc, &nl,
                        &PyTuple_Type, &anc, &ers, &h))
    return NULL;
  if (blist(anc, NANC, &ap, &al, &na) != 0) return NULL;
  Py_BEGIN_ALLOW_THREADS
  if (ers)
    rc = nqersput(dir, (nqhalg)h, U8(rsp), SZ(rl), U8(nc), SZ(nl),
                  (const uint8_t *const *)ap, al, na, &gt, &how, &w);
  else
    rc = nqtsput(dir, U8(rsp), SZ(rl), U8(nc), SZ(nl),
                 (const uint8_t *const *)ap, al, na, &gt, &w);
  Py_END_ALLOW_THREADS
  PyMem_Free((void *)ap);
  PyMem_Free(al);
  if (rc != NQOK) return dfail(rc, w);
  return Py_BuildValue("(Li)", (long long)gt, how);
}

/* ---- the data layer: the rest of nqd.h ---- */

/* a str of what f writes with the two-call size pattern, why for errors */
typedef int (*sfn)(void *u, char *out, size_t cap, size_t *n, char *why,
                   size_t wc);

static PyObject *wgrow(sfn f, void *u) {
  char why[600], *b;
  size_t n = 0;
  int rc;
  PyObject *s;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = f(u, NULL, 0, &n, why, sizeof why);
  Py_END_ALLOW_THREADS
  if (rc != NQEBUF) return dfail(rc == NQOK ? NQESTATE : rc, why);
  b = (char *)PyMem_Malloc(n + 1);
  if (b == NULL) return PyErr_NoMemory();
  Py_BEGIN_ALLOW_THREADS
  rc = f(u, b, n + 1, &n, why, sizeof why);
  Py_END_ALLOW_THREADS
  s = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n)
                 : dfail(rc, why);
  PyMem_Free(b);
  return s;
}

/* parse(text) -> canonical text */
typedef struct {
  const char *s;
  size_t n;
} dtext;

static int fparse(void *u, char *out, size_t cap, size_t *n, char *why,
                  size_t wc) {
  dtext *t = (dtext *)u;
  nqdrec *r = NULL;
  int rc = nqdparse(t->s, t->n, &r, why, wc);
  if (rc != NQOK) return rc;
  rc = nqdjson(r, out, cap, n);
  nqdrfree(r);
  return rc;
}

static PyObject *pdparse(PyObject *self, PyObject *args) {
  dtext t;
  Py_ssize_t n;
  (void)self;
  if (!PyArg_ParseTuple(args, "s#", &t.s, &n)) return NULL;
  t.n = SZ(n);
  return wgrow(fparse, &t);
}

/* dschk(dir, schema) -> rows */
static PyObject *pdschk(PyObject *self, PyObject *args) {
  const char *dir, *s;
  Py_ssize_t sl;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ys#", &dir, &s, &sl)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdschk(dir, s, SZ(sl), &r);
  Py_END_ALLOW_THREADS
  return ddone(rc, r);
}

/* dsyn(dir, path, seed, rows): the stand-in, recorded */
static PyObject *pdsyn(PyObject *self, PyObject *args) {
  const char *dir, *p;
  unsigned long long seed, rows;
  char why[600];
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysKK", &dir, &p, &seed, &rows)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = nqdsyn(r, dir, p, (uint64_t)seed, (uint64_t)rows, why, sizeof why);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) {
    nqdrfree(r);
    return dfail(rc, why);
  }
  return dsave(r, dir);
}

/* dcal(stats, files, delim, noheader) -> the calibrated element */
typedef struct {
  const char *s;
  size_t n;
  const char **f;
  size_t nf;
  nqdcsvopt o;
} dcal;

static int fcal(void *u, char *out, size_t cap, size_t *n, char *why,
                size_t wc) {
  dcal *c = (dcal *)u;
  return nqddcal(c->s, c->n, c->f, c->nf, &c->o, out, cap, n, why, wc);
}

static PyObject *pdcal(PyObject *self, PyObject *args) {
  dcal c;
  Py_ssize_t sl;
  PyObject *fs, *o;
  size_t *fl = NULL;
  int dl, noh;
  (void)self;
  if (!PyArg_ParseTuple(args, "s#O!Cp", &c.s, &sl, &PyTuple_Type, &fs, &dl,
                        &noh))
    return NULL;
  c.n = SZ(sl);
  memset(&c.o, 0, sizeof c.o);
  c.o.delim = (char)dl;
  c.o.noheader = noh;
  if (blist(fs, 100000, &c.f, &fl, &c.nf) != 0) return NULL;
  o = wgrow(fcal, &c);
  PyMem_Free((void *)c.f);
  PyMem_Free(fl);
  return o;
}

/* dchunk(dir, path, chunk) -> a "chunks" element */
typedef struct {
  const char *d, *p;
  uint64_t ch;
} dcnk;

static int fchunk(void *u, char *out, size_t cap, size_t *n, char *why,
                  size_t wc) {
  dcnk *c = (dcnk *)u;
  return nqdchunk(c->d, c->p, c->ch, out, cap, n, why, wc);
}

static PyObject *pdchunk(PyObject *self, PyObject *args) {
  dcnk c;
  unsigned long long ch;
  (void)self;
  if (!PyArg_ParseTuple(args, "ysK", &c.d, &c.p, &ch)) return NULL;
  c.ch = (uint64_t)ch;
  return wgrow(fchunk, &c);
}

/* dpiece(elem, piece, off) -> rows */
static PyObject *pdpiece(PyObject *self, PyObject *args) {
  const char *e, *p;
  Py_ssize_t el;
  unsigned long long off;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "s#yK", &e, &el, &p, &off)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdpiece(e, SZ(el), p, (uint64_t)off, &r);
  Py_END_ALLOW_THREADS
  return ddone(rc, r);
}

/* dcommit(salt, m) -> 64 hex digits */
static PyObject *pdcommit(PyObject *self, PyObject *args) {
  const char *s, *m;
  Py_ssize_t sl, ml;
  char hx[65];
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "y#y#", &s, &sl, &m, &ml)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdcommit(U8(s), SZ(sl), U8(m), SZ(ml), hx);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  return PyUnicode_FromStringAndSize(hx, 64);
}

/* dreveal(dir, salt, m) -> the index of the commitment, or None */
static PyObject *pdreveal(PyObject *self, PyObject *args) {
  const char *dir, *s, *m;
  Py_ssize_t sl, ml;
  size_t i = 0;
  nqdrec *r;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yy#y#", &dir, &s, &sl, &m, &ml)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdreveal(r, U8(s), SZ(sl), U8(m), SZ(ml), &i);
  Py_END_ALLOW_THREADS
  nqdrfree(r);
  if (rc == NQEVRFY) Py_RETURN_NONE;
  if (rc != NQOK) return fail(rc);
  return PyLong_FromSize_t(i);
}

/* dcite(dir, fmt) -> text */
static PyObject *pdcite(PyObject *self, PyObject *args) {
  const char *dir;
  int fmt, rc;
  nqdrec *r;
  size_t n = 0;
  char *b;
  PyObject *o;
  (void)self;
  if (!PyArg_ParseTuple(args, "yi", &dir, &fmt)) return NULL;
  if ((r = drec(dir, 0)) == NULL) return NULL;
  rc = nqdcite(r, fmt, NULL, 0, &n);
  if (rc != NQEBUF) {
    nqdrfree(r);
    return fail(rc == NQOK ? NQESTATE : rc);
  }
  b = (char *)PyMem_Malloc(n + 1);
  if (b == NULL) {
    nqdrfree(r);
    return PyErr_NoMemory();
  }
  rc = nqdcite(r, fmt, b, n + 1, &n);
  o = rc == NQOK ? PyUnicode_FromStringAndSize(b, (Py_ssize_t)n) : fail(rc);
  PyMem_Free(b);
  nqdrfree(r);
  return o;
}

/* drpt(dir, pk or None, fmt, sealed, hasrec) -> text: the capsule checked
 * (nqchkx with pk) when sealed, the record (nqdchk) when it has one */
typedef struct {
  const char *d;
  const nqrep *c;
  const nqdrep *r;
  int fmt;
} drpt;

static int frpt(void *u, char *out, size_t cap, size_t *n, char *why,
                size_t wc) {
  drpt *x = (drpt *)u;
  (void)why;
  (void)wc;
  return nqdrpt(x->d, x->c, x->r, x->fmt, out, cap, n);
}

static PyObject *pdrpt(PyObject *self, PyObject *args) {
  const char *dir, *pk = NULL;
  Py_ssize_t pl = 0;
  int fmt, sealed, hasrec, rc = NQOK;
  nqrep *cr = NULL;
  nqdrep *dr = NULL;
  nqcopt co;
  drpt x;
  PyObject *o;
  (void)self;
  if (!PyArg_ParseTuple(args, "yz#ipp", &dir, &pk, &pl, &fmt, &sealed,
                        &hasrec))
    return NULL;
  memset(&co, 0, sizeof co);
  co.trust = U8(pk);
  co.trustlen = SZ(pl);
  Py_BEGIN_ALLOW_THREADS
  if (sealed) rc = nqchkx(dir, &co, &cr);
  if (cr != NULL || !sealed) {
    rc = NQOK;
    if (hasrec) {
      rc = nqdchk(dir, &dr);
      if (dr != NULL) rc = NQOK;
    }
  }
  Py_END_ALLOW_THREADS
  if (rc != NQOK || (sealed && cr == NULL)) {
    nqrepfree(cr);
    nqdrepfree(dr);
    return fail(rc != NQOK ? rc : NQESTATE);
  }
  x.d = dir;
  x.c = cr;
  x.r = dr;
  x.fmt = fmt;
  o = wgrow(frpt, &x);
  nqrepfree(cr);
  nqdrepfree(dr);
  return o;
}

/* dpack(dir, files, file) */
static PyObject *pdpack(PyObject *self, PyObject *args) {
  const char *dir, *f;
  int files, rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "ypy", &dir, &files, &f)) return NULL;
  Py_BEGIN_ALLOW_THREADS
  rc = nqdpack(dir, files, f);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return fail(rc);
  Py_RETURN_NONE;
}

/* dunpack(file, dir, rm) */
static PyObject *pdunpack(PyObject *self, PyObject *args) {
  const char *f, *dir;
  int rm, rc;
  char why[600];
  (void)self;
  if (!PyArg_ParseTuple(args, "yyp", &f, &dir, &rm)) return NULL;
  why[0] = '\0';
  Py_BEGIN_ALLOW_THREADS
  rc = nqdunpack(f, dir, rm, why, sizeof why);
  Py_END_ALLOW_THREADS
  if (rc != NQOK) return dfail(rc, why);
  Py_RETURN_NONE;
}

/* dchain(dirs, pk or None, anchors) -> (code, head, rows) */
static PyObject *pdchain(PyObject *self, PyObject *args) {
  PyObject *ds, *anc, *rr;
  const char *pk = NULL, **dp = NULL, **ap = NULL;
  Py_ssize_t pl = 0;
  size_t *dl = NULL, *al = NULL, nd = 0, na = 0;
  uint8_t head[32];
  nqcopt co;
  nqdrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "O!z#O!", &PyTuple_Type, &ds, &pk, &pl,
                        &PyTuple_Type, &anc))
    return NULL;
  if (blist(ds, 1000000, &dp, &dl, &nd) != 0) return NULL;
  if (blist(anc, NANC, &ap, &al, &na) != 0) {
    PyMem_Free((void *)dp);
    PyMem_Free(dl);
    return NULL;
  }
  memset(&co, 0, sizeof co);
  co.trust = U8(pk);
  co.trustlen = SZ(pl);
  co.anc = (const uint8_t *const *)ap;
  co.anclen = al;
  co.nanc = na;
  memset(head, 0, sizeof head);
  Py_BEGIN_ALLOW_THREADS
  rc = nqdchain(dp, nd, &co, head, &r);
  Py_END_ALLOW_THREADS
  PyMem_Free((void *)dp);
  PyMem_Free(dl);
  PyMem_Free((void *)ap);
  PyMem_Free(al);
  rr = ddone(rc, r);
  if (rr == NULL) return NULL;
  return Py_BuildValue("(Ny#)", rr, (const char *)head, (Py_ssize_t)32);
}

static PyMethodDef meths[] = {
  {"setup", psetup, METH_O, "register the error classes"},
  {"version", pver, METH_NOARGS, "nqver()"},
  {"selftest", pself, METH_NOARGS, "nqselftest()"},
  {"salgs", psalgs, METH_NOARGS, "signature algorithms"},
  {"kalgs", pkalgs, METH_NOARGS, "KEM algorithms"},
  {"skg", pskg, METH_VARARGS, "nqskg / nqskgd"},
  {"sign", psign, METH_VARARGS, "nqsign / nqsignd"},
  {"vrfy", pvrfy, METH_VARARGS, "nqvrfy"},
  {"kkg", pkkg, METH_VARARGS, "nqkkg / nqkkgd"},
  {"enc", penc, METH_VARARGS, "nqenc / nqencd"},
  {"dec", pdec, METH_VARARGS, "nqdec"},
  {"hlen", phlen, METH_VARARGS, "nqhlen"},
  {"hash", phash, METH_VARARGS, "nqhash"},
  {"hmac", phmac, METH_VARARGS, "nqhmac"},
  {"seal", pseal, METH_VARARGS, "nqseal"},
  {"seal2", pseal2, METH_VARARGS, "nqseal2"},
  {"capid", pcapid, METH_VARARGS, "nqcapid"},
  {"chk", pchk, METH_VARARGS, "nqchkx / nqchkp"},
  {"prove", pprove, METH_VARARGS, "nqprove"},
  {"files", pfiles, METH_VARARGS, "nqfiles"},
  {"kstmt", pkstmt, METH_VARARGS, "nqkstmt"},
  {"dsse", pdsse, METH_VARARGS, "nqdsse"},
  {"dssevrfy", pdssevrfy, METH_VARARGS, "nqdssevrfy"},
  {"card", pcard, METH_VARARGS, "nqcard"},
  {"cardvrfy", pcardvrfy, METH_VARARGS, "nqcardvrfy"},
  {"dload", pdload, METH_VARARGS, "nqdload + nqdjson"},
  {"dput", pdput, METH_VARARGS, "nqdput + nqdsave"},
  {"dadd", pdadd, METH_VARARGS, "nqdsrc + nqdset + nqdsave"},
  {"ddel", pddel, METH_VARARGS, "nqddel + nqdsave"},
  {"dkey", pdkey, METH_VARARGS, "nqdkey"},
  {"dchk", pdchk, METH_VARARGS, "nqdchk"},
  {"dinfer", pdinfer, METH_VARARGS, "nqdinfer"},
  {"dstats", pdstats, METH_VARARGS, "nqdstats"},
  {"ddrift", pddrift, METH_VARARGS, "nqddriftat"},
  {"dsha", pdsha, METH_VARARGS, "nqdsha"},
  {"ddiff", pddiff, METH_VARARGS, "nqddiff"},
  {"daddr", pdaddr, METH_VARARGS, "nqdaddr"},
  {"dvrfy", pdvrfy, METH_VARARGS, "nqdvrfy"},
  {"dfld", pdfld, METH_VARARGS, "nqdfld"},
  {"drslv", pdrslv, METH_VARARGS, "nqdrslv"},
  {"drsp", pdrsp, METH_VARARGS, "nqdrsp"},
  {"dwb", pdwb, METH_VARARGS, "nqdwb"},
  {"rand", prand, METH_VARARGS, "nqrand"},
  {"cteq", pcteq, METH_VARARGS, "nqcteq"},
  {"b2b", pb2b, METH_VARARGS, "nqb2b"},
  {"kt", pkt, METH_VARARGS, "nqkt"},
  {"cha20", pcha20, METH_VARARGS, "nqcha20"},
  {"siv", psiv, METH_VARARGS, "nqsivenc, nqsivdec"},
  {"gsiv", pgsiv, METH_VARARGS, "nqgsivenc, nqgsivdec"},
  {"a2id", pa2id, METH_VARARGS, "nqa2id"},
  {"pwenc", ppwenc, METH_VARARGS, "nqpwenc"},
  {"pwdec", ppwdec, METH_VARARGS, "nqpwdec"},
  {"smu", psmu, METH_VARARGS, "nqsmu"},
  {"signmu", psignmu, METH_VARARGS, "nqsignmu"},
  {"vrfymu", pvrfymu, METH_VARARGS, "nqvrfymu"},
  {"hini", phini, METH_VARARGS, "nqhini"},
  {"hupd", phupd, METH_VARARGS, "nqhupd"},
  {"hfin", phfin, METH_VARARGS, "nqhfin"},
  {"sini", psini, METH_VARARGS, "nqsini / nqvini"},
  {"supd", psupd, METH_VARARGS, "nqsupd"},
  {"sfin", psfin, METH_VARARGS, "nqsfin"},
  {"vfin", pvfin, METH_VARARGS, "nqvfin"},
  {"kseal", pkseal, METH_VARARGS, "nqkseal"},
  {"kopen", pkopen, METH_VARARGS, "nqkopen"},
  {"kfeini", pkfeini, METH_VARARGS, "nqkfeini"},
  {"kfdini", pkfdini, METH_VARARGS, "nqkfdini"},
  {"kfupd", pkfupd, METH_VARARGS, "nqkfeupd / nqkfefin / nqkfdupd / nqkfdfin"},
  {"insp", pinsp, METH_VARARGS, "nqinsp"},
  {"sealwhy", psealwhy, METH_VARARGS, "nqsealwhy"},
  {"tsreq", ptsreq, METH_VARARGS, "nqtsreq / nqersreq"},
  {"tsput", ptsput, METH_VARARGS, "nqtsput / nqersput"},
  {"dparse", pdparse, METH_VARARGS, "nqdparse + nqdjson"},
  {"dschk", pdschk, METH_VARARGS, "nqdschk"},
  {"dsyn", pdsyn, METH_VARARGS, "nqdsyn + nqdsave"},
  {"dcal", pdcal, METH_VARARGS, "nqddcal"},
  {"dchunk", pdchunk, METH_VARARGS, "nqdchunk"},
  {"dpiece", pdpiece, METH_VARARGS, "nqdpiece"},
  {"dcommit", pdcommit, METH_VARARGS, "nqdcommit"},
  {"dreveal", pdreveal, METH_VARARGS, "nqdreveal"},
  {"dcite", pdcite, METH_VARARGS, "nqdcite"},
  {"drpt", pdrpt, METH_VARARGS, "nqdrpt"},
  {"dpack", pdpack, METH_VARARGS, "nqdpack"},
  {"dunpack", pdunpack, METH_VARARGS, "nqdunpack"},
  {"dchain", pdchain, METH_VARARGS, "nqdchain"},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mod = {
  PyModuleDef_HEAD_INIT, "noqtis._noqtis",
  "The C side of noqtis; use the noqtis package instead.", -1, meths,
  NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__noqtis(void);

PyMODINIT_FUNC PyInit__noqtis(void) {
  PyObject *m = PyModule_Create(&mod);
  if (m == NULL) return NULL;
  if (PyModule_AddIntConstant(m, "EVRFY", NQEVRFY) != 0 ||
      PyModule_AddIntConstant(m, "EDEC", NQEDEC) != 0) {
    Py_DECREF(m);
    return NULL;
  }
  return m;
}
