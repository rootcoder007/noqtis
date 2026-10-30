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
  return nqkstmt((nqsalg)a->alg, U8(a->sk), SZ(a->skl), U8(a->pk),
                 SZ(a->pkl), (nqsalg)a->nalg, U8(a->nsk), SZ(a->nskl),
                 U8(a->npk), SZ(a->npkl), (int64_t)a->at, a->why, out, cap,
                 outlen);
}

/* kstmt(alg, sk, pk, nalg, nsk or None, npk or None, at, reason or None)
 * -> statement */
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

static PyMethodDef meths[] = {
  {"setup", psetup, METH_O, "register the error classes"},
  {"version", pver, METH_NOARGS, "nqver()"},
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
