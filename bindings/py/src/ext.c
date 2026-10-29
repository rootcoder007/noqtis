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

#define NANC 32

/* chk(dir, pk or None, (anchor, ...)) -> (code, rows); raises when the
 * library made no report */
static PyObject *pchk(PyObject *self, PyObject *args) {
  const char *dir, *pk = NULL;
  Py_ssize_t pl = 0, na, i;
  PyObject *anc, *l, *out;
  const uint8_t *ap[NANC];
  size_t al[NANC];
  nqrep *r = NULL;
  int rc;
  (void)self;
  if (!PyArg_ParseTuple(args, "yz#O!", &dir, &pk, &pl, &PyTuple_Type, &anc))
    return NULL;
  na = PyTuple_Size(anc);
  if (na < 0) return NULL;
  if (na > NANC) return fail(NQEARG);
  for (i = 0; i < na; i++) {
    char *b;
    Py_ssize_t bl;
    if (PyBytes_AsStringAndSize(PyTuple_GetItem(anc, i), &b, &bl) != 0)
      return NULL;
    ap[i] = U8(b);
    al[i] = SZ(bl);
  }
  Py_BEGIN_ALLOW_THREADS
  rc = nqchkt(dir, U8(pk), SZ(pl), na > 0 ? ap : NULL, na > 0 ? al : NULL,
              SZ(na), &r);
  Py_END_ALLOW_THREADS
  if (r == NULL) return fail(rc == NQOK ? NQESTATE : rc);
  l = rows(r);
  nqrepfree(r);
  if (l == NULL) return NULL;
  out = Py_BuildValue("(iN)", rc, l);
  return out;
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
  {"chk", pchk, METH_VARARGS, "nqchkt"},
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
