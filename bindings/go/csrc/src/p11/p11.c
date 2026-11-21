/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * Keys on a token: PKCS #11 (OASIS, version 3.2 for the post-quantum
 * key types). A module, the shared library a token's maker ships, is
 * loaded; the private keys stay on the token, and the token signs and
 * decapsulates.
 *
 * The declarations below are the part of the standard's interface this
 * file calls, written from the specification: the function list is the
 * version and then the entry points in the order the standard fixes,
 * and the structures are packed on Windows as it requires.
 */
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"

#if defined(NQFREE) || defined(__EMSCRIPTEN__) || defined(__wasi__)
#define NOP11 1
#elif defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "p11/ck.h"

/* the entry points this file calls, by their place in the list */
enum {
  FINIT = 0, FFIN = 1, FSLOTS = 4, FTOKINFO = 6, FOPEN = 12, FCLOSE = 13,
  FLOGIN = 18, FLOGOUT = 19, FDESTROY = 22, FGETATTR = 24, FFINDINIT = 26,
  FFIND = 27, FFINDFIN = 28, FSIGNINIT = 42, FSIGN = 43, FGENPAIR = 59,
  FDECAP = 93
};
#define N240 68 /* entry points of version 2.40 */


struct nqp11 {
  void *lib;
  const ckfl *f;
  size_t nfn;   /* entry points the list has */
  ck sess;
  ck rv;        /* what the module last returned */
  int mine;     /* this handle initialised the module */
  int open;     /* a session is open */
};

typedef ck (*fvoidp)(void *);
typedef ck (*fslots)(unsigned char, ck *, ck *);
typedef ck (*ftokinfo)(ck, cktok *);
typedef ck (*fopen)(ck, ck, void *, void *, ck *);
typedef ck (*fsess)(ck);
typedef ck (*flogin)(ck, ck, unsigned char *, ck);
typedef ck (*fobj)(ck, ck);
typedef ck (*fattr)(ck, ck, ckattr *, ck);
typedef ck (*ffindinit)(ck, ckattr *, ck);
typedef ck (*ffind)(ck, ck *, ck, ck *);
typedef ck (*fsigninit)(ck, ckmech *, ck);
typedef ck (*fsign)(ck, unsigned char *, ck, unsigned char *, ck *);
typedef ck (*fgenpair)(ck, ckmech *, ckattr *, ck, ckattr *, ck, ck *, ck *);
typedef ck (*fdecap)(ck, ckmech *, ck, ckattr *, ck, unsigned char *, ck,
                     ck *);

#define FN(p, i, t) ((t)(p)->f->fn[i])

unsigned long nqp11why(const nqp11 *p) { return p != NULL ? p->rv : 0; }

#ifdef NOP11

int nqp11open(const char *module, nqp11 **p) {
  (void)module;
  if (p != NULL) *p = NULL;
  return NQENOSUP;
}
void nqp11close(nqp11 *p) { (void)p; }
int nqp11toks(nqp11 *p, nqp11t *t, size_t cap, size_t *n) {
  (void)p; (void)t; (void)cap;
  if (n != NULL) *n = 0;
  return NQENOSUP;
}
int nqp11login(nqp11 *p, unsigned long slot, const char *pin, size_t pinlen) {
  (void)p; (void)slot; (void)pin; (void)pinlen;
  return NQENOSUP;
}
int nqp11keys(nqp11 *p, nqp11k *k, size_t cap, size_t *n) {
  (void)p; (void)k; (void)cap;
  if (n != NULL) *n = 0;
  return NQENOSUP;
}
int nqp11pub(nqp11 *p, const nqp11k *k, uint8_t *pk, size_t cap,
             size_t *pklen) {
  (void)p; (void)k; (void)pk; (void)cap;
  if (pklen != NULL) *pklen = 0;
  return NQENOSUP;
}
int nqp11sign(nqp11 *p, const nqp11k *k, const uint8_t *msg, size_t n,
              const uint8_t *ctx, size_t ctxlen, uint8_t *sig, size_t cap,
              size_t *siglen) {
  (void)p; (void)k; (void)msg; (void)n; (void)ctx; (void)ctxlen; (void)sig;
  (void)cap;
  if (siglen != NULL) *siglen = 0;
  return NQENOSUP;
}
int nqp11dec(nqp11 *p, const nqp11k *k, const uint8_t *ct, size_t ctlen,
             uint8_t *ss, size_t sslen) {
  (void)p; (void)k; (void)ct; (void)ctlen; (void)ss; (void)sslen;
  return NQENOSUP;
}
int nqp11gen(nqp11 *p, int kem, int alg, const char *label, nqp11k *k) {
  (void)p; (void)kem; (void)alg; (void)label; (void)k;
  return NQENOSUP;
}

#else /* a system that loads shared libraries */

/* the object identifier of Ed25519 (RFC 8410), as CKA_EC_PARAMS */
static const unsigned char ed25519oid[5] = {0x06, 0x03, 0x2b, 0x65, 0x70};

/* what a module's return value is to the caller */
static int rvmap(nqp11 *p, ck rv) {
  p->rv = rv;
  switch (rv) {
  case CKR_OK:
    return NQOK;
  case CKR_HOST_MEMORY:
    return NQEMEM;
  case CKR_PIN_INCORRECT:
  case CKR_PIN_INVALID:
  case CKR_PIN_LEN_RANGE:
  case CKR_PIN_EXPIRED:
  case CKR_PIN_LOCKED:
    return NQEVRFY;
  case CKR_FUNCTION_NOT_SUPPORTED:
  case CKR_MECHANISM_INVALID:
    return NQENOSUP;
  case CKR_BUFFER_TOO_SMALL:
    return NQEBUF;
  default:
    return NQEIO;
  }
}

static void *libopen(const char *path) {
#ifdef _WIN32
  wchar_t w[1024];
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w,
                          (int)(sizeof w / sizeof w[0])) <= 0)
    return NULL;
  return (void *)LoadLibraryW(w);
#else
  return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void libclose(void *lib) {
#ifdef _WIN32
  FreeLibrary((HMODULE)lib);
#else
  dlclose(lib);
#endif
}

/* an entry point of the library by name, NULL when it has none. The
 * address goes by memcpy: ISO C has no conversion of an object pointer
 * to a function pointer, and every system with shared libraries keeps
 * the two the same size. */
static ckfn libsym(void *lib, const char *name) {
  ckfn f = NULL;
#ifdef _WIN32
  FARPROC s = GetProcAddress((HMODULE)lib, name);
  if (s != NULL) memcpy(&f, &s, sizeof f);
#else
  void *s = dlsym(lib, name);
  if (s != NULL) memcpy(&f, &s, sizeof f);
#endif
  return f;
}

int nqp11open(const char *module, nqp11 **out) {
  typedef ck (*fgetfl)(const ckfl **);
  typedef ck (*fgetif)(unsigned char *, ckver *, ckif **, ck);
  nqp11 *p;
  ckinit ia;
  ckfn s;
  ck rv;
  if (out != NULL) *out = NULL;
  if (module == NULL || out == NULL) return NQEARG;
  /* a path, never a bare name: the loader would then search its own
   * folders, and load what it finds there */
  if (strchr(module, '/') == NULL
#ifdef _WIN32
      && strchr(module, '\\') == NULL
#endif
  )
    return NQEARG;
  p = (nqp11 *)nqmal(sizeof *p);
  if (p == NULL) return NQEMEM;
  memset(p, 0, sizeof *p);
  p->lib = libopen(module);
  if (p->lib == NULL) {
    nqfree(p, sizeof *p);
    return NQEIO;
  }
  /* the version 3 interface when the module has one, for its longer
   * list (C_DecapsulateKey is of 3.2); else the list of 2.40 */
  s = libsym(p->lib, "C_GetInterface");
  if (s != NULL) {
    ckif *itf = NULL;
    rv = ((fgetif)s)(NULL, NULL, &itf, 0);
    if (rv == CKR_OK && itf != NULL && itf->fl != NULL) {
      p->f = (const ckfl *)itf->fl;
      /* 3.0 has 92 entry points, 3.2 has 104 */
      p->nfn = p->f->ver.major < 3 ? N240
               : p->f->ver.minor >= 2 || p->f->ver.major > 3 ? 104 : 92;
    }
  }
  if (p->f == NULL) {
    s = libsym(p->lib, "C_GetFunctionList");
    if (s == NULL || ((fgetfl)s)(&p->f) != CKR_OK || p->f == NULL) {
      libclose(p->lib);
      nqfree(p, sizeof *p);
      return NQEDEC; /* not a PKCS #11 module */
    }
    p->nfn = N240;
  }
  /* threads of the caller may use it: the module locks for itself */
  memset(&ia, 0, sizeof ia);
  ia.flags = CKF_OS_LOCKING_OK;
  rv = FN(p, FINIT, fvoidp)(&ia);
  if (rv == CKR_CANT_LOCK) rv = FN(p, FINIT, fvoidp)(NULL);
  if (rv == CKR_OK) {
    p->mine = 1;
  } else if (rv != CKR_ALREADY_INITIALIZED) {
    int rc = rvmap(p, rv);
    libclose(p->lib);
    nqfree(p, sizeof *p);
    return rc;
  }
  *out = p;
  return NQOK;
}

void nqp11close(nqp11 *p) {
  if (p == NULL) return;
  if (p->open) {
    (void)FN(p, FLOGOUT, fsess)(p->sess);
    (void)FN(p, FCLOSE, fsess)(p->sess);
  }
  if (p->mine) (void)FN(p, FFIN, fvoidp)(NULL);
  libclose(p->lib);
  nqfree(p, sizeof *p);
}

/* a field of the standard, padded with spaces, as a string */
static void field(char *o, size_t cap, const unsigned char *f, size_t n) {
  size_t i;
  while (n > 0 && (f[n - 1] == ' ' || f[n - 1] == '\0')) n--;
  if (n > cap - 1) n = cap - 1;
  for (i = 0; i < n; i++)
    o[i] = f[i] >= 0x20 && f[i] < 0x7f ? (char)f[i] : '?';
  o[n] = '\0';
}

int nqp11toks(nqp11 *p, nqp11t *t, size_t cap, size_t *n) {
  ck slots[64], cnt = 64, i;
  cktok ti;
  int rc;
  if (n != NULL) *n = 0;
  if (p == NULL || n == NULL || (t == NULL && cap != 0)) return NQEARG;
  rc = rvmap(p, FN(p, FSLOTS, fslots)(1, slots, &cnt));
  if (rc == NQEBUF) return NQELIM; /* more than 64 tokens */
  if (rc != NQOK) return rc;
  for (i = 0; i < cnt; i++) {
    memset(&ti, 0, sizeof ti);
    if (FN(p, FTOKINFO, ftokinfo)(slots[i], &ti) != CKR_OK) continue;
    if (*n < cap) {
      nqp11t *e = &t[*n];
      memset(e, 0, sizeof *e);
      e->slot = slots[i];
      field(e->label, sizeof e->label, ti.label, 32);
      field(e->maker, sizeof e->maker, ti.maker, 32);
      field(e->model, sizeof e->model, ti.model, 16);
      field(e->serial, sizeof e->serial, ti.serial, 16);
      e->login = (ti.flags & CKF_LOGIN_REQUIRED) != 0;
    }
    (*n)++;
  }
  return *n > cap ? NQEBUF : NQOK;
}

int nqp11login(nqp11 *p, unsigned long slot, const char *pin, size_t pinlen) {
  ck rv, s = 0;
  if (p == NULL || (pin == NULL && pinlen != 0) || pinlen > 255)
    return NQEARG;
  if (p->open) return NQESTATE;
  /* to read and write, for keys made on the token; a token that is
   * read-only gives a session to read */
  rv = FN(p, FOPEN, fopen)(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                           NULL, &s);
  if (rv != CKR_OK)
    rv = FN(p, FOPEN, fopen)(slot, CKF_SERIAL_SESSION, NULL, NULL, &s);
  if (rv != CKR_OK) return rvmap(p, rv);
  if (pin != NULL) {
    unsigned char pb[256];
    memcpy(pb, pin, pinlen);
    rv = FN(p, FLOGIN, flogin)(s, 1, pb, (ck)pinlen);
    nqwipe(pb, sizeof pb);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
      (void)FN(p, FCLOSE, fsess)(s);
      return rvmap(p, rv);
    }
  }
  p->sess = s;
  p->open = 1;
  p->rv = CKR_OK;
  return NQOK;
}

/* one attribute of an object into b: its length, or NOVAL when the
 * object has none or does not show it */
static ck getattr(nqp11 *p, ck obj, ck type, void *b, size_t cap) {
  ckattr a;
  a.type = type;
  a.val = b;
  a.len = (ck)cap;
  if (FN(p, FGETATTR, fattr)(p->sess, obj, &a, 1) != CKR_OK) return NOVAL;
  return a.len > cap ? NOVAL : a.len;
}

/* the noqtis algorithm of a key type and its parameter set, 0 when it
 * is none of them */
static int algof(ck kt, ck ps, int *kem) {
  static const nqsalg slh[12] = {NQSLH128S, NQSLHK128S, NQSLH128F, NQSLHK128F,
                                 NQSLH192S, NQSLHK192S, NQSLH192F, NQSLHK192F,
                                 NQSLH256S, NQSLHK256S, NQSLH256F, NQSLHK256F};
  *kem = 0;
  if (kt == CKK_ML_DSA && ps >= 1 && ps <= 3)
    return (int)NQMLDSA44 + (int)ps - 1;
  if (kt == CKK_SLH_DSA && ps >= 1 && ps <= 12) return (int)slh[ps - 1];
  if (kt == CKK_EC_EDWARDS) return (int)NQED25519;
  if (kt == CKK_ML_KEM && ps >= 1 && ps <= 3) {
    *kem = 1;
    return (int)NQMLKEM512 + (int)ps - 1;
  }
  return 0;
}

/* the key type and parameter set of a noqtis algorithm */
static int typeof11(int kem, int alg, ck *kt, ck *ps) {
  ck i;
  int k;
  static const ck kts[4] = {CKK_ML_DSA, CKK_SLH_DSA, CKK_EC_EDWARDS,
                            CKK_ML_KEM};
  size_t j;
  for (j = 0; j < 4; j++) {
    for (i = 1; i <= 12; i++) {
      if (algof(kts[j], i, &k) == alg && k == (kem != 0) && alg != 0) {
        *kt = kts[j];
        *ps = i;
        return NQOK;
      }
    }
  }
  return NQENOSUP;
}

/* reads what a key object says of itself into k: NQOK, or NQENOSUP for
 * a key of a kind noqtis has no use for */
static int keyread(nqp11 *p, ck obj, nqp11k *k) {
  ck kt = 0, ps = 0, l;
  unsigned char lab[64], oid[16];
  size_t i;
  memset(k, 0, sizeof *k);
  if (getattr(p, obj, CKA_KEY_TYPE, &kt, sizeof kt) != sizeof kt)
    return NQENOSUP;
  if (kt != CKK_EC_EDWARDS &&
      getattr(p, obj, CKA_PARAMETER_SET, &ps, sizeof ps) != sizeof ps)
    return NQENOSUP;
  if (kt == CKK_EC_EDWARDS) {
    /* Ed25519 alone, named by its object identifier or as a curve */
    l = getattr(p, obj, CKA_EC_PARAMS, oid, sizeof oid);
    if (l != NOVAL &&
        !(l == sizeof ed25519oid && memcmp(oid, ed25519oid, l) == 0) &&
        !(l == 14 && memcmp(oid + 2, "edwards25519", 12) == 0))
      return NQENOSUP;
  }
  k->alg = algof(kt, ps, &k->kem);
  if (k->alg == 0) return NQENOSUP;
  k->h = obj;
  l = getattr(p, obj, CKA_LABEL, lab, sizeof lab);
  if (l != NOVAL) {
    for (i = 0; i < l; i++)
      k->label[i] = lab[i] >= 0x20 && lab[i] != 0x7f ? (char)lab[i] : '?';
  }
  l = getattr(p, obj, CKA_ID, k->id, sizeof k->id);
  k->idlen = l == NOVAL ? 0 : (size_t)l;
  return NQOK;
}

int nqp11keys(nqp11 *p, nqp11k *k, size_t cap, size_t *n) {
  ck cls = CKO_PRIVATE_KEY, obj[16], got = 0, i;
  ckattr t;
  nqp11k e;
  int rc;
  if (n != NULL) *n = 0;
  if (p == NULL || n == NULL || (k == NULL && cap != 0)) return NQEARG;
  if (!p->open) return NQESTATE;
  t.type = CKA_CLASS;
  t.val = &cls;
  t.len = sizeof cls;
  rc = rvmap(p, FN(p, FFINDINIT, ffindinit)(p->sess, &t, 1));
  if (rc != NQOK) return rc;
  for (;;) {
    rc = rvmap(p, FN(p, FFIND, ffind)(p->sess, obj, 16, &got));
    if (rc != NQOK || got == 0 || got > 16) break;
    for (i = 0; i < got; i++) {
      if (keyread(p, obj[i], &e) != NQOK) continue;
      if (*n < cap) k[*n] = e;
      (*n)++;
    }
  }
  (void)FN(p, FFINDFIN, fsess)(p->sess);
  if (rc != NQOK) return rc;
  return *n > cap ? NQEBUF : NQOK;
}

static size_t pubsize(const nqp11k *k) {
  nqssz sz;
  nqksz kz;
  if (k->kem) return nqksize((nqkalg)k->alg, &kz) == NQOK ? kz.pk : 0;
  return nqssize((nqsalg)k->alg, &sz) == NQOK ? sz.pk : 0;
}

int nqp11pub(nqp11 *p, const nqp11k *k, uint8_t *pk, size_t cap,
             size_t *pklen) {
  ck cls = CKO_PUBLIC_KEY, obj = 0, got = 0, l;
  ckattr t[2];
  uint8_t *b;
  size_t need, bn;
  int rc;
  if (pklen != NULL) *pklen = 0;
  if (p == NULL || k == NULL || pklen == NULL || (pk == NULL && cap != 0))
    return NQEARG;
  if (!p->open) return NQESTATE;
  need = pubsize(k);
  if (need == 0) return NQEARG;
  *pklen = need;
  if (pk == NULL) return NQOK;
  if (cap < need) return NQEBUF;
  /* room for a SubjectPublicKeyInfo around the key */
  bn = need + 64;
  b = (uint8_t *)nqmal(bn);
  if (b == NULL) return NQEMEM;
  /* the public key object of the same ID */
  rc = NQEIO;
  if (k->idlen > 0) {
    t[0].type = CKA_CLASS;
    t[0].val = &cls;
    t[0].len = sizeof cls;
    t[1].type = CKA_ID;
    t[1].val = (void *)(uintptr_t)k->id;
    t[1].len = (ck)k->idlen;
    if (FN(p, FFINDINIT, ffindinit)(p->sess, t, 2) == CKR_OK) {
      if (FN(p, FFIND, ffind)(p->sess, &obj, 1, &got) != CKR_OK) got = 0;
      (void)FN(p, FFINDFIN, fsess)(p->sess);
    }
  }
  if (got == 1) {
    if (!k->kem && k->alg == (int)NQED25519) {
      /* the point: the 32 bytes, or those in a DER OCTET STRING */
      l = getattr(p, obj, CKA_EC_POINT, b, bn);
      if (l == 32) {
        memcpy(pk, b, 32);
        rc = NQOK;
      } else if (l == 34 && b[0] == 0x04 && b[1] == 0x20) {
        memcpy(pk, b + 2, 32);
        rc = NQOK;
      }
    } else {
      l = getattr(p, obj, CKA_VALUE, b, bn);
      if (l == need) {
        memcpy(pk, b, need);
        rc = NQOK;
      }
    }
  }
  if (rc != NQOK) {
    /* the private key's own SubjectPublicKeyInfo: the key is the end
     * of its BIT STRING */
    l = getattr(p, (ck)k->h, CKA_PUBLIC_KEY_INFO, b, bn);
    if (l != NOVAL && l > need && l <= bn && b[0] == 0x30) {
      memcpy(pk, b + l - need, need);
      rc = NQOK;
    }
  }
  nqfree(b, bn);
  if (rc != NQOK) *pklen = 0;
  return rc;
}

int nqp11sign(nqp11 *p, const nqp11k *k, const uint8_t *msg, size_t n,
              const uint8_t *ctx, size_t ctxlen, uint8_t *sig, size_t cap,
              size_t *siglen) {
  nqssz sz;
  ckmech m;
  cksctx sc;
  cked ed;
  ck sl;
  int rc;
  if (siglen != NULL) *siglen = 0;
  if (p == NULL || k == NULL || siglen == NULL || sig == NULL ||
      (msg == NULL && n != 0) || (ctx == NULL && ctxlen != 0) ||
      ctxlen > 255 || k->kem)
    return NQEARG;
  if (!p->open) return NQESTATE;
  if (n > ULONG_MAX) return NQELIM;
  rc = nqssize((nqsalg)k->alg, &sz);
  if (rc != NQOK) return NQEARG;
  if (cap < sz.sig) {
    *siglen = sz.sig;
    return NQEBUF;
  }
  memset(&m, 0, sizeof m);
  if (k->alg == (int)NQED25519) {
    /* no parameter: Ed25519; with a context: Ed25519ctx */
    m.mech = CKM_EDDSA;
    if (ctxlen > 0) {
      ed.ph = 0;
      ed.len = (ck)ctxlen;
      ed.ctx = (unsigned char *)(uintptr_t)ctx;
      m.par = &ed;
      m.len = sizeof ed;
    }
  } else {
    m.mech = k->alg <= (int)NQMLDSA87 ? CKM_ML_DSA : CKM_SLH_DSA;
    if (ctxlen > 0) {
      sc.hedge = 0; /* hedged when the token can */
      sc.ctx = (unsigned char *)(uintptr_t)ctx;
      sc.len = (ck)ctxlen;
      m.par = &sc;
      m.len = sizeof sc;
    }
  }
  rc = rvmap(p, FN(p, FSIGNINIT, fsigninit)(p->sess, &m, (ck)k->h));
  if (rc != NQOK) return rc;
  sl = (ck)cap;
  rc = rvmap(p, FN(p, FSIGN, fsign)(p->sess, (unsigned char *)(uintptr_t)msg,
                                    (ck)n, sig, &sl));
  if (rc != NQOK) return rc;
  if (sl != sz.sig) return NQEIO; /* not a signature of this algorithm */
  *siglen = sz.sig;
  return NQOK;
}

int nqp11dec(nqp11 *p, const nqp11k *k, const uint8_t *ct, size_t ctlen,
             uint8_t *ss, size_t sslen) {
  ck cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET, vl = 32, key = 0;
  unsigned char no = 0, yes = 1;
  ckattr t[6];
  ckmech m;
  nqksz kz;
  int rc;
  if (p == NULL || k == NULL || ct == NULL || ss == NULL || !k->kem)
    return NQEARG;
  if (!p->open) return NQESTATE;
  if (k->alg < (int)NQMLKEM512 || k->alg > (int)NQMLKEM1024 ||
      nqksize((nqkalg)k->alg, &kz) != NQOK)
    return NQENOSUP;
  if (ctlen != kz.ct || sslen != kz.ss) return NQEARG;
  /* C_DecapsulateKey is of version 3.2 */
  if (p->nfn <= FDECAP || p->f->fn[FDECAP] == NULL) return NQENOSUP;
  /* the shared secret as a session object that may be read */
  t[0].type = CKA_CLASS;
  t[0].val = &cls;
  t[0].len = sizeof cls;
  t[1].type = CKA_KEY_TYPE;
  t[1].val = &kt;
  t[1].len = sizeof kt;
  t[2].type = CKA_VALUE_LEN;
  t[2].val = &vl;
  t[2].len = sizeof vl;
  t[3].type = CKA_TOKEN;
  t[3].val = &no;
  t[3].len = 1;
  t[4].type = CKA_SENSITIVE;
  t[4].val = &no;
  t[4].len = 1;
  t[5].type = CKA_EXTRACTABLE;
  t[5].val = &yes;
  t[5].len = 1;
  memset(&m, 0, sizeof m);
  m.mech = CKM_ML_KEM;
  rc = rvmap(p, FN(p, FDECAP, fdecap)(p->sess, &m, (ck)k->h, t, 6,
                                      (unsigned char *)(uintptr_t)ct,
                                      (ck)ctlen, &key));
  if (rc != NQOK) return rc;
  rc = getattr(p, key, CKA_VALUE, ss, sslen) == (ck)sslen ? NQOK : NQEIO;
  (void)FN(p, FDESTROY, fobj)(p->sess, key);
  if (rc != NQOK) nqwipe(ss, sslen);
  return rc;
}

int nqp11gen(nqp11 *p, int kem, int alg, const char *label, nqp11k *k) {
  ck kt = 0, ps = 0, hpub = 0, hpriv = 0;
  unsigned char yes = 1, no = 0, id[16];
  ckattr pub[6], prv[8];
  ckmech m;
  ck np = 0, nv = 0;
  size_t ll;
  int rc;
  if (k != NULL) memset(k, 0, sizeof *k);
  if (p == NULL || label == NULL || k == NULL) return NQEARG;
  ll = strlen(label);
  if (ll == 0 || ll > 64) return NQEARG;
  if (!p->open) return NQESTATE;
  rc = typeof11(kem, alg, &kt, &ps);
  if (rc != NQOK) return rc;
  rc = nqrand(id, sizeof id);
  if (rc != NQOK) return rc;
  memset(&m, 0, sizeof m);
  m.mech = kt == CKK_ML_DSA    ? CKM_ML_DSA_KEY_PAIR_GEN
           : kt == CKK_SLH_DSA ? CKM_SLH_DSA_KEY_PAIR_GEN
           : kt == CKK_ML_KEM  ? CKM_ML_KEM_KEY_PAIR_GEN
                               : CKM_EC_EDWARDS_KEY_PAIR_GEN;
#define AT(a, i, ty, v, l)                                                    \
  do {                                                                        \
    (a)[i].type = (ty);                                                       \
    (a)[i].val = (void *)(uintptr_t)(v);                                      \
    (a)[i].len = (ck)(l);                                                     \
    (i)++;                                                                    \
  } while (0)
  /* the public key: kept on the token, to verify or encapsulate with */
  AT(pub, np, CKA_TOKEN, &yes, 1);
  AT(pub, np, kem ? CKA_ENCAPSULATE : CKA_VERIFY, &yes, 1);
  AT(pub, np, CKA_LABEL, label, ll);
  AT(pub, np, CKA_ID, id, sizeof id);
  if (kt == CKK_EC_EDWARDS)
    AT(pub, np, CKA_EC_PARAMS, ed25519oid, sizeof ed25519oid);
  else
    AT(pub, np, CKA_PARAMETER_SET, &ps, sizeof ps);
  /* the private key: on the token, behind the login, never to leave */
  AT(prv, nv, CKA_TOKEN, &yes, 1);
  AT(prv, nv, CKA_PRIVATE, &yes, 1);
  AT(prv, nv, CKA_SENSITIVE, &yes, 1);
  AT(prv, nv, CKA_EXTRACTABLE, &no, 1);
  AT(prv, nv, kem ? CKA_DECAPSULATE : CKA_SIGN, &yes, 1);
  AT(prv, nv, CKA_LABEL, label, ll);
  AT(prv, nv, CKA_ID, id, sizeof id);
#undef AT
  rc = rvmap(p, FN(p, FGENPAIR, fgenpair)(p->sess, &m, pub, np, prv, nv,
                                          &hpub, &hpriv));
  if (rc != NQOK) return rc;
  rc = keyread(p, hpriv, k);
  /* a token that made a key it then cannot describe */
  return rc == NQOK && k->alg == alg && k->kem == (kem != 0) ? NQOK : NQEIO;
}

#endif
