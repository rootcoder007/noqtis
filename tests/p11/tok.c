/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * A software token for the tests: a PKCS #11 module (version 3.2) over
 * noqtis itself, with one slot, one token and the PIN 1234. It makes
 * ML-DSA, SLH-DSA, Ed25519 and ML-KEM keys, signs and decapsulates.
 * Keys are kept as their seeds, in memory, and in the file $NQTOKFILE
 * when that is set, so that another process finds them. With
 * $NQTOK240 set it has the function list of version 2.40 alone.
 *
 * A test double, not a product: nothing here protects a key.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "p11/ck.h"

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#define NKEY 32
#define NSEC 8
#define SESS 7ul

typedef struct {
  int used, kem, alg;
  char label[65];
  size_t lablen;
  unsigned char id[32];
  size_t idlen;
  unsigned char seed[96];
  size_t seedlen;
  uint8_t *pk, *sk;
  size_t pkn, skn;
} tkey;

static tkey keys[NKEY];
static unsigned char secs[NSEC][32];
static int secused[NSEC];
static int inited, opened, logged;
static int signkey = -1;       /* the key of the sign operation begun */
static unsigned char sctx[255];
static size_t sctxn;
static ck findcls;             /* the search begun */
static unsigned char findid[32];
static size_t findidn;
static int finding, findat, findany;

/* handles: private key i is 2i+1, public key i is 2i+2, secret j is
 * 1000+j */
#define HPRIV(i) ((ck)(2 * (i) + 1))
#define HPUB(i) ((ck)(2 * (i) + 2))

static size_t seedsize(int kem, int alg) {
  nqssz z;
  if (kem) return 64;
  if (alg >= (int)NQSLH128S && alg <= (int)NQSLHK256F)
    return nqssize((nqsalg)alg, &z) == NQOK ? 3 * z.pk / 2 : 0;
  return 32;
}

/* the key pair of a key's seed */
static int derive(tkey *k) {
  nqssz z;
  nqksz kz;
  int rc;
  if (k->kem) {
    if (nqksize((nqkalg)k->alg, &kz) != NQOK) return 0;
    k->pkn = kz.pk;
    k->skn = kz.sk;
  } else {
    if (nqssize((nqsalg)k->alg, &z) != NQOK) return 0;
    k->pkn = z.pk;
    k->skn = z.sk;
  }
  k->pk = (uint8_t *)malloc(k->pkn);
  k->sk = (uint8_t *)malloc(k->skn);
  if (k->pk == NULL || k->sk == NULL) return 0;
  rc = k->kem ? nqkkgd((nqkalg)k->alg, k->seed, k->seedlen, k->pk, k->pkn,
                       k->sk, k->skn)
              : nqskgd((nqsalg)k->alg, k->seed, k->seedlen, k->pk, k->pkn,
                       k->sk, k->skn);
  return rc == NQOK;
}

static void drop(void) {
  int i;
  for (i = 0; i < NKEY; i++) {
    free(keys[i].pk);
    free(keys[i].sk);
  }
  memset(keys, 0, sizeof keys);
  memset(secused, 0, sizeof secused);
}

/* the file of the keys: one record a key, the fields and the seed */
static void load(void) {
  const char *path = getenv("NQTOKFILE");
  FILE *f;
  int i = 0;
  if (path == NULL || path[0] == '\0') return;
  f = fopen(path, "rb");
  if (f == NULL) return;
  while (i < NKEY) {
    tkey *k = &keys[i];
    unsigned char h[8];
    if (fread(h, 1, 8, f) != 8) break;
    k->kem = h[0];
    k->alg = h[1];
    k->lablen = h[2];
    k->idlen = h[3];
    k->seedlen = h[4];
    if (k->lablen > 64 || k->idlen > 32 || k->seedlen > 96 ||
        fread(k->label, 1, k->lablen, f) != k->lablen ||
        fread(k->id, 1, k->idlen, f) != k->idlen ||
        fread(k->seed, 1, k->seedlen, f) != k->seedlen || !derive(k))
      break;
    k->used = 1;
    i++;
  }
  fclose(f);
}

static void save(const tkey *k) {
  const char *path = getenv("NQTOKFILE");
  unsigned char h[8] = {0};
  FILE *f;
  if (path == NULL || path[0] == '\0') return;
  f = fopen(path, "ab");
  if (f == NULL) return;
  h[0] = (unsigned char)k->kem;
  h[1] = (unsigned char)k->alg;
  h[2] = (unsigned char)k->lablen;
  h[3] = (unsigned char)k->idlen;
  h[4] = (unsigned char)k->seedlen;
  fwrite(h, 1, 8, f);
  fwrite(k->label, 1, k->lablen, f);
  fwrite(k->id, 1, k->idlen, f);
  fwrite(k->seed, 1, k->seedlen, f);
  fclose(f);
}

static ck nosup(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

static ck tinit(void *a) {
  (void)a;
  if (inited) return CKR_ALREADY_INITIALIZED;
  drop();
  load();
  inited = 1;
  opened = logged = 0;
  return CKR_OK;
}

static ck tfin(void *a) {
  (void)a;
  if (!inited) return CKR_NOT_INITIALIZED;
  drop();
  inited = opened = logged = 0;
  return CKR_OK;
}

static ck tslots(unsigned char present, ck *list, ck *n) {
  (void)present;
  if (!inited) return CKR_NOT_INITIALIZED;
  if (n == NULL) return CKR_ARGUMENTS_BAD;
  if (list != NULL) {
    if (*n < 1) {
      *n = 1;
      return CKR_BUFFER_TOO_SMALL;
    }
    list[0] = 0;
  }
  *n = 1;
  return CKR_OK;
}

static void pad(unsigned char *o, size_t n, const char *s) {
  size_t l = strlen(s);
  memset(o, ' ', n);
  memcpy(o, s, l < n ? l : n);
}

static ck ttokinfo(ck slot, cktok *t) {
  if (!inited) return CKR_NOT_INITIALIZED;
  if (slot != 0) return CKR_SLOT_ID_INVALID;
  if (t == NULL) return CKR_ARGUMENTS_BAD;
  memset(t, 0, sizeof *t);
  pad(t->label, 32, "noqtis test token");
  pad(t->maker, 32, "noqtis");
  pad(t->model, 16, "software");
  pad(t->serial, 16, "0001");
  t->flags = CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED |
             CKF_USER_PIN_INITIALIZED;
  t->maxpin = 255;
  t->minpin = 4;
  return CKR_OK;
}

static ck topen(ck slot, ck flags, void *app, void *notify, ck *s) {
  (void)app;
  (void)notify;
  if (!inited) return CKR_NOT_INITIALIZED;
  if (slot != 0) return CKR_SLOT_ID_INVALID;
  if (s == NULL || (flags & CKF_SERIAL_SESSION) == 0) return CKR_ARGUMENTS_BAD;
  opened = 1;
  *s = SESS;
  return CKR_OK;
}

static ck tclose(ck s) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  opened = logged = 0;
  signkey = -1;
  finding = 0;
  return CKR_OK;
}

static ck tlogin(ck s, ck user, unsigned char *pin, ck n) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (user != 1) return CKR_ARGUMENTS_BAD;
  if (logged) return CKR_USER_ALREADY_LOGGED_IN;
  if (pin == NULL || n != 4 || memcmp(pin, "1234", 4) != 0)
    return CKR_PIN_INCORRECT;
  logged = 1;
  return CKR_OK;
}

static ck tlogout(ck s) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  logged = 0;
  return CKR_OK;
}

/* the key of a handle, and whether the handle is its private part */
static tkey *keyof(ck h, int *priv) {
  ck i;
  if (h < 1 || h > 2 * NKEY) return NULL;
  i = (h - 1) / 2;
  if (!keys[i].used) return NULL;
  *priv = (h & 1) != 0;
  return &keys[i];
}

static ck ktype(const tkey *k, ck *ps) {
  static const ck slh[12] = {1, 3, 5, 7, 9, 11, 2, 4, 6, 8, 10, 12};
  *ps = 0;
  if (k->kem) {
    *ps = (ck)(k->alg - (int)NQMLKEM512 + 1);
    return CKK_ML_KEM;
  }
  if (k->alg <= (int)NQMLDSA87) {
    *ps = (ck)(k->alg - (int)NQMLDSA44 + 1);
    return CKK_ML_DSA;
  }
  if (k->alg == (int)NQED25519) return CKK_EC_EDWARDS;
  *ps = slh[k->alg - (int)NQSLH128S];
  return CKK_SLH_DSA;
}

static ck tdestroy(ck s, ck h) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (h >= 1000 && h < 1000 + NSEC && secused[h - 1000]) {
    secused[h - 1000] = 0;
    memset(secs[h - 1000], 0, 32);
    return CKR_OK;
  }
  return CKR_OBJECT_HANDLE_INVALID;
}

/* gives len bytes at v as the value of an attribute */
static ck give(ckattr *a, const void *v, size_t len) {
  if (a->val == NULL) {
    a->len = (ck)len;
    return CKR_OK;
  }
  if (a->len < len) {
    a->len = NOVAL;
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(a->val, v, len);
  a->len = (ck)len;
  return CKR_OK;
}

static ck tgetattr(ck s, ck h, ckattr *t, ck n) {
  static const unsigned char oid[5] = {0x06, 0x03, 0x2b, 0x65, 0x70};
  ck rv = CKR_OK, i, r, ps, kt, cls;
  unsigned char pt[34];
  tkey *k;
  int priv = 0;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (t == NULL) return CKR_ARGUMENTS_BAD;
  if (h >= 1000 && h < 1000 + NSEC && secused[h - 1000]) {
    for (i = 0; i < n; i++) {
      if (t[i].type == CKA_VALUE) {
        r = give(&t[i], secs[h - 1000], 32);
      } else {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_TYPE_INVALID;
      }
      if (r != CKR_OK) rv = r;
    }
    return rv;
  }
  k = keyof(h, &priv);
  if (k == NULL || (priv && !logged)) return CKR_OBJECT_HANDLE_INVALID;
  kt = ktype(k, &ps);
  cls = priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
  for (i = 0; i < n; i++) {
    switch (t[i].type) {
    case CKA_CLASS:
      r = give(&t[i], &cls, sizeof cls);
      break;
    case CKA_KEY_TYPE:
      r = give(&t[i], &kt, sizeof kt);
      break;
    case CKA_LABEL:
      r = give(&t[i], k->label, k->lablen);
      break;
    case CKA_ID:
      r = give(&t[i], k->id, k->idlen);
      break;
    case CKA_PARAMETER_SET:
      if (kt == CKK_EC_EDWARDS) {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_TYPE_INVALID;
      } else {
        r = give(&t[i], &ps, sizeof ps);
      }
      break;
    case CKA_EC_PARAMS:
      if (kt != CKK_EC_EDWARDS) {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_TYPE_INVALID;
      } else {
        r = give(&t[i], oid, sizeof oid);
      }
      break;
    case CKA_EC_POINT:
      if (kt != CKK_EC_EDWARDS || priv) {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_TYPE_INVALID;
      } else {
        pt[0] = 0x04;
        pt[1] = 0x20;
        memcpy(pt + 2, k->pk, 32);
        r = give(&t[i], pt, sizeof pt);
      }
      break;
    case CKA_VALUE:
      if (priv) {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_SENSITIVE;
      } else if (kt == CKK_EC_EDWARDS) {
        t[i].len = NOVAL;
        r = CKR_ATTRIBUTE_TYPE_INVALID;
      } else {
        r = give(&t[i], k->pk, k->pkn);
      }
      break;
    default:
      t[i].len = NOVAL;
      r = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }
    if (r != CKR_OK) rv = r;
  }
  return rv;
}

static ck tfindinit(ck s, ckattr *t, ck n) {
  ck i;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  findany = 1;
  findidn = 0;
  for (i = 0; i < n; i++) {
    if (t[i].type == CKA_CLASS && t[i].len == sizeof(ck)) {
      memcpy(&findcls, t[i].val, sizeof(ck));
      findany = 0;
    } else if (t[i].type == CKA_ID && t[i].len <= 32) {
      memcpy(findid, t[i].val, t[i].len);
      findidn = t[i].len;
    } else {
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  finding = 1;
  findat = 0;
  return CKR_OK;
}

static ck tfind(ck s, ck *o, ck max, ck *n) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (!finding) return CKR_OPERATION_NOT_INITIALIZED;
  *n = 0;
  /* each key twice: its private part (when logged in), its public */
  for (; findat < 2 * NKEY && *n < max; findat++) {
    const tkey *k = &keys[findat / 2];
    int priv = (findat & 1) == 0;
    if (!k->used || (priv && !logged)) continue;
    if (!findany && findcls != (priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY))
      continue;
    if (findidn != 0 &&
        (findidn != k->idlen || memcmp(findid, k->id, findidn) != 0))
      continue;
    o[(*n)++] = priv ? HPRIV(findat / 2) : HPUB(findat / 2);
  }
  return CKR_OK;
}

static ck tfindfin(ck s) {
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  finding = 0;
  return CKR_OK;
}

static ck tsigninit(ck s, ckmech *m, ck h) {
  tkey *k;
  ck ps, kt, want;
  int priv = 0;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (!logged) return CKR_USER_NOT_LOGGED_IN;
  k = keyof(h, &priv);
  if (k == NULL || !priv) return CKR_KEY_HANDLE_INVALID;
  if (k->kem) return CKR_KEY_TYPE_INCONSISTENT;
  if (m == NULL) return CKR_ARGUMENTS_BAD;
  kt = ktype(k, &ps);
  want = kt == CKK_ML_DSA ? CKM_ML_DSA
         : kt == CKK_SLH_DSA ? CKM_SLH_DSA : CKM_EDDSA;
  if (m->mech != want)
    return m->mech == CKM_ML_DSA || m->mech == CKM_SLH_DSA ||
                   m->mech == CKM_EDDSA
               ? CKR_KEY_TYPE_INCONSISTENT
               : CKR_MECHANISM_INVALID;
  sctxn = 0;
  if (m->par != NULL) {
    if (kt == CKK_EC_EDWARDS) {
      const cked *e = (const cked *)m->par;
      if (m->len != sizeof *e || e->ph || e->len > 255)
        return CKR_ARGUMENTS_BAD;
      memcpy(sctx, e->ctx, e->len);
      sctxn = e->len;
    } else {
      const cksctx *c = (const cksctx *)m->par;
      if (m->len != sizeof *c || c->len > 255) return CKR_ARGUMENTS_BAD;
      if (c->len > 0) memcpy(sctx, c->ctx, c->len);
      sctxn = c->len;
    }
  }
  signkey = (int)((h - 1) / 2);
  return CKR_OK;
}

static ck tsign(ck s, unsigned char *d, ck n, unsigned char *sig, ck *sl) {
  const tkey *k;
  nqssz z;
  size_t on = 0;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (signkey < 0) return CKR_OPERATION_NOT_INITIALIZED;
  k = &keys[signkey];
  if (sl == NULL || nqssize((nqsalg)k->alg, &z) != NQOK)
    return CKR_ARGUMENTS_BAD;
  if (sig == NULL) {
    *sl = (ck)z.sig;
    return CKR_OK;
  }
  if (*sl < z.sig) {
    *sl = (ck)z.sig;
    return CKR_BUFFER_TOO_SMALL;
  }
  signkey = -1;
  if (nqsign((nqsalg)k->alg, k->sk, k->skn, d, n, sctx, sctxn, 0, sig, z.sig,
             &on) != NQOK)
    return CKR_DATA_INVALID;
  *sl = (ck)on;
  return CKR_OK;
}

/* the value of the attribute ty in a template, NULL when it has none */
static const ckattr *tfindattr(const ckattr *t, ck n, ck ty) {
  ck i;
  for (i = 0; i < n; i++)
    if (t[i].type == ty) return &t[i];
  return NULL;
}

static ck tgenpair(ck s, ckmech *m, ckattr *pub, ck np, ckattr *prv, ck nv,
                   ck *hpub, ck *hpriv) {
  static const nqsalg slh[12] = {NQSLH128S, NQSLHK128S, NQSLH128F, NQSLHK128F,
                                 NQSLH192S, NQSLHK192S, NQSLH192F, NQSLHK192F,
                                 NQSLH256S, NQSLHK256S, NQSLH256F, NQSLHK256F};
  const ckattr *a;
  tkey *k = NULL;
  ck ps = 0;
  int i;
  (void)nv;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (!logged) return CKR_USER_NOT_LOGGED_IN;
  if (m == NULL || pub == NULL || prv == NULL || hpub == NULL ||
      hpriv == NULL)
    return CKR_ARGUMENTS_BAD;
  for (i = 0; i < NKEY && k == NULL; i++)
    if (!keys[i].used) k = &keys[i];
  if (k == NULL) return CKR_DEVICE_MEMORY;
  i = (int)(k - keys);
  memset(k, 0, sizeof *k);
  a = tfindattr(pub, np, CKA_PARAMETER_SET);
  if (a != NULL && a->len == sizeof ps) memcpy(&ps, a->val, sizeof ps);
  switch (m->mech) {
  case CKM_ML_DSA_KEY_PAIR_GEN:
    if (ps < 1 || ps > 3) return CKR_TEMPLATE_INCOMPLETE;
    k->alg = (int)NQMLDSA44 + (int)ps - 1;
    break;
  case CKM_SLH_DSA_KEY_PAIR_GEN:
    if (ps < 1 || ps > 12) return CKR_TEMPLATE_INCOMPLETE;
    k->alg = (int)slh[ps - 1];
    break;
  case CKM_ML_KEM_KEY_PAIR_GEN:
    if (ps < 1 || ps > 3) return CKR_TEMPLATE_INCOMPLETE;
    k->kem = 1;
    k->alg = (int)NQMLKEM512 + (int)ps - 1;
    break;
  case CKM_EC_EDWARDS_KEY_PAIR_GEN:
    if (tfindattr(pub, np, CKA_EC_PARAMS) == NULL)
      return CKR_TEMPLATE_INCOMPLETE;
    k->alg = (int)NQED25519;
    break;
  default:
    return CKR_MECHANISM_INVALID;
  }
  a = tfindattr(prv, nv, CKA_LABEL);
  if (a != NULL && a->len <= 64) {
    memcpy(k->label, a->val, a->len);
    k->lablen = a->len;
  }
  a = tfindattr(prv, nv, CKA_ID);
  if (a != NULL && a->len <= 32) {
    memcpy(k->id, a->val, a->len);
    k->idlen = a->len;
  }
  k->seedlen = seedsize(k->kem, k->alg);
  if (k->seedlen == 0 || nqrand(k->seed, k->seedlen) != NQOK || !derive(k)) {
    free(k->pk);
    free(k->sk);
    memset(k, 0, sizeof *k);
    return CKR_DEVICE_MEMORY;
  }
  k->used = 1;
  save(k);
  *hpub = HPUB(i);
  *hpriv = HPRIV(i);
  return CKR_OK;
}

static ck tdecap(ck s, ckmech *m, ck h, ckattr *t, ck n, unsigned char *ct,
                 ck ctn, ck *key) {
  tkey *k;
  nqksz kz;
  int priv = 0, j;
  (void)t;
  (void)n;
  if (!opened || s != SESS) return CKR_SESSION_HANDLE_INVALID;
  if (!logged) return CKR_USER_NOT_LOGGED_IN;
  k = keyof(h, &priv);
  if (k == NULL || !priv) return CKR_KEY_HANDLE_INVALID;
  if (!k->kem) return CKR_KEY_TYPE_INCONSISTENT;
  if (m == NULL || m->mech != CKM_ML_KEM) return CKR_MECHANISM_INVALID;
  if (key == NULL || nqksize((nqkalg)k->alg, &kz) != NQOK)
    return CKR_ARGUMENTS_BAD;
  if (ctn != kz.ct) return CKR_ENCRYPTED_DATA_INVALID;
  for (j = 0; j < NSEC && secused[j]; j++) {
  }
  if (j == NSEC) return CKR_DEVICE_MEMORY;
  if (nqdec((nqkalg)k->alg, k->sk, k->skn, ct, ctn, secs[j], 32) != NQOK)
    return CKR_ENCRYPTED_DATA_INVALID;
  secused[j] = 1;
  *key = 1000 + (ck)j;
  return CKR_OK;
}

static ckfl list;
static ckif itf;
static unsigned char itfname[] = "PKCS 11";

static void fill(int v32) {
  size_t i;
  for (i = 0; i < sizeof list.fn / sizeof list.fn[0]; i++)
    list.fn[i] = (ckfn)nosup;
  list.ver.major = v32 ? 3 : 2;
  list.ver.minor = v32 ? 2 : 40;
  list.fn[0] = (ckfn)tinit;
  list.fn[1] = (ckfn)tfin;
  list.fn[4] = (ckfn)tslots;
  list.fn[6] = (ckfn)ttokinfo;
  list.fn[12] = (ckfn)topen;
  list.fn[13] = (ckfn)tclose;
  list.fn[18] = (ckfn)tlogin;
  list.fn[19] = (ckfn)tlogout;
  list.fn[22] = (ckfn)tdestroy;
  list.fn[24] = (ckfn)tgetattr;
  list.fn[26] = (ckfn)tfindinit;
  list.fn[27] = (ckfn)tfind;
  list.fn[28] = (ckfn)tfindfin;
  list.fn[42] = (ckfn)tsigninit;
  list.fn[43] = (ckfn)tsign;
  list.fn[59] = (ckfn)tgenpair;
  if (v32) list.fn[93] = (ckfn)tdecap;
}

EXPORT ck C_GetFunctionList(const ckfl **f);
EXPORT ck C_GetInterface(unsigned char *name, ckver *ver, ckif **out,
                         ck flags);

EXPORT ck C_GetFunctionList(const ckfl **f) {
  if (f == NULL) return CKR_ARGUMENTS_BAD;
  fill(0);
  *f = &list;
  return CKR_OK;
}

EXPORT ck C_GetInterface(unsigned char *name, ckver *ver, ckif **out,
                         ck flags) {
  const char *old = getenv("NQTOK240");
  (void)name;
  (void)ver;
  (void)flags;
  if (out == NULL) return CKR_ARGUMENTS_BAD;
  if (old != NULL && old[0] != '\0') return CKR_FUNCTION_NOT_SUPPORTED;
  fill(1);
  itf.name = itfname;
  itf.fl = &list;
  itf.flags = 0;
  *out = &itf;
  return CKR_OK;
}
