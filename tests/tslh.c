/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SLH-DSA tests: every NIST ACVP SLH-DSA keyGen, sigGen and sigVer vector
 * in vectors/acvp, the parameter table, round trips and the API's errors.
 *
 * Signing an "s" parameter set takes seconds, so by default only every
 * 4th "s" sigGen test runs (each "f" test always runs); NQSLOW=1 runs
 * them all. NQSLSUB=k runs only every k-th sigGen test of any set (for
 * valgrind). Every signature produced is also verified. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "slh/slh.h"
#include "nqt.h"

static int slow = 0;  /* NQSLOW=1 */
static long sub = 0;  /* NQSLSUB=k */
static int nmiss = 0;

/* ---- JSON helpers (as in thash.c) ---- */

static nqjs *ldjs(const char *dir, const char *name) {
  char path[256];
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc;
  snprintf(path, sizeof path, "vectors/acvp/%s/%s", dir, name);
  rc = nqreadf(path, (size_t)1 << 28, &buf, &len);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot read (%s)\n", path, nqerr(rc));
    return NULL;
  }
  rc = nqjparse(buf, len, &v, NULL);
  nqfree(buf, len + 1);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot parse (%s)\n", path, nqerr(rc));
    return NULL;
  }
  return v;
}

static const nqjs *groups(const nqjs *v) {
  return nqjget(v->type == NQJARR ? nqjat(v, 1) : v, "testGroups");
}

static int getf(const nqjs *o, const char *key, uint64_t *out) {
  int64_t x;
  const nqjs *v = nqjget(o, key);
  if (v == NULL || v->type != NQJNUM || nqjint(v, &x) != NQOK || x < 0) {
    return 0;
  }
  *out = (uint64_t)x;
  return 1;
}

static const nqjs *findexp(const nqjs *eg, uint64_t tg, uint64_t tc) {
  size_t i, j;
  uint64_t x;
  for (i = 0; eg != NULL && i < eg->n; i++) {
    const nqjs *g = nqjat(eg, i), *ts;
    if (!getf(g, "tgId", &x) || x != tg) continue;
    ts = nqjget(g, "tests");
    for (j = 0; ts != NULL && j < ts->n; j++) {
      if (getf(nqjat(ts, j), "tcId", &x) && x == tc) return nqjat(ts, j);
    }
  }
  return NULL;
}

/* A hex field decoded into a fresh buffer (one spare byte, so an empty
 * field is not NULL); NULL when missing or malformed. */
static uint8_t *unhexa(const nqjs *v, size_t *n) {
  const char *s = nqjstr(v);
  size_t len;
  uint8_t *b;
  if (s == NULL) return NULL;
  len = strlen(s);
  b = (uint8_t *)calloc(len / 2 + 1, 1);
  if (b == NULL) return NULL;
  if (nqunhex(s, len, b, len / 2 + 1, n) != NQOK) {
    free(b);
    return NULL;
  }
  return b;
}

static int eqhex(const nqjs *v, const uint8_t *got, size_t n) {
  size_t m = 0;
  uint8_t *b = unhexa(v, &m);
  int ok = b != NULL && m == n && memcmp(b, got, n) == 0;
  free(b);
  return ok;
}

static void miss(const char *what, const char *ps, uint64_t tg,
                 uint64_t tc) {
  if (nmiss++ < 20) {
    fprintf(stderr, "%s %s failed (tgId %llu, tcId %llu)\n", what, ps,
            (unsigned long long)tg, (unsigned long long)tc);
  }
}

/* ACVP hashAlg names */
static const struct {
  const char *name;
  nqhalg alg;
} hnames[] = {
    {"SHA2-224", NQS224},       {"SHA2-256", NQS256},
    {"SHA2-384", NQS384},       {"SHA2-512", NQS512},
    {"SHA2-512/224", NQS512T224}, {"SHA2-512/256", NQS512T256},
    {"SHA3-224", NQS3224},      {"SHA3-256", NQS3256},
    {"SHA3-384", NQS3384},      {"SHA3-512", NQS3512},
    {"SHAKE-128", NQSHK128},    {"SHAKE-256", NQSHK256},
};

static int hfind(const char *s) {
  size_t i;
  if (s == NULL) return -1;
  for (i = 0; i < sizeof hnames / sizeof hnames[0]; i++) {
    if (strcmp(s, hnames[i].name) == 0) return (int)hnames[i].alg;
  }
  return -1;
}

/* the s sets' sigGen tests seen so far, run, skipped */
static long sseen = 0, srun = 0, sskip = 0;

/* ---- keyGen ---- */

static void tkg(void) {
  const char *dir = "SLH-DSA-keyGen-FIPS205";
  nqjs *p = ldjs(dir, "prompt.json"), *x = ldjs(dir, "expectedResults.json");
  const nqjs *pg, *eg;
  long run = 0, pass = 0;
  size_t i, j;
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) goto done;
  pg = groups(p);
  eg = groups(x);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const nqslp *sp = nqslfind(nqjstr(nqjget(g, "parameterSet")));
    uint64_t tg = 0;
    getf(g, "tgId", &tg);
    NQTCHK(sp != NULL);
    for (j = 0; sp != NULL && ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t l1 = 0, l2 = 0, l3 = 0;
      uint8_t *a, *b, *c, seed[96], pk[64], sk[128];
      int ok = 0;
      getf(t, "tcId", &tc);
      e = findexp(eg, tg, tc);
      a = unhexa(nqjget(t, "skSeed"), &l1);
      b = unhexa(nqjget(t, "skPrf"), &l2);
      c = unhexa(nqjget(t, "pkSeed"), &l3);
      run++;
      if (e != NULL && a != NULL && b != NULL && c != NULL &&
          l1 == sp->n && l2 == sp->n && l3 == sp->n) {
        memcpy(seed, a, sp->n);
        memcpy(seed + sp->n, b, sp->n);
        memcpy(seed + 2 * sp->n, c, sp->n);
        ok = nqslkgd(sp->alg, seed, 3 * sp->n, pk, sp->pk, sk, sp->sk) ==
                 NQOK &&
             eqhex(nqjget(e, "pk"), pk, sp->pk) &&
             eqhex(nqjget(e, "sk"), sk, sp->sk);
      }
      if (ok) {
        pass++;
      } else {
        miss("keyGen", sp->name, tg, tc);
      }
      NQTCHK(ok);
      free(a);
      free(b);
      free(c);
    }
  }
done:
  printf("%-24s %ld/%ld\n", dir, pass, run);
  nqjfree(p);
  nqjfree(x);
}

/* ---- sigGen ---- */

static void tsg(void) {
  const char *dir = "SLH-DSA-sigGen-FIPS205";
  nqjs *p = ldjs(dir, "prompt.json"), *x = ldjs(dir, "expectedResults.json");
  const nqjs *pg, *eg;
  long run = 0, pass = 0, skip = 0;
  size_t i, j;
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) goto done;
  pg = groups(p);
  eg = groups(x);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const char *ps = nqjstr(nqjget(g, "parameterSet"));
    const nqslp *sp = nqslfind(ps);
    const char *ifc = nqjstr(nqjget(g, "signatureInterface"));
    const char *pre = nqjstr(nqjget(g, "preHash"));
    int det = nqjbool(nqjget(g, "deterministic"));
    int inl = ifc != NULL && strcmp(ifc, "internal") == 0;
    int isph = pre != NULL && strcmp(pre, "preHash") == 0;
    int sset = sp != NULL && sp->name[strlen(sp->name) - 1] == 's';
    uint64_t tg = 0;
    getf(g, "tgId", &tg);
    NQTCHK(sp != NULL && det >= 0 && ifc != NULL);
    NQTCHK(inl || (pre != NULL && (isph || strcmp(pre, "pure") == 0)));
    for (j = 0; sp != NULL && det >= 0 && ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t skn = 0, mn = 0, cn = 0, rn = 0, outl = 0;
      uint8_t *sk, *m, *cx = NULL, *rnd = NULL, *sig;
      int ok = 0, ph = 0, rc;
      getf(t, "tcId", &tc);
      if (sub > 0) {
        if ((sseen++ % sub) != 0) {
          skip++;
          if (sset) sskip++;
          continue;
        }
        if (sset) srun++;
      } else if (sset) {
        if (!slow && (sseen++ % 4) != 0) {
          skip++;
          sskip++;
          continue;
        }
        if (slow) sseen++;
        srun++;
      }
      e = findexp(eg, tg, tc);
      sk = unhexa(nqjget(t, "sk"), &skn);
      m = unhexa(nqjget(t, "message"), &mn);
      if (!inl) cx = unhexa(nqjget(t, "context"), &cn);
      if (!det) rnd = unhexa(nqjget(t, "additionalRandomness"), &rn);
      if (isph) ph = hfind(nqjstr(nqjget(t, "hashAlg")));
      sig = (uint8_t *)malloc(sp->sig);
      run++;
      if (e != NULL && sk != NULL && m != NULL && sig != NULL &&
          (inl || cx != NULL) && (det || rnd != NULL) && ph >= 0) {
        if (inl) {
          rc = nqslsigi(sp->alg, sk, skn, m, mn, rnd, det ? 0 : rn, sig,
                        sp->sig, &outl);
        } else {
          rc = nqslsignd(sp->alg, sk, skn, m, mn, cx, cn, ph, rnd,
                         det ? 0 : rn, sig, sp->sig, &outl);
        }
        ok = rc == NQOK && outl == sp->sig &&
             eqhex(nqjget(e, "signature"), sig, sp->sig);
        /* and the signature verifies under the key in sk */
        if (ok) {
          const uint8_t *pk = sk + 2 * sp->n;
          rc = inl ? nqslvrfi(sp->alg, pk, sp->pk, m, mn, sig, sp->sig)
                   : nqslvrfy(sp->alg, pk, sp->pk, m, mn, cx, cn, ph, sig,
                              sp->sig);
          ok = rc == NQOK;
        }
      }
      if (ok) {
        pass++;
      } else {
        miss("sigGen", sp->name, tg, tc);
      }
      NQTCHK(ok);
      free(sk);
      free(m);
      free(cx);
      free(rnd);
      free(sig);
    }
  }
done:
  printf("%-24s %ld/%ld", dir, pass, run);
  if (skip) printf(" (%ld skipped: %s)", skip,
                   sub > 0 ? "NQSLSUB" : "s sets; set NQSLOW=1");
  printf("\n");
  nqjfree(p);
  nqjfree(x);
}

/* ---- sigVer ---- */

static void tsv(void) {
  const char *dir = "SLH-DSA-sigVer-FIPS205";
  nqjs *p = ldjs(dir, "prompt.json"), *x = ldjs(dir, "expectedResults.json");
  const nqjs *pg, *eg;
  long run = 0, pass = 0, npos = 0, nneg = 0;
  size_t i, j;
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) goto done;
  pg = groups(p);
  eg = groups(x);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const nqslp *sp = nqslfind(nqjstr(nqjget(g, "parameterSet")));
    const char *ifc = nqjstr(nqjget(g, "signatureInterface"));
    const char *pre = nqjstr(nqjget(g, "preHash"));
    int inl = ifc != NULL && strcmp(ifc, "internal") == 0;
    int isph = pre != NULL && strcmp(pre, "preHash") == 0;
    uint64_t tg = 0;
    getf(g, "tgId", &tg);
    NQTCHK(sp != NULL && ifc != NULL);
    for (j = 0; sp != NULL && ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t pn = 0, mn = 0, cn = 0, sn = 0;
      uint8_t *pk, *m, *cx = NULL, *sig;
      int ok = 0, ph = 0, want, rc;
      getf(t, "tcId", &tc);
      e = findexp(eg, tg, tc);
      want = e != NULL ? nqjbool(nqjget(e, "testPassed")) : -1;
      pk = unhexa(nqjget(t, "pk"), &pn);
      m = unhexa(nqjget(t, "message"), &mn);
      sig = unhexa(nqjget(t, "signature"), &sn);
      if (!inl) cx = unhexa(nqjget(t, "context"), &cn);
      if (isph) ph = hfind(nqjstr(nqjget(t, "hashAlg")));
      run++;
      if (want >= 0 && pk != NULL && m != NULL && sig != NULL &&
          (inl || cx != NULL) && ph >= 0) {
        rc = inl ? nqslvrfi(sp->alg, pk, pn, m, mn, sig, sn)
                 : nqslvrfy(sp->alg, pk, pn, m, mn, cx, cn, ph, sig, sn);
        ok = want ? rc == NQOK : (rc == NQEVRFY || rc == NQEDEC);
        if (want) {
          npos++;
        } else {
          nneg++;
        }
      }
      if (ok) {
        pass++;
      } else {
        miss("sigVer", sp->name, tg, tc);
      }
      NQTCHK(ok);
      free(pk);
      free(m);
      free(cx);
      free(sig);
    }
  }
done:
  printf("%-24s %ld/%ld (%ld valid, %ld invalid)\n", dir, pass, run, npos,
         nneg);
  nqjfree(p);
  nqjfree(x);
}

/* ---- the table, round trips, errors ---- */

static void ttab(void) {
  /* FIPS 205 table 2: signature sizes */
  static const size_t sig[NQSLNSET] = {7856,  17088, 16224, 35664,
                                       29792, 49856, 7856,  17088,
                                       16224, 35664, 29792, 49856};
  size_t i;
  for (i = 0; i < NQSLNSET; i++) {
    const nqslp *p = &nqsltab[i];
    NQTEQI(p->sig, sig[i]);
    NQTEQI(p->pk, 2 * p->n);
    NQTEQI(p->sk, 4 * p->n);
    NQTEQI(p->h, p->hp * p->d);
    NQTEQI(p->m, (p->k * p->a + 7) / 8 + (p->h - p->hp + 7) / 8 +
                     (p->hp + 7) / 8);
    NQTCHK(nqslpar(p->alg) == p);
    NQTCHK(nqslfind(p->name) == p);
  }
  NQTCHK(nqslpar(NQMLDSA65) == NULL);
  NQTCHK(nqslpar((nqsalg)0) == NULL);
  NQTCHK(nqslpar((nqsalg)(NQSLHK256F + 1)) == NULL);
  NQTCHK(nqslfind("SLH-DSA-SHA2-128") == NULL);
  NQTCHK(nqslfind(NULL) == NULL);
}

/* round trips and errors on one parameter set */
static void tapi(nqsalg alg) {
  const nqslp *p = nqslpar(alg);
  uint8_t pk[64], sk[128], seed[96], z[32], pk2[64], sk2[128];
  uint8_t *s1 = (uint8_t *)malloc(p->sig + 1);
  uint8_t *s2 = (uint8_t *)malloc(p->sig + 1);
  static const uint8_t msg[] = "noqtis SLH-DSA";
  static const uint8_t ctx[] = "noqtis-capsule-1";
  uint8_t big[256];
  size_t ml = sizeof msg - 1, cl = sizeof ctx - 1, ol = 0, i;
  NQTCHK(s1 != NULL && s2 != NULL);
  if (s1 == NULL || s2 == NULL) goto out;
  memset(big, 7, sizeof big);
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 37 + 1);
  memset(z, 0, sizeof z);

  /* key generation */
  NQTEQI(nqslkgd(alg, seed, 3 * p->n, pk, p->pk, sk, p->sk), NQOK);
  NQTEQM(sk, seed, 3 * p->n);
  NQTEQM(pk, sk + 2 * p->n, 2 * p->n);
  NQTEQI(nqslkgd(alg, seed, 3 * p->n - 1, pk2, p->pk, sk2, p->sk), NQEARG);
  NQTEQI(nqslkgd(alg, seed, 3 * p->n, pk2, p->pk - 1, sk2, p->sk), NQEBUF);
  NQTEQI(nqslkgd(alg, seed, 3 * p->n, pk2, p->pk, sk2, p->sk - 1), NQEBUF);
  NQTEQI(nqslkgd(alg, seed, 3 * p->n, pk2, p->pk + 1, sk2, p->sk), NQEARG);
  NQTEQI(nqslkgd(alg, NULL, 3 * p->n, pk2, p->pk, sk2, p->sk), NQEARG);
  NQTEQI(nqslkgd(NQMLDSA44, seed, 48, pk2, 32, sk2, 64), NQEARG);
  NQTEQI(nqslkg(alg, pk2, p->pk, sk2, p->sk), NQOK);
  NQTCHK(memcmp(pk2, pk, p->pk) != 0);

  /* deterministic: rnd NULL, rnd zero and rnd = PK.seed agree */
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, 0, NULL, 0, s1,
                   p->sig, &ol), NQOK);
  NQTEQI(ol, p->sig);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, 0, z, p->n, s2,
                   p->sig, &ol), NQOK);
  NQTEQM(s1, s2, p->sig);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, 0, pk, p->n, s2,
                   p->sig, &ol), NQOK);
  NQTEQM(s1, s2, p->sig);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig), NQOK);

  /* a wrong context, message, interface or pre-hash fails */
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl - 1, 0, s1, p->sig),
         NQEVRFY);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml - 1, ctx, cl, 0, s1, p->sig),
         NQEVRFY);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, NQS256, s1, p->sig),
         NQEVRFY);
  NQTEQI(nqslvrfi(alg, pk, p->pk, msg, ml, s1, p->sig), NQEVRFY);
  NQTEQI(nqslvrfy(alg, pk2, p->pk, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEVRFY);

  /* one flipped bit in R, in FORS, in the last auth path node */
  s1[0] ^= 1;
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEVRFY);
  s1[0] ^= 1;
  s1[p->n + 5] ^= 0x80;
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEVRFY);
  s1[p->n + 5] ^= 0x80;
  s1[p->sig - 1] ^= 1;
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEVRFY);
  s1[p->sig - 1] ^= 1;
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig), NQOK);

  /* malformed lengths */
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig - 1),
         NQEDEC);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig + 1),
         NQEDEC);
  NQTEQI(nqslvrfy(alg, pk, p->pk - 1, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEDEC);
  NQTEQI(nqslvrfi(alg, pk, p->pk + 1, msg, ml, s1, p->sig), NQEDEC);
  NQTEQI(nqslvrfi(alg, pk, p->pk, msg, ml, s1, 0), NQEDEC);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, big, 256, 0, s1, p->sig),
         NQEARG);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, NULL, 1, 0, s1, p->sig),
         NQEARG);
  NQTEQI(nqslvrfy(alg, pk, p->pk, NULL, 1, ctx, cl, 0, s1, p->sig),
         NQEARG);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, ctx, cl, 99, s1, p->sig),
         NQEARG);
  NQTEQI(nqslvrfy(NQMLDSA44, pk, p->pk, msg, ml, ctx, cl, 0, s1, p->sig),
         NQEARG);
  NQTEQI(nqslsignd(alg, sk, p->sk - 1, msg, ml, ctx, cl, 0, NULL, 0, s2,
                   p->sig, &ol), NQEDEC);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, 0, NULL, 0, s2,
                   p->sig - 1, &ol), NQEBUF);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, big, 256, 0, NULL, 0, s2,
                   p->sig, &ol), NQEARG);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, 0, z, p->n - 1, s2,
                   p->sig, &ol), NQEARG);
  NQTEQI(nqslsignd(alg, sk, p->sk, msg, ml, ctx, cl, -1, NULL, 0, s2,
                   p->sig, &ol), NQEARG);
  NQTEQI(nqslsigi(alg, sk, p->sk, msg, ml, z, p->n + 1, s2, p->sig, &ol),
         NQEARG);
  NQTEQI(nqslsign(alg, sk, p->sk, msg, ml, ctx, cl, 0, s2, p->sig - 1,
                  &ol), NQEBUF);

  /* hedged, with a 255-byte context and a pre-hash; a bigger buffer */
  NQTEQI(nqslsign(alg, sk, p->sk, msg, ml, big, 255, NQSHK256, s2,
                  p->sig + 1, &ol), NQOK);
  NQTEQI(ol, p->sig);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, big, 255, NQSHK256, s2, p->sig),
         NQOK);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, big, 255, NQSHK128, s2, p->sig),
         NQEVRFY);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, ml, big, 255, 0, s2, p->sig),
         NQEVRFY);
  /* two hedged signatures differ */
  NQTEQI(nqslsign(alg, sk, p->sk, msg, ml, big, 255, NQSHK256, s1, p->sig,
                  NULL), NQOK);
  NQTCHK(memcmp(s1, s2, p->n) != 0);

  /* the internal interface, empty message */
  NQTEQI(nqslsigi(alg, sk, p->sk, NULL, 0, NULL, 0, s1, p->sig, &ol), NQOK);
  NQTEQI(nqslvrfi(alg, pk, p->pk, NULL, 0, s1, p->sig), NQOK);
  NQTEQI(nqslvrfy(alg, pk, p->pk, NULL, 0, NULL, 0, 0, s1, p->sig),
         NQEVRFY);
out:
  free(s1);
  free(s2);
}

int main(void) {
  const char *e = getenv("NQSLOW");
  slow = e != NULL && strcmp(e, "1") == 0;
  e = getenv("NQSLSUB");
  if (e != NULL) sub = strtol(e, NULL, 10);
  ttab();
  tapi(NQSLH128F);
  tapi(NQSLHK192F);
  tapi(NQSLH256F);
  tkg();
  tsg();
  tsv();
  printf("s-set sigGen tests: %ld run, %ld skipped%s\n", srun, sskip,
         sub > 0  ? " (NQSLSUB)"
         : slow ? " (NQSLOW=1)"
                : " (every 4th; NQSLOW=1 runs all)");
  return nqtdone("tslh");
}
