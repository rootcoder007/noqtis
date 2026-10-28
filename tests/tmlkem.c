/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-KEM tests: every NIST ACVP ML-KEM keyGen and encapDecap vector
 * (encapsulation, decapsulation, and both key checks), every Wycheproof
 * mlkem_* file, round trips with tampered ciphertexts (masked and plain
 * decapsulation must agree with each other and with J(z || c)), and the
 * API's errors. Decapsulation vectors run through both nqmkdec (masked)
 * and nqmkdecp. NQVEC=<dir> reads the vectors from <dir> instead of
 * vectors/ (dir/acvp/<set>/, dir/wycheproof/). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "hash/h.h"
#include "mlkem/mlkem.h"
#include "nqt.h"

static const char *vroot = "vectors";
static int nmiss = 0;

/* ---- JSON helpers (as in thash.c) ---- */

static nqjs *ldjs(const char *path) {
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc = nqreadf(path, (size_t)1 << 28, &buf, &len);
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

/* A hex field into a fresh buffer (at least one byte allocated); NULL
 * when missing or malformed. */
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

/* a field of the test, else of its group */
static const nqjs *fld(const nqjs *t, const nqjs *g, const char *key) {
  const nqjs *v = nqjget(t, key);
  return v != NULL ? v : nqjget(g, key);
}

static int pset(const nqjs *g) {
  const char *s = nqjstr(nqjget(g, "parameterSet"));
  if (s == NULL) return 0;
  if (strcmp(s, "ML-KEM-512") == 0) return 2;
  if (strcmp(s, "ML-KEM-768") == 0) return 3;
  if (strcmp(s, "ML-KEM-1024") == 0) return 4;
  return 0;
}

static void miss(const char *set, const char *what, uint64_t tg,
                 uint64_t tc) {
  if (nmiss++ < 30) {
    fprintf(stderr, "%s: %s failed (tgId %llu, tcId %llu)\n", set, what,
            (unsigned long long)tg, (unsigned long long)tc);
  }
}

/* both decapsulations; 1 when both return rc and (rc NQOK) the secret
 * in want (NULL: not checked) */
static int bothdec(int k, const uint8_t *dk, size_t dkl, const uint8_t *c,
                   size_t cl, const uint8_t *want, int wrc) {
  uint8_t s1[NQMKSS], s2[NQMKSS];
  int r1 = nqmkdec(k, dk, dkl, c, cl, s1, sizeof s1);
  int r2 = nqmkdecp(k, dk, dkl, c, cl, s2, sizeof s2);
  int ok = r1 == wrc && r2 == wrc;
  if (ok && wrc == NQOK) {
    ok = memcmp(s1, s2, NQMKSS) == 0 &&
         (want == NULL || memcmp(s1, want, NQMKSS) == 0);
  }
  return ok;
}

/* ---- ACVP ---- */

typedef struct {
  long run, pass;
} cnt;

static void report(const char *set, uint64_t tg, const char *fn, int k,
                   const cnt *c) {
  printf("  %-26s tg %2llu %-22s ML-KEM-%-4d %ld/%ld\n", set,
         (unsigned long long)tg, fn,
         k == 2 ? 512 : k == 3 ? 768 : 1024, c->pass, c->run);
}

static void acvpkg(void) {
  static const char *set = "ML-KEM-keyGen-FIPS203";
  char path[512];
  nqjs *p, *x;
  const nqjs *pg, *eg;
  size_t i, j;
  long tot = 0, tp = 0;
  snprintf(path, sizeof path, "%s/acvp/%s/prompt.json", vroot, set);
  p = ldjs(path);
  snprintf(path, sizeof path, "%s/acvp/%s/expectedResults.json", vroot,
           set);
  x = ldjs(path);
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) {
    nqjfree(p);
    nqjfree(x);
    return;
  }
  pg = groups(p);
  eg = groups(x);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    uint64_t tg = 0, tc;
    int k = pset(g);
    cnt c = {0, 0};
    getf(g, "tgId", &tg);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint8_t seed[64], ek[NQMKEKX], dk[NQMKDKX], *d, *z;
      size_t dn = 0, zn = 0;
      int ok = 0;
      if (!getf(t, "tcId", &tc)) continue;
      e = findexp(eg, tg, tc);
      c.run++;
      d = unhexa(nqjget(t, "d"), &dn);
      z = unhexa(nqjget(t, "z"), &zn);
      if (k && e != NULL && d != NULL && z != NULL && dn == 32 &&
          zn == 32) {
        memcpy(seed, d, 32);
        memcpy(seed + 32, z, 32);
        ok = nqmkkgd(k, seed, 64, ek, sizeof ek, dk, sizeof dk) == NQOK &&
             eqhex(nqjget(e, "ek"), ek, NQMKEK(k)) &&
             eqhex(nqjget(e, "dk"), dk, NQMKDK(k));
      }
      if (ok) c.pass++;
      else miss(set, "keyGen", tg, tc);
      free(d);
      free(z);
      NQTCHK(ok);
    }
    report(set, tg, "keyGen", k, &c);
    tot += c.run;
    tp += c.pass;
  }
  printf("  %-26s total %ld/%ld\n", set, tp, tot);
  nqjfree(p);
  nqjfree(x);
}

static int ckencap(int k, const nqjs *t, const nqjs *g, const nqjs *e) {
  uint8_t ct[NQMKCTX], ss[NQMKSS], *ek, *m;
  size_t en = 0, mn = 0;
  int ok = 0;
  ek = unhexa(fld(t, g, "ek"), &en);
  m = unhexa(nqjget(t, "m"), &mn);
  if (ek != NULL && m != NULL &&
      nqmkencd(k, ek, en, m, mn, ct, sizeof ct, ss, sizeof ss) == NQOK) {
    ok = eqhex(nqjget(e, "c"), ct, NQMKCT(k)) &&
         eqhex(nqjget(e, "k"), ss, NQMKSS);
  }
  free(ek);
  free(m);
  return ok;
}

static int ckdecap(int k, const nqjs *t, const nqjs *g, const nqjs *e) {
  uint8_t *dk, *c, *want;
  size_t dn = 0, cn = 0, wn = 0;
  int ok = 0;
  dk = unhexa(fld(t, g, "dk"), &dn);
  c = unhexa(nqjget(t, "c"), &cn);
  want = unhexa(nqjget(e, "k"), &wn);
  if (dk != NULL && c != NULL && want != NULL && wn == NQMKSS) {
    ok = bothdec(k, dk, dn, c, cn, want, NQOK);
  }
  free(dk);
  free(c);
  free(want);
  return ok;
}

static int ckkey(int k, const nqjs *t, const nqjs *e, int isdk) {
  uint8_t *key;
  size_t n = 0;
  int want = nqjbool(nqjget(e, "testPassed")), got, ok = 0;
  key = unhexa(nqjget(t, isdk ? "dk" : "ek"), &n);
  if (key != NULL && want >= 0) {
    got = isdk ? nqmkdkc(k, key, n) : nqmkekc(k, key, n);
    ok = (got == NQOK) == (want == 1) && (got == NQOK || got == NQEDEC);
  }
  free(key);
  return ok;
}

static void acvped(void) {
  static const char *set = "ML-KEM-encapDecap-FIPS203";
  char path[512];
  nqjs *p, *x;
  const nqjs *pg, *eg;
  size_t i, j;
  long tot = 0, tp = 0;
  snprintf(path, sizeof path, "%s/acvp/%s/prompt.json", vroot, set);
  p = ldjs(path);
  snprintf(path, sizeof path, "%s/acvp/%s/expectedResults.json", vroot,
           set);
  x = ldjs(path);
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) {
    nqjfree(p);
    nqjfree(x);
    return;
  }
  pg = groups(p);
  eg = groups(x);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const char *fn = nqjstr(nqjget(g, "function"));
    uint64_t tg = 0, tc;
    int k = pset(g);
    cnt c = {0, 0};
    getf(g, "tgId", &tg);
    if (fn == NULL) fn = "?";
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      int ok = 0;
      if (!getf(t, "tcId", &tc)) continue;
      e = findexp(eg, tg, tc);
      c.run++;
      if (k && e != NULL) {
        if (strcmp(fn, "encapsulation") == 0) {
          ok = ckencap(k, t, g, e);
        } else if (strcmp(fn, "decapsulation") == 0) {
          ok = ckdecap(k, t, g, e);
        } else if (strcmp(fn, "encapsulationKeyCheck") == 0) {
          ok = ckkey(k, t, e, 0);
        } else if (strcmp(fn, "decapsulationKeyCheck") == 0) {
          ok = ckkey(k, t, e, 1);
        }
      }
      if (ok) c.pass++;
      else miss(set, fn, tg, tc);
      NQTCHK(ok);
    }
    report(set, tg, fn, k, &c);
    tot += c.run;
    tp += c.pass;
  }
  printf("  %-26s total %ld/%ld\n", set, tp, tot);
  nqjfree(p);
  nqjfree(x);
}

/* ---- Wycheproof ---- */

static int wkg(int k, const nqjs *t) {
  uint8_t ek[NQMKEKX], dk[NQMKDKX], *seed;
  size_t sn = 0;
  int ok = 0;
  seed = unhexa(nqjget(t, "seed"), &sn);
  if (seed != NULL &&
      nqmkkgd(k, seed, sn, ek, sizeof ek, dk, sizeof dk) == NQOK) {
    ok = eqhex(nqjget(t, "ek"), ek, NQMKEK(k)) &&
         eqhex(nqjget(t, "dk"), dk, NQMKDK(k));
  }
  free(seed);
  return ok;
}

/* MLKEMTest: keygen from seed, then decapsulate c; 1 for valid, 0 for
 * rejected, -1 for a wrong answer */
static int wfull(int k, const nqjs *t) {
  uint8_t ek[NQMKEKX], dk[NQMKDKX], *seed, *c, *want;
  size_t sn = 0, cn = 0, wn = 0;
  int r = -1;
  seed = unhexa(nqjget(t, "seed"), &sn);
  c = unhexa(nqjget(t, "c"), &cn);
  want = unhexa(nqjget(t, "K"), &wn);
  if (seed != NULL && c != NULL && want != NULL) {
    int rc = nqmkkgd(k, seed, sn, ek, sizeof ek, dk, sizeof dk);
    if (rc != NQOK) {
      r = rc == NQEARG ? 0 : -1;
    } else if (nqjget(t, "ek") != NULL &&
               !eqhex(nqjget(t, "ek"), ek, NQMKEK(k))) {
      r = -1;
    } else if (cn != NQMKCT(k)) {
      r = bothdec(k, dk, NQMKDK(k), c, cn, NULL, NQEDEC) ? 0 : -1;
    } else {
      r = wn == NQMKSS &&
                  bothdec(k, dk, NQMKDK(k), c, cn, want, NQOK)
              ? 1
              : -1;
    }
  }
  free(seed);
  free(c);
  free(want);
  return r;
}

static int wenc(int k, const nqjs *t) {
  uint8_t ct[NQMKCTX], ss[NQMKSS], *ek, *m;
  size_t en = 0, mn = 0;
  int r = -1, rc;
  ek = unhexa(nqjget(t, "ek"), &en);
  m = unhexa(nqjget(t, "m"), &mn);
  if (ek != NULL && m != NULL) {
    rc = nqmkencd(k, ek, en, m, mn, ct, sizeof ct, ss, sizeof ss);
    if (rc == NQEDEC) {
      r = 0;
    } else if (rc == NQOK) {
      r = eqhex(nqjget(t, "c"), ct, NQMKCT(k)) &&
                  eqhex(nqjget(t, "K"), ss, NQMKSS)
              ? 1
              : -1;
    }
  }
  free(ek);
  free(m);
  return r;
}

static int wdec(int k, const nqjs *t) {
  uint8_t *dk, *c, *want;
  size_t dn = 0, cn = 0, wn = 0;
  int r = -1;
  dk = unhexa(nqjget(t, "dk"), &dn);
  c = unhexa(nqjget(t, "c"), &cn);
  want = unhexa(nqjget(t, "K"), &wn);
  if (dk != NULL && c != NULL) {
    if (bothdec(k, dk, dn, c, cn, NULL, NQEDEC)) {
      r = 0;
    } else if (want != NULL && wn == NQMKSS &&
               bothdec(k, dk, dn, c, cn, want, NQOK)) {
      r = 1;
    }
  }
  free(dk);
  free(c);
  free(want);
  return r;
}

static void wfile(const char *name) {
  char path[512];
  nqjs *v;
  const nqjs *gs;
  size_t i, j;
  long run[2] = {0, 0}, pass[2] = {0, 0};
  snprintf(path, sizeof path, "%s/wycheproof/%s", vroot, name);
  v = ldjs(path);
  NQTCHK(v != NULL);
  if (v == NULL) return;
  gs = nqjget(v, "testGroups");
  for (i = 0; gs != NULL && i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *ty = nqjstr(nqjget(g, "type"));
    int k = pset(g);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      const char *res = nqjstr(nqjget(t, "result"));
      uint64_t tc = 0;
      int valid = res != NULL && strcmp(res, "valid") == 0, r = -1, ok;
      getf(t, "tcId", &tc);
      if (k && ty != NULL) {
        if (strcmp(ty, "MLKEMKeyGen") == 0) {
          r = wkg(k, t);
        } else if (strcmp(ty, "MLKEMTest") == 0) {
          r = wfull(k, t);
        } else if (strcmp(ty, "MLKEMEncapsTest") == 0) {
          r = wenc(k, t);
        } else if (strcmp(ty, "MLKEMDecapsValidationTest") == 0) {
          r = wdec(k, t);
        }
      }
      ok = valid ? r == 1 : r == 0;
      run[valid]++;
      if (ok) pass[valid]++;
      else miss(name, valid ? "valid" : "invalid", 0, tc);
      NQTCHK(ok);
    }
  }
  printf("  %-40s valid %ld/%ld invalid %ld/%ld\n", name, pass[1], run[1],
         pass[0], run[0]);
  nqjfree(v);
}

static void wyche(void) {
  static const char *f[] = {
      "mlkem_512_keygen_seed_test.json",
      "mlkem_768_keygen_seed_test.json",
      "mlkem_1024_keygen_seed_test.json",
      "mlkem_512_encaps_test.json",
      "mlkem_768_encaps_test.json",
      "mlkem_1024_encaps_test.json",
      "mlkem_512_semi_expanded_decaps_test.json",
      "mlkem_768_semi_expanded_decaps_test.json",
      "mlkem_1024_semi_expanded_decaps_test.json",
      "mlkem_512_test.json",
      "mlkem_768_test.json",
      "mlkem_1024_test.json"};
  size_t i;
  printf("Wycheproof (%s/wycheproof)\n", vroot);
  for (i = 0; i < sizeof f / sizeof *f; i++) wfile(f[i]);
}

/* ---- round trips, implicit rejection, errors ---- */

/* xorshift: reproducible test inputs */
static uint64_t xs = 0x9e3779b97f4a7c15u;
static uint32_t rnd(void) {
  xs ^= xs << 13;
  xs ^= xs >> 7;
  xs ^= xs << 17;
  return (uint32_t)(xs >> 32);
}

/* J(z || c), independently */
static void jref(int k, const uint8_t *dk, const uint8_t *c, uint8_t *out) {
  uint8_t in[32 + NQMKCTX];
  memcpy(in, dk + NQMKDK(k) - 32, 32);
  memcpy(in + 32, c, NQMKCT(k));
  nqshk(256, in, 32 + NQMKCT(k), out, 32);
}

static void ttrip(void) {
  static uint8_t ek[NQMKEKX], dk[NQMKDKX], ct[NQMKCTX], c2[NQMKCTX];
  uint8_t s1[NQMKSS], s2[NQMKSS], s3[NQMKSS], jr[NQMKSS];
  int k, it;
  long n = 0, bad = 0;
  for (k = 2; k <= 4; k++) {
    for (it = 0; it < 12; it++) {
      size_t pos;
      NQTEQI(nqmkkg(k, ek, sizeof ek, dk, sizeof dk), NQOK);
      NQTEQI(nqmkenc(k, ek, NQMKEK(k), ct, sizeof ct, s1, sizeof s1),
             NQOK);
      NQTEQI(nqmkdec(k, dk, NQMKDK(k), ct, NQMKCT(k), s2, sizeof s2),
             NQOK);
      NQTEQI(nqmkdecp(k, dk, NQMKDK(k), ct, NQMKCT(k), s3, sizeof s3),
             NQOK);
      NQTEQM(s2, s1, NQMKSS);
      NQTEQM(s3, s1, NQMKSS);
      /* one flipped bit anywhere: implicit rejection, J(z || c') */
      memcpy(c2, ct, NQMKCT(k));
      pos = rnd() % NQMKCT(k);
      c2[pos] = (uint8_t)(c2[pos] ^ (1u << (rnd() % 8)));
      NQTEQI(nqmkdec(k, dk, NQMKDK(k), c2, NQMKCT(k), s2, sizeof s2),
             NQOK);
      NQTEQI(nqmkdecp(k, dk, NQMKDK(k), c2, NQMKCT(k), s3, sizeof s3),
             NQOK);
      jref(k, dk, c2, jr);
      NQTEQM(s2, jr, NQMKSS);
      NQTEQM(s3, jr, NQMKSS);
      NQTCHK(memcmp(s2, s1, NQMKSS) != 0);
      n++;
    }
    /* an ek inside dk that fails the modulus check, with h recomputed
     * so the hash check passes: decapsulation never re-encrypts under
     * it, so even the honest ciphertext is rejected */
    NQTEQI(nqmkkg(k, ek, sizeof ek, dk, sizeof dk), NQOK);
    NQTEQI(nqmkenc(k, ek, NQMKEK(k), ct, sizeof ct, s1, sizeof s1), NQOK);
    dk[384 * k] = 0xff;
    dk[384 * k + 1] |= 0x0f; /* first coefficient of t-hat = 4095 */
    nqs3(256, dk + 384 * k, NQMKEK(k), dk + 384 * k + NQMKEK(k));
    NQTEQI(nqmkdkc(k, dk, NQMKDK(k)), NQOK);
    NQTEQI(nqmkekc(k, dk + 384 * k, NQMKEK(k)), NQEDEC);
    NQTEQI(nqmkdec(k, dk, NQMKDK(k), ct, NQMKCT(k), s2, sizeof s2), NQOK);
    NQTEQI(nqmkdecp(k, dk, NQMKDK(k), ct, NQMKCT(k), s3, sizeof s3),
           NQOK);
    jref(k, dk, ct, jr);
    NQTEQM(s2, jr, NQMKSS);
    NQTEQM(s3, jr, NQMKSS);
    if (memcmp(s2, jr, NQMKSS) != 0) bad++;
  }
  printf("round trips: %ld encapsulations, %ld tampered ciphertexts, "
         "3 non-canonical ek in dk (%ld wrong)\n",
         n, n, bad);
}

static int allz(const uint8_t *p, size_t n) {
  size_t i;
  uint8_t d = 0;
  for (i = 0; i < n; i++) d |= p[i];
  return d == 0;
}

static void terr(void) {
  static uint8_t ek[NQMKEKX + 1], dk[NQMKDKX + 1], ct[NQMKCTX + 1];
  uint8_t ss[NQMKSS + 1], seed[NQMKSEED], m[NQMKMSG];
  int k;
  memset(seed, 7, sizeof seed);
  memset(m, 9, sizeof m);
  NQTEQI(nqmkkgd(1, seed, 64, ek, sizeof ek, dk, sizeof dk), NQEARG);
  NQTEQI(nqmkkgd(5, seed, 64, ek, sizeof ek, dk, sizeof dk), NQEARG);
  NQTEQI(nqmkkgd(3, NULL, 64, ek, sizeof ek, dk, sizeof dk), NQEARG);
  NQTEQI(nqmkkg(0, ek, sizeof ek, dk, sizeof dk), NQEARG);
  NQTEQI(nqmkenc(3, NULL, 1184, ct, sizeof ct, ss, sizeof ss), NQEARG);
  NQTEQI(nqmkdec(3, dk, 2400, NULL, 1088, ss, sizeof ss), NQEARG);
  NQTEQI(nqmkdecp(3, dk, 2400, ct, 1088, NULL, 32), NQEARG);
  NQTEQI(nqmkekc(9, ek, 1184), NQEARG);
  NQTEQI(nqmkdkc(3, NULL, 2400), NQEARG);
  NQTEQI(nqmkk(NQMLKEM512), 2);
  NQTEQI(nqmkk(NQMLKEM768), 3);
  NQTEQI(nqmkk(NQMLKEM1024), 4);
  NQTEQI(nqmkk(NQHQC128), 0);
  for (k = 2; k <= 4; k++) {
    const size_t e = NQMKEK(k), d = NQMKDK(k), c = NQMKCT(k);
    NQTEQI(nqmkkgd(k, seed, 63, ek, e, dk, d), NQEARG);
    NQTCHK(allz(ek, e) && allz(dk, d));
    NQTEQI(nqmkkgd(k, seed, 64, ek, e - 1, dk, d), NQEBUF);
    NQTEQI(nqmkkgd(k, seed, 64, ek, e, dk, d - 1), NQEBUF);
    NQTEQI(nqmkkgd(k, seed, 64, ek, e, dk, d), NQOK);
    NQTEQI(nqmkekc(k, ek, e), NQOK);
    NQTEQI(nqmkekc(k, ek, e - 1), NQEDEC);
    NQTEQI(nqmkekc(k, ek, e + 1), NQEDEC);
    NQTEQI(nqmkdkc(k, dk, d), NQOK);
    NQTEQI(nqmkdkc(k, dk, d - 1), NQEDEC);
    NQTEQI(nqmkdkc(k, dk, d + 1), NQEDEC);
    NQTEQI(nqmkencd(k, ek, e, m, 31, ct, c, ss, 32), NQEARG);
    NQTCHK(allz(ct, c) && allz(ss, 32));
    NQTEQI(nqmkencd(k, ek, e, m, 32, ct, c - 1, ss, 32), NQEBUF);
    NQTEQI(nqmkencd(k, ek, e, m, 32, ct, c, ss, 31), NQEBUF);
    NQTEQI(nqmkencd(k, ek, e - 1, m, 32, ct, c, ss, 32), NQEDEC);
    NQTEQI(nqmkencd(k, ek, e + 1, m, 32, ct, c, ss, 32), NQEDEC);
    NQTEQI(nqmkencd(k, ek, e, m, 32, ct, c, ss, 32), NQOK);
    NQTEQI(nqmkdec(k, dk, d, ct, c, ss, 31), NQEBUF);
    NQTEQI(nqmkdec(k, dk, d, ct, c - 1, ss, 32), NQEDEC);
    NQTCHK(allz(ss, 32));
    NQTEQI(nqmkdec(k, dk, d, ct, c + 1, ss, 32), NQEDEC);
    NQTEQI(nqmkdec(k, dk, d - 1, ct, c, ss, 32), NQEDEC);
    NQTEQI(nqmkdecp(k, dk, d + 1, ct, c, ss, 32), NQEDEC);
    NQTEQI(nqmkdecp(k, dk, d, ct, c + 1, ss, 32), NQEDEC);
    /* larger buffers are fine; only the defined bytes are written */
    ss[32] = 0xa5;
    NQTEQI(nqmkdec(k, dk, d, ct, c, ss, sizeof ss), NQOK);
    NQTEQI(ss[32], 0xa5);
    /* the hash check */
    dk[d - 40] ^= 1;
    NQTEQI(nqmkdkc(k, dk, d), NQEDEC);
    NQTEQI(nqmkdec(k, dk, d, ct, c, ss, 32), NQEDEC);
    NQTEQI(nqmkdecp(k, dk, d, ct, c, ss, 32), NQEDEC);
    dk[d - 40] ^= 1;
    /* the modulus check: coefficient 0 = 3329 */
    ek[0] = 0x01;
    ek[1] = (uint8_t)((ek[1] & 0xf0) | 0x0d);
    NQTEQI(nqmkekc(k, ek, e), NQEDEC);
    NQTEQI(nqmkencd(k, ek, e, m, 32, ct, c, ss, 32), NQEDEC);
    NQTCHK(allz(ct, c) && allz(ss, 32));
  }
}

int main(void) {
  const char *env = getenv("NQVEC");
  if (env != NULL && *env) vroot = env;
  printf("ACVP (%s/acvp)\n", vroot);
  acvpkg();
  acvped();
  wyche();
  ttrip();
  terr();
  return nqtdone("tmlkem");
}
