/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA tests: every NIST ACVP ML-DSA keyGen / sigGen / sigVer test and
 * every Wycheproof mldsa_* test in vectors/ (or under $NQMDVEC, which
 * holds acvp/ and wycheproof/ the same way), masked against unmasked
 * signing, round trips, and the errors of the interface.
 *
 * With arguments it is a small tool for the OpenSSL cross-check:
 *   tmldsa kgd 44|65|87 SEEDHEX PKFILE SKFILE
 *   tmldsa sign 44|65|87 SKFILE MSGFILE CTXHEX|- RNDHEX|-|z SIGFILE
 *   tmldsa vrfy 44|65|87 PKFILE MSGFILE CTXHEX|- SIGFILE
 * (rnd "-": hedged from the OS, "z": deterministic; exit 0 on success). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "mldsa/mldsa.h"
#include "nqt.h"

static const char *vroot = "vectors";
static int nmiss = 0;

typedef struct {
  long run, pass, skip;
} cnt;

/* ---- JSON helpers ---- */

static nqjs *ldjs(const char *sub, const char *name) {
  char path[512];
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc;
  snprintf(path, sizeof path, "%s/%s/%s", vroot, sub, name);
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
  if (v == NULL || nqjint(v, &x) != NQOK || x < 0) return 0;
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

/* A hex field as a fresh buffer (at least one byte); NULL when the field
 * is missing or not hex. */
static uint8_t *hexf(const nqjs *o, const char *key, size_t *n) {
  const char *s = nqjstr(nqjget(o, key));
  size_t len;
  uint8_t *b;
  *n = 0;
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
  const char *s = nqjstr(v);
  size_t m = 0, len;
  uint8_t *b;
  int ok;
  if (s == NULL) return 0;
  len = strlen(s);
  b = (uint8_t *)calloc(len / 2 + 1, 1);
  if (b == NULL) return 0;
  ok = nqunhex(s, len, b, len / 2 + 1, &m) == NQOK && m == n &&
       memcmp(b, got, n) == 0;
  free(b);
  return ok;
}

static int streq(const nqjs *v, const char *s) {
  const char *t = nqjstr(v);
  return t != NULL && strcmp(t, s) == 0;
}

static int salg(const char *s) {
  if (s == NULL) return 0;
  if (strcmp(s, "ML-DSA-44") == 0) return NQMLDSA44;
  if (strcmp(s, "ML-DSA-65") == 0) return NQMLDSA65;
  if (strcmp(s, "ML-DSA-87") == 0) return NQMLDSA87;
  return 0;
}

static int halg(const char *s) {
  static const struct {
    const char *n;
    nqhalg a;
  } t[] = {{"SHA2-224", NQS224},     {"SHA2-256", NQS256},
           {"SHA2-384", NQS384},     {"SHA2-512", NQS512},
           {"SHA2-512/224", NQS512T224}, {"SHA2-512/256", NQS512T256},
           {"SHA3-224", NQS3224},    {"SHA3-256", NQS3256},
           {"SHA3-384", NQS3384},    {"SHA3-512", NQS3512},
           {"SHAKE-128", NQSHK128},  {"SHAKE-256", NQSHK256}};
  size_t i;
  if (s == NULL) return -1;
  for (i = 0; i < sizeof t / sizeof t[0]; i++) {
    if (strcmp(s, t[i].n) == 0) return (int)t[i].a;
  }
  return -1;
}

static void miss(const char *set, const char *what, uint64_t tg,
                 uint64_t tc) {
  if (nmiss++ < 30) {
    fprintf(stderr, "%s: %s failed (group %llu, tcId %llu)\n", set, what,
            (unsigned long long)tg, (unsigned long long)tc);
  }
}

static void prc(const char *set, uint64_t tg, const char *desc,
                const cnt *c) {
  printf("  %s group %llu %s: %ld run, %ld passed, %ld skipped\n", set,
         (unsigned long long)tg, desc, c->run, c->pass, c->skip);
}

/* NQSUB=n runs every n-th signing test (sigGen and Wycheproof signing),
 * for slow runs such as valgrind; verification always runs in full. */
static size_t step = 1;

/* ---- ACVP ---- */

static void tally(cnt *c, cnt *all, int ok, int skip) {
  if (skip) {
    c->skip++;
    all->skip++;
    return;
  }
  c->run++;
  all->run++;
  NQTCHK(ok);
  if (ok) {
    c->pass++;
    all->pass++;
  }
}

static void acvpkg(void) {
  const char *set = "acvp/ML-DSA-keyGen-FIPS204";
  nqjs *pr = ldjs(set, "prompt.json");
  nqjs *ex = ldjs(set, "expectedResults.json");
  const nqjs *pg, *eg;
  static uint8_t pk[NQMDPKMAX], sk[NQMDSKMAX];
  cnt all = {0, 0, 0};
  size_t i, j;
  NQTCHK(pr != NULL && ex != NULL);
  if (pr == NULL || ex == NULL) goto out;
  pg = groups(pr);
  eg = groups(ex);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    int alg = salg(nqjstr(nqjget(g, "parameterSet")));
    uint64_t tg = 0;
    cnt c = {0, 0, 0};
    nqssz sz;
    getf(g, "tgId", &tg);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t n;
      uint8_t *seed;
      int ok = 0;
      getf(t, "tcId", &tc);
      e = findexp(eg, tg, tc);
      seed = hexf(t, "seed", &n);
      if (alg == 0 || seed == NULL || e == NULL) {
        tally(&c, &all, 0, 1);
        free(seed);
        continue;
      }
      nqmdsz(alg, &sz);
      if (nqmdkgd(alg, seed, n, pk, sizeof pk, sk, sizeof sk) == NQOK) {
        ok = eqhex(nqjget(e, "pk"), pk, sz.pk) &&
             eqhex(nqjget(e, "sk"), sk, sz.sk);
      }
      if (!ok) miss(set, "keyGen", tg, tc);
      tally(&c, &all, ok, 0);
      free(seed);
    }
    prc("keyGen", tg, nqjstr(nqjget(g, "parameterSet")), &c);
  }
  printf("ACVP keyGen: %ld run, %ld passed, %ld skipped\n", all.run,
         all.pass, all.skip);
  NQTCHK(all.run > 0 && all.skip == 0);
out:
  nqjfree(pr);
  nqjfree(ex);
}

static void gdesc(const nqjs *g, char *d, size_t n) {
  const char *ps = nqjstr(nqjget(g, "parameterSet"));
  const char *ifc = nqjstr(nqjget(g, "signatureInterface"));
  const char *ph = nqjstr(nqjget(g, "preHash"));
  int det = nqjbool(nqjget(g, "deterministic"));
  int emu = nqjbool(nqjget(g, "externalMu"));
  snprintf(d, n, "%s %s%s%s%s", ps ? ps : "?", ifc ? ifc : "?",
           ph ? (strcmp(ph, "pure") == 0 ? "/pure" : "/preHash") : "",
           det < 0 ? "" : det ? " deterministic" : " hedged",
           emu == 1 ? " externalMu" : emu == 0 ? " message" : "");
}

static void acvpsg(void) {
  const char *set = "acvp/ML-DSA-sigGen-FIPS204";
  nqjs *pr = ldjs(set, "prompt.json");
  nqjs *ex = ldjs(set, "expectedResults.json");
  const nqjs *pg, *eg;
  static uint8_t sig[NQMDSIGMAX], sig2[NQMDSIGMAX];
  cnt all = {0, 0, 0};
  size_t i, j;
  NQTCHK(pr != NULL && ex != NULL);
  if (pr == NULL || ex == NULL) goto out;
  pg = groups(pr);
  eg = groups(ex);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    int alg = salg(nqjstr(nqjget(g, "parameterSet")));
    int det = nqjbool(nqjget(g, "deterministic"));
    int ext = streq(nqjget(g, "signatureInterface"), "external");
    int pre = streq(nqjget(g, "preHash"), "preHash");
    int emu = nqjbool(nqjget(g, "externalMu")) == 1;
    uint64_t tg = 0;
    cnt c = {0, 0, 0};
    char desc[128];
    getf(g, "tgId", &tg);
    gdesc(g, desc, sizeof desc);
    for (j = 0; ts != NULL && j < ts->n; j += step) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t skn, mn, cn, rn, mun, out = 0;
      uint8_t *sk, *m, *ctx, *rnd, *mu, zero[32];
      int ok = 0, rc = NQEARG, ph = 0;
      getf(t, "tcId", &tc);
      e = findexp(eg, tg, tc);
      sk = hexf(t, "sk", &skn);
      m = hexf(t, "message", &mn);
      ctx = hexf(t, "context", &cn);
      rnd = hexf(t, "rnd", &rn);
      mu = hexf(t, "mu", &mun);
      memset(zero, 0, sizeof zero);
      if (pre) ph = halg(nqjstr(nqjget(t, "hashAlg")));
      if (alg == 0 || sk == NULL || e == NULL || det < 0 || ph < 0 ||
          (!det && rnd == NULL) || (emu ? mu == NULL : m == NULL)) {
        tally(&c, &all, 0, 1);
      } else {
        const uint8_t *r = det ? zero : rnd;
        size_t rl = det ? sizeof zero : rn;
        if (ext) {
          rc = nqmdsign(alg, sk, skn, m, mn, ctx, ctx ? cn : 0, ph, r, rl,
                        sig, sizeof sig, &out);
        } else if (emu) {
          rc = mun == NQMDMU ? nqmdsmu(alg, sk, skn, mu, r, rl, NQMDMASK,
                                       sig, sizeof sig, &out)
                             : NQEARG;
          /* the unmasked signer gives the same bytes */
          if (rc == NQOK) {
            size_t o2 = 0;
            NQTEQI(nqmdsmu(alg, sk, skn, mu, r, rl, NQMDPLAIN, sig2,
                           sizeof sig2, &o2),
                   NQOK);
            NQTEQI(o2, out);
            NQTEQM(sig2, sig, out);
          }
        } else {
          rc = nqmdsigi(alg, sk, skn, m, mn, r, rl, sig, sizeof sig, &out);
        }
        ok = rc == NQOK && eqhex(nqjget(e, "signature"), sig, out);
        if (!ok) miss(set, "sigGen", tg, tc);
        tally(&c, &all, ok, 0);
      }
      free(sk);
      free(m);
      free(ctx);
      free(rnd);
      free(mu);
    }
    prc("sigGen", tg, desc, &c);
  }
  printf("ACVP sigGen: %ld run, %ld passed, %ld skipped\n", all.run,
         all.pass, all.skip);
  NQTCHK(all.run > 0 && all.skip == 0);
out:
  nqjfree(pr);
  nqjfree(ex);
}

static void acvpsv(void) {
  const char *set = "acvp/ML-DSA-sigVer-FIPS204";
  nqjs *pr = ldjs(set, "prompt.json");
  nqjs *ex = ldjs(set, "expectedResults.json");
  const nqjs *pg, *eg;
  cnt all = {0, 0, 0};
  long npass = 0, nfail = 0;
  size_t i, j;
  NQTCHK(pr != NULL && ex != NULL);
  if (pr == NULL || ex == NULL) goto out;
  pg = groups(pr);
  eg = groups(ex);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    int alg = salg(nqjstr(nqjget(g, "parameterSet")));
    int ext = streq(nqjget(g, "signatureInterface"), "external");
    int pre = streq(nqjget(g, "preHash"), "preHash");
    int emu = nqjbool(nqjget(g, "externalMu")) == 1;
    uint64_t tg = 0;
    cnt c = {0, 0, 0};
    char desc[128];
    getf(g, "tgId", &tg);
    gdesc(g, desc, sizeof desc);
    for (j = 0; ts != NULL && j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      size_t pkn, mn, cn, sn, mun;
      uint8_t *pk, *m, *ctx, *s, *mu;
      int rc, ph = 0, want;
      getf(t, "tcId", &tc);
      e = findexp(eg, tg, tc);
      pk = hexf(t, "pk", &pkn);
      m = hexf(t, "message", &mn);
      ctx = hexf(t, "context", &cn);
      s = hexf(t, "signature", &sn);
      mu = hexf(t, "mu", &mun);
      want = nqjbool(nqjget(e, "testPassed"));
      if (pre) ph = halg(nqjstr(nqjget(t, "hashAlg")));
      if (alg == 0 || pk == NULL || s == NULL || e == NULL || want < 0 ||
          ph < 0 || (emu ? mu == NULL : m == NULL)) {
        tally(&c, &all, 0, 1);
      } else {
        if (ext) {
          rc = nqmdvrfy(alg, pk, pkn, m, mn, ctx, ctx ? cn : 0, ph, s, sn);
        } else if (emu) {
          rc = mun == NQMDMU ? nqmdvmu(alg, pk, pkn, mu, s, sn) : NQEARG;
        } else {
          rc = nqmdvfyi(alg, pk, pkn, m, mn, s, sn);
        }
        if (want) npass++;
        else nfail++;
        if ((rc == NQOK) != (want == 1)) miss(set, "sigVer", tg, tc);
        tally(&c, &all, (rc == NQOK) == (want == 1), 0);
      }
      free(pk);
      free(m);
      free(ctx);
      free(s);
      free(mu);
    }
    prc("sigVer", tg, desc, &c);
  }
  printf("ACVP sigVer: %ld run (%ld valid, %ld invalid), %ld passed, "
         "%ld skipped\n",
         all.run, npass, nfail, all.pass, all.skip);
  NQTCHK(all.run > 0 && all.skip == 0);
out:
  nqjfree(pr);
  nqjfree(ex);
}

/* ---- Wycheproof ---- */

enum { WVER, WNOSEED, WSEED };

static void wyc(int alg, int kind) {
  static const char *kn[3] = {"verify", "sign_noseed", "sign_seed"};
  static uint8_t pkd[NQMDPKMAX], skd[NQMDSKMAX], sig[NQMDSIGMAX],
      sig2[NQMDSIGMAX];
  char name[64];
  nqjs *v;
  const nqjs *gs;
  cnt c = {0, 0, 0};
  long nval = 0, ninv = 0;
  size_t i, j;
  nqssz sz;
  nqmdsz(alg, &sz);
  snprintf(name, sizeof name, "mldsa_%d_%s_test.json",
           alg == NQMLDSA44 ? 44 : alg == NQMLDSA65 ? 65 : 87, kn[kind]);
  v = ldjs("wycheproof", name);
  NQTCHK(v != NULL);
  if (v == NULL) return;
  gs = nqjget(v, "testGroups");
  for (i = 0; gs != NULL && i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    size_t pkn = 0, skn = 0, seedn = 0;
    uint8_t *pk = hexf(g, "publicKey", &pkn);
    uint8_t *sk = NULL, *seed = NULL;
    int krc = NQOK;
    if (kind == WNOSEED) {
      sk = hexf(g, "privateKey", &skn);
      if (sk == NULL) krc = NQEDEC;
    } else if (kind == WSEED) {
      seed = hexf(g, "privateSeed", &seedn);
      krc = seed == NULL ? NQEDEC
                         : nqmdkgd(alg, seed, seedn, pkd, sizeof pkd, skd,
                                   sizeof skd);
      if (krc == NQOK) {
        sk = (uint8_t *)malloc(sz.sk);
        if (sk != NULL) memcpy(sk, skd, sz.sk);
        skn = sz.sk;
        /* the key from the seed is the one the file gives */
        if (pk != NULL) NQTCHK(pkn == sz.pk && memcmp(pk, pkd, pkn) == 0);
      }
    }
    for (j = 0; ts != NULL && j < ts->n;
         j += kind == WVER ? 1 : step) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      size_t mn, cn, sn, mun, rn, out = 0;
      uint8_t *m = hexf(t, "msg", &mn), *ctx = hexf(t, "ctx", &cn);
      uint8_t *s = hexf(t, "sig", &sn), *mu = hexf(t, "mu", &mun);
      uint8_t *rnd = hexf(t, "rnd", &rn), zero[32];
      const char *res = nqjstr(nqjget(t, "result"));
      int valid = res != NULL && strcmp(res, "valid") == 0;
      int acc = res != NULL && strcmp(res, "acceptable") == 0;
      int rc, ok;
      getf(t, "tcId", &tc);
      memset(zero, 0, sizeof zero);
      if (res == NULL || s == NULL || (m == NULL && mu == NULL)) {
        c.skip++;
        goto next;
      }
      if (kind == WVER) {
        static const uint8_t none[1] = {0};
        rc = nqmdvrfy(alg, pk ? pk : none, pk ? pkn : 0, m ? m : none,
                      m ? mn : 0, ctx, ctx ? cn : 0, 0, s, sn);
        ok = valid ? rc == NQOK : acc || rc != NQOK;
      } else {
        const uint8_t *r = rnd ? rnd : zero;
        size_t rl = rnd ? rn : sizeof zero;
        rc = krc;
        if (rc == NQOK && sk == NULL) rc = NQEMEM;
        if (rc == NQOK && m != NULL) {
          rc = nqmdsign(alg, sk, skn, m, mn, ctx, ctx ? cn : 0, 0, r, rl,
                        sig, sizeof sig, &out);
        } else if (rc == NQOK) {
          rc = mun == NQMDMU ? nqmdsmu(alg, sk, skn, mu, r, rl, NQMDMASK,
                                       sig, sizeof sig, &out)
                             : NQEARG;
        }
        ok = valid ? rc == NQOK && out == sn && memcmp(sig, s, sn) == 0
                   : acc || rc != NQOK;
        /* mu as the file gives it, and the external-mu signers on it */
        if (rc == NQOK && mu != NULL && mun == NQMDMU) {
          size_t o2 = 0;
          int k;
          if (m != NULL && pk != NULL) {
            uint8_t mu2[NQMDMU];
            NQTEQI(nqmdmu(alg, pk, pkn, m, mn, ctx, ctx ? cn : 0, 0, mu2),
                   NQOK);
            NQTEQM(mu2, mu, NQMDMU);
          }
          for (k = 0; k < 2; k++) {
            NQTEQI(nqmdsmu(alg, sk, skn, mu, r, rl,
                           k ? NQMDMASK : NQMDPLAIN, sig2, sizeof sig2,
                           &o2),
                   NQOK);
            NQTEQM(sig2, sig, out);
          }
        }
      }
      if (valid) nval++;
      else ninv++;
      c.run++;
      NQTCHK(ok);
      if (ok) {
        c.pass++;
      } else {
        miss(name, valid ? "valid test" : "invalid test", 0, tc);
      }
    next:
      free(m);
      free(ctx);
      free(s);
      free(mu);
      free(rnd);
    }
    free(pk);
    if (sk != NULL) {
      nqwipe(sk, skn);
      free(sk);
    }
    free(seed);
  }
  printf("Wycheproof %s: %ld run (%ld valid, %ld invalid), %ld passed, "
         "%ld skipped\n",
         name, c.run, nval, ninv, c.pass, c.skip);
  NQTCHK(c.run > 0 && c.skip == 0);
  nqjfree(v);
}

/* ---- round trips, masked against unmasked, errors ---- */

static const int algs[3] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};

static void units(void) {
  static uint8_t pk[NQMDPKMAX], sk[NQMDSKMAX], sig[NQMDSIGMAX],
      sig2[NQMDSIGMAX], bad[NQMDSKMAX + 1];
  static const nqssz want[3] = {{NQMD44PK, NQMD44SK, NQMD44SIG},
                                {NQMD65PK, NQMD65SK, NQMD65SIG},
                                {NQMD87PK, NQMD87SK, NQMD87SIG}};
  const uint8_t msg[] = "noqtis ML-DSA round trip";
  const uint8_t ctx[] = "noqtis-capsule-1";
  uint8_t mu[NQMDMU], rnd[32], big[256], oid[NQMDOID];
  size_t ml = sizeof msg - 1, cl = sizeof ctx - 1, out;
  int a, ph, i;
  memset(big, 'A', sizeof big);
  NQTEQI(nqmdsz(99, NULL), NQEARG);
  NQTEQI(nqmdoid(0, oid), NQEARG);
  NQTEQI(nqmdoid(NQS256, oid), NQOK);
  NQTCHK(oid[0] == 0x06 && oid[1] == 0x09 && oid[10] == 1);
  for (a = 0; a < 3; a++) {
    int alg = algs[a];
    nqssz sz;
    size_t hoff;
    NQTEQI(nqmdsz(alg, &sz), NQOK);
    NQTCHK(sz.pk == want[a].pk && sz.sk == want[a].sk &&
           sz.sig == want[a].sig);
    NQTEQI(nqmdkg(alg, pk, sizeof pk, sk, sizeof sk), NQOK);
    /* hedged and deterministic, pure and every pre-hash */
    for (ph = 0; ph <= (int)NQSHK256; ph++) {
      NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, ctx, cl, ph, NULL, 0, sig,
                      sizeof sig, &out),
             NQOK);
      NQTEQI(out, sz.sig);
      NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, ctx, cl, ph, sig, sz.sig),
             NQOK);
      NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, ctx, cl - 1, ph, sig,
                      sz.sig),
             NQEVRFY);
      NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml - 1, ctx, cl, ph, sig,
                      sz.sig),
             NQEVRFY);
      NQTCHK(nqmdvrfy(alg, pk, sz.pk, msg, ml, ctx, cl,
                      ph == 0 ? (int)NQS256 : 0, sig, sz.sig) != NQOK);
    }
    /* deterministic signing repeats; hedged does not */
    memset(rnd, 0, sizeof rnd);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, rnd, 32, sig,
                    sizeof sig, &out),
           NQOK);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, rnd, 32, sig2,
                    sizeof sig2, &out),
           NQOK);
    NQTEQM(sig, sig2, sz.sig);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig2,
                    sizeof sig2, &out),
           NQOK);
    NQTCHK(memcmp(sig, sig2, sz.sig) != 0);
    /* external mu agrees with the pure interface */
    NQTEQI(nqmdmu(alg, pk, sz.pk, msg, ml, ctx, cl, 0, mu), NQOK);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, ctx, cl, 0, rnd, 32, sig,
                    sizeof sig, &out),
           NQOK);
    NQTEQI(nqmdsmu(alg, sk, sz.sk, mu, rnd, 32, NQMDPLAIN, sig2,
                   sizeof sig2, &out),
           NQOK);
    NQTEQM(sig, sig2, sz.sig);
    NQTEQI(nqmdvmu(alg, pk, sz.pk, mu, sig, sz.sig), NQOK);
    /* masked against unmasked, on random mu and rnd */
    for (i = 0; i < 4; i++) {
      NQTEQI(nqrand(mu, sizeof mu), NQOK);
      NQTEQI(nqrand(rnd, sizeof rnd), NQOK);
      NQTEQI(nqmdsmu(alg, sk, sz.sk, mu, rnd, 32, NQMDMASK, sig,
                     sizeof sig, &out),
             NQOK);
      NQTEQI(nqmdsmu(alg, sk, sz.sk, mu, rnd, 32, NQMDPLAIN, sig2,
                     sizeof sig2, &out),
             NQOK);
      NQTEQM(sig, sig2, sz.sig);
      NQTEQI(nqmdvmu(alg, pk, sz.pk, mu, sig, sz.sig), NQOK);
    }
    /* the internal interface */
    NQTEQI(nqmdsigi(alg, sk, sz.sk, msg, ml, NULL, 0, sig, sizeof sig,
                    &out),
           NQOK);
    NQTEQI(nqmdvfyi(alg, pk, sz.pk, msg, ml, sig, sz.sig), NQOK);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, sig, sz.sig),
           NQEVRFY);
    /* argument errors */
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, big, 256, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, big, 255, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQOK);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, big, 255, 0, sig, sz.sig),
           NQOK);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, big, 256, 0, sig, sz.sig),
           NQEARG);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 3, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 99, NULL, 0, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, rnd, 31, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdsign(alg, sk, sz.sk - 1, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEDEC);
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sz.sig - 1, &out),
           NQEBUF);
    NQTEQI(nqmdsign(alg, NULL, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdsign(99, sk, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEARG);
    NQTEQI(nqmdkgd(alg, rnd, 31, pk, sizeof pk, sk, sizeof sk), NQEARG);
    NQTEQI(nqmdkgd(alg, rnd, 32, pk, sz.pk - 1, sk, sizeof sk), NQEBUF);
    /* verification of malformed input */
    NQTEQI(nqmdsign(alg, sk, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQOK);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk - 1, msg, ml, NULL, 0, 0, sig, sz.sig),
           NQEDEC);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk + 1, msg, ml, NULL, 0, 0, sig, sz.sig),
           NQEDEC);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, sig, sz.sig - 1),
           NQEDEC);
    memcpy(bad, sig, sz.sig);
    bad[sz.sig] = 0;
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad, sz.sig + 1),
           NQEDEC);
    NQTEQI(nqmdvrfy(alg, NULL, sz.pk, msg, ml, NULL, 0, 0, sig, sz.sig),
           NQEARG);
    /* every bit of the signature matters */
    for (i = 0; i < 64; i++) {
      size_t at = (size_t)(i * 997) % sz.sig;
      memcpy(bad, sig, sz.sig);
      bad[at] ^= (uint8_t)(1u << (i % 8));
      NQTCHK(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad, sz.sig) !=
             NQOK);
    }
    /* the hint encoding: counts must not fall, must not pass omega, the
     * positions must rise, the padding must be zero */
    hoff = sz.sig - (a == 0 ? 84 : a == 1 ? 61 : 83);
    {
      size_t kk = a == 0 ? 4 : a == 1 ? 6 : 8, om = a == 0 ? 80
                                                   : a == 1 ? 55 : 75;
      size_t cnt0 = sig[hoff + om], last = sig[hoff + om + kk - 1];
      memcpy(bad, sig, sz.sig);
      bad[hoff + om + kk - 1] = (uint8_t)(om + 1);
      NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad, sz.sig),
             NQEDEC);
      if (last < om) {
        memcpy(bad, sig, sz.sig);
        bad[hoff + om - 1] = 1;
        NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad,
                        sz.sig),
               NQEDEC);
      }
      if (cnt0 > 0 && kk > 1) {
        memcpy(bad, sig, sz.sig);
        bad[hoff + om + 1] = (uint8_t)(cnt0 - 1);
        NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad,
                        sz.sig),
               NQEDEC);
      }
      if (cnt0 >= 2) {
        memcpy(bad, sig, sz.sig);
        bad[hoff + 1] = bad[hoff];
        NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad,
                        sz.sig),
               NQEDEC);
      }
    }
    /* z at the norm bound: gamma1 - beta packs as beta */
    {
      size_t ct = a == 0 ? 32 : a == 1 ? 48 : 64;
      memcpy(bad, sig, sz.sig);
      memset(bad + ct, 0, 3); /* z[0] = gamma1 > gamma1 - beta */
      NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, ml, NULL, 0, 0, bad, sz.sig),
             NQEVRFY);
    }
    /* a secret key whose s1 leaves [-eta, eta] */
    memcpy(bad, sk, sz.sk);
    bad[128] = 0xff;
    NQTEQI(nqmdsign(alg, bad, sz.sk, msg, ml, NULL, 0, 0, NULL, 0, sig,
                    sizeof sig, &out),
           NQEDEC);
    NQTEQI(nqmdsmu(alg, bad, sz.sk, mu, rnd, 32, NQMDPLAIN, sig,
                   sizeof sig, &out),
           NQEDEC);
    for (i = 0; i < (int)sz.sig; i++) NQTCHK(sig[i] == 0);
  }
}

/* ---- the cross-check tool ---- */

static int calg(const char *s) {
  if (strcmp(s, "44") == 0) return NQMLDSA44;
  if (strcmp(s, "65") == 0) return NQMLDSA65;
  if (strcmp(s, "87") == 0) return NQMLDSA87;
  return 0;
}

static int wrf(const char *path, const uint8_t *b, size_t n) {
  FILE *f = fopen(path, "wb");
  int ok;
  if (f == NULL) return 0;
  ok = fwrite(b, 1, n, f) == n;
  return fclose(f) == 0 && ok;
}

static uint8_t *uhx(const char *s, size_t *n) {
  size_t len = strlen(s);
  uint8_t *b = (uint8_t *)calloc(len / 2 + 1, 1);
  *n = 0;
  if (b == NULL) return NULL;
  if (strcmp(s, "-") == 0) return b;
  if (nqunhex(s, len, b, len / 2 + 1, n) != NQOK) {
    free(b);
    return NULL;
  }
  return b;
}

static int tool(int argc, char **argv) {
  static uint8_t pk[NQMDPKMAX], sk[NQMDSKMAX], sig[NQMDSIGMAX];
  int alg = argc > 2 ? calg(argv[2]) : 0, rc = NQEARG;
  char *a = NULL, *b = NULL;
  size_t an = 0, bn = 0, n = 0, n2 = 0, out = 0;
  uint8_t *x = NULL, *y = NULL;
  nqssz sz;
  if (alg == 0) return 2;
  nqmdsz(alg, &sz);
  if (strcmp(argv[1], "kgd") == 0 && argc == 6) {
    x = uhx(argv[3], &n);
    if (x != NULL) rc = nqmdkgd(alg, x, n, pk, sizeof pk, sk, sizeof sk);
    if (rc == NQOK && (!wrf(argv[4], pk, sz.pk) || !wrf(argv[5], sk, sz.sk))) {
      rc = NQEIO;
    }
  } else if (strcmp(argv[1], "sign") == 0 && argc == 8) {
    x = uhx(argv[5], &n);
    if (strcmp(argv[6], "z") == 0) {
      y = (uint8_t *)calloc(32, 1);
      n2 = 32;
    } else {
      y = uhx(argv[6], &n2);
    }
    if (x != NULL && y != NULL &&
        nqreadf(argv[3], 1 << 20, &a, &an) == NQOK &&
        nqreadf(argv[4], 1 << 28, &b, &bn) == NQOK) {
      rc = nqmdsign(alg, (const uint8_t *)a, an, (const uint8_t *)b, bn, x,
                    n, 0, strcmp(argv[6], "-") == 0 ? NULL : y, n2, sig,
                    sizeof sig, &out);
      if (rc == NQOK && !wrf(argv[7], sig, out)) rc = NQEIO;
    }
  } else if (strcmp(argv[1], "vrfy") == 0 && argc == 7) {
    x = uhx(argv[5], &n);
    if (x != NULL && nqreadf(argv[3], 1 << 20, &a, &an) == NQOK &&
        nqreadf(argv[4], 1 << 28, &b, &bn) == NQOK) {
      char *s = NULL;
      size_t sn = 0;
      if (nqreadf(argv[6], 1 << 20, &s, &sn) == NQOK) {
        rc = nqmdvrfy(alg, (const uint8_t *)a, an, (const uint8_t *)b, bn, x,
                      n, 0, (const uint8_t *)s, sn);
        nqfree(s, sn + 1);
      }
    }
  }
  if (a != NULL) nqfree(a, an + 1);
  if (b != NULL) nqfree(b, bn + 1);
  free(x);
  free(y);
  nqwipe(sk, sizeof sk);
  if (rc != NQOK) fprintf(stderr, "tmldsa %s: %s\n", argv[1], nqerr(rc));
  return rc == NQOK ? 0 : 1;
}

int main(int argc, char **argv) {
  const char *env = getenv("NQMDVEC"), *sub = getenv("NQSUB");
  int a;
  if (argc > 1) return tool(argc, argv);
  if (env != NULL && *env) vroot = env;
  if (sub != NULL && atoi(sub) > 1) {
    step = (size_t)atoi(sub);
    printf("NQSUB=%u: every %u-th signing test\n", (unsigned)step,
           (unsigned)step);
  }
  printf("vectors: %s\n", vroot);
  units();
  acvpkg();
  acvpsg();
  acvpsv();
  for (a = 0; a < 3; a++) {
    wyc(algs[a], WVER);
    wyc(algs[a], WNOSEED);
    wyc(algs[a], WSEED);
  }
  return nqtdone("tmldsa");
}
