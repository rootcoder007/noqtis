/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HMAC_DRBG tests: every SHA2-256 and SHA2-512 test of the NIST ACVP set
 * vectors/acvp/hmacDRBG-1.0 (the other hashes are counted as skipped),
 * the reseed counter limit, wiping, self-seeding and every error. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "drbg/drbg.h"
#include "nqt.h"

#define DIR "hmacDRBG-1.0"

static int nmiss = 0;

/* ---- JSON helpers (as in thash.c) ---- */

static nqjs *ldjs(const char *name) {
  char path[256];
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc;
  snprintf(path, sizeof path, "vectors/acvp/%s/%s", DIR, name);
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
  if (nqjint(nqjget(o, key), &x) != NQOK || x < 0) return 0;
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

/* A hex field decoded into a fresh buffer (never NULL on success, even
 * when empty); NULL when missing or malformed. */
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

/* ---- one ACVP test ---- */

typedef struct {
  long run, pass;
} cnt;

/* 1 on a match. pr: the group's predResistance. */
static int one(nqhalg alg, int pr, uint64_t bits, const nqjs *t,
               const nqjs *e) {
  uint8_t *ent, *non, *ps, *exp, *out = NULL;
  size_t el = 0, nl = 0, pl = 0, xl = 0, i, ol = (size_t)(bits / 8);
  const nqjs *oi = nqjget(t, "otherInput");
  nqdrbg d;
  int ok = 0, rc;
  memset(&d, 0, sizeof d);
  ent = unhexa(nqjget(t, "entropyInput"), &el);
  non = unhexa(nqjget(t, "nonce"), &nl);
  ps = unhexa(nqjget(t, "persoString"), &pl);
  exp = unhexa(nqjget(e, "returnedBits"), &xl);
  if (ent == NULL || non == NULL || ps == NULL || exp == NULL ||
      oi == NULL || oi->type != NQJARR || bits % 8 != 0 || xl != ol) {
    goto done;
  }
  out = (uint8_t *)calloc(ol + 1, 1);
  if (out == NULL) goto done;
  rc = nqdini(&d, alg, ent, el, non, nl, pl ? ps : NULL, pl, pr);
  if (rc != NQOK) goto done;
  for (i = 0; i < oi->n; i++) {
    const nqjs *o = nqjat(oi, i);
    const char *use = nqjstr(nqjget(o, "intendedUse"));
    size_t al = 0, il = 0;
    uint8_t *add = unhexa(nqjget(o, "additionalInput"), &al);
    uint8_t *ei = unhexa(nqjget(o, "entropyInput"), &il);
    rc = NQEDEC;
    if (use != NULL && add != NULL && ei != NULL) {
      const uint8_t *ap = al ? add : NULL;
      if (strcmp(use, "reSeed") == 0) {
        rc = nqdres(&d, ei, il, ap, al);
      } else if (strcmp(use, "generate") == 0 && pr) {
        rc = nqdgenp(&d, out, ol, ap, al, ei, il);
      } else if (strcmp(use, "generate") == 0 && il == 0) {
        rc = nqdgen(&d, out, ol, ap, al);
      }
    }
    free(add);
    free(ei);
    if (rc != NQOK) goto done;
  }
  ok = memcmp(out, exp, ol) == 0;
done:
  nqdfree(&d);
  free(ent);
  free(non);
  free(ps);
  free(exp);
  free(out);
  return ok;
}

/* ---- the ACVP set ---- */

#define NMODE 16

static void acvp(void) {
  nqjs *p = ldjs("prompt.json"), *x = ldjs("expectedResults.json");
  const nqjs *pg, *eg;
  const char *mname[NMODE] = {NULL};
  long mskip[NMODE] = {0};
  size_t nm = 0, i, j, k;
  cnt c[2][2]; /* [SHA-512][predResistance] */
  memset(c, 0, sizeof c);
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) goto out;
  pg = groups(p);
  eg = groups(x);
  NQTCHK(pg != NULL && eg != NULL);
  for (i = 0; pg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const char *mode = nqjstr(nqjget(g, "mode"));
    const char *tt = nqjstr(nqjget(g, "testType"));
    int pr = nqjbool(nqjget(g, "predResistance"));
    int df = nqjbool(nqjget(g, "derFunc"));
    uint64_t tg = 0, bits = 0, tc = 0;
    nqhalg alg;
    if (mode == NULL || ts == NULL || pr < 0 || !getf(g, "tgId", &tg) ||
        !getf(g, "returnedBitsLen", &bits)) {
      NQTCHK(0);
      continue;
    }
    if (strcmp(mode, "SHA2-256") == 0) {
      alg = NQS256;
    } else if (strcmp(mode, "SHA2-512") == 0) {
      alg = NQS512;
    } else {
      for (k = 0; k < nm && strcmp(mname[k], mode) != 0; k++) {
      }
      if (k == nm && nm < NMODE) {
        mname[nm] = mode;
        mskip[nm++] = 0;
      }
      if (k < NMODE) mskip[k] += (long)ts->n;
      continue;
    }
    NQTCHK(tt != NULL && strcmp(tt, "AFT") == 0);
    NQTCHK(df != 1);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      cnt *cc = &c[alg == NQS512][pr];
      int ok = 0;
      if (getf(t, "tcId", &tc)) {
        ok = one(alg, pr, bits, t, findexp(eg, tg, tc));
      }
      cc->run++;
      cc->pass += ok;
      NQTCHK(ok);
      if (!ok && nmiss++ < 20) {
        fprintf(stderr, DIR ": %s failed (tgId %llu, tcId %llu)\n", mode,
                (unsigned long long)tg, (unsigned long long)tc);
      }
    }
  }
  for (i = 0; i < 2; i++) {
    for (j = 0; j < 2; j++) {
      printf(DIR " %s predResistance=%s reSeed: run %ld, passed %ld\n",
             i ? "SHA2-512" : "SHA2-256", j ? "true " : "false", c[i][j].run,
             c[i][j].pass);
      NQTCHK(c[i][j].run > 0);
    }
  }
  for (k = 0; k < nm; k++) {
    printf(DIR " %s: skipped %ld (hash not provided)\n", mname[k],
           mskip[k]);
  }
out:
  nqjfree(p);
  nqjfree(x);
}

/* ---- unit checks ---- */

static uint8_t ent[48], non[16], ps[32], add[32], buf[256], ref[256];

static void fill(void) {
  size_t i;
  for (i = 0; i < sizeof ent; i++) ent[i] = (uint8_t)(i * 7 + 1);
  for (i = 0; i < sizeof non; i++) non[i] = (uint8_t)(i * 13 + 2);
  for (i = 0; i < sizeof ps; i++) ps[i] = (uint8_t)(i * 3 + 5);
  for (i = 0; i < sizeof add; i++) add[i] = (uint8_t)(i * 11 + 9);
}

static int allzero(const void *p, size_t n) {
  const uint8_t *b = (const uint8_t *)p;
  size_t i;
  uint8_t a = 0;
  for (i = 0; i < n; i++) a = (uint8_t)(a | b[i]);
  return a == 0;
}

static int mk(nqdrbg *d, nqhalg alg, int pr) {
  return nqdini(d, alg, ent, sizeof ent, non, sizeof non, ps, sizeof ps,
                pr);
}

static void tcounter(nqhalg alg) {
  nqdrbg d;
  memset(&d, 0, sizeof d);
  NQTEQI(mk(&d, alg, 0), NQOK);
  NQTCHK(d.rc == 1);
  NQTEQI(nqdgen(&d, buf, 10, NULL, 0), NQOK);
  NQTCHK(d.rc == 2);
  /* the last request the interval allows */
  d.rc = NQDMAXR;
  NQTEQI(nqdgen(&d, buf, 16, add, sizeof add), NQOK);
  NQTCHK(d.rc == NQDMAXR + 1);
  memset(buf, 0xa5, sizeof buf);
  NQTEQI(nqdgen(&d, buf, 16, NULL, 0), NQESTATE);
  NQTCHK(allzero(buf, 16));
  NQTCHK(d.rc == NQDMAXR + 1);
  NQTEQI(nqdgen(&d, buf, 16, add, sizeof add), NQESTATE);
  NQTEQI(nqdres(&d, ent, 32, NULL, 0), NQOK);
  NQTCHK(d.rc == 1);
  NQTEQI(nqdgen(&d, buf, 16, NULL, 0), NQOK);
  NQTCHK(d.rc == 2);
  /* nqdgenp reseeds, so the counter cannot stop it */
  NQTEQI(mk(&d, alg, 1), NQOK);
  d.rc = NQDMAXR + 1;
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, ent, 32), NQOK);
  NQTCHK(d.rc == 2);
  /* a self-seeded DRBG reseeds itself from nqrand */
  NQTEQI(nqdseed(&d, alg, NULL, 0, 0), NQOK);
  d.rc = NQDMAXR;
  NQTEQI(nqdgen(&d, buf, 16, NULL, 0), NQOK);
  NQTCHK(d.rc == NQDMAXR + 1);
  NQTEQI(nqdgen(&d, buf, 16, add, sizeof add), NQOK);
  NQTCHK(d.rc == 2);
  nqdfree(&d);
}

static void twipe(nqhalg alg) {
  nqdrbg d;
  memset(&d, 0, sizeof d);
  NQTEQI(mk(&d, alg, 1), NQOK);
  NQTEQI(nqdgen(&d, buf, 64, NULL, 0), NQOK);
  NQTCHK(!allzero(d.k, d.n) && !allzero(d.v, d.n));
  nqdfree(&d);
  NQTCHK(allzero(&d, sizeof d));
  NQTEQI(nqdgen(&d, buf, 16, NULL, 0), NQESTATE);
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, ent, 32), NQESTATE);
  NQTEQI(nqdres(&d, ent, 32, NULL, 0), NQESTATE);
  nqdfree(NULL);
  /* a failed instantiate leaves nothing of the old state */
  NQTEQI(mk(&d, alg, 0), NQOK);
  NQTEQI(nqdini(&d, alg, ent, 31, non, sizeof non, NULL, 0, 0), NQEARG);
  NQTCHK(allzero(&d, sizeof d));
  NQTEQI(nqdgen(&d, buf, 16, NULL, 0), NQESTATE);
  NQTEQI(mk(&d, alg, 0), NQOK);
  NQTEQI(nqdseed(&d, NQS3256, NULL, 0, 0), NQENOSUP);
  NQTCHK(allzero(&d, sizeof d));
}

/* Same inputs give the same bytes; nqdgenp is nqdres then nqdgen. */
static void tsame(nqhalg alg) {
  nqdrbg a, b;
  memset(&a, 0, sizeof a);
  memset(&b, 0, sizeof b);
  NQTEQI(mk(&a, alg, 1), NQOK);
  NQTEQI(mk(&b, alg, 1), NQOK);
  NQTEQI(nqdgen(&a, buf, 100, add, sizeof add), NQOK);
  NQTEQI(nqdgen(&b, ref, 100, add, sizeof add), NQOK);
  NQTEQM(buf, ref, 100);
  NQTEQI(nqdgenp(&a, buf, 77, add, 5, ent, 40), NQOK);
  NQTEQI(nqdres(&b, ent, 40, add, 5), NQOK);
  NQTEQI(nqdgen(&b, ref, 77, NULL, 0), NQOK);
  NQTEQM(buf, ref, 77);
  NQTEQM(a.k, b.k, a.n);
  NQTEQM(a.v, b.v, a.n);
  /* a request of 0 bytes still advances the state */
  NQTEQI(nqdgen(&a, NULL, 0, NULL, 0), NQOK);
  NQTCHK(memcmp(a.v, b.v, a.n) != 0);
  /* personalization and additional input change the output */
  NQTEQI(nqdini(&a, alg, ent, sizeof ent, non, sizeof non, NULL, 0, 0),
         NQOK);
  NQTEQI(mk(&b, alg, 0), NQOK);
  NQTEQI(nqdgen(&a, buf, 32, NULL, 0), NQOK);
  NQTEQI(nqdgen(&b, ref, 32, NULL, 0), NQOK);
  NQTCHK(memcmp(buf, ref, 32) != 0);
  NQTEQI(nqdgen(&a, buf, 32, add, 1), NQOK);
  NQTEQI(nqdgen(&a, ref, 32, NULL, 0), NQOK);
  NQTCHK(memcmp(buf, ref, 32) != 0);
  /* two self-seeded DRBGs differ; with pr each request reseeds */
  NQTEQI(nqdseed(&a, alg, ps, sizeof ps, 1), NQOK);
  NQTEQI(nqdseed(&b, alg, NULL, 0, 0), NQOK);
  NQTCHK(a.own == 1 && a.pr == 1 && b.own == 1 && b.pr == 0);
  NQTEQI(nqdgen(&a, buf, 64, add, sizeof add), NQOK);
  NQTCHK(a.rc == 2);
  NQTEQI(nqdgen(&a, buf + 64, 64, NULL, 0), NQOK);
  NQTCHK(a.rc == 2);
  NQTEQI(nqdgen(&b, ref, 64, NULL, 0), NQOK);
  NQTCHK(b.rc == 2);
  NQTCHK(memcmp(buf, ref, 64) != 0 && memcmp(buf, buf + 64, 64) != 0);
  nqdfree(&a);
  nqdfree(&b);
}

static void terr(void) {
  static uint8_t big[NQDMAXB + 1];
  nqdrbg d;
  const nqhalg bad[] = {NQS224, NQS384, NQS512T224, NQS512T256,
                        NQS3224, NQS3256, NQS3384, NQS3512};
  size_t i;
  memset(&d, 0, sizeof d);
  /* nqdini */
  NQTEQI(nqdini(NULL, NQS256, ent, 32, non, 16, NULL, 0, 0), NQEARG);
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    NQTEQI(nqdini(&d, bad[i], ent, 32, non, 16, NULL, 0, 0), NQENOSUP);
    NQTEQI(nqdseed(&d, bad[i], NULL, 0, 0), NQENOSUP);
  }
  NQTEQI(nqdini(&d, NQSHK128, ent, 32, non, 16, NULL, 0, 0), NQENOSUP);
  NQTEQI(nqdini(&d, (nqhalg)0, ent, 32, non, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, (nqhalg)99, ent, 32, non, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdseed(&d, (nqhalg)99, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, NULL, 32, non, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, ent, 31, non, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, ent, 0, non, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, ent, 32, NULL, 16, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, ent, 32, non, 15, NULL, 0, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS512, ent, 32, non, 16, NULL, 1, 0), NQEARG);
  NQTEQI(nqdseed(NULL, NQS256, NULL, 0, 0), NQEARG);
  NQTEQI(nqdseed(&d, NQS256, NULL, 1, 0), NQEARG);
  NQTEQI(nqdini(&d, NQS256, ent, 32, non, 16, NULL, 0, 0), NQOK);
  NQTEQI(nqdini(&d, NQS256, ent, 32, non, 16, ps, 0, 0), NQOK);
  /* nqdres */
  NQTEQI(nqdres(NULL, ent, 32, NULL, 0), NQEARG);
  NQTEQI(nqdres(&d, NULL, 32, NULL, 0), NQEARG);
  NQTEQI(nqdres(&d, ent, 31, NULL, 0), NQEARG);
  NQTEQI(nqdres(&d, ent, 32, NULL, 1), NQEARG);
  NQTEQI(nqdres(&d, ent, 32, add, 0), NQOK);
  /* nqdgen */
  NQTEQI(nqdgen(NULL, buf, 16, NULL, 0), NQEARG);
  NQTEQI(nqdgen(&d, NULL, 16, NULL, 0), NQEARG);
  NQTEQI(nqdgen(&d, buf, 16, NULL, 1), NQEARG);
  NQTEQI(nqdgen(&d, big, NQDMAXB + 1, NULL, 0), NQELIM);
  NQTEQI(nqdgen(&d, big, NQDMAXB, NULL, 0), NQOK);
  /* nqdgenp */
  NQTEQI(nqdgenp(NULL, buf, 16, NULL, 0, ent, 32), NQEARG);
  NQTEQI(nqdgenp(&d, NULL, 16, NULL, 0, ent, 32), NQEARG);
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 1, ent, 32), NQEARG);
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, NULL, 32), NQEARG);
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, ent, 31), NQEARG);
  NQTEQI(nqdgenp(&d, big, NQDMAXB + 1, NULL, 0, ent, 32), NQELIM);
  memset(buf, 0xa5, 16);
  NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, ent, 32), NQESTATE); /* pr off */
  NQTCHK(allzero(buf, 16));
  /* inputs longer than 2^35 bits; checked before anything is read */
  if ((uint64_t)SIZE_MAX > NQDMAXL) {
    size_t l = (size_t)(NQDMAXL + 1);
    NQTEQI(nqdres(&d, ent, l, NULL, 0), NQELIM);
    NQTEQI(nqdres(&d, ent, 32, add, l), NQELIM);
    NQTEQI(nqdgen(&d, buf, 16, add, l), NQELIM);
    NQTEQI(nqdgenp(&d, buf, 16, add, l, ent, 32), NQELIM);
    NQTEQI(nqdgenp(&d, buf, 16, NULL, 0, ent, l), NQELIM);
    NQTEQI(nqdseed(&d, NQS256, ps, l, 0), NQELIM);
    NQTEQI(nqdini(&d, NQS256, ent, l, non, 16, NULL, 0, 0), NQELIM);
    NQTEQI(nqdini(&d, NQS256, ent, 32, non, l, NULL, 0, 0), NQELIM);
    NQTEQI(nqdini(&d, NQS256, ent, 32, non, 16, ps, l, 0), NQELIM);
    nqdfree(&d);
  }
  nqdfree(&d);
}

int main(void) {
  fill();
  acvp();
  tcounter(NQS256);
  tcounter(NQS512);
  twipe(NQS256);
  twipe(NQS512);
  tsame(NQS256);
  tsame(NQS512);
  terr();
  return nqtdone("tdrbg");
}
