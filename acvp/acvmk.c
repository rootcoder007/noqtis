/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for ML-KEM (FIPS 203; ACVP algorithm ML-KEM, revision
 * FIPS203): keyGen, and encapDecap with its four functions
 * (encapsulation, decapsulation, and the encapsulation and
 * decapsulation key checks of FIPS 203 section 7) for ML-KEM-512, 768
 * and 1024. Decapsulation is the library's masked one.
 *
 *   acvmk <request.json> <response.json> [<expected.json>] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "mlkem/mlkem.h"

static int rank(const char *s) {
  if (s == NULL) return 0;
  if (strcmp(s, "ML-KEM-512") == 0) return 2;
  if (strcmp(s, "ML-KEM-768") == 0) return 3;
  if (strcmp(s, "ML-KEM-1024") == 0) return 4;
  return 0;
}

static int keygen(acvw *w, int k, const nqjs *t) {
  uint8_t seed[NQMKSEED], ek[NQMKEKX], dk[NQMKDKX], *d, *z;
  size_t dn = 0, zn = 0;
  int ok = 0;
  d = acvhex(nqjget(t, "d"), &dn);
  z = acvhex(nqjget(t, "z"), &zn);
  if (d != NULL && z != NULL && dn == 32 && zn == 32) {
    memcpy(seed, d, 32);
    memcpy(seed + 32, z, 32);
    ok = nqmkkgd(k, seed, sizeof seed, ek, sizeof ek, dk, sizeof dk) == NQOK;
  }
  if (ok) {
    acvkhex(w, "ek", ek, NQMKEK(k));
    acvkhex(w, "dk", dk, NQMKDK(k));
  }
  nqwipe(seed, sizeof seed);
  nqwipe(dk, sizeof dk);
  free(d);
  free(z);
  return ok;
}

static int encap(acvw *w, int k, const nqjs *t, const nqjs *g) {
  uint8_t ct[NQMKCTX], ss[NQMKSS], *ek, *m;
  size_t en = 0, mn = 0;
  int ok = 0;
  ek = acvhex(acvfld(t, g, "ek"), &en);
  m = acvhex(nqjget(t, "m"), &mn);
  if (ek != NULL && m != NULL &&
      nqmkencd(k, ek, en, m, mn, ct, sizeof ct, ss, sizeof ss) == NQOK) {
    acvkhex(w, "c", ct, NQMKCT(k));
    acvkhex(w, "k", ss, NQMKSS);
    ok = 1;
  }
  nqwipe(ss, sizeof ss);
  free(ek);
  free(m);
  return ok;
}

static int decap(acvw *w, int k, const nqjs *t, const nqjs *g) {
  uint8_t ss[NQMKSS], *dk, *c;
  size_t dn = 0, cn = 0;
  int ok = 0;
  dk = acvhex(acvfld(t, g, "dk"), &dn);
  c = acvhex(nqjget(t, "c"), &cn);
  if (dk != NULL && c != NULL &&
      nqmkdec(k, dk, dn, c, cn, ss, sizeof ss) == NQOK) {
    acvkhex(w, "k", ss, NQMKSS);
    ok = 1;
  }
  nqwipe(ss, sizeof ss);
  if (dk != NULL) nqwipe(dk, dn);
  free(dk);
  free(c);
  return ok;
}

/* the key checks: NQEDEC is a failed check, anything else no answer */
static int keychk(acvw *w, int k, const nqjs *t, const nqjs *g, int isdk) {
  uint8_t *key;
  size_t n = 0;
  int rc = NQEARG;
  key = acvhex(acvfld(t, g, isdk ? "dk" : "ek"), &n);
  if (key != NULL) rc = isdk ? nqmkdkc(k, key, n) : nqmkekc(k, key, n);
  if (rc == NQOK || rc == NQEDEC) acvkbool(w, "testPassed", rc == NQOK);
  if (key != NULL) nqwipe(key, n);
  free(key);
  return rc == NQOK || rc == NQEDEC;
}

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *vs = acvset(pr), *gs = acvgrps(pr);
  const char *mode = acvs(vs, "mode");
  int kg;
  size_t i, j;
  (void)omit;
  if (!acvis(vs, "algorithm", "ML-KEM") || mode == NULL ||
      (strcmp(mode, "keyGen") != 0 && strcmp(mode, "encapDecap") != 0)) {
    fprintf(stderr, "acvmk: not an ML-KEM keyGen or encapDecap request\n");
    return NQENOSUP;
  }
  kg = strcmp(mode, "keyGen") == 0;
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *fn = kg ? "keyGen" : acvs(g, "function");
    int k = rank(acvs(g, "parameterSet")), f;
    uint64_t tg = 0;
    f = fn == NULL                                   ? -1
        : strcmp(fn, "keyGen") == 0                  ? 0
        : strcmp(fn, "encapsulation") == 0           ? 1
        : strcmp(fn, "decapsulation") == 0           ? 2
        : strcmp(fn, "encapsulationKeyCheck") == 0   ? 3
        : strcmp(fn, "decapsulationKeyCheck") == 0   ? 4
                                                     : -1;
    if (!acvu(g, "tgId", &tg) || ts == NULL || k == 0 || f < 0) {
      fprintf(stderr, "acvmk: group %lu: malformed or unknown function\n",
              (unsigned long)i);
      return NQEDEC;
    }
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      int ok;
      if (!acvu(t, "tcId", &tc)) return NQEDEC;
      acvtbeg(w, tc);
      switch (f) {
      case 0:
        ok = keygen(w, k, t);
        break;
      case 1:
        ok = encap(w, k, t, g);
        break;
      case 2:
        ok = decap(w, k, t, g);
        break;
      default:
        ok = keychk(w, k, t, g, f == 4);
        break;
      }
      if (!ok) {
        fprintf(stderr, "acvmk: tgId %llu tcId %llu (%s): cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc, fn);
        return NQEDEC;
      }
      acvtend(w);
    }
    acvgend(w);
  }
  return NQOK;
}

int main(int argc, char **argv) {
  return acvmain(argc, argv, "acvmk", run);
}
