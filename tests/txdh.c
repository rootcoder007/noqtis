/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X25519 tests: the RFC 7748 vectors of sections 5.2 (1 and 1,000
 * iterations; 1,000,000 with NQSLOW=1) and 6.1, every Wycheproof X25519
 * test (an all-zero shared secret must give NQEVRFY), output aliasing
 * and the API's errors. */
#include "xdh/xdh.h"
#include "nqt.h"
#include "tvec.h"

static void rfc(void) {
  static const struct {
    const char *k, *u, *o;
  } v[2] = {
      {"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
       "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
       "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
      {"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
       "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
       "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"}};
  uint8_t k[32], u[32], o[32], e[32], a[32], b[32], pa[32], pb[32];
  const char *slow = getenv("NQSLOW");
  long i, n;
  for (i = 0; i < 2; i++) {
    tvlit(v[i].k, k, 32);
    tvlit(v[i].u, u, 32);
    tvlit(v[i].o, e, 32);
    NQTEQI(nqx25519(o, k, u), NQOK);
    NQTEQM(o, e, 32);
    /* in place, over the scalar and over the point */
    memcpy(o, k, 32);
    NQTEQI(nqx25519(o, o, u), NQOK);
    NQTEQM(o, e, 32);
    memcpy(o, u, 32);
    NQTEQI(nqx25519(o, k, o), NQOK);
    NQTEQM(o, e, 32);
  }
  /* iterated: k, u = X25519(k, u), k */
  memset(k, 0, 32);
  k[0] = 9;
  memcpy(u, k, 32);
  n = slow != NULL && strcmp(slow, "1") == 0 ? 1000000 : 1000;
  for (i = 1; i <= n; i++) {
    NQTEQI(nqx25519(o, k, u), NQOK);
    memcpy(u, k, 32);
    memcpy(k, o, 32);
    if (i == 1) {
      tvlit("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            e, 32);
      NQTEQM(k, e, 32);
    } else if (i == 1000) {
      tvlit("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            e, 32);
      NQTEQM(k, e, 32);
    } else if (i == 1000000) {
      tvlit("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            e, 32);
      NQTEQM(k, e, 32);
    }
  }
  /* 6.1: Diffie-Hellman */
  tvlit("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a,
        32);
  tvlit("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b,
        32);
  NQTEQI(nqx25519b(pa, a), NQOK);
  tvlit("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", e,
        32);
  NQTEQM(pa, e, 32);
  NQTEQI(nqx25519b(pb, b), NQOK);
  tvlit("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", e,
        32);
  NQTEQM(pb, e, 32);
  tvlit("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", e,
        32);
  NQTEQI(nqx25519(o, a, pb), NQOK);
  NQTEQM(o, e, 32);
  NQTEQI(nqx25519(o, b, pa), NQOK);
  NQTEQM(o, e, 32);
  /* a point of small order (0, and 1) gives all zeros and NQEVRFY */
  memset(u, 0, 32);
  NQTEQI(nqx25519(o, a, u), NQEVRFY);
  u[0] = 1;
  NQTEQI(nqx25519(o, a, u), NQEVRFY);
  NQTEQI(nqx25519(NULL, a, u), NQEARG);
  NQTEQI(nqx25519(o, NULL, u), NQEARG);
  NQTEQI(nqx25519(o, a, NULL), NQEARG);
}

static long wfile(void) {
  nqjs *v = tvjs("vectors/wycheproof/x25519_test.json");
  const nqjs *gs;
  size_t gi, ti;
  long run = 0;
  NQTCHK(v != NULL);
  if (v == NULL) return 0;
  gs = nqjget(v, "testGroups");
  for (gi = 0; gs != NULL && gi < gs->n; gi++) {
    const nqjs *ts = nqjget(nqjat(gs, gi), "tests");
    for (ti = 0; ts != NULL && ti < ts->n; ti++) {
      const nqjs *t = nqjat(ts, ti);
      const char *res = nqjstr(nqjget(t, "result"));
      size_t pl, kl, sl, i;
      uint8_t *pu = tvhex(nqjget(t, "public"), &pl),
              *pr = tvhex(nqjget(t, "private"), &kl),
              *sh = tvhex(nqjget(t, "shared"), &sl), o[32], z = 0;
      int rc;
      NQTCHK(pu != NULL && pr != NULL && sh != NULL && res != NULL);
      if (pu == NULL || pr == NULL || sh == NULL || res == NULL ||
          pl != 32 || kl != 32 || sl != 32) {
        NQTCHK(0);
        goto next;
      }
      run++;
      /* every test is valid or acceptable: the value is defined */
      NQTCHK(strcmp(res, "invalid") != 0);
      rc = nqx25519(o, pr, pu);
      for (i = 0; i < 32; i++) z |= sh[i];
      NQTEQI(rc, z == 0 ? NQEVRFY : NQOK);
      NQTEQM(o, sh, 32);
    next:
      free(pu);
      free(pr);
      free(sh);
    }
  }
  nqjfree(v);
  return run;
}

int main(void) {
  long n;
  rfc();
  n = wfile();
  printf("wycheproof X25519: %ld tests\n", n);
  NQTCHK(n >= 500);
  return nqtdone("txdh");
}
