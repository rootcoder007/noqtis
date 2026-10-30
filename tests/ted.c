/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Ed25519 (src/ed): the RFC 8032 test vectors of Ed25519, Ed25519ctx and
 * Ed25519ph (key generation, the exact signature, verification, and a
 * changed signature refused), every Wycheproof Ed25519 verification test
 * (vectors/wycheproof/ed25519_test.json), random round trips in all three
 * variants, signing in place, and the argument checks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "ed/ed.h"
#include "nqt.h"

static nqjs *ldjs(const char *path) {
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc = nqreadf(path, (size_t)1 << 26, &buf, &len);
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

/* A hex field into a fresh buffer (at least one byte allocated). */
static uint8_t *unhexa(const nqjs *v, size_t *n) {
  const char *s = nqjstr(v);
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

static void trfc(void) {
  nqjs *v = ldjs("vectors/ed/rfc8032.json");
  const nqjs *ts;
  size_t i, n = 0;
  NQTCHK(v != NULL);
  if (v == NULL) return;
  ts = nqjget(v, "tests");
  for (i = 0; ts != NULL && i < ts->n; i++) {
    const nqjs *t = nqjat(ts, i);
    const char *alg = nqjstr(nqjget(t, "alg"));
    size_t skl, pkl, ml, cl, sl;
    uint8_t *sk = unhexa(nqjget(t, "sk"), &skl);
    uint8_t *pk = unhexa(nqjget(t, "pk"), &pkl);
    uint8_t *m = unhexa(nqjget(t, "msg"), &ml);
    uint8_t *c = unhexa(nqjget(t, "ctx"), &cl);
    uint8_t *s = unhexa(nqjget(t, "sig"), &sl);
    uint8_t p2[32], s2[64];
    int ph = alg != NULL && strcmp(alg, "Ed25519ph") == 0;
    NQTCHK(sk && pk && m && c && s && skl == 32 && pkl == 32 && sl == 64);
    if (sk && pk && m && c && s) {
      NQTEQI(nqedkg(sk, p2), NQOK);
      NQTEQM(p2, pk, 32);
      NQTEQI(nqedsign(sk, m, ml, c, cl, ph, s2), NQOK);
      NQTEQM(s2, s, 64);
      NQTEQI(nqedvrfy(pk, m, ml, c, cl, ph, s), NQOK);
      s2[i % 64] ^= 0x01;
      NQTCHK(nqedvrfy(pk, m, ml, c, cl, ph, s2) != NQOK);
      /* the wrong variant does not verify */
      NQTCHK(nqedvrfy(pk, m, ml, c, cl, !ph, s) != NQOK);
      n++;
    }
    free(sk);
    free(pk);
    free(m);
    free(c);
    free(s);
  }
  NQTEQI((int)n, 10);
  nqjfree(v);
}

static void twyc(void) {
  nqjs *v = ldjs("vectors/wycheproof/ed25519_test.json");
  const nqjs *gs;
  size_t gi, ti, nv = 0, ni = 0;
  NQTCHK(v != NULL);
  if (v == NULL) return;
  gs = nqjget(v, "testGroups");
  for (gi = 0; gs != NULL && gi < gs->n; gi++) {
    const nqjs *g = nqjat(gs, gi), *ts = nqjget(g, "tests");
    size_t pkl;
    uint8_t *pk = unhexa(nqjget(nqjget(g, "publicKey"), "pk"), &pkl);
    NQTCHK(pk != NULL && pkl == 32);
    for (ti = 0; pk != NULL && ts != NULL && ti < ts->n; ti++) {
      const nqjs *t = nqjat(ts, ti);
      const char *res = nqjstr(nqjget(t, "result"));
      size_t ml, sl;
      uint8_t *m = unhexa(nqjget(t, "msg"), &ml);
      uint8_t *s = unhexa(nqjget(t, "sig"), &sl);
      int64_t id = 0;
      int rc = NQEVRFY;
      nqjint(nqjget(t, "tcId"), &id);
      if (m != NULL && s != NULL && sl == 64) {
        rc = nqedvrfy(pk, m, ml, NULL, 0, 0, s);
      }
      if (res != NULL && strcmp(res, "valid") == 0) {
        nv++;
        if (rc != NQOK) fprintf(stderr, "ted: tcId %lld valid, refused\n",
                                (long long)id);
        NQTEQI(rc, NQOK);
      } else {
        ni++;
        if (rc == NQOK) fprintf(stderr, "ted: tcId %lld invalid, accepted\n",
                                (long long)id);
        NQTCHK(rc != NQOK);
      }
      free(m);
      free(s);
    }
    free(pk);
  }
  printf("ted: Wycheproof %zu valid, %zu invalid\n", nv, ni);
  NQTCHK(nv + ni == 210);
  nqjfree(v);
}

static void tround(void) {
  uint8_t sk[32], pk[32], m[300], c[255], s[64];
  size_t i;
  for (i = 0; i < 120; i++) {
    size_t ml = i * 7 % sizeof m, cl = (i % 3 == 1) ? 1 + i % 255 : 0;
    int ph = i % 3 == 2;
    NQTEQI(nqrand(sk, 32), NQOK);
    NQTEQI(nqrand(m, sizeof m), NQOK);
    NQTEQI(nqrand(c, sizeof c), NQOK);
    NQTEQI(nqedkg(sk, pk), NQOK);
    NQTEQI(nqedsign(sk, m, ml, c, cl, ph, s), NQOK);
    NQTEQI(nqedvrfy(pk, m, ml, c, cl, ph, s), NQOK);
    if (ml > 0) {
      m[i % ml] ^= 0x80;
      NQTEQI(nqedvrfy(pk, m, ml, c, cl, ph, s), NQEVRFY);
      m[i % ml] ^= 0x80;
    }
    if (cl > 0) {
      c[0] ^= 1;
      NQTEQI(nqedvrfy(pk, m, ml, c, cl, ph, s), NQEVRFY);
      c[0] ^= 1;
    }
    /* deterministic: the same signature again */
    {
      uint8_t s2[64];
      NQTEQI(nqedsign(sk, m, ml, c, cl, ph, s2), NQOK);
      NQTEQM(s2, s, 64);
    }
  }
}

static void tplace(void) {
  uint8_t sk[32], pk[32], b[100], m[100], s[64];
  NQTEQI(nqrand(sk, 32), NQOK);
  NQTEQI(nqrand(b, sizeof b), NQOK);
  memcpy(m, b, sizeof m);
  NQTEQI(nqedkg(sk, pk), NQOK);
  NQTEQI(nqedsign(sk, m, sizeof m, NULL, 0, 0, s), NQOK);
  /* the signature written over the message it signs */
  NQTEQI(nqedsign(sk, b, sizeof b, NULL, 0, 0, b), NQOK);
  NQTEQM(b, s, 64);
}

static void targs(void) {
  uint8_t sk[32] = {0}, pk[32], s[64] = {0}, c[256] = {0};
  NQTEQI(nqedkg(NULL, pk), NQEARG);
  NQTEQI(nqedsign(sk, NULL, 1, NULL, 0, 0, s), NQEARG);
  NQTEQI(nqedsign(sk, (const uint8_t *)"", 0, c, 256, 0, s), NQEARG);
  NQTEQI(nqedsign(sk, (const uint8_t *)"", 0, NULL, 1, 0, s), NQEARG);
  NQTEQI(nqedkg(sk, pk), NQOK);
  NQTEQI(nqedvrfy(pk, (const uint8_t *)"", 0, c, 256, 0, s), NQEARG);
  /* a public key that is not a point: y = p (not canonical) */
  memset(pk, 0xff, 32);
  pk[0] = 0xed;
  pk[31] = 0x7f;
  NQTEQI(nqedvrfy(pk, (const uint8_t *)"", 0, NULL, 0, 0, s), NQEDEC);
}

int main(void) {
  trfc();
  twyc();
  tround();
  tplace();
  targs();
  return nqtdone("ted");
}
