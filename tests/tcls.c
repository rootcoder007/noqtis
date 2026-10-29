/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Classical verification tests: every Wycheproof RSA PKCS#1 v1.5, RSA-PSS
 * and ECDSA P-256 / P-384 file in vectors/wycheproof, the OpenSSL
 * differential set in vectors/ossl/cls.json (when present), corrupted
 * signatures, strict DER and the API's errors. A Wycheproof "acceptable"
 * test may go either way; the counts say which way each went. NQCLSN=n
 * runs at most n tests per file and every eighth OpenSSL test (for
 * valgrind). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "cls/cls.h"
#include "nqt.h"

static const char *const files[] = {
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_2048_sha512_224_test.json",
    "rsa_signature_2048_sha512_256_test.json",
    "rsa_signature_2048_sha3_224_test.json",
    "rsa_signature_2048_sha3_256_test.json",
    "rsa_signature_2048_sha3_384_test.json",
    "rsa_signature_2048_sha3_512_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_3072_sha512_256_test.json",
    "rsa_signature_3072_sha3_256_test.json",
    "rsa_signature_3072_sha3_384_test.json",
    "rsa_signature_3072_sha3_512_test.json",
    "rsa_signature_4096_sha256_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
    "rsa_signature_4096_sha512_256_test.json",
    "rsa_signature_8192_sha256_test.json",
    "rsa_signature_8192_sha384_test.json",
    "rsa_signature_8192_sha512_test.json",
    "rsa_pss_2048_sha1_mgf1_20_test.json",
    "rsa_pss_2048_sha1_mgf1_20_params_test.json",
    "rsa_pss_2048_sha256_mgf1_0_test.json",
    "rsa_pss_2048_sha256_mgf1_0_params_test.json",
    "rsa_pss_2048_sha256_mgf1_32_test.json",
    "rsa_pss_2048_sha256_mgf1_32_params_test.json",
    "rsa_pss_2048_sha256_mgf1sha1_20_test.json",
    "rsa_pss_2048_sha384_mgf1_48_test.json",
    "rsa_pss_2048_sha512_224_mgf1_28_test.json",
    "rsa_pss_2048_sha512_256_mgf1_32_test.json",
    "rsa_pss_2048_sha512_mgf1sha256_32_params_test.json",
    "rsa_pss_2048_shake128_test.json",
    "rsa_pss_2048_shake256_test.json",
    "rsa_pss_3072_sha256_mgf1_32_test.json",
    "rsa_pss_3072_sha256_mgf1_32_params_test.json",
    "rsa_pss_3072_shake128_test.json",
    "rsa_pss_3072_shake256_test.json",
    "rsa_pss_4096_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha384_mgf1_48_test.json",
    "rsa_pss_4096_sha512_mgf1_32_test.json",
    "rsa_pss_4096_sha512_mgf1_32_params_test.json",
    "rsa_pss_4096_sha512_mgf1_64_test.json",
    "rsa_pss_4096_sha512_mgf1_64_params_test.json",
    "rsa_pss_4096_shake256_test.json",
    "rsa_pss_misc_test.json",
    "rsa_pss_misc_params_test.json",
    "ecdsa_secp256r1_sha256_test.json",
    "ecdsa_secp256r1_sha512_test.json",
    "ecdsa_secp256r1_sha3_256_test.json",
    "ecdsa_secp256r1_sha3_512_test.json",
    "ecdsa_secp256r1_shake128_test.json",
    "ecdsa_secp256r1_sha256_p1363_test.json",
    "ecdsa_secp256r1_sha512_p1363_test.json",
    "ecdsa_secp256r1_shake128_p1363_test.json",
    "ecdsa_secp384r1_sha256_test.json",
    "ecdsa_secp384r1_sha384_test.json",
    "ecdsa_secp384r1_sha512_test.json",
    "ecdsa_secp384r1_sha3_384_test.json",
    "ecdsa_secp384r1_sha3_512_test.json",
    "ecdsa_secp384r1_shake256_test.json",
    "ecdsa_secp384r1_sha384_p1363_test.json",
    "ecdsa_secp384r1_sha512_p1363_test.json",
    "ecdsa_secp384r1_shake256_p1363_test.json",
};

enum { VPKCS = 1, VPSS, VECDSA };

typedef struct {
  long run, pass, skip, acca, accr;
} cnt;

static int nmiss = 0;
static long lim = 0; /* NQCLSN=n: at most n tests per file (for valgrind) */

/* ---- helpers ---- */

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

static int hname(const char *s, nqhalg *h) {
  static const struct {
    const char *n;
    nqhalg h;
  } t[] = {{"SHA-224", NQS224},     {"SHA-256", NQS256},
           {"SHA-384", NQS384},     {"SHA-512", NQS512},
           {"SHA-512/224", NQS512T224}, {"SHA-512/256", NQS512T256},
           {"SHA3-224", NQS3224},   {"SHA3-256", NQS3256},
           {"SHA3-384", NQS3384},   {"SHA3-512", NQS3512},
           {"SHAKE128", NQSHK128},  {"SHAKE256", NQSHK256}};
  size_t i;
  for (i = 0; s != NULL && i < sizeof t / sizeof t[0]; i++) {
    if (strcmp(s, t[i].n) == 0) {
      *h = t[i].h;
      return 1;
    }
  }
  return 0;
}

static int vrfy(int kind, const nqck *k, nqhalg h, const nqpss *p,
                int raw, const uint8_t *m, size_t ml, const uint8_t *s,
                size_t sl) {
  if (kind == VPKCS) return nqrsav(k, h, m, ml, s, sl);
  if (kind == VPSS) return nqpssv(k, p, m, ml, s, sl);
  return nqecv(k, h, m, ml, s, sl, raw);
}

/* Every bit of the signature and the first and last bytes of the
 * message, flipped one at a time, must fail. */
static void corrupt(const char *f, int kind, const nqck *k, nqhalg h,
                    const nqpss *p, int raw, const uint8_t *m, size_t ml,
                    const uint8_t *s, size_t sl) {
  uint8_t *ms = (uint8_t *)malloc(ml + 1), *ss = (uint8_t *)malloc(sl + 1);
  size_t i;
  int bad = 0;
  if (ms == NULL || ss == NULL) {
    NQTCHK(0);
    free(ms);
    free(ss);
    return;
  }
  memcpy(ss, s, sl);
  /* every bit of the first 16 bytes (the DER structure), then every
   * seventh bit, which still visits every bit position */
  for (i = 0; i < 8 * sl; i += i < 128 ? 1 : 7) {
    ss[i / 8] ^= (uint8_t)(1u << (i % 8));
    if (vrfy(kind, k, h, p, raw, m, ml, ss, sl) == NQOK) bad++;
    ss[i / 8] ^= (uint8_t)(1u << (i % 8));
  }
  if (ml > 0) {
    memcpy(ms, m, ml);
    ms[0] ^= 0x80;
    if (vrfy(kind, k, h, p, raw, ms, ml, s, sl) == NQOK) bad++;
    ms[0] ^= 0x80;
    ms[ml - 1] ^= 0x01;
    if (vrfy(kind, k, h, p, raw, ms, ml, s, sl) == NQOK) bad++;
  }
  /* truncated and extended */
  if (vrfy(kind, k, h, p, raw, m, ml, s, sl - 1) == NQOK) bad++;
  ss[sl] = 0;
  if (vrfy(kind, k, h, p, raw, m, ml, ss, sl + 1) == NQOK) bad++;
  if (bad != 0) fprintf(stderr, "%s: %d corruptions accepted\n", f, bad);
  NQTEQI(bad, 0);
  free(ms);
  free(ss);
}

/* ---- one Wycheproof file ---- */

static void wfile(const char *f, cnt *c) {
  char path[256];
  nqjs *v;
  const nqjs *gs;
  size_t gi, ti;
  int corr = 0;
  snprintf(path, sizeof path, "vectors/wycheproof/%s", f);
  v = ldjs(path);
  NQTCHK(v != NULL);
  if (v == NULL) return;
  gs = nqjget(v, "testGroups");
  NQTCHK(gs != NULL);
  for (gi = 0; gs != NULL && gi < gs->n; gi++) {
    const nqjs *g = nqjat(gs, gi), *ts = nqjget(g, "tests");
    const char *ty = nqjstr(nqjget(g, "type"));
    nqck k;
    nqpss p;
    nqhalg h = NQS256;
    int kind = 0, raw = 0, rc, use = 1;
    uint8_t *kd;
    size_t kl;
    if (ts == NULL || ty == NULL) {
      NQTCHK(0);
      continue;
    }
    memset(&k, 0, sizeof k);
    memset(&p, 0, sizeof p);
    if (strcmp(ty, "RsassaPkcs1Verify") == 0) {
      kind = VPKCS;
    } else if (strcmp(ty, "RsassaPssVerify") == 0 ||
               strcmp(ty, "RsassaPssWithParametersVerify") == 0) {
      kind = VPSS;
    } else if (strcmp(ty, "EcdsaVerify") == 0) {
      kind = VECDSA;
    } else if (strcmp(ty, "EcdsaP1363Verify") == 0) {
      kind = VECDSA;
      raw = 1;
    }
    NQTCHK(kind != 0);
    if (!hname(nqjstr(nqjget(g, "sha")), &h)) use = 0; /* SHA-1 */
    if (kind == VPSS && use) {
      const char *mg = nqjstr(nqjget(g, "mgf"));
      int64_t sl = -1;
      p.h = h;
      if (mg != NULL && strcmp(mg, "MGF1") == 0) {
        if (!hname(nqjstr(nqjget(g, "mgfSha")), &p.mgf)) use = 0;
      } else if (!hname(mg, &p.mgf)) {
        use = 0;
      }
      if (nqjint(nqjget(g, "sLen"), &sl) != NQOK || sl < 0) {
        NQTCHK(0);
        use = 0;
      }
      p.slen = (size_t)sl;
    }
    kd = unhexa(nqjget(g, "publicKeyDer"), &kl);
    NQTCHK(kd != NULL);
    rc = kd != NULL ? nqckey(&k, kd, kl) : NQEDEC;
    free(kd);
    if (rc == NQENOSUP) use = 0; /* 8192 bits, SHA-1 PSS parameters */
    if (use && rc != NQOK) {
      fprintf(stderr, "%s: group %zu: key rejected (%s)\n", f, gi,
              nqerr(rc));
      NQTEQI(rc, NQOK);
      use = 0;
    }
    /* the bare RSAPublicKey and the compressed point give the same key */
    if (use && kind != VECDSA) {
      nqck k2;
      kd = unhexa(nqjget(g, "publicKeyAsn"), &kl);
      NQTCHK(kd != NULL && nqrsapk(&k2, kd, kl) == NQOK &&
             k2.bits == k.bits && k2.e == k.e &&
             memcmp(k2.n.m, k.n.m, sizeof k.n.m) == 0);
      free(kd);
    }
    if (use && kind == VECDSA) {
      nqck k2;
      uint8_t cp[49];
      size_t nb = k.crv == NQP256 ? 32 : 48;
      cp[0] = (uint8_t)(2 + (k.y[nb - 1] & 1));
      memcpy(cp + 1, k.x, nb);
      NQTCHK(nqecpk(&k2, k.crv, cp, nb + 1) == NQOK &&
             memcmp(k2.y, k.y, nb) == 0);
      cp[0] ^= 1;
      NQTCHK(nqecpk(&k2, k.crv, cp, nb + 1) == NQOK &&
             memcmp(k2.y, k.y, nb) != 0);
    }
    for (ti = 0; ti < ts->n; ti++) {
      const nqjs *t = nqjat(ts, ti);
      const char *res = nqjstr(nqjget(t, "result"));
      uint8_t *m, *s;
      size_t ml, sl;
      int64_t id = 0;
      if (!use || (lim > 0 && c->run >= lim)) {
        c->skip++;
        continue;
      }
      nqjint(nqjget(t, "tcId"), &id);
      m = unhexa(nqjget(t, "msg"), &ml);
      s = unhexa(nqjget(t, "sig"), &sl);
      NQTCHK(m != NULL && s != NULL && res != NULL);
      if (m == NULL || s == NULL || res == NULL) {
        free(m);
        free(s);
        continue;
      }
      c->run++;
      rc = vrfy(kind, &k, h, &p, raw, m, ml, s, sl);
      if (strcmp(res, "acceptable") == 0) {
        c->pass++;
        if (rc == NQOK) {
          c->acca++;
        } else {
          c->accr++;
        }
      } else if ((strcmp(res, "valid") == 0) == (rc == NQOK) &&
                 (rc == NQOK || rc == NQEVRFY)) {
        c->pass++;
      } else {
        NQTCHK(0);
        if (nmiss++ < 30) {
          fprintf(stderr, "%s: tcId %lld (%s): got %s\n", f, (long long)id,
                  res, nqerr(rc));
        }
      }
      if (rc == NQOK && strcmp(res, "valid") == 0 && corr < 1) {
        corrupt(f, kind, &k, h, &p, raw, m, ml, s, sl);
        corr++;
      }
      free(m);
      free(s);
    }
  }
  nqjfree(v);
}

/* ---- the OpenSSL 3.5 differential set ---- */

static void ossl(void) {
  nqjs *v = ldjs("vectors/ossl/cls.json");
  const nqjs *ts;
  size_t i;
  long run = 0, pass = 0, ok = 0;
  if (v == NULL) {
    printf("ossl: vectors/ossl/cls.json missing, skipped\n");
    return;
  }
  ts = nqjget(v, "tests");
  NQTCHK(ts != NULL);
  for (i = 0; ts != NULL && i < ts->n; i++) {
    const nqjs *t = nqjat(ts, i);
    const char *ty = nqjstr(nqjget(t, "type"));
    if (lim > 0 && i % 8 != 0) continue;
    nqck k;
    nqpss p;
    nqhalg h = NQS256;
    uint8_t *kd, *m, *s;
    size_t kl, ml, sl;
    int64_t x = 0;
    int kind = 0, raw = 0, want = nqjbool(nqjget(t, "ok")), rc;
    memset(&p, 0, sizeof p);
    if (ty == NULL) {
      NQTCHK(0);
      continue;
    }
    if (strcmp(ty, "pkcs1") == 0) kind = VPKCS;
    if (strcmp(ty, "pss") == 0) kind = VPSS;
    if (strcmp(ty, "ecdsa") == 0) kind = VECDSA;
    if (strcmp(ty, "p1363") == 0) {
      kind = VECDSA;
      raw = 1;
    }
    NQTCHK(kind != 0 && hname(nqjstr(nqjget(t, "hash")), &h));
    if (kind == VPSS) {
      p.h = h;
      NQTCHK(hname(nqjstr(nqjget(t, "mgf")), &p.mgf));
      NQTCHK(nqjint(nqjget(t, "slen"), &x) == NQOK && x >= 0);
      p.slen = (size_t)x;
    }
    kd = unhexa(nqjget(t, "spki"), &kl);
    m = unhexa(nqjget(t, "msg"), &ml);
    s = unhexa(nqjget(t, "sig"), &sl);
    NQTCHK(kd != NULL && m != NULL && s != NULL && want >= 0);
    if (kd != NULL && m != NULL && s != NULL) {
      run++;
      rc = nqckey(&k, kd, kl);
      if (rc == NQOK) rc = vrfy(kind, &k, h, &p, raw, m, ml, s, sl);
      if ((rc == NQOK) == (want == 1)) {
        pass++;
      } else {
        NQTCHK(0);
        if (nmiss++ < 30) {
          fprintf(stderr, "ossl: test %zu (%s %s) openssl %d, noqtis %s\n",
                  i, ty, nqjstr(nqjget(t, "hash")), want, nqerr(rc));
        }
      }
      ok += rc == NQOK;
    }
    free(kd);
    free(m);
    free(s);
  }
  printf("%-52s run %5ld pass %5ld (%ld verify)\n", "ossl/cls.json", run,
         pass, ok);
  nqjfree(v);
}

/* ---- DER and API ---- */

static void der(void) {
  /* RSASSA-PSS-params: SHA-256, MGF1-SHA-256, salt 32 */
  static const uint8_t pp[] = {
      0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30,
      0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
      0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20};
  static const uint8_t empty[] = {0x30, 0x00};
  /* a P-256 SPKI head: SEQUENCE, AlgorithmIdentifier, BIT STRING */
  static const uint8_t ech[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
                                0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
                                0x01, 0x07, 0x03, 0x42, 0x00, 0x04};
  /* the P-256 generator */
  static const char *gx =
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
  static const char *gy =
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
  uint8_t b[160], d[64];
  nqpss p;
  nqck k;
  size_t n = 0;
  NQTEQI(nqpssp(&p, pp, sizeof pp), NQOK);
  NQTCHK(p.h == NQS256 && p.mgf == NQS256 && p.slen == 32);
  memcpy(b, pp, sizeof pp);
  b[sizeof pp - 1] = 20; /* the default, spelt out */
  NQTEQI(nqpssp(&p, b, sizeof pp), NQEDEC);
  b[sizeof pp - 1] = 32;
  b[sizeof pp] = 0; /* trailing byte */
  NQTEQI(nqpssp(&p, b, sizeof pp + 1), NQEDEC);
  b[1] = 0x81; /* long form for a short length */
  NQTEQI(nqpssp(&p, b, sizeof pp), NQEDEC);
  NQTEQI(nqpssp(&p, empty, sizeof empty), NQENOSUP); /* SHA-1 */
  /* a P-256 key: the generator */
  memcpy(b, ech, sizeof ech);
  nqunhex(gx, 64, b + sizeof ech, 32, &n);
  nqunhex(gy, 64, b + sizeof ech + 32, 32, &n);
  n = sizeof ech + 64;
  NQTEQI(nqckey(&k, b, n), NQOK);
  NQTCHK(k.kind == NQKEC && k.crv == NQP256);
  b[n - 1] ^= 1; /* off the curve */
  NQTEQI(nqckey(&k, b, n), NQEDEC);
  b[n - 1] ^= 1;
  b[n] = 0;
  NQTEQI(nqckey(&k, b, n + 1), NQEDEC); /* trailing */
  b[25] = 1;                             /* unused bits */
  NQTEQI(nqckey(&k, b, n), NQEDEC);
  b[25] = 0;
  b[26] = 0x06; /* hybrid */
  NQTEQI(nqckey(&k, b, n), NQEDEC);
  b[26] = 0x04;
  b[22] = 0x08; /* another curve OID */
  NQTEQI(nqckey(&k, b, n), NQENOSUP);
  b[22] = 0x07;
  /* x = p: not a field element */
  memset(b + sizeof ech, 0xff, 32);
  NQTEQI(nqecpk(&k, NQP256, b + sizeof ech - 1, 65), NQEDEC);
  /* API */
  NQTEQI(nqckey(NULL, b, n), NQEARG);
  NQTEQI(nqckey(&k, NULL, n), NQEARG);
  NQTEQI(nqecpk(&k, 3, b, 65), NQENOSUP);
  NQTEQI(nqecpk(&k, NQP256, empty, 1), NQEDEC);
  memset(d, 0, sizeof d);
  NQTEQI(nqecvh(NULL, d, 32, d, 64, 1), NQEARG);
  NQTEQI(nqrsavh(NULL, NQS256, d, 32, d, 64), NQEARG);
  NQTEQI(nqpssvh(NULL, &p, d, 32, d, 64), NQEARG);
  NQTEQI(nqrsav(NULL, NQS256, d, 32, d, 64), NQEARG);
  NQTEQI(nqecv(NULL, NQS256, d, 32, d, 64, 0), NQEARG);
}

/* Parameters and lengths at their limits, on a real key. */
static void lims(void) {
  nqjs *v = ldjs("vectors/wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json");
  const nqjs *g = nqjat(nqjget(v, "testGroups"), 0);
  uint8_t *kd, d[64], s[512];
  size_t kl;
  nqck k;
  nqpss p;
  NQTCHK(g != NULL);
  if (g == NULL) {
    nqjfree(v);
    return;
  }
  kd = unhexa(nqjget(g, "publicKeyDer"), &kl);
  NQTCHK(kd != NULL && nqckey(&k, kd, kl) == NQOK);
  free(kd);
  memset(d, 0, sizeof d);
  memset(s, 0, sizeof s);
  s[511] = 2;
  p.h = NQS512;
  p.mgf = NQS512;
  p.slen = (size_t)-1;
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 512), NQEVRFY);
  p.slen = 512 - 64 - 2 + 1;
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 512), NQEVRFY);
  p.slen = 0;
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 512), NQEVRFY);
  NQTEQI(nqpssvh(&k, &p, d, 63, s, 512), NQEARG);
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 511), NQEVRFY);
  memset(s, 0xff, sizeof s); /* >= n */
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 512), NQEVRFY);
  p.mgf = NQSHK256; /* SHAKE MGF with a SHA-2 hash */
  NQTEQI(nqpssvh(&k, &p, d, 64, s, 512), NQENOSUP);
  p.h = NQSHK128; /* SHAKE hash with another MGF */
  NQTEQI(nqpssvh(&k, &p, d, 32, s, 512), NQENOSUP);
  NQTEQI(nqrsavh(&k, NQSHK128, d, 32, s, 512), NQENOSUP);
  NQTEQI(nqrsavh(&k, NQS512, d, 32, s, 512), NQEARG);
  NQTEQI(nqecvh(&k, d, 32, s, 64, 1), NQEARG); /* an RSA key */
  nqjfree(v);
}

int main(void) {
  size_t i;
  cnt tot;
  const char *ev = getenv("NQCLSN");
  if (ev != NULL) lim = atol(ev);
  memset(&tot, 0, sizeof tot);
  der();
  lims();
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    cnt c;
    memset(&c, 0, sizeof c);
    wfile(files[i], &c);
    printf("%-52s run %5ld pass %5ld skip %5ld acceptable %ld/%ld\n",
           files[i], c.run, c.pass, c.skip, c.acca, c.accr);
    tot.run += c.run;
    tot.pass += c.pass;
    tot.skip += c.skip;
    tot.acca += c.acca;
    tot.accr += c.accr;
  }
  printf("%-52s run %5ld pass %5ld skip %5ld acceptable %ld/%ld\n",
         "wycheproof total", tot.run, tot.pass, tot.skip, tot.acca,
         tot.accr);
  printf("(acceptable: accepted/rejected)\n");
  ossl();
  return nqtdone("tcls");
}
