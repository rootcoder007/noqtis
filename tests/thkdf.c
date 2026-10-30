/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HKDF tests: the SHA-256 cases of RFC 5869 appendix A (the SHA-1 ones
 * do not apply: noqtis has no SHA-1 HMAC), every Wycheproof HKDF-SHA-256,
 * -SHA-384 and -SHA-512 test, and the API's errors. */
#include "hash/h.h"
#include "nqt.h"
#include "tvec.h"

static void rfc(void) {
  static const struct {
    const char *ikm, *salt, *info, *prk, *okm;
  } c[3] = {
      {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
       "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
       "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
       "34007208d5b887185865"},
      {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
       "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
       "404142434445464748494a4b4c4d4e4f",
       "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
       "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
       "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
       "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
       "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
       "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
       "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
       "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
       "cc30c58179ec3e87c14c01d5c1f3434f1d87"},
      {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
       "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
       "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
       "9d201395faa4b61a96c8"}};
  uint8_t ikm[80], salt[80], info[80], prk[32], okm[82], e[82], p[32];
  size_t i;
  for (i = 0; i < 3; i++) {
    size_t il = tvlit(c[i].ikm, ikm, 80), sl = tvlit(c[i].salt, salt, 80),
           fl = tvlit(c[i].info, info, 80), ol = tvlit(c[i].okm, e, 82);
    tvlit(c[i].prk, p, 32);
    NQTEQI(nqhkx(NQS256, sl ? salt : NULL, sl, ikm, il, prk), NQOK);
    NQTEQM(prk, p, 32);
    NQTEQI(nqhke(NQS256, prk, 32, fl ? info : NULL, fl, okm, ol), NQOK);
    NQTEQM(okm, e, ol);
  }
  NQTEQI(nqhke(NQS256, prk, 32, NULL, 0, okm, 255 * 32 + 1), NQEARG);
  NQTEQI(nqhke(NQSHK128, prk, 32, NULL, 0, okm, 16), NQENOSUP);
  NQTEQI(nqhkx(NQSHK128, NULL, 0, ikm, 1, prk), NQENOSUP);
  NQTEQI(nqhkx(NQS256, NULL, 1, ikm, 1, prk), NQEARG);
  NQTEQI(nqhke(NQS256, NULL, 32, NULL, 0, okm, 16), NQEARG);
}

static long wfile(const char *f, nqhalg h) {
  char path[256];
  nqjs *v;
  const nqjs *gs;
  size_t gi, ti;
  long run = 0;
  snprintf(path, sizeof path, "vectors/wycheproof/%s", f);
  v = tvjs(path);
  NQTCHK(v != NULL);
  if (v == NULL) return 0;
  gs = nqjget(v, "testGroups");
  for (gi = 0; gs != NULL && gi < gs->n; gi++) {
    const nqjs *ts = nqjget(nqjat(gs, gi), "tests");
    for (ti = 0; ts != NULL && ti < ts->n; ti++) {
      const nqjs *t = nqjat(ts, ti);
      const char *res = nqjstr(nqjget(t, "result"));
      size_t il, sl, fl, ol;
      int64_t sz = -1;
      uint8_t *ikm = tvhex(nqjget(t, "ikm"), &il),
              *salt = tvhex(nqjget(t, "salt"), &sl),
              *info = tvhex(nqjget(t, "info"), &fl),
              *okm = tvhex(nqjget(t, "okm"), &ol), prk[NQHMAX], *o = NULL;
      int rc, valid = res != NULL && strcmp(res, "valid") == 0;
      NQTCHK(ikm != NULL && salt != NULL && info != NULL && okm != NULL &&
             nqjint(nqjget(t, "size"), &sz) == NQOK && sz >= 0);
      if (ikm == NULL || salt == NULL || info == NULL || okm == NULL ||
          sz < 0) {
        goto next;
      }
      run++;
      o = (uint8_t *)malloc((size_t)sz + 1);
      if (o == NULL) goto next;
      rc = nqhkx(h, salt, sl, ikm, il, prk);
      if (rc == NQOK) rc = nqhke(h, prk, nqhlen(h), info, fl, o, (size_t)sz);
      if (valid) {
        NQTEQI(rc, NQOK);
        NQTCHK(ol == (size_t)sz && memcmp(o, okm, ol) == 0);
      } else {
        NQTCHK(rc != NQOK);
      }
    next:
      free(ikm);
      free(salt);
      free(info);
      free(okm);
      free(o);
    }
  }
  nqjfree(v);
  return run;
}

int main(void) {
  long n;
  rfc();
  n = wfile("hkdf_sha256_test.json", NQS256);
  n += wfile("hkdf_sha384_test.json", NQS384);
  n += wfile("hkdf_sha512_test.json", NQS512);
  printf("wycheproof HKDF: %ld tests\n", n);
  NQTCHK(n >= 250);
  return nqtdone("thkdf");
}
