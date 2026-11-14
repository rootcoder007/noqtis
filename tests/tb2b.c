/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* BLAKE2b tests: RFC 7693's BLAKE2b-512("abc") (appendix A) and its
 * self-test over keyed and unkeyed hashes of every listed length
 * (appendix E), keyed known answers of every message length 0 to 255,
 * every output length 1 to 64 with keys of 0, 1, 32 and 64 bytes
 * (vectors/b2b/), incremental input in pieces of every size, and the
 * errors of nqb2b. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "hash/h.h"
#include "nqt.h"
#include "tkv.h"

static tkv kv;

/* appendix E's Fibonacci sequence */
static void seq(uint8_t *out, size_t len, uint32_t seed) {
  uint32_t a = 0xDEAD4BADu * seed, b = 1, t;
  size_t i;
  for (i = 0; i < len; i++) {
    t = a + b;
    a = b;
    b = t;
    out[i] = (uint8_t)(t >> 24);
  }
}

static void trfc(void) {
  static const size_t md[4] = {20, 32, 48, 64};
  static const size_t il[6] = {0, 3, 128, 129, 255, 1024};
  uint8_t want[64], got[64], in[1024], key[64];
  nqb2ctx c;
  size_t i, j;
  int seen = 0;
  NQTCHK(tkvopen(&kv, "b2b/rfc7693.txt"));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    if (tkvs(&kv, "abc") != NULL) {
      NQTEQI(tkvh(&kv, "abc", want, sizeof want), 64);
      NQTEQI(nqb2b(NULL, 0, (const uint8_t *)"abc", 3, got, 64), NQOK);
      NQTEQM(got, want, 64);
      seen++;
    }
    if (tkvs(&kv, "selftest") != NULL) {
      NQTEQI(tkvh(&kv, "selftest", want, sizeof want), 32);
      NQTEQI(nqb2ini(&c, 32, NULL, 0), NQOK);
      for (i = 0; i < 4; i++) {
        for (j = 0; j < 6; j++) {
          seq(in, il[j], (uint32_t)il[j]);
          NQTEQI(nqb2b(NULL, 0, in, il[j], got, md[i]), NQOK);
          nqb2upd(&c, got, md[i]);
          seq(key, md[i], (uint32_t)md[i]);
          NQTEQI(nqb2b(key, md[i], in, il[j], got, md[i]), NQOK);
          nqb2upd(&c, got, md[i]);
        }
      }
      nqb2fin(&c, got);
      NQTEQM(got, want, 32);
      seen++;
    }
  }
  tkvclose(&kv);
  NQTEQI(seen, 2);
}

static void tkat(void) {
  static uint8_t in[512], key[64], want[64], got[64];
  long n = 0, ok = 0;
  NQTCHK(tkvopen(&kv, "b2b/kat.txt"));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    size_t il = tkvh(&kv, "in", in, sizeof in);
    size_t kl = tkvh(&kv, "key", key, sizeof key);
    size_t ol = tkvh(&kv, "hash", want, sizeof want);
    n++;
    if (il == (size_t)-1 || kl == (size_t)-1 || ol == (size_t)-1) {
      NQTCHK(0);
      continue;
    }
    memset(got, 0, sizeof got);
    if (nqb2b(kl > 0 ? key : NULL, kl, in, il, got, ol) == NQOK &&
        memcmp(got, want, ol) == 0) {
      ok++;
    } else {
      fprintf(stderr, "b2b kat: in %lu key %lu out %lu differs\n",
              (unsigned long)il, (unsigned long)kl, (unsigned long)ol);
    }
  }
  tkvclose(&kv);
  printf("BLAKE2b known answers: %ld run, %ld passed\n", n, ok);
  NQTCHK(n >= 256 + 256);
  NQTEQI(ok, n);
}

/* pieces of every size give the one-call digest */
static void tparts(void) {
  uint8_t in[300], key[64], one[64], got[64];
  size_t step, i;
  nqb2ctx c;
  for (i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 7 + 1);
  for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)i;
  NQTEQI(nqb2b(key, 64, in, sizeof in, one, 64), NQOK);
  for (step = 1; step <= 260; step++) {
    size_t at = 0;
    NQTEQI(nqb2ini(&c, 64, key, 64), NQOK);
    while (at < sizeof in) {
      size_t k = sizeof in - at < step ? sizeof in - at : step;
      nqb2upd(&c, in + at, k);
      nqb2upd(&c, in + at, 0);
      at += k;
    }
    nqb2fin(&c, got);
    NQTEQM(got, one, 64);
  }
}

static void terr(void) {
  uint8_t out[65], key[65];
  memset(key, 1, sizeof key);
  NQTEQI(nqb2b(NULL, 0, NULL, 0, out, 0), NQEARG);
  NQTEQI(nqb2b(NULL, 0, NULL, 0, out, 65), NQEARG);
  NQTEQI(nqb2b(key, 65, NULL, 0, out, 64), NQEARG);
  NQTEQI(nqb2b(NULL, 1, NULL, 0, out, 64), NQEARG);
  NQTEQI(nqb2b(NULL, 0, NULL, 1, out, 64), NQEARG);
  NQTEQI(nqb2b(NULL, 0, NULL, 0, NULL, 64), NQEARG);
  NQTEQI(nqb2b(NULL, 0, NULL, 0, out, 1), NQOK);
  NQTEQI(nqb2b(key, 64, NULL, 0, out, 64), NQOK);
}

int main(void) {
  trfc();
  tkat();
  tparts();
  terr();
  return nqtdone("tb2b");
}
