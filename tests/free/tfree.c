/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The freestanding library (-DNQFREE=ON): no random source until one is
 * set, then the self-test, a hedged ML-DSA signature and an ML-KEM round
 * trip with the caller's source. The source here is a test generator
 * (SHAKE256 of a counter); a device would give its hardware one. */
#include <stdio.h>
#include <string.h>

#include "noqtis.h"

static unsigned long calls = 0;

static int src(uint8_t *buf, size_t len, void *user) {
  uint8_t seed[16];
  unsigned long c = ++calls;
  (void)user;
  memset(seed, 0, sizeof seed);
  memcpy(seed, &c, sizeof c);
  return nqhash(NQSHK256, seed, sizeof seed, buf, len) == NQOK ? 0 : 1;
}

int main(void) {
  static uint8_t pk[2000], sk[3000], sig[3000], ct[1600], ss[32], ss2[32];
  uint8_t b[8];
  size_t n = 0;
  int bad = 0;
  bad |= nqrand(b, sizeof b) != NQERNG;          /* no source yet */
  bad |= nqsetrng(src, NULL) != NQOK;
  bad |= nqrand(b, sizeof b) != NQOK;
  bad |= nqselftest() != NQOK;
  bad |= nqskg(NQMLDSA44, pk, 1312, sk, 2560) != NQOK;
  bad |= nqsign(NQMLDSA44, sk, 2560, (const uint8_t *)"m", 1, NULL, 0, 0,
                sig, sizeof sig, &n) != NQOK;
  bad |= nqvrfy(NQMLDSA44, pk, 1312, (const uint8_t *)"m", 1, NULL, 0, 0,
                sig, n) != NQOK;
  bad |= nqkkg(NQMLKEM768, pk, 1184, sk, 2400) != NQOK;
  bad |= nqenc(NQMLKEM768, pk, 1184, ct, 1088, ss, 32) != NQOK;
  bad |= nqdec(NQMLKEM768, sk, 2400, ct, 1088, ss2, 32) != NQOK;
  bad |= memcmp(ss, ss2, 32) != 0;
  bad |= calls == 0;
  printf("tfree: %s (%lu draws from the caller's source)\n",
         bad ? "FAIL" : "ok", calls);
  return bad;
}
