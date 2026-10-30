/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* core tests: errors, wiping, constant-time helpers, randomness, allocator. */
#include "noqtis.h"
#include "core/int.h"
#include "nqt.h"

#include <stdlib.h>

static size_t nmal = 0, nfree = 0;

static void *cntmal(size_t size, void *user) {
  (void)user;
  nmal++;
  return malloc(size);
}

static void cntfree(void *p, size_t size, void *user) {
  (void)user;
  (void)size;
  nfree++;
  free(p);
}

static void terr(void) {
  NQTCHK(strcmp(nqerr(NQOK), "success") == 0);
  NQTCHK(strcmp(nqerr(NQEVRFY), "verification failed") == 0);
  NQTCHK(strcmp(nqerr(12345), "unknown error") == 0);
  NQTCHK(strcmp(nqver(), "0.1.1") == 0);
}

static void twipe(void) {
  unsigned char b[64];
  size_t i;
  int all = 1;
  memset(b, 0xa5, sizeof b);
  nqwipe(b, sizeof b);
  for (i = 0; i < sizeof b; i++) {
    all &= (b[i] == 0);
  }
  NQTCHK(all);
  b[0] = 1;
  nqwipe(b, 0); /* nothing to wipe */
  NQTCHK(b[0] == 1);
  nqwipe(NULL, 10); /* must not crash */
}

static void tct(void) {
  unsigned char a[32], b[32], c[4] = {1, 2, 3, 4}, d[4] = {9, 9, 9, 9};
  size_t i;
  for (i = 0; i < 32; i++) {
    a[i] = b[i] = (unsigned char)i;
  }
  NQTEQI(nqcteq(a, b, 32), 1);
  NQTEQI(nqcteq(a, b, 0), 1);
  for (i = 0; i < 32; i++) {
    b[i] ^= 0x80;
    NQTEQI(nqcteq(a, b, 32), 0);
    b[i] ^= 0x80;
  }
  NQTCHK(nqctmask(0) == 0u);
  NQTCHK(nqctmask(1) == 0xffffffffu);
  NQTCHK(nqctmask(0x80000000u) == 0xffffffffu);
  NQTCHK(nqctsel(0xffffffffu, 7, 9) == 7u);
  NQTCHK(nqctsel(0, 7, 9) == 9u);
  nqcmov(c, d, 4, 0);
  NQTCHK(c[0] == 1 && c[3] == 4);
  nqcmov(c, d, 4, 1);
  NQTCHK(c[0] == 9 && c[3] == 9);
}

static void tend(void) {
  unsigned char b[8];
  nqst64b(b, 0x0102030405060708ull);
  NQTCHK(b[0] == 1 && b[7] == 8);
  NQTCHK(nqld64b(b) == 0x0102030405060708ull);
  nqst64l(b, 0x0102030405060708ull);
  NQTCHK(b[0] == 8 && b[7] == 1);
  NQTCHK(nqld64l(b) == 0x0102030405060708ull);
}

static void trand(void) {
  unsigned char a[64], b[64];
  NQTEQI(nqrand(a, sizeof a), NQOK);
  NQTEQI(nqrand(b, sizeof b), NQOK);
  /* two 512-bit draws are equal with probability 2^-512 */
  NQTCHK(memcmp(a, b, sizeof a) != 0);
  NQTEQI(nqrand(NULL, 0), NQOK);
  NQTEQI(nqrand(NULL, 1), NQEARG);
}

static void tal(void) {
  void *p;
  NQTEQI(nqsetal(cntmal, NULL, NULL), NQEARG);
  NQTEQI(nqsetal(cntmal, cntfree, NULL), NQOK);
  p = nqmal(16);
  NQTCHK(p != NULL);
  nqfree(p, 16);
  NQTCHK(nqmal(0) == NULL);
  NQTCHK(nmal == 1 && nfree == 1);
  NQTEQI(nqsetal(NULL, NULL, NULL), NQOK);
}

int main(void) {
  terr();
  twipe();
  tct();
  tend();
  trand();
  tal();
  return nqtdone("tcore");
}
