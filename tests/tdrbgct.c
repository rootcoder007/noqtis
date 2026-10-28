/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of HMAC_DRBG (ctgrind). Built with -DNQCTGRIND and
 * run under valgrind, the entropy, nonce and DRBG state are marked
 * undefined, so memcheck reports any branch or index that depends on
 * them. Without NQCTGRIND it runs plainly and checks that marking changes
 * nothing. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "drbg/drbg.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

static uint8_t ent[48], non[16], ent2[40], add[24], out[300], ref[300];

/* Key and V only: the lengths, flags and counter are public. */
static void hide(nqdrbg *d) {
  SECRET(d->k, sizeof d->k);
  SECRET(d->v, sizeof d->v);
}

/* Runs every operation on secret data; marks only when mark is 1. */
static void run(nqhalg alg, int mark, uint8_t *o) {
  nqdrbg d;
  memset(&d, 0, sizeof d);
  if (mark) {
    SECRET(ent, sizeof ent);
    SECRET(non, sizeof non);
    SECRET(ent2, sizeof ent2);
  }
  NQTEQI(nqdini(&d, alg, ent, sizeof ent, non, sizeof non, add, 7, 1),
         NQOK);
  NQTEQI(nqdgen(&d, o, 100, add, sizeof add), NQOK);
  NQTEQI(nqdres(&d, ent2, sizeof ent2, add, 3), NQOK);
  NQTEQI(nqdgen(&d, o + 100, 67, NULL, 0), NQOK);
  NQTEQI(nqdgenp(&d, o + 167, 133, add, 11, ent2, 32), NQOK);
  nqdfree(&d);
  /* the self-seeded path: nqrand entropy, reseed on every request */
  NQTEQI(nqdseed(&d, alg, NULL, 0, 1), NQOK);
  if (mark) hide(&d);
  NQTEQI(nqdgen(&d, ref, 50, add, sizeof add), NQOK);
  d.rc = NQDMAXR + 1;
  d.pr = 0;
  NQTEQI(nqdgen(&d, ref, 50, NULL, 0), NQOK);
  nqdfree(&d);
  if (mark) {
    PUBLIC(o, 300);
    PUBLIC(ent, sizeof ent);
    PUBLIC(non, sizeof non);
    PUBLIC(ent2, sizeof ent2);
  }
  NQTCHK(d.ok == 0);
}

int main(void) {
  static uint8_t plain[300];
  size_t i;
  for (i = 0; i < sizeof ent; i++) ent[i] = (uint8_t)(i * 5 + 3);
  for (i = 0; i < sizeof non; i++) non[i] = (uint8_t)(i * 9 + 1);
  for (i = 0; i < sizeof ent2; i++) ent2[i] = (uint8_t)(i * 17 + 4);
  for (i = 0; i < sizeof add; i++) add[i] = (uint8_t)i;
  run(NQS256, 0, plain);
  run(NQS256, 1, out);
  NQTEQM(out, plain, sizeof out);
  run(NQS512, 0, plain);
  run(NQS512, 1, out);
  NQTEQM(out, plain, sizeof out);
  return nqtdone("tdrbgct");
}
