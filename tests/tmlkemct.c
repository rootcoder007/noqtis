/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of ML-KEM (ctgrind). Built with -DNQCTGRIND (the
 * library too) and run under valgrind, the key-generation seed, the
 * encapsulation randomness m and the whole decapsulation key are marked
 * undefined, so memcheck reports any branch or index that depends on
 * them. The library declares public only what FIPS 203 publishes (rho,
 * and the ek and H(ek) inside dk). Decapsulation runs masked and plain,
 * on an honest and on a tampered ciphertext. Without NQCTGRIND it runs
 * plainly and checks that marking changes nothing. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "mlkem/mlkem.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

typedef struct {
  uint8_t ek[NQMKEKX], dk[NQMKDKX], ct[NQMKCTX], ct2[NQMKCTX];
  uint8_t ss[NQMKSS], sm[NQMKSS], sp[NQMKSS], tm[NQMKSS], tp[NQMKSS];
} res;

static void run(int k, int mark, res *r) {
  uint8_t seed[NQMKSEED], m[NQMKMSG];
  size_t i;
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 7 + (size_t)k);
  for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 13 + 5);
  memset(r, 0, sizeof *r);
  if (mark) SECRET(seed, sizeof seed);
  NQTEQI(nqmkkgd(k, seed, sizeof seed, r->ek, NQMKEK(k), r->dk,
                 NQMKDK(k)),
         NQOK);
  if (mark) {
    PUBLIC(r->ek, NQMKEK(k));
    SECRET(m, sizeof m);
  }
  NQTEQI(nqmkencd(k, r->ek, NQMKEK(k), m, sizeof m, r->ct, NQMKCT(k),
                  r->ss, NQMKSS),
         NQOK);
  if (mark) {
    PUBLIC(r->ct, NQMKCT(k));
    SECRET(r->dk, NQMKDK(k));
  }
  memcpy(r->ct2, r->ct, NQMKCT(k));
  r->ct2[NQMKCT(k) / 3] ^= 0x10;
  NQTEQI(nqmkdec(k, r->dk, NQMKDK(k), r->ct, NQMKCT(k), r->sm, NQMKSS),
         NQOK);
  NQTEQI(nqmkdecp(k, r->dk, NQMKDK(k), r->ct, NQMKCT(k), r->sp, NQMKSS),
         NQOK);
  NQTEQI(nqmkdec(k, r->dk, NQMKDK(k), r->ct2, NQMKCT(k), r->tm, NQMKSS),
         NQOK);
  NQTEQI(nqmkdecp(k, r->dk, NQMKDK(k), r->ct2, NQMKCT(k), r->tp,
                  NQMKSS),
         NQOK);
  if (mark) {
    PUBLIC(r->dk, NQMKDK(k));
    PUBLIC(r->ss, NQMKSS);
    PUBLIC(r->sm, NQMKSS);
    PUBLIC(r->sp, NQMKSS);
    PUBLIC(r->tm, NQMKSS);
    PUBLIC(r->tp, NQMKSS);
  }
}

int main(void) {
  static res a, b;
  int k;
  for (k = 2; k <= 4; k++) {
    run(k, 0, &a);
    run(k, 1, &b);
    NQTCHK(memcmp(&a, &b, sizeof a) == 0);
    NQTEQM(b.sm, b.ss, NQMKSS);
    NQTEQM(b.sp, b.ss, NQMKSS);
    NQTEQM(b.tm, b.tp, NQMKSS);
    NQTCHK(memcmp(b.tm, b.ss, NQMKSS) != 0);
  }
  return nqtdone("tmlkemct");
}
