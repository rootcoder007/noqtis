/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of HQC (ctgrind): built with -DNQCTGRIND and run
 * under valgrind memcheck, the secrets (key seed, the secret half of the
 * key, m and the salt) are marked undefined, so any branch or address
 * that depends on them is reported as a use of an uninitialised value.
 * The module's sources are compiled into this file so that the three
 * places the specification lets a secret-derived bit become public
 * (NQHQDCL in kem.c) are declassified here, and only here.
 *
 * Without NQCTGRIND it runs the same calls through the library as a
 * plain smoke test. */
#include <stdint.h>
#include <string.h>

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQHQDCL(ptr, len) VALGRIND_MAKE_MEM_DEFINED((ptr), (len))
#include "hqc/mul.c"
#include "hqc/code.c"
#include "hqc/kem.c"
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

#include "noqtis.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"
#include "nqt.h"

static uint8_t pk[NQHQPK5], sk[NQHQSK5], ct[NQHQCT5];

int main(void) {
  static const nqkalg algs[3] = {NQHQC128, NQHQC192, NQHQC256};
  int i, j;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    uint8_t seed[NQHQSEED], es[NQHQM5 + NQHQSALT], ss[32], ss2[32];
    uint8_t ss3[32];
    for (j = 0; j < NQHQSEED; j++) {
      seed[j] = (uint8_t)(7 * j + i);
    }
    for (j = 0; j < (int)sizeof es; j++) {
      es[j] = (uint8_t)(11 * j + i);
    }
    /* key generation: the seed is secret */
    SECRET(seed, sizeof seed);
    NQTEQI(nqhqkgd(algs[i], seed, sizeof seed, pk, p->pk, sk, p->sk),
           NQOK);
    PUBLIC(pk, p->pk);
    PUBLIC(sk, p->pk); /* sk starts with a copy of pk */
    /* encapsulation: m and the salt are secret */
    SECRET(es, sizeof es);
    NQTEQI(nqhqencd(algs[i], pk, p->pk, es, p->k + NQHQSALT, ct, p->ct,
                    ss, 32),
           NQOK);
    PUBLIC(ct, p->ct);
    PUBLIC(ss, 32);
    /* decapsulation of the ciphertext and of a tampered one: the secret
     * half of the key is secret */
    SECRET(sk + p->pk, p->sk - p->pk);
    NQTEQI(nqhqdec(algs[i], sk, p->sk, ct, p->ct, ss2, 32), NQOK);
    PUBLIC(ss2, 32);
    ct[100] ^= 1;
    NQTEQI(nqhqdec(algs[i], sk, p->sk, ct, p->ct, ss3, 32), NQOK);
    PUBLIC(ss3, 32);
    PUBLIC(sk, p->sk);
    NQTEQM(ss, ss2, 32);
    NQTCHK(memcmp(ss, ss3, 32) != 0);
  }
  return nqtdone("thqcct");
}
