/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SLH-DSA constant-time check. Built with -DNQCTGRIND (library sources
 * included, see below) and run under valgrind memcheck, the seed, the
 * secret key and the signing randomness are marked undefined, so any
 * branch or memory index that depends on them is reported. The values
 * FIPS 205 publishes (R, the FORS key, each layer's root, the public key
 * inside sk) are declassified in src/slh by NQSLDECL. Without NQCTGRIND
 * this is a plain keygen / sign / verify test. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "slh/slh.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)0)
#define PUBLIC(p, n) ((void)0)
#endif

static void one(nqsalg alg) {
  const nqslp *p = nqslpar(alg);
  uint8_t seed[96], pk[64], sk[128], rnd[32];
  uint8_t *sig = (uint8_t *)malloc(p->sig);
  static const uint8_t msg[] = "constant time";
  static const uint8_t ctx[] = "ct";
  size_t i, ol = 0;
  int rc;
  NQTCHK(sig != NULL);
  if (sig == NULL) return;
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 29 + 3);
  for (i = 0; i < sizeof rnd; i++) rnd[i] = (uint8_t)(i * 13 + 5);

  /* key generation: the whole seed is secret (PK.seed too, to be strict;
   * nothing branches on it) */
  SECRET(seed, sizeof seed);
  rc = nqslkgd(alg, seed, 3 * p->n, pk, p->pk, sk, p->sk);
  PUBLIC(&rc, sizeof rc);
  PUBLIC(pk, sizeof pk);
  PUBLIC(sk, sizeof sk);
  NQTEQI(rc, NQOK);

  /* hedged signing, pure and pre-hashed, and the internal interface */
  SECRET(sk, p->sk);
  SECRET(rnd, sizeof rnd);
  rc = nqslsignd(alg, sk, p->sk, msg, sizeof msg - 1, ctx, sizeof ctx - 1,
                 0, rnd, p->n, sig, p->sig, &ol);
  PUBLIC(&rc, sizeof rc);
  PUBLIC(sig, p->sig);
  NQTEQI(rc, NQOK);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, sizeof msg - 1, ctx,
                  sizeof ctx - 1, 0, sig, p->sig), NQOK);

  rc = nqslsignd(alg, sk, p->sk, msg, sizeof msg - 1, ctx, sizeof ctx - 1,
                 NQS3256, rnd, p->n, sig, p->sig, &ol);
  PUBLIC(&rc, sizeof rc);
  PUBLIC(sig, p->sig);
  NQTEQI(rc, NQOK);
  NQTEQI(nqslvrfy(alg, pk, p->pk, msg, sizeof msg - 1, ctx,
                  sizeof ctx - 1, NQS3256, sig, p->sig), NQOK);

  /* deterministic: opt_rand is PK.seed, read from the secret key */
  rc = nqslsigi(alg, sk, p->sk, msg, sizeof msg - 1, NULL, 0, sig, p->sig,
                &ol);
  PUBLIC(&rc, sizeof rc);
  PUBLIC(sig, p->sig);
  NQTEQI(rc, NQOK);
  NQTEQI(nqslvrfi(alg, pk, p->pk, msg, sizeof msg - 1, sig, p->sig), NQOK);
  free(sig);
}

int main(void) {
  size_t i;
  const char *e = getenv("NQSLOW");
  int all = e != NULL && strcmp(e, "1") == 0;
  /* every f set; the s sets (seconds each, minutes under valgrind) with
   * NQSLOW=1 */
  for (i = 0; i < NQSLNSET; i++) {
    const char *nm = nqsltab[i].name;
    if (all || nm[strlen(nm) - 1] == 'f') one(nqsltab[i].alg);
  }
  return nqtdone("tslhct");
}
