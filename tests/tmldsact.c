/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of ML-DSA key generation and signing (ctgrind).
 *
 * Built with -DNQCTGRIND (library and test) and run under valgrind, the
 * seed xi, the secret key and rnd are marked undefined, so memcheck
 * reports any branch, memory index or system call that depends on them.
 * The library declares public only what FIPS 204 publishes (rho, c~, the
 * hint, rejection decisions, the RejBoundedPoly nibble decisions). The
 * outputs are marked defined before they are compared. Built plainly, it
 * runs the same operations as an ordinary test. */
#include <stdint.h>

#include "noqtis.h"
#include "core/int.h"
#include "mldsa/mldsa.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#define PUBLIC(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

int main(void) {
  static const int algs[3] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};
  static uint8_t pk[NQMDPKMAX], sk[NQMDSKMAX], sig[NQMDSIGMAX],
      sig2[NQMDSIGMAX];
  const uint8_t msg[] = "constant time";
  const uint8_t ctx[] = "noqtis-capsule-1";
  uint8_t xi[NQMDSEED], rnd[NQMDRND], mu[NQMDMU];
  int a, rc, m;
  for (a = 0; a < 3; a++) {
    int alg = algs[a];
    nqssz sz;
    size_t out = 0, o2 = 0;
    nqmdsz(alg, &sz);
    /* key generation */
    NQTEQI(nqrand(xi, sizeof xi), NQOK);
    SECRET(xi, sizeof xi);
    rc = nqmdkgd(alg, xi, sizeof xi, pk, sizeof pk, sk, sizeof sk);
    NQTEQI(rc, NQOK);
    PUBLIC(pk, sz.pk);
    /* signing: masked and unmasked, external mu, hedged rnd */
    NQTEQI(nqrand(mu, sizeof mu), NQOK);
    NQTEQI(nqrand(rnd, sizeof rnd), NQOK);
    SECRET(sk, sz.sk);
    SECRET(rnd, sizeof rnd);
    for (m = 0; m < 2; m++) {
      uint8_t *s = m ? sig2 : sig;
      size_t *o = m ? &o2 : &out;
      rc = nqmdsmu(alg, sk, sz.sk, mu, rnd, sizeof rnd,
                   m ? NQMDPLAIN : NQMDMASK, s, NQMDSIGMAX, o);
      PUBLIC(&rc, sizeof rc);
      PUBLIC(s, NQMDSIGMAX);
      PUBLIC(o, sizeof *o);
      NQTEQI(rc, NQOK);
    }
    NQTEQI(out, sz.sig);
    NQTEQM(sig, sig2, sz.sig);
    NQTEQI(nqmdvmu(alg, pk, sz.pk, mu, sig, sz.sig), NQOK);
    /* the pure interface with a context, deterministic (rnd zero, still
     * marked secret) */
    memset(rnd, 0, sizeof rnd);
    SECRET(rnd, sizeof rnd);
    rc = nqmdsign(alg, sk, sz.sk, msg, sizeof msg - 1, ctx, sizeof ctx - 1,
                  0, rnd, sizeof rnd, sig, sizeof sig, &out);
    PUBLIC(&rc, sizeof rc);
    PUBLIC(sig, sizeof sig);
    PUBLIC(&out, sizeof out);
    NQTEQI(rc, NQOK);
    PUBLIC(sk, sz.sk);
    NQTEQI(nqmdvrfy(alg, pk, sz.pk, msg, sizeof msg - 1, ctx,
                    sizeof ctx - 1, 0, sig, sz.sig),
           NQOK);
    nqwipe(sk, sizeof sk);
  }
  nqwipe(xi, sizeof xi);
  return nqtdone("tmldsact");
}
