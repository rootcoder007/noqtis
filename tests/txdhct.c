/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of X25519 (ctgrind). Built with -DNQCTGRIND (the
 * library too) and run under valgrind, the scalars are marked undefined,
 * so memcheck reports any branch or index that depends on them; the
 * public keys and the peer's point are public, and only whether the
 * shared secret is all zero is declared public in the library (xdh.h,
 * NQXPUB). Without NQCTGRIND it runs plainly and checks that both sides
 * agree. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "xdh/xdh.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

int main(void) {
  uint8_t a[32], b[32], pa[32], pb[32], sa[32], sb[32], z[32];
  int i, r;
  for (r = 0; r < 3; r++) {
    for (i = 0; i < 32; i++) {
      a[i] = (uint8_t)(i * 37 + r);
      b[i] = (uint8_t)(i * 91 + 7 * r + 1);
    }
    SECRET(a, sizeof a);
    SECRET(b, sizeof b);
    NQTEQI(nqx25519b(pa, a), NQOK);
    NQTEQI(nqx25519b(pb, b), NQOK);
    PUBLIC(pa, sizeof pa);
    PUBLIC(pb, sizeof pb);
    NQTEQI(nqx25519(sa, a, pb), NQOK);
    NQTEQI(nqx25519(sb, b, pa), NQOK);
    PUBLIC(sa, sizeof sa);
    PUBLIC(sb, sizeof sb);
    NQTEQM(sa, sb, 32);
  }
  /* a point of small order: the all-zero result, still in constant time */
  memset(z, 0, sizeof z);
  SECRET(a, sizeof a);
  NQTEQI(nqx25519(sa, a, z), NQEVRFY);
  return nqtdone("txdhct");
}
