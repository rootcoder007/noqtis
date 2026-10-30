/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Ed25519 constant-time check. Built with -DNQCTGRIND (library and test)
 * and run under valgrind memcheck, the private key is marked undefined,
 * so any branch or memory index that depends on it, on the expanded
 * scalar or on the secret nonce, is reported. The public key and the
 * signature are declared public before they are used. Without NQCTGRIND
 * this is a plain keygen / sign / verify test of every variant. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "ed/ed.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)0)
#define PUBLIC(p, n) ((void)0)
#endif

int main(void) {
  static const uint8_t msg[] = "constant time";
  static const uint8_t ctx[] = "ct";
  uint8_t sk[32], pk[32], sig[64];
  int v, rc;
  size_t i;
  for (i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 29 + 3);
  SECRET(sk, sizeof sk);
  rc = nqedkg(sk, pk);
  PUBLIC(&rc, sizeof rc);
  PUBLIC(pk, sizeof pk);
  NQTEQI(rc, NQOK);
  /* Ed25519, Ed25519ctx, Ed25519ph */
  for (v = 0; v < 3; v++) {
    rc = nqedsign(sk, msg, sizeof msg - 1, v == 0 ? NULL : ctx,
                  v == 0 ? 0 : sizeof ctx - 1, v == 2, sig);
    PUBLIC(&rc, sizeof rc);
    PUBLIC(sig, sizeof sig);
    NQTEQI(rc, NQOK);
    NQTEQI(nqedvrfy(pk, msg, sizeof msg - 1, v == 0 ? NULL : ctx,
                    v == 0 ? 0 : sizeof ctx - 1, v == 2, sig), NQOK);
  }
  return nqtdone("tedct");
}
