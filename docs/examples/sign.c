/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Sign a message with ML-DSA-65 and verify it (README, nqsign(3)). */
#include <noqtis.h>
#include <stdio.h>

int main(void) {
  static uint8_t pk[1952], sk[4032], sig[3309];
  const uint8_t msg[] = "results v1";
  size_t n = 0;
  int rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqsign(NQMLDSA65, sk, sizeof sk, msg, sizeof msg - 1, NULL, 0, 0,
                sig, sizeof sig, &n);
  nqwipe(sk, sizeof sk);
  if (rc == NQOK)
    rc = nqvrfy(NQMLDSA65, pk, sizeof pk, msg, sizeof msg - 1, NULL, 0, 0,
                sig, n);
  printf("%s\n", nqerr(rc));
  return rc == NQOK ? 0 : 1;
}
