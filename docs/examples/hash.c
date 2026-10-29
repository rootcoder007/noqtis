/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* One-shot and incremental hashing, SHAKE squeezing, HMAC (nqhash(3)). */
#include <noqtis.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const uint8_t abc[] = "abc";
  uint8_t d1[32], d2[32], x[64], mac[32];
  nqhctx c;
  int rc = nqhash(NQS256, abc, 3, d1, sizeof d1);
  /* the same digest in two pieces */
  if (rc == NQOK)
    rc = nqhini(&c, NQS256);
  if (rc == NQOK)
    rc = nqhupd(&c, abc, 1);
  if (rc == NQOK)
    rc = nqhupd(&c, abc + 1, 2);
  if (rc == NQOK)
    rc = nqhfin(&c, d2, sizeof d2);
  /* SHAKE256: 32 bytes, then 32 more from the same context */
  if (rc == NQOK)
    rc = nqhini(&c, NQSHK256);
  if (rc == NQOK)
    rc = nqhupd(&c, abc, 3);
  if (rc == NQOK)
    rc = nqhfin(&c, x, 32);
  if (rc == NQOK)
    rc = nqhfin(&c, x + 32, 32);
  if (rc == NQOK)
    rc = nqhmac(NQS256, (const uint8_t *)"key", 3, abc, 3, mac, sizeof mac);
  printf("%s, %s, sha256(abc) starts %02x%02x\n", nqerr(rc),
         memcmp(d1, d2, 32) == 0 ? "same" : "different", d1[0], d1[1]);
  return rc == NQOK && memcmp(d1, d2, 32) == 0 ? 0 : 1;
}
