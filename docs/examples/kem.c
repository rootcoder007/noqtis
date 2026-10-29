/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-KEM-768 key generation, encapsulation and decapsulation, with the
 * sizes taken at run time (nqenc(3)). */
#include <noqtis.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  nqksz z;
  uint8_t *pk, *sk, *ct, a[32], b[32];
  int rc = nqksize(NQMLKEM768, &z), same = 0;
  if (rc != NQOK || z.ss != sizeof a)
    return 2;
  pk = malloc(z.pk);
  sk = malloc(z.sk);
  ct = malloc(z.ct);
  if (pk == NULL || sk == NULL || ct == NULL)
    return 2;
  rc = nqkkg(NQMLKEM768, pk, z.pk, sk, z.sk);
  if (rc == NQOK)
    rc = nqenc(NQMLKEM768, pk, z.pk, ct, z.ct, a, sizeof a);
  if (rc == NQOK)
    rc = nqdec(NQMLKEM768, sk, z.sk, ct, z.ct, b, sizeof b);
  if (rc == NQOK)
    same = nqcteq(a, b, sizeof a);
  nqwipe(sk, z.sk);
  nqwipe(a, sizeof a);
  nqwipe(b, sizeof b);
  free(pk);
  free(sk);
  free(ct);
  printf("%s, secrets %s\n", nqerr(rc), same ? "agree" : "differ");
  return rc == NQOK && same ? 0 : 1;
}
