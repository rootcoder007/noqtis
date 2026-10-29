/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The C example of README.md, as a program. Usage: readme <dir> */
#include <noqtis.h>
#include <stdio.h>

int main(int argc, char **argv) {
  static uint8_t pk[1952], sk[4032];   /* ML-DSA-65 key sizes, see nqssize() */
  nqrep *rep = NULL;
  int rc;
  if (argc != 2)
    return 2;
  rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqseal(argv[1], NQMLDSA65, sk, sizeof sk, pk, sizeof pk, NULL, NULL);
  nqwipe(sk, sizeof sk);
  if (rc == NQOK)
    rc = nqchk(argv[1], pk, sizeof pk, &rep);   /* NQOK, or NQEVRFY + report */
  nqrepfree(rep);
  printf("%s\n", nqerr(rc));
  return rc == NQOK ? 0 : 1;
}
