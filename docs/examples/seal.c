/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Seal a folder and check it, printing every row of the report
 * (nqseal(3), nqchk(3), nqrep(3)). Usage: seal <dir> */
#include <noqtis.h>
#include <stdio.h>

int main(int argc, char **argv) {
  static uint8_t pk[1952], sk[4032];
  nqrep *rep = NULL;
  size_t i;
  int rc;
  if (argc != 2) {
    fprintf(stderr, "usage: seal <dir>\n");
    return 2;
  }
  rc = nqskg(NQMLDSA65, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqseal(argv[1], NQMLDSA65, sk, sizeof sk, pk, sizeof pk,
                "{\"tool\":\"example\"}", NULL);
  nqwipe(sk, sizeof sk);
  if (rc != NQOK) {
    fprintf(stderr, "seal: %s\n", nqerr(rc));
    return 2;
  }
  /* pin the key we expect, so the check also says who sealed it */
  rc = nqchk(argv[1], pk, sizeof pk, &rep);
  for (i = 0; i < nqrepn(rep); i++) {
    const char *check, *detail;
    int ok;
    if (nqrepi(rep, i, &check, &ok, &detail) == NQOK)
      printf("%-4s %s: %s\n", ok ? "ok" : "FAIL", check, detail);
  }
  nqrepfree(rep);
  printf("%s\n", nqerr(rc));
  return rc == NQOK ? 0 : 1;
}
