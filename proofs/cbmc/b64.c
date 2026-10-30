/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: the base64 decoder (nqb64d, src/cap/misc.c) on every
 * string of up to N bytes into every output size up to M: no access out
 * of bounds, and what it reports written fits the output. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cap/cap.h"

#ifndef N
#define N 8
#endif
#ifndef M
#define M 6
#endif

size_t nondet_size(void);

int main(void) {
  size_t n = nondet_size(), cap = nondet_size(), got = 0;
  char *s;
  uint8_t *out;
  /* exactly n characters and cap bytes, so a read or write past either
   * is out of bounds */
  __CPROVER_assume(n <= N && cap <= M);
  s = (char *)malloc(n);
  out = (uint8_t *)malloc(cap);
  __CPROVER_assume(s != NULL && out != NULL);
  if (nqb64d(s, n, out, cap, &got) == NQOK)
    __CPROVER_assert(got <= cap, "the decoded length fits the output");
  free(s);
  free(out);
  return 0;
}
