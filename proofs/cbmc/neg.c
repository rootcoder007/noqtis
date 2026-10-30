/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC negative controls, which must FAIL: the parser is told its input
 * holds one byte more than it does, with the input laid out as the
 * harnesses lay it out: alone in an object of n bytes (hdr, b64, jlex,
 * json), or at the end of an object of N bytes (-DEND: der, dwalk).
 * run.sh expects CBMC to report the read past the end, which shows that
 * the checks and those layouts catch an over-read. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "der/der.h"

#define N 4

size_t nondet_size(void);

int main(void) {
  size_t n = nondet_size();
  uint8_t *obj, *p;
  nqdtlv t;
  __CPROVER_assume(n <= N);
#ifdef END
  obj = (uint8_t *)malloc(N);
  __CPROVER_assume(obj != NULL);
  p = obj + (N - n);
  (void)nqdone(p, n + 1, &t);
#else
  obj = (uint8_t *)malloc(n);
  __CPROVER_assume(obj != NULL);
  p = obj;
  (void)nqdhdr(p, n + 1, &t);
#endif
  free(obj);
  return 0;
}
