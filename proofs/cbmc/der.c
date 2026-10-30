/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: the DER reader (src/der/der.c) on every input of N bytes.
 * Walks the elements of each level and of each constructed element below,
 * as the X.509, OCSP, CRL and timestamp parsers do, and asserts that
 * every element lies inside its parent; CBMC checks every access, shift
 * and overflow on the way. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "der/der.h"

#ifndef LEVELS
#define LEVELS 2
#endif
#ifndef N
#define N 8
#endif

size_t nondet_size(void);

static void walk(nqdcur *c, const uint8_t *lo, const uint8_t *hi,
                 unsigned left) {
  nqdtlv t;
  while (!nqdend(c) && nqdnext(c, &t) == NQOK) {
    __CPROVER_assert(t.raw.p >= lo && t.raw.p + t.raw.n <= hi,
                     "an element lies inside its parent");
    __CPROVER_assert(t.v.p >= t.raw.p &&
                         t.v.p + t.v.n <= t.raw.p + t.raw.n,
                     "the contents lie inside the element");
    if (t.con && left > 0) {
      nqdcur in;
      if (nqddown(&t, &in) == NQOK)
        walk(&in, t.v.p, t.v.p + t.v.n, left - 1);
    }
  }
}

int main(void) {
  size_t n = nondet_size();
  uint8_t *buf;
  nqdcur c;
  uint8_t *obj;
  /* the input ends where its object ends, so a read past its n bytes is
   * out of bounds (and, for n = N, so is one before them); an object of
   * N bytes keeps the formula small. CBMC gives fresh memory
   * nondeterministic contents. */
  __CPROVER_assume(n <= N);
  obj = (uint8_t *)malloc(N);
  __CPROVER_assume(obj != NULL);
  buf = obj + (N - n);
  nqdinit(&c, buf, n);
  walk(&c, buf, buf + n, LEVELS);
  free(obj);
  return 0;
}
