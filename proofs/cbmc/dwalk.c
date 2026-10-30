/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: the whole-tree check (nqdone, which calls nqdhdr and
 * nqdwalk, src/der/der.c) on every input of up to N bytes: every
 * element, nested to any depth those bytes allow, every universal
 * primitive's contents check (nqdprim: INTEGER, OID, BIT STRING, the
 * strings, the times) and the DER order of every SET's elements. No
 * access out of bounds or overflow on the way, and an accepted input is
 * exactly one element. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "der/der.h"

#ifndef N
#define N 6
#endif

size_t nondet_size(void);

int main(void) {
  size_t n = nondet_size();
  uint8_t *buf;
  nqdtlv t;
  uint8_t *obj;
  /* the input ends where its object ends, so a read past its n bytes is
   * out of bounds (and, for n = N, so is one before them); an object of
   * N bytes keeps the formula small. CBMC gives fresh memory
   * nondeterministic contents. */
  __CPROVER_assume(n <= N);
  obj = (uint8_t *)malloc(N);
  __CPROVER_assume(obj != NULL);
  buf = obj + (N - n);
  if (nqdone(buf, n, &t) == NQOK) {
    __CPROVER_assert(t.raw.p == buf && t.raw.n == n,
                     "an accepted input is exactly one element");
  }
  free(obj);
  return 0;
}
