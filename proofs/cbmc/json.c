/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: the strict JSON reader (nqjparse, src/core/json.c) on every
 * input of up to N bytes, then its free: no access out of bounds, no
 * overflow, and nothing leaks (--memory-leak-check). The allocator hook is
 * plain malloc and free here. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"

#ifndef N
#define N 1
#endif

size_t nondet_size(void);

void *nqmal(size_t size) {
  return size == 0 ? NULL : malloc(size);
}

void nqfree(void *ptr, size_t size) {
  (void)size;
  free(ptr);
}

int main(void) {
  size_t n = nondet_size(), at = 0;
  char *s;
  nqjs *v = NULL;
  /* exactly n bytes, nondeterministic */
  __CPROVER_assume(n <= N);
  s = (char *)malloc(n);
  __CPROVER_assume(s != NULL);
  if (nqjparse(s, n, &v, &at) == NQOK) {
    __CPROVER_assert(v != NULL, "a parse that succeeds gives a value");
    nqjfree(v);
  } else {
    __CPROVER_assert(at <= n, "the error offset is inside the input");
  }
  free(s);
  return 0;
}
