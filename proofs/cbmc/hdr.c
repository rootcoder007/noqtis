/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: one DER header (nqdhdr, src/der/der.c) on every input of
 * every length n, the buffer allocated with n nondeterministic: nqdhdr
 * reads at most 9 bytes (an identifier, 3 tag septets, a length octet and
 * 4 length octets), so its loops are bounded whatever n is. On success
 * the element and its contents lie inside the n bytes. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "der/der.h"

size_t nondet_size(void);

int main(void) {
  size_t n = nondet_size();
  uint8_t *p = (uint8_t *)malloc(n);
  nqdtlv t;
  __CPROVER_assume(p != NULL);
  if (nqdhdr(p, n, &t) == NQOK) {
    __CPROVER_assert(t.raw.p == p && t.raw.n <= n,
                     "the element lies inside the input");
    __CPROVER_assert(t.v.n <= t.raw.n && t.v.p == p + (t.raw.n - t.v.n),
                     "the contents end the element");
    __CPROVER_assert(t.raw.n - t.v.n >= 2 && t.raw.n - t.v.n <= 9,
                     "a header is 2 to 9 bytes");
    __CPROVER_assert(t.cls <= 3 && t.con <= 1 && t.tag <= NQDTAGMAX,
                     "the tag fields are in range");
  }
  free(p);
  return 0;
}
