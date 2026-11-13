/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The data record reader (nqdparse): any bytes. A record it accepts
 * must write as canonical JSON that reads back to the same bytes, and
 * every element must read back through nqdput. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nqd.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char *const ms[] = {"sources", "schemas", "stats", "chunks",
                                   "steps", "checks", "commits", "env",
                                   "cite"};
  nqdrec *r = NULL, *r2 = NULL, *r3 = NULL;
  char why[256], *a, *b;
  size_t na = 0, nb = 0, i, k;
  if (nqdparse((const char *)data, size, &r, why, sizeof why) != NQOK)
    return 0;
  if (nqdjson(r, NULL, 0, &na) != NQEBUF || (a = (char *)malloc(na + 1)) ==
                                                NULL)
    abort();
  if (nqdjson(r, a, na + 1, &na) != NQOK)
    abort();
  if (nqdparse(a, na, &r2, why, sizeof why) != NQOK)
    abort();
  if (nqdjson(r2, NULL, 0, &nb) != NQEBUF || nb != na ||
      (b = (char *)malloc(nb + 1)) == NULL)
    abort();
  if (nqdjson(r2, b, nb + 1, &nb) != NQOK || memcmp(a, b, na) != 0)
    abort();
  /* rebuild from the elements */
  if (nqdnew(&r3) != NQOK)
    abort();
  for (i = 0; i < sizeof ms / sizeof ms[0]; i++) {
    for (k = 0; k < nqdlen(r, ms[i]); k++) {
      size_t n = 0;
      char *e;
      if (nqdat(r, ms[i], k, NULL, 0, &n) != NQEBUF ||
          (e = (char *)malloc(n + 1)) == NULL ||
          nqdat(r, ms[i], k, e, n + 1, &n) != NQOK)
        abort();
      if (nqdput(r3, ms[i], e, n, why, sizeof why) != NQOK)
        abort();
      free(e);
    }
  }
  free(b);
  if (nqdjson(r3, NULL, 0, &nb) != NQEBUF || nb != na ||
      (b = (char *)malloc(nb + 1)) == NULL ||
      nqdjson(r3, b, nb + 1, &nb) != NQOK || memcmp(a, b, na) != 0)
    abort();
  free(a);
  free(b);
  nqdrfree(r);
  nqdrfree(r2);
  nqdrfree(r3);
  return 0;
}
