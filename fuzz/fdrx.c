/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The regex rule's patterns: the first byte is the pattern's length, the
 * rest after the pattern a value. Any bytes compile or are refused with
 * a reason; a compiled pattern answers 0 or 1 on any value, in time
 * linear in its length. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../nqd/int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qdrx *x = NULL;
  char why[300];
  size_t pl;
  int rc, m;
  if (size == 0)
    return 0;
  pl = data[0];
  if (pl > size - 1)
    pl = size - 1;
  why[0] = '\0';
  rc = qdrxcomp((const char *)data + 1, pl, &x, why, sizeof why);
  if (rc != NQOK) {
    if (x != NULL || (rc == NQEDEC && why[0] == '\0'))
      abort();
    return 0;
  }
  m = qdrxrun(x, (const char *)data + 1 + pl, size - 1 - pl);
  if (m != 0 && m != 1)
    abort();
  m = qdrxrun(x, (const char *)data + 1, pl);
  if (m != 0 && m != 1)
    abort();
  qdrxfree(x);
  return 0;
}
