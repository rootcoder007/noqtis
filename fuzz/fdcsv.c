/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The CSV reader: any bytes, with the first byte choosing the delimiter.
 * Every record's fields must lie inside the record and be UTF-8 without
 * a NUL; the reader must end (or refuse) within the input. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../nqd/int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char dl[] = {',', ';', '\t', '|'};
  qdcsv c;
  int got = 1;
  uint64_t n = 0;
  if (size == 0)
    return 0;
  if (qdcsvmem(&c, (const char *)data + 1, size - 1, dl[data[0] & 3]) !=
      NQOK)
    return 0;
  while (qdcsvnext(&c, &got) == NQOK && got) {
    size_t i, l;
    for (i = 0; i < c.nf; i++) {
      const char *f = qdcsvf(&c, i, &l);
      if (f == NULL || f[l] != '\0' || strlen(f) != l || !qdutf8(f, l))
        abort();
    }
    if (++n > size + 1)
      abort();
  }
  qdcsvclose(&c);
  return 0;
}
