/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqddrift on any "stats" element and any CSV file: the input is the
 * element, a NUL, then the file's bytes. A valid element must never make
 * the comparison read out of bounds, whatever the file holds. The file
 * goes through a temporary file, as nqddrift reads a path. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nqd.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static char path[64];
  const uint8_t *z = (const uint8_t *)memchr(data, 0, size);
  nqdrep *rep = NULL;
  nqddopt d;
  FILE *f;
  size_t i;
  if (z == NULL)
    return 0;
  if (path[0] == '\0')
    snprintf(path, sizeof path, "/tmp/fddft.%p.csv", (void *)&path);
  f = fopen(path, "wb");
  if (f == NULL)
    return 0;
  fwrite(z + 1, 1, size - (size_t)(z - data) - 1, f);
  fclose(f);
  d.psiwarn = 0.1;
  d.psifail = 0.25;
  d.alpha = 0.001;
  d.minn = 1;
  d.benford = 1;
  nqddrift((const char *)data, (size_t)(z - data), path, NULL, &d, &rep);
  for (i = 0; i < nqdrepn(rep); i++) {
    const char *c, *dt;
    int ok;
    if (nqdrepi(rep, i, &c, &ok, &dt) != NQOK || c == NULL || dt == NULL)
      abort();
  }
  nqdrepfree(rep);
  return 0;
}
