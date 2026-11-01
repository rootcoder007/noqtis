/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Prints src/api/kat.h: the hash of each self-test. Build against the
 * static library, which has nqselfdg:
 *   cc -I include tests/selfgen.c build/libnoqtis.a -o selfgen
 *   ./selfgen > src/api/kat.h.new */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
int nqselfdg(int i, uint8_t out[32]);
int main(void) {
  uint8_t d[32];
  int i, j;
  clock_t t0 = clock();
  for (i = 0; nqselfdg(i, d); i++) {
    printf("    {");
    for (j = 0; j < 32; j++) printf("0x%02x%s%s", d[j], j < 31 ? "," : "", j % 8 == 7 && j < 31 ? "\n     " : (j < 31 ? " " : ""));
    printf("},\n");
  }
  fprintf(stderr, "%d tests, %.0f ms\n", i, 1000.0 * (double)(clock() - t0) / CLOCKS_PER_SEC);
  return 0;
}
