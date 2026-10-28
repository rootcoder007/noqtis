/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * A program that uses noqtis the way an outside project does: the public
 * header only, linked against the built or installed library.
 */
#include <noqtis.h>

#include <stdio.h>
#include <string.h>

#define NQS2(x) #x
#define NQS(x) NQS2(x)

int main(void) {
  static const uint8_t want[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  };
  const char *v = nqver();
  uint8_t d[32], r[32];
  size_t i, nz = 0;
  int bad = 0;

  if (strcmp(v, NQS(NQVMAJ) "." NQS(NQVMIN) "." NQS(NQVPAT)) != 0) {
    fprintf(stderr, "nqver %s does not match the header\n", v);
    bad = 1;
  }
  if (nqhash(NQS256, (const uint8_t *)"abc", 3, d, sizeof d) != NQOK ||
      memcmp(d, want, sizeof d) != 0) {
    fprintf(stderr, "nqhash SHA-256(abc) is wrong\n");
    bad = 1;
  }
  memset(r, 0, sizeof r);
  if (nqrand(r, sizeof r) != NQOK) {
    fprintf(stderr, "nqrand failed\n");
    bad = 1;
  }
  for (i = 0; i < sizeof r; i++)
    nz |= r[i];
  if (nz == 0) {
    fprintf(stderr, "nqrand returned only zeros\n");
    bad = 1;
  }
  if (bad)
    return 1;
  printf("noqtis %s: nqver, nqhash and nqrand work\n", v);
  return 0;
}
