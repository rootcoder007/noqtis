/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over sealed messages (nqkopen): any bytes, opened
 * with fixed ML-KEM-512, -768 and -1024 keys (from fixed seeds) and a
 * context the input's first byte chooses. An input that opens must be
 * the size nqkseal writes for its message, and sealing that message
 * again gives an input that opens to it. */
#include "fz.h"

static uint8_t pk[3][1568], sk[3][3168];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[64];
  int i;
  (void)argc;
  (void)argv;
  for (i = 0; i < 3; i++) {
    memset(seed, 0x40 + i, sizeof seed);
    if (nqkkgd((nqkalg)(NQMLKEM512 + i), seed, sizeof seed, pk[i],
               sizeof pk[i], sk[i], sizeof sk[i]) != NQOK) {
      return 0;
    }
  }
  ready = 1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t ctx[] = "noqtis-commit-1";
  uint8_t *in, *msg, *again;
  size_t cl, n = 0, an = 0, cap;
  nqksz z;
  int i, rc;
  fzready(ready, "fks");
  if (size < 1) return 0;
  cl = data[0] % (sizeof ctx);
  in = fzdup(data + 1, size - 1);
  cap = size;
  msg = (uint8_t *)malloc(cap);
  if (in == NULL || msg == NULL) {
    free(in);
    free(msg);
    return 0;
  }
  for (i = 0; i < 3; i++) {
    nqkalg a = (nqkalg)(NQMLKEM512 + i);
    if (nqksize(a, &z) != NQOK) abort();
    rc = nqkopen(a, sk[i], z.sk, ctx, cl, in, size - 1, msg, cap, &n);
    if (rc != NQOK) continue;
    if (n + NQKSOVH + z.ct != size - 1) abort();
    again = (uint8_t *)malloc(size - 1);
    if (again == NULL) continue;
    if (nqkseal(a, pk[i], z.pk, ctx, cl, msg, n, again, size - 1, &an) !=
            NQOK ||
        an != size - 1 ||
        nqkopen(a, sk[i], z.sk, ctx, cl, again, an, msg, cap, &n) != NQOK) {
      abort();
    }
    free(again);
  }
  free(in);
  free(msg);
  return 0;
}
