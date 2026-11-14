/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over passphrase key files (nqpwdec): any bytes, read
 * with a fixed passphrase and ad. A file that decrypts must be one
 * nqpwenc could write (its size the key's plus NQPWOVH). The memory
 * field is cut to the 8 MiB minimum and the passes to 1 before reading,
 * so one input costs one Argon2id run at the smallest size the reader
 * takes (the limits themselves are tested in tests/tpw.c); the rest of
 * the header is fuzzed as given. */
#include "fz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t pw[] = "fuzz", ad[] = "noqtis-key-1 ML-DSA-44 sec";
  uint8_t *in = fzdup(data, size), *sk;
  size_t n = 0, cap = size > NQPWOVH ? size - NQPWOVH : 1;
  int rc;
  if (in == NULL) return 0;
  if (size >= 19) {
    if (nqld32b(in + 7) > NQPWMMIN && nqld32b(in + 7) <= NQPWMMAX) {
      nqst32b(in + 7, NQPWMMIN);
    }
    if (nqld32b(in + 11) > 1 && nqld32b(in + 11) <= NQPWTMAX) {
      nqst32b(in + 11, 1);
    }
  }
  sk = (uint8_t *)malloc(cap);
  if (sk != NULL) {
    rc = nqpwdec(pw, sizeof pw - 1, ad, sizeof ad - 1, in, size, sk, cap,
                 &n);
    if (rc == NQOK && (n + NQPWOVH != size || n > NQPWMAX)) abort();
    if (rc != NQOK && n != 0 && rc != NQEBUF) abort();
    free(sk);
  }
  free(in);
  return 0;
}
