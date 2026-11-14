/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over sealed streams (nqkfdini, nqkfdupd, nqkfdfin):
 * any bytes, opened with a fixed ML-KEM-768 key (from a fixed seed) as
 * noqtis unbox reads them: the header, then chunks of the size it
 * names, the last one being the one the input ends with. Plaintext comes
 * out only for a chunk whose tag verified, and an opened stream must
 * have the sizes the format gives it. */
#include "fz.h"

static uint8_t pk[1184], sk[2400];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[64];
  (void)argc;
  (void)argv;
  memset(seed, 0x5f, sizeof seed);
  ready = nqkkgd(NQMLKEM768, seed, sizeof seed, pk, sizeof pk, sk,
                 sizeof sk) == NQOK;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t ctx[] = "noqtis-stream";
  const size_t hl = NQKFHDR + 1088;
  nqkfctx c;
  uint32_t ch = 0;
  uint8_t *in, *out;
  size_t at, k = 0;
  int rc;
  fzready(ready, "fkf");
  in = fzdup(data, size);
  if (in == NULL) return 0;
  if (size < hl ||
      nqkfdini(&c, NQMLKEM768, sk, sizeof sk, ctx, sizeof ctx - 1, in, hl,
               &ch) != NQOK) {
    free(in);
    return 0;
  }
  if (ch < NQKFCMIN || ch > NQKFCMAX) abort();
  out = (uint8_t *)malloc(ch);
  if (out == NULL) {
    free(in);
    return 0;
  }
  at = hl;
  rc = NQOK;
  while (rc == NQOK && size - at > (size_t)ch + 16) {
    rc = nqkfdupd(&c, in + at, (size_t)ch + 16, out, ch, &k);
    if (rc == NQOK && k != ch) abort();
    at += (size_t)ch + 16;
  }
  if (rc == NQOK) {
    rc = nqkfdfin(&c, in + at, size - at, out, ch, &k);
    if (rc == NQOK && k + 16 != size - at) abort();
  }
  /* the stream is over either way */
  if (nqkfdupd(&c, in, 16, out, ch, &k) != NQESTATE) abort();
  free(out);
  free(in);
  return 0;
}
