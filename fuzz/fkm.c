/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* libFuzzer target over streams sealed to several keys (nqkmpeek,
 * nqkmdini, nqkmdupd, nqkmdfin): any bytes, opened with a fixed
 * ML-KEM-768 key (from a fixed seed) as noqtis unbox reads them: the
 * fixed part of the header, the header of the length it names, then
 * chunks of the size it names, the last one being the one the input
 * ends with, the signature record after it when the stream is signed.
 * The first byte chooses whether a sender's key is given. Plaintext
 * comes out only for a chunk whose tag verified, and an opened stream
 * must have the sizes the format gives it. */
#include "fz.h"

static uint8_t pk[1184], sk[2400], spk[1312], ssk[2560];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[64];
  (void)argc;
  (void)argv;
  memset(seed, 0x5f, sizeof seed);
  ready = nqkkgd(NQMLKEM768, seed, sizeof seed, pk, sizeof pk, sk,
                 sizeof sk) == NQOK &&
          nqskgd(NQMLDSA44, seed, 32, spk, sizeof spk, ssk, sizeof ssk) ==
              NQOK;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t ctx[] = "noqtis-stream";
  nqkmctx c;
  nqsalg sg = (nqsalg)0, sg2 = (nqsalg)0;
  nqssz z;
  uint32_t ch = 0;
  uint8_t *in, *out;
  size_t hl = 0, nr = 0, at, k = 0, rec = 0;
  int rc, ask;
  fzready(ready, "fkm");
  if (size < 1) return 0;
  ask = data[0] & 1;
  data++;
  size--;
  in = fzdup(data, size);
  if (in == NULL) return 0;
  if (nqkmpeek(in, size, &hl, &sg, &nr) != NQOK) {
    free(in);
    return 0;
  }
  /* what nqkmpeek let through is within the limits */
  if (hl < NQKMFIX || nr < 1 || nr > NQKMRCP) abort();
  if (hl > size ||
      nqkmdini(&c, NQMLKEM768, sk, sizeof sk, ctx, sizeof ctx - 1, in, hl,
               &ch, &sg2) != NQOK) {
    free(in);
    return 0;
  }
  if (ch < NQKFCMIN || ch > NQKFCMAX || sg2 != sg) abort();
  if (sg != 0) {
    if (nqssize(sg, &z) != NQOK) abort();
    rec = z.sig + 16;
  }
  out = (uint8_t *)malloc(ch);
  if (out == NULL) {
    free(in);
    return 0;
  }
  at = hl;
  rc = NQOK;
  while (rc == NQOK && size - at > (size_t)ch + 16 + rec) {
    rc = nqkmdupd(&c, in + at, (size_t)ch + 16, out, ch, &k);
    if (rc == NQOK && k != ch) abort();
    at += (size_t)ch + 16;
  }
  if (rc == NQOK) {
    rc = nqkmdfin(&c, in + at, size - at, ask ? spk : NULL,
                  ask ? sizeof spk : 0, out, ch, &k);
    if (rc == NQOK && k + 16 + rec != size - at) abort();
    /* a key asked of a stream that is not signed never opens it */
    if (rc == NQOK && ask && sg == 0) abort();
  }
  /* the stream is over either way */
  if (nqkmdupd(&c, in, 16, out, ch, &k) != NQESTATE) abort();
  free(out);
  free(in);
  return 0;
}
