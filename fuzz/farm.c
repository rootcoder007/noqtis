/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* libFuzzer target over text armor: nqarmdec (RFC 7468) and nqpgpdearm
 * (OpenPGP, with its headers and checksum line). Any bytes are read as
 * an armor. What nqarmdec accepts is written again by nqarmenc and must
 * read back to the same label and bytes; the input is also armored
 * under a fixed label and under each OpenPGP kind, and must come back
 * whole. */
#include "fz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char lab[NQARMLAB], lab2[NQARMLAB], *a;
  uint8_t *out, *back;
  size_t on = 0, an = 0, bn = 0, need = 0;
  int kind = 0, k;
  if (size > ((size_t)1 << 20)) return 0;
  out = (uint8_t *)malloc(size + 1);
  back = (uint8_t *)malloc(size + 1);
  if (out == NULL || back == NULL) {
    free(out);
    free(back);
    return 0;
  }
  /* the input as an armor */
  if (nqarmdec((const char *)data, size, lab, sizeof lab, out, size, &on) ==
      NQOK) {
    if (on > size || memchr(lab, 0, sizeof lab) == NULL) abort();
    if (nqarmlen(lab, on, &need) != NQOK) abort();
    a = (char *)malloc(need + 1);
    if (a != NULL) {
      if (nqarmenc(lab, out, on, a, need, &an) != NQOK || an != need) abort();
      if (nqarmdec(a, an, lab2, sizeof lab2, back, size + 1, &bn) != NQOK ||
          bn != on || memcmp(back, out, on) != 0 || strcmp(lab, lab2) != 0)
        abort();
      free(a);
    }
  }
  if (nqpgpdearm((const char *)data, size, &kind, out, size, &on) == NQOK) {
    if (on > size || kind < NQPGPMSG || kind > NQPGPSIG) abort();
  }
  /* the input as bytes to armor: there and back */
  if (nqarmlen("NOQTIS FUZZ", size, &need) != NQOK) abort();
  a = (char *)malloc(need + 1);
  if (a != NULL) {
    if (nqarmenc("NOQTIS FUZZ", data, size, a, need, &an) != NQOK) abort();
    if (nqarmdec(a, an, lab, sizeof lab, back, size + 1, &bn) != NQOK ||
        bn != size || (size > 0 && memcmp(back, data, size) != 0))
      abort();
    free(a);
  }
  for (k = NQPGPMSG; k <= NQPGPSIG; k++) {
    if (nqpgparm(k, data, size, NULL, 0, &need) != NQOK) abort();
    a = (char *)malloc(need + 1);
    if (a == NULL) continue;
    if (nqpgparm(k, data, size, a, need, &an) != NQOK) abort();
    if (nqpgpdearm(a, an, &kind, back, size + 1, &bn) != NQOK || kind != k ||
        bn != size || (size > 0 && memcmp(back, data, size) != 0))
      abort();
    free(a);
  }
  free(out);
  free(back);
  return 0;
}
