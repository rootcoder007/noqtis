/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over identity cards (nqcardvrfy). At start it makes a
 * card with every field for a fixed ML-DSA-44 key. Each input is then
 * checked as a card by itself, with and without that key pinned, and as
 * an edit of the good card (two bytes of offset, then the bytes to write
 * there), so the mutations reach the field checks and the signature past
 * the parser. A card that verifies must carry the fixed key, unless it
 * is the input itself (anyone may sign a card with their own key). */
#include "fz.h"
#include "cap/cap.h"

static char *good;
static size_t goodn;
static uint8_t pk[1312];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[32], sk[2560];
  size_t i;
  int rc;
  (void)argc;
  fzinit(argv);
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)i;
  if (nqskgd(NQMLDSA44, seed, sizeof seed, pk, sizeof pk, sk, sizeof sk) !=
      NQOK) {
    fprintf(stderr, "fcard: cannot make the key\n");
    return 0;
  }
  rc = nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "Ada Lovelace",
              "0000-0002-1825-0097", "ada@example.org",
              "https://example.org/ada", "AES", 1767225600, NULL, 0, &goodn);
  good = rc == NQEBUF ? (char *)malloc(goodn) : NULL;
  if (good != NULL)
    rc = nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "Ada Lovelace",
                "0000-0002-1825-0097", "ada@example.org",
                "https://example.org/ada", "AES", 1767225600, good, goodn,
                &goodn);
  nqwipe(sk, sizeof sk);
  if (rc != NQOK) {
    fprintf(stderr, "fcard: cannot make the card: %s\n", nqerr(rc));
    return 0;
  }
  ready = 1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqcardf f;
  char *e;
  size_t at, k;
  int rc;
  fzready(ready, "fcard");
  /* the input as a card; one that verifies has its fields in bounds */
  if (nqcardvrfy((const char *)data, size, NULL, 0, &f) == NQOK) {
    if (f.name[0] == 0 || f.pklen == 0 || f.pklen > sizeof f.pk ||
        memchr(f.name, 0, sizeof f.name) == NULL)
      abort();
  }
  nqcardvrfy((const char *)data, size, pk, sizeof pk, &f);
  /* an edit of the good card */
  if (size < 2) return 0;
  at = ((size_t)data[0] << 8 | data[1]) % goodn;
  k = size - 2;
  if (k > goodn - at) k = goodn - at;
  e = (char *)malloc(goodn);
  if (e == NULL) return 0;
  memcpy(e, good, goodn);
  memcpy(e + at, data + 2, k);
  rc = nqcardvrfy(e, goodn, pk, sizeof pk, &f);
  /* only the card as made verifies under its key: an edit that leaves
   * it verifying left it unchanged */
  if (rc == NQOK && memcmp(e, good, goodn) != 0) abort();
  free(e);
  return 0;
}
