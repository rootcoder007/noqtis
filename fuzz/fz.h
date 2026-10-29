/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Shared by the libFuzzer targets in fuzz/: where the fixture files are,
 * a signature stub that accepts everything (so a target reaches every
 * check after a signature), and a reader that cuts an input into
 * length-prefixed pieces.
 *
 * Fixtures are read from $NQFIX, else from fix/ beside the target (where
 * fuzz/build.sh copies them), else from tests/vectors/der/local. */
#ifndef NQFZ_H
#define NQFZ_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "der/x509.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static char fzdir[512];

/* Sets fzdir from $NQFIX or argv[0]. */
static inline void fzinit(char ***argv) {
  const char *e = getenv("NQFIX");
  const char *a = argv != NULL && *argv != NULL ? (*argv)[0] : NULL;
  const char *s;
  char probe[600];
  FILE *f;
  if (e != NULL && *e != 0) {
    snprintf(fzdir, sizeof fzdir, "%s", e);
    return;
  }
  snprintf(fzdir, sizeof fzdir, "tests/vectors/der/local");
  if (a == NULL || (s = strrchr(a, '/')) == NULL ||
      (size_t)(s - a) + 5 >= sizeof fzdir) {
    return;
  }
  snprintf(probe, sizeof probe, "%.*s/fix/rsa_root.der", (int)(s - a), a);
  f = fopen(probe, "rb");
  if (f != NULL) {
    fclose(f);
    snprintf(fzdir, sizeof fzdir, "%.*s/fix", (int)(s - a), a);
  }
}

/* A fixture as a fresh buffer (free with nqfree(p, *n + 1)); NULL when it
 * cannot be read. */
static inline uint8_t *fzread(const char *name, size_t *n) {
  char path[700], *b = NULL;
  snprintf(path, sizeof path, "%s/%s", fzdir, name);
  if (nqreadf(path, (size_t)1 << 22, &b, n) != NQOK) {
    fprintf(stderr, "fuzz: no fixture %s\n", path);
    return NULL;
  }
  return (uint8_t *)b;
}

/* A fixture certificate, parsed; its bytes stay allocated for the life
 * of the process (the parse points into them). 0 when it is missing. */
static inline int fzcert(const char *name, nqcert *c) {
  size_t n = 0;
  uint8_t *b = fzread(name, &n);
  if (b == NULL) return 0;
  if (nqcprs(b, n, c) != NQOK) {
    fprintf(stderr, "fuzz: %s does not parse\n", name);
    nqfree(b, n + 1);
    return 0;
  }
  return 1;
}

static inline int fzyes(void *user, const nqxvreq *r) {
  (void)user;
  /* touch what the callback is given */
  return r->msg.n > 0 && r->sig.n > 0 && r->key->spki.n > 0 ? NQOK
                                                              : NQEVRFY;
}

static inline int fzsha1(void *user, const uint8_t *in, size_t len,
                         uint8_t out[20]) {
  /* not SHA-1: any 20 bytes do for the parsers */
  uint8_t d[32];
  (void)user;
  nqhash(NQS256, in, len, d, 32);
  memcpy(out, d, 20);
  return NQOK;
}

/* the stub: every signature verifies */
static const nqxops fzops = {fzyes, fzsha1, NULL};

/* The seed nqencd takes for alg: m (ML-KEM), m || salt (HQC). */
static inline size_t fzeseed(int alg) {
  switch (alg) {
  case NQHQC128:
    return 32;
  case NQHQC192:
    return 40;
  case NQHQC256:
    return 48;
  default:
    return 32;
  }
}

/* ---- cutting an input ---- */

typedef struct {
  const uint8_t *p;
  size_t n;
} fzin;

/* One byte (0 when the input is used up). */
static inline unsigned fzbyte(fzin *in) {
  unsigned b;
  if (in->n == 0) return 0;
  b = in->p[0];
  in->p++;
  in->n--;
  return b;
}

/* The next piece: a two-byte big-endian length, then that many bytes
 * (fewer when the input ends first). */
static inline const uint8_t *fzpart(fzin *in, size_t *n) {
  size_t k = (size_t)fzbyte(in) << 8;
  const uint8_t *p;
  k |= fzbyte(in);
  if (k > in->n) k = in->n;
  p = in->p;
  in->p += k;
  in->n -= k;
  *n = k;
  return p;
}

/* A fresh copy of exactly n bytes (one for n 0), so that ASan sees a
 * read past the end of each piece; free() it. NULL only when out of
 * memory. */
static inline uint8_t *fzdup(const uint8_t *p, size_t n) {
  uint8_t *b = (uint8_t *)malloc(n != 0 ? n : 1);
  if (b != NULL && n != 0) memcpy(b, p, n);
  return b;
}

#endif /* NQFZ_H */
