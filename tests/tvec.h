/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Shared by the AEAD, X25519, HKDF and TLS tests: Wycheproof JSON files
 * and hex fields, read with the library's own strict JSON reader. */
#ifndef NQTVEC_H
#define NQTVEC_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"

/* A JSON file as a tree (free with nqjfree); NULL when it cannot be
 * read or parsed. */
static inline nqjs *tvjs(const char *path) {
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc = nqreadf(path, (size_t)1 << 28, &buf, &len);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot read (%s)\n", path, nqerr(rc));
    return NULL;
  }
  rc = nqjparse(buf, len, &v, NULL);
  nqfree(buf, len + 1);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot parse (%s)\n", path, nqerr(rc));
    return NULL;
  }
  return v;
}

/* A hex field into a fresh buffer of at least one byte (free it); NULL
 * when the field is absent or not hex. */
static inline uint8_t *tvhex(const nqjs *v, size_t *n) {
  const char *s = nqjstr(v);
  size_t len;
  uint8_t *b;
  *n = 0;
  if (s == NULL) return NULL;
  len = strlen(s);
  b = (uint8_t *)calloc(len / 2 + 1, 1);
  if (b == NULL) return NULL;
  if (nqunhex(s, len, b, len / 2 + 1, n) != NQOK) {
    free(b);
    return NULL;
  }
  return b;
}

/* A hex string literal into b (at most cap bytes); the byte count. */
static inline size_t tvlit(const char *hex, uint8_t *b, size_t cap) {
  size_t n = 0;
  if (nqunhex(hex, strlen(hex), b, cap, &n) != NQOK) return 0;
  return n;
}

#endif /* NQTVEC_H */
