/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Shared by the BLAKE2b, Argon2, key file and sealed-message tests: a
 * vector file of records, each a run of "name=value" lines ended by a
 * blank line or the end of the file; lines starting with '#' (the
 * file's header, which says where its values come from) are skipped.
 * A line may also be "name:" and a tab or space before the value, the
 * layout of the BLAKE2 reference's KAT files. Values are hex or
 * decimal; at most 16 names a record, 16 KiB a line. */
#ifndef NQTKV_H
#define NQTKV_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"

#define TKVN 16
#define TKVL 16384

typedef struct {
  FILE *f;
  int n;
  char name[TKVN][16];
  char val[TKVN][TKVL];
} tkv;

/* Opens vectors/<rel>; 0 when it cannot be read. */
static inline int tkvopen(tkv *k, const char *rel) {
  char p[512];
  snprintf(p, sizeof p, "vectors/%s", rel);
  k->f = fopen(p, "rb");
  if (k->f == NULL) fprintf(stderr, "%s: cannot read\n", p);
  return k->f != NULL;
}

/* The next record; 0 at the end of the file. */
static inline int tkvnext(tkv *k) {
  static char line[TKVL + 32];
  k->n = 0;
  while (fgets(line, sizeof line, k->f) != NULL) {
    size_t l = strlen(line);
    char *eq;
    while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) {
      line[--l] = '\0';
    }
    if (line[0] == '#') continue;
    if (l == 0) {
      if (k->n > 0) return 1;
      continue;
    }
    eq = strchr(line, '=');
    if (eq == NULL) eq = strchr(line, ':');
    if (eq == NULL || k->n == TKVN || (size_t)(eq - line) >= 16 ||
        strlen(eq + 1) >= TKVL) {
      fprintf(stderr, "vector file: bad line %.40s\n", line);
      continue;
    }
    *eq = '\0';
    memcpy(k->name[k->n], line, (size_t)(eq - line) + 1);
    eq++;
    while (*eq == ' ' || *eq == '\t') eq++;
    memcpy(k->val[k->n], eq, strlen(eq) + 1);
    k->n++;
  }
  return k->n > 0;
}

static inline const char *tkvs(const tkv *k, const char *name) {
  int i;
  for (i = 0; i < k->n; i++) {
    if (strcmp(k->name[i], name) == 0) return k->val[i];
  }
  return NULL;
}

/* A hex value into b (cap bytes): its length, or (size_t)-1 when it is
 * absent or not hex. */
static inline size_t tkvh(const tkv *k, const char *name, uint8_t *b,
                          size_t cap) {
  const char *s = tkvs(k, name);
  size_t n = 0;
  if (s == NULL) return (size_t)-1;
  if (nqunhex(s, strlen(s), b, cap, &n) != NQOK) return (size_t)-1;
  return n;
}

static inline unsigned long tkvu(const tkv *k, const char *name) {
  const char *s = tkvs(k, name);
  return s == NULL ? 0 : strtoul(s, NULL, 10);
}

static inline void tkvclose(tkv *k) {
  if (k->f != NULL) fclose(k->f);
  k->f = NULL;
}

#endif /* NQTKV_H */
