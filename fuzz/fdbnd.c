/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The bundle reader (qdbread, under nqdunpack): any bytes. Every entry
 * it hands on must have a path a capsule holds, after the one before,
 * and exactly its stated size in bytes, all within the input; the
 * reader must end (or refuse) within the input. Nothing is written. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../nqd/int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
  const uint8_t *p;
  size_t n, at;
} mem;

typedef struct {
  char prev[4097];
  int have, open;
  uint64_t left, total;
  size_t n;
} seen;

static int mrd(void *u, uint8_t *b, size_t n, size_t *got) {
  mem *m = (mem *)u;
  size_t k = m->n - m->at < n ? m->n - m->at : n;
  memcpy(b, m->p + m->at, k);
  m->at += k;
  *got = k;
  return NQOK;
}

static int put(void *v, int op, const char *path, uint64_t size,
               const uint8_t *b, size_t n) {
  seen *s = (seen *)v;
  char t[4200];
  (void)b;
  if (op == QDBBEG) {
    if (s->open || strlen(path) > 4096 ||
        qdjoin(".", path, t, sizeof t) != NQOK ||
        (s->have && strcmp(s->prev, path) >= 0))
      abort();
    memcpy(s->prev, path, strlen(path) + 1);
    s->have = s->open = 1;
    s->left = size;
  } else if (op == QDBDAT) {
    if (!s->open || n == 0 || n > s->left)
      abort();
    s->left -= n;
    s->total += n;
  } else {
    if (!s->open || s->left != 0)
      abort();
    s->open = 0;
  }
  return NQOK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mem m;
  qdbio io;
  seen *s = (seen *)calloc(1, sizeof *s);
  char why[300];
  int rc;
  if (s == NULL)
    return 0;
  m.p = data;
  m.n = size;
  m.at = 0;
  io.rd = mrd;
  io.u = &m;
  io.put = put;
  io.s = s;
  rc = qdbread(&io, why, sizeof why);
  if (s->total > size || m.at > size || (rc == NQOK && s->open))
    abort();
  if (rc != NQOK && rc != NQEDEC && rc != NQELIM)
    abort();
  free(s);
  return 0;
}
