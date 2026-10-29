/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the strict JSON reader (src/core/json.c) and the
 * canonical writer (RFC 8785, src/cap/jw.c). Whatever parses is written
 * canonically; that text must parse again and write to the same bytes
 * (the writer is a fixed point), and every lookup is tried on the tree. */
#include "fz.h"
#include "cap/cap.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

/* the accessors on every node, without recursion */
static void touch(const nqjs *root) {
  const nqjs *st[NQJDEPTH + 2];
  size_t d = 0;
  st[d++] = root;
  while (d > 0) {
    const nqjs *v = st[--d];
    int64_t x;
    size_t i;
    (void)nqjstr(v);
    (void)nqjint(v, &x);
    (void)nqjbool(v);
    if (v->type == NQJNUM) {
      nqcbuf b;
      memset(&b, 0, sizeof b);
      (void)nqcjnum(&b, v->str, v->len);
      nqcbfree(&b);
    }
    if (v->type == NQJSTR) {
      (void)nqcutf8(v->str, v->len);
      (void)nqcname(v->str, v->len);
      (void)nqctchk(v->str, v->len);
    }
    if (v->type == NQJOBJ && v->n > 0) {
      /* a lookup of the first key finds a child; keys may hold NUL */
      if (memchr(v->keys[0], 0, v->klen[0]) == NULL) {
        if (nqjget(v, v->keys[0]) == NULL) abort();
      }
      (void)nqjget(v, "");
    }
    for (i = 0; i < v->n && d < sizeof st / sizeof st[0]; i++) {
      if (v->type == NQJARR && nqjat(v, i) != v->kids[i]) abort();
      st[d++] = v->kids[i];
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqjs *v = NULL, *w = NULL;
  nqcbuf a, b;
  size_t off = 0;
  int rc;
  if (nqjparse((const char *)data, size, &v, &off) != NQOK) {
    if (off > size) abort();
    return 0;
  }
  touch(v);
  memset(&a, 0, sizeof a);
  memset(&b, 0, sizeof b);
  rc = nqcjval(&a, v);
  if (rc == NQOK) {
    /* canonical output is JSON and a fixed point of the writer */
    if (nqjparse(a.p, a.n, &w, NULL) != NQOK) abort();
    if (nqcjval(&b, w) != NQOK || b.n != a.n || memcmp(a.p, b.p, a.n) != 0) {
      abort();
    }
  }
  nqcbfree(&a);
  nqcbfree(&b);
  nqjfree(w);
  nqjfree(v);
  return 0;
}
