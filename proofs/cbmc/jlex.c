/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* CBMC harness: the JSON reader's lexers (src/core/json.c, included here
 * for its static functions) on every input of up to N bytes: skipws,
 * then the token at that place: a string (rdstr, with its escapes and
 * raw UTF-8 through utf8len; a \u escape needs more than 4 bytes), a
 * number (rdnum) or a literal (rdword). No access out of bounds or
 * overflow; a token read stays inside the input; a decoded string is
 * shorter than its raw text and NUL-terminated; nothing leaks
 * (--memory-leak-check). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/json.c"

#ifndef N
#define N 4
#endif

size_t nondet_size(void);

void *nqmal(size_t size) {
  return size == 0 ? NULL : malloc(size);
}

void nqfree(void *ptr, size_t size) {
  (void)size;
  free(ptr);
}

int main(void) {
  unsigned char *s;
  size_t at;
  lexer lx;
  nqjs *v = NULL;
  /* exactly lx.len bytes, nondeterministic */
  lx.len = nondet_size();
  lx.pos = 0;
  __CPROVER_assume(lx.len <= N);
  s = (unsigned char *)malloc(lx.len);
  __CPROVER_assume(s != NULL);
  lx.s = s;
  skipws(&lx);
  __CPROVER_assert(lx.pos <= lx.len, "skipws stays inside the input");
  if (lx.pos >= lx.len) {
    free(s);
    return 0;
  }
  at = lx.pos;
  if (s[at] == '"') {
    char *o = NULL;
    size_t ol = 0;
    if (rdstr(&lx, &o, &ol) == NQOK) {
      __CPROVER_assert(lx.pos <= lx.len && ol + 2 <= lx.pos - at,
                       "a string is no longer than its raw text");
      __CPROVER_assert(o[ol] == 0, "a string is NUL-terminated");
      nqfree(o, ol + 1);
    } else {
      __CPROVER_assert(lx.pos <= lx.len, "an error offset is inside");
    }
  } else if (s[at] == '-' || isdig(s[at])) {
    if (rdnum(&lx, &v) == NQOK) {
      __CPROVER_assert(lx.pos <= lx.len && v->len == lx.pos - at,
                       "a number's text is what was read");
      nqjfree(v);
    }
  } else if (s[at] == 'f') {
    if (rdword(&lx, "false", NQJFALSE, &v) == NQOK) {
      __CPROVER_assert(lx.pos == at + 5, "a literal is read whole");
      nqjfree(v);
    }
  }
  free(s);
  return 0;
}
