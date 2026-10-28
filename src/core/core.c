/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Error strings, version, wiping, constant-time comparison, allocator. */
#include "noqtis.h"
#include "core/int.h"

#include <stdlib.h>

#define NQSTR2(x) #x
#define NQSTR(x) NQSTR2(x)

const char *nqver(void) {
  return NQSTR(NQVMAJ) "." NQSTR(NQVMIN) "." NQSTR(NQVPAT);
}

const char *nqerr(int err) {
  switch (err) {
  case NQOK: return "success";
  case NQEARG: return "invalid argument";
  case NQEBUF: return "output buffer too small";
  case NQEVRFY: return "verification failed";
  case NQEDEC: return "input is not in the encoding the standard defines";
  case NQERNG: return "the operating system's random source failed";
  case NQEMEM: return "out of memory";
  case NQEIO: return "file could not be read or written";
  case NQENOSUP: return "algorithm or option not supported";
  case NQELIM: return "input exceeds a size or depth limit";
  case NQESTATE: return "context used out of order";
  default: return "unknown error";
  }
}

/* Stores through a volatile pointer cannot be removed as dead stores. */
void nqwipe(void *p, size_t len) {
  volatile unsigned char *v = (volatile unsigned char *)p;
  if (p == NULL) {
    return;
  }
  while (len--) {
    *v++ = 0;
  }
}

int nqcteq(const void *a, const void *b, size_t len) {
  const unsigned char *x = (const unsigned char *)a;
  const unsigned char *y = (const unsigned char *)b;
  unsigned char d = 0;
  size_t i;
  for (i = 0; i < len; i++) {
    d = (unsigned char)(d | (x[i] ^ y[i]));
  }
  /* 1 when d == 0, without a branch on d */
  return (int)(1u & (((unsigned int)d - 1u) >> 8));
}

/* ---- allocator hook ---- */

static void *defmal(size_t size, void *user) {
  (void)user;
  return malloc(size);
}

static void deffree(void *ptr, size_t size, void *user) {
  (void)user;
  (void)size;
  free(ptr);
}

static nqmalfn curmal = defmal;
static nqfreefn curfree = deffree;
static void *curuser = NULL;

int nqsetal(nqmalfn mal, nqfreefn fre, void *user) {
  if (mal == NULL && fre == NULL) {
    curmal = defmal;
    curfree = deffree;
    curuser = NULL;
    return NQOK;
  }
  if (mal == NULL || fre == NULL) {
    return NQEARG;
  }
  curmal = mal;
  curfree = fre;
  curuser = user;
  return NQOK;
}

void *nqmal(size_t size) {
  if (size == 0) {
    return NULL;
  }
  return curmal(size, curuser);
}

void nqfree(void *ptr, size_t size) {
  if (ptr == NULL) {
    return;
  }
  /* freed memory may hold secrets: wipe it first */
  nqwipe(ptr, size);
  curfree(ptr, size, curuser);
}
