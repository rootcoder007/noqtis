/* A minimal test harness: no dependencies, prints each failure with its
 * line, and main() returns nonzero on any failure (ctest sees it). */
#ifndef NQT_H
#define NQT_H

#include <stdio.h>
#include <string.h>

static int nqtfail = 0;
static int nqtn = 0;

#define NQTCHK(cond)                                                        \
  do {                                                                      \
    nqtn++;                                                                 \
    if (!(cond)) {                                                          \
      nqtfail++;                                                            \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,      \
              #cond);                                                       \
    }                                                                       \
  } while (0)

#define NQTEQI(a, b)                                                        \
  do {                                                                      \
    long nqta = (long)(a), nqtb = (long)(b);                                \
    nqtn++;                                                                 \
    if (nqta != nqtb) {                                                     \
      nqtfail++;                                                            \
      fprintf(stderr, "%s:%d: %s == %ld, expected %ld\n", __FILE__,         \
              __LINE__, #a, nqta, nqtb);                                    \
    }                                                                       \
  } while (0)

#define NQTEQM(a, b, n)                                                     \
  do {                                                                      \
    nqtn++;                                                                 \
    if (memcmp((a), (b), (n)) != 0) {                                       \
      nqtfail++;                                                            \
      fprintf(stderr, "%s:%d: %s differs from %s\n", __FILE__, __LINE__,    \
              #a, #b);                                                      \
    }                                                                       \
  } while (0)

static inline int nqtdone(const char *name) {
  printf("%s: %d checks, %d failed\n", name, nqtn, nqtfail);
  return nqtfail == 0 ? 0 : 1;
}

#endif /* NQT_H */
