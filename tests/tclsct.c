/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of the src/cls bignum core. The verifiers handle
 * only public data, but the Montgomery arithmetic is written to be
 * constant time in its operands (only the exponent of nqcpw and the limb
 * count are public), so a later signer can reuse it. With -DNQCTGRIND the
 * operands are marked undefined for valgrind (memcheck reports any branch
 * or index on them); without it the same calls run as a plain test. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "cls/bn.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

/* Runs the core operations modulo m on secret a and b; returns 1 when
 * from(to(a)) == a and (a + b) - b == a. */
static int core(const nqcmod *m, uint32_t *a, uint32_t *b) {
  uint32_t x[NQBL], y[NQBL], z[NQBL], e[1] = {65537};
  uint8_t by[4 * NQBL];
  uint32_t f1, f2, f3, f4;
  size_t nl = m->nl;
  int ok;
  SECRET(a, nl * sizeof *a);
  SECRET(b, nl * sizeof *b);
  nqcto(x, a, m);
  nqcmm(y, x, b, m);
  nqcpw(z, x, e, 1, m);
  nqcad(y, y, z, m);
  nqcsu(y, y, z, m);
  nqcfr(z, x, m);
  nqcad(x, a, b, m);
  nqcsu(x, x, b, m);
  f1 = nqclt(a, b, nl);
  f2 = nqceq(x, a, nl);
  f3 = nqcz(a, nl);
  f4 = nqceq(z, a, nl);
  nqcst(by, 4 * nl, y, nl);
  nqcld(y, nl, by, 4 * nl);
  nqcsb(y, y, a, nl);
  PUBLIC(&f1, sizeof f1);
  PUBLIC(&f2, sizeof f2);
  PUBLIC(&f3, sizeof f3);
  PUBLIC(&f4, sizeof f4);
  PUBLIC(a, nl * sizeof *a);
  PUBLIC(b, nl * sizeof *b);
  ok = f2 == 1 && f4 == 1 && f3 == 0 && f1 == nqclt(a, b, nl);
  return ok;
}

int main(void) {
  uint32_t v[NQBL], a[NQBL], b[NQBL];
  nqcmod m;
  size_t i, k;
  static const size_t sizes[] = {8, 12, 64, 96, 128};
  for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
    size_t nl = sizes[k];
    uint32_t s = 0x9e3779b9u * (uint32_t)(k + 1);
    for (i = 0; i < nl; i++) {
      s = s * 1664525u + 1013904223u;
      v[i] = s;
      s = s * 1664525u + 1013904223u;
      a[i] = s >> 1;
      s = s * 1664525u + 1013904223u;
      b[i] = s >> 1;
    }
    v[0] |= 1;
    v[nl - 1] |= 0x80000000u;
    nqcmset(&m, v, nl);
    NQTCHK(core(&m, a, b));
  }
  return nqtdone("tclsct");
}
