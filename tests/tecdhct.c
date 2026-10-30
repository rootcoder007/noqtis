/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of the ECDH scalar multiplication (nqecsm,
 * src/cls/ec.c): the fixed-window ladder, the table select and the
 * inversion by Fermat. With -DNQCTGRIND the scalar is marked undefined
 * for valgrind (memcheck reports any branch or index on it); without it
 * the same calls run as a plain test, checked against nqecpub. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "cls/cls.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

static void one(int crv, size_t nb) {
  uint8_t k[48], pk[97], p[97], x[48], y[48], z[48];
  uint32_t f;
  NQTEQI(nqeckg(crv, k, pk), NQOK);
  NQTEQI(nqeckg(crv, z, p), NQOK);
  /* k G, then k P for another point P */
  SECRET(k, nb);
  f = nqecsm(crv, k, NULL, x, y);
  PUBLIC(&f, sizeof f);
  PUBLIC(x, nb);
  PUBLIC(y, nb);
  NQTEQI(f, 1);
  NQTEQM(x, pk + 1, nb);
  NQTEQM(y, pk + 1 + nb, nb);
  SECRET(k, nb);
  f = nqecsm(crv, k, p, x, NULL);
  PUBLIC(&f, sizeof f);
  PUBLIC(x, nb);
  PUBLIC(k, nb);
  NQTEQI(f, 1);
  NQTEQI(nqecdh(crv, z, pk, 1 + 2 * nb, y), NQOK);
  NQTEQM(x, y, nb);
}

int main(void) {
  one(NQP256, 32);
  one(NQP384, 48);
  return nqtdone("tecdhct");
}
