/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* For the harnesses: whether an ML-DSA signature takes one attempt. The
 * number of attempts is public (a signature's time shows it), so the
 * harnesses compare inputs that sign in one attempt and ask whether
 * anything else differs. */
#ifndef NQMD1_H
#define NQMD1_H

#include <string.h>

#include "hash/h.h"
#include "mldsa/md.h"

/* 1 when signing mu under (sk, rnd) is accepted at its first attempt:
 * the signature's c~ equals H(mu || w1) of attempt 0, recomputed here */
static int first(const nqmdp *p, const uint8_t *sk, const uint8_t *mu,
                 const uint8_t *rnd) {
  static nqmdpl s1[NQMDL], s2[NQMDK], t0[NQMDK], y[NQMDL], w[NQMDK];
  uint8_t rho[32], key[32], rhop[64], wb[NQMDK * 192], c0[64];
  uint8_t sig[NQMDSIGMAX];
  nqkctx c;
  unsigned i, j;
  int32_t lo;
  if (nqmdspl(p, sk, mu, rnd, sig) != NQOK) return 0;
  nqmdsku(p, sk, rho, key, s1, s2, t0);
  nqshkini(&c, 256);
  nqkabs(&c, key, 32);
  nqkabs(&c, rnd, 32);
  nqkabs(&c, mu, NQMDMU);
  nqksqz(&c, rhop, 64);
  for (i = 0; i < p->l; i++) {
    nqmdmask(p, y[i].c, rhop, (uint16_t)i);
    nqmdntt(y[i].c);
  }
  nqmdmat(p, rho, w, y, NULL, NULL);
  for (i = 0; i < p->k; i++) {
    nqmdred(w[i].c);
    nqmdint(w[i].c);
    nqmdcadd(w[i].c);
    for (j = 0; j < NQMDN; j++) w[i].c[j] = nqmddec(p, &lo, w[i].c[j]);
    nqmdw1p(p, wb + i * 32 * p->w1b, w[i].c);
  }
  nqshkini(&c, 256);
  nqkabs(&c, mu, NQMDMU);
  nqkabs(&c, wb, (size_t)p->k * 32 * p->w1b);
  nqksqz(&c, c0, p->ctl);
  return memcmp(c0, sig, p->ctl) == 0;
}

#endif /* NQMD1_H */
