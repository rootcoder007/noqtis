/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Leakage hooks for the simulated TVLA (ct/tv.c). Only a build with
 * -DNQTVLA has them: there every intermediate the masked code passes
 * through a hook is handed to nqlkfn (when the harness has set it), with
 * the step of the algorithm it belongs to. In every other build each
 * macro is ((void)0) and the object code is the same as without them. */
#ifndef NQLK_H
#define NQLK_H

#include <stdint.h>

/* what a recorded value is */
#define NQLKOP 1  /* a 32-bit share word through an opaque copy */
#define NQLKKC 2  /* a 64-bit share lane of the masked Keccak */
#define NQLKSH 3  /* an arithmetic share coefficient after a linear step */
#define NQLKUN 4  /* unmasked: the stored secret key as it is loaded */
#define NQLKOUT 5 /* unmasked: an output (shared secret, signature) */
#define NQLKPB 6  /* a share word ANDed with a public constant: its weight
                   * depends on the constant's, not on the secret */

#ifdef NQTVLA
/* set by the harness; NULL records nothing */
extern void (*nqlkfn)(uint64_t v, unsigned what, unsigned step);
extern unsigned nqlkst;  /* the current step */
extern unsigned nqlkatt; /* the current ML-DSA signing attempt */
extern int nqlkzm;       /* 1: every mask is zero (the unmasked control) */
extern unsigned nqlkkd;  /* when not 0, the kind of the next NQLKO value */
#define NQLK(v, w)                                                       \
  ((void)(nqlkfn != NULL ? nqlkfn((uint64_t)(v), (w), nqlkst) : (void)0))
/* an opaque copy's value: NQLKOP, or the kind NQLKKD set just before */
#define NQLKO(v)                                                         \
  ((void)(NQLK((v), nqlkkd ? nqlkkd : NQLKOP), nqlkkd = 0))
#define NQLKKD(w) ((void)(nqlkkd = (w)))
#define NQLKST(n) ((void)(nqlkst = (n)))
#define NQLKAT(n) ((void)(nqlkatt = (n)))
#define NQLKZM(r) (nqlkzm ? 0 : (r))
#else
#define NQLK(v, w) ((void)0)
#define NQLKO(v) ((void)0)
#define NQLKKD(w) ((void)0)
#define NQLKST(n) ((void)0)
#define NQLKAT(n) ((void)0)
#define NQLKZM(r) (r)
#endif

#endif /* NQLK_H */
