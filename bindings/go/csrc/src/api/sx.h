/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The version 2 secret-key container (docs/spec/keyfile.md), inside the
 * library: X = S || P || T, P the Ed25519 public key for Ed25519 and the
 * hybrids, T = SHA3-256("noqtis-sk-2" || 0x00 || alg || 0x00 || S || P). */
#ifndef NQSX_H
#define NQSX_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* 1 when n is the length of alg's secret key S or of its container X */
int nqsxlen(nqsalg alg, size_t n);
/* The length of S when n is that of X, else n */
size_t nqsxs(nqsalg alg, size_t n);
/* After a signature of n bytes was made from the container x (xlen
 * bytes): T computed again and compared, and for Ed25519 and the hybrids
 * the public key derived again and compared with P; sig leaves only
 * through nqrel's mask of those verdicts. NQOK, or NQEFLT with sig zero.
 * A key of S's length (no container) is NQOK and leaves sig as it is. */
int nqsxrel(nqsalg alg, const uint8_t *x, size_t xlen, uint8_t *sig,
            size_t n);
/* The result of a signing call with the container x, rc the signer's:
 * after NQOK, nqsxrel's; after NQEDEC (S did not decode, as when a stored
 * coefficient was changed out of range), NQEFLT when the integrity value
 * does not hold either, so that a changed key is always NQEFLT; anything
 * else as it was. sig is zero unless NQOK. */
int nqsxend(nqsalg alg, const uint8_t *x, size_t xlen, uint8_t *sig,
            size_t n, int rc);

#endif /* NQSX_H */
