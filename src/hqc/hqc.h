/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC-KEM, HQC-128/192/256 as the specification of 2025-08-22 defines
 * them (reference implementation v5.0.0, the version NIST selected).
 * Internal interface; the public nqkkg / nqenc / nqdec dispatch here.
 *
 * Encodings: pk = seed_ek || s; sk = pk || seed_dk || sigma || seed_kem;
 * ct = u || v || salt; the shared secret is 32 bytes.
 *
 * Every function takes the buffer lengths. Returns: NQOK; NQEARG for an
 * alg that is not HQC, a NULL pointer or a seed of the wrong length;
 * NQEBUF for an output buffer that is too small; NQEDEC for an input key
 * or ciphertext of the wrong length, a public key with bits set past the
 * code length, or a secret key whose seeds do not derive from each other.
 * A ciphertext of the right length always decapsulates (implicit
 * rejection): a bad one gives a pseudorandom secret and NQOK. */
#ifndef NQHQC_H
#define NQHQC_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* byte lengths: public key, secret key, ciphertext, message (m) */
#define NQHQPK1 2241
#define NQHQSK1 2321
#define NQHQCT1 4433
#define NQHQM1 16
#define NQHQPK3 4514
#define NQHQSK3 4602
#define NQHQCT3 8978
#define NQHQM3 24
#define NQHQPK5 7237
#define NQHQSK5 7333
#define NQHQCT5 14421
#define NQHQM5 32
#define NQHQSEED 32  /* key-generation seed */
#define NQHQSALT 16
#define NQHQSS 32    /* shared secret */

/* the sizes of alg (NQHQC128, NQHQC192, NQHQC256) */
int nqhqsz(nqkalg alg, nqksz *sz);

/* Key generation from a 32-byte seed (seed_kem), and from nqrand. */
int nqhqkgd(nqkalg alg, const uint8_t *seed, size_t seedlen,
            uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqhqkg(nqkalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
           size_t sklen);

/* Encapsulation; seed is m || salt (NQHQM* + 16 bytes). */
int nqhqencd(nqkalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *seed, size_t seedlen,
             uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
int nqhqenc(nqkalg alg, const uint8_t *pk, size_t pklen,
            uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

/* Decapsulation with implicit rejection. */
int nqhqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

#endif /* NQHQC_H */
