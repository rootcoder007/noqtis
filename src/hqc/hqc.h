/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC-KEM, HQC-128/192/256 as the specification version 5.1 of
 * 2026-11-09 defines them (reference implementation v5.1.0). Keys and
 * ciphertexts of version 5.0 are not read: a 5.0 secret key has another
 * length (NQEDEC); a 5.0 public key or ciphertext has the same length as
 * a 5.1 one and cannot be told apart by it.
 * Internal interface; the public nqkkg / nqenc / nqdec dispatch here.
 *
 * Encodings: pk = seed_ek || s; sk = seed_kem (32 bytes);
 * ct = u || v || salt; the shared secret is 32 bytes.
 *
 * Every function takes the buffer lengths. Returns: NQOK; NQEARG for an
 * alg that is not HQC, a NULL pointer or a seed of the wrong length;
 * NQEBUF for an output buffer that is too small; NQEDEC for an input key
 * or ciphertext of the wrong length or a public key with bits set past the
 * code length (any 32 bytes are a secret key).
 * A ciphertext of the right length always decapsulates (implicit
 * rejection): a bad one gives a pseudorandom secret and NQOK. */
#ifndef NQHQC_H
#define NQHQC_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* byte lengths: public key, secret key, ciphertext, message (m) */
#define NQHQPK1 2241
#define NQHQSK1 32
#define NQHQCT1 4433
#define NQHQM1 16
#define NQHQPK3 4514
#define NQHQSK3 32
#define NQHQCT3 8978
#define NQHQM3 24
#define NQHQPK5 7237
#define NQHQSK5 32
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

/* Decapsulation with implicit rejection, first-order masked (the
 * default); nqhqdecp is the same, constant time but not masked. */
int nqhqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
int nqhqdecp(nqkalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

#endif /* NQHQC_H */
