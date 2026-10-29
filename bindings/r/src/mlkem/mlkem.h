/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-KEM-512/768/1024 (FIPS 203); internal API, not part of noqtis.h.
 *
 * k is the module rank: 2 (ML-KEM-512), 3 (ML-KEM-768), 4 (ML-KEM-1024).
 * Keys and ciphertexts are the byte strings FIPS 203 defines; the
 * decapsulation key is dk_PKE || ek || H(ek) || z.
 *
 * Every function returns NQOK or a negative NQE* code:
 *   NQEARG  k is not 2, 3 or 4, a pointer is NULL, or a seed / message
 *           has the wrong length
 *   NQEDEC  an input key or ciphertext has the wrong length or fails the
 *           input checks of FIPS 203 section 7 (encapsulation key
 *           modulus check, decapsulation key hash check)
 *   NQEBUF  an output buffer is too small (larger ones are fine; only
 *           the defined number of bytes is written)
 *   NQERNG  the operating system's random source failed
 * On any failure the outputs are zeroed.
 *
 * Decapsulation is constant time; nqmkdec is first-order masked as well
 * (every value that depends on the decapsulation key is held as two
 * shares, refreshed from the random source on every call). nqmkdecp is
 * the plain constant-time decapsulation, kept for testing and for
 * callers without a random source; both return the same secret for
 * every input. A ciphertext that does not re-encrypt to itself yields
 * the implicit-rejection secret J(z || c) and NQOK. */
#ifndef NQMLKEM_H
#define NQMLKEM_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQMKSEED 64 /* d || z */
#define NQMKMSG 32  /* the encapsulation randomness m */
#define NQMKSS 32   /* shared secret */

/* sizes in bytes for rank k (valid only for k = 2, 3, 4) */
#define NQMKEK(k) ((size_t)384 * (size_t)(k) + 32)
#define NQMKDK(k) ((size_t)768 * (size_t)(k) + 96)
#define NQMKCT(k) ((k) == 4 ? (size_t)1568 : (size_t)320 * (size_t)(k) + 128)

/* the largest of each, for buffers */
#define NQMKEKX 1568
#define NQMKDKX 3168
#define NQMKCTX 1568

/* The rank of a public algorithm identifier; 0 when it is not ML-KEM. */
static inline int nqmkk(nqkalg alg) {
  return alg == NQMLKEM512 ? 2 : alg == NQMLKEM768 ? 3
       : alg == NQMLKEM1024 ? 4 : 0;
}

/* ML-KEM.KeyGen_internal(d, z) with seed = d || z (64 bytes). */
int nqmkkgd(int k, const uint8_t *seed, size_t seedlen, uint8_t *ek,
            size_t eklen, uint8_t *dk, size_t dklen);
/* ML-KEM.KeyGen with d and z from nqrand. */
int nqmkkg(int k, uint8_t *ek, size_t eklen, uint8_t *dk, size_t dklen);

/* ML-KEM.Encaps_internal(ek, m), m 32 bytes, after the input checks. */
int nqmkencd(int k, const uint8_t *ek, size_t eklen, const uint8_t *m,
             size_t mlen, uint8_t *ct, size_t ctlen, uint8_t *ss,
             size_t sslen);
/* ML-KEM.Encaps with m from nqrand. */
int nqmkenc(int k, const uint8_t *ek, size_t eklen, uint8_t *ct,
            size_t ctlen, uint8_t *ss, size_t sslen);

/* ML-KEM.Decaps, masked (the default). */
int nqmkdec(int k, const uint8_t *dk, size_t dklen, const uint8_t *ct,
            size_t ctlen, uint8_t *ss, size_t sslen);
/* ML-KEM.Decaps, constant time but not masked. */
int nqmkdecp(int k, const uint8_t *dk, size_t dklen, const uint8_t *ct,
             size_t ctlen, uint8_t *ss, size_t sslen);

/* The input checks alone: NQOK, or NQEDEC (NQEARG for a bad k / NULL).
 * nqmkekc: length and modulus check (FIPS 203 7.2);
 * nqmkdkc: length and hash check (FIPS 203 7.3). */
int nqmkekc(int k, const uint8_t *ek, size_t eklen);
int nqmkdkc(int k, const uint8_t *dk, size_t dklen);

#endif /* NQMLKEM_H */
