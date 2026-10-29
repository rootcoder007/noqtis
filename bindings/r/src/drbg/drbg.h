/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HMAC_DRBG (NIST SP 800-90A Rev. 1, section 10.1.2) with SHA-256 or
 * SHA-512, no derivation function. Internal; not part of the public API.
 *
 * Both hashes give a security strength of 256 bits, so the entropy input
 * is at least 32 bytes and the nonce at least 16 (section 8.6.7). Entropy,
 * nonce, personalization and additional input are at most 2^32 bytes
 * (2^35 bits), a request at most NQDMAXB bytes (2^19 bits), and the
 * reseed interval is 2^48 requests (table 2).
 *
 * The state is secret. A struct must be zeroed (or nqdfree'd) before its
 * first nqdini or nqdseed: every other call refuses a struct that is not
 * instantiated with NQESTATE. Nothing allocates. */
#ifndef NQDRBG_H
#define NQDRBG_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"
#include "hash/h.h"

#define NQDMAXB 65536u                    /* bytes per request */
#define NQDMAXR ((uint64_t)1 << 48)       /* reseed interval */
#define NQDMAXL ((uint64_t)1 << 32)       /* bytes of any input */
#define NQDENT 32u                        /* minimum entropy input */
#define NQDNON 16u                        /* minimum nonce */

typedef struct {
  uint8_t k[NQHMAX];  /* Key */
  uint8_t v[NQHMAX];  /* V */
  uint64_t rc;        /* reseed_counter */
  nqhalg alg;         /* NQS256 or NQS512 */
  size_t n;           /* outlen in bytes: 32 or 64 */
  uint32_t ok;        /* NQDLIVE while instantiated */
  int pr;             /* prediction_resistance_flag */
  int own;            /* 1: entropy from nqrand (nqdseed) */
} nqdrbg;

#define NQDLIVE 0x6e716472u

/* Instantiate (9.1, 10.1.2.3) from caller-supplied entropy and nonce,
 * with an optional personalization string (ps NULL when pslen is 0).
 * pr != 0 enables prediction resistance (nqdgenp). On any error d is
 * wiped and left uninstantiated. NQEARG, NQENOSUP (another hash),
 * NQELIM (too long). */
int nqdini(nqdrbg *d, nqhalg alg, const uint8_t *ent, size_t entlen,
           const uint8_t *non, size_t nonlen, const uint8_t *ps,
           size_t pslen, int pr);

/* Instantiate from nqrand: 48 bytes of entropy and a 16-byte nonce. Such
 * a DRBG reseeds itself from nqrand when the counter runs out and, with
 * pr != 0, before every request. NQERNG when nqrand fails. */
int nqdseed(nqdrbg *d, nqhalg alg, const uint8_t *ps, size_t pslen,
            int pr);

/* Reseed (9.2, 10.1.2.4) with caller-supplied entropy and optional
 * additional input. Resets the reseed counter. */
int nqdres(nqdrbg *d, const uint8_t *ent, size_t entlen,
           const uint8_t *add, size_t addlen);

/* Generate (9.3, 10.1.2.5) outlen bytes, without a prediction-resistance
 * request, with optional additional input. NQESTATE when the counter has
 * passed NQDMAXR and d cannot reseed itself (reseed with nqdres first);
 * out is zeroed on that and on NQERNG. */
int nqdgen(nqdrbg *d, uint8_t *out, size_t outlen, const uint8_t *add,
           size_t addlen);

/* Generate with a prediction-resistance request (9.3.1 step 7): reseeds
 * with ent and add, then generates with no additional input. NQESTATE when
 * d was instantiated without prediction resistance. */
int nqdgenp(nqdrbg *d, uint8_t *out, size_t outlen, const uint8_t *add,
            size_t addlen, const uint8_t *ent, size_t entlen);

/* Uninstantiate (9.4): wipes the whole state. d may be NULL. */
void nqdfree(nqdrbg *d);

#endif /* NQDRBG_H */
