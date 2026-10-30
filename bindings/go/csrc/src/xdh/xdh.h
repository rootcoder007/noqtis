/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X25519 (RFC 7748 section 5), for the TLS 1.3 key exchange; internal
 * API, not part of noqtis.h.
 *
 * The field GF(2^255 - 19) is held in ten unsigned limbs of 26 and 25
 * bits alternately (radix 2^25.5), multiplied with 32 x 32 -> 64-bit
 * products; every value stays non-negative (a subtraction adds 4p
 * first), so no shift ever sees a negative number. The ladder swaps
 * under a mask and inverts with a fixed exponent: time depends on
 * neither the scalar nor the point. */
#ifndef NQXDH_H
#define NQXDH_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQX25519 32 /* scalar, point and shared secret bytes */

/* ctgrind (tests/txdhct.c): whether the shared secret is all zero is
 * public (the peer chose the point), so it is declared defined before
 * the code branches on it. A no-op otherwise. */
#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQXPUB(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define NQXPUB(p, n) ((void)0)
#endif

/* out = X25519(k, u): the scalar is clamped and the top bit of u
 * masked, as RFC 7748 says. NQEVRFY when out is all zero (u of small
 * order; RFC 8446 section 7.4.2 requires the abort), NQEARG for a NULL
 * pointer. out may be k or u. */
int nqx25519(uint8_t *out, const uint8_t *k, const uint8_t *u);
/* pk = X25519(sk, 9), the public key of sk. */
int nqx25519b(uint8_t *pk, const uint8_t *sk);

/* ---- X25519MLKEM768 (hyb.c) ---- */

#define NQHYBEK (1184 + 32)  /* the client's share: ML-KEM-768 ek, X25519 */
#define NQHYBCT (1088 + 32)  /* the server's: ML-KEM-768 ct, X25519 */
#define NQHYBSK (2400 + 32)  /* ML-KEM-768 dk, then the X25519 scalar */
#define NQHYBSS 64           /* ML-KEM secret, then X25519 secret */

/* A key pair from the ML-KEM seed d || z (64 bytes) and the X25519
 * scalar x; nqhybkg draws the seed from nqrand. */
int nqhybkgd(const uint8_t *seed, const uint8_t *x, uint8_t *ek,
             uint8_t *sk);
int nqhybkg(const uint8_t *x, uint8_t *ek, uint8_t *sk);
/* The server's side, for the tests: encapsulates to ek (ekn bytes) with
 * the ML-KEM randomness m (32 bytes) and the X25519 scalar x. */
int nqhybencd(const uint8_t *ek, size_t ekn, const uint8_t *m,
              const uint8_t *x, uint8_t *ct, uint8_t *ss);
/* The client's: NQEDEC for a share of the wrong length, NQEVRFY when
 * the X25519 part is of small order (ss is then zero); a bad ML-KEM
 * ciphertext yields the implicit-rejection secret, as FIPS 203 says. */
int nqhybdec(const uint8_t *sk, const uint8_t *ct, size_t ctn,
             uint8_t *ss);

#endif /* NQXDH_H */
