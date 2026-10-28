/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA (FIPS 204): the module's internal interface. alg is NQMLDSA44,
 * NQMLDSA65 or NQMLDSA87. Keys and signatures are the byte strings FIPS
 * 204 defines (pkEncode, skEncode, sigEncode).
 *
 * Errors: NQEARG for a NULL pointer, an unknown alg, a context over 255
 * bytes, an unknown pre-hash or a seed / rnd of the wrong length; NQEBUF
 * for an output buffer that is too small; NQEDEC for a key or signature
 * of the wrong length, a signature whose hint encoding is not canonical,
 * or a secret key whose s1 / s2 leave [-eta, eta]; NQEVRFY for a
 * signature that decodes but does not verify (||z|| too large, wrong
 * challenge); NQERNG when the operating system's random source fails.
 *
 * Signing is first-order masked (two shares) unless a caller of nqmdsmu
 * asks otherwise; both paths are constant time in the secret key, rnd and
 * the masks, and produce the same bytes. */
#ifndef NQMLDSA_H
#define NQMLDSA_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQMD44PK 1312
#define NQMD44SK 2560
#define NQMD44SIG 2420
#define NQMD65PK 1952
#define NQMD65SK 4032
#define NQMD65SIG 3309
#define NQMD87PK 2592
#define NQMD87SK 4896
#define NQMD87SIG 4627
#define NQMDPKMAX NQMD87PK
#define NQMDSKMAX NQMD87SK
#define NQMDSIGMAX NQMD87SIG

#define NQMDSEED 32  /* xi, the key-generation seed */
#define NQMDRND 32   /* rnd, the per-signature randomness */
#define NQMDMU 64    /* mu, the message representative */
#define NQMDCTX 255  /* the longest context string */
#define NQMDOID 11   /* DER length of a pre-hash OID */

/* nqmdsmu's msk argument */
#define NQMDPLAIN 0  /* unmasked (still constant time) */
#define NQMDMASK 1   /* first-order masked: the default everywhere else */

/* Sizes of pk, sk and signature for alg. */
int nqmdsz(int alg, nqssz *sz);

/* ML-DSA.KeyGen with a fresh xi from nqrand, and ML-DSA.KeyGen_internal
 * from the 32-byte xi. */
int nqmdkg(int alg, uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
int nqmdkgd(int alg, const uint8_t *xi, size_t xilen, uint8_t *pk,
            size_t pklen, uint8_t *sk, size_t sklen);

/* ML-DSA.Sign (ph 0) or HashML-DSA.Sign (ph an nqhalg: msg is hashed
 * here), with a context of at most 255 bytes (NULL when ctxlen is 0).
 * rnd NULL: hedged, 32 bytes from nqrand; otherwise rndlen must be 32
 * (all zero gives the deterministic variant). *outlen gets the signature
 * length. */
int nqmdsign(int alg, const uint8_t *sk, size_t sklen, const uint8_t *msg,
             size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t *rnd, size_t rndlen, uint8_t *sig,
             size_t siglen, size_t *outlen);
int nqmdvrfy(int alg, const uint8_t *pk, size_t pklen, const uint8_t *msg,
             size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t *sig, size_t siglen);

/* ML-DSA.Sign_internal / Verify_internal on the formatted message M' as
 * given: mu = SHAKE256(tr || M', 64) (ACVP "internal" interface). */
int nqmdsigi(int alg, const uint8_t *sk, size_t sklen, const uint8_t *m,
             size_t mlen, const uint8_t *rnd, size_t rndlen, uint8_t *sig,
             size_t siglen, size_t *outlen);
int nqmdvfyi(int alg, const uint8_t *pk, size_t pklen, const uint8_t *m,
             size_t mlen, const uint8_t *sig, size_t siglen);

/* External mu: Sign_internal / Verify_internal from the 64-byte mu. msk
 * is NQMDMASK or NQMDPLAIN. */
int nqmdsmu(int alg, const uint8_t *sk, size_t sklen, const uint8_t *mu,
            const uint8_t *rnd, size_t rndlen, int msk, uint8_t *sig,
            size_t siglen, size_t *outlen);
int nqmdvmu(int alg, const uint8_t *pk, size_t pklen, const uint8_t *mu,
            const uint8_t *sig, size_t siglen);

/* mu for the pure or pre-hash interface, from the public key (for a
 * caller that signs with an external mu). */
int nqmdmu(int alg, const uint8_t *pk, size_t pklen, const uint8_t *msg,
           size_t msglen, const uint8_t *ctx, size_t ctxlen, int ph,
           uint8_t *mu);

/* The DER-encoded OID (06 09 ...) FIPS 204 binds for pre-hash ph. */
int nqmdoid(int ph, uint8_t *oid);

#endif /* NQMLDSA_H */
