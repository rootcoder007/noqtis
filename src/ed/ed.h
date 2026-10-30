/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Ed25519 (RFC 8032): key generation, signing and verification of
 * Ed25519, Ed25519ctx and Ed25519ph, for the public dispatchers in
 * noqtis.h (Ed25519 alone and the hybrid ML-DSA + Ed25519 sets) and for
 * the tests. Internal: not part of the public API.
 *
 * pk is the 32-byte encoding of A; sk is the 32-byte private key (the
 * seed RFC 8032 hashes); a signature is R || S, 64 bytes.
 *
 * The variant follows ctx and ph: no context and ph 0 is Ed25519; a
 * context of 1 to 255 bytes with ph 0 is Ed25519ctx; ph 1 is Ed25519ph
 * (msg is hashed here with SHA-512), with or without a context.
 *
 * Signing runs in constant time in the secret key and the secret nonce.
 * Verification is strict: A and R must be canonical encodings of points
 * on the curve, A must be of prime order (not the identity, no small-order
 * part), S must be below the group order, and [S]B = R + [k]A is checked
 * on the encodings (cofactorless).
 *
 * Errors: NQEARG for a NULL pointer with a nonzero length or a context
 * over 255 bytes; NQEDEC for a public key that is not a point; NQEVRFY for
 * a signature that does not verify. */
#ifndef NQED_H
#define NQED_H

#include <stddef.h>
#include <stdint.h>

#define NQEDPK 32
#define NQEDSK 32
#define NQEDSIG 64

int nqedkg(const uint8_t sk[NQEDSK], uint8_t pk[NQEDPK]);
int nqedsign(const uint8_t sk[NQEDSK], const uint8_t *msg, size_t msglen,
             const uint8_t *ctx, size_t ctxlen, int ph,
             uint8_t sig[NQEDSIG]);
int nqedvrfy(const uint8_t pk[NQEDPK], const uint8_t *msg, size_t msglen,
             const uint8_t *ctx, size_t ctxlen, int ph,
             const uint8_t sig[NQEDSIG]);

#ifdef NQEDTEST
/* the curve constants, recomputed from their definitions, for tests */
void nqedcst(uint8_t d[32], uint8_t d2[32], uint8_t i[32], uint8_t bx[32],
             uint8_t by[32]);
void nqedtbl(uint8_t d[32], uint8_t d2[32], uint8_t i[32], uint8_t bx[32],
             uint8_t by[32]);
#endif

#endif
