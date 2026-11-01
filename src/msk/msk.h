/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* First-order Boolean masking for the masked SLH-DSA PRF (internal): a
 * mask generator, masked Keccak-f[1600] with SHAKE256 on top, and a
 * masked SHA-256 compression.
 *
 * A masked value x is two shares x0, x1 with x = x0 ^ x1, each uniform
 * on its own. Linear steps act share by share. AND is Trichina's gadget
 * with a fresh random word, its second operand refreshed first, so the
 * two operands' sharings are independent even when they come from the
 * same value. SHA-256's additions use the Kogge-Stone carry chain on
 * shares (Coron, Grossschaedl, Tibouchi and Vadnan, FSE 2015): the
 * carries are generate and propagate words combined by masked ANDs, and
 * every carry bit is a XOR of disjoint terms, so the OR of the plain
 * algorithm is a XOR on shares.
 *
 * The bitsliced SHA-256 (nqms2b) runs 64 compressions at once, one bit
 * of each lane's word per 64-bit plane: rotations and shifts rename
 * planes, and an addition is a ripple carry of masked ANDs shared by the
 * 64 lanes, which is what makes masking every SLH-DSA PRF affordable.
 *
 * The masks come from ChaCha20 (RFC 8439) keyed from nqrand: they must
 * be unpredictable, and they are drawn by the hundred per hash, so the
 * generator is the fast cipher rather than a SHAKE. In the TVLA
 * control (NQLKZM) every mask is zero. Opaque volatile copies keep the
 * compiler from recombining shares; in a TVLA build they pass each share
 * word to the leakage hook. */
#ifndef NQMSK_H
#define NQMSK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t k[32]; /* ChaCha20 key */
  uint8_t b[64]; /* the current key stream block */
  uint32_t ctr;
  unsigned pos;
} nqmrg;

/* Keys g from nqrand; NQOK or the error of nqrand. */
int nqmrini(nqmrg *g);
uint32_t nqmr32(nqmrg *g);
uint64_t nqmr64(nqmrg *g);
/* Random bytes for a share (zero in the TVLA control). */
void nqmrb(nqmrg *g, uint8_t *out, size_t n);

/* SHAKE256 of in0 ^ in1 (in1 NULL: share 1 all zero, a public input)
 * into out0 ^ out1. */
void nqmshk(uint8_t *out0, uint8_t *out1, size_t outlen,
            const uint8_t *in0, const uint8_t *in1, size_t inlen,
            nqmrg *g);

/* One SHA-256 compression: the chaining value h (public) with the block
 * b0 ^ b1 (64 bytes) gives o0 ^ o1 (the new chaining value, masked). */
void nqms2(const uint32_t h[8], const uint8_t b0[64], const uint8_t b1[64],
           uint32_t o0[8], uint32_t o1[8], nqmrg *g);

/* The same for cnt (at most NQMSBL) lanes at once, bitsliced: lane l's
 * block is b0 + 64 l (and b1 + 64 l), its result o0 + 8 l, o1 + 8 l.
 * Its working state (about 15 KB) is on the stack. */
#define NQMSBL 64
void nqms2b(const uint32_t h[8], const uint8_t *b0, const uint8_t *b1,
            unsigned cnt, uint32_t *o0, uint32_t *o1, nqmrg *g);

/* For the tests: z0 ^ z1 = (x0 ^ x1) + (y0 ^ y1) mod 2^32. */
void nqmsadd(uint32_t z[2], const uint32_t x[2], const uint32_t y[2],
             nqmrg *g);

#endif /* NQMSK_H */
