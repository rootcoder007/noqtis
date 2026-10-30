/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Authenticated encryption for the TLS 1.3 client (internal API, not
 * part of noqtis.h): AES-128/192/256 (FIPS 197) in GCM (SP 800-38D) and
 * ChaCha20-Poly1305 (RFC 8439).
 *
 * Everything here is constant time in the key and the data: AES is
 * bitsliced, its S-box computed as the inverse in GF(2^8) followed by
 * the affine map, with no table at all; GHASH multiplies bit by bit
 * under masks; ChaCha20 and Poly1305 use only additions, rotations and
 * multiplications of fixed-size words. Nothing allocates.
 *
 * The AEAD functions return NQOK, NQEARG for a bad length or a NULL
 * pointer, and (decryption) NQEVRFY when the tag does not verify; the
 * output is then all zero. The output may be the input (in place); it
 * may not overlap it otherwise. */
#ifndef NQAEAD_H
#define NQAEAD_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQAEADTAG 16  /* the tag, for both AEADs */

/* ctgrind (tests/taeadct.c): whether a tag verified goes on the wire
 * anyway, so it is declared defined before decryption branches on it.
 * A no-op otherwise. */
#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQAEPUB(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define NQAEPUB(p, n) ((void)0)
#endif

/* ---- AES ---- */

typedef struct {
  uint8_t rk[240];  /* the round keys, 16 bytes per round */
  unsigned nr;      /* rounds: 10, 12 or 14 */
} nqaes;

/* Expands a 16, 24 or 32 byte key; NQEARG for another length. */
int nqaesk(nqaes *k, const uint8_t *key, size_t len);
/* Encrypts two blocks (32 bytes) at once; in may be out. */
void nqaes2(const nqaes *k, const uint8_t *in, uint8_t *out);
/* Encrypts one block (16 bytes); in may be out. */
void nqaes1(const nqaes *k, const uint8_t *in, uint8_t *out);

/* ---- AES-GCM ---- */

typedef struct {
  nqaes k;
  uint64_t h[2];    /* the hash key E(K, 0^128), big-endian halves */
} nqgcm;

int nqgcmk(nqgcm *g, const uint8_t *key, size_t len);
/* Encrypts n bytes of in to out and writes the 16-byte tag. The IV is
 * any length from 1 byte (12 is the fast, recommended case). */
int nqgcme(const nqgcm *g, const uint8_t *iv, size_t ivlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           uint8_t *out, uint8_t *tag);
/* Checks the tag (taglen 16) and decrypts n bytes of in to out. */
int nqgcmd(const nqgcm *g, const uint8_t *iv, size_t ivlen,
           const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
           const uint8_t *tag, size_t taglen, uint8_t *out);

/* ---- ChaCha20-Poly1305 ---- */

/* The ChaCha20 block function's key stream XORed into n bytes of in,
 * starting at block counter ctr (RFC 8439 section 2.4). */
void nqcc20(const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr,
            const uint8_t *in, size_t n, uint8_t *out);

typedef struct {
  uint32_t r[5], h[5], pad[4];
  uint8_t buf[16];
  size_t pos;
} nqp1305;

/* Poly1305 (RFC 8439 section 2.5) with a one-time 32-byte key. */
void nqp1ini(nqp1305 *p, const uint8_t key[32]);
void nqp1upd(nqp1305 *p, const uint8_t *in, size_t n);
/* Writes the 16-byte tag and wipes p. */
void nqp1fin(nqp1305 *p, uint8_t tag[16]);

/* The AEAD of RFC 8439 section 2.8: a 32-byte key and a 12-byte nonce. */
int nqccpe(const uint8_t *key, size_t klen, const uint8_t *nonce,
           size_t nlen, const uint8_t *aad, size_t alen, const uint8_t *in,
           size_t n, uint8_t *out, uint8_t *tag);
int nqccpd(const uint8_t *key, size_t klen, const uint8_t *nonce,
           size_t nlen, const uint8_t *aad, size_t alen, const uint8_t *in,
           size_t n, const uint8_t *tag, size_t taglen, uint8_t *out);

#endif /* NQAEAD_H */
