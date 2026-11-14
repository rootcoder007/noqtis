/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* What the sealed message (ks.c) and the sealed stream (kf.c) share;
 * internal, not part of noqtis.h. */
#ifndef NQBOX_H
#define NQBOX_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQBXCTX 255   /* the longest context */
#define NQBXCT 1568   /* the longest ML-KEM ciphertext */

/* 1 for the ML-KEM sets */
int nqbxkem(nqkalg alg);
/* HKDF-SHA-256 of the 32-byte shared secret ss, no salt, with info lab
 * || hek || |ctx| || ctx || hdr || ct (hek the SHA3-256 of the
 * recipient's public key): on bytes of okm. hl + cl at most 17 + NQBXCT,
 * lab at most 16 bytes. */
int nqbxkd(const char *lab, const uint8_t *ss, const uint8_t hek[32],
           const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr, size_t hl,
           const uint8_t *ct, size_t cl, uint8_t *okm, size_t on);

/* The state of a sealed stream (an nqkfctx, copied in and out). */
typedef struct {
  uint32_t mag;
  int st;          /* NQKFENC or NQKFDEC while open */
  nqkalg alg;
  uint32_t chunk;  /* plaintext bytes of each chunk but the last */
  uint32_t ctr;    /* the next chunk's number */
  uint8_t key[32];
  uint8_t pre[7];  /* the nonce prefix */
} nqkfst;

#define NQKFENC 1
#define NQKFDEC 2

#endif /* NQBOX_H */
