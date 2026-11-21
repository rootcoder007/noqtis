/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* AES Key Wrap (RFC 3394), with the default initial value: a key of a
 * whole number of 8-byte blocks, two or more, wrapped under a
 * key-encryption key into 8 bytes more. CMS (the KEM recipient) and
 * OpenPGP (the session key of a KEM or ECDH recipient) carry keys this
 * way. */
#include <string.h>

#include "aead/aead.h"

static void xort(uint8_t *a, uint64_t t) {
  int i;
  for (i = 7; i >= 0; i--) {
    a[i] ^= (uint8_t)t;
    t >>= 8;
  }
}

int nqkwrap(const uint8_t *kek, size_t keklen, const uint8_t *in, size_t n,
            uint8_t *out) {
  nqaes k;
  uint8_t b[16];
  size_t blocks = n / 8, i, j;
  int rc;
  if (kek == NULL || in == NULL || out == NULL || n % 8 != 0 || n < 16 ||
      n > 4096)
    return NQEARG;
  rc = nqaesk(&k, kek, keklen);
  if (rc != NQOK) return rc;
  memset(out, 0xa6, 8);
  memmove(out + 8, in, n);
  for (j = 0; j < 6; j++) {
    for (i = 1; i <= blocks; i++) {
      memcpy(b, out, 8);
      memcpy(b + 8, out + 8 * i, 8);
      nqaes1(&k, b, b);
      xort(b, (uint64_t)(blocks * j + i));
      memcpy(out, b, 8);
      memcpy(out + 8 * i, b + 8, 8);
    }
  }
  nqwipe(&k, sizeof k);
  nqwipe(b, sizeof b);
  return NQOK;
}

int nqkunwrap(const uint8_t *kek, size_t keklen, const uint8_t *in, size_t n,
              uint8_t *out) {
  nqaes k;
  uint8_t a[8], b[16], bad = 0;
  size_t blocks, i, j;
  int rc;
  if (kek == NULL || in == NULL || out == NULL || n % 8 != 0 || n < 24 ||
      n > 4104)
    return NQEARG;
  blocks = n / 8 - 1;
  rc = nqaesk(&k, kek, keklen);
  if (rc != NQOK) return rc;
  memcpy(a, in, 8);
  memmove(out, in + 8, n - 8);
  for (j = 6; j-- > 0;) {
    for (i = blocks; i >= 1; i--) {
      xort(a, (uint64_t)(blocks * j + i));
      memcpy(b, a, 8);
      memcpy(b + 8, out + 8 * (i - 1), 8);
      nqaesd1(&k, b, b);
      memcpy(a, b, 8);
      memcpy(out + 8 * (i - 1), b + 8, 8);
    }
  }
  for (i = 0; i < 8; i++) bad |= (uint8_t)(a[i] ^ 0xa6);
  nqwipe(&k, sizeof k);
  nqwipe(b, sizeof b);
  nqwipe(a, sizeof a);
  if (bad != 0) {
    /* nothing of a key that did not unwrap is given out */
    nqwipe(out, n - 8);
    return NQEVRFY;
  }
  return NQOK;
}
