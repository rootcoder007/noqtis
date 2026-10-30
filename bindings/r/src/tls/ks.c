/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The TLS 1.3 key schedule (RFC 8446 section 7.1) and traffic keys
 * (section 7.3), without PSK: the early secret is HKDF-Extract of zeros
 * under a zero salt. */
#include <string.h>

#include "tls/tls.h"

nqhalg nqtlsh(uint16_t suite) {
  switch (suite) {
  case NQTLA128: case NQTLC20: return NQS256;
  case NQTLA256: return NQS384;
  default: return (nqhalg)0;
  }
}

int nqtlexp(nqhalg h, const uint8_t *sec, const char *label,
            const uint8_t *ctx, size_t cn, uint8_t *out, size_t n) {
  /* HkdfLabel: length, "tls13 " || label, context */
  uint8_t info[2 + 1 + 255 + 1 + 255];
  size_t ll = strlen(label), i = 0, hl = nqhlen(h);
  int rc;
  if (ll > 255 - 6 || cn > 255 || n > 0xffff || hl == 0) return NQEARG;
  info[i++] = (uint8_t)(n >> 8);
  info[i++] = (uint8_t)n;
  info[i++] = (uint8_t)(6 + ll);
  memcpy(info + i, "tls13 ", 6);
  i += 6;
  memcpy(info + i, label, ll);
  i += ll;
  info[i++] = (uint8_t)cn;
  if (cn > 0) memcpy(info + i, ctx, cn);
  i += cn;
  rc = nqhke(h, sec, hl, info, i, out, n);
  nqwipe(info, sizeof info);
  return rc;
}

int nqtlder(nqhalg h, const uint8_t *sec, const char *label,
            const uint8_t *th, uint8_t *out) {
  size_t hl = nqhlen(h);
  return nqtlexp(h, sec, label, th, hl, out, hl);
}

int nqtlnext(nqhalg h, const uint8_t *sec, const uint8_t *ikm, size_t in,
             uint8_t *out) {
  static const uint8_t z[NQHMAX] = {0};
  uint8_t e[NQHMAX], salt[NQHMAX];
  size_t hl = nqhlen(h);
  int rc;
  if (hl == 0 || hl > NQHMAX) return NQEARG;
  if (ikm == NULL) {
    ikm = z;
    in = hl;
  }
  if (sec == NULL) return nqhkx(h, NULL, 0, ikm, in, out);
  /* salt = Derive-Secret(sec, "derived", "") */
  if ((rc = nqhash(h, z, 0, e, hl)) != NQOK ||
      (rc = nqtlder(h, sec, "derived", e, salt)) != NQOK) {
    nqwipe(salt, sizeof salt);
    return rc;
  }
  rc = nqhkx(h, salt, hl, ikm, in, out);
  nqwipe(salt, sizeof salt);
  return rc;
}

int nqtlkeys(nqtlkey *k, uint16_t suite, nqhalg h, const uint8_t *sec) {
  uint8_t key[32];
  size_t kl = suite == NQTLA128 ? 16 : 32, hl = nqhlen(h);
  int rc;
  if (nqtlsh(suite) != h || hl == 0) return NQEARG;
  if ((rc = nqtlexp(h, sec, "key", NULL, 0, key, kl)) != NQOK ||
      (rc = nqtlexp(h, sec, "iv", NULL, 0, k->iv, 12)) != NQOK) {
    nqwipe(key, sizeof key);
    return rc;
  }
  if (suite == NQTLC20) {
    memcpy(k->ck, key, 32);
  } else if ((rc = nqgcmk(&k->g, key, kl)) != NQOK) {
    nqwipe(key, sizeof key);
    return rc;
  }
  if (sec != k->sec) memcpy(k->sec, sec, hl);
  k->suite = suite;
  k->seq = 0;
  k->on = 1;
  nqwipe(key, sizeof key);
  return NQOK;
}
