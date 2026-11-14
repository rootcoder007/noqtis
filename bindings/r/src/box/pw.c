/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Passphrase key files (noqtis-pwkey-1, noqtis.h): a secret key under
 * ChaCha20-Poly1305 with a key and nonce from Argon2id. The reader
 * checks the header's magic, version, algorithms, parameters and sizes
 * before it runs Argon2id, so a file cannot make it allocate more than
 * NQPWMMAX KiB or run more than NQPWWORK KiB-passes; anything else that
 * is wrong (the passphrase, a byte of the header or the body, the
 * caller's ad) fails the tag. */
#include <string.h>

#include "aead/aead.h"
#include "core/int.h"
#include "hash/h.h"

#define HDR 35     /* "NQPW", version, kdf, aead, m, t, p, salt */
#define SALT 16
#define KN 44      /* the AEAD's key (32) and nonce (12) */
#define ADMAX 1024

static const uint8_t mag[7] = {'N', 'Q', 'P', 'W', 1, 1, 1};

/* 1 when (m, t, p) is within the limits */
static int inlim(uint32_t m, uint32_t t, uint32_t p) {
  return m >= NQPWMMIN && m <= NQPWMMAX && t >= 1 && t <= NQPWTMAX &&
         p >= 1 && p <= NQPWPMAX && (uint64_t)m * t <= NQPWWORK;
}

/* the AEAD's key and nonce from the passphrase and the header's
 * parameters and salt; aad gets the header and ad */
static int derive(const uint8_t *pw, size_t pwlen, const uint8_t *hdr,
                  const uint8_t *ad, size_t alen, uint8_t *kn,
                  uint8_t *aad) {
  memcpy(aad, hdr, HDR);
  if (alen > 0) memcpy(aad + HDR, ad, alen);
  return nqa2(2, pw, pwlen, hdr + 19, SALT, NULL, 0, NULL, 0,
              nqld32b(hdr + 11), nqld32b(hdr + 7), nqld32b(hdr + 15), kn,
              KN);
}

static int args(const uint8_t *pw, size_t pwlen, const uint8_t *ad,
                size_t alen) {
  if (pw == NULL || pwlen < 1 || pwlen > NQPWLEN ||
      (ad == NULL && alen > 0) || alen > ADMAX) {
    return NQEARG;
  }
  return NQOK;
}

int nqpwenc(const uint8_t *pw, size_t pwlen, const uint8_t *ad,
            size_t alen, uint32_t m, uint32_t t, uint32_t p,
            const uint8_t *sk, size_t sklen, uint8_t *out, size_t cap,
            size_t *outlen) {
  uint8_t kn[KN], aad[HDR + ADMAX];
  int rc = args(pw, pwlen, ad, alen);
  if (outlen != NULL) *outlen = 0;
  if (rc != NQOK) return rc;
  if (sk == NULL || out == NULL || sklen < 1 || sklen > NQPWMAX) {
    return NQEARG;
  }
  if (m == 0) m = NQPWM;
  if (t == 0) t = NQPWT;
  if (p == 0) p = NQPWP;
  if (!inlim(m, t, p)) return NQEARG;
  if (outlen != NULL) *outlen = sklen + NQPWOVH;
  if (cap < sklen + NQPWOVH) return NQEBUF;
  memcpy(out, mag, sizeof mag);
  nqst32b(out + 7, m);
  nqst32b(out + 11, t);
  nqst32b(out + 15, p);
  rc = nqrand(out + 19, SALT);
  if (rc == NQOK) rc = derive(pw, pwlen, out, ad, alen, kn, aad);
  if (rc == NQOK) {
    rc = nqccpe(kn, 32, kn + 32, 12, aad, HDR + alen, sk, sklen, out + HDR,
                out + HDR + sklen);
  }
  nqwipe(kn, sizeof kn);
  if (rc != NQOK) {
    nqwipe(out, sklen + NQPWOVH);
    if (outlen != NULL) *outlen = 0;
  }
  return rc;
}

int nqpwdec(const uint8_t *pw, size_t pwlen, const uint8_t *ad,
            size_t alen, const uint8_t *in, size_t n, uint8_t *sk,
            size_t cap, size_t *sklen) {
  uint8_t kn[KN], aad[HDR + ADMAX];
  size_t len = 0;
  int rc = args(pw, pwlen, ad, alen);
  if (sklen != NULL) *sklen = 0;
  if (rc == NQOK && (in == NULL || sk == NULL)) rc = NQEARG;
  /* everything that needs no passphrase first */
  if (rc == NQOK && (n < NQPWOVH + 1 || memcmp(in, mag, sizeof mag) != 0)) {
    rc = NQEDEC;
  }
  if (rc == NQOK &&
      (!inlim(nqld32b(in + 7), nqld32b(in + 11), nqld32b(in + 15)) ||
       n - NQPWOVH > NQPWMAX)) {
    rc = NQELIM;
  }
  if (rc == NQOK) {
    len = n - NQPWOVH;
    if (cap < len) {
      if (sklen != NULL) *sklen = len;
      rc = NQEBUF;
    }
  }
  if (rc == NQOK) {
    rc = derive(pw, pwlen, in, ad, alen, kn, aad);
    if (rc == NQOK) {
      rc = nqccpd(kn, 32, kn + 32, 12, aad, HDR + alen, in + HDR, len,
                  in + HDR + len, NQAEADTAG, sk);
    }
    nqwipe(kn, sizeof kn);
  }
  if (rc == NQOK) {
    if (sklen != NULL) *sklen = len;
  } else if (sk != NULL) {
    nqwipe(sk, cap);
  }
  return rc;
}
