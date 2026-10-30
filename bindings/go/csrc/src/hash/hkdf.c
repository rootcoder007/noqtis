/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HKDF (RFC 5869) on the HMAC of hmac.c, for the TLS 1.3 key schedule. */
#include <string.h>

#include "hash/h.h"

int nqhkx(nqhalg alg, const uint8_t *salt, size_t slen, const uint8_t *ikm,
          size_t ilen, uint8_t *prk) {
  static const uint8_t z[NQHMAX] = {0};
  nqmctx m;
  size_t hl = nqhlen(alg);
  int rc;
  if (prk == NULL || (salt == NULL && slen > 0) ||
      (ikm == NULL && ilen > 0)) {
    return NQEARG;
  }
  /* no salt: HashLen zeros (section 2.2) */
  if (slen == 0) {
    salt = z;
    slen = hl;
  }
  if ((rc = nqmini(&m, alg, salt, slen)) != NQOK) return rc;
  if (ilen > 0) nqmupd(&m, ikm, ilen);
  nqmfin(&m, prk);
  return NQOK;
}

int nqhke(nqhalg alg, const uint8_t *prk, size_t plen, const uint8_t *info,
          size_t ilen, uint8_t *okm, size_t n) {
  uint8_t t[NQHMAX];
  nqmctx m;
  size_t hl = nqhlen(alg), done = 0, tl = 0;
  uint8_t i = 0;
  int rc;
  if (prk == NULL || (info == NULL && ilen > 0) || (okm == NULL && n > 0)) {
    return NQEARG;
  }
  if (hl == 0 || n > 255 * hl) return NQEARG;
  while (done < n) {
    size_t c = n - done < hl ? n - done : hl;
    i++;
    if ((rc = nqmini(&m, alg, prk, plen)) != NQOK) {
      nqwipe(t, sizeof t);
      return rc;
    }
    nqmupd(&m, t, tl);
    if (ilen > 0) nqmupd(&m, info, ilen);
    nqmupd(&m, &i, 1);
    nqmfin(&m, t);
    tl = hl;
    memcpy(okm + done, t, c);
    done += c;
  }
  nqwipe(t, sizeof t);
  return NQOK;
}
