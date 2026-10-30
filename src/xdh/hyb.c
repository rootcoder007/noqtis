/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X25519MLKEM768, the hybrid key exchange of draft-ietf-tls-ecdhe-mlkem
 * (TLS group 0x11ec): the client's share is ML-KEM-768's encapsulation
 * key followed by an X25519 public key, the server's an ML-KEM-768
 * ciphertext followed by its X25519 public key, and the shared secret
 * the ML-KEM secret followed by the X25519 one. ML-KEM comes first in
 * all three (the draft's one exception to "classical first"). */
#include <string.h>

#include "core/int.h"
#include "mlkem/mlkem.h"
#include "xdh/xdh.h"

int nqhybkgd(const uint8_t *seed, const uint8_t *x, uint8_t *ek,
             uint8_t *sk) {
  int rc;
  if (seed == NULL || x == NULL || ek == NULL || sk == NULL) return NQEARG;
  rc = nqmkkgd(3, seed, NQMKSEED, ek, NQMKEK(3), sk, NQMKDK(3));
  if (rc == NQOK) {
    memcpy(sk + NQMKDK(3), x, 32);
    rc = nqx25519b(ek + NQMKEK(3), x) == NQOK ? NQOK : NQEARG;
  }
  if (rc != NQOK) {
    memset(ek, 0, NQHYBEK);
    nqwipe(sk, NQHYBSK);
  }
  return rc;
}

int nqhybkg(const uint8_t *x, uint8_t *ek, uint8_t *sk) {
  uint8_t seed[NQMKSEED];
  int rc = nqrand(seed, sizeof seed);
  if (rc == NQOK) rc = nqhybkgd(seed, x, ek, sk);
  nqwipe(seed, sizeof seed);
  return rc;
}

int nqhybencd(const uint8_t *ek, size_t ekn, const uint8_t *m,
              const uint8_t *x, uint8_t *ct, uint8_t *ss) {
  int rc;
  if (ek == NULL || m == NULL || x == NULL || ct == NULL || ss == NULL) {
    return NQEARG;
  }
  if (ekn != NQHYBEK) return NQEDEC;
  rc = nqmkencd(3, ek, NQMKEK(3), m, NQMKMSG, ct, NQMKCT(3), ss, NQMKSS);
  if (rc == NQOK && nqx25519b(ct + NQMKCT(3), x) != NQOK) rc = NQEARG;
  if (rc == NQOK) rc = nqx25519(ss + NQMKSS, x, ek + NQMKEK(3));
  if (rc != NQOK) nqwipe(ss, NQHYBSS);
  return rc;
}

int nqhybdec(const uint8_t *sk, const uint8_t *ct, size_t ctn,
             uint8_t *ss) {
  int rc;
  if (sk == NULL || ct == NULL || ss == NULL) return NQEARG;
  if (ctn != NQHYBCT) return NQEDEC;
  rc = nqmkdec(3, sk, NQMKDK(3), ct, NQMKCT(3), ss, NQMKSS);
  if (rc == NQOK) rc = nqx25519(ss + NQMKSS, sk + NQMKDK(3), ct + NQMKCT(3));
  if (rc != NQOK) nqwipe(ss, NQHYBSS);
  return rc;
}
