/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Constant-time check of AES-GCM, ChaCha20-Poly1305 and HKDF (ctgrind).
 * Built with -DNQCTGRIND (the library too) and run under valgrind, the
 * keys, the plaintexts and the HKDF input keying material are marked
 * undefined, so memcheck reports any branch or index that depends on
 * them. Only whether a tag verified is declared public (aead.h,
 * NQAEPUB). Decryption runs on an honest and on a tampered ciphertext.
 * Without NQCTGRIND it runs plainly and checks the round trips. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "aead/aead.h"
#include "hash/h.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

static void gcm(size_t kl) {
  uint8_t k[32], iv[12], aad[13], m[77], c[77], o[77], t[16];
  nqgcm g;
  size_t i;
  for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 29 + kl);
  for (i = 0; i < sizeof iv; i++) iv[i] = (uint8_t)i;
  for (i = 0; i < sizeof aad; i++) aad[i] = (uint8_t)(i + 100);
  for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 7 + 1);
  SECRET(k, sizeof k);
  SECRET(m, sizeof m);
  NQTEQI(nqgcmk(&g, k, kl), NQOK);
  NQTEQI(nqgcme(&g, iv, sizeof iv, aad, sizeof aad, m, sizeof m, c, t),
         NQOK);
  /* the ciphertext and the tag go on the wire */
  PUBLIC(c, sizeof c);
  PUBLIC(t, sizeof t);
  NQTEQI(nqgcmd(&g, iv, sizeof iv, aad, sizeof aad, c, sizeof c, t, 16, o),
         NQOK);
  PUBLIC(o, sizeof o);
  PUBLIC(m, sizeof m);
  NQTEQM(o, m, sizeof m);
  c[5] ^= 1;
  NQTEQI(nqgcmd(&g, iv, sizeof iv, aad, sizeof aad, c, sizeof c, t, 16, o),
         NQEVRFY);
  /* another IV length: J0 through GHASH */
  NQTEQI(nqgcme(&g, iv, 7, aad, sizeof aad, m, sizeof m, c, t), NQOK);
}

static void ccp(void) {
  uint8_t k[32], n[12], aad[5], m[200], c[200], o[200], t[16];
  size_t i;
  for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 3 + 9);
  for (i = 0; i < sizeof n; i++) n[i] = (uint8_t)(i + 40);
  for (i = 0; i < sizeof aad; i++) aad[i] = (uint8_t)i;
  for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 11);
  SECRET(k, sizeof k);
  SECRET(m, sizeof m);
  NQTEQI(nqccpe(k, 32, n, 12, aad, sizeof aad, m, sizeof m, c, t), NQOK);
  PUBLIC(c, sizeof c);
  PUBLIC(t, sizeof t);
  NQTEQI(nqccpd(k, 32, n, 12, aad, sizeof aad, c, sizeof c, t, 16, o), NQOK);
  PUBLIC(o, sizeof o);
  PUBLIC(m, sizeof m);
  NQTEQM(o, m, sizeof m);
  t[15] ^= 0x80;
  NQTEQI(nqccpd(k, 32, n, 12, aad, sizeof aad, c, sizeof c, t, 16, o),
         NQEVRFY);
}

static void hkdf(void) {
  uint8_t ikm[48], prk[48], okm[100];
  size_t i;
  for (i = 0; i < sizeof ikm; i++) ikm[i] = (uint8_t)(i ^ 0x5a);
  SECRET(ikm, sizeof ikm);
  NQTEQI(nqhkx(NQS384, NULL, 0, ikm, sizeof ikm, prk), NQOK);
  NQTEQI(nqhke(NQS384, prk, 48, (const uint8_t *)"info", 4, okm,
               sizeof okm),
         NQOK);
  PUBLIC(okm, sizeof okm);
}

int main(void) {
  gcm(16);
  gcm(24);
  gcm(32);
  ccp();
  hkdf();
  return nqtdone("taeadct");
}
