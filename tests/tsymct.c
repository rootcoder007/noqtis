/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Constant-time check of ChaCha20, AES-SIV, AES-GCM-SIV and
 * KangarooTwelve (ctgrind). Built with -DNQCTGRIND (the library too) and
 * run under valgrind, the keys, the plaintexts, the hashed input and the
 * customization string are marked undefined, so memcheck reports any
 * branch or index that depends on them. Only whether a tag verified is
 * declared public (aead.h, NQAEPUB). Decryption runs on an honest and on
 * a tampered ciphertext, and messages of several lengths take every path
 * of the padding. Without NQCTGRIND it runs plainly and checks the round
 * trips. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#endif

static const size_t lens[] = {0, 1, 15, 16, 17, 32, 77};

static void cha(void) {
  uint8_t k[32], n[12], m[200], c[200], o[200];
  size_t i;
  for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 3 + 9);
  for (i = 0; i < sizeof n; i++) n[i] = (uint8_t)(i + 40);
  for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 11);
  SECRET(k, sizeof k);
  SECRET(m, sizeof m);
  NQTEQI(nqcha20(k, 32, n, 12, 1, m, sizeof m, c), NQOK);
  NQTEQI(nqcha20(k, 32, n, 12, 1, c, sizeof c, o), NQOK);
  PUBLIC(o, sizeof o);
  PUBLIC(m, sizeof m);
  NQTEQM(o, m, sizeof m);
}

static void siv(size_t kl) {
  uint8_t k[64], a1[20], a2[7], m[77], c[93], o[77];
  const uint8_t *ad[2];
  size_t adl[2] = {sizeof a1, sizeof a2}, i, q;
  ad[0] = a1;
  ad[1] = a2;
  for (q = 0; q < sizeof lens / sizeof lens[0]; q++) {
    size_t n = lens[q];
    for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 29 + kl);
    for (i = 0; i < sizeof a1; i++) a1[i] = (uint8_t)(i + 100);
    for (i = 0; i < sizeof a2; i++) a2[i] = (uint8_t)(i + 3);
    for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 7 + 1);
    SECRET(k, sizeof k);
    SECRET(m, sizeof m);
    NQTEQI(nqsivenc(k, kl, ad, adl, 2, m, n, c, n + 16), NQOK);
    /* the IV and the ciphertext go on the wire */
    PUBLIC(c, sizeof c);
    NQTEQI(nqsivdec(k, kl, ad, adl, 2, c, n + 16, o, n), NQOK);
    PUBLIC(o, sizeof o);
    PUBLIC(m, sizeof m);
    NQTEQM(o, m, n);
    c[3] ^= 1;
    NQTEQI(nqsivdec(k, kl, ad, adl, 2, c, n + 16, o, n), NQEVRFY);
    PUBLIC(k, sizeof k);
  }
}

static void gsiv(size_t kl) {
  uint8_t k[32], nc[12], aad[13], m[77], c[93], o[77];
  size_t i, q;
  for (q = 0; q < sizeof lens / sizeof lens[0]; q++) {
    size_t n = lens[q];
    for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 13 + kl);
    for (i = 0; i < sizeof nc; i++) nc[i] = (uint8_t)i;
    for (i = 0; i < sizeof aad; i++) aad[i] = (uint8_t)(i + 100);
    for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 5 + 2);
    SECRET(k, sizeof k);
    SECRET(m, sizeof m);
    NQTEQI(nqgsivenc(k, kl, nc, 12, aad, sizeof aad, m, n, c, n + 16), NQOK);
    PUBLIC(c, sizeof c);
    NQTEQI(nqgsivdec(k, kl, nc, 12, aad, sizeof aad, c, n + 16, o, n), NQOK);
    PUBLIC(o, sizeof o);
    PUBLIC(m, sizeof m);
    NQTEQM(o, m, n);
    c[n + 15] ^= 0x80;
    NQTEQI(nqgsivdec(k, kl, nc, 12, aad, sizeof aad, c, n + 16, o, n),
           NQEVRFY);
    PUBLIC(k, sizeof k);
  }
}

/* a secret message and a secret key as the customization string (the
 * MAC of RFC 9861 section 4): one node, and a tree of three chunks */
static void kt(unsigned bits) {
  static uint8_t m[20000];
  uint8_t key[32], a[64], b[64];
  size_t i;
  for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(i * 3 + (i >> 7));
  for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i + 17);
  SECRET(m, sizeof m);
  SECRET(key, sizeof key);
  NQTEQI(nqkt(bits, m, 100, key, sizeof key, a, 64), NQOK);
  NQTEQI(nqkt(bits, m, sizeof m, key, sizeof key, b, 64), NQOK);
  PUBLIC(a, sizeof a);
  PUBLIC(b, sizeof b);
  NQTCHK(memcmp(a, b, 64) != 0);
  PUBLIC(m, sizeof m);
}

int main(void) {
  cha();
  siv(32);
  siv(48);
  siv(64);
  gsiv(16);
  gsiv(32);
  kt(128);
  kt(256);
  return nqtdone("tsymct");
}
