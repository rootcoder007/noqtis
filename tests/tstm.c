/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Streaming signatures (nqsini, nqvini, nqsupd, nqsfin, nqvfin): for
 * ML-DSA-44, -65 and -87, pure and pre-hash, the bytes nqsignd gives at
 * every split of the message into two pieces, in pieces of one byte,
 * with empty pieces between, and with contexts of every length 0 to 255
 * (so the prefix ends at every offset of SHAKE256's 136-byte block);
 * nqvrfy accepts each, and nqvfin accepts nqsign's; HashSLH-DSA,
 * Ed25519ph and the hybrids with SHA-512 the same way on fewer splits;
 * the refusals (pure SLH-DSA, Ed25519 and hybrids), misuse (NQESTATE)
 * and another key at the end. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "nqt.h"

static uint8_t pk[2624], sk[4928], s1[50000], s2[50000], msg[700];

/* signs msg[0..n) in the pieces cuts[] says (sizes; 0 is an empty
 * piece), with rnd (rl bytes) */
static int ssig(nqsalg a, const nqssz *z, const uint8_t *ctx, size_t cl,
                int ph, const size_t *cuts, size_t nc, size_t n,
                const uint8_t *rnd, size_t rl, uint8_t *sig, size_t *ol) {
  nqsctx c;
  size_t at = 0, i;
  int rc = nqsini(&c, a, sk, z->sk, ctx, cl, ph);
  for (i = 0; rc == NQOK && i < nc; i++) {
    rc = nqsupd(&c, msg + at, cuts[i]);
    at += cuts[i];
  }
  if (rc == NQOK) rc = nqsupd(&c, msg + at, n - at);
  if (rc == NQOK) rc = nqsfin(&c, sk, z->sk, rnd, rl, sig, z->sig, ol);
  return rc;
}

static int sver(nqsalg a, const nqssz *z, const uint8_t *ctx, size_t cl,
                int ph, size_t cut, size_t n, const uint8_t *sig) {
  nqsctx c;
  int rc = nqvini(&c, a, pk, z->pk, ctx, cl, ph);
  if (rc == NQOK) rc = nqsupd(&c, msg, cut);
  if (rc == NQOK) rc = nqsupd(&c, NULL, 0);
  if (rc == NQOK) rc = nqsupd(&c, msg + cut, n - cut);
  if (rc == NQOK) rc = nqvfin(&c, pk, z->pk, sig, z->sig);
  return rc;
}

static void tmd(void) {
  static const nqsalg al[3] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};
  uint8_t seed[32], rnd[32], ctx[255];
  size_t a, i, ol = 0, o2 = 0, n = 300;
  long bad = 0;
  for (i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 29 + 3);
  for (i = 0; i < sizeof ctx; i++) ctx[i] = (uint8_t)(i + 1);
  for (a = 0; a < 3; a++) {
    nqssz z;
    size_t cut, cl;
    NQTEQI(nqssize(al[a], &z), NQOK);
    memset(seed, (int)(a + 9), sizeof seed);
    memset(rnd, (int)(a + 1), sizeof rnd);
    NQTEQI(nqskgd(al[a], seed, 32, pk, z.pk, sk, z.sk), NQOK);
    NQTEQI(nqsignd(al[a], sk, z.sk, msg, n, ctx, 7, 0, rnd, 32, s1, z.sig,
                   &o2),
           NQOK);
    /* every split into two */
    for (cut = 0; cut <= n; cut++) {
      if (ssig(al[a], &z, ctx, 7, 0, &cut, 1, n, rnd, 32, s2, &ol) != NQOK ||
          ol != z.sig || memcmp(s1, s2, z.sig) != 0) {
        bad++;
      }
    }
    NQTEQI(bad, 0);
    NQTEQI(nqvrfy(al[a], pk, z.pk, msg, n, ctx, 7, 0, s2, ol), NQOK);
    /* one byte at a time, with an empty piece after each */
    {
      size_t cuts[2 * 300];
      for (i = 0; i < n; i++) {
        cuts[2 * i] = 1;
        cuts[2 * i + 1] = 0;
      }
      NQTEQI(ssig(al[a], &z, ctx, 7, 0, cuts, 2 * n, n, rnd, 32, s2, &ol),
             NQOK);
      NQTEQM(s2, s1, z.sig);
    }
    /* every context length: the prefix ends at every offset of the
     * block; deterministic, and a few splits around the boundary */
    memset(rnd, 0, sizeof rnd);
    for (cl = 0; cl <= 255; cl += a == 0 ? 1 : 17) {
      size_t c2 = (136 - (64 + 2 + cl) % 136) % 136;
      NQTEQI(nqsignd(al[a], sk, z.sk, msg, n, ctx, cl, 0, rnd, 32, s1,
                     z.sig, &o2),
             NQOK);
      NQTEQI(ssig(al[a], &z, ctx, cl, 0, &c2, 1, n, rnd, 32, s2, &ol), NQOK);
      NQTEQM(s2, s1, z.sig);
      NQTEQI(sver(al[a], &z, ctx, cl, 0, c2 + 1, n, s1), NQOK);
    }
    /* pre-hash: HashML-DSA with SHA-256 and SHAKE256 */
    for (i = 0; i < 2; i++) {
      int ph = i == 0 ? (int)NQS256 : (int)NQSHK256;
      size_t c3 = 100 + i;
      NQTEQI(nqsignd(al[a], sk, z.sk, msg, n, ctx, 3, ph, rnd, 32, s1,
                     z.sig, &o2),
             NQOK);
      NQTEQI(ssig(al[a], &z, ctx, 3, ph, &c3, 1, n, rnd, 32, s2, &ol),
             NQOK);
      NQTEQM(s2, s1, z.sig);
      NQTEQI(sver(al[a], &z, ctx, 3, ph, 5, n, s1), NQOK);
    }
    /* hedged: another signature that verifies both ways */
    {
      size_t c3 = 10;
      NQTEQI(ssig(al[a], &z, NULL, 0, 0, &c3, 1, n, NULL, 0, s2, &ol),
             NQOK);
      NQTEQI(nqvrfy(al[a], pk, z.pk, msg, n, NULL, 0, 0, s2, ol), NQOK);
      NQTEQI(nqsign(al[a], sk, z.sk, msg, n, NULL, 0, 0, s1, z.sig, &o2),
             NQOK);
      NQTEQI(sver(al[a], &z, NULL, 0, 0, 299, n, s1), NQOK);
      s1[5] ^= 1;
      NQTEQI(sver(al[a], &z, NULL, 0, 0, 299, n, s1), NQEVRFY);
      /* another message */
      s1[5] ^= 1;
      NQTEQI(sver(al[a], &z, NULL, 0, 0, 299, n - 1, s1), NQEVRFY);
    }
  }
}

/* the pre-hash sets other than ML-DSA, with deterministic randomness */
static void tph(nqsalg a, int ph, const uint8_t *seed, size_t sl,
                const uint8_t *rnd, size_t rl) {
  static const uint8_t ctx[] = "stream";
  nqssz z;
  size_t cut, ol = 0, o2 = 0, n = 333;
  NQTEQI(nqssize(a, &z), NQOK);
  NQTEQI(nqskgd(a, seed, sl, pk, z.pk, sk, z.sk), NQOK);
  NQTEQI(nqsignd(a, sk, z.sk, msg, n, ctx, 6, ph, rnd, rl, s1, z.sig, &o2),
         NQOK);
  for (cut = 0; cut <= n; cut += 111) {
    NQTEQI(ssig(a, &z, ctx, 6, ph, &cut, 1, n, rnd != NULL ? rnd : msg, rl,
                s2, &ol),
           NQOK);
    NQTEQI(ol, z.sig);
    NQTEQM(s2, s1, z.sig);
    NQTEQI(sver(a, &z, ctx, 6, ph, n - cut, n, s1), NQOK);
  }
  NQTEQI(nqvrfy(a, pk, z.pk, msg, n, ctx, 6, ph, s2, ol), NQOK);
  /* hedged */
  NQTEQI(ssig(a, &z, ctx, 6, ph, &cut, 0, n, NULL, 0, s2, &ol), NQOK);
  NQTEQI(nqvrfy(a, pk, z.pk, msg, n, ctx, 6, ph, s2, ol), NQOK);
  s2[0] ^= 1;
  NQTEQI(sver(a, &z, ctx, 6, ph, 0, n, s2), NQEVRFY);
}

static void tothers(void) {
  uint8_t seed[96], rnd[32];
  memset(seed, 0x33, sizeof seed);
  memset(rnd, 0, sizeof rnd);
  tph(NQSLH128F, (int)NQS256, seed, 48, rnd, 16);
  tph(NQSLHK128F, (int)NQSHK128, seed, 48, rnd, 16);
  rnd[0] = 7; /* nonzero randomness, not the deterministic variant */
  tph(NQSLH128F, (int)NQS3256, seed, 48, rnd, 16);
  /* Ed25519ph: deterministic through rnd non-NULL, rndlen 0 */
  tph(NQED25519, (int)NQS512, seed, 32, NULL, 0);
  tph(NQMDED65, (int)NQS512, seed, 64, rnd, 32);
}

static void trefuse(void) {
  uint8_t seed[96], sig[64], other[32];
  nqsctx c;
  nqssz z;
  size_t ol = 0;
  memset(seed, 0x44, sizeof seed);
  NQTEQI(nqssize(NQSLH128F, &z), NQOK);
  NQTEQI(nqskgd(NQSLH128F, seed, 48, pk, z.pk, sk, z.sk), NQOK);
  NQTEQI(nqsini(&c, NQSLH128F, sk, z.sk, NULL, 0, 0), NQENOSUP);
  NQTEQI(nqvini(&c, NQSLH128F, pk, z.pk, NULL, 0, 0), NQENOSUP);
  NQTEQI(nqskgd(NQED25519, seed, 32, pk, 32, sk, 32), NQOK);
  NQTEQI(nqsini(&c, NQED25519, sk, 32, NULL, 0, 0), NQENOSUP);
  NQTEQI(nqsini(&c, NQED25519, sk, 32, (const uint8_t *)"c", 1, 0),
         NQENOSUP);
  NQTEQI(nqsini(&c, NQED25519, sk, 32, NULL, 0, (int)NQS256), NQENOSUP);
  NQTEQI(nqssize(NQMDED44, &z), NQOK);
  NQTEQI(nqskgd(NQMDED44, seed, 64, pk, z.pk, sk, z.sk), NQOK);
  NQTEQI(nqsini(&c, NQMDED44, sk, z.sk, NULL, 0, 0), NQENOSUP);
  NQTEQI(nqsini(&c, NQMDED44, sk, z.sk, NULL, 0, (int)NQS384), NQENOSUP);
  NQTEQI(nqsini(&c, (nqsalg)99, sk, z.sk, NULL, 0, 0), NQEARG);
  /* misuse */
  NQTEQI(nqssize(NQMLDSA44, &z), NQOK);
  NQTEQI(nqskgd(NQMLDSA44, seed, 32, pk, z.pk, sk, z.sk), NQOK);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk - 1, NULL, 0, 0), NQEDEC);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, NULL, 1, 0), NQEARG);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, seed, 256, 0), NQEARG);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, NULL, 0, 999), NQEARG);
  memset(&c, 0, sizeof c);
  NQTEQI(nqsupd(&c, msg, 1), NQESTATE);
  NQTEQI(nqsfin(&c, sk, z.sk, NULL, 0, s1, z.sig, &ol), NQESTATE);
  NQTEQI(nqvini(&c, NQMLDSA44, pk, z.pk, NULL, 0, 0), NQOK);
  NQTEQI(nqsupd(&c, NULL, 1), NQEARG);
  NQTEQI(nqsfin(&c, sk, z.sk, NULL, 0, s1, z.sig, &ol), NQESTATE);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, NULL, 0, 0), NQOK);
  NQTEQI(nqvfin(&c, pk, z.pk, s1, z.sig), NQESTATE);
  /* another key at the end: refused, and the context is used up */
  memset(other, 1, sizeof other);
  NQTEQI(nqsfin(&c, other, sizeof other, NULL, 0, s1, z.sig, &ol), NQEARG);
  NQTEQI(nqsupd(&c, msg, 1), NQESTATE);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, NULL, 0, 0), NQOK);
  NQTEQI(nqsfin(&c, sk, z.sk, NULL, 0, sig, sizeof sig, &ol), NQEBUF);
  NQTEQI(nqsini(&c, NQMLDSA44, sk, z.sk, NULL, 0, 0), NQOK);
  NQTEQI(nqsfin(&c, sk, z.sk, NULL, 0, s1, z.sig, &ol), NQOK);
  NQTEQI(nqsupd(&c, msg, 1), NQESTATE);
  NQTEQI(nqsfin(&c, sk, z.sk, NULL, 0, s1, z.sig, &ol), NQESTATE);
  /* a changed context */
  NQTEQI(nqvini(&c, NQMLDSA44, pk, z.pk, NULL, 0, 0), NQOK);
  ((uint8_t *)&c)[0] ^= 1;
  NQTEQI(nqvfin(&c, pk, z.pk, s1, z.sig), NQESTATE);
}

int main(void) {
  tmd();
  tothers();
  trefuse();
  return nqtdone("tstm");
}
