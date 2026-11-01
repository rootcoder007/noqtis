/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqselftest: known answers for every algorithm family, the kind of
 * self-test a cryptographic module runs before it is used (FIPS 140-3,
 * section 7.10). Each test runs fixed inputs through the public API and
 * hashes everything it produces (keys, ciphertexts, signatures, secrets
 * and the return codes, so that a decapsulation or verification that
 * disagrees changes the hash); the hash must be the one stored here. The
 * stored hashes were computed by this library where its test suite
 * checks the same functions against the NIST ACVP and KAT vectors. */
#include <string.h>

#include "noqtis.h"
#include "hash/h.h"

#define NT 7

/* the SHA-256 of each test's outputs */
static const uint8_t want[NT][32] = {
#include "api/kat.h"
};

static void put(nqs2ctx *h, const uint8_t *p, size_t n) {
  nqs2upd(h, p, n);
}

static void putrc(nqs2ctx *h, int rc) {
  uint8_t b = (uint8_t)(rc & 0xff);
  nqs2upd(h, &b, 1);
}

static void fill(uint8_t *p, size_t n, unsigned s) {
  size_t i;
  for (i = 0; i < n; i++) p[i] = (uint8_t)(i * 7u + s);
}

/* buffers for the largest sets tested */
typedef struct {
  uint8_t pk[8000], sk[8000], ct[8000], sig[20000], ss[64], ss2[64];
  uint8_t seed[128];
} sbuf;

static void thash(nqs2ctx *h, sbuf *b) {
  static const nqhalg hs[12] = {NQS224, NQS256, NQS384, NQS512,
                                NQS512T224, NQS512T256, NQS3224, NQS3256,
                                NQS3384, NQS3512, NQSHK128, NQSHK256};
  size_t i;
  for (i = 0; i < 12; i++) {
    const size_t n = nqhlen(hs[i]);
    putrc(h, nqhash(hs[i], (const uint8_t *)"abc", 3, b->ss, n));
    put(h, b->ss, n);
  }
}

static void thmac(nqs2ctx *h, sbuf *b) {
  static const char m[] = "what do ya want for nothing?";
  putrc(h, nqhmac(NQS256, (const uint8_t *)"Jefe", 4, (const uint8_t *)m,
                  sizeof m - 1, b->ss, 32));
  put(h, b->ss, 32);
  putrc(h, nqhmac(NQS512, (const uint8_t *)"Jefe", 4, (const uint8_t *)m,
                  sizeof m - 1, b->ss, 64));
  put(h, b->ss, 64);
}

/* a KEM: key pair and encapsulation from fixed seeds, decapsulation */
static void tkem(nqs2ctx *h, sbuf *b, nqkalg a, size_t ksl, size_t esl) {
  nqksz z;
  putrc(h, nqksize(a, &z));
  fill(b->seed, ksl, 1);
  putrc(h, nqkkgd(a, b->seed, ksl, b->pk, z.pk, b->sk, z.sk));
  put(h, b->pk, z.pk);
  put(h, b->sk, z.sk);
  fill(b->seed, esl, 2);
  putrc(h, nqencd(a, b->pk, z.pk, b->seed, esl, b->ct, z.ct, b->ss, z.ss));
  put(h, b->ct, z.ct);
  put(h, b->ss, z.ss);
  putrc(h, nqdec(a, b->sk, z.sk, b->ct, z.ct, b->ss2, z.ss));
  put(h, b->ss2, z.ss);
}

/* a signature set: key pair from a fixed seed; when sign, the
 * deterministic signature of a fixed message and its verification */
static void tsig(nqs2ctx *h, sbuf *b, nqsalg a, size_t sl, int sign) {
  static const uint8_t m[] = "noqtis self-test";
  uint8_t rnd[32];
  nqssz z;
  size_t n = 0, rl = a == NQED25519 ? 0 : 32;
  putrc(h, nqssize(a, &z));
  fill(b->seed, sl, 3);
  putrc(h, nqskgd(a, b->seed, sl, b->pk, z.pk, b->sk, z.sk));
  put(h, b->pk, z.pk);
  if (!sign) return;
  memset(rnd, 0, sizeof rnd);
  putrc(h, nqsignd(a, b->sk, z.sk, m, sizeof m - 1, NULL, 0, 0,
                   rl ? rnd : NULL, rl, b->sig, z.sig, &n));
  put(h, b->sig, n);
  putrc(h, nqvrfy(a, b->pk, z.pk, m, sizeof m - 1, NULL, 0, 0, b->sig, n));
}

/* test i's hash into out; 0 when there is no test i */
int nqselfdg(int i, uint8_t out[32]);
int nqselfdg(int i, uint8_t out[32]) {
  static sbuf b;
  nqs2ctx h;
  if (i < 0 || i >= NT) return 0;
  memset(&b, 0, sizeof b);
  nqs2ini(&h, 32);
  switch (i) {
  case 0: thash(&h, &b); break;
  case 1: thmac(&h, &b); break;
  case 2:
    tkem(&h, &b, NQMLKEM512, 64, 32);
    tkem(&h, &b, NQMLKEM768, 64, 32);
    tkem(&h, &b, NQMLKEM1024, 64, 32);
    break;
  case 3:
    tsig(&h, &b, NQMLDSA44, 32, 1);
    tsig(&h, &b, NQMLDSA65, 32, 1);
    tsig(&h, &b, NQMLDSA87, 32, 1);
    break;
  case 4:
    tsig(&h, &b, NQSLH128F, 48, 0);
    tsig(&h, &b, NQSLHK128F, 48, 0);
    break;
  case 5: tkem(&h, &b, NQHQC128, 32, 32); break;
  default:
    tsig(&h, &b, NQED25519, 32, 1);
    tsig(&h, &b, NQMDED44, 64, 1);
    break;
  }
  nqs2fin(&h, out);
  nqwipe(&b, sizeof b);
  return 1;
}

int nqselftest(void) {
  uint8_t dg[32];
  int i, ok = 1;
  for (i = 0; i < NT; i++) {
    nqselfdg(i, dg);
    ok &= nqcteq(dg, want[i], 32);
  }
  nqwipe(dg, sizeof dg);
  return ok ? NQOK : NQEKAT;
}
