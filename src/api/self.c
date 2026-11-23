/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqselftest: known answers for every algorithm family, the kind of
 * self-test a cryptographic module runs before it is used (FIPS 140-3,
 * section 7.10). Each test runs fixed inputs through the library's
 * functions (the public API, and for AES-GCM, ChaCha20-Poly1305, HKDF
 * and X25519 the internal ones TLS uses) and hashes everything it
 * produces (keys, ciphertexts, signatures, secrets and the return codes,
 * so that a decapsulation or verification that disagrees changes the
 * hash); the hash must be the one stored here. The stored hashes were
 * computed by this library where its test suite checks the same
 * functions against the NIST ACVP and KAT vectors; tests 7 to 16 use
 * the inputs of one published vector each, so their hash is also the
 * SHA-256 of the return codes and the published outputs (kat.h).
 *
 * The freestanding build (NQFREE) has no AEAD, stream cipher or X25519
 * (src/aead, src/xdh are not in it): tests 11 to 16 are not there, and
 * Argon2id (test 10) runs only with an allocator from nqsetal. */
#include <string.h>

#include "noqtis.h"
#include "hash/h.h"
#include "core/lock.h"
#ifndef NQFREE
#include "aead/aead.h"
#include "xdh/xdh.h"
#endif

#define NT 17

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

/* the bytes of the hex string s into o; their count */
static size_t unhex(const char *s, uint8_t *o) {
  size_t n = 0;
  for (; s[0] != '\0' && s[1] != '\0'; s += 2) {
    unsigned v = 0, j;
    for (j = 0; j < 2; j++) {
      char c = s[j];
      v = v * 16u + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    o[n++] = (uint8_t)v;
  }
  return n;
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
  /* KangarooTwelve: one node, and a tree of two chunks with a
   * customization string */
  fill(b->sig, 9000, 3);
  putrc(h, nqkt(128, (const uint8_t *)"abc", 3, NULL, 0, b->ss, 32));
  put(h, b->ss, 32);
  putrc(h, nqkt(256, (const uint8_t *)"abc", 3, NULL, 0, b->ss, 64));
  put(h, b->ss, 64);
  putrc(h, nqkt(128, b->sig, 9000, (const uint8_t *)"noqtis", 6, b->ss, 32));
  put(h, b->ss, 32);
  putrc(h, nqkt(256, b->sig, 9000, (const uint8_t *)"noqtis", 6, b->ss, 64));
  put(h, b->ss, 64);
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

/* BLAKE2b-512 of "abc" (RFC 7693 appendix A) */
static void tb2b(nqs2ctx *h, sbuf *b) {
  putrc(h, nqb2b(NULL, 0, (const uint8_t *)"abc", 3, b->ss, 64));
  put(h, b->ss, 64);
}

/* HKDF-SHA-256, RFC 5869 appendix A.1: the PRK, then 42 bytes of OKM */
static void thkdf(nqs2ctx *h, sbuf *b) {
  size_t il = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", b->seed),
         sl = unhex("000102030405060708090a0b0c", b->pk),
         fl = unhex("f0f1f2f3f4f5f6f7f8f9", b->sk);
  putrc(h, nqhkx(NQS256, b->pk, sl, b->seed, il, b->ss));
  put(h, b->ss, 32);
  putrc(h, nqhke(NQS256, b->ss, 32, b->sk, fl, b->ct, 42));
  put(h, b->ct, 42);
}

/* PBKDF2-HMAC-SHA-256, RFC 7914 section 11: "passwd", "salt", 1
 * iteration, 64 bytes */
static void tpbkdf2(nqs2ctx *h, sbuf *b) {
  putrc(h, nqpbkdf2(NQS256, (const uint8_t *)"passwd", 6,
                    (const uint8_t *)"salt", 4, 1, b->ss, 64));
  put(h, b->ss, 64);
}

/* Argon2id, RFC 9106 section 5.3: 32 KiB, 3 passes, 4 lanes. 0 when it
 * cannot run: the freestanding build with no allocator */
static int targon2(nqs2ctx *h, sbuf *b) {
  int rc;
  memset(b->seed, 1, 32);
  memset(b->pk, 2, 16);
  memset(b->sk, 3, 8);
  memset(b->ct, 4, 12);
  rc = nqa2id(b->seed, 32, b->pk, 16, b->sk, 8, b->ct, 12, 3, 32, 4, b->ss,
              32);
#ifdef NQFREE
  if (rc == NQEMEM) return 0;
#endif
  putrc(h, rc);
  put(h, b->ss, 32);
  return 1;
}

#ifndef NQFREE
/* AES-256-GCM, test case 14 of the GCM specification (McGrew and
 * Viega): a zero key and IV, 16 zero bytes; sealed, opened, and opened
 * with the tag changed, which must fail */
static void tgcm(nqs2ctx *h, sbuf *b) {
  nqgcm g;
  memset(b->seed, 0, 32);
  memset(b->pk, 0, 16);
  putrc(h, nqgcmk(&g, b->seed, 32));
  putrc(h, nqgcme(&g, b->seed, 12, NULL, 0, b->pk, 16, b->ct, b->ss));
  put(h, b->ct, 16);
  put(h, b->ss, 16);
  putrc(h, nqgcmd(&g, b->seed, 12, NULL, 0, b->ct, 16, b->ss, 16, b->sk));
  put(h, b->sk, 16);
  b->ss[0] ^= 1;
  putrc(h, nqgcmd(&g, b->seed, 12, NULL, 0, b->ct, 16, b->ss, 16, b->sk));
  nqwipe(&g, sizeof g);
}

/* ChaCha20-Poly1305, RFC 8439 section 2.8.2; the same three steps */
static void tccp(nqs2ctx *h, sbuf *b) {
  static const char m[] =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";
  const size_t n = sizeof m - 1;
  size_t i;
  for (i = 0; i < 32; i++) b->seed[i] = (uint8_t)(0x80 + i);
  unhex("070000004041424344454647", b->seed + 32);
  unhex("50515253c0c1c2c3c4c5c6c7", b->seed + 48);
  putrc(h, nqccpe(b->seed, 32, b->seed + 32, 12, b->seed + 48, 12,
                  (const uint8_t *)m, n, b->ct, b->ss));
  put(h, b->ct, n);
  put(h, b->ss, 16);
  putrc(h, nqccpd(b->seed, 32, b->seed + 32, 12, b->seed + 48, 12, b->ct, n,
                  b->ss, 16, b->sk));
  put(h, b->sk, n);
  b->ss[0] ^= 1;
  putrc(h, nqccpd(b->seed, 32, b->seed + 32, 12, b->seed + 48, 12, b->ct, n,
                  b->ss, 16, b->sk));
}

/* the ChaCha20 stream, RFC 8439 appendix A.2 test vector 1: a zero key
 * and nonce, counter 0, 64 zero bytes */
static void tcha(nqs2ctx *h, sbuf *b) {
  memset(b->seed, 0, 44);
  memset(b->pk, 0, 64);
  putrc(h, nqcha20(b->seed, 32, b->seed + 32, 12, 0, b->pk, 64, b->ct));
  put(h, b->ct, 64);
}

/* AES-SIV, RFC 5297 appendix A.1 (deterministic): sealed, opened, and
 * opened with the IV changed, which must fail */
static void tsiv(nqs2ctx *h, sbuf *b) {
  const uint8_t *ad[1];
  size_t al[1];
  unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        b->seed);
  al[0] = unhex("101112131415161718191a1b1c1d1e1f2021222324252627", b->pk);
  unhex("112233445566778899aabbccddee", b->sk);
  ad[0] = b->pk;
  putrc(h, nqsivenc(b->seed, 32, ad, al, 1, b->sk, 14, b->ct, 30));
  put(h, b->ct, 30);
  putrc(h, nqsivdec(b->seed, 32, ad, al, 1, b->ct, 30, b->ss, 14));
  put(h, b->ss, 14);
  b->ct[0] ^= 1;
  putrc(h, nqsivdec(b->seed, 32, ad, al, 1, b->ct, 30, b->ss, 14));
}

/* AES-256-GCM-SIV, RFC 8452 appendix C.2: the key 01 00.., the nonce
 * 03 00.., associated data 01, plaintext 02 00 00 00 00 00 00 00; the
 * same three steps */
static void tgsiv(nqs2ctx *h, sbuf *b) {
  memset(b->seed, 0, 44);
  b->seed[0] = 1;
  b->seed[32] = 3;
  b->pk[0] = 1;
  memset(b->sk, 0, 8);
  b->sk[0] = 2;
  putrc(h, nqgsivenc(b->seed, 32, b->seed + 32, 12, b->pk, 1, b->sk, 8,
                     b->ct, 24));
  put(h, b->ct, 24);
  putrc(h, nqgsivdec(b->seed, 32, b->seed + 32, 12, b->pk, 1, b->ct, 24,
                     b->ss, 8));
  put(h, b->ss, 8);
  b->ct[23] ^= 1;
  putrc(h, nqgsivdec(b->seed, 32, b->seed + 32, 12, b->pk, 1, b->ct, 24,
                     b->ss, 8));
}

/* X25519, RFC 7748 section 5.2, the first vector */
static void tx25519(nqs2ctx *h, sbuf *b) {
  unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        b->seed);
  unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        b->pk);
  putrc(h, nqx25519(b->ss, b->seed, b->pk));
  put(h, b->ss, 32);
}
#endif

/* test i's hash into out; 0 when there is no test i (in the
 * freestanding build: one of a module it does not have, or Argon2id
 * with no allocator) */
int nqselfdg(int i, uint8_t out[32]);
/* b is static (44 KB is too much stack for small targets, and the
 * freestanding build has no allocator); the lock keeps two threads off it.
 * note: a spin lock held for one test (well under a second); a waiting
 * thread spins meanwhile. A progress or stop hook that calls nqselftest
 * from inside the self-test would deadlock. */
NQLKDEF(slk);

int nqselfdg(int i, uint8_t out[32]) {
  static sbuf b;
  nqs2ctx h;
  int ran = 1;
  if (i < 0 || i >= NT) return 0;
  nqlk(slk);
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
  case 6:
    tsig(&h, &b, NQED25519, 32, 1);
    tsig(&h, &b, NQMDED44, 64, 1);
    break;
  case 7: tb2b(&h, &b); break;
  case 8: thkdf(&h, &b); break;
  case 9: tpbkdf2(&h, &b); break;
  case 10: ran = targon2(&h, &b); break;
#ifndef NQFREE
  case 11: tgcm(&h, &b); break;
  case 12: tccp(&h, &b); break;
  case 13: tcha(&h, &b); break;
  case 14: tsiv(&h, &b); break;
  case 15: tgsiv(&h, &b); break;
  default: tx25519(&h, &b); break;
#else
  default: ran = 0; break;
#endif
  }
  nqs2fin(&h, out);
  nqwipe(&b, sizeof b);
  nqul(slk);
  return ran;
}

int nqselftest(void) {
  uint8_t dg[32];
  int i, ok = 1;
  for (i = 0; i < NT; i++) {
    if (nqselfdg(i, dg)) ok &= nqcteq(dg, want[i], 32);
  }
  nqwipe(dg, sizeof dg);
  return ok ? NQOK : NQEKAT;
}
