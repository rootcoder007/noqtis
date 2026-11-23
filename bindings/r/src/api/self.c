/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* nqselftest: known answers for every algorithm family, the kind of
 * self-test a cryptographic module runs before it is used (FIPS 140-3,
 * section 7.10). Each test runs fixed inputs through the library's
 * functions (the public API, and for the algorithms only the formats
 * and TLS use, the internal ones) and hashes everything it produces
 * (keys, ciphertexts, signatures, secrets and the return codes, so that
 * a decapsulation or verification that disagrees changes the hash); the
 * hash must be the one stored here. The stored hashes of tests 0 to 6
 * were computed by this library where its test suite checks the same
 * functions against the NIST ACVP and KAT vectors; tests 7 to 24 use
 * the inputs of one published vector each, so their hash is also the
 * SHA-256 of the return codes and the published outputs (kat.h).
 *
 * The freestanding build (NQFREE) has no AEAD, stream cipher, X25519 or
 * RSA and elliptic-curve code (src/aead, src/xdh and src/cls are not in
 * it): tests 11 to 16 and 19 to 24 are not there, and Argon2id (test
 * 10) runs only with an allocator from nqsetal. */
#include <string.h>

#include "noqtis.h"
#include "hash/h.h"
#include "drbg/drbg.h"
#include "core/lock.h"
#ifndef NQFREE
#include "aead/aead.h"
#include "cls/cls.h"
#include "xdh/xdh.h"
#endif

#define NT 25

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

/* SHA-1, the two examples of FIPS 180-4 (NIST's "abc" and the 448-bit
 * two-block message) */
static void tsha1(nqs2ctx *h, sbuf *b) {
  static const char m[] =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  nqs1((const uint8_t *)"abc", 3, b->ss);
  put(h, b->ss, 20);
  nqs1((const uint8_t *)m, sizeof m - 1, b->ss);
  put(h, b->ss, 20);
}

/* HMAC_DRBG with SHA-256 (SP 800-90A), NIST ACVP hmacDRBG-1.0, test
 * group 14 (no prediction resistance, a reseed), test 196: instantiate,
 * reseed, generate twice; the second output is the published one */
static void tdrbg(nqs2ctx *h, sbuf *b) {
  static const char ent[] =
      "4e77ae5d72ec8acc250e63ebbeb7c81b669e5846659729e13a3fd6bff57dfa4a3d3f"
      "69c2aa25afeda481c986f99ca5e9f7978c32372abab83a588322da2f4def945c8763"
      "a0c0b3f2d09071204f643abd61b0ee436c8ea7c5a20a835d17807e15a218ea335906"
      "9ae6daf8c1dff05dc2bdb69aa25844f0087e90e1693ba78dea926f617e1122f05704"
      "083333740d37a60c462beb0212ed77202a0c24b10aa31a0e";
  static const char non[] =
      "32dccce9342957ebe75281b2fa8ebf11945e1c325c1761651338a10e38eced7b";
  static const char ps[] =
      "6ce23bcd9495bd90e291054e06fced2021210707b463dffc5b3035c46a95dc11c791"
      "c245413c74d1472e97fbfd521269d1d08c130b36b62e287d09086604be798d02a019"
      "66bef0ad35133d6a92077a64399bc9290f691467aa280432e9a9e48499290377b64c"
      "059af99b7d1f9e61572caff3b24b8958a3907a57666b59ea48b2";
  static const char ra[] =
      "b217d75355259530dee946604a49b66c8d51cc00571eea15400fcc968f5879c69a32"
      "886f9899e772455f259d1e0a976636903eec50498a3b866fed3c98da8f0486656be1"
      "afedfdcb3d1d49e15970852d4c65711f5d002c0513385c956524908e";
  static const char re[] =
      "407f0da438e3cba8af9bec7d4f9e73e20552602969d0849409a4c47b95ad662a9a98"
      "7fcd528a7fad8edaefe19436aad8b3f143cc4f2b27c04d602eb8905a839f7d81b3f9"
      "7727d4481eb0559091d1f4385c55d5184de4ac4e92f7f427d39e5de36b80b3896e06"
      "2d880a90b0fb79b9b742870256ed3eee20300b21ffa4b0ded9ceabcf4a48147c3bb3"
      "4313076d15b770919ba505ac6d09b3b6c9c706a9b9709c11";
  static const char g1[] =
      "77c83cfc37db8ff97492a5fb26af35a25942a32591a1bf64b663f3089bdfcbddccf3"
      "9fa36be20a756f725eab46bf7f5028d7363d96c3ae166ba7de4250ff6bd33eecbaa6"
      "005e7a907f39e83fb82b0c95a6440707b209ca879aa001e5728aaf57";
  static const char g2[] =
      "6dce16966a09e9a29cb545bc10328bb49274dec29c586086f8e81b0b92f4b94ef044"
      "a798eb398025ed885a73746f084517b7a6c3f20a52156702cfea2ed62af728b92b18"
      "78a26b3937d1cdef6dc888c8d249e1bdebe2081b5c203b5772b8f6ba";
  nqdrbg d;
  uint8_t *p = b->ct;
  size_t el = unhex(ent, p), nl = unhex(non, p + 200), pl = unhex(ps, p + 300),
         al = unhex(ra, p + 500), rl = unhex(re, p + 700),
         l1 = unhex(g1, p + 900), l2 = unhex(g2, p + 1000);
  memset(&d, 0, sizeof d);
  putrc(h, nqdini(&d, NQS256, p, el, p + 200, nl, p + 300, pl, 0));
  putrc(h, nqdres(&d, p + 700, rl, p + 500, al));
  putrc(h, nqdgen(&d, b->sig, 512, p + 900, l1));
  putrc(h, nqdgen(&d, b->sig, 512, p + 1000, l2));
  put(h, b->sig, 512);
  nqdfree(&d);
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

/* AES key wrap, RFC 3394 section 4.1: wrapped, unwrapped, and unwrapped
 * with the wrapped key changed, which must fail */
static void tkw(nqs2ctx *h, sbuf *b) {
  unhex("000102030405060708090a0b0c0d0e0f", b->seed);
  unhex("00112233445566778899aabbccddeeff", b->pk);
  putrc(h, nqkwrap(b->seed, 16, b->pk, 16, b->ct));
  put(h, b->ct, 24);
  putrc(h, nqkunwrap(b->seed, 16, b->ct, 24, b->sk));
  put(h, b->sk, 16);
  b->ct[0] ^= 1;
  putrc(h, nqkunwrap(b->seed, 16, b->ct, 24, b->sk));
}

/* an AEAD with a 16-byte tag, as OCB and EAX: sealed (the ciphertext,
 * then the tag), opened, and opened with the tag changed, which must
 * fail */
typedef int (*aenc)(const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, size_t, const uint8_t *, size_t,
                    uint8_t *, uint8_t *);
typedef int (*adec)(const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, uint8_t *);
static void taead(nqs2ctx *h, sbuf *b, aenc e, adec d, const char *key,
                  const char *nonce, const char *ad, const char *pt) {
  size_t kl = unhex(key, b->seed), nl = unhex(nonce, b->seed + 32),
         al = unhex(ad, b->seed + 64), pl = unhex(pt, b->pk);
  putrc(h, e(b->seed, kl, b->seed + 32, nl, b->seed + 64, al, b->pk, pl,
             b->ct, b->ss));
  put(h, b->ct, pl);
  put(h, b->ss, 16);
  putrc(h, d(b->seed, kl, b->seed + 32, nl, b->seed + 64, al, b->ct, pl,
             b->ss, b->sk));
  put(h, b->sk, pl);
  b->ss[0] ^= 1;
  putrc(h, d(b->seed, kl, b->seed + 32, nl, b->seed + 64, al, b->ct, pl,
             b->ss, b->sk));
}

/* AES-128-OCB, RFC 7253 appendix A, the second vector */
static void tocb(nqs2ctx *h, sbuf *b) {
  taead(h, b, nqocbe, nqocbd, "000102030405060708090a0b0c0d0e0f",
        "bbaa99887766554433221101", "0001020304050607", "0001020304050607");
}

/* AES-128-EAX, the second vector of appendix G of Bellare, Rogaway and
 * Wagner, "The EAX Mode of Operation" */
static void teax(nqs2ctx *h, sbuf *b) {
  taead(h, b, nqeaxe, nqeaxd, "91945d3f4dcbee0bf45ef52255f095a4",
        "becaf043b0a23d843194ba972c66debd", "fa3bfd4806eb53fa", "f7fb");
}

/* the 2048-bit RSA key of Wycheproof's rsa_signature_2048_sha256 and
 * rsa_pss_2048_sha256_mgf1_32 sets (the same key) */
static const char rpk[] =
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a2"
    "b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f974"
    "6d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189"
    "db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313"
    "a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d"
    "9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411"
    "eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79"
    "d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773"
    "066f453d1f5b4c2e9cf7820283f742b9d50203010001";

/* RSA verification, test 1 (the empty message) of Wycheproof's
 * rsa_signature_2048_sha256 (PKCS#1 v1.5) and of
 * rsa_pss_2048_sha256_mgf1_32 (PSS, SHA-256, a 32-byte salt): for each,
 * the key parsed, the signature verified, and verified changed, which
 * must fail */
static void trsa(nqs2ctx *h, sbuf *b) {
  static const char s1[] =
      "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e54153"
      "6fcc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed47da4d4b7"
      "9421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c5123051a84a10c"
      "62f8dac2f42a8640008eb3c7cccd6760ff5b51b689763922582845f048fb8150e5a7"
      "a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7615013219c1941b6708e"
      "9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b396f27860b7f3ec4e9191703"
      "c6332d944f6f69751167680c79c4f6b57f1cc8755d24b6ec158ccdbacdb23107a33c"
      "b6b332516c13274d1f9dccc21dced869e486";
  static const char s2[] =
      "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ffce9d"
      "5c471694fcebfc6b45534864689256e4fc81c78e583f675d0c94b449647451e81bef"
      "f01a11a516d5e5ce3f1a910437cb8a3a5096b19fb15f4524a35b23d89cdba12cf5b7"
      "1aac1047b28c562df7c5542c34ce23a182cf7e0e231934b17294799d44877a1d68ef"
      "1b8f073619b7618e6b7c22db20030d98cf591ffc3d4da5f58613ecd5ecfc3b40a1d0"
      "2f40891ca43695cd4c088b05a8054c89c595a47e274816f35384226f74459ee63e25"
      "a1bfc03c360490552ec38343f8ace502f065303b00bc0ec320711b211fde92e57feb"
      "9013c3609342495ec0d7cabdec21e54acc38";
  static const nqpss pp = {NQS256, NQS256, 32};
  static const uint8_t m[1] = {0};
  nqck k;
  size_t kl = unhex(rpk, b->pk), sl = unhex(s1, b->sig);
  putrc(h, nqckey(&k, b->pk, kl));
  putrc(h, nqrsav(&k, NQS256, m, 0, b->sig, sl));
  b->sig[sl - 1] ^= 1;
  putrc(h, nqrsav(&k, NQS256, m, 0, b->sig, sl));
  sl = unhex(s2, b->sig);
  putrc(h, nqckey(&k, b->pk, kl));
  putrc(h, nqpssv(&k, &pp, m, 0, b->sig, sl));
  b->sig[sl - 1] ^= 1;
  putrc(h, nqpssv(&k, &pp, m, 0, b->sig, sl));
}

/* ECDSA P-256 with SHA-256, test 1 (the empty message, a DER signature)
 * of Wycheproof's ecdsa_secp256r1_sha256: the key parsed, the signature
 * verified, and verified with s changed, which must fail */
static void tecdsa(nqs2ctx *h, sbuf *b) {
  static const char pk[] =
      "3059301306072a8648ce3d020106082a8648ce3d0301070342000404aaec73635726"
      "f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba"
      "01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d";
  static const char sg[] =
      "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d87"
      "70b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf8"
      "9a62e2";
  static const uint8_t m[1] = {0};
  nqck k;
  size_t kl = unhex(pk, b->pk), sl = unhex(sg, b->sig);
  putrc(h, nqckey(&k, b->pk, kl));
  putrc(h, nqecv(&k, NQS256, m, 0, b->sig, sl, 0));
  b->sig[sl - 1] ^= 1;
  putrc(h, nqecv(&k, NQS256, m, 0, b->sig, sl, 0));
}

/* ECDH over P-256, RFC 8448 section 5: the client's public key from its
 * private key, and the shared secret with the server's share (the
 * handshake secret's IKM) */
static void tecdh(nqs2ctx *h, sbuf *b) {
  unhex("ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39",
        b->sk);
  unhex("04583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c"
        "8de6776f5b04ac07d83540eab3e3d9c547bc6528c4317d294686093a6cad7d",
        b->ct);
  putrc(h, nqecpub(NQP256, b->sk, b->pk));
  put(h, b->pk, 65);
  putrc(h, nqecdh(NQP256, b->sk, b->ct, 65, b->ss));
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
 * thread spins meanwhile. The self-test calls no progress or stop hook;
 * it does call the random source (nqsetrng: the masked code draws fresh
 * shares) and the allocator (nqsetal: Argon2id), and one of those that
 * called nqselftest would deadlock. */
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
  case 17: tsha1(&h, &b); break;
  case 18: tdrbg(&h, &b); break;
#ifndef NQFREE
  case 11: tgcm(&h, &b); break;
  case 12: tccp(&h, &b); break;
  case 13: tcha(&h, &b); break;
  case 14: tsiv(&h, &b); break;
  case 15: tgsiv(&h, &b); break;
  case 16: tx25519(&h, &b); break;
  case 19: tkw(&h, &b); break;
  case 20: tocb(&h, &b); break;
  case 21: teax(&h, &b); break;
  case 22: trsa(&h, &b); break;
  case 23: tecdsa(&h, &b); break;
  default: tecdh(&h, &b); break;
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
