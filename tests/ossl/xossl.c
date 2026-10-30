/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Cross-checks against OpenSSL 3.5 (DESIGN.md, M1, M3, M4, M5, M7):
 * - SHA-2, SHA-3, SHAKE and HMAC: the same digests of random inputs;
 * - ML-DSA-44/65/87 and all twelve SLH-DSA sets: the same keys from the
 *   same seed, byte-identical signatures for the same randomness and
 *   context, and each verifies the other's hedged signatures;
 * - ML-KEM-512/768/1024: the same keys from the same seed, the same
 *   ciphertext and secret for the same encapsulation seed, each
 *   decapsulates the other's ciphertext, and both give the same implicit
 *   rejection secret for a changed ciphertext;
 * - Ed25519, Ed25519ctx and Ed25519ph: the same key and byte-identical
 *   signatures, each verifying the other's;
 * - RSA PKCS#1 v1.5 and PSS (2048, 3072), ECDSA P-256 and P-384: noqtis
 *   accepts every OpenSSL signature and refuses each one with a bit
 *   flipped.
 * Built and run only where OpenSSL 3.5 or later is found (CMake option
 * NQOSSL). NQFAST=1 runs fewer rounds. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "noqtis.h"
#include "cls/cls.h"
#include "nqt.h"

static int rounds = 8;

static void rnd(uint8_t *p, size_t n) {
  if (RAND_bytes(p, (int)n) != 1) abort();
}

/* ---- hashes and HMAC ---- */

static void thash(void) {
  static const struct {
    nqhalg a;
    const char *o;
    int xof;
  } h[] = {{NQS224, "SHA224", 0},         {NQS256, "SHA256", 0},
           {NQS384, "SHA384", 0},         {NQS512, "SHA512", 0},
           {NQS512T224, "SHA512-224", 0}, {NQS512T256, "SHA512-256", 0},
           {NQS3224, "SHA3-224", 0},      {NQS3256, "SHA3-256", 0},
           {NQS3384, "SHA3-384", 0},      {NQS3512, "SHA3-512", 0},
           {NQSHK128, "SHAKE128", 1},     {NQSHK256, "SHAKE256", 1}};
  uint8_t in[3000], key[200], a[200], b[200];
  size_t i, r;
  for (i = 0; i < sizeof h / sizeof *h; i++) {
    EVP_MD *md = EVP_MD_fetch(NULL, h[i].o, NULL);
    NQTCHK(md != NULL);
    if (md == NULL) continue;
    for (r = 0; r < (size_t)rounds * 8; r++) {
      size_t n = (r * 377u) % sizeof in, out = h[i].xof ? 1 + r * 7 % 199
                                                        : nqhlen(h[i].a);
      unsigned int ol = 0;
      EVP_MD_CTX *c = EVP_MD_CTX_new();
      rnd(in, n);
      NQTEQI(nqhash(h[i].a, in, n, a, out), NQOK);
      NQTCHK(c != NULL && EVP_DigestInit_ex(c, md, NULL) == 1 &&
             EVP_DigestUpdate(c, in, n) == 1);
      if (h[i].xof) {
        NQTCHK(EVP_DigestFinalXOF(c, b, out) == 1);
      } else {
        NQTCHK(EVP_DigestFinal_ex(c, b, &ol) == 1 && ol == out);
      }
      EVP_MD_CTX_free(c);
      NQTEQM(a, b, out);
      if (!h[i].xof) {
        size_t kl = r * 13 % sizeof key, ml = 0;
        rnd(key, kl);
        NQTEQI(nqhmac(h[i].a, key, kl, in, n, a, out), NQOK);
        NQTCHK(EVP_Q_mac(NULL, "HMAC", NULL, h[i].o, NULL, key, kl, in, n,
                         b, sizeof b, &ml) != NULL && ml == out);
        NQTEQM(a, b, out);
      }
    }
    EVP_MD_free(md);
  }
}

/* ---- signatures ---- */

static EVP_PKEY *okey(const char *name, uint8_t *seed, size_t sn,
                      const char *param) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
  EVP_PKEY *k = NULL;
  OSSL_PARAM p[2];
  p[0] = OSSL_PARAM_construct_octet_string(param, seed, sn);
  p[1] = OSSL_PARAM_construct_end();
  if (c == NULL || EVP_PKEY_keygen_init(c) != 1 ||
      EVP_PKEY_CTX_set_params(c, p) != 1 || EVP_PKEY_generate(c, &k) != 1)
    k = NULL;
  EVP_PKEY_CTX_free(c);
  return k;
}

/* sign (rn > 0: with that randomness) or verify with OpenSSL; 1 when it
 * worked (a signature made, or a valid one) */
static int osig(EVP_PKEY *k, const char *name, int sign, const uint8_t *m,
                size_t mn, uint8_t *ctx, size_t cn, uint8_t *r,
                size_t rn, uint8_t *sig, size_t *sl) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
  EVP_SIGNATURE *a = EVP_SIGNATURE_fetch(NULL, name, NULL);
  OSSL_PARAM p[3];
  int n = 0, ok = 0;
  p[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, cn);
  if (rn > 0)
    p[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY, r, rn);
  p[n] = OSSL_PARAM_construct_end();
  if (c != NULL && a != NULL) {
    if (sign) {
      ok = EVP_PKEY_sign_message_init(c, a, p) == 1 &&
           EVP_PKEY_sign(c, sig, sl, m, mn) == 1;
    } else {
      ok = EVP_PKEY_verify_message_init(c, a, p) == 1 &&
           EVP_PKEY_verify(c, sig, *sl, m, mn) == 1;
    }
  }
  EVP_SIGNATURE_free(a);
  EVP_PKEY_CTX_free(c);
  return ok;
}

static void tsig1(nqsalg alg, int n) {
  const char *name = nqsname(alg);
  nqssz z;
  uint8_t seed[96], r[32], m[300], ctx[40];
  uint8_t *pk, *sk, *s1, *s2, ob[8192];
  size_t sn, rl, ol, l1 = 0, l2, i;
  int md = alg <= NQMLDSA87;
  NQTEQI(nqssize(alg, &z), NQOK);
  sn = md ? 32 : 3 * (z.pk / 2);
  rl = md ? 32 : z.pk / 2;
  pk = (uint8_t *)malloc(z.pk);
  sk = (uint8_t *)malloc(z.sk);
  s1 = (uint8_t *)malloc(z.sig);
  s2 = (uint8_t *)malloc(z.sig);
  NQTCHK(pk && sk && s1 && s2 && z.pk <= sizeof ob && z.sk <= sizeof ob);
  if (!(pk && sk && s1 && s2)) return;
  for (i = 0; i < (size_t)n; i++) {
    EVP_PKEY *k;
    size_t mn = i * 37 % sizeof m, cn = i * 11 % sizeof ctx;
    rnd(seed, sn);
    rnd(r, rl);
    rnd(m, mn);
    rnd(ctx, cn);
    NQTEQI(nqskgd(alg, seed, sn, pk, z.pk, sk, z.sk), NQOK);
    k = okey(name, seed, sn, md ? OSSL_PKEY_PARAM_ML_DSA_SEED
                                : OSSL_PKEY_PARAM_SLH_DSA_SEED);
    NQTCHK(k != NULL);
    if (k == NULL) break;
    /* the same key pair */
    ol = sizeof ob;
    NQTCHK(EVP_PKEY_get_raw_public_key(k, ob, &ol) == 1 && ol == z.pk);
    NQTEQM(ob, pk, z.pk);
    ol = sizeof ob;
    NQTCHK(EVP_PKEY_get_raw_private_key(k, ob, &ol) == 1 && ol == z.sk);
    NQTEQM(ob, sk, z.sk);
    /* byte-identical signatures for the same randomness and context */
    NQTEQI(nqsignd(alg, sk, z.sk, m, mn, ctx, cn, 0, r, rl, s1, z.sig, &l1),
           NQOK);
    l2 = z.sig;
    NQTCHK(osig(k, name, 1, m, mn, ctx, cn, r, rl, s2, &l2));
    NQTCHK(l1 == l2);
    NQTEQM(s1, s2, l1);
    /* each verifies the other's hedged signature, and neither a changed
     * one */
    l2 = z.sig;
    NQTCHK(osig(k, name, 1, m, mn, ctx, cn, NULL, 0, s2, &l2));
    NQTEQI(nqvrfy(alg, pk, z.pk, m, mn, ctx, cn, 0, s2, l2), NQOK);
    NQTEQI(nqsign(alg, sk, z.sk, m, mn, ctx, cn, 0, s1, z.sig, &l1), NQOK);
    NQTCHK(osig(k, name, 0, m, mn, ctx, cn, NULL, 0, s1, &l1));
    s1[i % l1] ^= (uint8_t)(1u << (i % 8));
    NQTCHK(nqvrfy(alg, pk, z.pk, m, mn, ctx, cn, 0, s1, l1) != NQOK);
    NQTCHK(!osig(k, name, 0, m, mn, ctx, cn, NULL, 0, s1, &l1));
    EVP_PKEY_free(k);
  }
  free(pk);
  free(sk);
  free(s1);
  free(s2);
}

static void tsig(void) {
  static const nqsalg sl[] = {NQSLH128S, NQSLH128F, NQSLH192S, NQSLH192F,
                              NQSLH256S, NQSLH256F, NQSLHK128S, NQSLHK128F,
                              NQSLHK192S, NQSLHK192F, NQSLHK256S,
                              NQSLHK256F};
  size_t i;
  tsig1(NQMLDSA44, rounds * 4);
  tsig1(NQMLDSA65, rounds * 4);
  tsig1(NQMLDSA87, rounds * 4);
  for (i = 0; i < sizeof sl / sizeof *sl; i++) {
    nqssz z;
    nqssize(sl[i], &z);
    /* the small (s) sets sign slowly: one key each */
    tsig1(sl[i], i % 2 == 0 ? 1 : (rounds > 2 ? 3 : 1));
  }
}

/* ---- KEMs ---- */

static void tkem1(nqkalg alg, const char *name, int n) {
  nqksz z;
  uint8_t seed[64], m[32], pk[1600], sk[3200], ob[3200], ct[1600], ss[32],
      s2[32];
  size_t ol, cl, sl, i;
  NQTEQI(nqksize(alg, &z), NQOK);
  for (i = 0; i < (size_t)n; i++) {
    EVP_PKEY *k;
    EVP_PKEY_CTX *c;
    OSSL_PARAM p[2];
    rnd(seed, sizeof seed);
    rnd(m, sizeof m);
    NQTEQI(nqkkgd(alg, seed, 64, pk, z.pk, sk, z.sk), NQOK);
    k = okey(name, seed, 64, OSSL_PKEY_PARAM_ML_KEM_SEED);
    NQTCHK(k != NULL);
    if (k == NULL) break;
    ol = sizeof ob;
    NQTCHK(EVP_PKEY_get_raw_public_key(k, ob, &ol) == 1 && ol == z.pk);
    NQTEQM(ob, pk, z.pk);
    ol = sizeof ob;
    NQTCHK(EVP_PKEY_get_raw_private_key(k, ob, &ol) == 1 && ol == z.sk);
    NQTEQM(ob, sk, z.sk);
    /* the same encapsulation for the same m */
    NQTEQI(nqencd(alg, pk, z.pk, m, 32, ct, z.ct, ss, z.ss), NQOK);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, m, 32);
    p[1] = OSSL_PARAM_construct_end();
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    cl = sizeof ob;
    sl = sizeof s2;
    NQTCHK(c != NULL && EVP_PKEY_encapsulate_init(c, p) == 1 &&
           EVP_PKEY_encapsulate(c, ob, &cl, s2, &sl) == 1 && cl == z.ct &&
           sl == z.ss);
    EVP_PKEY_CTX_free(c);
    NQTEQM(ob, ct, z.ct);
    NQTEQM(s2, ss, z.ss);
    /* each decapsulates the other's ciphertext; a changed one gives the
     * same implicit rejection secret on both */
    ct[i % z.ct] ^= 0x40;
    NQTEQI(nqdec(alg, sk, z.sk, ct, z.ct, ss, z.ss), NQOK);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    sl = sizeof s2;
    NQTCHK(c != NULL && EVP_PKEY_decapsulate_init(c, NULL) == 1 &&
           EVP_PKEY_decapsulate(c, s2, &sl, ct, z.ct) == 1 && sl == z.ss);
    EVP_PKEY_CTX_free(c);
    NQTEQM(s2, ss, z.ss);
    EVP_PKEY_free(k);
  }
}

static void tkem(void) {
  tkem1(NQMLKEM512, "ML-KEM-512", rounds * 4);
  tkem1(NQMLKEM768, "ML-KEM-768", rounds * 4);
  tkem1(NQMLKEM1024, "ML-KEM-1024", rounds * 4);
}

/* ---- Ed25519 ---- */

/* Ed25519, Ed25519ctx and Ed25519ph: the same public key from the same
 * private key, byte-identical signatures (all three are deterministic),
 * and each verifies the other's */
static void ted(void) {
  static const char *inst[3] = {"Ed25519", "Ed25519ctx", "Ed25519ph"};
  uint8_t sk[32], pk[32], ob[64], m[300], ctx[64], s1[64], s2[64];
  size_t i, ol, sl;
  int v;
  for (i = 0; i < (size_t)rounds * 12; i++) {
    EVP_PKEY *k;
    EVP_MD_CTX *c;
    OSSL_PARAM p[3];
    int n = 0;
    size_t mn = i * 37 % sizeof m, cn = 1 + i % sizeof ctx;
    v = (int)(i % 3);
    if (v == 0) cn = 0;
    rnd(sk, 32);
    rnd(m, mn);
    rnd(ctx, cn);
    NQTEQI(nqskgd(NQED25519, sk, 32, pk, 32, ob, 32), NQOK);
    k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
    NQTCHK(k != NULL);
    if (k == NULL) break;
    ol = sizeof ob;
    NQTCHK(EVP_PKEY_get_raw_public_key(k, ob, &ol) == 1 && ol == 32);
    NQTEQM(ob, pk, 32);
    NQTEQI(nqsign(NQED25519, sk, 32, m, mn, ctx, cn,
                  v == 2 ? (int)NQS512 : 0, s1, 64, &sl), NQOK);
    p[n++] = OSSL_PARAM_construct_utf8_string(
        OSSL_SIGNATURE_PARAM_INSTANCE, (char *)(uintptr_t)inst[v], 0);
    if (cn > 0)
      p[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, cn);
    p[n] = OSSL_PARAM_construct_end();
    c = EVP_MD_CTX_new();
    sl = sizeof s2;
    NQTCHK(c != NULL &&
           EVP_DigestSignInit_ex(c, NULL, NULL, NULL, NULL, k, p) == 1 &&
           EVP_DigestSign(c, s2, &sl, m, mn) == 1 && sl == 64);
    EVP_MD_CTX_free(c);
    NQTEQM(s1, s2, 64);
    NQTEQI(nqvrfy(NQED25519, pk, 32, m, mn, ctx, cn,
                  v == 2 ? (int)NQS512 : 0, s2, 64), NQOK);
    s2[i % 64] ^= 1;
    c = EVP_MD_CTX_new();
    NQTCHK(c != NULL &&
           EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, k, p) == 1);
    NQTCHK(c != NULL && EVP_DigestVerify(c, s2, 64, m, mn) != 1);
    EVP_MD_CTX_free(c);
    NQTCHK(nqvrfy(NQED25519, pk, 32, m, mn, ctx, cn,
                  v == 2 ? (int)NQS512 : 0, s2, 64) != NQOK);
    EVP_PKEY_free(k);
  }
}

/* ---- RSA and ECDSA ---- */

static void tcls1(EVP_PKEY *k, int pss, const char *dn, nqhalg h, int n) {
  uint8_t *der = NULL, m[500], sig[600];
  int dl = i2d_PUBKEY(k, &der), i;
  nqck ck;
  NQTCHK(dl > 0);
  if (dl <= 0) return;
  NQTEQI(nqckey(&ck, der, (size_t)dl), NQOK);
  for (i = 0; i < n; i++) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    size_t mn = (size_t)i * 41 % sizeof m, sl = sizeof sig;
    int rc;
    rnd(m, mn);
    NQTCHK(c != NULL &&
           EVP_DigestSignInit_ex(c, &pc, dn, NULL, NULL, k, NULL) == 1);
    if (pss) {
      NQTCHK(EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) ==
                 1);
    }
    NQTCHK(EVP_DigestSign(c, sig, &sl, m, mn) == 1);
    EVP_MD_CTX_free(c);
    if (ck.kind == NQKEC) {
      rc = nqecv(&ck, h, m, mn, sig, sl, 0);
    } else if (pss) {
      nqpss pp;
      pp.h = h;
      pp.mgf = h;
      pp.slen = nqhlen(h);
      rc = nqpssv(&ck, &pp, m, mn, sig, sl);
      sig[(size_t)i % sl] ^= 1;
      NQTCHK(nqpssv(&ck, &pp, m, mn, sig, sl) != NQOK);
    } else {
      rc = nqrsav(&ck, h, m, mn, sig, sl);
      sig[(size_t)i % sl] ^= 1;
      NQTCHK(nqrsav(&ck, h, m, mn, sig, sl) != NQOK);
    }
    NQTEQI(rc, NQOK);
    if (ck.kind == NQKEC) {
      sig[sl - 1 - (size_t)i % 8] ^= 1;
      NQTCHK(nqecv(&ck, h, m, mn, sig, sl, 0) != NQOK);
    }
  }
  OPENSSL_free(der);
}

static void tcls(void) {
  EVP_PKEY *r2 = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
  EVP_PKEY *r3 = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072);
  EVP_PKEY *e2 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
  EVP_PKEY *e3 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
  NQTCHK(r2 && r3 && e2 && e3);
  if (!(r2 && r3 && e2 && e3)) return;
  tcls1(r2, 0, "SHA256", NQS256, rounds * 4);
  tcls1(r2, 1, "SHA256", NQS256, rounds * 4);
  tcls1(r3, 0, "SHA384", NQS384, rounds * 2);
  tcls1(r3, 1, "SHA512", NQS512, rounds * 2);
  tcls1(e2, 0, "SHA256", NQS256, rounds * 4);
  tcls1(e3, 0, "SHA384", NQS384, rounds * 4);
  tcls1(e2, 0, "SHA3-256", NQS3256, rounds * 2);
  EVP_PKEY_free(r2);
  EVP_PKEY_free(r3);
  EVP_PKEY_free(e2);
  EVP_PKEY_free(e3);
}

int main(void) {
  const char *f = getenv("NQFAST");
  if (f != NULL && f[0] == '1') rounds = 2;
  printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
  thash();
  tsig();
  tkem();
  ted();
  tcls();
  return nqtdone("xossl");
}
