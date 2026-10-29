/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer differential target against OpenSSL 3.5 or later (M10). The
 * input's first byte picks a check, the rest feeds it:
 *   0  a digest or HMAC of the rest: the same bytes from both;
 *   1  ML-DSA: the same key and signature from a seed, randomness and
 *      message in the input; then a signature changed as the input says
 *      is accepted by both or by neither;
 *   2  ML-KEM: the same key, ciphertext and secret from the seeds in the
 *      input; then a ciphertext changed as the input says decapsulates
 *      to the same secret on both;
 *   3  RSA PKCS#1 v1.5, RSA-PSS and ECDSA P-256/P-384 with keys made at
 *      start: OpenSSL signs the message, the input changes the
 *      signature, and whatever noqtis accepts OpenSSL accepts too.
 * Any difference aborts. Built only by fuzz/build.sh with NQOSSL=1 (not
 * for OSS-Fuzz), linked with -lcrypto. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "noqtis.h"
#include "cls/cls.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define NEED(c) \
  do {          \
    if (!(c)) abort(); \
  } while (0)

/* the input, read from the front; past the end it reads zeros */
typedef struct {
  const uint8_t *p;
  size_t n;
} rd;

static void take(rd *r, uint8_t *out, size_t n) {
  size_t k = n < r->n ? n : r->n;
  memcpy(out, r->p, k);
  memset(out + k, 0, n - k);
  r->p += k;
  r->n -= k;
}
static unsigned byte(rd *r) {
  uint8_t b;
  take(r, &b, 1);
  return b;
}

/* changes buf as the rest of the input says: pairs of (offset, xor) */
static void mutate(rd *r, uint8_t *buf, size_t n) {
  while (r->n >= 3 && n > 0) {
    size_t at = ((size_t)r->p[0] << 8 | r->p[1]) % n;
    buf[at] ^= r->p[2];
    r->p += 3;
    r->n -= 3;
  }
}

static EVP_PKEY *okey(const char *name, uint8_t *seed, size_t sn,
                      const char *param) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
  EVP_PKEY *k = NULL;
  OSSL_PARAM p[2];
  p[0] = OSSL_PARAM_construct_octet_string(param, seed, sn);
  p[1] = OSSL_PARAM_construct_end();
  NEED(c != NULL && EVP_PKEY_keygen_init(c) == 1 &&
       EVP_PKEY_CTX_set_params(c, p) == 1 && EVP_PKEY_generate(c, &k) == 1);
  EVP_PKEY_CTX_free(c);
  return k;
}

static void fhash(rd *r) {
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
  unsigned i = byte(r) % (sizeof h / sizeof *h), kl = byte(r);
  size_t out = h[i].xof ? 1 + byte(r) : nqhlen(h[i].a), ml = 0;
  uint8_t key[255], a[256], b[256];
  EVP_MD *md = EVP_MD_fetch(NULL, h[i].o, NULL);
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  unsigned int ol = 0;
  take(r, key, kl);
  NEED(md != NULL && c != NULL);
  NEED(nqhash(h[i].a, r->p, r->n, a, out) == NQOK);
  NEED(EVP_DigestInit_ex(c, md, NULL) == 1 &&
       EVP_DigestUpdate(c, r->p, r->n) == 1);
  if (h[i].xof) {
    NEED(EVP_DigestFinalXOF(c, b, out) == 1);
  } else {
    NEED(EVP_DigestFinal_ex(c, b, &ol) == 1 && ol == out);
  }
  NEED(memcmp(a, b, out) == 0);
  if (!h[i].xof) {
    NEED(nqhmac(h[i].a, key, kl, r->p, r->n, a, out) == NQOK);
    NEED(EVP_Q_mac(NULL, "HMAC", NULL, h[i].o, NULL, key, kl, r->p, r->n, b,
                   sizeof b, &ml) != NULL && ml == out);
    NEED(memcmp(a, b, out) == 0);
  }
  EVP_MD_CTX_free(c);
  EVP_MD_free(md);
}

static int overify(EVP_PKEY *k, const char *name, const uint8_t *m,
                   size_t mn, uint8_t *ctx, size_t cn, const uint8_t *sig,
                   size_t sl) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
  EVP_SIGNATURE *a = EVP_SIGNATURE_fetch(NULL, name, NULL);
  OSSL_PARAM p[2];
  int ok;
  p[0] = OSSL_PARAM_construct_octet_string(
      OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, cn);
  p[1] = OSSL_PARAM_construct_end();
  NEED(c != NULL && a != NULL);
  ok = EVP_PKEY_verify_message_init(c, a, p) == 1 &&
       EVP_PKEY_verify(c, sig, sl, m, mn) == 1;
  EVP_SIGNATURE_free(a);
  EVP_PKEY_CTX_free(c);
  return ok;
}

static void fmldsa(rd *r) {
  static const nqsalg al[] = {NQMLDSA44, NQMLDSA65, NQMLDSA87};
  nqsalg alg = al[byte(r) % 3];
  const char *name = nqsname(alg);
  uint8_t seed[32], rn[32], ctx[64], m[256], pk[2600], sk[4900],
      s1[4700], s2[4700], ob[4900];
  size_t cn = byte(r) % sizeof ctx, mn = byte(r), l1 = 0, l2 = sizeof s2,
         ol = sizeof ob;
  nqssz z;
  EVP_PKEY *k;
  EVP_PKEY_CTX *c;
  EVP_SIGNATURE *a;
  OSSL_PARAM p[3];
  NEED(nqssize(alg, &z) == NQOK && z.pk <= sizeof pk && z.sk <= sizeof sk &&
       z.sig <= sizeof s1);
  take(r, seed, 32);
  take(r, rn, 32);
  take(r, ctx, cn);
  take(r, m, mn);
  NEED(nqskgd(alg, seed, 32, pk, z.pk, sk, z.sk) == NQOK);
  k = okey(name, seed, 32, OSSL_PKEY_PARAM_ML_DSA_SEED);
  NEED(EVP_PKEY_get_raw_public_key(k, ob, &ol) == 1 && ol == z.pk &&
       memcmp(ob, pk, z.pk) == 0);
  NEED(nqsignd(alg, sk, z.sk, m, mn, ctx, cn, 0, rn, 32, s1, z.sig, &l1) ==
       NQOK);
  c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
  a = EVP_SIGNATURE_fetch(NULL, name, NULL);
  p[0] = OSSL_PARAM_construct_octet_string(
      OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, cn);
  p[1] = OSSL_PARAM_construct_octet_string(
      OSSL_SIGNATURE_PARAM_TEST_ENTROPY, rn, 32);
  p[2] = OSSL_PARAM_construct_end();
  NEED(c != NULL && a != NULL && EVP_PKEY_sign_message_init(c, a, p) == 1 &&
       EVP_PKEY_sign(c, s2, &l2, m, mn) == 1);
  EVP_SIGNATURE_free(a);
  EVP_PKEY_CTX_free(c);
  NEED(l1 == l2 && memcmp(s1, s2, l1) == 0);
  mutate(r, s1, l1);
  NEED((nqvrfy(alg, pk, z.pk, m, mn, ctx, cn, 0, s1, l1) == NQOK) ==
       overify(k, name, m, mn, ctx, cn, s1, l1));
  EVP_PKEY_free(k);
}

static void fmlkem(rd *r) {
  static const struct {
    nqkalg a;
    const char *o;
  } al[] = {{NQMLKEM512, "ML-KEM-512"},
            {NQMLKEM768, "ML-KEM-768"},
            {NQMLKEM1024, "ML-KEM-1024"}};
  unsigned i = byte(r) % 3;
  uint8_t seed[64], m[32], pk[1600], sk[3200], ob[3200], ct[1600], ss[32],
      s2[32];
  size_t ol = sizeof ob, cl = sizeof ob, sl = sizeof s2;
  nqksz z;
  EVP_PKEY *k;
  EVP_PKEY_CTX *c;
  OSSL_PARAM p[2];
  NEED(nqksize(al[i].a, &z) == NQOK);
  take(r, seed, 64);
  take(r, m, 32);
  NEED(nqkkgd(al[i].a, seed, 64, pk, z.pk, sk, z.sk) == NQOK);
  k = okey(al[i].o, seed, 64, OSSL_PKEY_PARAM_ML_KEM_SEED);
  NEED(EVP_PKEY_get_raw_public_key(k, ob, &ol) == 1 && ol == z.pk &&
       memcmp(ob, pk, z.pk) == 0);
  NEED(nqencd(al[i].a, pk, z.pk, m, 32, ct, z.ct, ss, z.ss) == NQOK);
  p[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, m, 32);
  p[1] = OSSL_PARAM_construct_end();
  c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
  NEED(c != NULL && EVP_PKEY_encapsulate_init(c, p) == 1 &&
       EVP_PKEY_encapsulate(c, ob, &cl, s2, &sl) == 1 && cl == z.ct &&
       sl == z.ss && memcmp(ob, ct, z.ct) == 0 && memcmp(s2, ss, z.ss) == 0);
  EVP_PKEY_CTX_free(c);
  mutate(r, ct, z.ct);
  NEED(nqdec(al[i].a, sk, z.sk, ct, z.ct, ss, z.ss) == NQOK);
  c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
  sl = sizeof s2;
  NEED(c != NULL && EVP_PKEY_decapsulate_init(c, NULL) == 1 &&
       EVP_PKEY_decapsulate(c, s2, &sl, ct, z.ct) == 1 && sl == z.ss &&
       memcmp(s2, ss, z.ss) == 0);
  EVP_PKEY_CTX_free(c);
  EVP_PKEY_free(k);
}

/* the classical keys, made once */
static struct {
  EVP_PKEY *k;
  nqck ck;
  const char *dn;
  nqhalg h;
  int pss;
} cl[5];

static void addkey(int i, EVP_PKEY *k, const char *dn, nqhalg h, int pss) {
  uint8_t *der = NULL;
  int dl;
  NEED(k != NULL);
  dl = i2d_PUBKEY(k, &der);
  NEED(dl > 0 && nqckey(&cl[i].ck, der, (size_t)dl) == NQOK);
  OPENSSL_free(der);
  cl[i].k = k;
  cl[i].dn = dn;
  cl[i].h = h;
  cl[i].pss = pss;
}

static void fcls(rd *r) {
  unsigned i = byte(r) % 5;
  uint8_t m[256], sig[600];
  size_t mn = byte(r), sl = sizeof sig;
  EVP_MD_CTX *c = EVP_MD_CTX_new(), *v = EVP_MD_CTX_new();
  EVP_PKEY_CTX *pc = NULL, *vc = NULL;
  int ours, theirs;
  take(r, m, mn);
  NEED(c != NULL && v != NULL &&
       EVP_DigestSignInit_ex(c, &pc, cl[i].dn, NULL, NULL, cl[i].k, NULL) ==
           1);
  if (cl[i].pss)
    NEED(EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1 &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) == 1);
  NEED(EVP_DigestSign(c, sig, &sl, m, mn) == 1);
  mutate(r, sig, sl);
  if (cl[i].ck.kind == NQKEC) {
    ours = nqecv(&cl[i].ck, cl[i].h, m, mn, sig, sl, 0) == NQOK;
  } else if (cl[i].pss) {
    nqpss pp;
    pp.h = cl[i].h;
    pp.mgf = cl[i].h;
    pp.slen = nqhlen(cl[i].h);
    ours = nqpssv(&cl[i].ck, &pp, m, mn, sig, sl) == NQOK;
  } else {
    ours = nqrsav(&cl[i].ck, cl[i].h, m, mn, sig, sl) == NQOK;
  }
  NEED(EVP_DigestVerifyInit_ex(v, &vc, cl[i].dn, NULL, NULL, cl[i].k,
                               NULL) == 1);
  if (cl[i].pss)
    NEED(EVP_PKEY_CTX_set_rsa_padding(vc, RSA_PKCS1_PSS_PADDING) == 1 &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(vc, RSA_PSS_SALTLEN_DIGEST) == 1);
  theirs = EVP_DigestVerify(v, sig, sl, m, mn) == 1;
  /* noqtis may refuse more (it wants strict DER), never accept more */
  NEED(!ours || theirs);
  EVP_MD_CTX_free(c);
  EVP_MD_CTX_free(v);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  EVP_PKEY *r2 = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
  (void)argc;
  (void)argv;
  addkey(0, r2, "SHA256", NQS256, 0);
  NEED(EVP_PKEY_up_ref(r2) == 1);
  addkey(1, r2, "SHA256", NQS256, 1);
  addkey(2, EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"), "SHA256", NQS256,
         0);
  addkey(3, EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384"), "SHA384", NQS384,
         0);
  addkey(4, EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072), "SHA384",
         NQS384, 1);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  rd r;
  if (size == 0) return 0;
  r.p = data + 1;
  r.n = size - 1;
  switch (data[0] % 4) {
    case 0: fhash(&r); break;
    case 1: fmldsa(&r); break;
    case 2: fmlkem(&r); break;
    default: fcls(&r); break;
  }
  return 0;
}
