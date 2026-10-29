/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over what the public API reads from a peer: public
 * keys and signatures of any length on nqvrfy (ML-DSA, SLH-DSA, pure and
 * pre-hash, with a context), encapsulation keys on nqencd, and
 * decapsulation keys and ciphertexts of any length on nqdec (ML-KEM,
 * HQC). Checks: nothing of the wrong length verifies; a signature that
 * verifies does not verify a longer message; masked and plain ML-KEM
 * decapsulation agree; decapsulation of well-sized input fails only for
 * a decapsulation key that fails its check (implicit rejection).
 * Verifying a well-sized signature of the larger SLH-DSA sets (192 and
 * 256) takes seconds under the sanitizers, so for those only inputs of
 * a wrong length reach nqvrfy; the 128 sets run the same code in full.
 *
 * Input: a selector byte (the algorithm), a mode byte (the pre-hash),
 * then length-prefixed pieces (fz.h): key, signature or ciphertext,
 * message, context, and for a KEM an encapsulation key. */
#include "fz.h"
#include "mldsa/mldsa.h"
#include "mlkem/mlkem.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

static void sig(nqsalg alg, unsigned mode, const uint8_t *pk, size_t pn,
                const uint8_t *s, size_t sn, const uint8_t *m, size_t mn,
                const uint8_t *c, size_t cn) {
  nqssz z;
  int ph = (int)(mode & 15), rc;
  uint8_t *m2;
  if (nqssize(alg, &z) != NQOK) abort();
  if (alg >= NQSLH192S && alg != NQSLHK128S && alg != NQSLHK128F &&
      pn == z.pk && sn == z.sig) {
    return;
  }
  rc = nqvrfy(alg, pk, pn, m, mn, c, cn, ph, s, sn);
  if (rc == NQOK && (pn != z.pk || sn != z.sig || cn > 255 || ph > 12)) {
    abort();
  }
  if (rc == NQOK) {
    /* the same signature over one more byte */
    m2 = (uint8_t *)malloc(mn + 1);
    if (m2 == NULL) return;
    if (mn != 0) memcpy(m2, m, mn);
    m2[mn] = 0;
    if (nqvrfy(alg, pk, pn, m2, mn + 1, c, cn, ph, s, sn) == NQOK) abort();
    free(m2);
  }
  if (alg <= NQMLDSA87 && mn >= NQMDMU) {
    /* the external-mu and internal interfaces */
    (void)nqmdvmu((int)alg, pk, pn, m, s, sn);
    (void)nqmdvfyi((int)alg, pk, pn, m, mn, s, sn);
  }
}

static void kem(nqkalg alg, const uint8_t *sk, size_t skn,
                const uint8_t *ct, size_t ctn, const uint8_t *pk,
                size_t pkn) {
  static uint8_t c2[16384];
  uint8_t s1[64], s2[64], seed[64];
  nqksz z;
  int k = nqmkk(alg), rc;
  if (nqksize(alg, &z) != NQOK) abort();
  rc = nqdec(alg, sk, skn, ct, ctn, s1, sizeof s1);
  if (rc == NQOK && (skn != z.sk || ctn != z.ct)) abort();
  if (rc != NQOK && rc != NQEDEC) abort();
  if (k != 0) {
    int r2 = nqmkdecp(k, sk, skn, ct, ctn, s2, sizeof s2);
    if (r2 != rc || (rc == NQOK && memcmp(s1, s2, NQMKSS) != 0)) abort();
    /* well sized: only the decapsulation key check may refuse it */
    if (skn == z.sk && ctn == z.ct &&
        (rc == NQOK) != (nqmkdkc(k, sk, skn) == NQOK)) {
      abort();
    }
  }
  memset(seed, 3, sizeof seed);
  rc = nqencd(alg, pk, pkn, seed, fzeseed((int)alg), c2, sizeof c2, s1,
              sizeof s1);
  if (rc == NQOK && pkn != z.pk) abort();
  if (k != 0 && (rc == NQOK) != (nqmkekc(k, pk, pkn) == NQOK)) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fzin in;
  unsigned sel, mode;
  const uint8_t *p[5];
  uint8_t *b[5];
  size_t n[5], i;
  in.p = data;
  in.n = size;
  sel = fzbyte(&in) % 21;
  mode = fzbyte(&in);
  for (i = 0; i < 5; i++) {
    p[i] = fzpart(&in, &n[i]);
    b[i] = fzdup(p[i], n[i]);
  }
  for (i = 0; i < 5; i++) {
    if (b[i] == NULL) goto out;
  }
  if (sel < 15) {
    sig((nqsalg)(sel + 1), mode, b[0], n[0], b[1], n[1], b[2], n[2], b[3],
        n[3]);
  } else {
    kem((nqkalg)(sel - 14), b[0], n[0], b[1], n[1], b[4], n[4]);
  }
out:
  for (i = 0; i < 5; i++) free(b[i]);
  return 0;
}
