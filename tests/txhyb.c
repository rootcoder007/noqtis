/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X25519MLKEM768 tests: the layout of the shares and the secret (the
 * ML-KEM part must equal ML-KEM-768 itself, the X25519 part X25519
 * itself), round trips, a tampered ciphertext (implicit rejection: a
 * different secret, still NQOK), an X25519 part of small order
 * (NQEVRFY) and wrong lengths. The draft has no test vectors; the
 * local-server test (tests/tls) checks it against OpenSSL 3.5. */
#include "mlkem/mlkem.h"
#include "xdh/xdh.h"
#include "nqt.h"
#include "tvec.h"

int main(void) {
  static uint8_t ek[NQHYBEK], sk[NQHYBSK], ct[NQHYBCT], ek1[NQMKEKX],
      dk1[NQMKDKX], ct1[NQMKCTX];
  uint8_t seed[64], x[32], y[32], m[32], s1[NQHYBSS], s2[NQHYBSS],
      ss[32], px[32];
  int i, r;
  for (r = 0; r < 4; r++) {
    for (i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 5 + r);
    for (i = 0; i < 32; i++) {
      x[i] = (uint8_t)(i * 3 + 1 + r);
      y[i] = (uint8_t)(i * 7 + 2 + r);
      m[i] = (uint8_t)(i * 11 + r);
    }
    NQTEQI(nqhybkgd(seed, x, ek, sk), NQOK);
    /* the parts are ML-KEM-768 and X25519, in that order */
    NQTEQI(nqmkkgd(3, seed, 64, ek1, NQMKEK(3), dk1, NQMKDK(3)), NQOK);
    NQTEQM(ek, ek1, NQMKEK(3));
    NQTEQM(sk, dk1, NQMKDK(3));
    NQTEQI(nqx25519b(px, x), NQOK);
    NQTEQM(ek + NQMKEK(3), px, 32);
    NQTEQI(nqhybencd(ek, sizeof ek, m, y, ct, s1), NQOK);
    NQTEQI(nqmkencd(3, ek1, NQMKEK(3), m, 32, ct1, NQMKCT(3), ss, 32), NQOK);
    NQTEQM(ct, ct1, NQMKCT(3));
    NQTEQM(s1, ss, 32);
    NQTEQI(nqx25519(ss, y, px), NQOK);
    NQTEQM(s1 + 32, ss, 32);
    NQTEQI(nqhybdec(sk, ct, sizeof ct, s2), NQOK);
    NQTEQM(s1, s2, NQHYBSS);
    /* implicit rejection on the ML-KEM part */
    ct[100] ^= 1;
    NQTEQI(nqhybdec(sk, ct, sizeof ct, s2), NQOK);
    NQTCHK(memcmp(s1, s2, 32) != 0);
    NQTEQM(s1 + 32, s2 + 32, 32);
    ct[100] ^= 1;
    /* an X25519 point of small order */
    memset(ct + NQMKCT(3), 0, 32);
    NQTEQI(nqhybdec(sk, ct, sizeof ct, s2), NQEVRFY);
    memset(ss, 0, sizeof ss);
    NQTEQM(s2, ss, 32);
  }
  NQTEQI(nqhybdec(sk, ct, sizeof ct - 1, s2), NQEDEC);
  NQTEQI(nqhybencd(ek, sizeof ek - 1, m, y, ct, s1), NQEDEC);
  NQTEQI(nqhybkg(x, ek, sk), NQOK);
  NQTEQI(nqhybencd(ek, sizeof ek, m, y, ct, s1), NQOK);
  NQTEQI(nqhybdec(sk, ct, sizeof ct, s2), NQOK);
  NQTEQM(s1, s2, NQHYBSS);
  NQTEQI(nqhybdec(NULL, ct, sizeof ct, s2), NQEARG);
  return nqtdone("txhyb");
}
