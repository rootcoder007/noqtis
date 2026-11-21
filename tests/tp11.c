/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Keys on a token (nqp11open, nqp11toks, nqp11login, nqp11keys,
 * nqp11pub, nqp11sign, nqp11dec, nqp11gen), against the software token
 * of tests/p11/tok.c: a key of every kind made on the token, its public
 * key read, its signatures verified by nqvrfy with and without a
 * context, a ciphertext of nqenc decapsulated; the PIN, the order of
 * calls, a module of version 2.40, keys found again by another load. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#ifndef NQTOKPATH
int main(void) { return nqtdone("tp11"); }
#else

static void env(const char *name, const char *v) {
#ifdef _WIN32
  _putenv_s(name, v != NULL ? v : "");
#else
  if (v != NULL)
    setenv(name, v, 1);
  else
    unsetenv(name);
#endif
}

static uint8_t pk[4096], sig[50000], ct[2048], ss[32], ss2[32], msg[300];

static void tsig(nqp11 *p, nqsalg alg, const char *label) {
  nqp11k k;
  nqssz z;
  size_t n = 0, sn = 0;
  NQTEQI(nqssize(alg, &z), NQOK);
  NQTEQI(nqp11gen(p, 0, (int)alg, label, &k), NQOK);
  NQTCHK(!k.kem && k.alg == (int)alg && strcmp(k.label, label) == 0 &&
         k.idlen == 16);
  NQTEQI(nqp11pub(p, &k, NULL, 0, &n), NQOK);
  NQTCHK(n == z.pk);
  NQTEQI(nqp11pub(p, &k, pk, z.pk - 1, &n), NQEBUF);
  NQTEQI(nqp11pub(p, &k, pk, sizeof pk, &n), NQOK);
  NQTEQI(nqp11sign(p, &k, msg, sizeof msg, NULL, 0, sig, sizeof sig, &sn),
         NQOK);
  NQTCHK(sn == z.sig);
  NQTEQI(nqvrfy(alg, pk, n, msg, sizeof msg, NULL, 0, 0, sig, sn), NQOK);
  NQTEQI(nqvrfy(alg, pk, n, msg, sizeof msg - 1, NULL, 0, 0, sig, sn),
         NQEVRFY);
  /* with a context: the same as nqsign with it */
  NQTEQI(nqp11sign(p, &k, msg, 10, (const uint8_t *)"ctx", 3, sig, sizeof sig,
                   &sn),
         NQOK);
  NQTEQI(nqvrfy(alg, pk, n, msg, 10, (const uint8_t *)"ctx", 3, 0, sig, sn),
         NQOK);
  NQTEQI(nqvrfy(alg, pk, n, msg, 10, (const uint8_t *)"cty", 3, 0, sig, sn),
         NQEVRFY);
  NQTEQI(nqvrfy(alg, pk, n, msg, 10, NULL, 0, 0, sig, sn), NQEVRFY);
  /* an empty message; a buffer too small says the size */
  NQTEQI(nqp11sign(p, &k, NULL, 0, NULL, 0, sig, sizeof sig, &sn), NQOK);
  NQTEQI(nqvrfy(alg, pk, n, NULL, 0, NULL, 0, 0, sig, sn), NQOK);
  NQTEQI(nqp11sign(p, &k, msg, 1, NULL, 0, sig, z.sig - 1, &sn), NQEBUF);
  NQTCHK(sn == z.sig);
  /* a signature key does not decapsulate */
  NQTEQI(nqp11dec(p, &k, ct, 768, ss, 32), NQEARG);
}

static void tkem(nqp11 *p, nqkalg alg, const char *label) {
  nqp11k k;
  nqksz z;
  size_t n = 0, sn = 0;
  NQTEQI(nqksize(alg, &z), NQOK);
  NQTEQI(nqp11gen(p, 1, (int)alg, label, &k), NQOK);
  NQTCHK(k.kem && k.alg == (int)alg);
  NQTEQI(nqp11pub(p, &k, pk, sizeof pk, &n), NQOK);
  NQTCHK(n == z.pk);
  NQTEQI(nqenc(alg, pk, n, ct, z.ct, ss, 32), NQOK);
  memset(ss2, 0, sizeof ss2);
  NQTEQI(nqp11dec(p, &k, ct, z.ct, ss2, 32), NQOK);
  NQTEQM(ss, ss2, 32);
  /* a changed ciphertext gives another secret (implicit rejection) */
  ct[5] ^= 1;
  NQTEQI(nqp11dec(p, &k, ct, z.ct, ss2, 32), NQOK);
  NQTCHK(memcmp(ss, ss2, 32) != 0);
  NQTEQI(nqp11dec(p, &k, ct, z.ct - 1, ss2, 32), NQEARG);
  NQTEQI(nqp11dec(p, &k, ct, z.ct, ss2, 31), NQEARG);
  /* a KEM key does not sign */
  NQTEQI(nqp11sign(p, &k, msg, 1, NULL, 0, sig, sizeof sig, &sn), NQEARG);
}

int main(void) {
  nqp11 *p = NULL;
  nqp11t t[4];
  nqp11k k[32], g;
  size_t n = 0, i, nk;
  for (i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 7 + 3);
  remove("q.tok");
  env("NQTOKFILE", "q.tok");
  env("NQTOK240", NULL);
  /* what is not a module */
  NQTEQI(nqp11open(NULL, &p), NQEARG);
  NQTEQI(nqp11open(NQTOKPATH, NULL), NQEARG);
  NQTEQI(nqp11open("nqtok", &p), NQEARG); /* a bare name is not searched */
  NQTCHK(p == NULL);
  NQTEQI(nqp11open("./no/such/module.so", &p), NQEIO);
  NQTCHK(nqp11why(NULL) == 0);
  nqp11close(NULL);
  /* the token, and the order of calls */
  NQTEQI(nqp11open(NQTOKPATH, &p), NQOK);
  NQTEQI(nqp11toks(p, t, 4, &n), NQOK);
  NQTCHK(n == 1 && t[0].slot == 0 && t[0].login == 1 &&
         strcmp(t[0].label, "noqtis test token") == 0 &&
         strcmp(t[0].maker, "noqtis") == 0 &&
         strcmp(t[0].model, "software") == 0 &&
         strcmp(t[0].serial, "0001") == 0);
  NQTEQI(nqp11toks(p, NULL, 0, &n), NQEBUF);
  NQTCHK(n == 1);
  NQTEQI(nqp11keys(p, k, 32, &n), NQESTATE);
  NQTEQI(nqp11gen(p, 0, (int)NQMLDSA44, "x", &g), NQESTATE);
  NQTEQI(nqp11login(p, 9, "1234", 4), NQEIO);
  NQTCHK(nqp11why(p) == 3); /* CKR_SLOT_ID_INVALID */
  NQTEQI(nqp11login(p, 0, "4321", 4), NQEVRFY);
  NQTEQI(nqp11login(p, 0, "12345", 5), NQEVRFY);
  /* without the PIN: a session, and no private key to see */
  NQTEQI(nqp11login(p, 0, NULL, 0), NQOK);
  NQTEQI(nqp11keys(p, k, 32, &n), NQOK);
  NQTCHK(n == 0);
  NQTEQI(nqp11gen(p, 0, (int)NQMLDSA44, "x", &g), NQEIO);
  NQTEQI(nqp11login(p, 0, "1234", 4), NQESTATE);
  nqp11close(p);
  NQTEQI(nqp11open(NQTOKPATH, &p), NQOK);
  NQTEQI(nqp11login(p, 0, "1234", 4), NQOK);
  NQTEQI(nqp11keys(p, k, 32, &n), NQOK);
  NQTCHK(n == 0);
  tsig(p, NQMLDSA44, "sig-44");
  tsig(p, NQMLDSA65, "sig-65");
  tsig(p, NQMLDSA87, "sig-87");
  tsig(p, NQSLH128F, "slh-sha2-128f");
  tsig(p, NQSLHK128F, "slh-shake-128f");
  tsig(p, NQSLH192F, "slh-sha2-192f");
  tsig(p, NQED25519, "ed");
  tkem(p, NQMLKEM512, "kem-512");
  tkem(p, NQMLKEM768, "kem-768");
  tkem(p, NQMLKEM1024, "kem-1024");
  /* what a token has no key type for */
  NQTEQI(nqp11gen(p, 0, (int)NQMDED65, "hy", &g), NQENOSUP);
  NQTEQI(nqp11gen(p, 1, (int)NQHQC128, "hqc", &g), NQENOSUP);
  NQTEQI(nqp11gen(p, 0, (int)NQMLDSA44, "", &g), NQEARG);
  NQTEQI(nqp11gen(p, 0, (int)NQMLDSA44, NULL, &g), NQEARG);
  NQTEQI(nqp11keys(p, k, 32, &nk), NQOK);
  NQTCHK(nk == 10);
  NQTEQI(nqp11keys(p, k, 3, &n), NQEBUF);
  NQTCHK(n == 10);
  nqp11close(p);
  /* loaded again: the keys are found, and sign as before */
  NQTEQI(nqp11open(NQTOKPATH, &p), NQOK);
  NQTEQI(nqp11login(p, 0, "1234", 4), NQOK);
  NQTEQI(nqp11keys(p, k, 32, &n), NQOK);
  NQTCHK(n == 10);
  for (i = 0; i < n; i++) {
    size_t pn = 0, sn = 0;
    if (k[i].kem) continue;
    NQTEQI(nqp11pub(p, &k[i], pk, sizeof pk, &pn), NQOK);
    NQTEQI(nqp11sign(p, &k[i], msg, 20, NULL, 0, sig, sizeof sig, &sn), NQOK);
    NQTEQI(nqvrfy((nqsalg)k[i].alg, pk, pn, msg, 20, NULL, 0, 0, sig, sn),
           NQOK);
  }
  nqp11close(p);
  /* a module of version 2.40: it signs, and cannot decapsulate */
  env("NQTOK240", "1");
  NQTEQI(nqp11open(NQTOKPATH, &p), NQOK);
  NQTEQI(nqp11login(p, 0, "1234", 4), NQOK);
  NQTEQI(nqp11keys(p, k, 32, &n), NQOK);
  for (i = 0; i < n; i++) {
    nqksz z;
    if (!k[i].kem) continue;
    NQTEQI(nqksize((nqkalg)k[i].alg, &z), NQOK);
    NQTEQI(nqp11dec(p, &k[i], ct, z.ct, ss2, 32), NQENOSUP);
  }
  nqp11close(p);
  env("NQTOK240", NULL);
  env("NQTOKFILE", NULL);
  remove("q.tok");
  return nqtdone("tp11");
}
#endif
