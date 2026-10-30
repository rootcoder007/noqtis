/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* DSSE envelopes (nqdsse, nqdssevrfy): the PAE of the DSSE specification's
 * example, byte for byte (an Ed25519 signature is deterministic, so the
 * envelope's must equal one made over the spec's PAE string); round trips
 * for ML-DSA, SLH-DSA and a hybrid; every field changed is refused. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

static const char T[] = "http://example.com/HelloWorld";
static const char P[] = "hello world";

/* the base64 text of member f ("sig" or "payload") in env, decoded */
static size_t field(const char *env, const char *f, uint8_t *out,
                    size_t cap) {
  static const char tb[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char key[32];
  const char *s, *e;
  size_t n = 0;
  unsigned acc = 0;
  int bits = 0;
  snprintf(key, sizeof key, "\"%s\":\"", f);
  s = strstr(env, key);
  if (s == NULL) return 0;
  s += strlen(key);
  e = strchr(s, '"');
  for (; s < e && *s != '='; s++) {
    const char *q = strchr(tb, *s);
    if (q == NULL) return 0;
    acc = (acc << 6) | (unsigned)(q - tb);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n < cap) out[n++] = (uint8_t)(acc >> bits);
      acc &= (1u << bits) - 1;
    }
  }
  return n;
}

static void tpae(void) {
  static const char pae[] = "DSSEv1 29 http://example.com/HelloWorld 11 "
                            "hello world";
  uint8_t pk[32], sk[32], want[64], got[64], pl[64];
  char env[512], ty[256];
  size_t n = 0, sn = 0, pn = 0;
  NQTEQI(nqskg(NQED25519, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqdsse(NQED25519, sk, sizeof sk, pk, sizeof pk, T,
                (const uint8_t *)P, strlen(P), env, sizeof env - 1, &n),
         NQOK);
  env[n] = 0;
  NQTEQI(nqsign(NQED25519, sk, sizeof sk, (const uint8_t *)pae,
                strlen(pae), NULL, 0, 0, want, sizeof want, &sn),
         NQOK);
  NQTEQI((long)field(env, "sig", got, sizeof got), 64);
  NQTCHK(memcmp(got, want, 64) == 0);
  NQTCHK(strstr(env, "\"payloadType\":\"http://example.com/HelloWorld\"") !=
         NULL);
  NQTCHK(strncmp(env, "{\"payload\":\"aGVsbG8gd29ybGQ=\"", 28) == 0);
  NQTEQI(nqdssevrfy(NQED25519, pk, sizeof pk, env, n, pl, sizeof pl, &pn,
                    ty),
         NQOK);
  NQTEQI((long)pn, (long)strlen(P));
  NQTCHK(memcmp(pl, P, pn) == 0 && strcmp(ty, T) == 0);
}

static void tround(nqsalg alg) {
  nqssz sz;
  uint8_t *pk, *sk, *pk2, *sk2, pl[64];
  char *env, ty[256];
  size_t n = 0, cap, pn = 0;
  NQTEQI(nqssize(alg, &sz), NQOK);
  cap = sz.sig * 2 + 512;
  pk = malloc(sz.pk);
  sk = malloc(sz.sk);
  pk2 = malloc(sz.pk);
  sk2 = malloc(sz.sk);
  env = malloc(cap);
  if (pk == NULL || sk == NULL || pk2 == NULL || sk2 == NULL || env == NULL)
    return;
  NQTEQI(nqskg(alg, pk, sz.pk, sk, sz.sk), NQOK);
  NQTEQI(nqskg(alg, pk2, sz.pk, sk2, sz.sk), NQOK);
  NQTEQI(nqdsse(alg, sk, sz.sk, pk, sz.pk, "application/vnd.in-toto+json",
                (const uint8_t *)P, strlen(P), NULL, 0, &n),
         NQEBUF);
  NQTEQI(nqdsse(alg, sk, sz.sk, pk, sz.pk, "application/vnd.in-toto+json",
                (const uint8_t *)P, strlen(P), env, cap, &n),
         NQOK);
  NQTEQI(nqdssevrfy(alg, pk, sz.pk, env, n, pl, sizeof pl, &pn, ty),
         NQOK);
  NQTCHK(pn == strlen(P) && memcmp(pl, P, pn) == 0);
  /* another key, a changed payload, type or signature: refused */
  NQTEQI(nqdssevrfy(alg, pk2, sz.pk, env, n, pl, sizeof pl, &pn, ty),
         NQEVRFY);
  {
    char *e2 = malloc(n + 1), *at;
    if (e2 != NULL) {
      memcpy(e2, env, n);
      e2[n] = 0;
      at = strstr(e2, "aGVsbG8");
      at[1] = 'H';
      NQTEQI(nqdssevrfy(alg, pk, sz.pk, e2, n, pl, sizeof pl, &pn, ty),
             NQEVRFY);
      memcpy(e2, env, n);
      at = strstr(e2, "in-toto");
      at[0] = 'X';
      NQTEQI(nqdssevrfy(alg, pk, sz.pk, e2, n, pl, sizeof pl, &pn, ty),
             NQEVRFY);
      memcpy(e2, env, n);
      at = strstr(e2, "\"sig\":\"") + 9;
      *at = *at == 'A' ? 'B' : 'A';
      NQTEQI(nqdssevrfy(alg, pk, sz.pk, e2, n, pl, sizeof pl, &pn, ty),
             NQEVRFY);
      free(e2);
    }
  }
  NQTEQI(nqdssevrfy(alg, pk, sz.pk, "{}", 2, pl, sizeof pl, &pn, ty),
         NQEDEC);
  NQTEQI(nqdssevrfy(alg, pk, sz.pk, "not json", 8, pl, sizeof pl, &pn, ty),
         NQEDEC);
  NQTEQI(nqdssevrfy(alg, pk, sz.pk, env, n, pl, 2, &pn, ty), NQEBUF);
  free(pk);
  free(sk);
  free(pk2);
  free(sk2);
  free(env);
}

static void trefuse(void) {
  uint8_t pk[1312], sk[2560], pk2[1312], sk2[2560];
  size_t n = 0;
  NQTEQI(nqskg(NQMLDSA44, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqskg(NQMLDSA44, pk2, sizeof pk2, sk2, sizeof sk2), NQOK);
  NQTEQI(nqdsse(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "a b",
                (const uint8_t *)P, 1, NULL, 0, &n),
         NQEARG);
  NQTEQI(nqdsse(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "",
                (const uint8_t *)P, 1, NULL, 0, &n),
         NQEARG);
  NQTEQI(nqdsse(NQMLDSA44, sk, sizeof sk, pk2, sizeof pk2, "t",
                (const uint8_t *)P, 1, NULL, 0, &n),
         NQEARG); /* not a pair */
  NQTEQI(nqdsse(NQMLDSA44, sk, 10, pk, sizeof pk, "t", (const uint8_t *)P,
                1, NULL, 0, &n),
         NQEARG);
}

int main(void) {
  tpae();
  tround(NQMLDSA65);
  tround(NQMDED44);
  if (getenv("NQFAST") == NULL) tround(NQSLH128F);
  trefuse();
  return nqtdone("tdsse");
}
