/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* The version 2 secret-key container (docs/spec/keyfile.md) against
 * tests/vectors/skx/kat.txt, whose X was computed from the specification
 * with Python's hashlib: for each key, S from its fixed seed (the
 * Ed25519 one is RFC 8032 section 7.1 test 1), nqsxmk's X byte for byte,
 * nqsxchk on X (NQOK), on X with any one byte changed (NQEDEC), on S
 * alone (NQENOSUP) and on other lengths; nqsxsz; and a signature made
 * with X, which verifies. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#define KAT "vectors/skx/kat.txt"

static uint8_t s[8000], x[8200], w[8200], pk[8000], sk[8000], sig[20000],
    sig1[20000];
static char ln[24000];

static size_t unhex(const char *h, uint8_t *o, size_t cap) {
  size_t n = 0;
  while (h[0] != 0 && h[1] != 0 && h[0] != '\n' && n < cap) {
    unsigned v;
    if (sscanf(h, "%2x", &v) != 1) break;
    o[n++] = (uint8_t)v;
    h += 2;
  }
  return n;
}

/* the seed the key of alg was made from (as in gen.py's keys.txt) */
static size_t seedof(nqsalg a, uint8_t *seed) {
  static const char ed[] =
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  size_t j;
  for (j = 0; j < 96; j++) seed[j] = (uint8_t)j;
  if (a == NQED25519) {
    unhex(ed, seed, 32);
    return 32;
  }
  if (a == NQMDED44) {
    unhex(ed, seed + 32, 32);
    return 64;
  }
  return a == NQSLHK128F ? 48 : 32;
}

static void one(nqsalg a, const uint8_t *ws, size_t sn, const uint8_t *wx,
                size_t xn) {
  static const uint8_t m[] = "message";
  uint8_t seed[96];
  nqssz z;
  size_t n = 0, i, on = 0, rl = a == NQED25519 ? 0 : 32;
  static const uint8_t r0[32];
  NQTEQI(nqssize(a, &z), NQOK);
  NQTEQI(nqsxsz(a, &n), NQOK);
  NQTEQI(n, xn);
  NQTEQI(sn, z.sk);
  /* S from the seed is the answers' S */
  NQTEQI(nqskgd(a, seed, seedof(a, seed), pk, z.pk, sk, z.sk), NQOK);
  NQTEQM(sk, ws, sn);
  /* X from S, in another buffer and in place */
  NQTEQI(nqsxmk(a, ws, sn, x, xn), NQOK);
  NQTEQM(x, wx, xn);
  memcpy(w, ws, sn);
  NQTEQI(nqsxmk(a, w, sn, w, xn), NQOK);
  NQTEQM(w, wx, xn);
  NQTEQI(nqsxmk(a, ws, sn, x, xn - 1), NQEBUF);
  NQTEQI(nqsxmk(a, ws, sn - 1, x, xn), NQEDEC);
  NQTEQI(nqsxchk(a, wx, xn), NQOK);
  NQTEQI(nqsxchk(a, ws, sn), NQENOSUP);
  NQTEQI(nqsxchk(a, wx, xn - 1), NQEDEC);
  /* any one byte changed */
  for (i = 0; i < xn; i++) {
    memcpy(w, wx, xn);
    w[i] ^= 0x10;
    NQTEQI(nqsxchk(a, w, xn), NQEDEC);
  }
  /* X signs; S does too, and gives the same deterministic signature */
  if (a == NQSLHK128F) rl = 16;
  NQTEQI(nqsignd(a, wx, xn, m, sizeof m, NULL, 0, 0, rl ? r0 : NULL, rl, sig,
                 sizeof sig, &on),
         NQOK);
  NQTEQI(nqvrfy(a, pk, z.pk, m, sizeof m, NULL, 0, 0, sig, on), NQOK);
  memcpy(sig1, sig, on);
  NQTEQI(nqsignd(a, ws, sn, m, sizeof m, NULL, 0, 0, rl ? r0 : NULL, rl, sig,
                 sizeof sig, &on),
         NQOK);
  NQTEQM(sig, sig1, on);
}

int main(void) {
  FILE *f = fopen(KAT, "rb");
  nqsalg a = NQMLDSA44;
  size_t sn = 0, xn = 0, k = 0;
  size_t n;
  NQTCHK(f != NULL);
  if (f == NULL) return nqtdone("tskx");
  while (fgets(ln, sizeof ln, f) != NULL) {
    if (strncmp(ln, "alg ", 4) == 0) {
      ln[strcspn(ln, "\r\n")] = 0;
      NQTEQI(nqsfind(ln + 4, &a), NQOK);
    } else if (strncmp(ln, "S ", 2) == 0) {
      sn = unhex(ln + 2, s, sizeof s);
    } else if (strncmp(ln, "X ", 2) == 0) {
      xn = unhex(ln + 2, x, sizeof x);
      memcpy(w, x, xn);
      {
        static uint8_t wx[8200];
        memcpy(wx, x, xn);
        one(a, s, sn, wx, xn);
      }
      k++;
    }
  }
  fclose(f);
  NQTEQI(k, 4);
  NQTEQI(nqsxsz((nqsalg)999, &n), NQEARG);
  NQTEQI(nqsxchk((nqsalg)999, x, 32), NQEARG);
  NQTEQI(nqsxmk((nqsalg)999, s, 32, x, 64), NQEARG);
  return nqtdone("tskx");
}
