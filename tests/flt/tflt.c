/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The checks a signer makes before it releases a signature, under
 * injected faults. Built with the library's sources and NQTEST, so the
 * fault hooks of src/core/int.h are live (they are compiled out of the
 * library itself).
 *
 * For every signing algorithm but the slow SLH-DSA "s" sets:
 *   - a bit of the signature flipped before the checks, the first
 *     verdict skipped, the second skipped, and the key check skipped:
 *     each ends in NQEFLT with the whole output zero;
 *   - one field of the stored secret key changed at a time: ML-DSA's
 *     rho, tr, s1, s2 (a coefficient changed to another in range, which
 *     the decoder cannot refuse) and t0, and SLH-DSA's SK.seed, PK.seed
 *     and PK.root end in NQEFLT with the output zero.
 * Three fields hold only the signer's own randomness or the key's seed,
 * and a change there gives a signature that is valid, so these are
 * checked to be what the documentation says: ML-DSA's K and SLH-DSA's
 * SK.prf give a valid signature under the true public key (as hedged
 * signing does), and Ed25519's seed (alone or in a hybrid) a signature
 * under another key, which the true public key refuses. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "ed/ed.h"
#include "nqt.h"

static uint8_t pk[8000], sk[8000], sk2[8000], sig[50000];
static const uint8_t msg[] = "a message to sign";
static const uint8_t z32[32];

static int zero(const uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (p[i] != 0) return 0;
  }
  return 1;
}

/* signs (deterministically: the same output each time) with key k */
static int dsign(nqsalg a, const nqssz *z, const uint8_t *k) {
  size_t n = 0, rl = 32;
  if (a == NQED25519) rl = 0;
  if (a >= NQSLH128S && a <= NQSLHK256F) {
    nqssz t;
    nqssize(a, &t);
    rl = t.pk / 2;
  }
  memset(sig, 0x5a, z->sig);
  return nqsignd(a, k, z->sk, msg, sizeof msg, NULL, 0, 0,
                 rl ? z32 : NULL, rl, sig, z->sig, &n);
}

/* the hooks: each ends in NQEFLT with sig zero */
static void hooks(nqsalg a, const nqssz *z, int keychk) {
  static const unsigned b[4] = {NQFSIG, NQFV1, NQFV2, NQFV3};
  size_t i, n = 0;
  for (i = 0; i < 4; i++) {
    if (b[i] == NQFV3 && !keychk) continue;
    nqtflt = b[i];
    memset(sig, 0x5a, z->sig);
    NQTEQI(nqsign(a, sk, z->sk, msg, sizeof msg, NULL, 0, 0, sig, z->sig,
                  &n),
           NQEFLT);
    NQTCHK(zero(sig, z->sig));
    NQTEQI(n, 0);
    nqtflt = 0;
  }
}

/* a copy of sk with the byte at o changed by f; signs with it */
static int fsign(nqsalg a, const nqssz *z, size_t o, uint8_t x) {
  memcpy(sk2, sk, z->sk);
  sk2[o] = x;
  return dsign(a, z, sk2);
}

/* the stored key changed: refused, the output zero */
static void refused(nqsalg a, const nqssz *z, size_t o, uint8_t x,
                    const char *what) {
  int rc = fsign(a, z, o, x);
  if (rc != NQEFLT) fprintf(stderr, "%s, %s: %d\n", nqsname(a), what, rc);
  NQTEQI(rc, NQEFLT);
  NQTCHK(zero(sig, z->sig));
}

/* the stored randomness changed: a valid signature under the true key */
static void valid(nqsalg a, const nqssz *z, size_t o, uint8_t x) {
  NQTEQI(fsign(a, z, o, x), NQOK);
  NQTEQI(nqvrfy(a, pk, z->pk, msg, sizeof msg, NULL, 0, 0, sig, z->sig),
         NQOK);
}

/* the Ed25519 seed at o changed: a signature under another key */
static void other(nqsalg a, const nqssz *z, size_t o) {
  NQTEQI(fsign(a, z, o, (uint8_t)(sk[o] ^ 1)), NQOK);
  NQTEQI(nqvrfy(a, pk, z->pk, msg, sizeof msg, NULL, 0, 0, sig, z->sig),
         NQEVRFY);
}

/* ML-DSA's fields, at o in a key of the set with l, k and eta */
static void mdkey(nqsalg a, const nqssz *z, size_t o, unsigned l,
                  unsigned k, unsigned eta) {
  size_t pb = eta == 2 ? 96 : 128, s1 = o + 128, s2 = s1 + l * pb,
         t0 = s2 + k * pb;
  uint8_t m = eta == 2 ? 7 : 15, c;
  refused(a, z, o, (uint8_t)(sk[o] ^ 1), "rho");
  valid(a, z, o + 32, (uint8_t)(sk[o + 32] ^ 1));
  refused(a, z, o + 64, (uint8_t)(sk[o + 64] ^ 1), "tr");
  /* a coefficient of s1, then of s2, changed to another in range */
  c = (uint8_t)(sk[s1] & m);
  refused(a, z, s1, (uint8_t)((sk[s1] & ~m) | (c == 0 ? 1 : c - 1)), "s1");
  c = (uint8_t)(sk[s2] & m);
  refused(a, z, s2, (uint8_t)((sk[s2] & ~m) | (c == 0 ? 1 : c - 1)), "s2");
  refused(a, z, t0 + 7, (uint8_t)(sk[t0 + 7] ^ 1), "t0");
}

static void one(nqsalg a) {
  nqssz z;
  size_t n = 0;
  NQTEQI(nqssize(a, &z), NQOK);
  NQTEQI(nqskg(a, pk, z.pk, sk, z.sk), NQOK);
  NQTEQI(nqsign(a, sk, z.sk, msg, sizeof msg, NULL, 0, 0, sig, z.sig, &n),
         NQOK);
  NQTEQI(nqvrfy(a, pk, z.pk, msg, sizeof msg, NULL, 0, 0, sig, n), NQOK);
  NQTEQI(dsign(a, &z, sk), NQOK);
  hooks(a, &z, !(a >= NQSLH128S && a <= NQSLHK256F));
  switch (a) {
  case NQMLDSA44: mdkey(a, &z, 0, 4, 4, 2); break;
  case NQMLDSA65: mdkey(a, &z, 0, 5, 6, 4); break;
  case NQMLDSA87: mdkey(a, &z, 0, 7, 8, 2); break;
  case NQED25519: other(a, &z, 0); break;
  case NQMDED44:
    mdkey(a, &z, 0, 4, 4, 2);
    other(a, &z, z.sk - NQEDSK);
    break;
  case NQMDED65:
    mdkey(a, &z, 0, 5, 6, 4);
    other(a, &z, z.sk - NQEDSK);
    break;
  case NQMDED87:
    mdkey(a, &z, 0, 7, 8, 2);
    other(a, &z, z.sk - NQEDSK);
    break;
  default: {
    /* SLH-DSA: SK.seed, SK.prf, PK.seed, PK.root, n bytes each */
    size_t nn = z.sk / 4;
    refused(a, &z, 0, (uint8_t)(sk[0] ^ 1), "SK.seed");
    valid(a, &z, nn, (uint8_t)(sk[nn] ^ 1));
    refused(a, &z, 2 * nn, (uint8_t)(sk[2 * nn] ^ 1), "PK.seed");
    refused(a, &z, 3 * nn, (uint8_t)(sk[3 * nn] ^ 1), "PK.root");
    break;
  }
  }
}

int main(void) {
  static const nqsalg as[] = {NQMLDSA44, NQMLDSA65, NQMLDSA87, NQED25519,
                              NQMDED44,  NQMDED65,  NQMDED87,  NQSLH128F,
                              NQSLHK128F};
  size_t i;
  for (i = 0; i < sizeof as / sizeof *as; i++) one(as[i]);
  return nqtdone("tflt");
}
