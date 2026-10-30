/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Ed25519 and the hybrid ML-DSA + Ed25519 sets through the public API:
 * sizes, names, keys from a seed (the parts equal the plain algorithms'
 * keys), hedged and deterministic signing, the context limit, the
 * pre-hash variant (SHA-512 only), each half's tamper, a half that does
 * not pass as a plain signature, signing in place, and capsules (a
 * hybrid seals and checks; Ed25519 alone is refused). */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#define NQTFS 1
#endif

static const struct {
  nqsalg a, md;
  const char *n;
  size_t pk, sk, sig;
} hy[3] = {
    {NQMDED44, NQMLDSA44, "ML-DSA-44+Ed25519", 1312 + 32, 2560 + 32,
     2420 + 64},
    {NQMDED65, NQMLDSA65, "ML-DSA-65+Ed25519", 1952 + 32, 4032 + 32,
     3309 + 64},
    {NQMDED87, NQMLDSA87, "ML-DSA-87+Ed25519", 2592 + 32, 4896 + 32,
     4627 + 64},
};

static void tnames(void) {
  nqssz z;
  nqsalg a;
  size_t i;
  NQTEQI(nqssize(NQED25519, &z), NQOK);
  NQTCHK(z.pk == 32 && z.sk == 32 && z.sig == 64);
  NQTCHK(strcmp(nqsname(NQED25519), "Ed25519") == 0);
  NQTEQI(nqsfind("Ed25519", &a), NQOK);
  NQTEQI(a, NQED25519);
  for (i = 0; i < 3; i++) {
    NQTEQI(nqssize(hy[i].a, &z), NQOK);
    NQTCHK(z.pk == hy[i].pk && z.sk == hy[i].sk && z.sig == hy[i].sig);
    NQTCHK(strcmp(nqsname(hy[i].a), hy[i].n) == 0);
    NQTEQI(nqsfind(hy[i].n, &a), NQOK);
    NQTEQI(a, hy[i].a);
  }
  NQTEQI(nqsfind("ed25519", &a), NQENOSUP);
  NQTEQI(nqsfind("ML-DSA-65+ed25519", &a), NQENOSUP);
}

static void ted(void) {
  uint8_t seed[32], pk[32], sk[32], sig[64], m[50] = "hello";
  size_t ol = 0;
  NQTEQI(nqrand(seed, 32), NQOK);
  NQTEQI(nqskgd(NQED25519, seed, 32, pk, 32, sk, 32), NQOK);
  NQTEQM(sk, seed, 32);
  {
    /* a seed of the wrong length fails, and clears its own outputs */
    uint8_t p2[32], s2[32];
    memset(p2, 1, 32);
    NQTEQI(nqskgd(NQED25519, seed, 31, p2, 32, s2, 32), NQEARG);
    NQTCHK(p2[0] == 0 && p2[31] == 0);
  }
  NQTEQI(nqsign(NQED25519, sk, 32, m, 5, NULL, 0, 0, sig, 64, &ol), NQOK);
  NQTEQI((int)ol, 64);
  NQTEQI(nqvrfy(NQED25519, pk, 32, m, 5, NULL, 0, 0, sig, 64), NQOK);
  /* deterministic: nqsignd takes no randomness */
  {
    uint8_t s2[64];
    NQTEQI(nqsignd(NQED25519, sk, 32, m, 5, NULL, 0, 0, NULL, 0, s2, 64,
                   &ol), NQOK);
    NQTEQM(s2, sig, 64);
    NQTEQI(nqsignd(NQED25519, sk, 32, m, 5, NULL, 0, 0, m, 1, s2, 64, &ol),
           NQEARG);
  }
  /* Ed25519ph is SHA-512 only */
  NQTEQI(nqsign(NQED25519, sk, 32, m, 5, NULL, 0, (int)NQS512, sig, 64,
                &ol), NQOK);
  NQTEQI(nqvrfy(NQED25519, pk, 32, m, 5, NULL, 0, (int)NQS512, sig, 64),
         NQOK);
  NQTEQI(nqvrfy(NQED25519, pk, 32, m, 5, NULL, 0, 0, sig, 64), NQEVRFY);
  NQTEQI(nqsign(NQED25519, sk, 32, m, 5, NULL, 0, (int)NQS256, sig, 64,
                &ol), NQENOSUP);
  NQTEQI(nqvrfy(NQED25519, pk, 31, m, 5, NULL, 0, 0, sig, 64), NQEDEC);
  NQTEQI(nqvrfy(NQED25519, pk, 32, m, 5, NULL, 0, 0, sig, 63), NQEDEC);
}

static void thy1(size_t i) {
  uint8_t seed[64], *pk = malloc(hy[i].pk), *sk = malloc(hy[i].sk),
                    *sig = malloc(hy[i].sig), *s2 = malloc(hy[i].sig),
                    *mp = malloc(hy[i].pk), *ms = malloc(hy[i].sk),
                    c[255], m[200], rnd[32];
  uint8_t ep[32], es[32];
  size_t mpl = hy[i].pk - 32, msl = hy[i].sk - 32, mgl = hy[i].sig - 64, ol;
  NQTCHK(pk && sk && sig && s2 && mp && ms);
  if (!(pk && sk && sig && s2 && mp && ms)) goto out;
  NQTEQI(nqrand(seed, 64), NQOK);
  NQTEQI(nqrand(m, sizeof m), NQOK);
  NQTEQI(nqrand(c, sizeof c), NQOK);
  memset(rnd, 0, sizeof rnd);
  /* the parts are the plain algorithms' keys from the two seed halves */
  NQTEQI(nqskgd(hy[i].a, seed, 64, pk, hy[i].pk, sk, hy[i].sk), NQOK);
  NQTEQI(nqskgd(hy[i].md, seed, 32, mp, mpl, ms, msl), NQOK);
  NQTEQI(nqskgd(NQED25519, seed + 32, 32, ep, 32, es, 32), NQOK);
  NQTEQM(pk, mp, mpl);
  NQTEQM(pk + mpl, ep, 32);
  NQTEQM(sk, ms, msl);
  NQTEQM(sk + msl, es, 32);
  NQTEQI(nqskgd(hy[i].a, seed, 32, pk, hy[i].pk, sk, hy[i].sk), NQEARG);
  NQTEQI(nqskgd(hy[i].a, seed, 64, pk, hy[i].pk, sk, hy[i].sk), NQOK);

  /* hedged, with a context of the largest length allowed */
  NQTEQI(nqsign(hy[i].a, sk, hy[i].sk, m, sizeof m, c, 241, 0, sig,
                hy[i].sig, &ol), NQOK);
  NQTEQI((int)ol, (int)hy[i].sig);
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, c, 241, 0, sig,
                hy[i].sig), NQOK);
  NQTEQI(nqsign(hy[i].a, sk, hy[i].sk, m, sizeof m, c, 242, 0, s2,
                hy[i].sig, &ol), NQEARG);
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, c, 242, 0, sig,
                hy[i].sig), NQEARG);
  /* each half's tamper fails the whole */
  sig[1] ^= 1;
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, c, 241, 0, sig,
                hy[i].sig), NQEVRFY);
  sig[1] ^= 1;
  sig[mgl + 1] ^= 1;
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, c, 241, 0, sig,
                hy[i].sig), NQEVRFY);
  sig[mgl + 1] ^= 1;
  /* neither half is a plain signature under the caller's context */
  NQTEQI(nqvrfy(hy[i].md, pk, mpl, m, sizeof m, c, 241, 0, sig, mgl),
         NQEVRFY);
  NQTEQI(nqvrfy(NQED25519, pk + mpl, 32, m, sizeof m, c, 241, 0, sig + mgl,
                64), NQEVRFY);
  /* deterministic (zero rnd): the same signature twice */
  NQTEQI(nqsignd(hy[i].a, sk, hy[i].sk, m, sizeof m, NULL, 0, 0, rnd, 32,
                 sig, hy[i].sig, &ol), NQOK);
  NQTEQI(nqsignd(hy[i].a, sk, hy[i].sk, m, sizeof m, NULL, 0, 0, rnd, 32,
                 s2, hy[i].sig, &ol), NQOK);
  NQTEQM(sig, s2, hy[i].sig);
  NQTEQI(nqsignd(hy[i].a, sk, hy[i].sk, m, sizeof m, NULL, 0, 0, rnd, 31,
                 s2, hy[i].sig, &ol), NQEARG);
  /* pre-hash: SHA-512 only */
  NQTEQI(nqsign(hy[i].a, sk, hy[i].sk, m, sizeof m, NULL, 0, (int)NQS512,
                sig, hy[i].sig, &ol), NQOK);
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, NULL, 0, (int)NQS512,
                sig, hy[i].sig), NQOK);
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, NULL, 0, 0, sig,
                hy[i].sig), NQEVRFY);
  NQTEQI(nqsign(hy[i].a, sk, hy[i].sk, m, sizeof m, NULL, 0, (int)NQS256,
                sig, hy[i].sig, &ol), NQENOSUP);
  /* wrong lengths */
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk - 1, m, sizeof m, NULL, 0, 0, sig,
                hy[i].sig), NQEDEC);
  NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, NULL, 0, 0, sig,
                hy[i].sig - 1), NQEDEC);
  /* in place: the signature over the message buffer it signs */
  {
    uint8_t *b = malloc(hy[i].sig);
    NQTCHK(b != NULL);
    if (b != NULL) {
      memset(b, 0, hy[i].sig);
      memcpy(b, m, sizeof m);
      NQTEQI(nqsign(hy[i].a, sk, hy[i].sk, b, sizeof m, NULL, 0, 0, b,
                    hy[i].sig, &ol), NQOK);
      NQTEQI(nqvrfy(hy[i].a, pk, hy[i].pk, m, sizeof m, NULL, 0, 0, b,
                    hy[i].sig), NQOK);
      free(b);
    }
  }
out:
  free(pk);
  free(sk);
  free(sig);
  free(s2);
  free(mp);
  free(ms);
}

#ifdef NQTFS
static void put(const char *p, const char *s) {
  FILE *f = fopen(p, "wb");
  NQTCHK(f != NULL);
  if (f == NULL) return;
  fputs(s, f);
  fclose(f);
}

static void tcap(void) {
  char d[300], p[400];
  const char *t = getenv("TMPDIR");
  uint8_t pk[2592 + 32], sk[4896 + 32], ep[32], es[32];
  uint8_t seed[32];
  nqrep *r = NULL;
  if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
  NQTEQI(nqrand(seed, sizeof seed), NQOK);
  snprintf(d, sizeof d, "%s/thyb%02x%02x%02x%02x", t, seed[0], seed[1],
           seed[2], seed[3]);
  NQTEQI(mkdir(d, 0700), 0);
  snprintf(p, sizeof p, "%s/a.txt", d);
  put(p, "hybrid\n");
  /* a hybrid seals, and checks with its key pinned */
  NQTEQI(nqskg(NQMDED65, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqseal(d, NQMDED65, sk, 4032 + 32, pk, 1952 + 32, NULL, NULL),
         NQOK);
  NQTEQI(nqchk(d, pk, 1952 + 32, &r), NQOK);
  nqrepfree(r);
  r = NULL;
  /* Ed25519 alone does not seal */
  NQTEQI(nqskg(NQED25519, ep, 32, es, 32), NQOK);
  NQTEQI(nqseal(d, NQED25519, es, 32, ep, 32, NULL, NULL), NQENOSUP);
  NQTEQI(nqchk(d, pk, 1952 + 32, &r), NQOK); /* the hybrid seal kept */
  nqrepfree(r);
  snprintf(p, sizeof p, "%s/a.txt", d);
  remove(p);
  snprintf(p, sizeof p, "%s/noqtis.json", d);
  remove(p);
  snprintf(p, sizeof p, "%s/noqtis.sig", d);
  remove(p);
  rmdir(d);
}
#endif

int main(void) {
  size_t i;
  tnames();
  ted();
  for (i = 0; i < 3; i++) thy1(i);
#ifdef NQTFS
  tcap();
#endif
  return nqtdone("thyb");
}
