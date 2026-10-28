/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The public signature and KEM dispatchers (src/api): sizes, names and
 * lookup; key generation, signing and verification for every nqsalg;
 * deterministic and hedged signing; every error the header promises;
 * KEM round trips and implicit rejection for every nqkalg; and that each
 * dispatcher gives the same bytes as the module it calls.
 *
 * The small SLH-DSA sets ("s") take seconds per signature: by default
 * SLH-DSA-SHA2-128s signs twice and the other five only make keys
 * (their signing is the same dispatch code, and tests/tslh.c checks it
 * against the ACVP vectors); the fast 192- and 256-bit sets sign twice;
 * NQSLOW=1 runs every check on every set; NQFAST=1, or NQSLSUB set as
 * in the valgrind job, signs with no small set. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "hash/h.h"
#include "hqc/hqc.h"
#include "mldsa/mldsa.h"
#include "mlkem/mlkem.h"
#include "slh/slh.h"
#include "nqt.h"

#define SIGX 49856  /* SLH-DSA-*-256f, the longest signature */
#define PKX 2592
#define SKX 4896
#define KPKX 7237   /* HQC-256 */
#define KSKX 7333
#define KCTX 14421

static int fast = 0;  /* NQFAST=1 */
static int slow = 0;  /* NQSLOW=1 */
static long levels[3];

static uint8_t pk[PKX + 8], sk[SKX + 8], pk2[PKX], sk2[SKX], pk3[PKX],
    sk3[SKX];
static uint8_t sig[SIGX + 8], sig2[SIGX + 8], sig3[SIGX + 8];

static const nqsalg salgs[] = {
    NQMLDSA44,  NQMLDSA65,  NQMLDSA87,  NQSLH128S,  NQSLH128F,
    NQSLH192S,  NQSLH192F,  NQSLH256S,  NQSLH256F,  NQSLHK128S,
    NQSLHK128F, NQSLHK192S, NQSLHK192F, NQSLHK256S, NQSLHK256F};
#define NSALG (sizeof salgs / sizeof salgs[0])

static const char *const snames[NSALG] = {
    "ML-DSA-44",          "ML-DSA-65",          "ML-DSA-87",
    "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"};

/* FIPS 204 table 2 and FIPS 205 table 2: pk, sk, sig */
static const size_t ssz[NSALG][3] = {
    {1312, 2560, 2420},  {1952, 4032, 3309},  {2592, 4896, 4627},
    {32, 64, 7856},      {32, 64, 17088},     {48, 96, 16224},
    {48, 96, 35664},     {64, 128, 29792},    {64, 128, 49856},
    {32, 64, 7856},      {32, 64, 17088},     {48, 96, 16224},
    {48, 96, 35664},     {64, 128, 29792},    {64, 128, 49856}};

static int ismd(nqsalg a) {
  return a == NQMLDSA44 || a == NQMLDSA65 || a == NQMLDSA87;
}

/* the seed length nqskgd takes, and the rnd length nqsignd takes */
static size_t kseed(nqsalg a) {
  return ismd(a) ? 32 : 3 * nqslpar(a)->n;
}
static size_t rlen(nqsalg a) { return ismd(a) ? 32 : nqslpar(a)->n; }

static void fill(uint8_t *p, size_t n, unsigned s) {
  size_t i;
  for (i = 0; i < n; i++) {
    p[i] = (uint8_t)((i * 131u + s * 7u + 1u) & 0xffu);
  }
}

/* ---- sizes, names, lookup ---- */

static void snames1(void) {
  nqssz sz;
  nqsalg a;
  size_t i;
  for (i = 0; i < NSALG; i++) {
    memset(&sz, 0, sizeof sz);
    NQTEQI(nqssize(salgs[i], &sz), NQOK);
    NQTEQI(sz.pk, ssz[i][0]);
    NQTEQI(sz.sk, ssz[i][1]);
    NQTEQI(sz.sig, ssz[i][2]);
    NQTCHK(nqsname(salgs[i]) != NULL &&
           strcmp(nqsname(salgs[i]), snames[i]) == 0);
    a = (nqsalg)0;
    NQTEQI(nqsfind(snames[i], &a), NQOK);
    NQTEQI(a, salgs[i]);
  }
  NQTEQI(nqssize((nqsalg)0, &sz), NQEARG);
  NQTEQI(nqssize((nqsalg)16, &sz), NQEARG);
  NQTEQI(nqssize((nqsalg)-1, &sz), NQEARG);
  NQTEQI(nqssize(NQMLDSA44, NULL), NQEARG);
  NQTCHK(nqsname((nqsalg)0) == NULL);
  NQTCHK(nqsname((nqsalg)16) == NULL);
  NQTEQI(nqsfind("ML-DSA-66", &a), NQENOSUP);
  NQTEQI(nqsfind("ml-dsa-44", &a), NQENOSUP);
  NQTEQI(nqsfind("", &a), NQENOSUP);
  NQTEQI(nqsfind("SLH-DSA-SHA2-128", &a), NQENOSUP);
  NQTEQI(nqsfind(NULL, &a), NQEARG);
  NQTEQI(nqsfind("ML-DSA-44", NULL), NQEARG);
}


/* ---- signatures ---- */

/* The argument errors of one algorithm (cheap: nothing is signed). */
static void serr(nqsalg a, size_t i) {
  const size_t p = ssz[i][0], s = ssz[i][1], g = ssz[i][2];
  uint8_t seed[96], rnd[64], ctx[256];
  const uint8_t m[3] = {1, 2, 3};
  size_t out = 7;
  fill(seed, sizeof seed, 1);
  memset(rnd, 0, sizeof rnd);
  memset(ctx, 0, sizeof ctx);
  /* keygen */
  NQTEQI(nqskg(a, NULL, p, sk, s), NQEARG);
  NQTEQI(nqskg(a, pk, p, NULL, s), NQEARG);
  NQTEQI(nqskg(a, pk, p - 1, sk, s), NQEBUF);
  NQTEQI(nqskg(a, pk, p, sk, s - 1), NQEBUF);
  NQTEQI(nqskgd(a, NULL, kseed(a), pk, p, sk, s), NQEARG);
  NQTEQI(nqskgd(a, seed, kseed(a) - 1, pk, p, sk, s), NQEARG);
  NQTEQI(nqskgd(a, seed, kseed(a) + 1, pk, p, sk, s), NQEARG);
  NQTEQI(nqskgd(a, seed, kseed(a), pk, p - 1, sk, s), NQEBUF);
  NQTEQI(nqskgd(a, seed, kseed(a), pk, p, sk, s - 1), NQEBUF);
  /* sign (pk, sk: the key pair sone made) */
  NQTEQI(nqsign(a, sk, s, m, 3, NULL, 0, 0, sig, g - 1, &out), NQEBUF);
  NQTEQI(out, 0);
  NQTEQI(nqsign(a, NULL, s, m, 3, NULL, 0, 0, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, NULL, 3, NULL, 0, 0, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, m, 3, NULL, 1, 0, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, m, 3, ctx, 256, 0, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, m, 3, NULL, 0, 0, NULL, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, m, 3, NULL, 0, 99, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s, m, 3, NULL, 0, -1, sig, g, &out), NQEARG);
  NQTEQI(nqsign(a, sk, s - 1, m, 3, NULL, 0, 0, sig, g, &out), NQEDEC);
  NQTEQI(nqsign(a, sk, s + 1, m, 3, NULL, 0, 0, sig, g, &out), NQEDEC);
  NQTEQI(nqsignd(a, sk, s, m, 3, NULL, 0, 0, NULL, 0, sig, g, &out),
         NQEARG);
  NQTEQI(nqsignd(a, sk, s, m, 3, NULL, 0, 0, rnd, rlen(a) - 1, sig, g,
                 &out), NQEARG);
  NQTEQI(nqsignd(a, sk, s, m, 3, NULL, 0, 0, rnd, rlen(a) + 1, sig, g,
                 &out), NQEARG);
  NQTEQI(nqsignd(a, sk, s, m, 3, NULL, 0, 0, rnd, rlen(a), sig, g - 1,
                 &out), NQEBUF);
  NQTEQI(nqsignd(a, sk, s, m, 3, ctx, 256, 0, rnd, rlen(a), sig, g, &out),
         NQEARG);
  /* verify: arguments and lengths, before any maths */
  memset(sig, 0, g + 1);
  NQTEQI(nqvrfy(a, NULL, p, m, 3, NULL, 0, 0, sig, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p, NULL, 3, NULL, 0, 0, sig, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p, m, 3, NULL, 1, 0, sig, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p, m, 3, ctx, 256, 0, sig, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p, m, 3, NULL, 0, 0, NULL, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p, m, 3, NULL, 0, 99, sig, g), NQEARG);
  NQTEQI(nqvrfy(a, pk, p - 1, m, 3, NULL, 0, 0, sig, g), NQEDEC);
  NQTEQI(nqvrfy(a, pk, p + 1, m, 3, NULL, 0, 0, sig, g), NQEDEC);
  NQTEQI(nqvrfy(a, pk, p, m, 3, NULL, 0, 0, sig, g - 1), NQEDEC);
  NQTEQI(nqvrfy(a, pk, p, m, 3, NULL, 0, 0, sig, g + 1), NQEDEC);
  NQTCHK(nqvrfy(a, pk, p, m, 3, NULL, 0, 0, sig, g) != NQOK);
}

/* How much of sone runs: KG keygen only, ONE also one deterministic and
 * one hedged signature, ALL every check. */
enum { KG, ONE, ALL };

/* The level for alg. By default: ML-DSA and the 128-bit fast SLH-DSA
 * sets ALL; the other fast sets and SLH-DSA-SHA2-128s ONE; the other
 * small sets KG (each of their signatures takes seconds). NQSLOW=1:
 * ALL everywhere. NQFAST=1 or NQSLSUB set (the valgrind job): ML-DSA
 * ALL, fast sets ONE, small sets KG. */
static int level(nqsalg a) {
  const nqslp *p = nqslpar(a);
  int sm = p != NULL && p->hp >= 8; /* h' 8 or 9: the "s" sets */
  if (slow || p == NULL) {
    return ALL;
  }
  if (fast) {
    return sm ? KG : ONE;
  }
  if (sm) {
    return p->n == 16 && p->sha2 ? ONE : KG;
  }
  return p->n == 16 ? ALL : ONE;
}

/* Keygen, sign and verify for one algorithm, and the dispatch against
 * the module. */
static void sone(nqsalg a, size_t i) {
  const size_t p = ssz[i][0], s = ssz[i][1], g = ssz[i][2];
  const int md = ismd(a), lv = level(a);
  uint8_t seed[96], rnd[64], ctx[255], m[64], ref[SKX];
  size_t out = 0, ol = 0;
  fill(seed, sizeof seed, (unsigned)i);
  fill(m, sizeof m, 9);
  fill(ctx, sizeof ctx, 5);
  memset(rnd, 0, sizeof rnd);
  levels[lv]++;

  /* keygen: deterministic equals the module, larger buffers are fine
   * and untouched past the key */
  memset(pk, 0xa5, sizeof pk);
  memset(sk, 0xa5, sizeof sk);
  NQTEQI(nqskgd(a, seed, kseed(a), pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(pk[p], 0xa5);
  NQTEQI(sk[s], 0xa5);
  if (md) {
    NQTEQI(nqmdkgd((int)a, seed, 32, pk2, p, sk2, s), NQOK);
  } else {
    NQTEQI(nqslkgd(a, seed, kseed(a), pk2, p, sk2, s), NQOK);
    /* sk = SK.seed || SK.prf || PK.seed || PK.root, pk = its tail */
    NQTEQM(sk, seed, kseed(a));
    NQTEQM(pk, sk + s / 2, p);
  }
  NQTEQM(pk, pk2, p);
  NQTEQM(sk, sk2, s);
  memcpy(ref, sk, s);
  if (lv == KG) {
    return;
  }

  /* deterministic: verifies, by the module too; sk unchanged */
  NQTEQI(nqsignd(a, sk, s, m, sizeof m, ctx, 3, 0, rnd, rlen(a), sig,
                 sizeof sig, &out), NQOK);
  NQTEQI(out, g);
  NQTEQM(sk, ref, s);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQOK);
  if (md) {
    NQTEQI(nqmdvrfy((int)a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQOK);
  } else {
    NQTEQI(nqslvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQOK);
  }

  /* failures on it: NQEVRFY (another key: pk with a changed root or
   * t1 byte) */
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m - 1, ctx, 3, 0, sig, g), NQEVRFY);
  m[0] ^= 1;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  m[0] ^= 1;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 2, 0, sig, g), NQEVRFY);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, NULL, 0, 0, sig, g), NQEVRFY);
  ctx[1] ^= 0x80;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  ctx[1] ^= 0x80;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, NQS256, sig, g), NQEVRFY);
  sig[0] ^= 1;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  sig[0] ^= 1;
  sig[g / 2] ^= 0x10;
  NQTCHK(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g) != NQOK);
  sig[g / 2] ^= 0x10;
  pk[p - 1] ^= 1;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  pk[p - 1] ^= 1;
  pk[p / 2] ^= 0x40;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  pk[p / 2] ^= 0x40;
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig, g), NQOK);

  /* hedged: verifies, differs from the deterministic one; outlen NULL
   * is allowed; the buffer past the signature is untouched */
  memset(sig2, 0x5a, sizeof sig2);
  NQTEQI(nqsign(a, sk, s, m, sizeof m, ctx, 3, 0, sig2, sizeof sig2,
                NULL), NQOK);
  NQTEQI(sig2[g], 0x5a);
  NQTCHK(memcmp(sig, sig2, g) != 0);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig2, g), NQOK);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 1, 0, sig2, g), NQEVRFY);
  if (lv == ONE) {
    return;
  }

  /* the deterministic signature equals the module's */
  if (md) {
    NQTEQI(nqmdsign((int)a, sk, s, m, sizeof m, ctx, 3, 0, rnd, 32, sig3,
                    g, &ol), NQOK);
  } else {
    NQTEQI(nqslsignd(a, sk, s, m, sizeof m, ctx, 3, 0, NULL, 0, sig3, g,
                     &ol), NQOK);
  }
  NQTEQI(ol, g);
  NQTEQM(sig, sig3, g);

  /* a second hedged one differs from the first */
  NQTEQI(nqsign(a, sk, s, m, sizeof m, ctx, 3, 0, sig3, g, &out), NQOK);
  NQTEQI(out, g);
  NQTCHK(memcmp(sig2, sig3, g) != 0);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig3, g), NQOK);

  /* a nonzero rnd: another signature, and the module's bytes */
  rnd[rlen(a) - 1] = 1;
  NQTEQI(nqsignd(a, sk, s, m, sizeof m, ctx, 3, 0, rnd, rlen(a), sig2,
                 g, &out), NQOK);
  NQTCHK(memcmp(sig, sig2, g) != 0);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig2, g), NQOK);
  if (md) {
    NQTEQI(nqmdsign((int)a, sk, s, m, sizeof m, ctx, 3, 0, rnd, 32, sig3,
                    g, &ol), NQOK);
  } else {
    NQTEQI(nqslsignd(a, sk, s, m, sizeof m, ctx, 3, 0, rnd, rlen(a),
                     sig3, g, &ol), NQOK);
  }
  NQTEQM(sig2, sig3, g);

  /* a fresh key pair: differs; the empty message with a NULL pointer;
   * the longest context; another key's signature is NQEVRFY */
  NQTEQI(nqskg(a, pk3, p, sk3, s), NQOK);
  NQTCHK(memcmp(pk3, pk, p) != 0);
  NQTEQI(nqvrfy(a, pk3, p, m, sizeof m, ctx, 3, 0, sig, g), NQEVRFY);
  NQTEQI(nqsign(a, sk3, s, NULL, 0, ctx, 255, 0, sig2, g, &out), NQOK);
  NQTEQI(nqvrfy(a, pk3, p, NULL, 0, ctx, 255, 0, sig2, g), NQOK);
  NQTEQI(nqvrfy(a, pk3, p, m, 0, ctx, 255, 0, sig2, g), NQOK);
  NQTEQI(nqvrfy(a, pk3, p, NULL, 0, ctx, 254, 0, sig2, g), NQEVRFY);
  NQTEQI(nqvrfy(a, pk, p, NULL, 0, ctx, 255, 0, sig2, g), NQEVRFY);

  /* pre-hash (HashML-DSA / HashSLH-DSA) with SHA-256: verifies only as
   * the same pre-hash, equals the module */
  NQTEQI(nqsignd(a, sk, s, m, sizeof m, ctx, 3, NQS256, rnd, rlen(a),
                 sig2, g, &out), NQOK);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, NQS256, sig2, g), NQOK);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, 0, sig2, g), NQEVRFY);
  NQTEQI(nqvrfy(a, pk, p, m, sizeof m, ctx, 3, NQS512, sig2, g),
         NQEVRFY);
  if (md) {
    NQTEQI(nqmdsign((int)a, sk, s, m, sizeof m, ctx, 3, NQS256, rnd, 32,
                    sig3, g, &ol), NQOK);
  } else {
    NQTEQI(nqslsignd(a, sk, s, m, sizeof m, ctx, 3, NQS256, rnd, rlen(a),
                     sig3, g, &ol), NQOK);
  }
  NQTEQM(sig2, sig3, g);
}

/* Every pre-hash on the fastest set of each family. */
static void sph(void) {
  static const nqsalg a[2] = {NQMLDSA44, NQSLHK128F};
  const uint8_t m[5] = {'h', 'e', 'l', 'l', 'o'};
  uint8_t rnd[32];
  nqssz sz;
  size_t out;
  int h, j;
  memset(rnd, 0, sizeof rnd);
  for (j = 0; j < 2; j++) {
    NQTEQI(nqssize(a[j], &sz), NQOK);
    NQTEQI(nqskg(a[j], pk, sz.pk, sk, sz.sk), NQOK);
    for (h = NQS224; h <= NQSHK256; h++) {
      NQTEQI(nqsignd(a[j], sk, sz.sk, m, 5, NULL, 0, h, rnd,
                     ismd(a[j]) ? 32 : 16, sig, sz.sig, &out), NQOK);
      NQTEQI(nqvrfy(a[j], pk, sz.pk, m, 5, NULL, 0, h, sig, sz.sig),
             NQOK);
      NQTEQI(nqvrfy(a[j], pk, sz.pk, m, 5, NULL, 0,
                    h == NQSHK256 ? NQS224 : h + 1, sig, sz.sig),
             NQEVRFY);
      NQTEQI(nqvrfy(a[j], pk, sz.pk, m, 4, NULL, 0, h, sig, sz.sig),
             NQEVRFY);
    }
  }
}

static void sigs(void) {
  size_t i;
  for (i = 0; i < NSALG; i++) {
    sone(salgs[i], i);
    serr(salgs[i], i);
  }
  sph();
  /* an unknown alg everywhere */
  {
    size_t out = 1;
    uint8_t r[32] = {0};
    NQTEQI(nqskg((nqsalg)0, pk, PKX, sk, SKX), NQEARG);
    NQTEQI(nqskgd((nqsalg)99, r, 32, pk, PKX, sk, SKX), NQEARG);
    NQTEQI(nqsign((nqsalg)0, sk, 64, r, 1, NULL, 0, 0, sig, SIGX, &out),
           NQEARG);
    NQTEQI(out, 0);
    NQTEQI(nqsignd((nqsalg)16, sk, 64, r, 1, NULL, 0, 0, r, 32, sig, SIGX,
                   &out), NQEARG);
    NQTEQI(nqvrfy((nqsalg)0, pk, 32, r, 1, NULL, 0, 0, sig, 7856),
           NQEARG);
  }
}

/* ---- key encapsulation ---- */

static const nqkalg kalgs[6] = {NQMLKEM512, NQMLKEM768, NQMLKEM1024,
                                NQHQC128,   NQHQC192,   NQHQC256};
static const char *const kn[6] = {"ML-KEM-512", "ML-KEM-768",
                                  "ML-KEM-1024", "HQC-128", "HQC-192",
                                  "HQC-256"};
/* FIPS 203 table 3 and the HQC specification: pk, sk, ct, ss */
static const size_t ksz[6][4] = {
    {800, 1632, 768, 32},    {1184, 2400, 1088, 32},
    {1568, 3168, 1568, 32},  {2241, 2321, 4433, 32},
    {4514, 4602, 8978, 32},  {7237, 7333, 14421, 32}};
static const size_t kmsg[6] = {32, 32, 32, 32, 40, 48};

static uint8_t kpk[KPKX + 8], ksk[KSKX + 8], kpk2[KPKX], ksk2[KSKX];
static uint8_t kct[KCTX + 8], kct2[KCTX];

static void knames(void) {
  nqksz sz;
  nqkalg a;
  size_t i;
  for (i = 0; i < 6; i++) {
    NQTEQI(nqksize(kalgs[i], &sz), NQOK);
    NQTEQI(sz.pk, ksz[i][0]);
    NQTEQI(sz.sk, ksz[i][1]);
    NQTEQI(sz.ct, ksz[i][2]);
    NQTEQI(sz.ss, ksz[i][3]);
    NQTCHK(nqkname(kalgs[i]) != NULL &&
           strcmp(nqkname(kalgs[i]), kn[i]) == 0);
    a = (nqkalg)0;
    NQTEQI(nqkfind(kn[i], &a), NQOK);
    NQTEQI(a, kalgs[i]);
  }
  NQTEQI(nqksize((nqkalg)0, &sz), NQEARG);
  NQTEQI(nqksize((nqkalg)7, &sz), NQEARG);
  NQTEQI(nqksize(NQHQC128, NULL), NQEARG);
  NQTCHK(nqkname((nqkalg)0) == NULL);
  NQTCHK(nqkname((nqkalg)7) == NULL);
  NQTEQI(nqkfind("HQC-512", &a), NQENOSUP);
  NQTEQI(nqkfind("ML-KEM-768 ", &a), NQENOSUP);
  NQTEQI(nqkfind(NULL, &a), NQEARG);
  NQTEQI(nqkfind("HQC-128", NULL), NQEARG);
}

static void kone(size_t i) {
  const nqkalg a = kalgs[i];
  const size_t p = ksz[i][0], s = ksz[i][1], c = ksz[i][2];
  const int mk = i < 3, k = (int)i + 2;
  uint8_t seed[64], es[48], ss[40], ss2[32], ss3[32], j[32], r2[32];
  size_t sl = mk ? 64 : 32;
  fill(seed, sizeof seed, (unsigned)i + 40);
  fill(es, sizeof es, (unsigned)i + 50);

  /* keygen: seeded equals the module; the buffer tail is untouched */
  memset(kpk, 0xa5, sizeof kpk);
  memset(ksk, 0xa5, sizeof ksk);
  NQTEQI(nqkkgd(a, seed, sl, kpk, sizeof kpk, ksk, sizeof ksk), NQOK);
  NQTEQI(kpk[p], 0xa5);
  NQTEQI(ksk[s], 0xa5);
  if (mk) {
    NQTEQI(nqmkkgd(k, seed, 64, kpk2, p, ksk2, s), NQOK);
  } else {
    NQTEQI(nqhqkgd(a, seed, 32, kpk2, p, ksk2, s), NQOK);
  }
  NQTEQM(kpk, kpk2, p);
  NQTEQM(ksk, ksk2, s);

  /* seeded encapsulation equals the module; decapsulates */
  memset(ss, 0x5a, sizeof ss);
  memset(kct, 0x5a, sizeof kct);
  NQTEQI(nqencd(a, kpk, p, es, kmsg[i], kct, sizeof kct, ss, sizeof ss),
         NQOK);
  NQTEQI(ss[32], 0x5a);
  NQTEQI(kct[c], 0x5a);
  if (mk) {
    NQTEQI(nqmkencd(k, kpk, p, es, 32, kct2, c, ss2, 32), NQOK);
  } else {
    NQTEQI(nqhqencd(a, kpk, p, es, kmsg[i], kct2, c, ss2, 32), NQOK);
  }
  NQTEQM(kct, kct2, c);
  NQTEQM(ss, ss2, 32);
  NQTEQI(nqdec(a, ksk, s, kct, c, ss3, 32), NQOK);
  NQTEQM(ss, ss3, 32);
  if (mk) {
    NQTEQI(nqmkdecp(k, ksk, s, kct, c, ss2, 32), NQOK);
  } else {
    NQTEQI(nqhqdec(a, ksk, s, kct, c, ss2, 32), NQOK);
  }
  NQTEQM(ss, ss2, 32);

  /* fresh keys and randomness: round trip, differs each time */
  NQTEQI(nqkkg(a, kpk2, p, ksk2, s), NQOK);
  NQTCHK(memcmp(kpk, kpk2, p) != 0);
  NQTEQI(nqenc(a, kpk2, p, kct, c, ss, 32), NQOK);
  NQTEQI(nqenc(a, kpk2, p, kct2, c, ss2, 32), NQOK);
  NQTCHK(memcmp(kct, kct2, c) != 0);
  NQTCHK(memcmp(ss, ss2, 32) != 0);
  NQTEQI(nqdec(a, ksk2, s, kct, c, ss3, 32), NQOK);
  NQTEQM(ss, ss3, 32);
  NQTEQI(nqdec(a, ksk2, s, kct2, c, ss3, 32), NQOK);
  NQTEQM(ss2, ss3, 32);
  memcpy(r2, ss2, 32);

  /* implicit rejection: a changed ciphertext gives NQOK and another
   * secret, the same one each time; for ML-KEM it is J(z || c) */
  kct[c / 3] ^= 0x04;
  NQTEQI(nqdec(a, ksk2, s, kct, c, ss3, 32), NQOK);
  NQTCHK(memcmp(ss, ss3, 32) != 0);
  NQTEQI(nqdec(a, ksk2, s, kct, c, ss2, 32), NQOK);
  NQTEQM(ss2, ss3, 32);
  if (mk) {
    nqkctx x;
    nqshkini(&x, 256);
    nqkabs(&x, ksk2 + s - 32, 32);
    nqkabs(&x, kct, c);
    nqksqz(&x, j, 32);
    NQTEQM(ss3, j, 32);
    NQTEQI(nqmkdecp(k, ksk2, s, kct, c, ss2, 32), NQOK);
    NQTEQM(ss2, ss3, 32);
  }
  /* the wrong secret key also decapsulates, to another secret */
  NQTEQI(nqdec(a, ksk, s, kct2, c, ss3, 32), NQOK);
  NQTCHK(memcmp(ss3, r2, 32) != 0);

  /* errors */
  NQTEQI(nqkkg(a, NULL, p, ksk2, s), NQEARG);
  NQTEQI(nqkkg(a, kpk2, p, NULL, s), NQEARG);
  NQTEQI(nqkkg(a, kpk2, p - 1, ksk2, s), NQEBUF);
  NQTEQI(nqkkg(a, kpk2, p, ksk2, s - 1), NQEBUF);
  NQTEQI(nqkkgd(a, NULL, sl, kpk2, p, ksk2, s), NQEARG);
  NQTEQI(nqkkgd(a, seed, sl - 1, kpk2, p, ksk2, s), NQEARG);
  NQTEQI(nqkkgd(a, seed, sl + 1, kpk2, p, ksk2, s), NQEARG);
  NQTEQI(nqkkgd(a, seed, sl, kpk2, p - 1, ksk2, s), NQEBUF);
  NQTEQI(nqenc(a, NULL, p, kct, c, ss, 32), NQEARG);
  NQTEQI(nqenc(a, kpk, p, NULL, c, ss, 32), NQEARG);
  NQTEQI(nqenc(a, kpk, p, kct, c, NULL, 32), NQEARG);
  NQTEQI(nqenc(a, kpk, p, kct, c - 1, ss, 32), NQEBUF);
  NQTEQI(nqenc(a, kpk, p, kct, c, ss, 31), NQEBUF);
  NQTEQI(nqenc(a, kpk, p - 1, kct, c, ss, 32), NQEDEC);
  NQTEQI(nqenc(a, kpk, p + 1, kct, c, ss, 32), NQEDEC);
  NQTEQI(nqencd(a, kpk, p, NULL, kmsg[i], kct, c, ss, 32), NQEARG);
  NQTEQI(nqencd(a, kpk, p, es, kmsg[i] - 1, kct, c, ss, 32), NQEARG);
  NQTEQI(nqencd(a, kpk, p, es, kmsg[i] + 1, kct, c, ss, 32), NQEARG);
  NQTEQI(nqencd(a, kpk, p, es, kmsg[i], kct, c - 1, ss, 32), NQEBUF);
  memset(ss, 1, 32);
  NQTEQI(nqdec(a, ksk, s, kct, c - 1, ss, 32), NQEDEC);
  NQTEQI(ss[0] | ss[31], 0);
  NQTEQI(nqdec(a, ksk, s, kct, c + 1, ss, 32), NQEDEC);
  NQTEQI(nqdec(a, ksk, s - 1, kct, c, ss, 32), NQEDEC);
  NQTEQI(nqdec(a, ksk, s, kct, c, ss, 31), NQEBUF);
  NQTEQI(nqdec(a, NULL, s, kct, c, ss, 32), NQEARG);
  NQTEQI(nqdec(a, ksk, s, NULL, c, ss, 32), NQEARG);
  NQTEQI(nqdec(a, ksk, s, kct, c, NULL, 32), NQEARG);
  if (mk) {
    /* FIPS 203 7.2 modulus check: a coefficient of 4095 >= q */
    memcpy(kpk2, kpk, p);
    kpk2[0] = 0xff;
    kpk2[1] |= 0x0f;
    NQTEQI(nqenc(a, kpk2, p, kct, c, ss, 32), NQEDEC);
    /* 7.3 hash check: H(ek) inside dk */
    memcpy(ksk2, ksk, s);
    ksk2[s - 33] ^= 1;
    NQTEQI(nqdec(a, ksk2, s, kct, c, ss, 32), NQEDEC);
  }
}

static void kems(void) {
  size_t i;
  uint8_t b[64] = {0};
  knames();
  for (i = 0; i < 6; i++) {
    kone(i);
  }
  NQTEQI(nqkkg((nqkalg)0, kpk, KPKX, ksk, KSKX), NQEARG);
  NQTEQI(nqkkgd((nqkalg)7, b, 64, kpk, KPKX, ksk, KSKX), NQEARG);
  NQTEQI(nqenc((nqkalg)0, kpk, 800, kct, KCTX, b, 32), NQEARG);
  NQTEQI(nqencd((nqkalg)0, kpk, 800, b, 32, kct, KCTX, b + 32, 32),
         NQEARG);
  NQTEQI(nqdec((nqkalg)99, ksk, 1632, kct, 768, b, 32), NQEARG);
}

int main(void) {
  const char *f = getenv("NQFAST");
  fast = (f != NULL && f[0] == '1') || getenv("NQSLSUB") != NULL;
  f = getenv("NQSLOW");
  slow = f != NULL && f[0] == '1';
  snames1();
  sigs();
  kems();
  printf("signature sets: %ld all checks, %ld one signature each, %ld "
         "keys only%s\n", levels[ALL], levels[ONE], levels[KG],
         slow   ? " (NQSLOW=1)"
         : fast ? " (NQFAST=1 or NQSLSUB)"
                : " (NQSLOW=1: all)");
  return nqtdone("tapi");
}
