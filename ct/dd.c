/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* dudect: timing leakage test of every secret operation (Reparaz,
 * Balasch and Verbauwhede, "Dude, is my code constant time?", DATE 2017).
 *
 * Each measurement times one call, or a fixed batch of calls, of an
 * operation on an input of class 0 or class 1, the class drawn at random
 * per measurement so drift in the machine falls on both alike. Welch's
 * t-test compares the two timing distributions, raw and under 100 upper
 * crops (the paper's guard against the long tail of interrupts). A target
 * passes when every |t| stays below 4.5 after its N measurements.
 *
 * Inputs for a chunk of measurements are made before any of them is
 * timed, and both classes reach their slot the same way, by a copy:
 * making an input just before timing it, or in place, leaves caches and
 * predictors in a state that differs by class and shows a difference that
 * is not the code's. The inputs and the classes come from a seeded
 * generator (-s), so a run can be repeated; the library's own randomness
 * (the masks) comes from the operating system as always.
 *
 * The clock is ISO C timespec_get. A control (an early-exit compare) runs
 * first and must be flagged; if it is not, the clock or the machine cannot
 * resolve a leak and the run stops (exit 3).
 *
 *   nqdd [-n N] [-s seed] [-o out.json] [-m machine] [-t name,...|all|list]
 *
 * -t takes target and group names; "all" is every group but slhx (the
 * slower SLH-DSA sets), kg (key generation) and raw (comparisons whose
 * time depends on public values by design, kept to show it).
 *
 * Exit status: 0 every selected target passed, 1 one failed, 2 usage, 3
 * the control was not detected. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "noqtis.h"
#include "core/int.h"
#include "drbg/drbg.h"
#include "hash/h.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"
#include "mldsa/md.h"
#include "mldsa/mldsa.h"
#include "mlkem/mlkem.h"
#include "mlkem/ring.h"
#include "st.h"
#include "md1.h"

/* from cli/b64.c, compiled into this program */
size_t ncb64n(size_t len);
void ncb64e(const uint8_t *in, size_t len, char *out);
int ncb64d(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);
void nchexe(const uint8_t *in, size_t len, char *out);
int nchexd(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);

#define NCROP 100
#define POOL 256         /* random-class inputs made in advance */
#define CHMEM (8u << 20) /* bytes of input slots per chunk */

typedef struct tg {
  const char *name, *grp, *what;
  int a;          /* parameter: k, an nqsalg / nqkalg, a hash */
  size_t len;     /* bytes of one input */
  unsigned bat;   /* calls per measurement */
  unsigned div;   /* measures N / div */
  int (*prep)(const struct tg *t);
  void (*run)(const struct tg *t, const uint8_t *in);
  /* times one measurement itself when not NULL */
  double (*tm)(const struct tg *t, const uint8_t *in);
} tg;

/* ---- state shared by the targets ---- */

static xr G;
static uint8_t *p0, *p1;  /* class pools: n0 / n1 entries of len bytes */
static size_t n0, n1;     /* n1 == 0: class 1 is fresh random bytes */
static uint8_t gk[16384]; /* a fixed key or operand the input is used with */
static uint8_t gm[64];    /* a fixed message or mu */
static uint8_t ob[65536]; /* outputs */
static volatile uint32_t sink;

static int pools(size_t len, size_t a, size_t b) {
  free(p0);
  free(p1);
  p0 = (uint8_t *)malloc(len * (a ? a : 1));
  p1 = (uint8_t *)malloc(len * (b ? b : 1));
  n0 = a;
  n1 = b;
  return p0 != NULL && p1 != NULL ? 0 : -1;
}

static uint64_t now(void) {
  struct timespec t;
  timespec_get(&t, TIME_UTC);
  return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

/* ---- core: constant-time helpers ---- */

static int pcmp(const tg *t) {
  if (pools(t->len, 1, 0)) return -1;
  xrfill(&G, gk, t->len);
  memcpy(p0, gk, t->len); /* class 0: equal to gk */
  return 0;
}

static void rcteq(const tg *t, const uint8_t *in) {
  sink += (uint32_t)nqcteq(in, gk, t->len);
}

/* the control: an early-exit compare, which must be flagged */
static void rleak(const tg *t, const uint8_t *in) {
  size_t i;
  for (i = 0; i < t->len; i++) {
    if (in[i] != gk[i]) break;
  }
  sink += (uint32_t)i;
}

/* cond byte, then 32 bytes; class 0: cond 0 and a fixed source */
static int pzero(const tg *t) {
  if (pools(t->len, 1, 0)) return -1;
  memset(p0, 0, t->len);
  xrfill(&G, gk, 64);
  return 0;
}

static void rcmov(const tg *t, const uint8_t *in) {
  uint8_t d[32];
  (void)t;
  memcpy(d, gk, 32);
  nqcmov(d, in + 1, 32, (uint8_t)(in[0] & 1u));
  sink += d[0];
}

static void rsel(const tg *t, const uint8_t *in) {
  uint32_t acc = 0;
  size_t i;
  for (i = 0; i + 4 <= t->len; i += 4) {
    acc ^= nqctsel(nqctmask(nqld32l(in + i)), 0x5a5a5a5au, 0xa5a5a5a5u);
  }
  sink += acc;
}

/* fixed secret bytes against random ones */
static int pfix(const tg *t) {
  if (pools(t->len, 1, 0)) return -1;
  xrfill(&G, p0, t->len);
  xrfill(&G, gk, sizeof gk);
  xrfill(&G, gm, sizeof gm);
  return 0;
}

static void rb64e(const tg *t, const uint8_t *in) {
  ncb64e(in, t->len, (char *)ob);
  sink += ob[0];
}

/* base64 text of 48 bytes (64 characters and a newline) */
static int pb64(const tg *t) {
  uint8_t b[48];
  size_t i;
  if (pools(t->len, 1, POOL)) return -1;
  xrfill(&G, b, sizeof b);
  ncb64e(b, sizeof b, (char *)p0);
  for (i = 0; i < POOL; i++) {
    xrfill(&G, b, sizeof b);
    ncb64e(b, sizeof b, (char *)p1 + i * t->len);
  }
  return 0;
}

static void rb64d(const tg *t, const uint8_t *in) {
  size_t n;
  sink += (uint32_t)ncb64d((const char *)in, t->len, ob, 48, &n);
}

/* hex text of 32 bytes */
static int phex(const tg *t) {
  uint8_t b[32];
  size_t i;
  if (pools(t->len, 1, POOL)) return -1;
  xrfill(&G, b, sizeof b);
  nchexe(b, sizeof b, (char *)p0);
  for (i = 0; i < POOL; i++) {
    xrfill(&G, b, sizeof b);
    nchexe(b, sizeof b, (char *)p1 + i * t->len);
  }
  return 0;
}

static void rhexd(const tg *t, const uint8_t *in) {
  size_t n;
  sink += (uint32_t)nchexd((const char *)in, t->len, ob, 32, &n);
}

/* ---- hash, HMAC_DRBG ---- */

static void rhmac(const tg *t, const uint8_t *in) {
  nqhmac((nqhalg)t->a, in, t->len, gm, sizeof gm, ob, nqhlen((nqhalg)t->a));
  sink += ob[0];
}

/* entropy (48) and nonce (16): instantiate, generate 64 bytes */
static void rdrbg(const tg *t, const uint8_t *in) {
  nqdrbg d;
  nqdini(&d, (nqhalg)t->a, in, 48, in + 48, 16, NULL, 0, 0);
  nqdgen(&d, ob, 64, NULL, 0);
  nqdfree(&d);
  sink += ob[0];
}

/* ---- ML-KEM ---- */

/* Key generation samples A from rho by rejection, in time that depends
 * on rho; rho is public (it is in ek) but comes from the secret seed, so
 * fixed-vs-random seeds differ by that whatever else the code does. The
 * keygen targets measure the whole key generation and are reported in
 * their own group; mlkemmat768 times SampleNTT alone on the same rho,
 * which shows how much of the difference it explains. */
static double tmat(const tg *t, const uint8_t *in) {
  static nqmkpoly a[NQMKKX * NQMKKX];
  uint8_t g[33], h[64];
  uint64_t x, y;
  memcpy(g, in, 32);
  g[32] = (uint8_t)t->a;
  nqs3(512, g, sizeof g, h);
  x = now();
  nqmkmat(a, h, t->a, 0);
  y = now();
  sink += (uint16_t)a[0].c[0];
  return (double)(y - x);
}

static void rmat(const tg *t, const uint8_t *in) {
  (void)t;
  (void)in;
}

static void rmkkg(const tg *t, const uint8_t *in) {
  nqmkkgd(t->a, in, NQMKSEED, ob, NQMKEK(t->a), ob + NQMKEKX,
          NQMKDK(t->a));
  sink += ob[0];
}

/* A key pair with a given rho: K-PKE.KeyGen of FIPS 203 with rho fixed
 * and sigma, z random, so that every key of a test shares the public
 * matrix and differs only in its secrets. Into ek and dk. */
static void mkrho(int k, const uint8_t rho[32], uint8_t *ek, uint8_t *dk) {
  static nqmkpoly a[NQMKKX * NQMKKX], s[NQMKKX], e[NQMKKX], u[NQMKKX];
  uint8_t sig[32], n = 0;
  nqmkprm p;
  int i, j;
  nqmkpar(k, &p);
  xrfill(&G, sig, sizeof sig);
  nqmkmat(a, rho, k, 0);
  for (i = 0; i < k; i++) nqmkprf(&s[i], sig, n++, p.eta1);
  for (i = 0; i < k; i++) nqmkprf(&e[i], sig, n++, p.eta1);
  for (i = 0; i < k; i++) nqmkntt(&s[i]);
  for (i = 0; i < k; i++) nqmkntt(&e[i]);
  for (i = 0; i < k; i++) {
    nqmkdot(&u[i], &a[i * NQMKKX], s, k);
    for (j = 0; j < 256; j++) u[i].c[j] = nqmkmr((int32_t)u[i].c[j] * 1353);
    nqmkadd(&u[i], &u[i], &e[i]);
    nqmkcan(&u[i]);
    nqmkbe(ek + 384 * i, &u[i], 12);
    nqmkcan(&s[i]);
    nqmkbe(dk + 384 * i, &s[i], 12);
  }
  memcpy(ek + 384 * k, rho, 32);
  memcpy(dk + 384 * k, ek, p.ek);
  nqs3(256, ek, p.ek, dk + 384 * k + p.ek);
  xrfill(&G, dk + 384 * k + p.ek + 32, 32); /* z */
}

/* a valid ciphertext for ek into ct; -1 when decapsulation does not give
 * the encapsulated secret back (the key would be wrong) */
static int mkct(int k, const uint8_t *ek, const uint8_t *dk, uint8_t *ct) {
  uint8_t m[NQMKMSG], s1[NQMKSS], s2[NQMKSS];
  xrfill(&G, m, sizeof m);
  nqmkencd(k, ek, NQMKEK(k), m, sizeof m, ct, NQMKCT(k), s1, sizeof s1);
  nqmkdecp(k, dk, NQMKDK(k), ct, NQMKCT(k), s2, sizeof s2);
  return memcmp(s1, s2, sizeof s1) == 0 ? 0 : -1;
}

/* key test, dk || ct: class 0 one key with valid ciphertexts, class 1
 * other keys with theirs; every key has the same rho */
static int pmkk(const tg *t) {
  const int k = t->a;
  const size_t dl = NQMKDK(k);
  uint8_t rho[32], ek[NQMKEKX];
  size_t i;
  if (pools(t->len, POOL, POOL)) return -1;
  xrfill(&G, rho, sizeof rho);
  mkrho(k, rho, ek, gk);
  for (i = 0; i < POOL; i++) {
    uint8_t *e = p0 + i * t->len;
    memcpy(e, gk, dl);
    if (mkct(k, ek, e, e + dl)) return -1;
  }
  for (i = 0; i < POOL; i++) {
    uint8_t *e = p1 + i * t->len;
    mkrho(k, rho, ek, e);
    if (mkct(k, ek, e, e + dl)) return -1;
  }
  return 0;
}

/* the same with keys from nqmkkgd, each with its own rho (raw) */
static int pmkx(const tg *t) {
  const int k = t->a;
  const size_t dl = NQMKDK(k);
  uint8_t s[NQMKSEED], ek[NQMKEKX];
  size_t i;
  if (pools(t->len, POOL, POOL)) return -1;
  xrfill(&G, s, sizeof s);
  nqmkkgd(k, s, sizeof s, ek, NQMKEK(k), gk, dl);
  for (i = 0; i < POOL; i++) {
    uint8_t *e = p0 + i * t->len;
    memcpy(e, gk, dl);
    if (mkct(k, ek, e, e + dl)) return -1;
  }
  for (i = 0; i < POOL; i++) {
    uint8_t *e = p1 + i * t->len;
    xrfill(&G, s, sizeof s);
    nqmkkgd(k, s, sizeof s, ek, NQMKEK(k), e, dl);
    if (mkct(k, ek, e, e + dl)) return -1;
  }
  return 0;
}

/* validity test, ct: one key; class 0 valid ciphertexts, class 1 random
 * bytes (implicit rejection) */
static int pmkv(const tg *t) {
  const int k = t->a;
  uint8_t s[NQMKSEED], ek[NQMKEKX];
  size_t i;
  if (pools(t->len, POOL, 0)) return -1;
  xrfill(&G, s, sizeof s);
  nqmkkgd(k, s, sizeof s, ek, NQMKEK(k), gk, NQMKDK(k));
  for (i = 0; i < POOL; i++) {
    if (mkct(k, ek, gk, p0 + i * t->len)) return -1;
  }
  return 0;
}

static void rmkd(const tg *t, const uint8_t *in) {
  nqmkdec(t->a, in, NQMKDK(t->a), in + NQMKDK(t->a), NQMKCT(t->a), ob, 32);
  sink += ob[0];
}

static void rmkdp(const tg *t, const uint8_t *in) {
  nqmkdecp(t->a, in, NQMKDK(t->a), in + NQMKDK(t->a), NQMKCT(t->a), ob,
           32);
  sink += ob[0];
}

static void rmkv(const tg *t, const uint8_t *in) {
  nqmkdec(t->a, gk, NQMKDK(t->a), in, NQMKCT(t->a), ob, 32);
  sink += ob[0];
}

static void rmkvp(const tg *t, const uint8_t *in) {
  nqmkdecp(t->a, gk, NQMKDK(t->a), in, NQMKCT(t->a), ob, 32);
  sink += ob[0];
}

/* ---- ML-DSA ---- */

/* Signing time depends on public values by design: the number of
 * attempts, ExpandA from rho and SampleInBall from c~. So every input
 * signs in one attempt, every key of a test has the same rho, and both
 * classes draw a fresh rnd (c~ then varies in both); what is left to
 * differ is the secret key. The raw comparison (keys from nqmdkgd, rnd
 * fixed) is target mldsa44px. */

/* ML-DSA.KeyGen_internal with rho given and rho', K random: into sk */
static void mdrho(const nqmdp *p, const uint8_t rho[32], uint8_t *sk) {
  static nqmdpl s1[NQMDL], s1h[NQMDL], s2[NQMDK], t[NQMDK], t0[NQMDK];
  uint8_t rp[64], pk[NQMDPKMAX], *q;
  unsigned i, j;
  xrfill(&G, rp, sizeof rp);
  for (i = 0; i < p->l; i++) nqmdeta(p, s1[i].c, rp, (uint16_t)i);
  for (i = 0; i < p->k; i++) nqmdeta(p, s2[i].c, rp, (uint16_t)(p->l + i));
  for (i = 0; i < p->l; i++) {
    s1h[i] = s1[i];
    nqmdntt(s1h[i].c);
  }
  nqmdmat(p, rho, t, s1h, NULL, NULL);
  for (i = 0; i < p->k; i++) {
    nqmdred(t[i].c);
    nqmdint(t[i].c);
    for (j = 0; j < NQMDN; j++) t[i].c[j] += s2[i].c[j];
    nqmdcadd(t[i].c);
    for (j = 0; j < NQMDN; j++) { /* Power2Round */
      const int32_t a1 = (t[i].c[j] + (1 << 12) - 1) >> 13;
      t0[i].c[j] = t[i].c[j] - a1 * (1 << 13);
      t[i].c[j] = a1;
    }
  }
  memcpy(pk, rho, 32);
  for (i = 0; i < p->k; i++) nqmdt1p(pk + 32 + 320 * i, t[i].c);
  memcpy(sk, rho, 32);
  xrfill(&G, sk + 32, 32); /* K */
  nqshk(256, pk, p->pk, sk + 64, 64);
  q = sk + 128;
  for (i = 0; i < p->l; i++, q += 32 * p->etab) nqmdetp(p, q, s1[i].c);
  for (i = 0; i < p->k; i++, q += 32 * p->etab) nqmdetp(p, q, s2[i].c);
  for (i = 0; i < p->k; i++, q += 416) nqmdt0p(q, t0[i].c);
}

/* an rnd for sk that signs gm in one attempt, after sk */
static void mdrnd(const nqmdp *p, uint8_t *e) {
  do {
    xrfill(&G, e + p->sk, NQMDRND);
  } while (!first(p, e, gm, e + p->sk));
}

/* sk || rnd: class 0 one key with many rnd, class 1 other keys with
 * theirs; one rho */
static int pmd(const tg *t) {
  const nqmdp *p = nqmdpar(t->a);
  uint8_t rho[32];
  size_t i;
  if (p == NULL || pools(t->len, POOL, POOL)) return -1;
  xrfill(&G, gm, sizeof gm);
  xrfill(&G, rho, sizeof rho);
  mdrho(p, rho, gk);
  for (i = 0; i < POOL; i++) {
    memcpy(p0 + i * t->len, gk, p->sk);
    mdrnd(p, p0 + i * t->len);
  }
  for (i = 0; i < POOL; i++) {
    mdrho(p, rho, p1 + i * t->len);
    mdrnd(p, p1 + i * t->len);
  }
  return 0;
}

/* raw: class 0 one key and one rnd, class 1 keys from nqmdkgd (each its
 * own rho), still one attempt each */
static int pmdx(const tg *t) {
  const nqmdp *p = nqmdpar(t->a);
  uint8_t xi[NQMDSEED], pk[NQMDPKMAX];
  size_t i;
  if (p == NULL || pools(t->len, 1, POOL)) return -1;
  xrfill(&G, gm, sizeof gm);
  for (i = 0; i <= POOL; i++) {
    uint8_t *e = i == 0 ? p0 : p1 + (i - 1) * t->len;
    xrfill(&G, xi, sizeof xi);
    nqmdkgd(p->alg, xi, sizeof xi, pk, p->pk, e, p->sk);
    mdrnd(p, e);
  }
  return 0;
}

static void rmd(const tg *t, const uint8_t *in) {
  const nqmdp *p = nqmdpar(t->a);
  size_t ol;
  nqmdsmu(t->a, in, p->sk, gm, in + p->sk, NQMDRND, NQMDMASK, ob, p->sig,
          &ol);
  sink += ob[0];
}

static void rmdp(const tg *t, const uint8_t *in) {
  const nqmdp *p = nqmdpar(t->a);
  size_t ol;
  nqmdsmu(t->a, in, p->sk, gm, in + p->sk, NQMDRND, NQMDPLAIN, ob, p->sig,
          &ol);
  sink += ob[0];
}

/* ---- SLH-DSA ---- */

static void slpair(nqsalg a, uint8_t *e) {
  uint8_t seed[96], pk[64];
  nqssz z;
  nqssize(a, &z);
  xrfill(&G, seed, 3 * z.pk / 2);
  nqskgd(a, seed, 3 * z.pk / 2, pk, z.pk, e, z.sk);
  xrfill(&G, e + z.sk, z.pk / 2);
}

/* sk || opt_rand: class 0 one key and opt_rand, class 1 others */
static int psl(const tg *t) {
  size_t i;
  if (pools(t->len, 1, POOL / 8)) return -1;
  xrfill(&G, gm, sizeof gm);
  slpair((nqsalg)t->a, p0);
  for (i = 0; i < POOL / 8; i++) slpair((nqsalg)t->a, p1 + i * t->len);
  return 0;
}

static void rsl(const tg *t, const uint8_t *in) {
  nqssz z;
  size_t ol;
  nqssize((nqsalg)t->a, &z);
  nqsignd((nqsalg)t->a, in, z.sk, gm, sizeof gm, NULL, 0, 0, in + z.sk,
          z.pk / 2, ob, sizeof ob, &ol);
  sink += ob[0];
}

/* ---- HQC ---- */

/* Decapsulation draws y again from seed_dk with the specification's
 * rejection sampler (SampleFixedWeightVect$), whose time grows with the
 * 24-bit draws it rejects and the positions it draws twice; the code
 * declares both public, as the specification allows. They are fixed per
 * key, so keys differ in time by them. The key test therefore uses keys
 * whose sampler rejected nothing and repeated nothing, as most keys do,
 * and asks whether anything else differs; target hqc128x is the raw
 * comparison. This counts both, replaying the sampler on seed_dk. */
static unsigned hqcnt(const nqhqp *p, const uint8_t *sk) {
  uint32_t sup[NQHQWM];
  uint8_t buf[3 * NQHQWM + 8], d = 1;
  const size_t bl = 3 * (size_t)p->w, rem = bl % 8;
  size_t i = 0, j = bl, k;
  unsigned rej = 0, dup = 0;
  nqkctx x;
  nqshkini(&x, 256);
  nqkabs(&x, sk + p->pk, 32);
  nqkabs(&x, &d, 1);
  while (i < p->w) {
    uint32_t s, rp = 0;
    for (;;) {
      if (j == bl) {
        nqksqz(&x, buf, bl - rem);
        if (rem) nqksqz(&x, buf + bl - rem, 8);
        j = 0;
      }
      s = ((uint32_t)buf[j] << 16) | ((uint32_t)buf[j + 1] << 8) | buf[j + 2];
      j += 3;
      if (s < p->thr) break;
      rej++;
    }
    s %= p->n;
    for (k = 0; k < i; k++) rp |= sup[k] == s;
    sup[i] = s;
    dup += rp;
    i += 1u ^ rp;
  }
  return rej * 1000u + dup;
}

/* a ciphertext under a new key (newkey 1) or the last one, into sk, ct */
static void hqpair(nqkalg a, const nqksz *z, uint8_t *sk, uint8_t *ct,
                   int newkey) {
  static uint8_t pk[NQHQPK5];
  uint8_t s[NQHQSEED], m[NQHQM5 + NQHQSALT], ss[NQHQSS];
  const size_t ml = a == NQHQC128   ? NQHQM1
                    : a == NQHQC192 ? NQHQM3
                                    : NQHQM5;
  if (newkey) {
    xrfill(&G, s, sizeof s);
    nqhqkgd(a, s, sizeof s, pk, z->pk, sk, z->sk);
  }
  xrfill(&G, m, ml + NQHQSALT);
  nqhqencd(a, pk, z->pk, m, ml + NQHQSALT, ct, z->ct, ss, sizeof ss);
}

/* a key whose sampler drew no rejected and no repeated value */
static void hqclean(nqkalg a, const nqksz *z, uint8_t *sk, uint8_t *ct) {
  do {
    hqpair(a, z, sk, ct, 1);
  } while (hqcnt(nqhqpar(a), sk) != 0);
}

/* sk || ct: class 0 one key with valid ciphertexts, class 1 other keys
 * with theirs; clean: all keys of the sampler's common case */
static int phq(const tg *t, int clean) {
  const nqkalg a = (nqkalg)t->a;
  nqksz z;
  size_t i;
  nqksize(a, &z);
  if (pools(t->len, POOL / 4, POOL / 4)) return -1;
  if (clean) {
    hqclean(a, &z, gk, p0 + z.sk);
  } else {
    hqpair(a, &z, gk, p0 + z.sk, 1);
  }
  memcpy(p0, gk, z.sk);
  for (i = 1; i < POOL / 4; i++) {
    uint8_t *e = p0 + i * t->len;
    memcpy(e, gk, z.sk);
    hqpair(a, &z, e, e + z.sk, 0);
  }
  for (i = 0; i < POOL / 4; i++) {
    uint8_t *e = p1 + i * t->len;
    if (clean) {
      hqclean(a, &z, e, e + z.sk);
    } else {
      hqpair(a, &z, e, e + z.sk, 1);
    }
  }
  return 0;
}

static int phqk(const tg *t) {
  return phq(t, 1);
}

static int phqx(const tg *t) {
  return phq(t, 0);
}

/* ct: one key; class 0 valid ciphertexts, class 1 random bytes */
static int phqv(const tg *t) {
  nqksz z;
  size_t i;
  nqksize((nqkalg)t->a, &z);
  if (pools(t->len, POOL / 4, 0)) return -1;
  hqpair((nqkalg)t->a, &z, gk, p0, 1);
  for (i = 1; i < POOL / 4; i++) {
    hqpair((nqkalg)t->a, &z, gk, p0 + i * t->len, 0);
  }
  return 0;
}

static void rhqk(const tg *t, const uint8_t *in) {
  nqksz z;
  nqksize((nqkalg)t->a, &z);
  nqhqdec((nqkalg)t->a, in, z.sk, in + z.sk, z.ct, ob, 32);
  sink += ob[0];
}

static void rhqv(const tg *t, const uint8_t *in) {
  nqksz z;
  nqksize((nqkalg)t->a, &z);
  nqhqdec((nqkalg)t->a, gk, z.sk, in, z.ct, ob, 32);
  sink += ob[0];
}

/* ---- the targets ---- */

#define MKK(k) ((size_t)NQMKDK(k) + NQMKCT(k))
#define MDK(a) ((size_t)NQMD##a##SK + NQMDRND)
#define HQK(l) ((size_t)NQHQSK##l + NQHQCT##l)

static const tg tgs[] = {
    /* core */
    {"cteq", "core", "nqcteq, 64 bytes: equal vs random", 0, 64, 512, 1,
     pcmp, rcteq, NULL},
    {"cmov", "core", "nqcmov, 32 bytes: condition 0 and a fixed source vs "
     "random condition and source", 0, 33, 512, 1, pzero, rcmov, NULL},
    {"ctsel", "core", "nqctmask and nqctsel over 16 words: zero vs random",
     0, 64, 512, 1, pzero, rsel, NULL},
    {"b64e", "core", "key-file base64 encoder, 64 bytes: fixed vs random",
     0, 64, 32, 1, pfix, rb64e, NULL},
    {"b64d", "core", "key-file base64 decoder, 48 bytes: fixed vs random",
     0, 65, 32, 1, pb64, rb64d, NULL},
    {"hexd", "core", "seed hex decoder, 32 bytes: fixed vs random", 0, 64,
     32, 1, phex, rhexd, NULL},
    /* hash, drbg */
    {"hmac256", "hash", "HMAC-SHA-256, 32-byte key: fixed vs random",
     NQS256, 32, 4, 1, pfix, rhmac, NULL},
    {"hmac512", "hash", "HMAC-SHA-512, 64-byte key: fixed vs random",
     NQS512, 64, 4, 1, pfix, rhmac, NULL},
    {"drbg256", "drbg", "HMAC_DRBG SHA-256 instantiate and generate 64 "
     "bytes: fixed vs random entropy", NQS256, 64, 1, 1, pfix, rdrbg, NULL},
    {"drbg512", "drbg", "HMAC_DRBG SHA-512 instantiate and generate 64 "
     "bytes: fixed vs random entropy", NQS512, 64, 1, 1, pfix, rdrbg, NULL},
    /* ML-KEM */
    {"mlkem512", "mlkem", "ML-KEM-512 masked decaps: one key vs other "
     "keys (same rho), valid ciphertexts", 2, MKK(2), 1, 8, pmkk, rmkd,
     NULL},
    {"mlkem768", "mlkem", "ML-KEM-768 masked decaps: one key vs other "
     "keys (same rho), valid ciphertexts", 3, MKK(3), 1, 8, pmkk, rmkd,
     NULL},
    {"mlkem1024", "mlkem", "ML-KEM-1024 masked decaps: one key vs other "
     "keys (same rho), valid ciphertexts", 4, MKK(4), 1, 8, pmkk, rmkd,
     NULL},
    {"mlkem512v", "mlkem", "ML-KEM-512 masked decaps, one key: valid vs "
     "random (rejected) ciphertexts", 2, NQMKCT(2), 1, 8, pmkv, rmkv, NULL},
    {"mlkem768v", "mlkem", "ML-KEM-768 masked decaps, one key: valid vs "
     "random (rejected) ciphertexts", 3, NQMKCT(3), 1, 8, pmkv, rmkv, NULL},
    {"mlkem1024v", "mlkem", "ML-KEM-1024 masked decaps, one key: valid vs "
     "random (rejected) ciphertexts", 4, NQMKCT(4), 1, 8, pmkv, rmkv, NULL},
    {"mlkem512p", "mlkem", "ML-KEM-512 unmasked decaps: one key vs other "
     "keys (same rho)", 2, MKK(2), 1, 1, pmkk, rmkdp, NULL},
    {"mlkem768p", "mlkem", "ML-KEM-768 unmasked decaps: one key vs other "
     "keys (same rho)", 3, MKK(3), 1, 1, pmkk, rmkdp, NULL},
    {"mlkem1024p", "mlkem", "ML-KEM-1024 unmasked decaps: one key vs "
     "other keys (same rho)", 4, MKK(4), 1, 1, pmkk, rmkdp, NULL},
    {"mlkem512pv", "mlkem", "ML-KEM-512 unmasked decaps, one key: valid "
     "vs random ciphertexts", 2, NQMKCT(2), 1, 1, pmkv, rmkvp, NULL},
    {"mlkem768pv", "mlkem", "ML-KEM-768 unmasked decaps, one key: valid "
     "vs random ciphertexts", 3, NQMKCT(3), 1, 1, pmkv, rmkvp, NULL},
    {"mlkem1024pv", "mlkem", "ML-KEM-1024 unmasked decaps, one key: valid "
     "vs random ciphertexts", 4, NQMKCT(4), 1, 1, pmkv, rmkvp, NULL},
    /* ML-DSA */
    {"mldsa44", "mldsa", "ML-DSA-44 masked sign, one attempt: one key vs "
     "other keys (same rho), fresh rnd", NQMLDSA44, MDK(44), 1, 16, pmd,
     rmd, NULL},
    {"mldsa65", "mldsa", "ML-DSA-65 masked sign, one attempt: one key vs "
     "other keys (same rho), fresh rnd", NQMLDSA65, MDK(65), 1, 16, pmd,
     rmd, NULL},
    {"mldsa87", "mldsa", "ML-DSA-87 masked sign, one attempt: one key vs "
     "other keys (same rho), fresh rnd", NQMLDSA87, MDK(87), 1, 16, pmd,
     rmd, NULL},
    {"mldsa44p", "mldsa", "ML-DSA-44 unmasked sign, one attempt: one key "
     "vs other keys (same rho), fresh rnd", NQMLDSA44, MDK(44), 1, 2, pmd,
     rmdp, NULL},
    {"mldsa65p", "mldsa", "ML-DSA-65 unmasked sign, one attempt: one key "
     "vs other keys (same rho), fresh rnd", NQMLDSA65, MDK(65), 1, 2, pmd,
     rmdp, NULL},
    {"mldsa87p", "mldsa", "ML-DSA-87 unmasked sign, one attempt: one key "
     "vs other keys (same rho), fresh rnd", NQMLDSA87, MDK(87), 1, 2, pmd,
     rmdp, NULL},
    /* SLH-DSA: the 128f sets on every run, the others in slhx */
    {"slh128f", "slh", "SLH-DSA-SHA2-128f sign: one key and opt_rand vs "
     "others", NQSLH128F, 64 + 16, 1, 32, psl, rsl, NULL},
    {"slhk128f", "slh", "SLH-DSA-SHAKE-128f sign: one key and opt_rand vs "
     "others", NQSLHK128F, 64 + 16, 1, 64, psl, rsl, NULL},
    {"slh192f", "slhx", "SLH-DSA-SHA2-192f sign: one key and opt_rand vs "
     "others", NQSLH192F, 96 + 24, 1, 64, psl, rsl, NULL},
    {"slh256f", "slhx", "SLH-DSA-SHA2-256f sign: one key and opt_rand vs "
     "others", NQSLH256F, 128 + 32, 1, 128, psl, rsl, NULL},
    {"slhk192f", "slhx", "SLH-DSA-SHAKE-192f sign: one key and opt_rand "
     "vs others", NQSLHK192F, 96 + 24, 1, 128, psl, rsl, NULL},
    {"slhk256f", "slhx", "SLH-DSA-SHAKE-256f sign: one key and opt_rand "
     "vs others", NQSLHK256F, 128 + 32, 1, 256, psl, rsl, NULL},
    {"slh128s", "slhx", "SLH-DSA-SHA2-128s sign: one key and opt_rand vs "
     "others", NQSLH128S, 64 + 16, 1, 1024, psl, rsl, NULL},
    /* HQC */
    {"hqc128", "hqc", "HQC-128 decaps: one key vs other keys (sampler "
     "without rejections or repeats), valid ciphertexts", NQHQC128,
     HQK(1), 1, 4, phqk, rhqk, NULL},
    {"hqc192", "hqc", "HQC-192 decaps: one key vs other keys (sampler "
     "without rejections or repeats), valid ciphertexts", NQHQC192,
     HQK(3), 1, 8, phqk, rhqk, NULL},
    {"hqc256", "hqc", "HQC-256 decaps: one key vs other keys (sampler "
     "without rejections or repeats), valid ciphertexts", NQHQC256,
     HQK(5), 1, 16, phqk, rhqk, NULL},
    {"hqc128v", "hqc", "HQC-128 decaps, one key: valid vs random "
     "ciphertexts", NQHQC128, NQHQCT1, 1, 4, phqv, rhqv, NULL},
    {"hqc192v", "hqc", "HQC-192 decaps, one key: valid vs random "
     "ciphertexts", NQHQC192, NQHQCT3, 1, 8, phqv, rhqv, NULL},
    {"hqc256v", "hqc", "HQC-256 decaps, one key: valid vs random "
     "ciphertexts", NQHQC256, NQHQCT5, 1, 16, phqv, rhqv, NULL},
    /* key generation: its time depends on the public rho (see tmat) */
    {"mlkemkg512", "kg", "ML-KEM-512 keygen: fixed vs random seed (rho "
     "differs)", 2, NQMKSEED, 1, 1, pfix, rmkkg, NULL},
    {"mlkemkg768", "kg", "ML-KEM-768 keygen: fixed vs random seed (rho "
     "differs)", 3, NQMKSEED, 1, 1, pfix, rmkkg, NULL},
    {"mlkemkg1024", "kg", "ML-KEM-1024 keygen: fixed vs random seed (rho "
     "differs)", 4, NQMKSEED, 1, 1, pfix, rmkkg, NULL},
    /* raw: what public values do to the time (selected by name or raw) */
    {"mlkemmat768", "raw", "ML-KEM-768 SampleNTT alone of rho from a "
     "fixed vs random seed", 3, NQMKSEED, 1, 1, pfix, rmat, tmat},
    {"mlkem768px", "raw", "ML-KEM-768 unmasked decaps, raw: one key vs "
     "keys from keygen (rho differs)", 3, MKK(3), 1, 1, pmkx, rmkdp, NULL},
    {"mldsa44px", "raw", "ML-DSA-44 unmasked sign, raw: one key and rnd vs "
     "keys from keygen (rho and c~ differ)", NQMLDSA44, MDK(44), 1, 2,
     pmdx, rmdp, NULL},
    {"hqc128x", "raw", "HQC-128 decaps, raw: one key vs keys from keygen "
     "(sampler counts differ)", NQHQC128, HQK(1), 1, 4, phqx, rhqk, NULL},
};

static const tg ctl = {"control", "control", "early-exit compare, 64 "
                       "bytes: equal vs random (must be flagged)", 0, 64,
                       64, 1, pcmp, rleak, NULL};

/* ---- the test ---- */

typedef struct {
  long n;
  double t, tmax, m0, m1;
  int crop;
} res;

static double t1(const tg *t, const uint8_t *in) {
  uint64_t a, z;
  unsigned b;
  if (t->tm != NULL) return t->tm(t, in);
  a = now();
  for (b = 0; b < t->bat; b++) t->run(t, in);
  z = now();
  return (double)(z - a);
}

/* class of each slot at random; both classes reach the slot by a copy */
static void fill(const tg *t, uint8_t *buf, uint8_t *cls, uint8_t *scr,
                 long n) {
  long i;
  for (i = 0; i < n; i++) {
    uint8_t *s = buf + (size_t)i * t->len;
    const uint64_t r = xr64(&G);
    cls[i] = (uint8_t)(r & 1u);
    if (cls[i] == 0) {
      memcpy(s, p0 + (size_t)((r >> 1) % n0) * t->len, t->len);
    } else if (n1 > 0) {
      memcpy(s, p1 + (size_t)((r >> 1) % n1) * t->len, t->len);
    } else {
      xrfill(&G, scr, t->len);
      memcpy(s, scr, t->len);
    }
  }
}

static int cmpd(const void *a, const void *b) {
  const double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}

static int meas(const tg *t, long nm, res *o) {
  static wel all[2], cr[NCROP][2];
  double thr[NCROP], *w;
  uint8_t *buf, *cls, *scr;
  long ch = (long)(CHMEM / t->len), done, i;
  int k;
  if (ch > 4096) ch = 4096;
  if (ch < 64) ch = 64;
  if (t->prep(t)) return -1;
  buf = (uint8_t *)malloc((size_t)ch * t->len);
  cls = (uint8_t *)malloc((size_t)ch);
  scr = (uint8_t *)malloc(t->len);
  w = (double *)malloc((size_t)ch * sizeof *w);
  if (!buf || !cls || !scr || !w) return -1;
  memset(all, 0, sizeof all);
  memset(cr, 0, sizeof cr);
  /* a warm-up chunk, not counted, sets the crop thresholds */
  {
    const long nw = ch < nm ? ch : nm;
    fill(t, buf, cls, scr, nw);
    for (i = 0; i < nw; i++) w[i] = t1(t, buf + (size_t)i * t->len);
    qsort(w, (size_t)nw, sizeof *w, cmpd);
    for (k = 0; k < NCROP; k++) {
      const double p = 1.0 - pow(0.5, 10.0 * (k + 1) / NCROP);
      thr[k] = w[(size_t)(p * (double)(nw - 1))];
    }
  }
  for (done = 0; done < nm; done += ch) {
    const long n = nm - done < ch ? nm - done : ch;
    fill(t, buf, cls, scr, n);
    for (i = 0; i < n; i++) w[i] = t1(t, buf + (size_t)i * t->len);
    for (i = 0; i < n; i++) {
      welp(&all[cls[i]], w[i]);
      for (k = 0; k < NCROP; k++) {
        if (w[i] < thr[k]) welp(&cr[k][cls[i]], w[i]);
      }
    }
  }
  o->n = nm;
  o->t = welt(&all[0], &all[1]);
  o->tmax = fabs(o->t);
  o->crop = -1;
  o->m0 = all[0].m / t->bat;
  o->m1 = all[1].m / t->bat;
  for (k = 0; k < NCROP; k++) {
    double v;
    if (cr[k][0].n + cr[k][1].n < 100) continue;
    v = fabs(welt(&cr[k][0], &cr[k][1]));
    if (v > o->tmax) {
      o->tmax = v;
      o->crop = k;
    }
  }
  free(buf);
  free(cls);
  free(scr);
  free(w);
  return 0;
}

static void prow(const tg *t, const res *r) {
  printf("%-12s %9ld %8.2f %8.2f %4d %12.1f %12.1f  %s\n", t->name, r->n,
         r->t, r->tmax, r->crop, r->m0, r->m1,
         t == &ctl ? (r->tmax >= 10 ? "detected" : "NOT DETECTED")
                   : (r->tmax < NQTHR ? "pass" : "FAIL"));
  fflush(stdout);
}

/* a string into JSON, with anything but printable ASCII dropped */
static void jstr(FILE *f, const char *s) {
  fputc('"', f);
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') fputc('\\', f);
    if (*s >= 0x20 && *s < 0x7f) fputc(*s, f);
  }
  fputc('"', f);
}

static void jrow(FILE *f, const tg *t, const res *r, int last) {
  fprintf(f,
          "    {\"name\": \"%s\", \"group\": \"%s\", \"what\": \"%s\", "
          "\"n\": %ld, \"batch\": %u, \"t\": %.3f, \"maxt\": %.3f, "
          "\"crop\": %d, \"ns0\": %.1f, \"ns1\": %.1f, \"pass\": %s}%s\n",
          t->name, t->grp, t->what, r->n, t->bat, r->t, r->tmax, r->crop,
          r->m0, r->m1, r->tmax < NQTHR ? "true" : "false", last ? "" : ",");
}

/* name is selected by "all", its own name or its group, in a comma list */
static int pick(const char *sel, const tg *t) {
  const char *p = sel;
  while (*p) {
    size_t n = strcspn(p, ",");
    if ((n == 3 && strncmp(p, "all", 3) == 0 && strcmp(t->grp, "slhx") &&
         strcmp(t->grp, "raw") && strcmp(t->grp, "kg")) ||
        (strlen(t->name) == n && strncmp(p, t->name, n) == 0) ||
        (strlen(t->grp) == n && strncmp(p, t->grp, n) == 0)) {
      return 1;
    }
    p += n;
    if (*p == ',') p++;
  }
  return 0;
}

int main(int argc, char **argv) {
  const size_t nt = sizeof tgs / sizeof tgs[0];
  const char *sel = "all", *out = NULL, *mach = "";
  unsigned long long seed = 1;
  long n = 10000;
  static res rs[sizeof tgs / sizeof tgs[0]];
  res rc;
  int i, bad = 0, ran[sizeof tgs / sizeof tgs[0]];
  size_t j;
  FILE *f;
  for (i = 1; i < argc; i++) {
    if (i + 1 < argc && strcmp(argv[i], "-n") == 0) {
      n = atol(argv[++i]);
    } else if (i + 1 < argc && strcmp(argv[i], "-s") == 0) {
      seed = strtoull(argv[++i], NULL, 0);
    } else if (i + 1 < argc && strcmp(argv[i], "-o") == 0) {
      out = argv[++i];
    } else if (i + 1 < argc && strcmp(argv[i], "-m") == 0) {
      mach = argv[++i];
    } else if (i + 1 < argc && strcmp(argv[i], "-t") == 0) {
      sel = argv[++i];
    } else {
      fprintf(stderr, "usage: nqdd [-n N] [-s seed] [-o out.json] "
                      "[-m machine] [-t name,group,...|all|list]\n");
      return 2;
    }
  }
  if (strcmp(sel, "list") == 0) {
    for (j = 0; j < nt; j++) {
      printf("%-12s %-6s N/%-4u %s\n", tgs[j].name, tgs[j].grp, tgs[j].div,
             tgs[j].what);
    }
    return 0;
  }
  if (n < 200) n = 200;
  xrs(&G, seed);
  printf("noqtis %s dudect: N %ld (N/div per target), seed %llu, clock "
         "timespec_get, pass |t| < %.1f\n",
         nqver(), n, seed, NQTHR);
  printf("%-12s %9s %8s %8s %4s %12s %12s\n", "target", "n", "t", "max|t|",
         "crop", "ns class 0", "ns class 1");
  if (meas(&ctl, n, &rc)) return 2;
  prow(&ctl, &rc);
  if (rc.tmax < 10) {
    printf("control not detected (max |t| %.2f < 10): this clock or "
           "machine cannot resolve a leak; no result below is evidence\n",
           rc.tmax);
    return 3;
  }
  for (j = 0; j < nt; j++) {
    long m = n / (long)tgs[j].div;
    ran[j] = pick(sel, &tgs[j]);
    if (!ran[j]) continue;
    if (m < 200) m = 200;
    if (meas(&tgs[j], m, &rs[j])) {
      fprintf(stderr, "%s: setup failed\n", tgs[j].name);
      return 2;
    }
    prow(&tgs[j], &rs[j]);
    bad |= rs[j].tmax >= NQTHR;
  }
  if (out != NULL) {
    size_t last = nt;
    f = strcmp(out, "-") == 0 ? stdout : fopen(out, "w");
    if (f == NULL) return 2;
    for (j = 0; j < nt; j++) {
      if (ran[j]) last = j;
    }
    fprintf(f, "{\n  \"tool\": \"dudect\", \"noqtis\": \"%s\", "
               "\"machine\": ", nqver());
    jstr(f, mach);
    fprintf(f, ",\n  \"clock\": \"timespec_get\", \"n\": %ld, "
               "\"seed\": %llu, \"threshold\": %.1f,\n",
            n, seed, NQTHR);
    fprintf(f, "  \"control\": {\"maxt\": %.3f, \"detected\": %s},\n",
            rc.tmax, rc.tmax >= 10 ? "true" : "false");
    fprintf(f, "  \"results\": [\n");
    for (j = 0; j < nt; j++) {
      if (ran[j]) jrow(f, &tgs[j], &rs[j], j == last);
    }
    fprintf(f, "  ]\n}\n");
    if (f != stdout) fclose(f);
  }
  free(p0);
  free(p1);
  return bad ? 1 : 0;
}
