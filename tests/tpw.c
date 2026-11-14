/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Passphrase key file tests (nqpwenc, nqpwdec): known answers from a
 * fixed random source (vectors/pwk/kat.txt), a round trip with the
 * defaults, every byte of a file changed, each header field set out of
 * its limits (refused before any memory is taken), a wrong passphrase,
 * a wrong ad, cut and lengthened files, and the arguments refused.
 *
 *   tpw gen
 * prints the known answers' records again (test keys and passphrases,
 * fixed patterns; nothing secret). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "nqt.h"
#include "tkv.h"

static tkv kv;

/* the random source: SHAKE256 of a seed, as a stream */
static nqhctx rs;
static int rngfn(uint8_t *buf, size_t len, void *user) {
  (void)user;
  return nqhfin(&rs, buf, len) == NQOK ? 0 : 1;
}
static void rngseed(const uint8_t *s, size_t n) {
  (void)nqhini(&rs, NQSHK256);
  (void)nqhupd(&rs, s, n);
  (void)nqsetrng(rngfn, NULL);
}
static int rngno(uint8_t *buf, size_t len, void *user) {
  (void)buf;
  (void)len;
  (void)user;
  return 1;
}

static int nal;
static void *mal(size_t n, void *u) {
  (void)u;
  nal++;
  return malloc(n);
}
static void fre(void *p, size_t n, void *u) {
  (void)n;
  (void)u;
  free(p);
}

static int zero(const uint8_t *b, size_t n) {
  size_t i;
  uint8_t o = 0;
  for (i = 0; i < n; i++) o |= b[i];
  return o == 0;
}

static const char *ad = "noqtis-key-1 ML-DSA-44 sec";

/* the known answers' inputs: (m, t, p) and the key's length */
static const uint32_t gp[3][4] = {
  {8192, 1, 1, 32}, {8192, 2, 3, 2560}, {NQPWM, NQPWT, NQPWP, 64}};

static void hexp(const char *name, const uint8_t *b, size_t n) {
  size_t i;
  printf("%s=", name);
  for (i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static int gen(void) {
  static uint8_t sk[4096], out[4096 + NQPWOVH];
  uint8_t seed[32], pw[24];
  size_t i, j, on = 0;
  for (i = 0; i < 3; i++) {
    for (j = 0; j < sizeof seed; j++) seed[j] = (uint8_t)(i * 32 + j);
    for (j = 0; j < sizeof pw; j++) pw[j] = (uint8_t)('a' + (i + j) % 26);
    for (j = 0; j < gp[i][3]; j++) sk[j] = (uint8_t)(j * 13 + i);
    rngseed(seed, sizeof seed);
    if (nqpwenc(pw, sizeof pw, (const uint8_t *)ad, strlen(ad), gp[i][0],
                gp[i][1], gp[i][2], sk, gp[i][3], out, sizeof out,
                &on) != NQOK) {
      return 1;
    }
    hexp("seed", seed, sizeof seed);
    hexp("pw", pw, sizeof pw);
    hexp("ad", (const uint8_t *)ad, strlen(ad));
    printf("m=%u\nt=%u\np=%u\n", (unsigned)gp[i][0], (unsigned)gp[i][1],
           (unsigned)gp[i][2]);
    hexp("sk", sk, gp[i][3]);
    hexp("out", out, on);
    printf("\n");
  }
  (void)nqsetrng(NULL, NULL);
  return 0;
}

static void tkat(void) {
  static uint8_t seed[64], pw[64], a[256], sk[4096], want[4096 + NQPWOVH],
      got[4096 + NQPWOVH], back[4096];
  int seen = 0;
  NQTCHK(tkvopen(&kv, "pwk/kat.txt"));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    size_t sl = tkvh(&kv, "seed", seed, sizeof seed);
    size_t pl = tkvh(&kv, "pw", pw, sizeof pw);
    size_t al = tkvh(&kv, "ad", a, sizeof a);
    size_t kl = tkvh(&kv, "sk", sk, sizeof sk);
    size_t wl = tkvh(&kv, "out", want, sizeof want), on = 0, bn = 0;
    NQTCHK(sl != (size_t)-1 && pl != (size_t)-1 && al != (size_t)-1 &&
           kl != (size_t)-1 && wl == kl + NQPWOVH);
    rngseed(seed, sl);
    NQTEQI(nqpwenc(pw, pl, a, al, (uint32_t)tkvu(&kv, "m"),
                   (uint32_t)tkvu(&kv, "t"), (uint32_t)tkvu(&kv, "p"), sk, kl,
                   got, sizeof got, &on),
           NQOK);
    (void)nqsetrng(NULL, NULL);
    NQTEQI(on, wl);
    NQTEQM(got, want, wl);
    NQTEQI(nqpwdec(pw, pl, a, al, want, wl, back, sizeof back, &bn), NQOK);
    NQTEQI(bn, kl);
    NQTEQM(back, sk, kl);
    seen++;
  }
  tkvclose(&kv);
  NQTEQI(seen, 3);
}

/* a file of a 32-byte key under m 8 MiB, t 1, p 1 */
static uint8_t f0[32 + NQPWOVH], k0[32];
static const uint8_t pw0[] = "correct horse";

static int dec(const uint8_t *f, size_t n, uint8_t *out) {
  size_t got = 99;
  int rc;
  memset(out, 0xee, 32);
  rc = nqpwdec(pw0, sizeof pw0 - 1, (const uint8_t *)ad, strlen(ad), f, n,
               out, 32, &got);
  if (rc != NQOK) {
    NQTCHK(zero(out, 32));
    NQTCHK(got == 0 || rc == NQEBUF);
  }
  return rc;
}

/* f0 with the 32-bit field at off set to v */
static int field(size_t off, uint32_t v) {
  uint8_t f[sizeof f0], out[32];
  memcpy(f, f0, sizeof f);
  nqst32b(f + off, v);
  return dec(f, sizeof f, out);
}

static void ttamper(void) {
  uint8_t f[sizeof f0 + 1], out[32];
  size_t i, on = 0, bad = 0;
  int rc;
  for (i = 0; i < sizeof k0; i++) k0[i] = (uint8_t)(0xa0 + i);
  NQTEQI(nqpwenc(pw0, sizeof pw0 - 1, (const uint8_t *)ad, strlen(ad),
                 NQPWMMIN, 1, 1, k0, sizeof k0, f0, sizeof f0, &on),
         NQOK);
  NQTEQI(on, sizeof f0);
  NQTEQI(dec(f0, sizeof f0, out), NQOK);
  NQTEQM(out, k0, 32);
  /* every byte, one bit and all bits */
  for (i = 0; i < sizeof f0; i++) {
    unsigned x;
    for (x = 0; x < 2; x++) {
      memcpy(f, f0, sizeof f0);
      f[i] ^= x == 0 ? 0x01 : 0xff;
      rc = dec(f, sizeof f0, out);
      if (rc == NQOK) bad++;
      /* magic, version, KDF, AEAD: refused as another format */
      if (i < 7) NQTEQI(rc, NQEDEC);
      /* the salt, the key and the tag: the tag fails */
      if (i >= 19) NQTEQI(rc, NQEVRFY);
    }
  }
  NQTEQI(bad, 0);
  /* parameters out of the limits: refused before Argon2id (no memory) */
  NQTEQI(nqsetal(mal, fre, NULL), NQOK);
  nal = 0;
  NQTEQI(field(7, NQPWMMIN - 1), NQELIM);
  NQTEQI(field(7, NQPWMMAX + 1), NQELIM);
  NQTEQI(field(7, 0xffffffffu), NQELIM);
  NQTEQI(field(11, 0), NQELIM);
  NQTEQI(field(11, NQPWTMAX + 1), NQELIM);
  NQTEQI(field(15, 0), NQELIM);
  NQTEQI(field(15, NQPWPMAX + 1), NQELIM);
  {
    /* both within their own limits, m * t over the budget */
    uint8_t g[sizeof f0];
    memcpy(g, f0, sizeof g);
    nqst32b(g + 7, NQPWMMAX);
    nqst32b(g + 11, NQPWWORK / NQPWMMAX + 1);
    NQTEQI(dec(g, sizeof g, out), NQELIM);
  }
  NQTEQI(nal, 0);
  /* within the limits but not what was written: the tag fails */
  NQTEQI(field(7, NQPWMMIN + 4), NQEVRFY);
  NQTEQI(field(11, 2), NQEVRFY);
  NQTEQI(field(15, 2), NQEVRFY);
  NQTEQI(nqsetal(NULL, NULL, NULL), NQOK);
  /* cut at every length, and one byte more */
  for (i = 0; i < sizeof f0; i++) {
    rc = dec(f0, i, out);
    NQTCHK(rc == NQEDEC || rc == NQEVRFY);
  }
  memcpy(f, f0, sizeof f0);
  f[sizeof f0] = 0;
  {
    uint8_t o2[33];
    NQTEQI(nqpwdec(pw0, sizeof pw0 - 1, (const uint8_t *)ad, strlen(ad), f,
                   sizeof f0 + 1, o2, sizeof o2, &on),
           NQEVRFY);
    NQTCHK(zero(o2, sizeof o2));
  }
  /* a wrong passphrase, a wrong ad */
  NQTEQI(nqpwdec((const uint8_t *)"correct horsf", 13, (const uint8_t *)ad,
                 strlen(ad), f0, sizeof f0, out, 32, &on),
         NQEVRFY);
  NQTEQI(nqpwdec(pw0, sizeof pw0 - 1, (const uint8_t *)"noqtis-key-1 x sec",
                 18, f0, sizeof f0, out, 32, &on),
         NQEVRFY);
  NQTEQI(nqpwdec(pw0, sizeof pw0 - 1, NULL, 0, f0, sizeof f0, out, 32, &on),
         NQEVRFY);
  /* too small a buffer: the size, and nothing written */
  NQTEQI(nqpwdec(pw0, sizeof pw0 - 1, (const uint8_t *)ad, strlen(ad), f0,
                 sizeof f0, out, 31, &on),
         NQEBUF);
  NQTEQI(on, 32);
}

static void targs(void) {
  static uint8_t big[NQPWMAX + 1 + NQPWOVH], k[32], out[64 + NQPWOVH],
      pw[NQPWLEN + 1];
  size_t on = 0;
  memset(pw, 'p', sizeof pw);
  memset(k, 1, sizeof k);
#define ENC(pp, pl, m, t, p, cap)                                          \
  nqpwenc(pp, pl, NULL, 0, m, t, p, k, sizeof k, out, cap, &on)
  NQTEQI(ENC(pw, 0, 0, 0, 0, sizeof out), NQEARG);
  NQTEQI(ENC(NULL, 1, 0, 0, 0, sizeof out), NQEARG);
  NQTEQI(ENC(pw, NQPWLEN + 1, 0, 0, 0, sizeof out), NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMIN - 1, 1, 1, sizeof out), NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMAX + 1, 1, 1, sizeof out), NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMIN, NQPWTMAX + 1, 1, sizeof out), NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMIN, 1, NQPWPMAX + 1, sizeof out), NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMAX, NQPWWORK / NQPWMMAX + 1, 1, sizeof out),
         NQEARG);
  NQTEQI(ENC(pw, 8, NQPWMMIN, 1, 1, sizeof k + NQPWOVH - 1), NQEBUF);
  NQTEQI(on, sizeof k + NQPWOVH);
  NQTEQI(nqpwenc(pw, 8, pw, 1025, NQPWMMIN, 1, 1, k, sizeof k, out,
                 sizeof out, &on),
         NQEARG);
  NQTEQI(nqpwenc(pw, 8, NULL, 0, NQPWMMIN, 1, 1, k, 0, out, sizeof out,
                 &on),
         NQEARG);
  NQTEQI(nqpwenc(pw, 8, NULL, 0, NQPWMMIN, 1, 1, big, NQPWMAX + 1, big,
                 sizeof big, &on),
         NQEARG);
  /* the random source fails: nothing written */
  NQTEQI(nqsetrng(rngno, NULL), NQOK);
  memset(out, 0x55, sizeof out);
  NQTEQI(ENC(pw, 8, NQPWMMIN, 1, 1, sizeof out), NQERNG);
  NQTCHK(zero(out, sizeof k + NQPWOVH));
  NQTEQI(nqsetrng(NULL, NULL), NQOK);
  /* a key over NQPWMAX in a file: refused as a limit */
  memcpy(big, f0, 19);
  NQTEQI(nqpwdec(pw0, sizeof pw0 - 1, NULL, 0, big, sizeof big, big,
                 sizeof big, &on),
         NQELIM);
#undef ENC
}

/* the defaults, 64 MiB and 3 passes in 4 lanes, once */
static void tdef(void) {
  uint8_t k[64], out[64 + NQPWOVH], back[64];
  size_t on = 0, bn = 0;
  memset(k, 7, sizeof k);
  NQTEQI(nqpwenc(pw0, 13, NULL, 0, 0, 0, 0, k, sizeof k, out, sizeof out,
                 &on),
         NQOK);
  NQTEQI(nqld32b(out + 7), NQPWM);
  NQTEQI(nqld32b(out + 11), NQPWT);
  NQTEQI(nqld32b(out + 15), NQPWP);
  NQTEQI(nqpwdec(pw0, 13, NULL, 0, out, on, back, sizeof back, &bn), NQOK);
  NQTEQI(bn, sizeof k);
  NQTEQM(back, k, sizeof k);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "gen") == 0) return gen();
  tkat();
  ttamper();
  targs();
  tdef();
  return nqtdone("tpw");
}
