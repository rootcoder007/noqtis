/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Sealed messages (nqkseal, nqkopen): known answers for the three
 * ML-KEM sets from fixed seeds (vectors/kseal/kat.txt), round trips of
 * empty and longer messages, every byte of a sealed message changed,
 * another context, another key, another algorithm, cut and lengthened
 * input, and the arguments refused.
 *
 *   tks gen
 * prints the known answers' records again (test keys from fixed seeds;
 * nothing secret). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "nqt.h"
#include "tkv.h"

static tkv kv;

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

static int zero(const uint8_t *b, size_t n) {
  size_t i;
  uint8_t o = 0;
  for (i = 0; i < n; i++) o |= b[i];
  return o == 0;
}

#define PKMAX 1568
#define SKMAX 3168
#define OUTMAX (NQKSOVH + 1568 + 300)

static void hexp(const char *name, const uint8_t *b, size_t n) {
  size_t i;
  printf("%s=", name);
  for (i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static const char *ctxs[3] = {"", "noqtis-commit-1", "x"};
static const size_t mlen[3] = {0, 37, 256};

static int gen(void) {
  static uint8_t pk[PKMAX], sk[SKMAX], out[OUTMAX], msg[300];
  uint8_t kseed[64], eseed[32];
  nqkalg a;
  nqksz z;
  size_t i, j, on = 0;
  for (a = NQMLKEM512; a <= NQMLKEM1024; a++) {
    for (i = 0; i < 3; i++) {
      for (j = 0; j < sizeof kseed; j++) kseed[j] = (uint8_t)(a * 64 + j);
      for (j = 0; j < sizeof eseed; j++) {
        eseed[j] = (uint8_t)(0x80 + a * 3 + i + j);
      }
      for (j = 0; j < mlen[i]; j++) msg[j] = (uint8_t)(j * 11 + i);
      if (nqksize(a, &z) != NQOK ||
          nqkkgd(a, kseed, sizeof kseed, pk, sizeof pk, sk, sizeof sk) !=
              NQOK) {
        return 1;
      }
      rngseed(eseed, sizeof eseed);
      if (nqkseal(a, pk, z.pk, (const uint8_t *)ctxs[i], strlen(ctxs[i]),
                  msg, mlen[i], out, sizeof out, &on) != NQOK) {
        return 1;
      }
      (void)nqsetrng(NULL, NULL);
      printf("alg=%s\n", nqkname(a));
      hexp("kseed", kseed, sizeof kseed);
      hexp("eseed", eseed, sizeof eseed);
      hexp("ctx", (const uint8_t *)ctxs[i], strlen(ctxs[i]));
      hexp("msg", msg, mlen[i]);
      hexp("out", out, on);
      printf("\n");
    }
  }
  return 0;
}

static void tkat(void) {
  static uint8_t pk[PKMAX], sk[SKMAX], want[OUTMAX], got[OUTMAX], msg[300],
      back[300], kseed[64], eseed[64], ctx[256];
  int seen = 0;
  NQTCHK(tkvopen(&kv, "kseal/kat.txt"));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    nqkalg a = (nqkalg)0;
    nqksz z = {0, 0, 0, 0};
    size_t kl = tkvh(&kv, "kseed", kseed, sizeof kseed);
    size_t el = tkvh(&kv, "eseed", eseed, sizeof eseed);
    size_t cl = tkvh(&kv, "ctx", ctx, sizeof ctx);
    size_t ml = tkvh(&kv, "msg", msg, sizeof msg);
    size_t wl = tkvh(&kv, "out", want, sizeof want), on = 0, bn = 0;
    const char *an = tkvs(&kv, "alg");
    NQTCHK(an != NULL && nqkfind(an, &a) == NQOK && nqksize(a, &z) == NQOK);
    NQTCHK(kl == 64 && el != (size_t)-1 && cl != (size_t)-1 &&
           ml != (size_t)-1 && wl == NQKSOVH + z.ct + ml);
    NQTEQI(nqkkgd(a, kseed, kl, pk, sizeof pk, sk, sizeof sk), NQOK);
    rngseed(eseed, el);
    NQTEQI(nqkseal(a, pk, z.pk, ctx, cl, msg, ml, got, sizeof got, &on),
           NQOK);
    (void)nqsetrng(NULL, NULL);
    NQTEQI(on, wl);
    NQTEQM(got, want, wl);
    NQTEQI(nqkopen(a, sk, z.sk, ctx, cl, want, wl, back, sizeof back, &bn),
           NQOK);
    NQTEQI(bn, ml);
    NQTEQM(back, msg, ml);
    seen++;
  }
  tkvclose(&kv);
  NQTEQI(seen, 9);
}

static void ttamper(void) {
  static uint8_t pk[PKMAX], sk[SKMAX], pk2[PKMAX], sk2[SKMAX], out[OUTMAX],
      f[OUTMAX + 1], back[64];
  static const uint8_t msg[16] = "the hidden list";
  static const uint8_t ctx[] = "noqtis-commit-1";
  nqksz z;
  size_t i, on = 0, bn = 0, bad = 0;
  int rc;
  NQTEQI(nqksize(NQMLKEM512, &z), NQOK);
  NQTEQI(nqkkg(NQMLKEM512, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqkkg(NQMLKEM512, pk2, sizeof pk2, sk2, sizeof sk2), NQOK);
  NQTEQI(nqkseal(NQMLKEM512, pk, z.pk, ctx, sizeof ctx - 1, msg, sizeof msg,
                 out, sizeof out, &on),
         NQOK);
  NQTEQI(on, NQKSOVH + z.ct + sizeof msg);
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 1, out, on, back,
                 sizeof back, &bn),
         NQOK);
  NQTEQI(bn, sizeof msg);
  NQTEQM(back, msg, sizeof msg);
  /* every byte: the header as another format, the rest fails the tag */
  for (i = 0; i < on; i++) {
    unsigned x;
    for (x = 0; x < 2; x++) {
      memcpy(f, out, on);
      f[i] ^= x == 0 ? 0x01 : 0x80;
      memset(back, 0xee, sizeof back);
      rc = nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 1, f, on, back,
                   sizeof back, &bn);
      if (rc == NQOK) bad++;
      NQTEQI(rc, i < 6 ? NQEDEC : NQEVRFY);
      NQTCHK(zero(back, sizeof msg));
      NQTEQI(bn, 0);
    }
  }
  NQTEQI(bad, 0);
  /* another context: none, one byte less, one byte more */
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, NULL, 0, out, on, back, sizeof back,
                 &bn),
         NQEVRFY);
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 2, out, on, back,
                 sizeof back, &bn),
         NQEVRFY);
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx, out, on, back,
                 sizeof back, &bn),
         NQEVRFY);
  /* another key of the same set */
  NQTEQI(nqkopen(NQMLKEM512, sk2, z.sk, ctx, sizeof ctx - 1, out, on, back,
                 sizeof back, &bn),
         NQEVRFY);
  /* another set: its header names ML-KEM-512 */
  NQTEQI(nqkopen(NQMLKEM768, sk2, 2400, ctx, sizeof ctx - 1, out, on, back,
                 sizeof back, &bn),
         NQEDEC);
  /* cut at every length below a full one, one byte more */
  for (i = 0; i < on; i++) {
    rc = nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 1, out, i, back,
                 sizeof back, &bn);
    NQTCHK(rc == (i < NQKSOVH + z.ct ? NQEDEC : NQEVRFY));
  }
  memcpy(f, out, on);
  f[on] = 0;
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 1, f, on + 1, back,
                 sizeof back, &bn),
         NQEVRFY);
  /* a short buffer: the size */
  NQTEQI(nqkopen(NQMLKEM512, sk, z.sk, ctx, sizeof ctx - 1, out, on, back,
                 sizeof msg - 1, &bn),
         NQEBUF);
  NQTEQI(bn, sizeof msg);
  /* a secret key whose H(ek) was changed: ML-KEM refuses it */
  memcpy(sk2, sk, z.sk);
  sk2[z.sk - 64] ^= 1;
  NQTEQI(nqkopen(NQMLKEM512, sk2, z.sk, ctx, sizeof ctx - 1, out, on, back,
                 sizeof back, &bn),
         NQEDEC);
}

static void targs(void) {
  static uint8_t pk[PKMAX], sk[SKMAX], out[OUTMAX], ctx[256];
  nqksz z;
  size_t on = 0, bn = 0;
  NQTEQI(nqksize(NQMLKEM768, &z), NQOK);
  NQTEQI(nqkkg(NQMLKEM768, pk, sizeof pk, sk, sizeof sk), NQOK);
  /* an empty message, both ways */
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, NULL, 0, NULL, 0, out, sizeof out,
                 &on),
         NQOK);
  NQTEQI(on, NQKSOVH + z.ct);
  NQTEQI(nqkopen(NQMLKEM768, sk, z.sk, NULL, 0, out, on, NULL, 0, &bn),
         NQOK);
  NQTEQI(bn, 0);
  memset(ctx, 'c', sizeof ctx);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, ctx, 256, NULL, 0, out, sizeof out,
                 &on),
         NQEARG);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, ctx, 255, NULL, 0, out, sizeof out,
                 &on),
         NQOK);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, NULL, 1, NULL, 0, out, sizeof out,
                 &on),
         NQEARG);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, NULL, 0, NULL, 1, out, sizeof out,
                 &on),
         NQEARG);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk - 1, NULL, 0, NULL, 0, out,
                 sizeof out, &on),
         NQEDEC);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, NULL, 0, ctx, NQKSMAX + 1, out,
                 sizeof out, &on),
         NQELIM);
  NQTEQI(nqkseal(NQMLKEM768, pk, z.pk, NULL, 0, NULL, 0, out,
                 NQKSOVH + z.ct - 1, &on),
         NQEBUF);
  NQTEQI(on, NQKSOVH + z.ct);
  NQTEQI(nqkseal(NQHQC128, pk, z.pk, NULL, 0, NULL, 0, out, sizeof out,
                 &on),
         NQENOSUP);
  NQTEQI(nqkseal((nqkalg)99, pk, z.pk, NULL, 0, NULL, 0, out, sizeof out,
                 &on),
         NQEARG);
  NQTEQI(nqkopen(NQHQC128, sk, z.sk, NULL, 0, out, on, NULL, 0, &bn),
         NQENOSUP);
  NQTEQI(nqkopen(NQMLKEM768, sk, z.sk - 1, NULL, 0, out, on, NULL, 0, &bn),
         NQEDEC);
  NQTEQI(nqkopen(NQMLKEM768, NULL, z.sk, NULL, 0, out, on, NULL, 0, &bn),
         NQEARG);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "gen") == 0) return gen();
  tkat();
  ttamper();
  targs();
  return nqtdone("tks");
}
