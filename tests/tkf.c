/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Sealed streams (nqkfeini ... nqkfdfin): known answers from fixed seeds
 * (vectors/kstream/kat.txt: an empty stream, part of a chunk, exactly
 * one chunk, exactly three, and two and a half, for each ML-KEM set),
 * round trips; every byte of the header changed, a chunk changed,
 * moved, repeated or dropped, the stream cut at a chunk's end or with
 * bytes after its end, a last chunk read as another and another read as
 * the last, another context or key; the chunk-size limits a reader
 * refuses, the chunk counter's end, and misuse.
 *
 *   tkf gen
 * prints the known answers' records again (test keys from fixed seeds). */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "box/box.h"
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

#define CH 1024
#define MAXS (NQKFHDR + 1568 + 4 * (CH + 16))
static uint8_t pk[1568], sk[3168], st[MAXS], st2[MAXS], pt[4 * CH],
    back[4 * CH];

/* seals pt[0..n) in chunks of CH; the stream's size */
static size_t seal(nqkalg a, const uint8_t *ctx, size_t cl, size_t n,
                   uint8_t *o) {
  nqkfctx c;
  nqksz z;
  size_t at = 0, w = 0, k = 0;
  (void)nqksize(a, &z);
  if (nqkfeini(&c, a, pk, z.pk, ctx, cl, CH, o, MAXS, &w) != NQOK) return 0;
  while (n - at > CH) {
    if (nqkfeupd(&c, pt + at, CH, o + w, MAXS - w, &k) != NQOK) return 0;
    at += CH;
    w += k;
  }
  /* the last chunk may be full: the stream ends with it */
  if (nqkfefin(&c, pt + at, n - at, o + w, MAXS - w, &k) != NQOK) return 0;
  return w + k;
}

/* opens a stream of n bytes as a reader does: the last chunk is the one
 * the input ends with; NQOK and *got, or the first error */
static int open1(nqkalg a, const uint8_t *ctx, size_t cl, const uint8_t *in,
                 size_t n, size_t *got) {
  nqkfctx c;
  nqksz z;
  uint32_t ch = 0;
  size_t at, k = 0;
  int rc;
  *got = 0;
  (void)nqksize(a, &z);
  if (n < NQKFHDR + z.ct) return NQEDEC;
  rc = nqkfdini(&c, a, sk, z.sk, ctx, cl, in, NQKFHDR + z.ct, &ch);
  if (rc != NQOK) return rc;
  at = NQKFHDR + z.ct;
  while (n - at > (size_t)ch + 16) {
    rc = nqkfdupd(&c, in + at, (size_t)ch + 16, back + *got,
                  sizeof back - *got, &k);
    if (rc != NQOK) return rc;
    at += (size_t)ch + 16;
    *got += k;
  }
  rc = nqkfdfin(&c, in + at, n - at, back + *got, sizeof back - *got, &k);
  if (rc == NQOK) *got += k;
  return rc;
}

static const size_t lens[5] = {0, 100, CH, 3 * CH, 2 * CH + CH / 2};

static void hexp(const char *name, const uint8_t *b, size_t n) {
  size_t i;
  printf("%s=", name);
  for (i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static int gen(void) {
  uint8_t kseed[64], eseed[32];
  nqkalg a;
  size_t i, j, n;
  for (j = 0; j < sizeof pt; j++) pt[j] = (uint8_t)(j * 7 + 5);
  for (a = NQMLKEM512; a <= NQMLKEM1024; a++) {
    nqksz z;
    (void)nqksize(a, &z);
    for (i = 0; i < 5; i++) {
      for (j = 0; j < 64; j++) kseed[j] = (uint8_t)(a * 16 + j);
      for (j = 0; j < 32; j++) eseed[j] = (uint8_t)(0x40 + a + i * 5 + j);
      if (nqkkgd(a, kseed, 64, pk, sizeof pk, sk, sizeof sk) != NQOK) {
        return 1;
      }
      rngseed(eseed, 32);
      n = seal(a, (const uint8_t *)"noqtis-stream", 13, lens[i], st);
      (void)nqsetrng(NULL, NULL);
      if (n == 0) return 1;
      printf("alg=%s\nchunk=%d\n", nqkname(a), CH);
      hexp("kseed", kseed, 64);
      hexp("eseed", eseed, 32);
      hexp("ctx", (const uint8_t *)"noqtis-stream", 13);
      hexp("msg", pt, lens[i]);
      hexp("out", st, n);
      printf("\n");
    }
  }
  return 0;
}

static void tkat(void) {
  static uint8_t kseed[64], eseed[64], ctx[64], want[MAXS];
  int seen = 0;
  NQTCHK(tkvopen(&kv, "kstream/kat.txt"));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    nqkalg a = (nqkalg)0;
    nqksz z;
    size_t kl = tkvh(&kv, "kseed", kseed, sizeof kseed);
    size_t el = tkvh(&kv, "eseed", eseed, sizeof eseed);
    size_t cl = tkvh(&kv, "ctx", ctx, sizeof ctx);
    size_t ml = tkvh(&kv, "msg", pt, sizeof pt);
    size_t wl = tkvh(&kv, "out", want, sizeof want), n, got = 0;
    NQTCHK(nqkfind(tkvs(&kv, "alg"), &a) == NQOK &&
           nqksize(a, &z) == NQOK && kl == 64 && el != (size_t)-1 &&
           cl != (size_t)-1 && ml != (size_t)-1 && wl != (size_t)-1);
    NQTEQI(nqkkgd(a, kseed, 64, pk, sizeof pk, sk, sizeof sk), NQOK);
    rngseed(eseed, el);
    n = seal(a, ctx, cl, ml, st);
    (void)nqsetrng(NULL, NULL);
    NQTEQI(n, wl);
    NQTEQM(st, want, wl);
    NQTEQI(open1(a, ctx, cl, want, wl, &got), NQOK);
    NQTEQI(got, ml);
    NQTEQM(back, pt, ml);
    seen++;
  }
  tkvclose(&kv);
  NQTEQI(seen, 15);
}

static void ttamper(void) {
  static const uint8_t ctx[] = "noqtis-stream";
  nqksz z;
  size_t n, h, i, got = 0, bad = 0, c0, c1;
  int rc;
  for (i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i * 3);
  NQTEQI(nqksize(NQMLKEM768, &z), NQOK);
  NQTEQI(nqkkg(NQMLKEM768, pk, sizeof pk, sk, sizeof sk), NQOK);
  h = NQKFHDR + z.ct;
  /* three chunks: two full, one of 500 bytes */
  n = seal(NQMLKEM768, ctx, sizeof ctx - 1, 2 * CH + 500, st);
  NQTEQI(n, h + 2 * (CH + 16) + 500 + 16);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, n, &got), NQOK);
  NQTEQI(got, 2 * CH + 500);
  NQTEQM(back, pt, got);
  /* every byte of the header and the first chunk, and some of the rest */
  for (i = 0; i < n; i += i < h + CH + 16 ? 1 : 97) {
    memcpy(st2, st, n);
    st2[i] ^= 0x10;
    rc = open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n, &got);
    if (rc == NQOK) bad++;
    if (i < 6) NQTEQI(rc, NQEDEC);
  }
  NQTEQI(bad, 0);
  /* a chunk size out of the limits in the header */
  memcpy(st2, st, n);
  nqst32b(st2 + 6, NQKFCMAX + 1);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n, &got), NQELIM);
  nqst32b(st2 + 6, NQKFCMIN - 1);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n, &got), NQELIM);
  /* within the limits, but not the one sealed: another key */
  nqst32b(st2 + 6, 2 * CH);
  rc = open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n, &got);
  NQTCHK(rc == NQEVRFY || rc == NQEDEC);
  c0 = h;
  c1 = h + CH + 16;
  /* chunks 0 and 1 swapped */
  memcpy(st2, st, n);
  memcpy(st2 + c0, st + c1, CH + 16);
  memcpy(st2 + c1, st + c0, CH + 16);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n, &got), NQEVRFY);
  /* chunk 0 twice (and so the rest one later) */
  memcpy(st2, st, c1);
  memcpy(st2 + c1, st + c0, n - c0);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n + CH + 16, &got),
         NQEVRFY);
  /* chunk 1 dropped */
  memcpy(st2, st, c1);
  memcpy(st2 + c1, st + c1 + CH + 16, n - c1 - CH - 16);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n - CH - 16, &got),
         NQEVRFY);
  /* the last chunk dropped: chunk 1 read as the last */
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, c1 + CH + 16, &got),
         NQEVRFY);
  /* cut inside a chunk, and with no chunk at all */
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, n - 1, &got), NQEVRFY);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, h + 5, &got), NQEDEC);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, h, &got), NQEDEC);
  /* bytes after the last chunk */
  memcpy(st2, st, n);
  memset(st2 + n, 0, 40);
  rc = open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n + 40, &got);
  NQTCHK(rc == NQEVRFY || rc == NQEDEC);
  /* the last chunk read as not the last: its full-size twin */
  n = seal(NQMLKEM768, ctx, sizeof ctx - 1, 2 * CH, st);
  memcpy(st2, st, n);
  memcpy(st2 + n, st + c0, CH + 16);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st2, n + CH + 16, &got),
         NQEVRFY);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, n, &got), NQOK);
  /* another context, another key, another set */
  NQTEQI(open1(NQMLKEM768, NULL, 0, st, n, &got), NQEVRFY);
  memcpy(st2, sk, z.sk);
  NQTEQI(nqkkg(NQMLKEM768, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(open1(NQMLKEM768, ctx, sizeof ctx - 1, st, n, &got), NQEVRFY);
  NQTEQI(open1(NQMLKEM1024, ctx, sizeof ctx - 1, st, n, &got), NQEDEC);
  memcpy(sk, st2, z.sk);
}

static void tmisuse(void) {
  nqkfctx c;
  nqkfst s;
  nqksz z;
  uint8_t h[NQKFHDR + 1568], o[CH + 16];
  size_t hl = 0, k = 0;
  uint32_t ch = 0;
  NQTEQI(nqksize(NQMLKEM512, &z), NQOK);
  NQTEQI(nqkkg(NQMLKEM512, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqkfeini(&c, NQHQC128, pk, z.pk, NULL, 0, 0, h, sizeof h, &hl),
         NQENOSUP);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, NQKFCMIN - 1, h,
                  sizeof h, &hl),
         NQEARG);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, NQKFCMAX + 1, h,
                  sizeof h, &hl),
         NQEARG);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, 0, h, NQKFHDR, &hl),
         NQEBUF);
  NQTEQI(hl, NQKFHDR + z.ct);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, 0, h, sizeof h, &hl),
         NQOK);
  NQTEQI(nqld32b(h + 6), NQKFCHUNK);
  NQTEQI(nqkfeupd(&c, pt, 100, o, sizeof o, &k), NQEARG);
  NQTEQI(nqkfeupd(&c, pt, 100, o, sizeof o, &k), NQESTATE);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, CH, h, sizeof h, &hl),
         NQOK);
  NQTEQI(nqkfdupd(&c, o, CH + 16, o, sizeof o, &k), NQESTATE);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, CH, h, sizeof h, &hl),
         NQOK);
  NQTEQI(nqkfefin(&c, pt, 0, o, sizeof o, &k), NQOK);
  NQTEQI(k, 16);
  NQTEQI(nqkfefin(&c, pt, 0, o, sizeof o, &k), NQESTATE);
  /* the counter's end: chunk 2^32 - 1 can only be the last */
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, CH, h, sizeof h, &hl),
         NQOK);
  memcpy(&s, &c, sizeof s);
  s.ctr = 0xffffffffu;
  memcpy(&c, &s, sizeof s);
  NQTEQI(nqkfeupd(&c, pt, CH, o, sizeof o, &k), NQELIM);
  NQTEQI(nqkfeini(&c, NQMLKEM512, pk, z.pk, NULL, 0, CH, h, sizeof h, &hl),
         NQOK);
  memcpy(&s, &c, sizeof s);
  s.ctr = 0xffffffffu;
  memcpy(&c, &s, sizeof s);
  NQTEQI(nqkfefin(&c, pt, 10, o, sizeof o, &k), NQOK);
  /* a reader: the wrong header size, a key of the wrong size */
  NQTEQI(nqkfdini(&c, NQMLKEM512, sk, z.sk, NULL, 0, h, hl - 1, &ch),
         NQEDEC);
  NQTEQI(nqkfdini(&c, NQMLKEM512, sk, z.sk - 1, NULL, 0, h, hl, &ch),
         NQEDEC);
  NQTEQI(nqkfdini(&c, NQMLKEM512, sk, z.sk, NULL, 0, h, hl, &ch), NQOK);
  NQTEQI(ch, CH);
  NQTEQI(nqkfdupd(&c, o, CH, o, sizeof o, &k), NQEDEC);
  NQTEQI(nqkfdupd(&c, o, CH + 16, o, sizeof o, &k), NQESTATE);
  memset(&c, 0, sizeof c);
  NQTEQI(nqkfdfin(&c, o, 16, o, sizeof o, &k), NQESTATE);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "gen") == 0) return gen();
  tkat();
  ttamper();
  tmisuse();
  return nqtdone("tkf");
}
