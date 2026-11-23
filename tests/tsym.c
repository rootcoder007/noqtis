/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* ChaCha20, AES-SIV and AES-GCM-SIV tests: every test vector of RFC 5297
 * appendix A, RFC 8452 appendix C (the counter-wrap tests among them)
 * and RFC 8439 appendix A.2 (vectors/sym/rfc.txt), each both ways; a
 * changed byte anywhere in a ciphertext, a tag, a key, a nonce or the
 * associated data is refused and the output is then zero; messages of
 * every length around the block size; and the errors. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "nqt.h"

#define LMAX 1700

static int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* the bytes of a hex field ("-" is none) into b; the length */
static size_t unhex(const char *s, size_t sl, uint8_t *b) {
  size_t i;
  if (sl == 1 && s[0] == '-') return 0;
  for (i = 0; i + 1 < sl; i += 2)
    b[i / 2] = (uint8_t)(hexv(s[i]) * 16 + hexv(s[i + 1]));
  return sl / 2;
}

static int zero(const uint8_t *p, size_t n) {
  size_t i;
  unsigned x = 0;
  for (i = 0; i < n; i++) x |= p[i];
  return x == 0;
}

static void tsiv(char **f, size_t *fl) {
  uint8_t key[64], adb[400], pt[400], want[420], got[420], back[400];
  const uint8_t *ad[8];
  size_t adl[8], nad = 0, kl, pl, wl, at = 0, i;
  const char *s = f[2], *e = f[2] + fl[2];
  kl = unhex(f[1], fl[1], key);
  if (!(fl[2] == 1 && s[0] == '-')) {
    while (s < e) {
      const char *c = memchr(s, ',', (size_t)(e - s));
      size_t l = c != NULL ? (size_t)(c - s) : (size_t)(e - s);
      ad[nad] = adb + at;
      adl[nad] = unhex(s, l, adb + at);
      at += adl[nad++];
      s += l + 1;
    }
  }
  pl = unhex(f[3], fl[3], pt);
  wl = unhex(f[4], fl[4], want);
  NQTEQI(wl, pl + 16);
  NQTEQI(nqsivenc(key, kl, ad, adl, nad, pt, pl, got, wl), NQOK);
  NQTEQM(got, want, wl);
  NQTEQI(nqsivdec(key, kl, ad, adl, nad, want, wl, back, pl), NQOK);
  NQTEQM(back, pt, pl);
  /* a changed byte of the output, of a string or of the key */
  for (i = 0; i < wl; i++) {
    want[i] ^= 0x01;
    memset(back, 0xaa, sizeof back);
    NQTEQI(nqsivdec(key, kl, ad, adl, nad, want, wl, back, pl), NQEVRFY);
    NQTCHK(zero(back, pl));
    want[i] ^= 0x01;
  }
  for (i = 0; i < at; i++) {
    adb[i] ^= 0x80;
    NQTEQI(nqsivdec(key, kl, ad, adl, nad, want, wl, back, pl), NQEVRFY);
    adb[i] ^= 0x80;
  }
  for (i = 0; i < kl; i++) {
    key[i] ^= 0x10;
    NQTEQI(nqsivdec(key, kl, ad, adl, nad, want, wl, back, pl), NQEVRFY);
    key[i] ^= 0x10;
  }
  /* the strings are separate inputs: one fewer, or the same bytes cut
   * elsewhere, is another message */
  if (nad > 0) {
    NQTEQI(nqsivdec(key, kl, ad, adl, nad - 1, want, wl, back, pl), NQEVRFY);
  }
  if (nad > 1 && adl[0] > 1) {
    adl[0]--;
    ad[1]--;
    adl[1]++;
    NQTEQI(nqsivdec(key, kl, ad, adl, nad, want, wl, back, pl), NQEVRFY);
  }
}

static void tgsiv(char **f, size_t *fl) {
  uint8_t key[32], nonce[12], ad[300], pt[300], want[320], got[320], back[300];
  size_t kl, al, pl, wl, i;
  kl = unhex(f[1], fl[1], key);
  NQTEQI(unhex(f[2], fl[2], nonce), 12);
  al = unhex(f[3], fl[3], ad);
  pl = unhex(f[4], fl[4], pt);
  wl = unhex(f[5], fl[5], want);
  NQTEQI(wl, pl + 16);
  NQTEQI(nqgsivenc(key, kl, nonce, 12, ad, al, pt, pl, got, wl), NQOK);
  NQTEQM(got, want, wl);
  NQTEQI(nqgsivdec(key, kl, nonce, 12, ad, al, want, wl, back, pl), NQOK);
  NQTEQM(back, pt, pl);
  for (i = 0; i < wl; i++) {
    want[i] ^= 0x04;
    memset(back, 0xaa, sizeof back);
    NQTEQI(nqgsivdec(key, kl, nonce, 12, ad, al, want, wl, back, pl), NQEVRFY);
    NQTCHK(zero(back, pl));
    want[i] ^= 0x04;
  }
  for (i = 0; i < al; i++) {
    ad[i] ^= 0x01;
    NQTEQI(nqgsivdec(key, kl, nonce, 12, ad, al, want, wl, back, pl), NQEVRFY);
    ad[i] ^= 0x01;
  }
  for (i = 0; i < 12; i++) {
    nonce[i] ^= 0x40;
    NQTEQI(nqgsivdec(key, kl, nonce, 12, ad, al, want, wl, back, pl), NQEVRFY);
    nonce[i] ^= 0x40;
  }
  for (i = 0; i < kl; i++) {
    key[i] ^= 0x02;
    NQTEQI(nqgsivdec(key, kl, nonce, 12, ad, al, want, wl, back, pl), NQEVRFY);
    key[i] ^= 0x02;
  }
}

static void tcha(char **f, size_t *fl) {
  uint8_t key[32], nonce[12], pt[400], want[400], got[400];
  size_t pl, i;
  uint32_t ctr = (uint32_t)strtoul(f[3], NULL, 10);
  NQTEQI(unhex(f[1], fl[1], key), 32);
  NQTEQI(unhex(f[2], fl[2], nonce), 12);
  pl = unhex(f[4], fl[4], pt);
  NQTEQI(unhex(f[5], fl[5], want), pl);
  NQTEQI(nqcha20(key, 32, nonce, 12, ctr, pt, pl, got), NQOK);
  NQTEQM(got, want, pl);
  /* in place, and the same call decrypts */
  NQTEQI(nqcha20(key, 32, nonce, 12, ctr, got, pl, got), NQOK);
  NQTEQM(got, pt, pl);
  /* from a later block the stream is the same stream */
  for (i = 64; i < pl; i += 64) {
    NQTEQI(nqcha20(key, 32, nonce, 12, ctr + (uint32_t)(i / 64), pt + i,
                   pl - i, got),
           NQOK);
    NQTEQM(got, want + i, pl - i);
  }
}

static void trfc(void) {
  static char line[LMAX];
  FILE *fp = fopen("vectors/sym/rfc.txt", "rb");
  int n[3] = {0, 0, 0};
  NQTCHK(fp != NULL);
  if (fp == NULL) return;
  while (fgets(line, sizeof line, fp) != NULL) {
    char *f[6], *p = line;
    size_t fl[6], k = 0;
    if (line[0] == '#' || line[0] == '\n') continue;
    while (k < 6 && *p != '\0' && *p != '\n') {
      f[k] = p;
      while (*p != ' ' && *p != '\n' && *p != '\0') p++;
      fl[k] = (size_t)(p - f[k]);
      k++;
      if (*p == ' ') *p++ = '\0';
    }
    *p = '\0';
    if (strcmp(f[0], "siv") == 0 && k == 5) {
      tsiv(f, fl);
      n[0]++;
    } else if (strcmp(f[0], "gsiv") == 0 && k == 6) {
      tgsiv(f, fl);
      n[1]++;
    } else if (strcmp(f[0], "cha") == 0 && k == 6) {
      tcha(f, fl);
      n[2]++;
    } else {
      NQTCHK(0);
    }
  }
  fclose(fp);
  NQTEQI(n[0], 2);
  NQTEQI(n[1], 50);
  NQTEQI(n[2], 3);
}

/* every length from 0 to 70 bytes, every key size, with and without
 * associated strings: what is encrypted decrypts, the output is the same
 * the second time, and another string, nonce or key is another output */
static void tlens(void) {
  uint8_t key[64], nonce[12], ad[40], pt[70], a[90], b[90], back[70];
  const uint8_t *adv[2];
  size_t adl[2], n, i, q;
  static const size_t sk[3] = {32, 48, 64}, gk[2] = {16, 32};
  for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i * 5 + 1);
  for (i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0xa0 + i);
  for (i = 0; i < sizeof ad; i++) ad[i] = (uint8_t)(i ^ 0x5c);
  for (i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i * 11 + 7);
  adv[0] = ad;
  adv[1] = ad + 17;
  adl[0] = 17;
  adl[1] = 23;
  for (n = 0; n <= 70; n++) {
    for (q = 0; q < 3; q++) {
      NQTEQI(nqsivenc(key, sk[q], adv, adl, 2, pt, n, a, n + 16), NQOK);
      NQTEQI(nqsivenc(key, sk[q], adv, adl, 2, pt, n, b, n + 16), NQOK);
      NQTEQM(a, b, n + 16);
      NQTEQI(nqsivdec(key, sk[q], adv, adl, 2, a, n + 16, back, n), NQOK);
      NQTEQM(back, pt, n);
      /* no strings at all, and an empty string, are different inputs */
      NQTEQI(nqsivenc(key, sk[q], NULL, NULL, 0, pt, n, b, n + 16), NQOK);
      NQTCHK(memcmp(a, b, 16) != 0);
      adl[1] = 0;
      NQTEQI(nqsivenc(key, sk[q], adv, adl, 1, pt, n, a, n + 16), NQOK);
      NQTEQI(nqsivenc(key, sk[q], adv, adl, 2, pt, n, b, n + 16), NQOK);
      NQTCHK(memcmp(a, b, 16) != 0);
      NQTEQI(nqsivdec(key, sk[q], adv, adl, 2, b, n + 16, back, n), NQOK);
      NQTEQM(back, pt, n);
      adl[1] = 23;
    }
    for (q = 0; q < 2; q++) {
      NQTEQI(nqgsivenc(key, gk[q], nonce, 12, ad, 40, pt, n, a, n + 16), NQOK);
      NQTEQI(nqgsivdec(key, gk[q], nonce, 12, ad, 40, a, n + 16, back, n),
             NQOK);
      NQTEQM(back, pt, n);
      nonce[3] ^= 1;
      NQTEQI(nqgsivenc(key, gk[q], nonce, 12, ad, 40, pt, n, b, n + 16), NQOK);
      nonce[3] ^= 1;
      NQTCHK(memcmp(a + n, b + n, 16) != 0);
      NQTEQI(nqgsivenc(key, gk[q], nonce, 12, NULL, 0, pt, n, b, n + 16), NQOK);
      NQTCHK(memcmp(a + n, b + n, 16) != 0);
      NQTEQI(nqgsivdec(key, gk[q], nonce, 12, NULL, 0, b, n + 16, back, n),
             NQOK);
      NQTEQM(back, pt, n);
    }
  }
}

static void terr(void) {
  uint8_t key[64] = {0}, nonce[12] = {0}, in[32] = {0}, out[48];
  const uint8_t *adv[1];
  size_t adl[1] = {4};
  adv[0] = in;
  /* ChaCha20 */
  NQTEQI(nqcha20(key, 32, nonce, 12, 0, in, 32, out), NQOK);
  NQTEQI(nqcha20(key, 32, nonce, 12, 0, NULL, 0, NULL), NQOK);
  NQTEQI(nqcha20(key, 16, nonce, 12, 0, in, 32, out), NQEARG);
  NQTEQI(nqcha20(key, 32, nonce, 8, 0, in, 32, out), NQEARG);
  NQTEQI(nqcha20(NULL, 32, nonce, 12, 0, in, 32, out), NQEARG);
  NQTEQI(nqcha20(key, 32, NULL, 12, 0, in, 32, out), NQEARG);
  NQTEQI(nqcha20(key, 32, nonce, 12, 0, NULL, 32, out), NQEARG);
  NQTEQI(nqcha20(key, 32, nonce, 12, 0, in, 32, NULL), NQEARG);
  /* the last block of the counter: 64 bytes fit, 65 do not */
  NQTEQI(nqcha20(key, 32, nonce, 12, 0xffffffffu, in, 32, out), NQOK);
  {
    uint8_t big[65] = {0}, bo[65];
    NQTEQI(nqcha20(key, 32, nonce, 12, 0xffffffffu, big, 64, bo), NQOK);
    NQTEQI(nqcha20(key, 32, nonce, 12, 0xffffffffu, big, 65, bo), NQELIM);
  }
  /* AES-SIV */
  NQTEQI(nqsivenc(key, 32, adv, adl, 1, in, 32, out, 48), NQOK);
  NQTEQI(nqsivenc(key, 32, NULL, NULL, 0, NULL, 0, out, 16), NQOK);
  NQTEQI(nqsivdec(key, 32, NULL, NULL, 0, out, 16, NULL, 0), NQOK);
  NQTEQI(nqsivenc(key, 16, adv, adl, 1, in, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(key, 40, adv, adl, 1, in, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(NULL, 32, adv, adl, 1, in, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(key, 32, adv, adl, 1, in, 32, out, 47), NQEARG);
  NQTEQI(nqsivenc(key, 32, adv, adl, 1, in, 32, NULL, 48), NQEARG);
  NQTEQI(nqsivenc(key, 32, adv, adl, 1, NULL, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(key, 32, NULL, adl, 1, in, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(key, 32, adv, NULL, 1, in, 32, out, 48), NQEARG);
  NQTEQI(nqsivenc(key, 32, adv, adl, 127, in, 32, out, 48), NQEARG);
  adv[0] = NULL;
  NQTEQI(nqsivenc(key, 32, adv, adl, 1, in, 32, out, 48), NQEARG);
  adv[0] = in;
  NQTEQI(nqsivdec(key, 32, adv, adl, 1, out, 15, in, 0), NQEARG);
  NQTEQI(nqsivdec(key, 32, adv, adl, 1, out, 48, in, 31), NQEARG);
  NQTEQI(nqsivdec(key, 32, adv, adl, 1, NULL, 48, in, 32), NQEARG);
  NQTEQI(nqsivdec(key, 32, adv, adl, 1, out, 48, NULL, 32), NQEARG);
  NQTEQI(nqsivdec(key, 33, adv, adl, 1, out, 48, in, 32), NQEARG);
  /* AES-GCM-SIV */
  NQTEQI(nqgsivenc(key, 16, nonce, 12, in, 4, in, 32, out, 48), NQOK);
  NQTEQI(nqgsivenc(key, 32, nonce, 12, NULL, 0, NULL, 0, out, 16), NQOK);
  NQTEQI(nqgsivdec(key, 32, nonce, 12, NULL, 0, out, 16, NULL, 0), NQOK);
  NQTEQI(nqgsivenc(key, 24, nonce, 12, in, 4, in, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, nonce, 11, in, 4, in, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(NULL, 16, nonce, 12, in, 4, in, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, NULL, 12, in, 4, in, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, nonce, 12, NULL, 4, in, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, nonce, 12, in, 4, NULL, 32, out, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, nonce, 12, in, 4, in, 32, NULL, 48), NQEARG);
  NQTEQI(nqgsivenc(key, 16, nonce, 12, in, 4, in, 32, out, 49), NQEARG);
  NQTEQI(nqgsivdec(key, 16, nonce, 12, in, 4, out, 15, in, 0), NQEARG);
  NQTEQI(nqgsivdec(key, 16, nonce, 12, in, 4, out, 48, in, 33), NQEARG);
  NQTEQI(nqgsivdec(key, 16, nonce, 12, in, 4, NULL, 48, in, 32), NQEARG);
  NQTEQI(nqgsivdec(key, 16, nonce, 12, in, 4, out, 48, NULL, 32), NQEARG);
  NQTEQI(nqgsivdec(key, 16, nonce, 12, NULL, 4, out, 48, in, 32), NQEARG);
  NQTEQI(nqgsivdec(key, 20, nonce, 12, in, 4, out, 48, in, 32), NQEARG);
}

int main(void) {
  trfc();
  tlens();
  terr();
  return nqtdone("tsym");
}
