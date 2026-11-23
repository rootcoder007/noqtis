/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* TurboSHAKE and KangarooTwelve tests: every test vector of RFC 9861
 * section 5 (vectors/kt/rfc9861.txt: 31 of TurboSHAKE128 and
 * TurboSHAKE256, 36 of KT128 and KT256), the output as a prefix of a
 * longer one, incremental input and output of the sponge in pieces of
 * every size, the chunk boundaries of the tree, the input of nqkt in
 * pieces (nqktini, nqktupd, nqktfin), and the errors. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "hash/h.h"
#include "nqt.h"

/* the bytes a vector names: ptn:N, the pattern 00 .. FA repeated to N
 * bytes, or ff:N, N bytes FF; NULL when it is neither */
static uint8_t *mk(const char *s, size_t *n) {
  uint8_t *p;
  size_t i;
  int ff = strncmp(s, "ff:", 3) == 0;
  if (!ff && strncmp(s, "ptn:", 4) != 0) return NULL;
  *n = (size_t)strtoul(s + (ff ? 3 : 4), NULL, 10);
  p = (uint8_t *)malloc(*n + 1);
  if (p == NULL) return NULL;
  for (i = 0; i < *n; i++) p[i] = ff ? 0xff : (uint8_t)(i % 251);
  return p;
}

static int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static void trfc(void) {
  char line[600], fn[16], ms[32], as[32], hex[300];
  unsigned long L;
  FILE *f = fopen("vectors/kt/rfc9861.txt", "rb");
  int seen[4] = {0, 0, 0, 0};
  NQTCHK(f != NULL);
  if (f == NULL) return;
  while (fgets(line, sizeof line, f) != NULL) {
    uint8_t want[128], *m, *a = NULL, *out;
    size_t ml = 0, al = 0, hl, i;
    unsigned bits;
    int kt;
    if (line[0] == '#' || line[0] == '\n') continue;
    NQTEQI(sscanf(line, "%15s %31s %31s %lu %299s", fn, ms, as, &L, hex), 5);
    kt = fn[0] == 'K';
    bits = strstr(fn, "128") != NULL ? 128u : 256u;
    hl = strlen(hex) / 2;
    NQTCHK(hl <= sizeof want && hl <= L);
    for (i = 0; i < hl; i++)
      want[i] = (uint8_t)(hexv(hex[2 * i]) * 16 + hexv(hex[2 * i + 1]));
    m = mk(ms, &ml);
    out = (uint8_t *)malloc(L);
    NQTCHK(m != NULL && out != NULL);
    if (m == NULL || out == NULL) {
      free(m);
      free(out);
      continue;
    }
    if (kt) {
      a = mk(as, &al);
      NQTCHK(a != NULL);
      NQTEQI(nqkt(bits, m, ml, a, al, out, L), NQOK);
    } else {
      nqtshk(bits, m, ml, (uint8_t)strtoul(as, NULL, 16), out, L);
    }
    /* the vector is the whole output, or its last bytes */
    NQTEQM(out + (L - hl), want, hl);
    seen[(kt ? 2 : 0) + (bits == 256)]++;
    free(m);
    free(a);
    free(out);
  }
  fclose(f);
  NQTEQI(seen[0], 16);
  NQTEQI(seen[1], 15);
  NQTEQI(seen[2], 18);
  NQTEQI(seen[3], 18);
}

/* the sponge in pieces of every size gives what the one-shot gives, and
 * a shorter output is the start of a longer one */
static void tparts(void) {
  uint8_t in[700], one[500], got[500];
  size_t i, step, at;
  unsigned b;
  for (i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 7 + 3);
  for (b = 128; b <= 256; b += 128) {
    nqtshk(b, in, sizeof in, 0x1f, one, sizeof one);
    for (step = 1; step <= 173; step += (step < 9 ? 1 : 41)) {
      nqtsctx c;
      nqtsini(&c, b);
      for (at = 0; at < sizeof in; at += step)
        nqtsabs(&c, in + at, sizeof in - at < step ? sizeof in - at : step);
      nqtspad(&c, 0x1f);
      for (at = 0; at < sizeof got; at += step)
        nqtssqz(&c, got + at,
                sizeof got - at < step ? sizeof got - at : step);
      NQTEQM(got, one, sizeof one);
    }
    NQTEQI(nqkt(b, in, sizeof in, NULL, 0, one, 300), NQOK);
    NQTEQI(nqkt(b, in, sizeof in, NULL, 0, got, 17), NQOK);
    NQTEQM(got, one, 17);
  }
}

/* around the chunk boundaries: a tree of n chunks agrees with the final
 * node built by hand from the chaining values of the chunks */
static void ttree(void) {
  static const size_t len[] = {8190, 8191, 8192, 8193, 16382, 16383, 16384,
                               16385, 24576, 40000};
  size_t q, i;
  unsigned b;
  uint8_t *in = (uint8_t *)malloc(40000 + 2);
  NQTCHK(in != NULL);
  if (in == NULL) return;
  for (i = 0; i < 40002; i++) in[i] = (uint8_t)(i * 13 + (i >> 8));
  for (b = 128; b <= 256; b += 128) {
    size_t cv = b == 128 ? 32 : 64;
    for (q = 0; q < sizeof len / sizeof len[0]; q++) {
      /* S is the input and the byte 00, the length of no customization */
      size_t sl = len[q] + 1, n = (sl + 8191) / 8192, j;
      uint8_t got[64], want[64], v[64], tail[4];
      static const uint8_t mark[8] = {3, 0, 0, 0, 0, 0, 0, 0};
      nqtsctx c;
      in[len[q]] = 0;
      NQTEQI(nqkt(b, in, len[q], NULL, 0, got, 64), NQOK);
      nqtsini(&c, b);
      if (n == 1) {
        nqtsabs(&c, in, sl);
        nqtspad(&c, 0x07);
      } else {
        nqtsabs(&c, in, 8192);
        nqtsabs(&c, mark, 8);
        for (j = 1; j < n; j++) {
          size_t l = j + 1 < n ? 8192 : sl - 8192 * j;
          nqtshk(b, in + 8192 * j, l, 0x0b, v, cv);
          nqtsabs(&c, v, cv);
        }
        tail[0] = (uint8_t)(n - 1);
        tail[1] = 1;
        tail[2] = 0xff;
        tail[3] = 0xff;
        nqtsabs(&c, tail, 4);
        nqtspad(&c, 0x06);
      }
      nqtssqz(&c, want, 64);
      NQTEQM(got, want, 64);
      in[len[q]] = (uint8_t)(len[q] * 13 + (len[q] >> 8));
    }
  }
  /* the customization string is not the message: moving a byte from one
   * to the other changes the output */
  {
    uint8_t a[32], c2[32];
    NQTEQI(nqkt(128, in, 10, in + 10, 5, a, 32), NQOK);
    NQTEQI(nqkt(128, in, 11, in + 11, 4, c2, 32), NQOK);
    NQTCHK(memcmp(a, c2, 32) != 0);
    NQTEQI(nqkt(128, in, 15, NULL, 0, c2, 32), NQOK);
    NQTCHK(memcmp(a, c2, 32) != 0);
  }
  free(in);
}

static void terr(void) {
  uint8_t out[8], in[4] = {1, 2, 3, 4};
  NQTEQI(nqkt(128, in, 4, NULL, 0, out, 8), NQOK);
  NQTEQI(nqkt(256, NULL, 0, NULL, 0, out, 1), NQOK);
  NQTEQI(nqkt(192, in, 4, NULL, 0, out, 8), NQEARG);
  NQTEQI(nqkt(0, in, 4, NULL, 0, out, 8), NQEARG);
  NQTEQI(nqkt(128, in, 4, NULL, 0, NULL, 8), NQEARG);
  NQTEQI(nqkt(128, in, 4, NULL, 0, out, 0), NQEARG);
  NQTEQI(nqkt(128, NULL, 4, NULL, 0, out, 8), NQEARG);
  NQTEQI(nqkt(128, in, 4, NULL, 1, out, 8), NQEARG);
  {
    nqktctx c;
    NQTEQI(nqktini(NULL, 128), NQEARG);
    NQTEQI(nqktini(&c, 512), NQEARG);
    memset(&c, 0, sizeof c);
    NQTEQI(nqktupd(&c, in, 4), NQESTATE);
    NQTEQI(nqktfin(&c, NULL, 0, out, 8), NQESTATE);
    NQTEQI(nqktini(&c, 128), NQOK);
    NQTEQI(nqktupd(NULL, in, 4), NQEARG);
    NQTEQI(nqktupd(&c, NULL, 4), NQEARG);
    NQTEQI(nqktupd(&c, NULL, 0), NQOK);
    NQTEQI(nqktfin(&c, NULL, 1, out, 8), NQEARG);
    NQTEQI(nqktfin(&c, NULL, 0, NULL, 8), NQEARG);
    NQTEQI(nqktfin(&c, NULL, 0, out, 0), NQEARG);
    NQTEQI(nqktfin(NULL, NULL, 0, out, 8), NQEARG);
    NQTEQI(nqktfin(&c, NULL, 0, out, 8), NQOK);
    /* ended: neither more input nor a second output */
    NQTEQI(nqktupd(&c, in, 4), NQESTATE);
    NQTEQI(nqktfin(&c, NULL, 0, out, 8), NQESTATE);
  }
}

/* the input in pieces of every size, cut before, at and after every
 * chunk boundary, gives what the one call gives */
static void tstream(void) {
  static const size_t len[] = {0, 1, 8190, 8191, 8192, 8193, 16383, 16384,
                               16385, 30000};
  static const size_t step[] = {1, 7, 4096, 8191, 8192, 8193, 20000};
  static uint8_t in[30000];
  uint8_t one[64], got[64], cu[9000];
  size_t q, w, i, at;
  unsigned b;
  for (i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 31 + (i >> 9));
  for (i = 0; i < sizeof cu; i++) cu[i] = (uint8_t)(i + 5);
  for (b = 128; b <= 256; b += 128) {
    for (q = 0; q < sizeof len / sizeof len[0]; q++) {
      /* without a customization string, and with one that crosses a
       * chunk by itself */
      size_t cl = (q & 1) ? 8500 : 0;
      NQTEQI(nqkt(b, in, len[q], cl ? cu : NULL, cl, one, 64), NQOK);
      for (w = 0; w < sizeof step / sizeof step[0]; w++) {
        nqktctx c;
        if (step[w] == 1 && len[q] > 9000) continue;
        NQTEQI(nqktini(&c, b), NQOK);
        for (at = 0; at < len[q]; at += step[w])
          NQTEQI(nqktupd(&c, in + at,
                         len[q] - at < step[w] ? len[q] - at : step[w]),
                 NQOK);
        NQTEQI(nqktfin(&c, cl ? cu : NULL, cl, got, 64), NQOK);
        NQTEQM(got, one, 64);
      }
    }
  }
}

int main(void) {
  trfc();
  tparts();
  ttree();
  terr();
  tstream();
  return nqtdone("tkt");
}
