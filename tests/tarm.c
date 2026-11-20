/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ASCII armor (nqarmlen, nqarmenc, nqarmdec): every length from nothing
 * to four lines there and back, the exact text of a small one, line
 * ends and spaces a reader meets, and what is refused: another label at
 * the end, a label that is not one, text around the armor, a group cut
 * short, padding in the middle, bits under the padding, a buffer too
 * small, NULL pointers. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

static void tround(void) {
  uint8_t in[200], back[200];
  char txt[512], lab[NQARMLAB];
  size_t n, len, got, k, i;
  for (i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 7 + 3);
  for (n = 0; n <= sizeof in; n++) {
    NQTEQI(nqarmlen("NOQTIS SIGNATURE", n, &len), NQOK);
    NQTCHK(len <= sizeof txt);
    NQTEQI(nqarmenc("NOQTIS SIGNATURE", in, n, txt, sizeof txt, &got), NQOK);
    NQTCHK(got == len);
    /* no line over 64 characters, the last one ended */
    for (i = 0, k = 0; i < got; i++) {
      k = txt[i] == '\n' ? 0 : k + 1;
      NQTCHK(k <= 64);
    }
    NQTCHK(txt[got - 1] == '\n');
    memset(back, 0xee, sizeof back);
    NQTEQI(nqarmdec(txt, got, lab, sizeof lab, back, sizeof back, &k), NQOK);
    NQTCHK(k == n);
    NQTEQM(back, in, n);
    NQTCHK(strcmp(lab, "NOQTIS SIGNATURE") == 0);
    /* exactly the buffer it needs, and one byte less */
    NQTEQI(nqarmenc("NOQTIS SIGNATURE", in, n, txt, len, &got), NQOK);
    NQTEQI(nqarmenc("NOQTIS SIGNATURE", in, n, txt, len - 1, &got), NQEBUF);
    NQTEQI(nqarmdec(txt, len, NULL, 0, back, n, &k), NQOK);
    if (n > 0) {
      NQTEQI(nqarmdec(txt, len, NULL, 0, back, n - 1, &k), NQEBUF);
      NQTEQI(nqarmdec(txt, len, NULL, 0, NULL, 0, &k), NQEBUF);
    }
  }
}

static void ttext(void) {
  static const char want[] =
      "-----BEGIN X-----\naGVsbG8=\n-----END X-----\n";
  static const char crlf[] =
      "\r\n  -----BEGIN X----- \t\r\naGVs\r\n\r\n bG8= \r\n-----END X-----\r\n\n ";
  static const char none[] = "-----BEGIN A 1-----\n-----END A 1-----\n";
  char txt[80], lab[NQARMLAB];
  uint8_t out[16];
  size_t got, k;
  NQTEQI(nqarmenc("X", (const uint8_t *)"hello", 5, txt, sizeof txt, &got),
         NQOK);
  NQTCHK(got == sizeof want - 1);
  NQTEQM(txt, want, got);
  NQTEQI(nqarmdec(crlf, sizeof crlf - 1, lab, sizeof lab, out, sizeof out,
                  &k),
         NQOK);
  NQTCHK(k == 5);
  NQTEQM(out, "hello", 5);
  NQTCHK(strcmp(lab, "X") == 0);
  NQTEQI(nqarmenc("A 1", NULL, 0, txt, sizeof txt, &got), NQOK);
  NQTCHK(got == sizeof none - 1);
  NQTEQM(txt, none, got);
  NQTEQI(nqarmdec(none, sizeof none - 1, lab, sizeof lab, out, 0, &k), NQOK);
  NQTCHK(k == 0);
  /* the label does not fit */
  NQTEQI(nqarmdec(none, sizeof none - 1, lab, 3, out, sizeof out, &k),
         NQEBUF);
  NQTEQI(nqarmdec(none, sizeof none - 1, lab, 4, out, sizeof out, &k), NQOK);
}

static void bad(const char *s) {
  uint8_t out[64];
  size_t k;
  NQTEQI(nqarmdec(s, strlen(s), NULL, 0, out, sizeof out, &k), NQEDEC);
}

static void trefuse(void) {
  char txt[80], lab[80];
  uint8_t out[16];
  size_t k, i;
  bad("");
  bad("   \n");
  bad("aGVsbG8=\n");
  bad("-----BEGIN X-----");
  bad("-----BEGIN X-----\n");
  bad("-----BEGIN X-----\naGVsbG8=\n");
  bad("-----BEGIN X-----\naGVsbG8=\n-----END Y-----\n");
  bad("-----BEGIN X-----\naGVsbG8=\n-----END XX-----\n");
  bad("-----BEGIN X-----\naGVsbG8=\n-----END X----\n");
  bad("-----BEGIN X-----\naGVsbG8=\n-----END X-----\nmore\n");
  bad("text\n-----BEGIN X-----\naGVsbG8=\n-----END X-----\n");
  bad("-----BEGIN X----- aGVsbG8=\n-----END X-----\n");
  bad("-----BEGIN X-----\naGVsbG8=-----END X-----\n");
  bad("-----BEGIN X-----\naGVsbG8\n-----END X-----\n");
  bad("-----BEGIN X-----\naGVs=bG8\n-----END X-----\n");
  bad("-----BEGIN X-----\naGVsbG8=\naGVs\n-----END X-----\n");
  bad("-----BEGIN X-----\naGVsbG9=\n-----END X-----\n");
  bad("-----BEGIN X-----\naGV$bG8=\n-----END X-----\n");
  bad("-----BEGIN X-----\nVersion: 1\n\naGVsbG8=\n-----END X-----\n");
  bad("-----BEGIN -----\n-----END -----\n");
  bad("-----BEGIN x-----\n-----END x-----\n");
  bad("-----BEGIN  X-----\n-----END  X-----\n");
  bad("-----BEGIN X -----\n-----END X -----\n");
  bad("-----BEGIN X  Y-----\n-----END X  Y-----\n");
  bad("-----BEGIN X\n-----\n-----END X\n-----\n");
  bad("----BEGIN X-----\n-----END X-----\n");
  bad("-----BEGIN X-----\n-----BEGIN X-----\n");
  /* a NUL inside */
  NQTEQI(nqarmdec("-----BEGIN X-----\n\0-----END X-----\n", 34, NULL, 0, out,
                  sizeof out, &k),
         NQEDEC);
  /* labels: the longest, one longer, and what is not one */
  memset(lab, 'A', sizeof lab);
  lab[NQARMLAB - 1] = '\0';
  NQTEQI(nqarmlen(lab, 0, &k), NQOK);
  lab[NQARMLAB - 1] = 'A';
  lab[NQARMLAB] = '\0';
  NQTEQI(nqarmlen(lab, 0, &k), NQEARG);
  NQTEQI(nqarmlen("", 0, &k), NQEARG);
  NQTEQI(nqarmlen(" X", 0, &k), NQEARG);
  NQTEQI(nqarmlen("X ", 0, &k), NQEARG);
  NQTEQI(nqarmlen("X  Y", 0, &k), NQEARG);
  NQTEQI(nqarmlen("x", 0, &k), NQEARG);
  NQTEQI(nqarmlen("X-Y", 0, &k), NQEARG);
  NQTEQI(nqarmlen("X\n", 0, &k), NQEARG);
  NQTEQI(nqarmlen("X", (size_t)-1, &k), NQELIM);
  NQTEQI(nqarmenc("x", out, 1, txt, sizeof txt, &k), NQEARG);
  NQTEQI(nqarmenc("X", out, (size_t)-1, txt, sizeof txt, &k), NQELIM);
  /* NULL pointers */
  NQTEQI(nqarmlen(NULL, 0, &k), NQEARG);
  NQTEQI(nqarmlen("X", 0, NULL), NQEARG);
  NQTEQI(nqarmenc("X", NULL, 1, txt, sizeof txt, &k), NQEARG);
  NQTEQI(nqarmenc("X", out, 1, NULL, 0, &k), NQEARG);
  NQTEQI(nqarmenc("X", out, 1, txt, sizeof txt, NULL), NQEARG);
  NQTEQI(nqarmdec(NULL, 0, NULL, 0, out, sizeof out, &k), NQEARG);
  NQTEQI(nqarmdec("x", 1, NULL, 0, NULL, 1, &k), NQEARG);
  NQTEQI(nqarmdec("x", 1, NULL, 1, out, sizeof out, &k), NQEARG);
  NQTEQI(nqarmdec("x", 1, NULL, 0, out, sizeof out, NULL), NQEARG);
  /* every cut of a good one is refused */
  NQTEQI(nqarmenc("X", (const uint8_t *)"hello", 5, txt, sizeof txt, &k),
         NQOK);
  for (i = 0; i + 1 < k; i++) {
    size_t g;
    NQTEQI(nqarmdec(txt, i, NULL, 0, out, sizeof out, &g), NQEDEC);
  }
}

int main(void) {
  tround();
  ttext();
  trefuse();
  return nqtdone("tarm");
}
