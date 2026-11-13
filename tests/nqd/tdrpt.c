/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Reports (nqdrpt) of vectors/nqd/cap, which is not sealed: the counts,
 * a folder not sealed failing, the record's values in Markdown (escaped
 * once) and in text, the buffer protocol and the refusals. The tool's
 * reports of sealed folders, with values that hold '|' and line
 * breaks, are in cli.sh. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

static char *rpt(const char *dir, int fmt) {
  size_t n = 0, m = 0;
  char *b;
  if (nqdrpt(dir, NULL, NULL, fmt, NULL, 0, &n) != NQEBUF)
    return NULL;
  if ((b = (char *)malloc(n + 1)) == NULL)
    return NULL;
  if (nqdrpt(dir, NULL, NULL, fmt, b, n + 1, &m) != NQOK || m != n ||
      strlen(b) != n) {
    free(b);
    return NULL;
  }
  return b;
}

#define HAS(b, s)                                                           \
  do {                                                                      \
    int h_ = (b) != NULL && strstr((b), (s)) != NULL;                       \
    if (!h_)                                                                \
      fprintf(stderr, "report lacks [%s]\n", (s));                          \
    NQTCHK(h_);                                                             \
  } while (0)

int main(void) {
  char *m = rpt("vectors/nqd/cap", NQDMD), *t = rpt("vectors/nqd/cap",
                                                    NQDTXT);
  char small[8];
  size_t n = 0;
  nqdrep *dr = NULL;
  NQTCHK(m != NULL && t != NULL);
  /* the record, two sources and no seal: four checks, one failed */
  HAS(m, "# noqtis report: vectors/nqd/cap\n\n**Failed**: 1 of 4 checks "
         "failed (not sealed)\n");
  HAS(m, "\n## Capsule\n\nNot sealed: no `noqtis.sig`");
  HAS(m, "| path | size | sha256 | url | publisher | licence | retrieved | "
         "synthetic |\n|---|---|---|---|---|---|---|---|\n");
  HAS(m, "| data/a.csv | 89 | 7a1668480cde19db0b76c7a36e6fee9a82afd9937f5d0"
         "3cec3dae1705ce173e2 | https://example.org/a.csv | City of Example | "
         "OGL-Canada-2.0 | 2026-01-01T00:00:00Z |  |\n");
  HAS(m, "| data/b.csv | 6 |");
  HAS(m, "|  | true |\n");
  /* the brackets of [synthetic] are Markdown: escaped, once */
  HAS(m, "| ok | data.source | data/b.csv \\[synthetic\\]: SHA-256 and size "
         "match |\n");
  NQTCHK(m == NULL || strstr(m, "\\\\[") == NULL);
  HAS(t, "noqtis report: vectors/nqd/cap\nFailed: 1 of 4 checks failed "
         "(not sealed)\n");
  HAS(t, "  FAIL  seal  not sealed: no noqtis.sig\n");
  HAS(t, "    ok  data.source  data/b.csv [synthetic]: SHA-256 and size "
         "match\n");
  HAS(t, "    data/b.csv  6  aea2");
  /* a folder with no record: no data rows */
  free(m);
  m = rpt("vectors/nqd/drift", NQDMD);
  HAS(m, "**Failed**: 1 of 1 check failed (not sealed)\n");
  HAS(m, "No data record (`noqtis.data.json`).");
  free(m);
  free(t);
  /* the rows given are the rows reported */
  NQTEQI(nqdchk("vectors/nqd/cap", &dr), NQOK);
  m = NULL;
  n = 0;
  NQTEQI(nqdrpt("vectors/nqd/cap", NULL, dr, NQDTXT, NULL, 0, &n), NQEBUF);
  if ((m = (char *)malloc(n + 1)) != NULL) {
    NQTEQI(nqdrpt("vectors/nqd/cap", NULL, dr, NQDTXT, m, n + 1, &n), NQOK);
    HAS(m, "Failed: 1 of 4 checks failed");
  }
  free(m);
  nqdrepfree(dr);
  /* too small a buffer: NQEBUF and the length, the buffer NUL-ended */
  NQTEQI(nqdrpt("vectors/nqd/cap", NULL, NULL, NQDMD, small, sizeof small,
                &n),
         NQEBUF);
  NQTCHK(n > sizeof small);
  NQTEQI(nqdrpt("vectors/nqd/cap", NULL, NULL, 3, NULL, 0, &n), NQEARG);
  NQTEQI(nqdrpt(NULL, NULL, NULL, NQDMD, NULL, 0, &n), NQEARG);
  return nqtdone("tdrpt");
}
