/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Chunk digests (nqdchunk, nqdpiece, the "chunks" member): the digests
 * against SHA-256 of each run of bytes computed here, the element's
 * refusals, pieces that check and pieces that do not, and nqdchk on the
 * whole file. Writes in a folder of its own under $TMPDIR. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

static char tmp[400];
static uint8_t data[5000];

static const char *at(const char *name) {
  static char p[4][600];
  static int k = 0;
  k = (k + 1) % 4;
  qdwhy(p[k], sizeof p[k], "%s/%s", tmp, name);
  return p[k];
}

static int rows(nqdrep *r, const char *text) {
  size_t i;
  for (i = 0; i < nqdrepn(r); i++) {
    const char *d = NULL;
    nqdrepi(r, i, NULL, NULL, &d);
    if (d != NULL && strstr(d, text) != NULL)
      return 1;
  }
  return 0;
}

static void elem(void) {
  char out[8192], why[600], hx[65];
  uint8_t h[32];
  size_t n = 0, i;
  nqdrec *r = NULL;
  /* the digests are SHA-256 of each 1024 bytes, the last 904 */
  NQTEQI(nqdchunk(tmp, "big.bin", 1024, out, sizeof out, &n, why,
                  sizeof why), NQOK);
  NQTCHK(strncmp(out, "{\"chunk\":1024,\"digests\":[", 25) == 0);
  NQTCHK(strstr(out, "\"path\":\"big.bin\",\"size\":5000}") != NULL);
  for (i = 0; i < 5; i++) {
    size_t k = i < 4 ? 1024 : 904;
    NQTEQI(nqhash(NQS256, data + 1024 * i, k, h, 32), NQOK);
    qdhex(h, 32, hx);
    NQTCHK(strstr(out, hx) != NULL);
  }
  /* sizing, as the other element writers */
  NQTEQI(nqdchunk(tmp, "big.bin", 1024, NULL, 0, &i, why, sizeof why),
         NQEBUF);
  NQTEQI(i, n);
  /* a run of exactly two chunks, and an empty file */
  NQTEQI(nqdchunk(tmp, "two.bin", 1024, out, sizeof out, &n, why,
                  sizeof why), NQOK);
  NQTCHK(strstr(out, "\"size\":2048") != NULL);
  NQTCHK(strchr(strchr(out, '[') + 66, ']') == strchr(out, '[') + 134);
  NQTEQI(nqdchunk(tmp, "empty", 1024, out, sizeof out, &n, why, sizeof why),
         NQOK);
  NQTCHK(strstr(out, "\"digests\":[]") != NULL);
  /* refusals */
  NQTEQI(nqdchunk(tmp, "big.bin", 1023, out, sizeof out, &n, why,
                  sizeof why), NQEARG);
  NQTEQI(nqdchunk(tmp, "big.bin", ((uint64_t)1 << 30) + 1, out, sizeof out,
                  &n, why, sizeof why), NQEARG);
  NQTEQI(nqdchunk(tmp, "../big.bin", 1024, out, sizeof out, &n, why,
                  sizeof why), NQEARG);
  NQTEQI(nqdchunk(tmp, "none", 1024, out, sizeof out, &n, why, sizeof why),
         NQEIO);
  /* the member's own checks */
  NQTEQI(nqdnew(&r), NQOK);
  NQTEQI(nqdchunk(tmp, "big.bin", 1024, out, sizeof out, &n, why,
                  sizeof why), NQOK);
  NQTEQI(nqdput(r, "chunks", out, n, why, sizeof why), NQOK);
  NQTEQI(nqdlen(r, "chunks"), 1);
  {
    static const char *const bad[] = {
        /* one digest short, one too many */
        "{\"chunk\":1024,\"digests\":[],\"path\":\"a\",\"size\":1}",
        "{\"chunk\":1024,\"digests\":[\"" "0000000000000000000000000000000"
        "000000000000000000000000000000000\"],\"path\":\"a\",\"size\":0}",
        /* a chunk out of bounds */
        "{\"chunk\":1000,\"digests\":[],\"path\":\"a\",\"size\":0}",
        "{\"chunk\":1073741825,\"digests\":[],\"path\":\"a\",\"size\":0}",
        /* not a digest */
        "{\"chunk\":1024,\"digests\":[\"00\"],\"path\":\"a\",\"size\":1}",
        "{\"chunk\":1024,\"digests\":[\"" "0000000000000000000000000000000"
        "00000000000000000000000000000000A\"],\"path\":\"a\",\"size\":1}",
        /* missing members, an unknown one, a noqtis file */
        "{\"chunk\":1024,\"path\":\"a\",\"size\":0}",
        "{\"chunk\":1024,\"digests\":[],\"path\":\"a\"}",
        "{\"chunk\":1024,\"digests\":[],\"path\":\"a\",\"size\":0,\"x\":1}",
        "{\"chunk\":1024,\"digests\":[],\"path\":\"noqtis.json\",\"size\":0}"};
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
      NQTEQI(nqdput(r, "chunks", bad[i], strlen(bad[i]), why, sizeof why),
             NQEDEC);
  }
  NQTEQI(nqdsave(r, tmp), NQOK);
  nqdrfree(r);
}

static void piece(void) {
  char e[8192], why[600];
  size_t n = 0;
  nqdrep *r = NULL;
  NQTEQI(nqdchunk(tmp, "big.bin", 1024, e, sizeof e, &n, why, sizeof why),
         NQOK);
  /* the whole file */
  NQTEQI(nqdpiece(e, n, at("big.bin"), 0, &r), NQOK);
  NQTCHK(rows(r, "chunks 0 to 4 of 5 match (bytes 0 to 4999)"));
  nqdrepfree(r);
  /* chunks 2 and 3, alone */
  NQTEQI(qdwrite(at("p23"), (const char *)data + 2048, 2048), NQOK);
  NQTEQI(nqdpiece(e, n, at("p23"), 2048, &r), NQOK);
  NQTCHK(rows(r, "chunks 2 to 3 of 5 match (bytes 2048 to 4095)"));
  nqdrepfree(r);
  /* said to start elsewhere: both differ */
  NQTEQI(nqdpiece(e, n, at("p23"), 1024, &r), NQEVRFY);
  NQTCHK(rows(r, "chunk 1 (bytes 1024 to 2047) differs"));
  NQTCHK(rows(r, "chunk 2 (bytes 2048 to 3071) differs"));
  nqdrepfree(r);
  /* not where a chunk starts; past the end */
  NQTEQI(nqdpiece(e, n, at("p23"), 100, &r), NQEVRFY);
  NQTCHK(rows(r, "not where a chunk starts"));
  nqdrepfree(r);
  NQTEQI(nqdpiece(e, n, at("p23"), 5120, &r), NQEVRFY);
  nqdrepfree(r);
  NQTEQI(nqdpiece(e, n, at("p23"), 4096, &r), NQEVRFY);
  NQTCHK(rows(r, "runs past the 5000 bytes recorded"));
  nqdrepfree(r);
  /* the file's short last chunk, alone; a short run before the end is
   * not checked, and says so */
  NQTEQI(qdwrite(at("p4"), (const char *)data + 4096, 904), NQOK);
  NQTEQI(nqdpiece(e, n, at("p4"), 4096, &r), NQOK);
  nqdrepfree(r);
  NQTEQI(qdwrite(at("p1x"), (const char *)data + 1024, 1500), NQOK);
  NQTEQI(nqdpiece(e, n, at("p1x"), 1024, &r), NQOK);
  NQTCHK(rows(r, "last 476 bytes are not a whole chunk"));
  NQTCHK(rows(r, "chunks 1 to 1 of 5 match"));
  nqdrepfree(r);
  /* less than a chunk; nothing; a changed byte */
  NQTEQI(qdwrite(at("p0"), (const char *)data, 10), NQOK);
  NQTEQI(nqdpiece(e, n, at("p0"), 0, &r), NQEVRFY);
  NQTCHK(rows(r, "no whole chunk"));
  nqdrepfree(r);
  NQTEQI(nqdpiece(e, n, at("none"), 0, &r), NQEVRFY);
  nqdrepfree(r);
  data[3000] ^= 1;
  NQTEQI(qdwrite(at("p23"), (const char *)data + 2048, 2048), NQOK);
  data[3000] ^= 1;
  NQTEQI(nqdpiece(e, n, at("p23"), 2048, &r), NQEVRFY);
  NQTCHK(rows(r, "chunk 2 (bytes 2048 to 3071) differs"));
  NQTCHK(!rows(r, "chunk 3"));
  nqdrepfree(r);
  /* not an element */
  NQTEQI(nqdpiece("{}", 2, at("p23"), 0, &r), NQEVRFY);
  NQTCHK(rows(r, "the chunks element"));
  nqdrepfree(r);
  NQTEQI(nqdpiece(NULL, 0, at("p23"), 0, &r), NQEARG);
  /* nqdchk: the whole file, at its recorded size */
  NQTEQI(nqdchk(tmp, &r), NQOK);
  NQTCHK(rows(r, "chunks 0 to 4 of 5 match"));
  nqdrepfree(r);
  NQTEQI(qdwrite(at("big.bin"), (const char *)data, 4096), NQOK);
  NQTEQI(nqdchk(tmp, &r), NQEVRFY);
  NQTCHK(rows(r, "4096 bytes, the record says 5000"));
  nqdrepfree(r);
}

int main(void) {
  static const char *const made[] = {"big.bin", "two.bin", "empty", "p23",
                                     "p4", "p1x", "p0", NQDFILE};
  const char *t = getenv("TMPDIR");
  uint8_t r[8];
  char hx[17];
  size_t i;
  if (t == NULL || *t == '\0' || strlen(t) > 300)
    t = "/tmp";
#ifdef _WIN32
  if (getenv("TEMP") != NULL && strlen(getenv("TEMP")) <= 300)
    t = getenv("TEMP");
#endif
  NQTEQI(nqrand(r, sizeof r), NQOK);
  qdhex(r, sizeof r, hx);
  qdwhy(tmp, sizeof tmp, "%s/tdcnk%s", t, hx);
  NQTEQI(qdmkdir(tmp), NQOK);
  for (i = 0; i < sizeof data; i++)
    data[i] = (uint8_t)(i * 7 + (i >> 8));
  NQTEQI(qdwrite(at("big.bin"), (const char *)data, sizeof data), NQOK);
  NQTEQI(qdwrite(at("two.bin"), (const char *)data, 2048), NQOK);
  NQTEQI(qdwrite(at("empty"), "", 0), NQOK);
  elem();
  piece();
  for (i = 0; i < sizeof made / sizeof made[0]; i++)
    qdrm(at(made[i]), 0);
  qdrm(tmp, 1);
  return nqtdone("tdcnk");
}
