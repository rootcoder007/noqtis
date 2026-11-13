/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Bundles (noqtis-bundle-1): the reader's refusals, one by one, on
 * bundles made here in memory; a bundle cut at every byte; and nqdpack
 * and nqdunpack on the sample capsule (vectors/cap/sample): the same
 * bytes twice, a round trip that checks, refusals that leave nothing
 * behind, and the removal of what an unpack wrote. Run from tests/. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  const uint8_t *p;
  size_t n, at;
} mem;

static int mrd(void *u, uint8_t *b, size_t n, size_t *got) {
  mem *m = (mem *)u;
  size_t k = m->n - m->at < n ? m->n - m->at : n;
  memcpy(b, m->p + m->at, k);
  m->at += k;
  *got = k;
  return NQOK;
}

/* counts entries; fails at the entry named "stop" */
static int cput(void *s, int op, const char *path, uint64_t size,
                const uint8_t *b, size_t n) {
  (void)size;
  (void)b;
  (void)n;
  if (op == QDBBEG) {
    if (strcmp(path, "stop") == 0)
      return NQEIO;
    (*(int *)s)++;
  }
  return NQOK;
}

static uint8_t bb[1 << 16];
static size_t bn;

static void bmag(void) {
  memcpy(bb, "noqtis-bundle-1\n", 16);
  bn = 16;
}

/* an entry whose path is n bytes at p (n may hold a NUL) */
static void bentn(const char *p, size_t n, uint64_t size, const char *data) {
  int i;
  bb[bn++] = (uint8_t)(n >> 8);
  bb[bn++] = (uint8_t)n;
  memcpy(bb + bn, p, n);
  bn += n;
  for (i = 7; i >= 0; i--)
    bb[bn++] = (uint8_t)(size >> (8 * i));
  if (data != NULL) {
    memcpy(bb + bn, data, (size_t)size);
    bn += (size_t)size;
  }
}

static void bent(const char *p, uint64_t size, const char *data) {
  bentn(p, strlen(p), size, data);
}

static void bend(void) {
  bb[bn++] = 0;
  bb[bn++] = 0;
}

static int rd(int *cnt, char *why, size_t cap) {
  mem m;
  qdbio io;
  m.p = bb;
  m.n = bn;
  m.at = 0;
  io.rd = mrd;
  io.u = &m;
  io.put = cput;
  io.s = cnt;
  *cnt = 0;
  return qdbread(&io, why, cap);
}

/* a minimal good bundle, with path p (between noqtis.json and
 * noqtis.sig in order, or NULL) */
static void good(const char *p) {
  bmag();
  if (p != NULL && strcmp(p, "noqtis.json") < 0)
    bent(p, 1, "x");
  bent("noqtis.json", 2, "{}");
  if (p != NULL && strcmp(p, "noqtis.json") > 0 && strcmp(p, "noqtis.sig") < 0)
    bent(p, 1, "x");
  bent("noqtis.sig", 0, NULL);
  if (p != NULL && strcmp(p, "noqtis.sig") > 0)
    bent(p, 1, "x");
  bend();
}

static void reader(void) {
  static const char *const badp[] = {
      "/abs", "../x", "a/../b", "a\\b", "C:x", "c:/x", "a//b", "a/",
      ".", "a/./b", "x\x01y", "\xff", "a/\xc0\xaf", "x\x7f"};
  char why[600], deep[200], big[4200];
  int cnt, i;
  size_t k, full;
  /* the minimal bundle reads */
  good(NULL);
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  NQTEQI(cnt, 2);
  good("data/a.csv");
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  NQTEQI(cnt, 3);
  /* cut at every byte, and a byte after the end */
  full = bn;
  for (k = 0; k < full; k++) {
    bn = k;
    NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  }
  bn = full;
  bb[bn++] = 0;
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "after the end") != NULL);
  /* not a bundle */
  bn = 0;
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  bmag();
  bb[14] = '2';
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "noqtis-bundle-1") != NULL);
  /* no seal, no manifest */
  bmag();
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  bmag();
  bent("noqtis.json", 2, "{}");
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "noqtis.sig") != NULL);
  /* out of order, and twice */
  bmag();
  bent("noqtis.sig", 0, NULL);
  bent("noqtis.json", 2, "{}");
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "not after") != NULL);
  bmag();
  bent("noqtis.json", 2, "{}");
  bent("noqtis.json", 2, "{}");
  bent("noqtis.sig", 0, NULL);
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  /* a proper prefix sorts first; a byte above 0x7f after */
  good("noqtis.jso");
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  good("noqtis.sig\xc3\xa9");
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  /* paths a capsule cannot hold */
  for (i = 0; i < (int)(sizeof badp / sizeof badp[0]); i++) {
    good(badp[i]);
    NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  }
  bmag();
  bentn("a\0b", 3, 1, "x");
  bent("noqtis.json", 2, "{}");
  bent("noqtis.sig", 0, NULL);
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  /* 64 folders deep reads, 65 does not */
  for (k = 0; k < 64; k++) {
    deep[2 * k] = 'a';
    deep[2 * k + 1] = '/';
  }
  deep[128] = 'f';
  deep[129] = '\0';
  good(deep);
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  memmove(deep + 2, deep, 130);
  deep[0] = 'a';
  deep[1] = '/';
  good(deep);
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  /* a path of 4096 bytes reads, 4097 does not */
  memset(big, 'b', 4096);
  big[4096] = '\0';
  good(big);
  NQTEQI(rd(&cnt, why, sizeof why), NQOK);
  bmag();
  big[4096] = 'b';
  bentn(big, 4097, 0, NULL);
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQELIM);
  /* sizes: over 2^53 - 1, a seal over 1 MiB, a manifest over 512 MiB */
  bmag();
  bent("a", (uint64_t)1 << 53, NULL);
  NQTEQI(rd(&cnt, why, sizeof why), NQELIM);
  bmag();
  bent("noqtis.json", 2, "{}");
  bent("noqtis.sig", ((uint64_t)1 << 20) + 1, NULL);
  NQTEQI(rd(&cnt, why, sizeof why), NQELIM);
  bmag();
  bent("noqtis.json", ((uint64_t)512 << 20) + 1, NULL);
  NQTEQI(rd(&cnt, why, sizeof why), NQELIM);
  /* a size larger than what follows */
  bmag();
  bent("a", 100, NULL);
  bend();
  NQTEQI(rd(&cnt, why, sizeof why), NQEDEC);
  /* the output's refusal stops the reader with its code */
  good("stop");
  NQTEQI(rd(&cnt, why, sizeof why), NQEIO);
}

static char tmp[400];

static const char *at(const char *name) {
  static char p[4][600];
  static int k = 0;
  k = (k + 1) % 4;
  qdwhy(p[k], sizeof p[k], "%s/%s", tmp, name);
  return p[k];
}

/* 1 when the folder p is not there (it can be made, and is removed) */
static int gone(const char *p) {
  return qdmkdir(p) == NQOK && qdrm(p, 1) == NQOK;
}

static void files(void) {
  char why[600], *a, *b;
  size_t an, bn2;
  nqrep *r = NULL;
  /* the same bytes twice */
  NQTEQI(nqdpack("vectors/cap/sample", 1, at("s1.nqb")), NQOK);
  NQTEQI(nqdpack("vectors/cap/sample", 1, at("s2.nqb")), NQOK);
  NQTEQI(qdread(at("s1.nqb"), 1 << 20, &a, &an), NQOK);
  NQTEQI(qdread(at("s2.nqb"), 1 << 20, &b, &bn2), NQOK);
  NQTCHK(an == bn2 && memcmp(a, b, an) == 0);
  NQTCHK(an > 16 && memcmp(a, "noqtis-bundle-1\n", 16) == 0);
  qdfree(b);
  /* never over a file, nor without a record when the files stay out,
   * nor from a folder that is not a capsule */
  NQTEQI(nqdpack("vectors/cap/sample", 1, at("s1.nqb")), NQEIO);
  NQTEQI(nqdpack("vectors/cap/sample", 0, at("s3.nqb")), NQEARG);
  NQTCHK(qdfopen(at("s3.nqb"), "rb") == NULL);
  NQTCHK(nqdpack("vectors/nqd", 1, at("s3.nqb")) != NQOK);
  NQTCHK(qdfopen(at("s3.nqb"), "rb") == NULL);
  NQTEQI(nqdpack("vectors/cap/sample", 2, at("s3.nqb")), NQEARG);
  /* the round trip checks */
  NQTEQI(nqdunpack(at("s1.nqb"), at("out"), 0, why, sizeof why), NQOK);
  NQTEQI(nqchk(at("out"), NULL, 0, &r), NQOK);
  nqrepfree(r);
  /* never into a folder that is there */
  NQTEQI(nqdunpack(at("s1.nqb"), at("out"), 0, why, sizeof why), NQEIO);
  NQTCHK(strstr(why, "must not exist") != NULL);
  /* the removal takes everything, and the folder */
  NQTEQI(nqdunpack(at("s1.nqb"), at("out"), 1, why, sizeof why), NQOK);
  NQTCHK(gone(at("out")));
  NQTEQI(nqdunpack(at("s1.nqb"), at("out"), 2, why, sizeof why), NQEARG);
  NQTEQI(nqdunpack(at("none.nqb"), at("out"), 0, why, sizeof why), NQEIO);
  NQTCHK(gone(at("out")));
  /* a cut bundle leaves nothing behind */
  NQTEQI(qdwrite(at("cut.nqb"), a, an - 1), NQOK);
  NQTEQI(nqdunpack(at("cut.nqb"), at("out"), 0, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "end mark") != NULL);
  NQTCHK(gone(at("out")));
  /* nor does a file where a folder goes ("a" then "a/b") */
  good(NULL);
  bn -= 2;
  bent("x", 1, "1");
  bent("x/y", 1, "2");
  bend();
  NQTEQI(qdwrite(at("clash.nqb"), (const char *)bb, bn), NQOK);
  NQTEQI(nqdunpack(at("clash.nqb"), at("out"), 0, why, sizeof why), NQEIO);
  NQTCHK(strstr(why, "x/y") != NULL);
  NQTCHK(gone(at("out")));
  qdfree(a);
  /* tidy */
  qdrm(at("s1.nqb"), 0);
  qdrm(at("s2.nqb"), 0);
  qdrm(at("cut.nqb"), 0);
  qdrm(at("clash.nqb"), 0);
  qdrm(tmp, 1);
}

int main(void) {
  const char *t = getenv("TMPDIR");
  uint8_t r[8];
  char hx[17];
  reader();
  if (t == NULL || *t == '\0' || strlen(t) > 300)
    t = "/tmp";
#ifdef _WIN32
  if (getenv("TEMP") != NULL && strlen(getenv("TEMP")) <= 300)
    t = getenv("TEMP");
#endif
  NQTEQI(nqrand(r, sizeof r), NQOK);
  qdhex(r, sizeof r, hx);
  qdwhy(tmp, sizeof tmp, "%s/tdbnd%s", t, hx);
  NQTEQI(qdmkdir(tmp), NQOK);
  files();
  return nqtdone("tdbnd");
}
