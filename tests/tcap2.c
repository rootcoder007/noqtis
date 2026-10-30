/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Capsule format 2 (noqtis-capsule-2, noqtis-seal-2): the Merkle tree
 * against an independent reference (every tree size to 40, every audit
 * path, tampered paths refused), a sealed folder that checks, a changed
 * file entry caught by the Merkle row while the head still matches, a
 * changed head caught by the digest, formats 1 and 2 not mixed, inputs
 * and their limits, and capsule ids. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "cap/cap.h"
#include "core/int.h"
#include "nqt.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#define NQTFS 1
#endif

/* ---- the Merkle tree against a plain reference ---- */

static void rnode(const uint8_t *l, const uint8_t *r, uint8_t *out) {
  uint8_t b[65];
  b[0] = 1;
  memcpy(b + 1, l, 32);
  memcpy(b + 33, r, 32);
  nqhash(NQS256, b, 65, out, 32);
}

/* RFC 6962's MTH, written as the RFC states it */
static void rmth(const uint8_t *lv, size_t n, uint8_t *out) {
  size_t k = 1;
  uint8_t a[32], b[32];
  if (n == 0) {
    nqhash(NQS256, NULL, 0, out, 32);
    return;
  }
  if (n == 1) {
    memcpy(out, lv, 32);
    return;
  }
  while (k * 2 < n) k *= 2;
  rmth(lv, k, a);
  rmth(lv + 32 * k, n - k, b);
  rnode(a, b, out);
}

static void tmerkle(void) {
  uint8_t lv[40 * 32], r1[32], r2[32], path[64 * 32];
  size_t n, m, len;
  char e[16];
  for (n = 0; n < 40; n++) {
    snprintf(e, sizeof e, "entry %u", (unsigned)n);
    nqcmleaf(e, strlen(e), lv + 32 * n);
  }
  /* a leaf is SHA-256 of 0x00 and the bytes */
  {
    uint8_t b[16], h[32];
    b[0] = 0;
    memcpy(b + 1, "entry 0", 7);
    nqhash(NQS256, b, 8, h, 32);
    NQTEQM(h, lv, 32);
  }
  for (n = 0; n <= 40; n++) {
    nqcmroot(lv, n, r1);
    rmth(lv, n, r2);
    NQTEQM(r1, r2, 32);
    for (m = 0; m < n; m++) {
      NQTEQI(nqcmpath(lv, n, m, path, 64, &len), NQOK);
      NQTCHK(nqcmvrfy(lv + 32 * m, m, n, path, len, r1));
      /* another leaf, index, size or sibling does not verify */
      NQTCHK(!nqcmvrfy(lv + 32 * ((m + 1) % 40), m, n, path, len, r1) ||
             n == 1);
      if (n > 1) {
        NQTCHK(!nqcmvrfy(lv + 32 * m, (m + 1) % n, n, path, len, r1));
        /* (a path does not fix the tree size by itself: format 2 signs the
         * leaf count in the head, and nqchkp checks with that count) */
        {
          uint8_t r3[32];
          memcpy(r3, r1, 32);
          r3[31] ^= 1;
          NQTCHK(!nqcmvrfy(lv + 32 * m, m, n, path, len, r3));
        }
        path[0] ^= 1;
        NQTCHK(!nqcmvrfy(lv + 32 * m, m, n, path, len, r1));
        path[0] ^= 1;
        NQTCHK(!nqcmvrfy(lv + 32 * m, m, n, path, len - 1, r1));
      }
    }
    NQTEQI(nqcmpath(lv, n, n, path, 64, &len), NQEARG);
  }
}

#ifdef NQTFS
static char root[300];

static void put(const char *d, const char *rel, const char *s) {
  char p[600];
  FILE *f;
  snprintf(p, sizeof p, "%s/%s", d, rel);
  f = fopen(p, "wb");
  NQTCHK(f != NULL);
  if (f == NULL) return;
  fputs(s, f);
  fclose(f);
}

static char *slurp(const char *d, const char *rel, size_t *n) {
  char p[600], *b;
  FILE *f;
  long l;
  snprintf(p, sizeof p, "%s/%s", d, rel);
  f = fopen(p, "rb");
  if (f == NULL) return NULL;
  fseek(f, 0, SEEK_END);
  l = ftell(f);
  fseek(f, 0, SEEK_SET);
  b = (char *)malloc((size_t)l + 1);
  if (b != NULL && fread(b, 1, (size_t)l, f) != (size_t)l) {
    free(b);
    b = NULL;
  }
  fclose(f);
  if (b != NULL) {
    b[l] = 0;
    *n = (size_t)l;
  }
  return b;
}

/* replaces the first a with b in d/rel */
static int sub(const char *d, const char *rel, const char *a,
               const char *b) {
  size_t n = 0;
  char *s = slurp(d, rel, &n), *at, p[600];
  FILE *f;
  if (s == NULL || (at = strstr(s, a)) == NULL) {
    free(s);
    return 0;
  }
  snprintf(p, sizeof p, "%s/%s", d, rel);
  f = fopen(p, "wb");
  if (f == NULL) {
    free(s);
    return 0;
  }
  fwrite(s, 1, (size_t)(at - s), f);
  fputs(b, f);
  fputs(at + strlen(a), f);
  fclose(f);
  free(s);
  return 1;
}

/* the ok of the first row named chk, -1 when there is none */
static int row(const nqrep *r, const char *chk) {
  size_t i;
  for (i = 0; i < nqrepn(r); i++) {
    const char *c;
    int ok;
    nqrepi(r, i, &c, &ok, NULL);
    if (strcmp(c, chk) == 0) return ok;
  }
  return -1;
}

static void mk(char *d, size_t cap, const char *name) {
  snprintf(d, cap, "%s/%s", root, name);
  NQTEQI(mkdir(d, 0700), 0);
  put(d, "a.txt", "alpha\n");
  put(d, "b.csv", "x,y\n1,2\n");
  {
    char s[400];
    snprintf(s, sizeof s, "%s/sub", d);
    NQTEQI(mkdir(s, 0700), 0);
  }
  put(d, "sub/c.bin", "gamma");
}

static void rmall(const char *d) {
  static const char *const f[] = {"a.txt", "b.csv", "sub/c.bin",
                                  "noqtis.json", "noqtis.sig"};
  char p[600];
  size_t i;
  for (i = 0; i < 5; i++) {
    snprintf(p, sizeof p, "%s/%s", d, f[i]);
    remove(p);
  }
  snprintf(p, sizeof p, "%s/sub", d);
  rmdir(p);
  rmdir(d);
}

static uint8_t pk[1312], sk[2560];
static const uint8_t rnd[32];

static int seal(const char *d, int ver, const nqcin *in, size_t nin) {
  return nqcsealx(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk,
                  "{\"study\":\"s1\"}", NULL, 1793210645, rnd, sizeof rnd,
                  ver, in, nin, NULL);
}

static void tseal(void) {
  char d[400], *m;
  size_t n = 0;
  nqrep *r = NULL;
  uint8_t id[32], h[32];
  mk(d, sizeof d, "v2");
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQOK);
  NQTEQI(row(r, "manifest.merkle"), 1);
  NQTEQI(row(r, "manifest.digest"), 1);
  NQTEQI(row(r, "signature"), 1);
  nqrepfree(r);
  m = slurp(d, "noqtis.json", &n);
  NQTCHK(m != NULL && strstr(m, "\"format\":\"noqtis-capsule-2\"") != NULL &&
         strstr(m, "\"merkle\":{\"alg\":\"sha256\",\"leaves\":3,") != NULL);
  free(m);
  m = slurp(d, "noqtis.sig", &n);
  NQTCHK(m != NULL && strstr(m, "\"format\":\"noqtis-seal-2\"") != NULL &&
         strstr(m, "\"head_sha256\"") != NULL &&
         strstr(m, "\"context\":\"noqtis-capsule-2\"") != NULL);
  free(m);
  /* the id is the SHA-256 of the head: the manifest without its files */
  NQTEQI(nqcapid(d, id), NQOK);
  m = slurp(d, "noqtis.json", &n);
  if (m != NULL) {
    char *f = strstr(m, "\"files\":["), *e = strstr(m, "\"format\":");
    char *hd = (char *)malloc(n + 1);
    size_t hn = 0;
    NQTCHK(f != NULL && e != NULL && hd != NULL);
    if (f != NULL && e != NULL && hd != NULL) {
      memcpy(hd, m, (size_t)(f - m));
      hn = (size_t)(f - m);
      memcpy(hd + hn, e, n - (size_t)(e - m));
      hn += n - (size_t)(e - m);
      nqhash(NQS256, (const uint8_t *)hd, hn, h, 32);
      NQTEQM(id, h, 32);
    }
    free(hd);
    free(m);
  }
  /* inspect says format 2 */
  NQTEQI(nqinsp(d, &r), NQOK);
  NQTEQI(row(r, "info.format"), 1);
  {
    size_t i;
    for (i = 0; i < nqrepn(r); i++) {
      const char *c, *dt;
      nqrepi(r, i, &c, NULL, &dt);
      if (strcmp(c, "info.format") == 0) {
        NQTCHK(strcmp(dt, "noqtis-capsule-2") == 0);
      }
    }
  }
  nqrepfree(r);

  /* a file entry changed: the head (and so the signature) still match,
   * the Merkle root does not */
  NQTCHK(sub(d, "noqtis.json", "\"size\":6", "\"size\":7"));
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.digest"), 1);
  NQTEQI(row(r, "signature"), 1);
  NQTEQI(row(r, "manifest.merkle"), 0);
  nqrepfree(r);
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  /* the head changed: the digest fails */
  NQTCHK(sub(d, "noqtis.json", "\"s1\"", "\"s2\""));
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.digest"), 0);
  nqrepfree(r);
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  /* the leaf count changed */
  NQTCHK(sub(d, "noqtis.json", "\"leaves\":3", "\"leaves\":4"));
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.digest"), 0);
  nqrepfree(r);
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  /* a file changed on disk: its row fails as in format 1 */
  put(d, "a.txt", "alpha!\n");
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "file"), 0);
  nqrepfree(r);
  put(d, "a.txt", "alpha\n");
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  /* the format 1 seal context on a format 2 seal */
  NQTCHK(sub(d, "noqtis.sig", "\"context\":\"noqtis-capsule-2\"",
             "\"context\":\"noqtis-capsule-1\""));
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "seal.context"), 0);
  nqrepfree(r);
  /* a format 1 seal over a format 2 manifest, and the reverse */
  {
    char d1[400];
    size_t n1 = 0, n2 = 0;
    char *s1, *j2;
    mk(d1, sizeof d1, "v1");
    NQTEQI(seal(d1, 1, NULL, 0), NQOK);
    NQTEQI(seal(d, 2, NULL, 0), NQOK);
    s1 = slurp(d1, "noqtis.sig", &n1);
    j2 = slurp(d, "noqtis.json", &n2);
    NQTCHK(s1 != NULL && j2 != NULL);
    if (s1 != NULL && j2 != NULL) {
      FILE *f;
      char p[600];
      snprintf(p, sizeof p, "%s/noqtis.json", d1);
      f = fopen(p, "wb");
      if (f != NULL) {
        fwrite(j2, 1, n2, f);
        fclose(f);
      }
      NQTEQI(nqchk(d1, pk, sizeof pk, &r), NQEVRFY);
      NQTCHK(row(r, "manifest.digest") == 0);
      nqrepfree(r);
    }
    free(s1);
    free(j2);
    rmall(d1);
  }
  rmall(d);
}

static void tinputs(void) {
  char da[400], db[400], *m, name[300];
  size_t n = 0, i;
  nqrep *r = NULL;
  nqcin in[2], many[NQCINMAX + 1];
  mk(da, sizeof da, "ina");
  NQTEQI(seal(da, 1, NULL, 0), NQOK);
  mk(db, sizeof db, "inb");
  NQTEQI(nqcapid(da, in[0].id), NQOK);
  in[0].name = "raw data";
  /* the format 1 id is manifest_sha256 */
  {
    uint8_t h[32];
    m = slurp(da, "noqtis.json", &n);
    NQTCHK(m != NULL);
    if (m != NULL) {
      nqhash(NQS256, (const uint8_t *)m, n, h, 32);
      NQTEQM(h, in[0].id, 32);
      free(m);
    }
  }
  NQTEQI(seal(db, 2, in, 1), NQOK);
  NQTEQI(nqchk(db, pk, sizeof pk, &r), NQOK);
  nqrepfree(r);
  m = slurp(db, "noqtis.json", &n);
  NQTCHK(m != NULL && strstr(m, "\"inputs\":[{\"capsule\":\"") != NULL &&
         strstr(m, "\"name\":\"raw data\"}]") != NULL);
  free(m);
  /* an input's name: not empty, not over 255 bytes, no control
   * character, valid UTF-8 */
  in[1] = in[0];
  in[1].name = "";
  NQTEQI(seal(db, 2, in + 1, 1), NQEARG);
  in[1].name = "tab\there";
  NQTEQI(seal(db, 2, in + 1, 1), NQEARG);
  in[1].name = "\xff";
  NQTEQI(seal(db, 2, in + 1, 1), NQEARG);
  memset(name, 'n', 256);
  name[256] = 0;
  in[1].name = name;
  NQTEQI(seal(db, 2, in + 1, 1), NQEARG);
  name[255] = 0;
  NQTEQI(seal(db, 2, in + 1, 1), NQOK);
  /* inputs need format 2; at most 1024 */
  NQTEQI(seal(db, 1, in, 1), NQEARG);
  for (i = 0; i <= NQCINMAX; i++) many[i] = in[0];
  NQTEQI(seal(db, 2, many, NQCINMAX + 1), NQELIM);
  NQTEQI(seal(db, 2, many, NQCINMAX), NQOK);
  NQTEQI(nqchk(db, pk, sizeof pk, &r), NQOK);
  nqrepfree(r);
  /* an edited input is refused (the head changes) */
  NQTEQI(seal(db, 2, in, 1), NQOK);
  NQTCHK(sub(db, "noqtis.json", "\"raw data\"", "\"raw dato\""));
  NQTEQI(nqchk(db, pk, sizeof pk, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.digest"), 0);
  nqrepfree(r);
  rmall(da);
  rmall(db);
}

static void tpartial(void) {
  char d[400];
  nqrep *r = NULL;
  nqcopt o;
  const char *one[1] = {"b.csv"}, *two[2] = {"b.csv", "nope.txt"};
  mk(d, sizeof d, "part");
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  memset(&o, 0, sizeof o);
  o.trust = pk;
  o.trustlen = sizeof pk;
  o.only = one;
  o.nonly = 1;
  /* a changed file not asked about, and an extra file, are not seen */
  put(d, "a.txt", "changed\n");
  put(d, "extra.txt", "x");
  NQTEQI(nqchkx(d, &o, &r), NQOK);
  NQTEQI(row(r, "partial"), 1);
  NQTEQI(row(r, "file"), 1);
  NQTEQI(row(r, "extra"), -1);
  nqrepfree(r);
  /* the file asked about, changed, fails */
  put(d, "b.csv", "x,y\n1,3\n");
  NQTEQI(nqchkx(d, &o, &r), NQEVRFY);
  NQTEQI(row(r, "file"), 0);
  nqrepfree(r);
  put(d, "b.csv", "x,y\n1,2\n");
  /* a path not in the manifest fails */
  o.only = two;
  o.nonly = 2;
  NQTEQI(nqchkx(d, &o, &r), NQEVRFY);
  nqrepfree(r);
  /* format 1 too: the partial check needs no Merkle tree */
  put(d, "a.txt", "alpha\n");
  {
    char p[600];
    snprintf(p, sizeof p, "%s/extra.txt", d);
    remove(p);
  }
  NQTEQI(seal(d, 1, NULL, 0), NQOK);
  o.only = one;
  o.nonly = 1;
  NQTEQI(nqchkx(d, &o, &r), NQOK);
  nqrepfree(r);
  rmall(d);
}

static void tlineage(void) {
  char raw[400], cln[400], res[400];
  nqrep *r = NULL;
  nqcopt o;
  nqcin in;
  const char *lin[2];
  mk(raw, sizeof raw, "lraw");
  NQTEQI(seal(raw, 1, NULL, 0), NQOK);
  mk(cln, sizeof cln, "lclean");
  NQTEQI(nqcapid(raw, in.id), NQOK);
  in.name = "raw";
  NQTEQI(seal(cln, 2, &in, 1), NQOK);
  mk(res, sizeof res, "lres");
  NQTEQI(nqcapid(cln, in.id), NQOK);
  in.name = "clean";
  NQTEQI(seal(res, 2, &in, 1), NQOK);
  memset(&o, 0, sizeof o);
  o.trust = pk;
  o.trustlen = sizeof pk;
  lin[0] = cln;
  lin[1] = raw;
  o.lin = lin;
  o.nlin = 2;
  /* res -> clean -> raw, each found and checked */
  NQTEQI(nqchkx(res, &o, &r), NQOK);
  NQTEQI(row(r, "lineage"), 1);
  nqrepfree(r);
  /* the raw capsule changed: cleans lineage fails, and so ress */
  put(raw, "a.txt", "tampered\n");
  NQTEQI(nqchkx(res, &o, &r), NQEVRFY);
  NQTEQI(row(r, "lineage"), 0);
  nqrepfree(r);
  put(raw, "a.txt", "alpha\n");
  /* an input not among the folders given fails */
  o.nlin = 1;
  lin[0] = raw;
  NQTEQI(nqchkx(res, &o, &r), NQEVRFY);
  NQTEQI(row(r, "lineage"), 0);
  nqrepfree(r);
  /* without folders, no lineage is checked (the inputs are only listed) */
  o.nlin = 0;
  o.lin = NULL;
  NQTEQI(nqchkx(res, &o, &r), NQOK);
  NQTEQI(row(r, "lineage"), -1);
  nqrepfree(r);
  rmall(res);
  rmall(cln);
  rmall(raw);
}

/* the proof of d's paths, in a fresh buffer (NULL on failure) */
static char *prove(const char *d, const char *const *ps, size_t n,
                   size_t *len, int *rc) {
  char *b;
  *rc = nqprove(d, ps, n, NULL, 0, len);
  if (*rc != NQEBUF) return NULL;
  b = (char *)malloc(*len + 1);
  if (b == NULL) return NULL;
  *rc = nqprove(d, ps, n, b, *len, len);
  if (*rc != NQOK) {
    free(b);
    return NULL;
  }
  b[*len] = 0;
  return b;
}

/* a copy of b with the first a replaced by c */
static char *swap(const char *b, const char *a, const char *c, size_t *n) {
  const char *at = strstr(b, a);
  char *o;
  size_t k;
  if (at == NULL) return NULL;
  k = strlen(b) - strlen(a) + strlen(c);
  o = (char *)malloc(k + 1);
  if (o == NULL) return NULL;
  memcpy(o, b, (size_t)(at - b));
  strcpy(o + (at - b), c);
  strcat(o, at + strlen(a));
  *n = k;
  return o;
}

static void tproof(void) {
  char d[400], *pf, *bad;
  size_t n = 0, bn = 0;
  int rc;
  nqrep *r = NULL;
  nqcopt o;
  const char *one[1] = {"b.csv"}, *dup[3] = {"sub/c.bin", "b.csv", "b.csv"},
             *no[1] = {"nope"};
  uint8_t pk2[1312], sk2[2560];
  mk(d, sizeof d, "proof");
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  pf = prove(d, one, 1, &n, &rc);
  NQTEQI(rc, NQOK);
  NQTCHK(pf != NULL);
  if (pf == NULL) return;
  /* nothing of the other files: no name, no digest */
  NQTCHK(strstr(pf, "a.txt") == NULL && strstr(pf, "c.bin") == NULL);
  NQTCHK(strstr(pf, "\"format\":\"noqtis-proof-1\"") != NULL);
  memset(&o, 0, sizeof o);
  o.trust = pk;
  o.trustlen = sizeof pk;
  NQTEQI(nqchkp(pf, n, &o, NULL, &r), NQOK);
  NQTEQI(row(r, "proof.entry"), 1);
  NQTEQI(row(r, "signature"), 1);
  nqrepfree(r);
  NQTEQI(nqchkp(pf, n, &o, d, &r), NQOK);
  NQTEQI(row(r, "file"), 1);
  NQTEQI(row(r, "partial"), 1);
  nqrepfree(r);
  /* the proven file changed: caught with the folder, not without */
  put(d, "b.csv", "x,y\n9,9\n");
  NQTEQI(nqchkp(pf, n, &o, d, &r), NQEVRFY);
  NQTEQI(row(r, "file"), 0);
  nqrepfree(r);
  NQTEQI(nqchkp(pf, n, &o, NULL, &r), NQOK);
  nqrepfree(r);
  put(d, "b.csv", "x,y\n1,2\n");
  /* another key */
  NQTEQI(nqskg(NQMLDSA44, pk2, sizeof pk2, sk2, sizeof sk2), NQOK);
  o.trust = pk2;
  NQTEQI(nqchkp(pf, n, &o, NULL, &r), NQEVRFY);
  NQTEQI(row(r, "key"), 0);
  nqrepfree(r);
  o.trust = pk;
  /* a changed entry, index, audit path or root */
  bad = swap(pf, "\"size\":8", "\"size\":9", &bn);
  NQTCHK(bad != NULL);
  if (bad != NULL) {
    NQTEQI(nqchkp(bad, bn, &o, NULL, &r), NQEVRFY);
    NQTEQI(row(r, "proof.entry"), 0);
    nqrepfree(r);
    free(bad);
  }
  bad = swap(pf, "\"index\":1", "\"index\":2", &bn);
  NQTCHK(bad != NULL);
  if (bad != NULL) {
    NQTEQI(nqchkp(bad, bn, &o, NULL, &r), NQEVRFY);
    NQTEQI(row(r, "proof.entry"), 0);
    nqrepfree(r);
    free(bad);
  }
  {
    char *at = strstr(pf, "\"path\":[\"");
    NQTCHK(at != NULL);
    if (at != NULL) {
      char *c = (char *)malloc(n + 1);
      if (c != NULL) {
        memcpy(c, pf, n + 1);
        at = c + (at - pf) + 9;
        *at = *at == 'a' ? 'b' : 'a';
        NQTEQI(nqchkp(c, n, &o, NULL, &r), NQEVRFY);
        NQTEQI(row(r, "proof.entry"), 0);
        nqrepfree(r);
        free(c);
      }
    }
  }
  bad = swap(pf, "\"root\":\"", "\"root\":\"0", &bn);
  NQTCHK(bad != NULL);
  if (bad != NULL) {
    NQTEQI(nqchkp(bad, bn, &o, NULL, &r), NQEVRFY);
    nqrepfree(r);
    free(bad);
  }
  /* not canonical */
  bad = swap(pf, "{\"entries\"", "{ \"entries\"", &bn);
  if (bad != NULL) {
    NQTEQI(nqchkp(bad, bn, &o, NULL, &r), NQEVRFY);
    NQTEQI(row(r, "proof.canonical"), 0);
    nqrepfree(r);
    free(bad);
  }
  free(pf);
  /* several paths, a repeat, in any order */
  pf = prove(d, dup, 3, &n, &rc);
  NQTEQI(rc, NQOK);
  if (pf != NULL) {
    NQTCHK(strstr(pf, "a.txt") == NULL);
    NQTEQI(nqchkp(pf, n, &o, d, &r), NQOK);
    nqrepfree(r);
    free(pf);
  }
  /* a path not listed; a format 1 capsule */
  NQTEQI(nqprove(d, no, 1, NULL, 0, &n), NQEIO);
  NQTEQI(seal(d, 1, NULL, 0), NQOK);
  NQTEQI(nqprove(d, one, 1, NULL, 0, &n), NQENOSUP);
  rmall(d);
}
#endif

/* NULL options are no options; key statements are refused, not ignored */
static void topts(void) {
  char d[400];
  nqrep *r = NULL;
  nqcopt o;
  const char *st[1] = {"x"};
  size_t sl[1] = {1};
  mk(d, sizeof d, "opts");
  NQTEQI(seal(d, 2, NULL, 0), NQOK);
  NQTEQI(nqchkx(d, NULL, &r), NQOK);
  NQTEQI(row(r, "key"), 1);
  nqrepfree(r);
  memset(&o, 0, sizeof o);
  o.stmt = st;
  o.stmtlen = sl;
  o.nstmt = 1;
  r = (nqrep *)&o;
  NQTEQI(nqchkx(d, &o, &r), NQENOSUP);
  NQTCHK(r == NULL);
  rmall(d);
}

int main(void) {
  tmerkle();
#ifdef NQTFS
  {
    const char *t = getenv("TMPDIR");
    uint8_t b[4];
    if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
    NQTEQI(nqrand(b, sizeof b), NQOK);
    snprintf(root, sizeof root, "%s/tcap2%02x%02x%02x%02x", t, b[0], b[1],
             b[2], b[3]);
    NQTEQI(mkdir(root, 0700), 0);
    NQTEQI(nqskg(NQMLDSA44, pk, sizeof pk, sk, sizeof sk), NQOK);
    tseal();
    tinputs();
    tpartial();
    tlineage();
    tproof();
    topts();
    rmdir(root);
  }
#endif
  return nqtdone("tcap2");
}
