/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Capsule format 3 (noqtis-capsule-3, noqtis-seal-3): salted Merkle
 * leaves. The salts, leaves, root and whole manifest of a seal with a
 * fixed salt key against tests/vectors/cap3/kat.txt (computed from the
 * specification with Python's hashlib); a sealed folder that checks, and
 * its id; proofs (noqtis-proof-2) that hold the proven entries' salts and
 * nothing of the others, and that fail when a salt, the proof's format
 * or the seal's is changed; two equal salts, a salt in the wrong place,
 * of the wrong length or case, refused; formats 2 and 3 not mixed; and
 * the arguments of nqseal3. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
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

#define KAT "vectors/cap3/kat.txt"
#define MAXF 8

/* kat.txt */
static uint8_t key[32];
static char created[32], man[4096], kroot[65];
static size_t nf;
static struct {
  char path[64];
  uint8_t data[64];
  size_t n;
  char salt[65], leaf[65];
} kf[MAXF];

/* s into d (cap bytes), cut to fit, always terminated */
static void scpy(char *d, size_t cap, const char *s) {
  size_t k = strlen(s);
  if (k >= cap) k = cap - 1;
  memcpy(d, s, k);
  d[k] = 0;
}

static int unhex(const char *s, uint8_t *o, size_t cap) {
  size_t n = 0;
  while (s[0] != 0 && s[1] != 0 && s[0] != '\n' && n < cap) {
    unsigned v;
    if (sscanf(s, "%2x", &v) != 1) return -1;
    o[n++] = (uint8_t)v;
    s += 2;
  }
  return (int)n;
}

static long at(const char *p) {
  size_t i;
  for (i = 0; i < nf; i++) {
    if (strcmp(kf[i].path, p) == 0) return (long)i;
  }
  return -1;
}

static int rdkat(void) {
  FILE *f = fopen(KAT, "rb");
  static char ln[8192];
  if (f == NULL) return 0;
  while (fgets(ln, sizeof ln, f) != NULL) {
    char a[64], b[4096];
    long i;
    size_t k = strlen(ln);
    if (k > 0 && ln[k - 1] == '\n') ln[--k] = 0;
    if (ln[0] == '#' || k == 0) continue;
    if (strncmp(ln, "manifest ", 9) == 0) {
      scpy(man, sizeof man, ln + 9);
    } else if (sscanf(ln, "key %64s", b) == 1) {
      unhex(b, key, sizeof key);
    } else if (sscanf(ln, "created %31s", created) == 1) {
    } else if (sscanf(ln, "root %64s", kroot) == 1) {
    } else if (sscanf(ln, "file %63s %4095s", a, b) == 2 && nf < MAXF) {
      scpy(kf[nf].path, sizeof kf[nf].path, a);
      kf[nf].n = (size_t)unhex(b, kf[nf].data, sizeof kf[nf].data);
      nf++;
    } else if (sscanf(ln, "salt %63s %64s", a, b) == 2 && (i = at(a)) >= 0) {
      scpy(kf[i].salt, sizeof kf[i].salt, b);
    } else if (sscanf(ln, "leaf %63s %64s", a, b) == 2 && (i = at(a)) >= 0) {
      scpy(kf[i].leaf, sizeof kf[i].leaf, b);
    }
  }
  fclose(f);
  return nf == 3 && man[0] != 0 && kroot[0] != 0;
}

/* the salts, leaves and root of the answers, from the library's own
 * functions on the answers' entries */
static void tleaves(void) {
  uint8_t lv[MAXF * 32], s[32], w[32], r[32];
  char hx[65];
  size_t i;
  for (i = 0; i < nf; i++) {
    char e[512];
    const char *p = strstr(man, kf[i].path), *q;
    NQTCHK(p != NULL);
    if (p == NULL) return;
    p -= strlen("{\"path\":\"");
    q = strchr(p, '}');
    NQTCHK(q != NULL);
    if (q == NULL) return;
    snprintf(e, sizeof e, "%.*s", (int)(q - p + 1), p);
    NQTEQI(nqcsaltk(key, kf[i].path, strlen(kf[i].path), s), NQOK);
    nqhex(s, 32, hx);
    NQTCHK(strcmp(hx, kf[i].salt) == 0);
    nqcmleaf3(s, e, strlen(e), lv + 32 * i);
    unhex(kf[i].leaf, w, 32);
    NQTEQM(lv + 32 * i, w, 32);
    /* and a leaf is not a format 2 leaf of the same bytes */
    nqcmleaf(e, strlen(e), w);
    NQTCHK(memcmp(w, lv + 32 * i, 32) != 0);
  }
  nqcmroot(lv, nf, r);
  nqhex(r, 32, hx);
  NQTCHK(strcmp(hx, kroot) == 0);
}

#ifdef NQTFS
static char root[300];
static uint8_t pk[1312], sk[2560];
static const uint8_t rnd[32];

static void putb(const char *d, const char *rel, const uint8_t *b,
                 size_t n) {
  char p[2400];
  FILE *f;
  snprintf(p, sizeof p, "%s/%s", d, rel);
  f = fopen(p, "wb");
  NQTCHK(f != NULL);
  if (f == NULL) return;
  if (n > 0) fwrite(b, 1, n, f);
  fclose(f);
}

static char *slurp(const char *d, const char *rel, size_t *n) {
  char p[2400], *b;
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

static void putm(const char *d, const char *s) {
  putb(d, NQCMAN, (const uint8_t *)s, strlen(s));
}

/* the answers' files in root/name */
static void mk(char *d, size_t cap, const char *name) {
  char s[2400];
  size_t i;
  snprintf(d, cap, "%s/%s", root, name);
  NQTEQI(mkdir(d, 0700), 0);
  snprintf(s, sizeof s, "%s/data", d);
  NQTEQI(mkdir(s, 0700), 0);
  snprintf(s, sizeof s, "%s/data/deep", d);
  NQTEQI(mkdir(s, 0700), 0);
  for (i = 0; i < nf; i++) putb(d, kf[i].path, kf[i].data, kf[i].n);
}

static void rmall(const char *d) {
  char p[2400];
  size_t i;
  for (i = 0; i < nf; i++) {
    snprintf(p, sizeof p, "%s/%s", d, kf[i].path);
    remove(p);
  }
  snprintf(p, sizeof p, "%s/%s", d, NQCMAN);
  remove(p);
  snprintf(p, sizeof p, "%s/%s", d, NQCSIG);
  remove(p);
  snprintf(p, sizeof p, "%s/data/deep", d);
  rmdir(p);
  snprintf(p, sizeof p, "%s/data", d);
  rmdir(p);
  rmdir(d);
}

/* a seal at the answers' time; skey NULL for fresh salts */
static int seal(const char *d, int ver, const uint8_t *skey) {
  return nqcsealk(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL,
                  1767225600, rnd, sizeof rnd, ver, NULL, 0, skey, NULL);
}

/* 1 when some row named chk failed */
static int failed(const nqrep *r, const char *chk) {
  size_t i;
  for (i = 0; i < nqrepn(r); i++) {
    const char *c;
    int ok;
    nqrepi(r, i, &c, &ok, NULL);
    if (strcmp(c, chk) == 0 && !ok) return 1;
  }
  return 0;
}

/* 1 when every row passed */
static int allok(const nqrep *r) {
  size_t i;
  for (i = 0; i < nqrepn(r); i++) {
    int ok;
    nqrepi(r, i, NULL, &ok, NULL);
    if (!ok) return 0;
  }
  return nqrepn(r) > 0;
}

static int chk(const char *d) {
  nqrep *r = NULL;
  int ok = nqchk(d, pk, sizeof pk, &r) == NQOK && allok(r);
  nqrepfree(r);
  return ok;
}

/* the seal with the key: the answers' manifest, byte for byte */
static void tkat(void) {
  char d[400], *m;
  size_t n = 0;
  uint8_t id[32], h[32];
  mk(d, sizeof d, "kat");
  NQTEQI(seal(d, 3, key), NQOK);
  m = slurp(d, NQCMAN, &n);
  NQTCHK(m != NULL && strcmp(m, man) == 0);
  NQTCHK(chk(d));
  /* the id is the SHA-256 of the head: the manifest without its files */
  if (m != NULL) {
    char *fs = strstr(m, "\"files\":["), *fe = strstr(m, "],\"format\"");
    char hd[4096];
    NQTCHK(fs != NULL && fe != NULL);
    if (fs != NULL && fe != NULL) {
      size_t a = (size_t)(fs - m);
      memcpy(hd, m, a);
      strcpy(hd + a, fe + 2);
      nqhash(NQS256, (const uint8_t *)hd, strlen(hd), h, 32);
      NQTEQI(nqcapid(d, id), NQOK);
      NQTEQM(id, h, 32);
    }
  }
  free(m);
  /* fresh salts: another manifest, which checks too */
  NQTEQI(seal(d, 3, NULL), NQOK);
  m = slurp(d, NQCMAN, &n);
  NQTCHK(m != NULL && strcmp(m, man) != 0);
  NQTCHK(chk(d));
  free(m);
  rmall(d);
}

static char *prove(const char *d, const char *p, size_t *len) {
  const char *ps[1];
  char *b;
  ps[0] = p;
  if (nqprove(d, ps, 1, NULL, 0, len) != NQEBUF) return NULL;
  b = (char *)malloc(*len + 1);
  if (b == NULL) return NULL;
  if (nqprove(d, ps, 1, b, *len, len) != NQOK) {
    free(b);
    return NULL;
  }
  b[*len] = 0;
  return b;
}

static int pchk(const char *pf, size_t n, const char *d, const char *bad) {
  nqcopt o;
  nqrep *r = NULL;
  int ok, rc;
  memset(&o, 0, sizeof o);
  o.trust = pk;
  o.trustlen = sizeof pk;
  /* NQOK when every row passed, NQEVRFY when one failed */
  rc = nqchkp(pf, n, &o, d, &r);
  ok = r != NULL && (bad == NULL ? rc == NQOK && allok(r)
                                 : rc == NQEVRFY && failed(r, bad));
  nqrepfree(r);
  return ok;
}

static void tproof(void) {
  char d[400], *pf, *e;
  size_t n = 0, i, k;
  mk(d, sizeof d, "proof");
  NQTEQI(seal(d, 3, key), NQOK);
  pf = prove(d, "a.txt", &n);
  NQTCHK(pf != NULL);
  if (pf == NULL) {
    rmall(d);
    return;
  }
  NQTCHK(strstr(pf, "\"format\":\"noqtis-proof-2\"") != NULL);
  /* the proven entry's salt is there; no other path or salt is */
  for (i = 0; i < nf; i++) {
    int self = strcmp(kf[i].path, "a.txt") == 0;
    NQTCHK((strstr(pf, kf[i].salt) != NULL) == self);
    NQTCHK(self || strstr(pf, kf[i].path) == NULL);
  }
  NQTCHK(pchk(pf, n, NULL, NULL));
  NQTCHK(pchk(pf, n, d, NULL));
  /* the salt changed: the entry's leaf is another, off the tree */
  e = (char *)malloc(n + 1);
  NQTCHK(e != NULL);
  if (e != NULL) {
    const char *s = strstr(pf, kf[at("a.txt")].salt);
    memcpy(e, pf, n + 1);
    k = (size_t)(s - pf);
    e[k] = e[k] == '0' ? '1' : '0';
    NQTCHK(pchk(e, n, NULL, "proof.entry"));
    /* a format 3 proof called a format 2 one: refused */
    memcpy(e, pf, n + 1);
    k = (size_t)(strstr(e, "noqtis-proof-2") - e);
    e[k + 13] = '1';
    NQTCHK(pchk(e, n, NULL, "seal.format"));
    free(e);
  }
  free(pf);
  /* a format 2 capsule's proof is still noqtis-proof-1, and checks */
  NQTEQI(seal(d, 2, NULL), NQOK);
  pf = prove(d, "a.txt", &n);
  NQTCHK(pf != NULL && strstr(pf, "\"format\":\"noqtis-proof-1\"") != NULL);
  if (pf != NULL) NQTCHK(pchk(pf, n, d, NULL));
  free(pf);
  rmall(d);
}

/* manifests a checker refuses, each from the answers' one */
static void tbad(void) {
  char d[400], m[4096];
  const char *s0 = kf[0].salt, *s1 = kf[1].salt;
  char *p;
  nqrep *r = NULL;
  mk(d, sizeof d, "bad");
  NQTEQI(seal(d, 3, key), NQOK);
  /* two entries with one salt */
  scpy(m, sizeof m, man);
  p = strstr(m, s1);
  NQTCHK(p != NULL);
  if (p != NULL) memcpy(p, s0, 64);
  putm(d, m);
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
  NQTCHK(r != NULL && failed(r, "manifest.fields"));
  nqrepfree(r);
  r = NULL;
  /* a salt in upper case, and one a digit short */
  scpy(m, sizeof m, man);
  p = strstr(m, s0);
  if (p != NULL) {
    size_t i;
    for (i = 0; i < 64; i++) {
      if (p[i] >= 'a' && p[i] <= 'f') {
        p[i] = (char)(p[i] - 'a' + 'A');
        break;
      }
    }
  }
  putm(d, m);
  NQTCHK(!chk(d));
  scpy(m, sizeof m, man);
  p = strstr(m, s0);
  if (p != NULL) memmove(p, p + 1, strlen(p + 1) + 1);
  putm(d, m);
  NQTCHK(!chk(d));
  /* no salt at all */
  scpy(m, sizeof m, man);
  p = strstr(m, ",\"salt\":\"");
  if (p != NULL) memmove(p, p + 74, strlen(p + 74) + 1);
  putm(d, m);
  NQTCHK(!chk(d));
  putm(d, man);
  NQTCHK(chk(d));
  /* a format 2 manifest with salts, under a format 2 seal: refused */
  NQTEQI(seal(d, 2, NULL), NQOK);
  {
    size_t n = 0;
    char *m2 = slurp(d, NQCMAN, &n);
    char *q = m2 != NULL ? strstr(m2, "\",\"sha256\"") : NULL;
    NQTCHK(q != NULL);
    if (q != NULL) {
      size_t a = (size_t)(q - m2) + 1;
      snprintf(m, sizeof m, "%.*s,\"salt\":\"%s\"%s", (int)a, m2, s0,
               m2 + a);
      putm(d, m);
      NQTCHK(!chk(d));
    }
    free(m2);
  }
  rmall(d);
}

static void targs(void) {
  char d[400];
  mk(d, sizeof d, "args");
  NQTEQI(nqseal3(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL, 0,
                 key, 31),
         NQEARG);
  NQTEQI(nqseal3(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL, 0,
                 NULL, 32),
         NQEARG);
  NQTEQI(nqseal3(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL, 0,
                 key, 0),
         NQEARG);
  /* a salt key is for format 3 only */
  NQTEQI(seal(d, 2, key), NQEARG);
  NQTEQI(seal(d, 1, key), NQEARG);
  NQTEQI(nqseal3(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL, 0,
                 NULL, 0),
         NQOK);
  NQTCHK(chk(d));
  rmall(d);
}
#endif

int main(void) {
  NQTCHK(rdkat());
  if (nf == 3) tleaves();
#ifdef NQTFS
  if (nf == 3) {
    const char *t = getenv("TMPDIR");
    uint8_t b[4];
    if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
    NQTEQI(nqrand(b, sizeof b), NQOK);
    snprintf(root, sizeof root, "%s/tcap3%02x%02x%02x%02x", t, b[0], b[1],
             b[2], b[3]);
    NQTEQI(mkdir(root, 0700), 0);
    NQTEQI(nqskg(NQMLDSA44, pk, sizeof pk, sk, sizeof sk), NQOK);
    tkat();
    tproof();
    tbad();
    targs();
    rmdir(root);
  }
#endif
  return nqtdone("tcap3");
}
