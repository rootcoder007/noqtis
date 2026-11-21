/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The key store (nqksadd, nqkslist, nqksget, nqkscert, nqkscput,
 * nqkstrust, nqksdel): a key with a card and one with a name; validity
 * from an ultimately trusted key through one full or three marginal
 * certifications, five levels deep and no further; what does not count
 * (a key certifying itself, an issuer never trusted, not valid, or not
 * in the store, a certification of a name the key no longer has); a KEM
 * key certified by a signature key; finding by fingerprint, name and
 * address; a certification carried to another store, and what that
 * refuses; removal; files of the store changed behind its back; the
 * refusals. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "cap/cap.h"
#include "core/int.h"
#include "core/json.h"
#include "nqt.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#define NQTFS 1
#endif

#define T0 1767225600 /* 2026-01-01T00:00:00Z */
#define NK 12
#define PK 1312
#define SK 2560

#ifdef NQTFS
static char root[300];
static uint8_t pk[NK][PK], sk[NK][SK], fp[NK][32];
static uint8_t kpk[1184], ksk[2400], kfp[32];

static void keys(void) {
  uint8_t seed[64];
  int i;
  for (i = 0; i < NK; i++) {
    memset(seed, 0x30 + i, sizeof seed);
    NQTEQI(nqskgd(NQMLDSA44, seed, 32, pk[i], PK, sk[i], SK), NQOK);
    nqhash(NQS256, pk[i], PK, fp[i], 32);
  }
  memset(seed, 0x7a, sizeof seed);
  NQTEQI(nqkkgd(NQMLKEM768, seed, 64, kpk, sizeof kpk, ksk, sizeof ksk),
         NQOK);
  nqhash(NQS256, kpk, sizeof kpk, kfp, 32);
}

static void mk(char *d, size_t cap, const char *name) {
  snprintf(d, cap, "%s/%s", root, name);
  NQTEQI(mkdir(d, 0700), 0);
}

/* removes every file of the store, and the folder */
static void wipe(const char *d) {
  nqclist l;
  char p[700];
  size_t i;
  memset(&l, 0, sizeof l);
  if (nqcwalk(d, &l) == NQOK) {
    for (i = 0; i < l.n; i++) {
      snprintf(p, sizeof p, "%s/%s", d, l.e[i].path);
      remove(p);
    }
  }
  nqclfree(&l);
  rmdir(d);
}

static void add(const char *d, int i, const char *name, const char *email) {
  uint8_t f[32];
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[i], PK, name, email, NULL, 0, f), NQOK);
  NQTEQM(f, fp[i], 32);
}

static void cert(const char *d, int by, const uint8_t *of) {
  NQTEQI(nqkscert(d, NQMLDSA44, sk[by], SK, pk[by], PK, of, T0, NULL, 0,
                  NULL),
         NQOK);
}

/* the entry of fingerprint f; valid -1 when it is not there */
static nqkse get(const char *d, const uint8_t *f) {
  static nqkse e[NK + 2];
  nqkse none;
  size_t n = 0, i;
  memset(&none, 0, sizeof none);
  none.valid = -1;
  NQTEQI(nqkslist(d, NULL, e, NK + 2, &n), NQOK);
  for (i = 0; i < n; i++) {
    if (memcmp(e[i].fp, f, 32) == 0) return e[i];
  }
  return none;
}

static void tbasic(void) {
  char d[400], card[8192];
  nqkse e[4], x;
  uint8_t f[32], got[PK];
  size_t n = 0, cl = 0, pl = 0;
  int kem = 9, alg = 0;
  mk(d, sizeof d, "basic");
  NQTEQI(nqkslist(d, NULL, e, 4, &n), NQOK);
  NQTCHK(n == 0);
  /* my own key, with its card */
  NQTEQI(nqcard(NQMLDSA44, sk[0], SK, pk[0], PK, "Ada Example", NULL,
                "ada@example.org", NULL, NULL, T0, card, sizeof card, &cl),
         NQOK);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[0], PK, NULL, NULL, card, cl, f), NQOK);
  NQTEQM(f, fp[0], 32);
  x = get(d, fp[0]);
  NQTCHK(x.kem == 0 && x.alg == (int)NQMLDSA44 && x.pklen == PK);
  NQTCHK(strcmp(x.name, "Ada Example") == 0);
  NQTCHK(strcmp(x.email, "ada@example.org") == 0);
  NQTCHK(x.card == 1 && x.trust == NQKTUNK && x.valid == NQKVNONE);
  NQTCHK(x.ncert == 0);
  NQTEQI(nqkstrust(d, fp[0], NQKTULT), NQOK);
  x = get(d, fp[0]);
  NQTCHK(x.trust == NQKTULT && x.valid == NQKVFULL);
  /* another's key, by name; with no address */
  add(d, 1, "Ben Example", "ben@example.org");
  add(d, 2, "Cy", NULL);
  x = get(d, fp[1]);
  NQTCHK(x.card == 0 && x.valid == NQKVNONE);
  x = get(d, fp[2]);
  NQTCHK(strcmp(x.email, "") == 0);
  /* the key itself comes back */
  NQTEQI(nqksget(d, fp[1], &kem, &alg, got, sizeof got, &pl), NQOK);
  NQTCHK(kem == 0 && alg == (int)NQMLDSA44 && pl == PK);
  NQTEQM(got, pk[1], PK);
  NQTEQI(nqksget(d, fp[1], NULL, NULL, got, sizeof got, &pl), NQOK);
  NQTEQI(nqksget(d, fp[1], &kem, &alg, got, PK - 1, &pl), NQEBUF);
  NQTEQI(nqksget(d, fp[5], &kem, &alg, got, sizeof got, &pl), NQEIO);
  /* one certification by my key makes it valid */
  cert(d, 0, fp[1]);
  x = get(d, fp[1]);
  NQTCHK(x.ncert == 1 && x.valid == NQKVFULL);
  /* a key certifying itself does not */
  NQTEQI(nqkstrust(d, fp[2], NQKTFULL), NQOK);
  cert(d, 2, fp[2]);
  x = get(d, fp[2]);
  NQTCHK(x.ncert == 1 && x.valid == NQKVNONE);
  /* nor does a valid key that is not trusted, or never */
  cert(d, 1, fp[2]);
  x = get(d, fp[2]);
  NQTCHK(x.ncert == 2 && x.valid == NQKVNONE);
  NQTEQI(nqkstrust(d, fp[1], NQKTNEVER), NQOK);
  NQTCHK(get(d, fp[2]).valid == NQKVNONE);
  NQTEQI(nqkstrust(d, fp[1], NQKTFULL), NQOK);
  NQTCHK(get(d, fp[2]).valid == NQKVFULL);
  /* a key under another name loses the certifications of the old one,
   * and keeps its trust */
  add(d, 1, "Benjamin Example", "ben@example.org");
  x = get(d, fp[1]);
  NQTCHK(x.ncert == 0 && x.valid == NQKVNONE && x.trust == NQKTFULL);
  NQTCHK(get(d, fp[2]).valid == NQKVNONE);
  cert(d, 0, fp[1]);
  NQTCHK(get(d, fp[1]).valid == NQKVFULL);
  NQTCHK(get(d, fp[2]).valid == NQKVFULL);
  /* a KEM key: certified by a signature key, it certifies nothing */
  NQTEQI(nqksadd(d, 1, NQMLKEM768, kpk, sizeof kpk, "Ben Example", NULL,
                 NULL, 0, f),
         NQOK);
  NQTEQM(f, kfp, 32);
  x = get(d, kfp);
  NQTCHK(x.kem == 1 && x.alg == (int)NQMLKEM768 && x.valid == NQKVNONE);
  cert(d, 1, kfp);
  NQTCHK(get(d, kfp).valid == NQKVFULL);
  NQTEQI(nqksget(d, kfp, &kem, &alg, got, sizeof got, &pl), NQOK);
  NQTCHK(kem == 1 && alg == (int)NQMLKEM768 && pl == sizeof kpk);
  /* finding */
  NQTEQI(nqkslist(d, "example", e, 4, &n), NQOK);
  NQTCHK(n == 3);
  NQTEQI(nqkslist(d, "BENJAMIN", e, 4, &n), NQOK);
  NQTCHK(n == 1 && memcmp(e[0].fp, fp[1], 32) == 0);
  NQTEQI(nqkslist(d, "ada@", e, 4, &n), NQOK);
  NQTCHK(n == 1 && memcmp(e[0].fp, fp[0], 32) == 0);
  NQTEQI(nqkslist(d, "nobody", e, 4, &n), NQOK);
  NQTCHK(n == 0);
  {
    char hx[65];
    nqhex(fp[2], 32, hx);
    NQTEQI(nqkslist(d, hx, e, 4, &n), NQOK);
    NQTCHK(n == 1 && memcmp(e[0].fp, fp[2], 32) == 0);
    hx[8] = '\0';
    NQTEQI(nqkslist(d, hx, e, 4, &n), NQOK);
    NQTCHK(n == 1 && memcmp(e[0].fp, fp[2], 32) == 0);
    hx[0] = (char)(hx[0] >= 'a' ? hx[0] - 'a' + 'A' : hx[0]);
    NQTEQI(nqkslist(d, hx, e, 4, &n), NQOK);
    NQTCHK(n == 1);
  }
  /* fewer entries than there are: the number, and NQEBUF */
  NQTEQI(nqkslist(d, NULL, e, 2, &n), NQEBUF);
  NQTCHK(n == 4);
  NQTEQI(nqkslist(d, NULL, NULL, 0, &n), NQEBUF);
  NQTCHK(n == 4);
  NQTEQI(nqkslist(d, NULL, e, 4, &n), NQOK);
  /* in the order of the fingerprints */
  NQTCHK(memcmp(e[0].fp, e[1].fp, 32) < 0 && memcmp(e[1].fp, e[2].fp, 32) < 0);
  /* removal takes the certifications of it and by it */
  NQTEQI(nqksdel(d, fp[1]), NQOK);
  NQTCHK(get(d, fp[1]).valid == -1);
  NQTCHK(get(d, fp[2]).valid == NQKVNONE && get(d, fp[2]).ncert == 1);
  NQTCHK(get(d, kfp).valid == NQKVNONE && get(d, kfp).ncert == 0);
  NQTEQI(nqksdel(d, fp[1]), NQEIO);
  wipe(d);
}

/* three marginal keys, and the five levels */
static void tweb(void) {
  char d[400];
  int i;
  mk(d, sizeof d, "web");
  add(d, 0, "Me", NULL);
  NQTEQI(nqkstrust(d, fp[0], NQKTULT), NQOK);
  for (i = 1; i <= 3; i++) {
    char nm[8];
    snprintf(nm, sizeof nm, "M%d", i);
    add(d, i, nm, NULL);
    cert(d, 0, fp[i]);
    NQTEQI(nqkstrust(d, fp[i], NQKTMARG), NQOK);
  }
  add(d, 4, "Target", NULL);
  NQTCHK(get(d, fp[4]).valid == NQKVNONE);
  cert(d, 1, fp[4]);
  NQTCHK(get(d, fp[4]).valid == NQKVMARG);
  cert(d, 2, fp[4]);
  NQTCHK(get(d, fp[4]).valid == NQKVMARG);
  cert(d, 3, fp[4]);
  NQTCHK(get(d, fp[4]).valid == NQKVFULL);
  /* a marginally valid key does not vouch, whatever its trust */
  NQTEQI(nqksdel(d, fp[3]), NQOK);
  NQTCHK(get(d, fp[4]).valid == NQKVMARG);
  NQTEQI(nqkstrust(d, fp[4], NQKTFULL), NQOK);
  add(d, 5, "Further", NULL);
  cert(d, 4, fp[5]);
  NQTCHK(get(d, fp[5]).valid == NQKVNONE);
  wipe(d);
  /* a chain: 0 is mine, each certifies the next and is trusted fully;
   * 1 to 5 are valid, 6 is a level too far */
  mk(d, sizeof d, "chain");
  for (i = 0; i <= 6; i++) {
    char nm[8];
    snprintf(nm, sizeof nm, "C%d", i);
    add(d, i, nm, NULL);
    NQTEQI(nqkstrust(d, fp[i], i == 0 ? NQKTULT : NQKTFULL), NQOK);
    if (i > 0) cert(d, i - 1, fp[i]);
  }
  for (i = 0; i <= 5; i++) NQTCHK(get(d, fp[i]).valid == NQKVFULL);
  NQTCHK(get(d, fp[6]).valid == NQKVNONE);
  wipe(d);
}

/* a certification carried from one store to another */
static void tcarry(void) {
  char a[400], b[400], c[8192], p[800];
  size_t n = 0, i;
  FILE *f;
  mk(a, sizeof a, "from");
  mk(b, sizeof b, "to");
  add(a, 0, "Me", NULL);
  add(a, 1, "Ben Example", "ben@example.org");
  NQTEQI(nqkscert(a, NQMLDSA44, sk[0], SK, pk[0], PK, fp[1], T0, c, 16, &n),
         NQEBUF);
  NQTCHK(n > 16 && n < sizeof c);
  NQTEQI(nqkscert(a, NQMLDSA44, sk[0], SK, pk[0], PK, fp[1], T0, c, sizeof c,
                  &n),
         NQOK);
  NQTCHK(memcmp(c, "{\"alg\":\"ML-DSA-44\",\"created\":\"2026-01-01T00:00:00Z\"",
                51) == 0);
  /* neither key is in the other store, then only the issuer, then both */
  NQTEQI(nqkscput(b, c, n), NQEIO);
  add(b, 0, "Me", NULL);
  NQTEQI(nqkscput(b, c, n), NQEIO);
  add(b, 1, "Ben Example", "ben@example.org");
  NQTEQI(nqkscput(b, c, n), NQOK);
  NQTEQI(nqkstrust(b, fp[0], NQKTULT), NQOK);
  NQTCHK(get(b, fp[1]).valid == NQKVFULL && get(b, fp[1]).ncert == 1);
  /* under another name there it is refused */
  add(b, 1, "Someone Else", "ben@example.org");
  NQTEQI(nqkscput(b, c, n), NQEVRFY);
  add(b, 1, "Ben Example", "other@example.org");
  NQTEQI(nqkscput(b, c, n), NQEVRFY);
  add(b, 1, "Ben Example", "ben@example.org");
  /* every byte of it changed: never accepted */
  for (i = 0; i < n; i++) {
    int rc;
    c[i] ^= 1;
    rc = nqkscput(b, c, n);
    NQTCHK(rc == NQEDEC || rc == NQEVRFY || rc == NQEIO);
    c[i] ^= 1;
  }
  NQTEQI(nqkscput(b, c, n - 1), NQEDEC);
  NQTEQI(nqkscput(b, c, 0), NQEDEC);
  NQTEQI(nqkscput(b, "[]", 2), NQEDEC);
  /* another key under the issuer's name in the store: the signature
   * does not verify (the fingerprint is the issuer's, the key is not) */
  NQTEQI(nqkscput(b, c, n), NQOK);
  /* a key file changed behind the store's back is not read as the key */
  snprintf(p, sizeof p, "%s/", b);
  nqhex(fp[1], 32, p + strlen(p));
  memcpy(p + strlen(p), ".pub", 5);
  f = fopen(p, "wb");
  NQTCHK(f != NULL);
  if (f != NULL) {
    fputs("noqtis-key-1 ML-DSA-44 pub\nAAAA\n", f);
    fclose(f);
  }
  {
    nqkse e[4];
    uint8_t got[PK];
    size_t pl = 0;
    NQTEQI(nqkslist(b, NULL, e, 4, &n), NQEDEC);
    NQTEQI(nqksget(b, fp[1], NULL, NULL, got, sizeof got, &pl), NQEDEC);
  }
  f = fopen(p, "wb");
  if (f != NULL) {
    fputs("not a key\n", f);
    fclose(f);
  }
  {
    nqkse e[4];
    NQTEQI(nqkslist(b, NULL, e, 4, &n), NQEDEC);
  }
  wipe(a);
  wipe(b);
}

static void targs(void) {
  char d[400], card[8192], c[8192], big[300];
  nqkse e[2];
  uint8_t f[32], epk[32], esk[64], got[PK];
  size_t n = 0, cl = 0, pl = 0;
  mk(d, sizeof d, "args");
  add(d, 0, "Me", NULL);
  add(d, 1, "Ben", NULL);
  memset(big, 'a', sizeof big);
  big[256] = '\0';
  NQTEQI(nqksadd(NULL, 0, NQMLDSA44, pk[2], PK, "X", NULL, NULL, 0, f),
         NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, NULL, PK, "X", NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 2, NQMLDSA44, pk[2], PK, "X", NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK - 1, "X", NULL, NULL, 0, f),
         NQEARG);
  NQTEQI(nqksadd(d, 0, 9999, pk[2], PK, "X", NULL, NULL, 0, f), NQENOSUP);
  NQTEQI(nqksadd(d, 1, 9999, kpk, sizeof kpk, "X", NULL, NULL, 0, f),
         NQENOSUP);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, NULL, NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, "", NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, " X", NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, "X\n", NULL, NULL, 0, f),
         NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, big, NULL, NULL, 0, f), NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, "X", "not an address", NULL, 0,
                 f),
         NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, "X", NULL, NULL, 5, f), NQEARG);
  /* a card: of another key, with a name beside it, for a KEM key */
  NQTEQI(nqcard(NQMLDSA44, sk[3], SK, pk[3], PK, "Dee", NULL, NULL, NULL,
                NULL, T0, card, sizeof card, &cl),
         NQOK);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[2], PK, NULL, NULL, card, cl, f),
         NQEVRFY);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[3], PK, "Dee", NULL, card, cl, f),
         NQEARG);
  NQTEQI(nqksadd(d, 1, NQMLKEM768, kpk, sizeof kpk, NULL, NULL, card, cl, f),
         NQEARG);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[3], PK, NULL, NULL, card, cl - 1, f),
         NQEDEC);
  NQTEQI(nqksadd(d, 0, NQMLDSA44, pk[3], PK, NULL, NULL, card, cl, NULL),
         NQOK);
  NQTCHK(get(d, fp[3]).card == 1);
  /* nothing of a refused key was written */
  NQTCHK(get(d, fp[2]).valid == -1);
  /* list, get, trust, del */
  NQTEQI(nqkslist(NULL, NULL, e, 2, &n), NQEARG);
  NQTEQI(nqkslist(d, NULL, e, 2, NULL), NQEARG);
  NQTEQI(nqkslist(d, NULL, NULL, 2, &n), NQEARG);
  NQTEQI(nqkslist(d, "", e, 2, &n), NQEARG);
  NQTEQI(nqkslist("/nonexistent/noqtis/store", NULL, e, 2, &n), NQEIO);
  NQTEQI(nqksget(NULL, fp[0], NULL, NULL, got, sizeof got, &pl), NQEARG);
  NQTEQI(nqksget(d, NULL, NULL, NULL, got, sizeof got, &pl), NQEARG);
  NQTEQI(nqksget(d, fp[0], NULL, NULL, got, sizeof got, NULL), NQEARG);
  NQTEQI(nqksget(d, fp[0], NULL, NULL, NULL, 4, &pl), NQEARG);
  NQTEQI(nqkstrust(NULL, fp[0], NQKTFULL), NQEARG);
  NQTEQI(nqkstrust(d, NULL, NQKTFULL), NQEARG);
  NQTEQI(nqkstrust(d, fp[0], -1), NQEARG);
  NQTEQI(nqkstrust(d, fp[0], NQKTULT + 1), NQEARG);
  NQTEQI(nqkstrust(d, fp[7], NQKTFULL), NQEIO);
  NQTEQI(nqksdel(NULL, fp[0]), NQEARG);
  NQTEQI(nqksdel(d, NULL), NQEARG);
  /* certifying */
  NQTEQI(nqkscert(NULL, NQMLDSA44, sk[0], SK, pk[0], PK, fp[1], T0, c,
                  sizeof c, &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, NULL, SK, pk[0], PK, fp[1], T0, c, sizeof c,
                  &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, NULL, PK, fp[1], T0, c, sizeof c,
                  &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, pk[0], PK, NULL, T0, c, sizeof c,
                  &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, pk[0], PK, fp[1], T0, NULL, 9, &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK - 1, pk[0], PK, fp[1], T0, c,
                  sizeof c, &n),
         NQEARG);
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, pk[0], PK, fp[1], -1, c, sizeof c,
                  &n),
         NQEARG);
  /* a pair that is not one */
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, pk[1], PK, fp[1], T0, c, sizeof c,
                  &n),
         NQEARG);
  NQTCHK(get(d, fp[1]).ncert == 0);
  /* a key that is not in the store, and Ed25519 alone */
  NQTEQI(nqkscert(d, NQMLDSA44, sk[0], SK, pk[0], PK, fp[7], T0, c, sizeof c,
                  &n),
         NQEIO);
  memset(f, 1, sizeof f);
  NQTEQI(nqskgd(NQED25519, f, 32, epk, sizeof epk, esk, sizeof esk), NQOK);
  NQTEQI(nqkscert(d, NQED25519, esk, sizeof esk, epk, sizeof epk, fp[1], T0,
                  c, sizeof c, &n),
         NQENOSUP);
  NQTEQI(nqkscert(d, (nqsalg)9999, sk[0], SK, pk[0], PK, fp[1], T0, c,
                  sizeof c, &n),
         NQENOSUP);
  NQTEQI(nqkscput(NULL, "x", 1), NQEARG);
  NQTEQI(nqkscput(d, NULL, 1), NQEARG);
  wipe(d);
}
#endif

int main(void) {
#ifdef NQTFS
  const char *t = getenv("TMPDIR");
  uint8_t b[4];
  if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
  NQTEQI(nqrand(b, sizeof b), NQOK);
  snprintf(root, sizeof root, "%s/tkst%02x%02x%02x%02x", t, b[0], b[1], b[2],
           b[3]);
  NQTEQI(mkdir(root, 0700), 0);
  keys();
  tbasic();
  tweb();
  tcarry();
  targs();
  rmdir(root);
#endif
  return nqtdone("tkst");
}
