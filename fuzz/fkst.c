/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the key store's readers: nqksimp (a bundle of
 * keys, cards and certifications) and nqkscput (one certification). At
 * start it makes a store with an owner's signature key, put in by its
 * identity card and trusted ultimately, and the owner's KEM key that
 * key certified, and exports the owner's bundle: the card, the KEM key
 * and its certification. Each
 * input is imported into a fresh store as a bundle, put into the made
 * store as a certification, and written into the good bundle as an edit
 * (two bytes of offset, then the bytes) that is imported in turn. What
 * comes in is listed again: every entry has a name, and nothing an
 * input brings is ever valid, since no key in the fresh store is
 * trusted. */
#define _POSIX_C_SOURCE 200809L /* mkdtemp */
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fz.h"

#define T0 1767225600
static char base[64] = "/tmp/nqfkstXXXXXX", home[128], fresh[128];
static char *good;
static size_t goodn;
static int ready = 0;

/* removes the files of a store folder, and the folder */
static void wipe(const char *dir) {
  DIR *d = opendir(dir);
  struct dirent *e;
  char p[512];
  if (d == NULL) return;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
    unlink(p);
  }
  closedir(d);
  rmdir(dir);
}

static void done(void) {
  wipe(home);
  wipe(fresh);
  rmdir(base);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[64], pk[1312], sk[2560], kpk[800], ksk[1632], me[32], his[32];
  static char card[16384], cert[16384];
  size_t i, cn = 0, cardn = 0;
  int rc;
  (void)argc;
  (void)argv;
  if (mkdtemp(base) == NULL) {
    fprintf(stderr, "fkst: cannot make a folder\n");
    return 0;
  }
  snprintf(home, sizeof home, "%s/home", base);
  snprintf(fresh, sizeof fresh, "%s/fresh", base);
  atexit(done);
  if (mkdir(home, 0700) != 0) {
    fprintf(stderr, "fkst: cannot make a folder\n");
    return 0;
  }
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i + 7);
  rc = nqskgd(NQMLDSA44, seed, 32, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqkkgd(NQMLKEM512, seed, 64, kpk, sizeof kpk, ksk, sizeof ksk);
  if (rc == NQOK)
    rc = nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "Fuzz Owner", NULL,
                "owner@example.org", NULL, NULL, T0, card, sizeof card,
                &cardn);
  /* the signature key is named by its card; the KEM key is the owner's
   * too, so the bundle carries it */
  if (rc == NQOK)
    rc = nqksadd(home, 0, NQMLDSA44, pk, sizeof pk, NULL, NULL, card, cardn,
                 me);
  if (rc == NQOK)
    rc = nqksadd(home, 1, NQMLKEM512, kpk, sizeof kpk, "Fuzz Owner",
                 "owner@example.org", NULL, 0, his);
  if (rc == NQOK) rc = nqkstrust(home, me, NQKTULT);
  if (rc == NQOK)
    rc = nqkscert(home, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, his, T0,
                  cert, sizeof cert, &cn);
  if (rc == NQOK) {
    rc = nqksexp(home, me, NULL, 0, &goodn);
    good = rc == NQEBUF || rc == NQOK ? (char *)malloc(goodn + 1) : NULL;
    rc = good == NULL ? NQEMEM
                      : nqksexp(home, me, good, goodn + 1, &goodn);
  }
  nqwipe(sk, sizeof sk);
  nqwipe(ksk, sizeof ksk);
  if (rc != NQOK) {
    fprintf(stderr, "fkst: cannot make the store: %s\n", nqerr(rc));
    return 0;
  }
  ready = 1;
  return 0;
}

/* imports b into a fresh store and lists what came in */
static void import(const char *b, size_t n) {
  static nqkse e[8];
  uint8_t fp[32];
  size_t k = 0, got = 0, i;
  if (mkdir(fresh, 0700) != 0) return;
  if (nqksimp(fresh, b, n, NULL, fp, &k) == NQOK) {
    if (k == 0) abort();
    if (nqkslist(fresh, NULL, e, 8, &got) != NQOK && got <= 8) abort();
    for (i = 0; i < got && i < 8; i++) {
      if (e[i].name[0] == 0 || memchr(e[i].name, 0, sizeof e[i].name) == NULL ||
          memchr(e[i].email, 0, sizeof e[i].email) == NULL)
        abort();
      /* no key of a fresh store is trusted: nothing in it is valid */
      if (e[i].valid != NQKVNONE) abort();
    }
  }
  nqksimp(fresh, b, n, "owner@example.org", fp, &k);
  wipe(fresh);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *e;
  size_t at, k;
  fzready(ready, "fkst");
  if (size > ((size_t)1 << 18)) return 0;
  import((const char *)data, size);
  /* as a certification for the made store: one the owner did not sign
   * changes nothing there */
  nqkscput(home, (const char *)data, size);
  /* an edit of the good bundle */
  if (size >= 2) {
    at = ((size_t)data[0] << 8 | data[1]) % goodn;
    k = size - 2;
    if (k > goodn - at) k = goodn - at;
    e = (char *)malloc(goodn);
    if (e != NULL) {
      memcpy(e, good, goodn);
      memcpy(e + at, data + 2, k);
      import(e, goodn);
      free(e);
    }
  }
  return 0;
}
