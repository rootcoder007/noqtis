/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the proofs of format 2 and format 3 capsules
 * (nqchkp) and their partial check (nqchkx). At start it seals two small
 * capsules under $TMPDIR (else /tmp) with a fixed ML-DSA-44 key, one in
 * format 2 and one in format 3 (salted, from a fixed salt key), and proves
 * two files of each. Each input is then checked: as a proof by itself; as
 * an edit of each good proof (two bytes of offset, then the bytes to
 * write there), so the mutations reach the audit paths, the entries, the
 * salts and the head past the parsers; that edited proof against its
 * capsule's folder; and, for the format 2 folder, as a key statement
 * (noqtis-keys-1) followed from the trusted key. The folders are removed
 * at exit. */
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#include <sys/stat.h>

#include "fz.h"
#include "cap/cap.h"

static char dirs[2][600];
static char *good[2];
static size_t goodn[2];
static uint8_t pk[1312];
static int ready = 0;

static const char *const files[] = {"a.txt", "b.csv", "sub/c.bin"};

static void rmcap(const char *dir) {
  char p[700];
  size_t i;
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(p, sizeof p, "%s/%s", dir, files[i]);
    remove(p);
  }
  snprintf(p, sizeof p, "%s/%s", dir, NQCMAN);
  remove(p);
  snprintf(p, sizeof p, "%s/%s", dir, NQCSIG);
  remove(p);
  snprintf(p, sizeof p, "%s/sub", dir);
  remove(p);
  remove(dir);
}

static void bye(void) {
  rmcap(dirs[0]);
  rmcap(dirs[1]);
}

/* the capsule of format ver (2 or 3) in dirs[k], and its proof */
static int mk(int k, int ver, const uint8_t *sk, size_t skn) {
  const char *t = getenv("TMPDIR");
  const char *ps[2] = {"b.csv", "sub/c.bin"};
  char p[700];
  uint8_t skey[32];
  size_t i;
  int rc;
  snprintf(dirs[k], sizeof dirs[k], "%s/nqfproof.XXXXXX",
           t != NULL && *t != 0 ? t : "/tmp");
  if (mkdtemp(dirs[k]) == NULL) {
    fprintf(stderr, "fproof: cannot make a folder under %s\n", dirs[k]);
    return 0;
  }
  snprintf(p, sizeof p, "%s/sub", dirs[k]);
  mkdir(p, 0755);
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    if (!fzput(dirs[k], files[i], files[i], strlen(files[i]))) return 0;
  }
  for (i = 0; i < sizeof skey; i++) skey[i] = (uint8_t)(0x40 + i);
  rc = ver == 3 ? nqseal3(dirs[k], NQMLDSA44, sk, skn, pk, sizeof pk, NULL,
                          NULL, 0, skey, sizeof skey)
                : nqseal2(dirs[k], NQMLDSA44, sk, skn, pk, sizeof pk, NULL,
                          NULL, 0);
  if (rc != NQOK) {
    fprintf(stderr, "fproof: cannot seal %s\n", dirs[k]);
    return 0;
  }
  rc = nqprove(dirs[k], ps, 2, NULL, 0, &goodn[k]);
  good[k] = rc == NQEBUF ? (char *)malloc(goodn[k]) : NULL;
  if (good[k] != NULL) rc = nqprove(dirs[k], ps, 2, good[k], goodn[k],
                                    &goodn[k]);
  if (rc != NQOK) {
    fprintf(stderr, "fproof: cannot prove %s: %s\n", dirs[k], nqerr(rc));
    return 0;
  }
  return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t seed[32], sk[2560];
  size_t i;
  int ok;
  (void)argc;
  fzinit(argv);
  atexit(bye);
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)i;
  if (nqskgd(NQMLDSA44, seed, sizeof seed, pk, sizeof pk, sk, sizeof sk) !=
      NQOK) {
    return 0;
  }
  ok = mk(0, 2, sk, sizeof sk) && mk(1, 3, sk, sizeof sk);
  nqwipe(sk, sizeof sk);
  ready = ok;
  return 0;
}

/* data as an edit of the good proof k, checked alone and against its
 * folder */
static void edit(int k, const uint8_t *data, size_t size, nqcopt *o) {
  nqrep *r = NULL;
  char *e;
  size_t at, n;
  at = ((size_t)data[0] << 8 | data[1]) % goodn[k];
  n = size - 2;
  if (n > goodn[k] - at) n = goodn[k] - at;
  e = (char *)malloc(goodn[k]);
  if (e == NULL) return;
  memcpy(e, good[k], goodn[k]);
  memcpy(e + at, data + 2, n);
  nqchkp(e, goodn[k], o, NULL, &r);
  nqrepfree(r);
  r = NULL;
  nqchkp(e, goodn[k], o, dirs[k], &r);
  nqrepfree(r);
  free(e);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqcopt o;
  nqrep *r = NULL;
  const char *only[1] = {"b.csv"};
  int k;
  fzready(ready, "fproof");
  memset(&o, 0, sizeof o);
  /* the input as a proof, with and without the trusted key */
  nqchkp((const char *)data, size, NULL, NULL, &r);
  nqrepfree(r);
  r = NULL;
  o.trust = pk;
  o.trustlen = sizeof pk;
  nqchkp((const char *)data, size, &o, NULL, &r);
  nqrepfree(r);
  r = NULL;
  /* the input as a key statement, followed from the trusted key */
  {
    const char *st[1];
    size_t sl[1];
    st[0] = (const char *)data;
    sl[0] = size;
    o.stmt = st;
    o.stmtlen = sl;
    o.nstmt = 1;
    nqchkx(dirs[0], &o, &r);
    nqrepfree(r);
    r = NULL;
    o.stmt = NULL;
    o.stmtlen = NULL;
    o.nstmt = 0;
  }
  /* an edit of each good proof */
  if (size < 2) return 0;
  edit(0, data, size, &o);
  edit(1, data, size, &o);
  /* and the capsules themselves, partially (unchanged by the target) */
  if (data[0] == 0 && data[1] == 0) {
    o.only = only;
    o.nonly = 1;
    for (k = 0; k < 2; k++) {
      nqchkx(dirs[k], &o, &r);
      nqrepfree(r);
      r = NULL;
    }
  }
  return 0;
}
