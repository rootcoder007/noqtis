/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the proofs of format 2 capsules (nqchkp) and the
 * format 2 check (nqchkx with a partial check). At start it seals a small
 * format 2 capsule under $TMPDIR (else /tmp) with a fixed ML-DSA-44 key
 * and proves two of its files. Each input is then checked three ways: as
 * a proof by itself; as an edit of the good proof (two bytes of offset,
 * then the bytes to write there), so the mutations reach the audit paths,
 * the entries and the head past the parsers; and that edited proof
 * against the capsule's folder; and each input is also a key statement
 * (noqtis-keys-1) followed from the trusted key. The folder is removed
 * at exit. */
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#include <sys/stat.h>

#include "fz.h"
#include "cap/cap.h"

static char dir[600];
static char *good;
static size_t goodn;
static uint8_t pk[1312];
static int ready = 0;

static const char *const files[] = {"a.txt", "b.csv", "sub/c.bin"};

static void bye(void) {
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

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *t = getenv("TMPDIR");
  const char *ps[2] = {"b.csv", "sub/c.bin"};
  char p[700];
  uint8_t seed[32], sk[2560];
  size_t i;
  int rc;
  (void)argc;
  fzinit(argv);
  snprintf(dir, sizeof dir, "%s/nqfproof.XXXXXX",
           t != NULL && *t != 0 ? t : "/tmp");
  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "fproof: cannot make a folder under %s\n", dir);
    return 0;
  }
  atexit(bye);
  snprintf(p, sizeof p, "%s/sub", dir);
  mkdir(p, 0755);
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    if (!fzput(dir, files[i], files[i], strlen(files[i]))) return 0;
  }
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)i;
  if (nqskgd(NQMLDSA44, seed, sizeof seed, pk, sizeof pk, sk, sizeof sk) !=
          NQOK ||
      nqseal2(dir, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL,
              0) != NQOK) {
    fprintf(stderr, "fproof: cannot seal %s\n", dir);
    return 0;
  }
  nqwipe(sk, sizeof sk);
  rc = nqprove(dir, ps, 2, NULL, 0, &goodn);
  good = rc == NQEBUF ? (char *)malloc(goodn) : NULL;
  if (good != NULL) rc = nqprove(dir, ps, 2, good, goodn, &goodn);
  if (rc != NQOK) {
    fprintf(stderr, "fproof: cannot prove %s: %s\n", dir, nqerr(rc));
    return 0;
  }
  ready = 1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqcopt o;
  nqrep *r = NULL;
  char *e;
  size_t at, k;
  const char *only[1] = {"b.csv"};
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
    nqchkx(dir, &o, &r);
    nqrepfree(r);
    r = NULL;
    o.stmt = NULL;
    o.stmtlen = NULL;
    o.nstmt = 0;
  }
  /* an edit of the good proof */
  if (size < 2) return 0;
  at = ((size_t)data[0] << 8 | data[1]) % goodn;
  k = size - 2;
  if (k > goodn - at) k = goodn - at;
  e = (char *)malloc(goodn);
  if (e == NULL) return 0;
  memcpy(e, good, goodn);
  memcpy(e + at, data + 2, k);
  nqchkp(e, goodn, &o, NULL, &r);
  nqrepfree(r);
  r = NULL;
  nqchkp(e, goodn, &o, dir, &r);
  nqrepfree(r);
  r = NULL;
  free(e);
  /* and the capsule itself, partially (unchanged by the target) */
  if (data[0] == 0 && data[1] == 0) {
    o.only = only;
    o.nonly = 1;
    nqchkx(dir, &o, &r);
    nqrepfree(r);
  }
  return 0;
}
