/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the capsule check (nqchk, nqchkt): the seal
 * noqtis.sig and the manifest noqtis.json are read from files, so each
 * input is written into a scratch folder that holds the golden sample's
 * other files (tests/vectors/cap/sample) and checked three ways: with
 * the key in the seal, pinned to the sample's key, and with the
 * capsule tests' TSA root as the timestamp anchor.
 *
 * Input: the seal, a NUL byte, the manifest (JSON holds no raw NUL).
 * Without a NUL the input is the manifest and the seal is the sample's.
 * The scratch folder is under $TMPDIR (else /tmp), removed at exit. */
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>

#include "fz.h"
#include "cap/cap.h"

static char dir[600];
static uint8_t *seal, *tsa, pk[1312];
static size_t sealn, tsan, pkn;
static int ready = 0;

/* the sample's files, relative to the fixtures and to dir */
static const char *const files[] = {"a.txt", "data/b.csv",
                                    "data/deep/c.bin", "empty"};

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
  snprintf(p, sizeof p, "%s/data/deep", dir);
  remove(p);
  snprintf(p, sizeof p, "%s/data", dir);
  remove(p);
  remove(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *t = getenv("TMPDIR");
  char p[700], name[64];
  size_t i, n;
  uint8_t *b;
  nqjs *v = NULL;
  const char *k;
  (void)argc;
  fzinit(argv);
  snprintf(dir, sizeof dir, "%s/nqfcap.XXXXXX",
           t != NULL && *t != 0 ? t : "/tmp");
  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "fcap: cannot make a folder under %s\n", dir);
    return 0;
  }
  atexit(bye);
  snprintf(p, sizeof p, "%s/data", dir);
  mkdir(p, 0755);
  snprintf(p, sizeof p, "%s/data/deep", dir);
  mkdir(p, 0755);
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(name, sizeof name, "cap/%s", files[i]);
    b = fzread(name, &n);
    if (b == NULL) return 0;
    if (nqcwrite(dir, files[i], (const char *)b, n) != NQOK) return 0;
    nqfree(b, n + 1);
  }
  seal = fzread("cap/noqtis.sig", &sealn);
  tsa = fzread("tsa_root.der", &tsan);
  if (seal == NULL || tsa == NULL) return 0;
  /* the sample's public key, for the pinned check */
  if (nqjparse((const char *)seal, sealn, &v, NULL) != NQOK) return 0;
  k = nqjstr(nqjget(v, "public_key"));
  if (k == NULL || nqb64d(k, strlen(k), pk, sizeof pk, &pkn) != NQOK) {
    nqjfree(v);
    return 0;
  }
  nqjfree(v);
  ready = 1;
  return 0;
}

static void run(const uint8_t *trust, size_t tn, const uint8_t *anc,
                size_t an) {
  nqrep *r = NULL;
  size_t i;
  int rc;
  if (anc != NULL) {
    rc = nqchkt(dir, trust, tn, &anc, &an, 1, &r);
  } else {
    rc = nqchk(dir, trust, tn, &r);
  }
  if ((rc == NQOK || rc == NQEVRFY) != (r != NULL)) abort();
  for (i = 0; i < nqrepn(r); i++) {
    const char *c, *d;
    int ok;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || strlen(c) == 0) abort();
    /* NQOK only when every row passed */
    if (rc == NQOK && !ok) abort();
    (void)strlen(d);
  }
  nqrepfree(r);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *z;
  const char *s = (const char *)seal, *m = (const char *)data;
  size_t sn = sealn, mn = size;
  if (!ready) return 0;
  z = (const uint8_t *)memchr(data, 0, size);
  if (z != NULL) {
    s = (const char *)data;
    sn = (size_t)(z - data);
    m = (const char *)z + 1;
    mn = size - sn - 1;
  }
  if (nqcwrite(dir, NQCSIG, s, sn) != NQOK ||
      nqcwrite(dir, NQCMAN, m, mn) != NQOK) {
    return 0;
  }
  run(NULL, 0, NULL, 0);
  run(pk, pkn, NULL, 0);
  run(NULL, 0, tsa, tsan);
  return 0;
}
