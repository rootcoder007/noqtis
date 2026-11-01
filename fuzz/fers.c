/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over RFC 4998 evidence records (src/cap/ers.c): each
 * input is written as noqtis.ers into a scratch folder that holds the
 * golden sample capsule (tests/vectors/cap/sample), then checked as
 * nqchkt checks it (nqcersck, without anchors and with the capsule
 * tests' TSA root) and read as nqersreq reads it before a renewal, with
 * the record's hash and with SHA-512.
 *
 * The scratch folder is under $TMPDIR (else /tmp), removed at exit. */
#define _POSIX_C_SOURCE 200809L
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#include <sys/stat.h>

#include "fz.h"
#include "cap/cap.h"

static char dir[600];
static uint8_t *tsa;
static size_t tsan;
static int ready = 0;

static const char *const files[] = {"a.txt", "data/b.csv",
                                    "data/deep/c.bin", "empty",
                                    NQCSIG, NQCERS};

static void bye(void) {
  char p[700];
  size_t i;
  for (i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(p, sizeof p, "%s/%s", dir, files[i]);
    remove(p);
  }
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
  (void)argc;
  fzinit(argv);
  snprintf(dir, sizeof dir, "%s/nqfers.XXXXXX",
           t != NULL && *t != 0 ? t : "/tmp");
  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "fers: cannot make a folder under %s\n", dir);
    return 0;
  }
  atexit(bye);
  snprintf(p, sizeof p, "%s/data", dir);
  mkdir(p, 0755);
  snprintf(p, sizeof p, "%s/data/deep", dir);
  mkdir(p, 0755);
  for (i = 0; i < 5; i++) {
    snprintf(name, sizeof name, "cap/%s", files[i]);
    b = fzread(name, &n);
    if (b == NULL) return 0;
    if (!fzput(dir, files[i], b, n)) return 0;
    nqfree(b, n + 1);
  }
  tsa = fzread("tsa_root.der", &tsan);
  if (tsa == NULL) return 0;
  ready = 1;
  return 0;
}

static void chk(const uint8_t *anc, size_t an) {
  char msg[300];
  int pres = -1, rc;
  rc = nqcersck(dir, anc != NULL ? &anc : NULL, anc != NULL ? &an : NULL,
                anc != NULL ? 1 : 0, &pres, msg, sizeof msg);
  if (pres != 1) abort(); /* the record is there */
  if (rc != NQOK && rc != NQEVRFY && rc != NQEMEM) abort();
  /* no anchors: never passed */
  if (anc == NULL && rc == NQOK) abort();
  if (strlen(msg) == 0 && rc != NQEMEM) abort();
}

static void req(nqhalg h) {
  uint8_t q[160];
  size_t qn = 7;
  const char *why = NULL;
  int rc = nqersreq(dir, h, NULL, 0, q, sizeof q, &qn, &why);
  if (rc == NQOK && (qn == 0 || qn > sizeof q || q[0] != 0x30)) abort();
  if (rc != NQOK && qn != 0) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fzready(ready, "fers");
  if (nqcwrite(dir, NQCERS, (const char *)data, size) != NQOK) return 0;
  chk(NULL, 0);
  chk(tsa, tsan);
  req((nqhalg)0);
  req(NQS512);
  return 0;
}
