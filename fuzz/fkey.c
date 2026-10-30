/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the command line tool's key files (cli/key.c:
 * the "noqtis-key-1 <alg> <pub|sec>" line and the base64 body, read as
 * a public and as a secret key), and the library's handling of whatever
 * key they give: a public key verifies a fixed signature or
 * encapsulates (deterministically), a secret key signs (ML-DSA; SLH-DSA
 * signing is too slow to fuzz) or decapsulates. A key file is read from
 * a path, so each input is written to a scratch file under $TMPDIR (else
 * /tmp), removed at exit. */
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#include "fz.h"
#include "cli.h"

/* the tool's messages (cli/main.c), silenced */
void ncmsg(const char *cmd, const char *fmt, ...) {
  (void)cmd;
  (void)fmt;
}

int nclib(const char *cmd, const char *what, int rc) {
  (void)cmd;
  (void)what;
  (void)rc;
  return NCUSE;
}

static char dir[600], file[700];
static int ready = 0;

static void bye(void) {
  remove(file);
  remove(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *t = getenv("TMPDIR");
  (void)argc;
  (void)argv;
  snprintf(dir, sizeof dir, "%s/nqfkey.XXXXXX",
           t != NULL && *t != 0 ? t : "/tmp");
  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "fkey: cannot make a folder under %s\n", dir);
    return 0;
  }
  snprintf(file, sizeof file, "%s/k", dir);
  atexit(bye);
  ready = 1;
  return 0;
}

static void use(const nckey *k) {
  static const uint8_t msg[] = "noqtis fuzz";
  static uint8_t out[50000], ss[64], seed[64];
  size_t ol = 0;
  memset(seed, 7, sizeof seed);
  if (!k->a.kem && !k->sec) {
    nqssz z;
    if (nqssize((nqsalg)k->a.alg, &z) != NQOK || z.sig > sizeof out) return;
    memset(out, 0x5a, z.sig);
    if (nqvrfy((nqsalg)k->a.alg, k->b, k->n, msg, sizeof msg - 1, NULL, 0,
               0, out, z.sig) == NQOK) {
      abort(); /* a constant is no signature */
    }
  } else if (!k->a.kem) {
    if (k->a.alg <= NQMLDSA87) {
      (void)nqsignd((nqsalg)k->a.alg, k->b, k->n, msg, sizeof msg - 1,
                    NULL, 0, 0, seed, 32, out, sizeof out, &ol);
    }
  } else if (!k->sec) {
    (void)nqencd((nqkalg)k->a.alg, k->b, k->n, seed, fzeseed(k->a.alg),
                 out, sizeof out, ss, sizeof ss);
  } else {
    nqksz z;
    if (nqksize((nqkalg)k->a.alg, &z) != NQOK || z.ct > sizeof out) return;
    memset(out, 0xa5, z.ct);
    (void)nqdec((nqkalg)k->a.alg, k->b, k->n, out, z.ct, ss, sizeof ss);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f;
  nckey k;
  int sec;
  fzready(ready, "fkey");
  f = fopen(file, "wb");
  if (f == NULL) return 0;
  if (size != 0 && fwrite(data, 1, size, f) != size) {
    fclose(f);
    return 0;
  }
  if (fclose(f) != 0) return 0;
  for (sec = 0; sec < 2; sec++) {
    memset(&k, 0, sizeof k);
    if (nckrd("fkey", file, sec, &k) == NCOK) {
      size_t pk = 0, sk = 0;
      if (k.b == NULL || ncksz(&k.a, &pk, &sk) != NQOK ||
          k.n != (sec ? sk : pk)) {
        abort();
      }
      use(&k);
      nckfree(&k);
    }
  }
  return 0;
}
