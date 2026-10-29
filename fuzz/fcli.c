/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the command line (M10, "fuzzed arguments"): the
 * input's first byte picks a command, the rest is cut at NUL bytes into at
 * most 16 arguments, and the tool's own entry point runs them in a sandbox
 * folder of fixtures (a signature key pair, a KEM key pair, a message and
 * its signature, a sealed capsule). A run that changed the sandbox is
 * followed by a fresh one. No argument may hold "://" (no network), start
 * with "/" or hold ".." (nothing written outside the sandbox), and the slow
 * SLH-DSA "s" sets are skipped, so every run stays fast.
 *
 * Built with the CLI's sources compiled under -Dmain=nqclimain (see
 * fuzz/build.sh). */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int nqclimain(int argc, char **argv);
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const char *const cmds[] = {
    "keygen", "sign", "verify", "enc",     "dec",   "hash",    "seal",
    "check",  "inspect", "timestamp", "algs", "version", "help", "nope"};
#define NCMD (sizeof cmds / sizeof *cmds)
#define MAXA 16
#define MAXL 512

static char box[512];      /* the sandbox */
static char home[1024];    /* the folder libFuzzer started in */
static int nul = -1, keep[2] = {-1, -1};

/* the tool's output is not what is tested (its exit and memory are), and
 * libFuzzer prints to the same stderr: both go to /dev/null only while
 * the tool runs */
static void quiet(int on) {
  fflush(stdout);
  fflush(stderr);
  if (on) {
    keep[0] = dup(1);
    keep[1] = dup(2);
    dup2(nul, 1);
    dup2(nul, 2);
  } else {
    dup2(keep[0], 1);
    dup2(keep[1], 2);
    close(keep[0]);
    close(keep[1]);
  }
}
static unsigned long snap; /* a digest of its listing, as made */

/* runs the tool with a NULL-terminated list of arguments (setup only) */
static void cli(const char *a0, ...);

static void rmtree(const char *p) {
  struct stat st;
  if (lstat(p, &st) != 0) return;
  if (S_ISDIR(st.st_mode)) {
    DIR *d = opendir(p);
    struct dirent *e;
    char q[1024];
    if (d != NULL) {
      while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
          continue;
        snprintf(q, sizeof q, "%s/%s", p, e->d_name);
        rmtree(q);
      }
      closedir(d);
    }
    rmdir(p);
  } else {
    unlink(p);
  }
}

/* a cheap digest of every name, size, mode, inode and change time under p:
 * any file made, removed, rewritten or replaced changes it */
static unsigned long walk(const char *p, unsigned long h) {
  struct stat st;
  DIR *d;
  struct dirent *e;
  char q[1024];
  const char *c;
  if (lstat(p, &st) != 0) return h * 31u + 7u;
  for (c = p; *c; c++) h = h * 131u + (unsigned char)*c;
  h = h * 31u + (unsigned long)st.st_size;
  h = h * 31u + (unsigned long)st.st_mode;
  h = h * 31u + (unsigned long)st.st_ino;
  h = h * 31u + (unsigned long)st.st_ctime;
  if (!S_ISDIR(st.st_mode) || (d = opendir(p)) == NULL) return h;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    snprintf(q, sizeof q, "%s/%s", p, e->d_name);
    h ^= walk(q, 0);
  }
  closedir(d);
  return h;
}

static void put(const char *name, const char *text) {
  FILE *f = fopen(name, "wb");
  if (f == NULL) return;
  fputs(text, f);
  fclose(f);
}

static void make(void) {
  rmtree(box);
  if (mkdir(box, 0700) != 0 || chdir(box) != 0) abort();
  cli("keygen", "-a", "ML-DSA-44", "-o", "k", NULL);
  cli("keygen", "-a", "ML-KEM-512", "-o", "e", NULL);
  put("m", "a message\n");
  cli("sign", "-k", "k", "m", NULL);
  cli("enc", "-p", "e.pub", "-o", "m.ct", "m", NULL);
  mkdir("cap", 0755);
  mkdir("cap/sub", 0755);
  put("cap/a.txt", "hello\n");
  put("cap/sub/b.csv", "x,y\n1,2\n");
  cli("seal", "-k", "k", "cap", NULL);
  snap = walk(".", 0);
  /* libFuzzer reads and writes its corpus relative to where it started */
  if (chdir(home) != 0) abort();
}

static void cli(const char *a0, ...) {
  char *v[MAXA + 2];
  int n = 0;
  va_list ap;
  const char *a;
  v[n++] = (char *)"noqtis";
  v[n++] = (char *)a0;
  va_start(ap, a0);
  while ((a = va_arg(ap, const char *)) != NULL && n < MAXA + 1)
    v[n++] = (char *)a;
  va_end(ap);
  v[n] = NULL;
  (void)nqclimain(n, v);
}

static void done(void) { rmtree(box); }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *t = getenv("TMPDIR");
  (void)argc;
  (void)argv;
  snprintf(box, sizeof box, "%s/nqfcli.%ld", t != NULL && *t ? t : "/tmp",
           (long)getpid());
  if (getcwd(home, sizeof home) == NULL) abort();
  if (freopen("/dev/null", "r", stdin) == NULL) abort();
  nul = open("/dev/null", O_WRONLY);
  if (nul < 0) abort();
  quiet(1);
  make();
  quiet(0);
  atexit(done);
  return 0;
}

/* whether an argument may run: no network, nothing outside the sandbox,
 * no slow SLH-DSA set */
static int allowed(const char *a, size_t n) {
  size_t i;
  if (strstr(a, "://") != NULL || strstr(a, "..") != NULL || a[0] == '/')
    return 0;
  for (i = 0; i + 4 <= n; i++) {
    if ((a[i] == 's' || a[i] == 'S') && (a[i + 1] == 'l' || a[i + 1] == 'L') &&
        (a[i + 2] == 'h' || a[i + 2] == 'H'))
      return a[n - 1] != 's' && a[n - 1] != 'S';
  }
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *v[MAXA + 3], buf[MAXA][MAXL + 1];
  size_t i = 1, k;
  int n = 0;
  if (size == 0) return 0;
  v[n++] = (char *)"noqtis";
  v[n++] = (char *)cmds[data[0] % NCMD];
  while (i < size && n < MAXA + 2) {
    k = 0;
    while (i < size && data[i] != 0 && k < MAXL) buf[n - 2][k++] = (char)data[i++];
    buf[n - 2][k] = '\0';
    while (i < size && data[i] != 0) i++; /* the rest of a long argument */
    i++;
    if (!allowed(buf[n - 2], k)) return 0;
    v[n] = buf[n - 2];
    n++;
  }
  v[n] = NULL;
  quiet(1);
  if (chdir(box) != 0) abort();
  (void)nqclimain(n, v);
  if (chdir(box) != 0 || walk(".", 0) != snap) make();
  if (chdir(home) != 0) abort();
  quiet(0);
  return 0;
}
