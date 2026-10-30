/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * Black-box tests of the noqtis tool: runs it the way a user does (through
 * the shell, stdout and stderr to files) and checks exit codes, outputs
 * and the files it writes.
 *
 *   tcli <path to noqtis> [<path to tsad> <tests/ in the source tree>]
 *
 * With tsad (tests/cli/tsad.c, a local TSA) it also runs seal --tsa and
 * check --anchor, and makes every check nqchk reports fail (the names are
 * read from src/cap/chk.c) to see that check says what to do about it,
 * and checks the capsules and bundle rmoriebricklayer made
 * (vectors/interop/bl).
 * The live TSA uses openssl when it is on the PATH.
 *
 * NQCLIWRAP, when set, is put in front of every command (for example
 * "valgrind -q --error-exitcode=9 --leak-check=full"). NQCLIALL=1 runs
 * every SLH-DSA parameter set instead of a sample.
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* snprintf that stops the test when the text does not fit: a cut command
 * or path would test something else (and GCC's -Wformat-truncation sees
 * every call checked) */
static void sn(char *o, size_t cap, const char *f, ...) {
  va_list ap;
  int n;
  va_start(ap, f);
  n = vsnprintf(o, cap, f, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= cap) {
    fprintf(stderr, "tcli: text too long for its buffer (%d >= %lu)\n", n,
            (unsigned long)cap);
    exit(2);
  }
}

static const char *exe;
static const char *wrap = "";
static int nrun, nbad;

/* ---- files ---- */

static unsigned char *rd(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  unsigned char *b;
  long l;
  *n = 0;
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (l = ftell(f)) < 0 ||
      fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  b = (unsigned char *)malloc((size_t)l + 1);
  if (b == NULL || fread(b, 1, (size_t)l, f) != (size_t)l) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  b[l] = 0;
  *n = (size_t)l;
  return b;
}

static void wr(const char *p, const void *b, size_t n) {
  FILE *f = fopen(p, "wb");
  if (f == NULL || fwrite(b, 1, n, f) != n) {
    fprintf(stderr, "tcli: cannot write %s\n", p);
    exit(2);
  }
  fclose(f);
}

static void wrs(const char *p, const char *s) {
  wr(p, s, strlen(s));
}

/* Flips one bit of byte i of file p. */
static void flip(const char *p, size_t i) {
  size_t n;
  unsigned char *b = rd(p, &n);
  if (b == NULL || n == 0) {
    fprintf(stderr, "tcli: cannot read %s\n", p);
    exit(2);
  }
  b[i % n] ^= 0x01;
  wr(p, b, n);
  free(b);
}

static void cp(const char *from, const char *to) {
  size_t n;
  unsigned char *b = rd(from, &n);
  if (b == NULL) {
    fprintf(stderr, "tcli: cannot read %s\n", from);
    exit(2);
  }
  wr(to, b, n);
  free(b);
}

static int same(const char *a, const char *b) {
  size_t an, bn;
  unsigned char *x = rd(a, &an), *y = rd(b, &bn);
  int r = x != NULL && y != NULL && an == bn && memcmp(x, y, an) == 0;
  free(x);
  free(y);
  return r;
}

static int exists(const char *p) {
  FILE *f = fopen(p, "rb");
  if (f == NULL)
    return 0;
  fclose(f);
  return 1;
}

/* 1 when the n bytes at s occur in file p */
static int infile(const char *p, const void *s, size_t n) {
  size_t fn, i;
  unsigned char *b = rd(p, &fn);
  int r = 0;
  if (b == NULL)
    return 0;
  for (i = 0; n > 0 && i + n <= fn && !r; i++)
    r = memcmp(b + i, s, n) == 0;
  free(b);
  return r;
}

static int has(const char *p, const char *s) {
  return infile(p, s, strlen(s));
}

static void hex(const unsigned char *b, size_t n, char *out) {
  static const char d[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = d[b[i] >> 4];
    out[2 * i + 1] = d[b[i] & 15];
  }
  out[2 * n] = '\0';
}

/* ---- running the tool ---- */

static void shell(const char *cmd) {
  if (system(cmd) == -1) {
    fprintf(stderr, "tcli: cannot run %s\n", cmd);
    exit(2);
  }
}

static void rmdirs(const char *d) {
  char c[256];
#ifdef _WIN32
  sn(c, sizeof c, "if exist %s rmdir /s /q %s", d, d);
#else
  sn(c, sizeof c, "rm -rf %s", d);
#endif
  shell(c);
}

/* a folder, made directly: cmd's mkdir reads "a/b" as a switch */
static void mkd(const char *d) {
#ifdef _WIN32
  (void)_mkdir(d);
#else
  (void)mkdir(d, 0777);
#endif
}

/* p as an absolute path (in a static buffer per slot), so the tests can
 * run in their own folder */
static const char *absp(const char *p, int slot) {
  static char b[3][4096];
#ifdef _WIN32
  if (_fullpath(b[slot], p, sizeof b[slot]) == NULL) return p;
#else
  char cwd[2048];
  if (p[0] == '/' || getcwd(cwd, sizeof cwd) == NULL) return p;
  sn(b[slot], sizeof b[slot], "%s/%s", cwd, p);
#endif
  return b[slot];
}

/* Runs noqtis with args (stdin from in when not NULL); returns its exit
 * status, or -1 if it did not exit normally. Output: q.out, q.err. */
static int run(const char *args, const char *in) {
  static char c[8192];
  int st, n;
#ifdef _WIN32
  n = snprintf(c, sizeof c, "\"%s\"%s\" %s <%s >q.out 2>q.err\"", wrap,
               exe, args, in != NULL ? in : "NUL");
#else
  n = snprintf(c, sizeof c, "%s'%s' %s <%s >q.out 2>q.err", wrap, exe,
               args, in != NULL ? in : "/dev/null");
#endif
  if (n < 0 || (size_t)n >= sizeof c) {
    fprintf(stderr, "tcli: command too long\n");
    exit(2);
  }
  st = system(c);
#ifndef _WIN32
  if (st == -1 || !WIFEXITED(st))
    return -1;
  st = WEXITSTATUS(st);
#endif
  return st;
}

static void dump(const char *p) {
  size_t n;
  unsigned char *b = rd(p, &n);
  if (b != NULL && n > 0)
    fprintf(stderr, "  %s: %.*s\n", p, (int)(n > 2000 ? 2000 : n),
            (const char *)b);
  free(b);
}

static void ok(int cond, const char *what) {
  nrun++;
  if (!cond) {
    nbad++;
    fprintf(stderr, "FAIL: %s\n", what);
  }
}

/* Runs and checks the exit status; a sanitizer or valgrind report in
 * stderr is a failure whatever the status. */
/* SOURCE_DATE_EPOCH for the next runs, or unset with NULL */
static void sde(const char *v) {
#ifdef _WIN32
  _putenv_s("SOURCE_DATE_EPOCH", v != NULL ? v : "");
#else
  if (v != NULL)
    setenv("SOURCE_DATE_EPOCH", v, 1);
  else
    unsetenv("SOURCE_DATE_EPOCH");
#endif
}

static void want(int code, const char *args, const char *in) {
  int st = run(args, in);
  int rep = has("q.err", "Sanitizer") || has("q.err", "runtime error:") ||
            has("q.err", "==ERROR") || has("q.err", "Invalid read") ||
            has("q.err", "Invalid write") || has("q.err", "uninitialised");
  nrun++;
  if (st != code || rep) {
    nbad++;
    fprintf(stderr, "FAIL: noqtis %s: exit %d, want %d%s\n", args, st,
            code, rep ? " (memory error report)" : "");
    dump("q.out");
    dump("q.err");
  }
}

/* ---- checks ---- */

static void tbasic(void) {
  want(0, "version", NULL);
  ok(has("q.out", "noqtis 0."), "version prints noqtis <version>");
  want(0, "--version", NULL);
  want(0, "algs", NULL);
  ok(has("q.out", "ML-DSA-65") && has("q.out", "SLH-DSA-SHAKE-128f") &&
     has("q.out", "ML-KEM-768") && has("q.out", "HQC"),
     "algs lists every family");
  want(0, "help", NULL);
  ok(has("q.out", "keygen") && has("q.out", "check"), "help lists commands");
  want(0, "help sign", NULL);
  ok(has("q.out", "usage: noqtis sign"), "help sign prints its usage");
  want(0, "sign --help", NULL);
  ok(has("q.out", "usage: noqtis sign"), "sign --help prints its usage");
  want(2, "", NULL);
  want(2, "help nosuch", NULL);
  want(2, "nosuch", NULL);
  want(2, "sign --nosuch q.k q.m", NULL);
  want(2, "sign", NULL);
  want(2, "keygen -a ML-DSA-44", NULL);
  want(2, "keygen -a NOPE-1 -o q.k", NULL);
  ok(!exists("q.k"), "a failed keygen writes nothing");
  want(2, "keygen -a ML-DSA-44 -o q.k extra", NULL);
  want(2, "verify -p q.k.pub q.m", NULL);
  want(2, "verify -p nosuch.pub -s nosuch.sig nosuch", NULL);
  want(2, "version extra", NULL);
  want(2, "keygen -a ML-DSA-44 -o", NULL);
  want(2, "keygen -a ML-DSA-44 --seed zz -o q.k", NULL);
  want(2, "keygen -a ML-DSA-44 --seed 0011 -o q.k", NULL);
  wrs("q.nk", "not a key\n");
  wrs("q.m", "hello\n");
  want(2, "sign -k q.nk q.m", NULL);
  wrs("q.nk", "noqtis-key-1 ML-DSA-44 sec\nAAAA\n");
  want(2, "sign -k q.nk q.m", NULL);
  wrs("q.nk", "noqtis-key-1 ML-DSA-44 sec\n!!!!\n");
  want(2, "sign -k q.nk q.m", NULL);
}

#ifndef _WIN32
static int priv(const char *p) {
  struct stat st;
  return stat(p, &st) == 0 && (st.st_mode & 077) == 0;
}
#endif

/* The secret key file's base64 lines must not appear in out or err. */
static void nosec(const char *key, const char *what) {
  size_t n, i, s;
  unsigned char *b = rd(key, &n);
  char m[200];
  int leak = 0;
  if (b == NULL) {
    ok(0, "secret key file readable");
    return;
  }
  for (i = 0; i < n && b[i] != '\n'; i++)
    ;
  /* every 24-character run of the body */
  for (s = i + 1; s + 24 <= n && !leak; s += 24) {
    if (memchr(b + s, '\n', 24) != NULL)
      continue;
    leak = infile("q.out", b + s, 24) || infile("q.err", b + s, 24);
  }
  free(b);
  sn(m, sizeof m, "%s: no secret key bytes on stdout/stderr", what);
  ok(!leak, m);
}

static void tsig(const char *alg, int full) {
  char a[512], m[256];
  sn(m, sizeof m, "%s round trip", alg);
  remove("q.k");
  remove("q.k.pub");
  remove("q.k2");
  remove("q.k2.pub");
  remove("q.sig");
  remove("q.m.sig");
  wrs("q.m", "the data an analysis used\n");
  sn(a, sizeof a, "keygen -a %s -o q.k", alg);
  want(0, a, NULL);
  nosec("q.k", alg);
  sn(m, sizeof m, "noqtis-key-1 %s sec\n", alg);
  ok(has("q.k", m), "secret key file header");
  sn(m, sizeof m, "noqtis-key-1 %s pub\n", alg);
  ok(has("q.k.pub", m), "public key file header");
#ifndef _WIN32
  ok(priv("q.k"), "secret key file is owner-only");
#endif
  want(0, "sign -k q.k q.m", NULL);
  ok(exists("q.m.sig"), "sign writes <file>.sig by default");
  ok(!has("q.out", "noqtis-key"), "sign prints no key");
  want(0, "verify -p q.k.pub -s q.m.sig q.m", NULL);
  ok(has("q.out", "OK"), "verify prints OK");
  want(0, "verify -q -p q.k.pub -s q.m.sig q.m", NULL);
  /* tampered message, signature, truncated signature */
  cp("q.m", "q.m2");
  flip("q.m2", 3);
  want(1, "verify -p q.k.pub -s q.m.sig q.m2", NULL);
  cp("q.m.sig", "q.bad");
  flip("q.bad", 100);
  want(1, "verify -p q.k.pub -s q.bad q.m", NULL);
  wrs("q.bad", "short");
  want(1, "verify -p q.k.pub -s q.bad q.m", NULL);
  /* the wrong kind of key file */
  want(2, "verify -p q.k -s q.m.sig q.m", NULL);
  want(2, "sign -k q.k.pub -o q.sig q.m", NULL);
  if (!full)
    return;
  /* refuses to overwrite */
  cp("q.m.sig", "q.keep");
  want(2, "sign -k q.k q.m", NULL);
  ok(same("q.m.sig", "q.keep"), "sign leaves an existing file alone");
  want(0, "sign --force -k q.k q.m", NULL);
  want(2, "keygen -a ML-DSA-44 -o q.k", NULL);
  want(0, "verify -p q.k.pub -s q.m.sig q.m", NULL);
  /* context */
  want(0, "sign -k q.k -c hello -o q.sig q.m", NULL);
  want(0, "verify -p q.k.pub -c hello -s q.sig q.m", NULL);
  want(1, "verify -p q.k.pub -s q.sig q.m", NULL);
  want(1, "verify -p q.k.pub -c other -s q.sig q.m", NULL);
  /* another key */
  sn(a, sizeof a, "keygen -a %s -o q.k2", alg);
  want(0, a, NULL);
  want(1, "verify -p q.k2.pub -s q.m.sig q.m", NULL);
  /* a signature is checked with <key>.pub before it is written */
  remove("q.sig3");
  cp("q.k", "q.k3");
  cp("q.k2.pub", "q.k3.pub");
  want(2, "sign -k q.k3 -o q.sig3 q.m", NULL);
  ok(has("q.err", "does not verify with q.k3.pub") && !exists("q.sig3"),
     "sign: a signature that does not verify is not written");
  remove("q.k3.pub");
  want(0, "sign -k q.k3 -o q.sig3 q.m", NULL);
  want(0, "verify -p q.k.pub -s q.sig3 q.m", NULL);
  /* stdin */
  want(0, "sign -k q.k -o q.sig --force -", "q.m");
  want(0, "verify -p q.k.pub -s q.sig q.m", NULL);
  want(0, "verify -p q.k.pub -s q.sig -", "q.m");
  want(2, "sign -k q.k -", "q.m");
}

static void tdet(void) {
  /* deterministic keys and signatures */
  static const char *xi =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  char a[512];
  remove("q.d1");
  remove("q.d1.pub");
  remove("q.d2");
  remove("q.d2.pub");
  remove("q.s1");
  remove("q.s2");
  sn(a, sizeof a, "keygen -a ml-dsa-44 --seed %s -o q.d1", xi);
  want(0, a, NULL);
  sn(a, sizeof a, "keygen -a ML-DSA-44 --seed %s -o q.d2", xi);
  want(0, a, NULL);
  ok(same("q.d1.pub", "q.d2.pub") && same("q.d1", "q.d2"),
     "keygen --seed is deterministic");
  wr("q.seed", "0123456789abcdef0123456789abcdef", 32);
  want(0, "keygen -a ML-DSA-44 --seed q.seed -o q.d2 --force", NULL);
  ok(!same("q.d1.pub", "q.d2.pub"), "--seed file differs from hex seed");
  want(0, "sign -d -k q.d1 -o q.s1 q.m", NULL);
  want(0, "sign -d -k q.d1 -o q.s2 q.m", NULL);
  ok(same("q.s1", "q.s2"), "sign -d is deterministic");
  want(0, "sign -k q.d1 -o q.s2 --force q.m", NULL);
  ok(!same("q.s1", "q.s2"), "sign without -d is randomized");
  want(0, "verify -p q.d1.pub -s q.s2 q.m", NULL);
  /* pre-hash */
  want(0, "sign --ph sha512 -k q.d1 -o q.s1 --force q.m", NULL);
  want(0, "verify --ph sha512 -p q.d1.pub -s q.s1 q.m", NULL);
  want(1, "verify -p q.d1.pub -s q.s1 q.m", NULL);
  want(1, "verify --ph sha256 -p q.d1.pub -s q.s1 q.m", NULL);
  want(2, "sign --ph nosuch -k q.d1 -o q.s1 --force q.m", NULL);
  /* SLH-DSA seed: SK.seed || SK.prf || PK.seed, 3n = 48 bytes */
  remove("q.d3");
  remove("q.d3.pub");
  remove("q.d4");
  remove("q.d4.pub");
  sn(a, sizeof a, "keygen -a SLH-DSA-SHAKE-128f --seed %s%s -o q.d3",
           xi, "000102030405060708090a0b0c0d0e0f");
  want(0, a, NULL);
  sn(a, sizeof a, "keygen -a SLH-DSA-SHAKE-128f --seed %s%s -o q.d4",
           xi, "000102030405060708090a0b0c0d0e0f");
  want(0, a, NULL);
  ok(same("q.d3.pub", "q.d4.pub"), "SLH-DSA keygen --seed is deterministic");
  want(0, "sign -d -k q.d3 -o q.s1 --force q.m", NULL);
  want(0, "sign -d -k q.d3 -o q.s2 --force q.m", NULL);
  ok(same("q.s1", "q.s2"), "SLH-DSA sign -d is deterministic");
  want(0, "verify -p q.d3.pub -s q.s1 q.m", NULL);
}

static void tkem(const char *alg) {
  char a[512], h[200], m[200];
  size_t n1, n2;
  unsigned char *s1, *s2;
  remove("q.e");
  remove("q.e.pub");
  remove("q.ct");
  remove("q.ss1");
  remove("q.ss2");
  remove("q.ss3");
  sn(a, sizeof a, "keygen -a %s -o q.e", alg);
  want(0, a, NULL);
  nosec("q.e", alg);
  want(0, "enc -p q.e.pub -o q.ct q.ss1", NULL);
  want(0, "dec -k q.e -o q.ss2 q.ct", NULL);
  s1 = rd("q.ss1", &n1);
  s2 = rd("q.ss2", &n2);
  sn(m, sizeof m, "%s: enc and dec agree", alg);
  ok(s1 != NULL && s2 != NULL && n1 == 32 && n2 == 32 &&
     memcmp(s1, s2, 32) == 0, m);
#ifndef _WIN32
  ok(priv("q.ss1") && priv("q.ss2"), "shared secret files are owner-only");
#endif
  if (s1 != NULL && n1 == 32) {
    hex(s1, 32, h);
    sn(m, sizeof m, "%s: no shared secret on stdout", alg);
    ok(!has("q.out", h) && !infile("q.out", s1, 32) && !has("q.err", h), m);
    want(0, "dec -k q.e --stdout q.ct", NULL);
    ok(has("q.out", h), "dec --stdout prints the secret in hex");
  }
  want(2, "dec -k q.e q.ct", NULL);
  want(2, "dec -k q.e -o q.ss2 q.ct", NULL);
  want(2, "dec -k q.e.pub -o q.ss3 q.ct", NULL);
  want(2, "enc -p q.e -o q.ct2 q.ss3", NULL);
  want(2, "enc -p q.k.pub -o q.ct2 q.ss3", NULL);
  wrs("q.bad", "short");
  want(2, "dec -k q.e -o q.ss3 q.bad", NULL);
  /* implicit rejection: a tampered ciphertext gives another secret */
  flip("q.ct", 7);
  want(0, "dec -k q.e -o q.ss3 q.ct", NULL);
  sn(m, sizeof m, "%s: a tampered ciphertext changes the secret", alg);
  ok(!same("q.ss1", "q.ss3"), m);
  want(0, "enc -p q.e.pub -o q.ct --force --stdout", NULL);
  ok(exists("q.ct"), "enc --stdout still writes the ciphertext");
  free(s1);
  free(s2);
}

static void thash(void) {
  wrs("q.h1", "abc");
  wr("q.h0", "", 0);
  want(0, "hash q.h1", NULL);
  ok(has("q.out", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
         "f20015ad  q.h1\n"), "sha256(abc), sha256sum format");
  want(0, "hash -a sha3-256 q.h1", NULL);
  ok(has("q.out", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245"
         "11431532  q.h1\n"), "sha3-256(abc)");
  want(0, "hash -a sha512 q.h1", NULL);
  ok(has("q.out", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee6"
         "4b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94f"
         "a54ca49f  q.h1\n"), "sha512(abc)");
  want(0, "hash -a sha224 q.h1", NULL);
  ok(has("q.out", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
         "  q.h1\n"), "sha224(abc)");
  want(0, "hash -a shake128 q.h1", NULL);
  ok(has("q.out", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351"
         "940f2cc8  q.h1\n"), "shake128(abc), 32 bytes");
  want(0, "hash q.h0 q.h1", NULL);
  ok(has("q.out", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
         "7852b855  q.h0\nba78"), "sha256 of an empty file, two files");
  cp("q.out", "q.sums");
  want(0, "hash", "q.h1");
  ok(has("q.out", "f20015ad  -\n"), "hash reads stdin");
  want(0, "hash --check q.sums", NULL);
  ok(has("q.out", "q.h1: OK"), "--check prints OK");
  wrs("q.h1", "abd");
  want(1, "hash -c q.sums", NULL);
  ok(has("q.out", "q.h1: FAILED"), "--check reports the changed file");
  wrs("q.h1", "abc");
  want(0, "hash -c q.sums", NULL);
  remove("q.h0");
  want(1, "hash -c q.sums", NULL);
  wrs("q.bad", "not a checksum line\n");
  want(1, "hash -c q.bad", NULL);
  want(1, "hash -a sha512 -c q.sums", NULL);
  mkd("q.dir");
  wrs("q.dsum", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
      "7852b855  q.dir\n");
  want(1, "hash -c q.dsum", NULL);
  ok(has("q.out", "q.dir: FAILED not a regular file"),
     "--check refuses a folder without reading it");
  want(2, "hash -c nosuch.sums", NULL);
  want(2, "hash -a nosuch q.h1", NULL);
  want(2, "hash nosuch", NULL);
}

static void tcap(void) {
  rmdirs("qcap");
  mkd("qcap");
  remove("q.c");
  remove("q.c.pub");
  remove("q.c2");
  remove("q.c2.pub");
  remove("q.ck");
  remove("q.ck.pub");
  wrs("qcap/a.txt", "first file\n");
  wrs("qcap/b.dat", "second file\n");
  wrs("q.meta", "{\"study\":\"tcli\"}");
  want(0, "keygen -a ML-DSA-65 -o q.c", NULL);
  want(0, "keygen -a ML-DSA-65 -o q.c2", NULL);
  want(0, "keygen -a ML-KEM-768 -o q.ck", NULL);
  want(2, "seal -k q.ck qcap", NULL);
  want(2, "seal -k q.c -p q.c2.pub qcap", NULL);
  want(0, "seal -k q.c --meta q.meta qcap", NULL);
  nosec("q.c", "seal");
  ok(exists("qcap/noqtis.json") && exists("qcap/noqtis.sig"),
     "seal writes noqtis.json and noqtis.sig");
  want(0, "check -p q.c.pub qcap", NULL);
  ok(has("q.out", "qcap: OK"), "check prints OK");
  want(0, "check qcap", NULL);
  want(0, "check --json -p q.c.pub qcap", NULL);
  ok(has("q.out", "\"ok\":true") && has("q.out", "\"checks\":["),
     "check --json");
  want(1, "check -p q.c2.pub qcap", NULL);
  /* a changed file */
  wrs("qcap/a.txt", "first file!\n");
  want(1, "check -p q.c.pub qcap", NULL);
  ok(has("q.out", "FAIL"), "check shows the failed row");
  want(1, "check --json -p q.c.pub qcap", NULL);
  ok(has("q.out", "\"ok\":false"), "check --json reports the failure");
  wrs("qcap/a.txt", "first file\n");
  want(0, "check -p q.c.pub qcap", NULL);
  /* an added file, a removed file, a changed manifest */
  wrs("qcap/c.txt", "extra\n");
  want(1, "check -p q.c.pub qcap", NULL);
  remove("qcap/c.txt");
  cp("qcap/b.dat", "q.b");
  remove("qcap/b.dat");
  want(1, "check -p q.c.pub qcap", NULL);
  cp("q.b", "qcap/b.dat");
  want(0, "check -p q.c.pub qcap", NULL);
  cp("qcap/noqtis.json", "q.j");
  flip("qcap/noqtis.json", 20);
  want(1, "check -p q.c.pub qcap", NULL);
  cp("q.j", "qcap/noqtis.json");
  cp("qcap/noqtis.sig", "q.j");
  flip("qcap/noqtis.sig", 200);
  want(1, "check -p q.c.pub qcap", NULL);
  cp("q.j", "qcap/noqtis.sig");
  want(0, "check -p q.c.pub qcap", NULL);
  want(2, "check -p q.ck.pub qcap", NULL);
  want(2, "check", NULL);
  rmdirs("qnone");
  want(2, "check -p q.c.pub qnone", NULL);
}

/* ---- timestamps (seal --tsa, check --anchor) through tsad ---- */

static const char *tsad;   /* tests/cli/tsad, the local TSA */
static const char *srcdir; /* tests/ in the source tree */

static void quoted(char *o, size_t cap, const char *p) {
#ifdef _WIN32
  sn(o, cap, "\"%s\"", p);
#else
  sn(o, cap, "'%s'", p);
#endif
}

/* Runs noqtis with args under tsad (mode, marg): the command goes to
 * q.cmd, tsad's own output to q.tsd. Returns noqtis's exit status. */
static int runts(const char *mode, const char *marg, const char *args) {
  static char c[8192], t[9000];
  char qm[1200];
  int st, n;
#ifdef _WIN32
  n = snprintf(c, sizeof c, "\"%s\"%s\" %s <NUL >q.out 2>q.err\"", wrap,
               exe, args);
#else
  n = snprintf(c, sizeof c, "%s'%s' %s </dev/null >q.out 2>q.err", wrap,
               exe, args);
#endif
  if (n < 0 || (size_t)n >= sizeof c) {
    fprintf(stderr, "tcli: command too long\n");
    exit(2);
  }
  wrs("q.cmd", c);
  quoted(qm, sizeof qm, marg);
#ifdef _WIN32
  sn(t, sizeof t, "\"\"%s\" q.cmd %s %s >q.tsd 2>&1\"", tsad, mode,
           qm);
#else
  sn(t, sizeof t, "'%s' q.cmd %s %s >q.tsd 2>&1", tsad, mode, qm);
#endif
  st = system(t);
#ifndef _WIN32
  if (st == -1 || !WIFEXITED(st))
    return -1;
  st = WEXITSTATUS(st);
#endif
  return st;
}

static void wantts(int code, const char *mode, const char *marg,
                   const char *args) {
  int st = runts(mode, marg, args);
  int rep = has("q.err", "Sanitizer") || has("q.err", "runtime error:") ||
            has("q.err", "==ERROR") || has("q.err", "Invalid read") ||
            has("q.err", "Invalid write") || has("q.err", "uninitialised");
  nrun++;
  if (st != code || rep) {
    nbad++;
    fprintf(stderr, "FAIL: tsad %s: noqtis %s: exit %d, want %d%s\n", mode,
            args, st, code, rep ? " (memory error report)" : "");
    dump("q.out");
    dump("q.err");
    dump("q.tsd");
  }
}

static void src(char *o, size_t cap, const char *rel) {
  sn(o, cap, "%s/%s", srcdir, rel);
}

/* base64 (RFC 4648, padded) of n bytes, NUL-terminated, new buffer */
static char *b64(const unsigned char *b, size_t n) {
  static const char a[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char *o = (char *)malloc(n / 3 * 4 + 8), *p = o;
  size_t i;
  if (o == NULL)
    exit(2);
  for (i = 0; i + 2 < n; i += 3, p += 4) {
    unsigned long v = ((unsigned long)b[i] << 16) |
                      ((unsigned long)b[i + 1] << 8) | b[i + 2];
    p[0] = a[v >> 18];
    p[1] = a[(v >> 12) & 63];
    p[2] = a[(v >> 6) & 63];
    p[3] = a[v & 63];
  }
  if (n - i == 1) {
    p[0] = a[b[i] >> 2];
    p[1] = a[(b[i] & 3) << 4];
    p[2] = p[3] = '=';
    p += 4;
  } else if (n - i == 2) {
    p[0] = a[b[i] >> 2];
    p[1] = a[((b[i] & 3) << 4) | (b[i + 1] >> 4)];
    p[2] = a[(b[i + 1] & 15) << 2];
    p[3] = '=';
    p += 4;
  }
  *p = '\0';
  return o;
}

/* replaces the first from in file p with to; 0 when from is not there */
static int sub(const char *p, const char *from, const char *to) {
  size_t n, fl = strlen(from), tl = strlen(to);
  unsigned char *b = rd(p, &n), *o;
  char *at;
  if (b == NULL)
    return 0;
  at = strstr((char *)b, from);
  if (at == NULL) {
    free(b);
    return 0;
  }
  o = (unsigned char *)malloc(n - fl + tl + 1);
  if (o == NULL)
    exit(2);
  memcpy(o, b, (size_t)(at - (char *)b));
  memcpy(o + (at - (char *)b), to, tl);
  memcpy(o + (at - (char *)b) + tl, at + fl,
         n - (size_t)(at - (char *)b) - fl);
  wr(p, o, n - fl + tl);
  free(o);
  free(b);
  return 1;
}

/* puts token file tok into dir's noqtis.sig as its timestamp (by hand,
 * as a forger or a damaged copy would) */
static void addts(const char *dir, const char *tok) {
  char p[600], *e, *t;
  size_t n;
  unsigned char *b = rd(tok, &n);
  if (b == NULL) {
    fprintf(stderr, "tcli: cannot read %s\n", tok);
    exit(2);
  }
  e = b64(b, n);
  free(b);
  t = (char *)malloc(strlen(e) + 32);
  if (t == NULL)
    exit(2);
  sprintf(t, "\",\"timestamp\":\"%s\"}", e);
  sn(p, sizeof p, "%s/noqtis.sig", dir);
  ok(sub(p, "\"}", t), "the seal ends in a string field");
  free(t);
  free(e);
}

static int haveossl;

/* a throwaway CA and TSA (EC P-256), named n: q.<n>r.der (the root,
 * DER), q.<n>t.pem, q.<n>t.key and q.<n>.rcmd, the reply command tsad
 * runs; 0 when openssl cannot make them or answer a request with them */
static int mktsa(const char *n) {
  char c[2048], f[64];
  sn(f, sizeof f, "q.%s.cnf", n);
  sn(c, sizeof c,
           "[ req ]\ndistinguished_name = dn\nprompt = no\n"
           "[ dn ]\nO = noqtis tcli\nCN = tcli TSA %s\n"
           "[ root ]\nbasicConstraints = critical,CA:true\n"
           "keyUsage = critical,keyCertSign,cRLSign\n"
           "subjectKeyIdentifier = hash\n"
           "[ tsaext ]\nbasicConstraints = critical,CA:false\n"
           "keyUsage = critical,digitalSignature\n"
           "extendedKeyUsage = critical,timeStamping\n"
           "subjectKeyIdentifier = hash\n"
           "authorityKeyIdentifier = keyid\n"
           "[ tsa ]\ndefault_tsa = t\n"
           "[ t ]\nserial = q.%s.ser\nsigner_digest = sha256\n"
           "default_policy = 1.2.3.4.1\ndigests = sha256, sha384, sha512\n"
           "accuracy = secs:1\nordering = no\ntsa_name = no\n"
           "ess_cert_id_chain = no\n", n, n);
  wrs(f, c);
  sn(c, sizeof c, "q.%s.ser", n);
  wrs(c, "01\n");
  sn(c, sizeof c,
           "(openssl ecparam -name prime256v1 -genkey -noout -out q.%sr.key"
           " && openssl ecparam -name prime256v1 -genkey -noout "
           "-out q.%st.key"
           " && openssl req -x509 -new -key q.%sr.key -out q.%sr.pem -days 3"
           " -config q.%s.cnf -extensions root -sha256"
           " && openssl req -new -key q.%st.key -out q.%st.csr"
           " -config q.%s.cnf"
           " && openssl x509 -req -in q.%st.csr -CA q.%sr.pem"
           " -CAkey q.%sr.key -set_serial 7 -days 2 -extfile q.%s.cnf"
           " -extensions tsaext -out q.%st.pem -sha256"
           " && openssl x509 -in q.%sr.pem -outform DER -out q.%sr.der"
           ") >q.ossl 2>&1",
           n, n, n, n, n, n, n, n, n, n, n, n, n, n, n);
  if (system(c) != 0 || !exists(f))
    return 0;
  sn(c, sizeof c, "q.%sr.der", n);
  if (!exists(c))
    return 0;
  sn(c, sizeof c,
           "openssl ts -reply -config q.%s.cnf -section t -queryfile q.tsq "
           "-signer q.%st.pem -inkey q.%st.key -out q.tsr", n, n, n);
  sn(f, sizeof f, "q.%s.rcmd", n);
  wrs(f, c);
  /* the reply command must work here (LibreSSL's ts differs a little) */
  remove("q.tsr");
  strcat(c, " >q.ossl 2>&1");
  if (system("openssl ts -query -data q.c.pub -sha256 -cert -out q.tsq "
             ">q.ossl 2>&1") != 0 || system(c) != 0 || !exists("q.tsr"))
    return 0;
  return 1;
}

static void tts(void) {
  char tok[1200], a[2000], x[1200];
  int i;
  rmdirs("qts");
  mkd("qts");
  wrs("qts/a.txt", "stamped\n");
  src(tok, sizeof tok, "vectors/cap/tsa/sample.tok");
  /* refused before anything is sealed */
#ifndef NQTLSON
  want(2, "seal -k q.c --tsa https://tsa.example/ qts", NULL);
  ok(has("q.err", "https:// is not supported") &&
     has("q.err", "give the TSA's http:// URL"), "seal refuses https");
#else
  /* with the TLS client, https:// is a URL like any other */
  want(2, "seal -k q.c --tsa https://127.0.0.1:1/ qts", NULL);
  ok(has("q.err", "cannot connect") && !exists("qts/noqtis.sig"),
     "seal tries https, and seals nothing without its timestamp");
#endif
  want(2, "seal -k q.c --tsa ftp://tsa.example/ qts", NULL);
  ok(has("q.err", "not an http:// URL"), "seal refuses another scheme");
  want(2, "seal -k q.c --tsa http://tsa.example:99999/ qts", NULL);
  ok(has("q.err", "port"), "seal refuses a bad port");
  want(2, "seal -k q.c --anchor q.none qts", NULL);
  ok(has("q.err", "give --tsa <url> too"), "--anchor needs --tsa");
  strcpy(a, "seal -k q.c");
  for (i = 0; i < 33; i++)
    strcat(a, " --tsa http://127.0.0.1:1/");
  strcat(a, " qts");
  want(2, a, NULL);
  ok(has("q.err", "at most 32 times"), "at most 32 --tsa");
  ok(!exists("qts/noqtis.sig"), "nothing sealed after a refused --tsa");
  /* timestamp: a --tsa, and a capsule that reads, are needed first */
  want(2, "timestamp qts", NULL);
#ifndef NQTLSON
  want(2, "timestamp --tsa https://tsa.example/ qts", NULL);
  ok(has("q.err", "https:// is not supported"), "timestamp refuses https");
#endif
  want(2, "timestamp --tsa http://127.0.0.1:1/ qts", NULL);
  ok(has("q.err", "is not a sealed capsule"), "timestamp needs a seal");
  want(2, "timestamp --tsa http://127.0.0.1:1/ no-such-folder", NULL);
  want(0, "help timestamp", NULL);
  /* the TSA answers, but not with a token over this seal: the seal is
   * removed, never left without its timestamp */
  wantts(2, "file", tok, "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "imprint is not the hash of this seal's signature") &&
     has("q.err", "removed noqtis.json and noqtis.sig"),
     "seal refuses a token over another signature");
  ok(!exists("qts/noqtis.sig") && !exists("qts/noqtis.json"),
     "a failed --tsa leaves no seal");
  ok(exists("q.tsq") && infile("q.tsq", "\x30", 1),
     "seal sends a DER request");
  wantts(2, "chunk", tok, "seal -k q.c --tsa http://127.0.0.1:@PORT@/x qts");
  ok(has("q.err", "imprint is not"), "seal reads a chunked reply");
  wantts(2, "short", tok, "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "shorter than its Content-Length"), "a cut reply");
  wantts(2, "type", tok, "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "text/html, not application/timestamp-reply"),
     "a reply of another type");
  wantts(2, "http", "404", "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "HTTP 404"), "an HTTP error");
  wantts(2, "http", "302", "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "moved to http://tsa.example/new; give that URL"),
     "a redirect names the new URL");
  wantts(2, "junk", "", "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  ok(has("q.err", "not HTTP/1.x"), "a reply that is not HTTP");
  wantts(2, "http", "200",
         "seal -k q.c --tsa http://127.0.0.1:@DEAD@/ qts");
  ok(has("q.err", "cannot connect to 127.0.0.1 port"), "a closed port");
  /* a live local TSA (openssl ts -reply), when openssl is there */
  haveossl = system("openssl version >q.ossl 2>&1") == 0 && mktsa("a") &&
             mktsa("b");
  if (!haveossl) {
    printf("tcli: no working openssl; the live TSA checks are skipped\n");
    return;
  }
  /* LibreSSL (macOS's /usr/bin/openssl) ignores signer_digest and signs
   * the reply with SHA-1, which noqtis refuses: check that it does, then
   * skip the checks that need a SHA-256 reply */
  if (system("openssl version >q.over 2>&1") == 0 &&
      has("q.over", "LibreSSL")) {
    wantts(2, "ossl", "q.a.rcmd",
           "seal -k q.c --tsa http://127.0.0.1:@PORT@/tsr qts");
    ok(has("q.err", "SHA-1"), "a SHA-1 signed reply is refused as such");
    printf("tcli: openssl is LibreSSL; the live TSA checks are skipped\n");
    return;
  }
  wantts(0, "ossl", "q.a.rcmd",
         "seal -k q.c --tsa http://127.0.0.1:@DEAD@/ "
         "--tsa http://127.0.0.1:@PORT@/tsr qts");
  ok(has("q.err", "cannot connect") && has("q.out", "timestamp from "
     "http://127.0.0.1:") && has("q.out", "genTime 20"),
     "seal falls back to the next --tsa");
  ok(has("q.err", "no --anchor given"), "seal says the TSA was not checked");
  want(0, "check -p q.c.pub --anchor q.ar.der qts", NULL);
  ok(has("q.out", "verifies under a TSA anchor; genTime 20"),
     "check --anchor passes a live token");
  /* a revoked key: the verified genTime decides */
  want(0, "revoke -k q.c --at 2099-01-01T00:00:00Z -o q.rv1", NULL);
  want(0, "check -p q.c.pub --anchor q.ar.der --keys q.rv1 qts", NULL);
  ok(has("q.out", "before its key was revoked"),
     "check --keys: a timestamp from before the revocation");
  want(0, "revoke -k q.c --at 2000-01-01T00:00:00Z -o q.rv2", NULL);
  want(1, "check -p q.c.pub --anchor q.ar.der --keys q.rv2 qts", NULL);
  ok(has("q.out", "after its key was revoked"),
     "check --keys: a timestamp from after the revocation");
  remove("q.rv1");
  remove("q.rv2");
  want(0, "check -p q.c.pub --anchor q.br.der --anchor q.ar.der qts", NULL);
  want(1, "check -p q.c.pub --anchor q.br.der qts", NULL);
  ok(has("q.err", "noqtis check: timestamp: the token is not from a TSA "
     "under the anchors given"), "the other TSA's anchor fails");
  want(1, "check -p q.c.pub qts", NULL);
  ok(has("q.err", "--anchor <der-file>"), "no anchor: check says to give one");
  /* the second authority, verified at seal time */
  wantts(0, "osslc", "q.b.rcmd",
         "seal -k q.c --tsa http://127.0.0.1:@PORT@/ --anchor q.br.der qts");
  ok(has("q.out", "verified under a TSA anchor"), "seal --anchor");
  want(0, "check -p q.c.pub --anchor q.ar.der --anchor q.br.der qts", NULL);
  want(1, "check -p q.c.pub --anchor q.ar.der qts", NULL);
  wantts(2, "ossl", "q.a.rcmd",
         "seal -k q.c --tsa http://127.0.0.1:@PORT@/ --anchor q.br.der qts");
  ok(has("q.err", "no valid path to a given anchor") &&
     !exists("qts/noqtis.sig"), "seal --anchor refuses another TSA");
  /* anchors that are not DER certificates */
  wantts(0, "ossl", "q.a.rcmd",
         "seal -k q.c --tsa http://127.0.0.1:@PORT@/ qts");
  want(2, "check -p q.c.pub --anchor q.ar.pem qts", NULL);
  ok(has("q.err", "is PEM; give the DER form"), "check refuses a PEM anchor");
  want(2, "check -p q.c.pub --anchor q.none qts", NULL);
  ok(has("q.err", "cannot read TSA anchor q.none"), "a missing anchor");
  want(2, "check -p q.c.pub --anchor q.a.cnf qts", NULL);
  ok(has("q.err", "not a DER certificate"), "an anchor that is not DER");
  sn(x, sizeof x, "check -p q.c.pub --anchor q.ar.der --json qts");
  want(0, x, NULL);
  ok(has("q.out", "\"ok\":true"), "check --anchor --json");
  /* noqtis timestamp on a capsule sealed before */
  want(2, "timestamp --tsa http://127.0.0.1:1/ qts", NULL);
  ok(has("q.err", "already has a timestamp"),
     "timestamp keeps a timestamp the seal has");
  wantts(0, "ossl", "q.a.rcmd",
         "timestamp --force --tsa http://127.0.0.1:@PORT@/tsr qts");
  ok(has("q.out", "timestamped qts (the old timestamp was replaced)"),
     "timestamp --force replaces it");
  want(0, "check -p q.c.pub --anchor q.ar.der qts", NULL);
  want(0, "seal -k q.c qts", NULL);
  want(0, "inspect qts", NULL);
  ok(has("q.out", "timestamp  none"), "a seal without a timestamp");
  wantts(0, "osslc", "q.b.rcmd",
         "timestamp --tsa http://127.0.0.1:@PORT@/ --anchor q.br.der qts");
  ok(has("q.out", "verified under a TSA anchor") &&
     has("q.out", "timestamped qts\n"), "timestamp --anchor");
  want(0, "check -p q.c.pub --anchor q.br.der qts", NULL);
  want(0, "inspect qts", NULL);
  ok(has("q.out", "timestamp  present"), "inspect sees the timestamp");
  /* a reply that does not check writes nothing */
  want(0, "seal -k q.c qts", NULL);
  wantts(2, "ossl", "q.a.rcmd",
         "timestamp --tsa http://127.0.0.1:@PORT@/ --anchor q.br.der qts");
  ok(has("q.err", "qts is unchanged"), "a refused reply: unchanged");
  want(0, "inspect qts", NULL);
  ok(has("q.out", "timestamp  none"), "still no timestamp");
  want(0, "check -p q.c.pub qts", NULL);
}

/* ---- rmoriebricklayer interop: its fixtures, checked by noqtis ----
 *
 * vectors/interop/bl (tests/interop/gen.sh): two capsules sealed by
 * rmoriebricklayer in the noqtis format, and one of its own bundles,
 * whose attestation signature and file digests noqtis checks. */

static void tbl(void) {
  static const char *caps[] = {"mldsa", "slh"};
  static const char *files[] = {"data/table.csv", "readme.txt",
                                "noqtis.json", "noqtis.sig"};
  char p[1200], k[1200], qp[1300], qk[1300], c[6000], f[1300];
  size_t i, j, n;
  unsigned char *b;
  for (i = 0; i < 2; i++) {
    sn(c, sizeof c, "vectors/interop/bl/%s", caps[i]);
    src(p, sizeof p, c);
    sn(c, sizeof c, "vectors/interop/bl/%s.pub", caps[i]);
    src(k, sizeof k, c);
    quoted(qp, sizeof qp, p);
    quoted(qk, sizeof qk, k);
    sn(c, sizeof c, "check -p %s %s", qk, qp);
    want(0, c, NULL);
    ok(has("q.out", "OK (") && has("q.out", "signature over noqtis.json "
       "is valid"), "a capsule sealed by rmoriebricklayer checks");
    sn(c, sizeof c, "check -p q.c.pub %s", qp);
    want(1, c, NULL);
    /* a copy with one file changed fails */
    rmdirs("qbl");
    mkd("qbl");
    mkd("qbl/data");
    for (j = 0; j < 4; j++) {
      char t[64];
      sn(f, sizeof f, "%s/%s", p, files[j]);
      sn(t, sizeof t, "qbl/%s", files[j]);
      cp(f, t);
    }
    sn(c, sizeof c, "check -p %s qbl", qk);
    want(0, c, NULL);
    wrs("qbl/readme.txt", "changed\n");
    want(1, c, NULL);
    ok(has("q.out", "FAIL  file") && has("q.out", "readme.txt"),
       "a changed file in rmoriebricklayer's capsule fails");
  }
  /* its own bundle: the attestation signature, under its context */
  src(p, sizeof p, "vectors/interop/bl/bundle/attest.ctx");
  b = rd(p, &n);
  ok(b != NULL && n > 0 && n < 200, "the bundle's context");
  if (b == NULL)
    return;
  src(p, sizeof p, "vectors/interop/bl/bundle");
#ifdef _WIN32
  sn(c, sizeof c, "verify -p \"%s/attest.pub\" -s \"%s/attest.sig\" "
           "-c %s \"%s/attest.msg\"", p, p, (char *)b, p);
#else
  sn(c, sizeof c, "verify -p '%s/attest.pub' -s '%s/attest.sig' "
           "-c %s '%s/attest.msg'", p, p, (char *)b, p);
#endif
  want(0, c, NULL);
  ok(has("q.out", "attest.msg: OK (ML-DSA-65)"),
     "noqtis verifies rmoriebricklayer's attestation signature");
  free(b);
  /* and the SHA-256 it recorded of each file */
  sn(f, sizeof f, "%s/files.sha256", p);
  b = rd(f, &n);
  ok(b != NULL, "the bundle's file digests");
  if (b != NULL) {
    FILE *o = fopen("q.blsums", "wb");
    char *l = (char *)b, *e;
    while (o != NULL && (e = strchr(l, '\n')) != NULL) {
      *e = '\0';
      if (strlen(l) > 66)
        fprintf(o, "%.64s  %s/files/%s\n", l, p, l + 66);
      l = e + 1;
    }
    if (o != NULL)
      fclose(o);
    free(b);
    want(0, "hash --check q.blsums", NULL);
    ok(has("q.out", "table.csv: OK") && has("q.out", "readme.txt: OK"),
       "the files match the digests rmoriebricklayer bundled");
  }
}

/* ---- every refusal of check says what failed and what to do ---- */

/* the check names nqchk can report, read from src/cap/chk.c */
static char names[64][32];
static int nnames, seen[64];

static void rdnames(void) {
  char p[1200];
  size_t n, i;
  unsigned char *b;
  src(p, sizeof p, "../src/cap/chk.c");
  b = rd(p, &n);
  ok(b != NULL, "tcli reads src/cap/chk.c");
  if (b == NULL)
    return;
  for (i = 0; i + 8 < n; i++) {
    size_t k = 0;
    int j, dup = 0;
    if (memcmp(b + i, "add(r, \"", 8) != 0)
      continue;
    i += 8;
    while (i < n && b[i] != '"' && k < 31)
      names[nnames][k++] = (char)b[i++];
    names[nnames][k] = '\0';
    if (strncmp(names[nnames], "info.", 5) == 0 ||
        strcmp(names[nnames], "partial") == 0)
      continue; /* nqinsp's facts, and what a partial check left out:
                   never a failing check */
    for (j = 0; j < nnames; j++)
      dup |= strcmp(names[j], names[nnames]) == 0;
    if (!dup && nnames < 63)
      nnames++;
  }
  free(b);
  ok(nnames >= 20, "chk.c names at least 20 checks");
}

/* checks the last run: every FAIL row has its advice on stderr, none is
 * the fallback, and want (a check name) failed */
static void advice(const char *want, const char *what) {
  size_t n, i;
  unsigned char *b = rd("q.out", &n);
  int got = 0, j;
  char line[64], pat[96], msg[200];
  ok(b != NULL, what);
  if (b == NULL)
    return;
  for (i = 0; i < n; i++) {
    size_t k = 0;
    if ((i == 0 || b[i - 1] == '\n') && n - i > 6 &&
        memcmp(b + i, "FAIL  ", 6) == 0) {
      i += 6;
      while (i < n && b[i] != ' ' && k < sizeof line - 16)
        line[k++] = (char)b[i++];
      line[k] = '\0';
      for (j = 0; j < nnames; j++) {
        if (strcmp(names[j], line) == 0)
          seen[j] = 1;
      }
      if (strcmp(line, want) == 0)
        got = 1;
      sn(pat, sizeof pat, "noqtis check: %s: ", line);
      sn(msg, sizeof msg, "%s: advice for a failed %s row", what,
               line);
      ok(has("q.err", pat), msg);
    }
  }
  free(b);
  sn(msg, sizeof msg, "%s: fails %s", what, want);
  ok(got, msg);
  sn(msg, sizeof msg, "%s: no row without advice", what);
  ok(!has("q.err", "no advice for this check"), msg);
}

/* one refusal: runs args (a check), which must fail chk with advice */
static void ref1(const char *chk, const char *what, int code,
                 const char *args) {
  want(code, args, NULL);
  advice(chk, what);
}

static void pristine(void) {
  rmdirs("qref");
  mkd("qref");
  mkd("qref/sub");
  wrs("qref/a.txt", "first\n");
  wrs("qref/b.txt", "second\n");
  wrs("qref/sub/c.txt", "third\n");
  want(0, "seal -k q.c qref", NULL);
}

/* check <url>: the capsule served by tsad's www mode from this folder */
static void tremote(void) {
#define URL " http://127.0.0.1:@PORT@/qref"
  pristine();
  wantts(0, "www", ".", "check -p q.c.pub" URL);
  ok(has("q.out", "/qref: OK (") && has("q.tsd", "served 5 requests"),
     "check <url>: the seal, the manifest and three files fetched");
  wantts(1, "www", ".", "check -p q.c2.pub" URL);
  ok(has("q.err", "no file was fetched") &&
     has("q.tsd", "served 2 requests"),
     "check <url>: another key, so no file is fetched");
  want(0, "seal --format 2 -k q.c qref", NULL);
  wantts(0, "www", ".", "check -p q.c.pub --only sub/c.txt" URL "/");
  ok(has("q.out", "partial") && has("q.tsd", "served 3 requests"),
     "check --only <url>: one file fetched");
  wrs("qref/b.txt", "second!\n");
  wantts(1, "www", ".", "check -p q.c.pub" URL);
  ok(has("q.out", "FAIL  file"), "check <url>: a changed file");
  want(0, "seal --format 2 -k q.c qref", NULL);
  want(0, "prove -p q.c.pub -o q.pf qref a.txt", NULL);
  wantts(0, "www", ".",
         "check -p q.c.pub --proof http://127.0.0.1:@PORT@/q.pf");
  ok(has("q.out", "q.pf: OK ("), "check --proof <url>");
  remove("q.pf");
  wantts(1, "www", ".", "check -p q.c.pub http://127.0.0.1:@PORT@/none");
  ok(has("q.err", "HTTP 404"), "check <url>: nothing there");
  want(2, "check -p q.c.pub http://127.0.0.1:1/qref?x=1", NULL);
  ok(has("q.err", "without a query"), "check <url>: a query refused");
#undef URL
}

/* export: in-toto, DSSE (and verify --dsse), RO-Crate, BagIt */
static void texport(void) {
  pristine();
  want(0, "seal --format 2 -k q.c qref", NULL);
  want(0, "export --as intoto -o q.st qref", NULL);
  ok(has("q.st", "\"_type\":\"https://in-toto.io/Statement/v1\"") &&
     has("q.st", "\"name\":\"sub/c.txt\"") &&
     has("q.st", "\"predicateType\":\"https://rootcoder007.github.io/"
         "noqtis/spec/capsule/\""),
     "export --as intoto: a statement of the files");
  want(0, "export --as dsse -k q.c -o q.env qref", NULL);
  want(0, "verify -p q.c.pub --dsse -o q.pl q.env", NULL);
  ok(has("q.out", "payloadType application/vnd.in-toto+json") &&
     same("q.pl", "q.st"), "verify --dsse: the statement comes back");
  want(1, "verify -p q.c2.pub --dsse q.env", NULL);
  sub("q.env", "\"payload\":\"ey", "\"payload\":\"ex");
  want(1, "verify -p q.c.pub --dsse q.env", NULL);
  want(2, "verify -p q.c.pub --dsse -s q.st q.env", NULL);
  want(0, "export --as rocrate -o q.ro qref", NULL);
  ok(has("q.ro", "\"conformsTo\":{\"@id\":\"https://w3id.org/ro/crate/"
         "1.1\"}") && has("q.ro", "{\"@id\":\"sub/c.txt\",\"@type\":"
         "\"File\""), "export --as rocrate: every file, with its digest");
  rmdirs("q.bag");
  want(0, "export --as bagit -o q.bag qref", NULL);
  ok(has("q.out", "3 files, 19 bytes") &&
     has("q.bag/bagit.txt", "BagIt-Version: 1.0\nTag-File-Character-"
         "Encoding: UTF-8\n") &&
     has("q.bag/bag-info.txt", "Payload-Oxum: 19.3") &&
     has("q.bag/manifest-sha256.txt", "  data/sub/c.txt\n") &&
     same("q.bag/data/b.txt", "qref/b.txt") &&
     same("q.bag/noqtis.sig", "qref/noqtis.sig"),
     "export --as bagit: the bag, its data and its tags");
  want(2, "export --as bagit -o q.bag qref", NULL);
  ok(has("q.err", "exists"), "export --as bagit: an existing folder");
  rmdirs("q.bag");
  /* refusals: a capsule that does not check, options that do not fit */
  wrs("qref/a.txt", "first!\n");
  want(1, "export --as intoto qref", NULL);
  ok(has("q.err", "does not check"), "export: a capsule that does not check");
  want(2, "export --as dsse qref", NULL);
  want(2, "export --as intoto -k q.c qref", NULL);
  want(2, "export --as bagit qref", NULL);
  want(2, "export --as zip qref", NULL);
  remove("q.st");
  remove("q.env");
  remove("q.pl");
  remove("q.ro");
}

static void trefuse(void) {
  char tok[1200], oth[1200], ctx[1400];
  int j;
  rdnames();
  src(tok, sizeof tok, "vectors/cap/tsa/sample.tok");
  src(oth, sizeof oth, "vectors/cap/tsa/other.der");
#define CHK "check -p q.c.pub qref"
  pristine();
  remove("qref/noqtis.sig");
  ref1("seal.read", "no seal", 1, CHK);
  wrs("qref/noqtis.sig", "not json");
  ref1("seal.parse", "seal not JSON", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "{\"alg\"", "{ \"alg\"");
  ref1("seal.canonical", "seal not canonical", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "\"format\"", "\"extra\":\"x\",\"format\"");
  ref1("seal.fields", "seal with an unknown field", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "noqtis-seal-1", "noqtis-seal-9");
  ref1("seal.format", "seal of another format", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "ML-DSA-65", "ML-DSA-99");
  ref1("seal.alg", "seal of an unknown algorithm", 1, CHK);
  pristine();
  memset(ctx, 'c', 300);
  ctx[300] = '\0';
  sub("qref/noqtis.sig", "noqtis-capsule-1", ctx);
  ref1("seal.context", "seal context over 255 bytes", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "\"public_key\":\"", "\"public_key\":\"AAAA");
  ref1("seal.key", "seal key damaged", 1, CHK);
  pristine();
  sub("qref/noqtis.sig", "\"signature\":\"", "\"signature\":\"AAAA");
  ref1("seal.signature", "seal signature damaged", 1, CHK);
  pristine();
  remove("qref/noqtis.json");
  ref1("manifest.read", "no manifest", 1, CHK);
  wrs("qref/noqtis.json", "not json");
  ref1("manifest.parse", "manifest not JSON", 1, CHK);
  pristine();
  sub("qref/noqtis.json", "first", "first");
  sub("qref/noqtis.json", "\"size\":6", "\"size\":7");
  ref1("manifest.digest", "manifest changed", 1, CHK);
  advice("signature", "manifest changed");
  pristine();
  sub("qref/noqtis.json", "{\"created\"", "{ \"created\"");
  ref1("manifest.canonical", "manifest not canonical", 1, CHK);
  pristine();
  sub("qref/noqtis.json", "\"noqtis-capsule-1\"",
      "\"noqtis-capsule-1\",\"zzz\":1");
  ref1("manifest.fields", "manifest with an unknown field", 1, CHK);
  pristine();
  sub("qref/noqtis.json", "noqtis-capsule-1", "noqtis-capsule-9");
  ref1("manifest.format", "manifest of another format", 1, CHK);
  pristine();
  sub("qref/noqtis.json", "\"created\":\"", "\"created\":\"x");
  ref1("manifest.created", "manifest created not RFC 3339", 1, CHK);
  pristine();
  sub("qref/noqtis.json", "\"a.txt\"", "\"c.txt\"");
  ref1("manifest.order", "manifest out of order", 1, CHK);
  advice("file", "manifest out of order");
  advice("extra", "manifest out of order");
  /* key statements: a rotation followed, a changed one, a revoked key */
  pristine();
  want(0, "rotate -k q.c -n q.c2 --at 2026-01-01T00:00:00Z -o q.rot", NULL);
  want(0, "seal -k q.c2 qref", NULL);
  want(0, "check -p q.c.pub --keys q.rot qref", NULL);
  ok(has("q.out", "successor by 1 rotation"),
     "check --keys: a rotation followed");
  want(1, "check -p q.c.pub qref", NULL);
  sub("q.rot", "\"reason\":\"\"", "\"reason\":\"x\"");
  ref1("keys", "a changed key statement", 1,
       "check -p q.c.pub --keys q.rot qref");
  pristine();
  want(0, "revoke -k q.c -o q.rev", NULL);
  ref1("key.time", "a revoked key, no timestamp", 1,
       "check -p q.c.pub --keys q.rev qref");
  want(2, "check --keys q.rev qref", NULL);
  ok(has("q.err", "give it with -p"), "check --keys needs -p");
  want(2, "rotate -k q.c -n q.c2 --at 2026-13-01T00:00:00Z", NULL);
  ok(has("q.err", "YYYY-MM-DDTHH:MM:SSZ"), "rotate --at: a bad time");
  want(2, "revoke -k q.c -n q.c2", NULL);
  want(2, "rotate -k q.c -n q.c", NULL);
  remove("q.rot");
  remove("q.rev");
  /* format 2: the signature covers the head, the Merkle root the files;
   * a changed entry leaves the signature valid but not the root */
  pristine();
  want(0, "seal --format 2 -k q.c qref", NULL);
  sub("qref/noqtis.json", "\"size\":6", "\"size\":7");
  ref1("manifest.merkle", "a format 2 entry changed", 1, CHK);
  /* a proof of b.txt alone: it checks, names no other file, and each of
   * its rows can be refused */
  pristine();
  want(0, "seal --format 2 -k q.c qref", NULL);
  want(0, "prove -p q.c.pub -o q.pf qref b.txt", NULL);
  ok(!has("q.pf", "a.txt") && !has("q.pf", "c.txt"),
     "prove: the proof names no other file");
  want(0, "check -p q.c.pub --proof q.pf", NULL);
  ok(has("q.out", "proof.entry") && has("q.out", "q.pf: OK"),
     "check --proof: the proof alone checks");
  want(0, "check -p q.c.pub --proof q.pf qref", NULL);
  ok(has("q.out", "partial"), "check --proof <dir>: says it is partial");
  want(1, "check -p q.c2.pub --proof q.pf", NULL);
  cp("q.pf", "q.pf0");
  wrs("q.pf", "not json");
  ref1("proof.parse", "proof not JSON", 1, "check -p q.c.pub --proof q.pf");
  cp("q.pf0", "q.pf");
  sub("q.pf", "{\"entries\"", "{ \"entries\"");
  ref1("proof.canonical", "proof not canonical", 1,
       "check -p q.c.pub --proof q.pf");
  cp("q.pf0", "q.pf");
  sub("q.pf", "\"format\":\"noqtis-proof-1\"",
      "\"extra\":1,\"format\":\"noqtis-proof-1\"");
  ref1("proof.fields", "proof with an unknown field", 1,
       "check -p q.c.pub --proof q.pf");
  cp("q.pf0", "q.pf");
  sub("q.pf", "\"index\":1", "\"index\":2");
  ref1("proof.entry", "proof entry at another index", 1,
       "check -p q.c.pub --proof q.pf");
  cp("q.pf0", "q.pf");
  wrs("qref/b.txt", "second!\n");
  ref1("file", "a proven file changed", 1,
       "check -p q.c.pub --proof q.pf qref");
  /* a partial check reads only the files given */
  pristine();
  want(0, "seal --format 2 -k q.c qref", NULL);
  wrs("qref/a.txt", "first!\n");
  want(0, "check -p q.c.pub --only b.txt qref", NULL);
  ok(has("q.out", "partial"), "check --only: says it is partial");
  want(1, "check -p q.c.pub --only a.txt qref", NULL);
  /* lineage: an input found and checking, not found, changed */
  rmdirs("qin");
  mkd("qin");
  wrs("qin/x.txt", "input\n");
  want(0, "seal -k q.c qin", NULL);
  pristine();
  want(0, "seal -k q.c --input src=qin qref", NULL);
  want(0, "check -p q.c.pub --lineage qin qref", NULL);
  ok(has("q.out", "lineage") && has("q.out", "src"),
     "check --lineage: the input checks");
  ref1("lineage", "an input not found", 1,
       "check -p q.c.pub --lineage qref qref");
  wrs("qin/x.txt", "changed\n");
  ref1("lineage", "an input that does not check", 1,
       "check -p q.c.pub --lineage qin qref");
  want(2, "seal -k q.c --input qin qref", NULL);
  ok(has("q.err", "qin"), "seal --input: an input that does not check");
  rmdirs("qin");
  /* prove refuses a format 1 capsule, an unlisted path, a broken one */
  pristine();
  want(2, "prove qref a.txt", NULL);
  ok(has("q.err", "format 1"), "prove: a format 1 capsule");
  want(0, "seal --format 2 -k q.c qref", NULL);
  want(2, "prove qref nope.txt", NULL);
  ok(has("q.err", "not in the manifest"), "prove: an unlisted path");
  wrs("qref/a.txt", "first!\n");
  want(1, "prove qref b.txt", NULL);
  ok(has("q.err", "does not check"), "prove: a capsule that does not check");
  want(2, "check --proof q.pf --only a.txt qref", NULL);
  remove("q.pf");
  remove("q.pf0");
  pristine();
  sub("qref/noqtis.json", "\"a.txt\"", "\"../a.txt\"");
  ref1("path", "manifest path with ..", 1, CHK);
  pristine();
  ref1("key", "another key", 1, "check -p q.c2.pub qref");
  wrs("qref/a.txt", "first!\n");
  ref1("file", "a changed file", 1, CHK);
  pristine();
  remove("qref/a.txt");
  ref1("file", "a removed file", 1, CHK);
  pristine();
  wrs("qref/new.txt", "added\n");
  ref1("extra", "an added file", 1, CHK);
  /* timestamps */
  pristine();
  {
    char q[1200], c[1400];
    quoted(q, sizeof q, oth);
    sn(c, sizeof c, "check -p q.c.pub --anchor %s qref", q);
    ref1("timestamp", "anchor, no timestamp", 1, c);
  }
  addts("qref", tok);
  ref1("timestamp", "a token over another signature", 1, CHK);
  rmdirs("qgold");
  mkd("qgold");
  mkd("qgold/data");
  mkd("qgold/data/deep");
  {
    static const char *f[] = {"a.txt",       "empty",      "data/b.csv",
                              "noqtis.json", "noqtis.sig"};
    char a[1200], b[64];
    size_t k;
    for (k = 0; k < 5; k++) {
      sn(b, sizeof b, "vectors/cap/sample/%s", f[k]);
      src(a, sizeof a, b);
      sn(b, sizeof b, "qgold/%s", f[k]);
      cp(a, b);
    }
    src(a, sizeof a, "vectors/cap/sample/data/deep/c.bin");
    cp(a, "qgold/data/deep/c.bin");
  }
  want(0, "check qgold", NULL);
  ok(has("q.out", "qgold: OK"), "the golden capsule copied");
  addts("qgold", tok);
  want(1, "check qgold", NULL);
  advice("timestamp", "a token, no anchor");
  ok(has("q.err", "--anchor <der-file>"), "no anchor: give one");
  {
    char q[1200];
    quoted(q, sizeof q, oth);
    sn(ctx, sizeof ctx, "check --anchor %s qgold", q);
  }
  want(1, ctx, NULL);
  advice("timestamp", "a token, the wrong anchor");
  wr("q.notcert", "\x30\x03\x02\x01\x01", 5);
  want(1, "check --anchor q.notcert qgold", NULL);
  advice("timestamp", "an anchor that is not a certificate");
  ok(has("q.err", "DER X.509"), "say a DER certificate is needed");
  sub("qgold/noqtis.sig", "\"timestamp\":\"MI", "\"timestamp\":\"AA");
  want(1, "check qgold", NULL);
  advice("timestamp", "a damaged token");
#ifndef _WIN32
  /* a link, and a folder that cannot be listed (not as root) */
  pristine();
  shell("ln -s a.txt qref/l");
  ref1("unsafe", "a symbolic link", 1, CHK);
  pristine();
  shell("chmod 000 qref/sub");
  if (!exists("qref/sub/c.txt")) {
    ref1("folder", "a folder that cannot be listed", 1, CHK);
  } else {
    /* root lists it anyway */
    for (j = 0; j < nnames; j++) {
      if (strcmp(names[j], "folder") == 0)
        seen[j] = 1;
    }
  }
  shell("chmod 755 qref/sub");
#else
  for (j = 0; j < nnames; j++) {
    if (strcmp(names[j], "unsafe") == 0 || strcmp(names[j], "folder") == 0)
      seen[j] = 1; /* no links or unlistable folders made here */
  }
#endif
#undef CHK
  /* every check nqchk can fail was made to fail, with advice */
  for (j = 0; j < nnames; j++) {
    char m[96];
    sn(m, sizeof m, "check %s was refused and advised on", names[j]);
    ok(seen[j], m);
  }
  /* and the refusals of check itself */
  want(2, "check qnone", NULL);
  ok(has("q.err", "not a folder (give the folder that holds"),
     "check: a folder that is not there");
  want(2, "check -p q.none qref", NULL);
  ok(has("q.err", "cannot read key file q.none (missing or unreadable; "
     "give a key file `noqtis keygen` wrote)"), "check: a missing key");
  want(2, "check -p q.ck.pub qref", NULL);
  ok(has("q.err", "not a signature key; give the signer's .pub"),
     "check: a KEM key");
  wrs("q.badkey", "noqtis-key-1 ML-DSA-99 pub\nAAAA\n");
  want(2, "check -p q.badkey qref", NULL);
  ok(has("q.err", "`noqtis algs` lists"), "check: an unknown algorithm");
  wrs("q.badkey", "noqtis-key-1 ML-DSA-65 pub\nAAAA\n");
  want(2, "check -p q.badkey qref", NULL);
  ok(has("q.err", "use the file keygen wrote"), "check: a short key");
  wrs("q.badkey", "hello\n");
  want(2, "check -p q.badkey qref", NULL);
  ok(has("q.err", "not a noqtis key file (want a first line"),
     "check: not a key file");
  want(2, "check --nope qref", NULL);
  ok(has("q.err", "see `noqtis help check`"), "check: an unknown option");
  want(2, "check --anchor", NULL);
  ok(has("q.err", "needs a value"), "check: --anchor without a file");
  want(1, "check -p q.c.pub --json qgold", NULL);
  ok(has("q.out", "\"fix\":\""), "check --json gives the fix");
}

/* noqtis inspect: what a capsule says, nothing checked */
static void tinsp(void) {
  want(0, "keygen -a ML-DSA-44 -o q.ik --force", NULL);
  rmdirs("qins");
  mkd("qins");
  mkd("qins/sub");
  wrs("qins/a.txt", "first\n");
  wrs("qins/sub/b.txt", "second line\n");
  wrs("q.meta", "{\"project\":\"demo\",\"n\":2}");
  want(0, "seal -k q.ik --meta q.meta qins", NULL);
  want(0, "inspect qins", NULL);
  ok(has("q.out", "format     noqtis-capsule-1\n"), "inspect: format");
  ok(has("q.out", "alg        ML-DSA-44\n"), "inspect: alg");
  ok(has("q.out", "files      2\n"), "inspect: files");
  ok(has("q.out", "bytes      18\n"), "inspect: bytes");
  ok(has("q.out", "timestamp  none\n"), "inspect: no timestamp");
  ok(has("q.out", "meta       {\"n\":2,\"project\":\"demo\"}\n"),
     "inspect: canonical meta");
  /* any year: package builds seal under SOURCE_DATE_EPOCH (Nix: 1980) */
  ok(has("q.out", "\ncreated    ") && has("q.out", "Z\nfiles      2\n"),
     "inspect: created");
  ok(has("q.out", "not checked"), "inspect says nothing was checked");
  ok(!has("q.out", "OK"), "inspect never says OK");
  want(0, "inspect --json qins", NULL);
  ok(has("q.out", "\"checked\":false,\"format\":\"noqtis-capsule-1\","
         "\"alg\":\"ML-DSA-44\",\"key_sha256\":\""),
     "inspect --json: fields");
  ok(has("q.out", "\"files\":2,\"bytes\":18,\"timestamp\":false,"
         "\"meta\":{\"n\":2,\"project\":\"demo\"}}"),
     "inspect --json: counts, timestamp and meta");
  /* a changed file: inspect reads, check fails */
  wrs("qins/a.txt", "changed\n");
  want(0, "inspect qins", NULL);
  want(1, "check qins", NULL);
  /* a seal that does not parse */
  wrs("qins/noqtis.sig", "not json");
  want(1, "inspect qins", NULL);
  ok(has("q.out", "FAIL  seal.parse"), "inspect: a broken seal");
  ok(has("q.out", "cannot be read as a capsule"), "inspect: says so");
  want(1, "inspect --json qins", NULL);
  ok(has("q.out", "\"errors\":[{\"check\":\"seal.parse\""),
     "inspect --json: the failing rows");
  want(2, "inspect", NULL);
  want(2, "inspect no-such-folder", NULL);
  want(2, "inspect --bogus qins", NULL);
  want(0, "help inspect", NULL);
  rmdirs("qins");
}


/* review of a4eec67 (capsule, CLI and network): options given twice,
 * folders, the key file's algorithm, terminal escapes, secret keys in the
 * folder, hex seeds, file modes, input limits, signing a manifest */
static void treview(void) {
  rmdirs("qrv");
  mkd("qrv");
  wrs("qrv/a", "x\n");
  want(0, "keygen -a SLH-DSA-SHA2-128f -o q.rk", NULL);
  want(0, "seal -k q.rk qrv", NULL);
  want(0, "check -p q.rk.pub qrv", NULL);
  /* a second -p does not replace the first */
  want(2, "check -p q.rk.pub -p q.rk.pub qrv", NULL);
  ok(has("q.err", "is given more than once"), "check: -p twice is refused");
  want(2, "keygen -a ML-DSA-44 -o q.r1 -o q.r2", NULL);
  /* a file is not a folder (exit 2, as for no folder) */
  want(2, "check qrv/a", NULL);
  ok(has("q.err", "not a folder"), "check: a file given as the folder");
  want(2, "inspect qrv/a", NULL);
  /* -p pins the key file's algorithm too: SHAKE-128f has SHA2-128f's sizes */
  shell("cp q.rk.pub q.rk2.pub");
  ok(sub("q.rk2.pub", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"),
     "relabel the key file");
  want(1, "check -p q.rk2.pub qrv", NULL);
  ok(has("q.out", "key.alg") && has("q.out", "the seal says SLH-DSA-SHA2-128f"),
     "check: a key file of another algorithm with the same bytes fails");
  ok(has("q.err", "key.alg: the -p key file is for another algorithm"),
     "check: key.alg says what to do");
  want(1, "check -j -p q.rk2.pub qrv", NULL);
  ok(has("q.out", "\"check\":\"key.alg\",\"ok\":false"), "check -j: key.alg");
  ok(has("q.out", "the seal says SLH-DSA-SHA2-128f\",\"fix\":\"the -p key "
                  "file is for another algorithm"),
     "check -j: key.alg has its detail and fix");
#ifndef _WIN32
  /* terminal escapes in a name reach the terminal escaped */
  wrs("qrv/\x1b[2K\x1b[1Aesc", "y\n");
  want(1, "check -p q.rk.pub qrv", NULL);
  ok(has("q.out", "\\x1b[2K\\x1b[1Aesc") && !has("q.out", "\x1b"),
     "check: a name's escape characters are printed escaped");
  shell("rm -f 'qrv/'$(printf '\\033')'[2K'$(printf '\\033')'[1Aesc'");
  /* the public key's mode does not follow a umask of 000 */
  {
    struct stat st;
    mode_t old = umask(0);
    want(0, "keygen -a ML-DSA-44 -o q.um", NULL);
    umask(old);
    ok(stat("q.um.pub", &st) == 0 && (st.st_mode & 0777) == 0644,
       "keygen: the .pub is 0644 under umask 000");
    ok(stat("q.um", &st) == 0 && (st.st_mode & 0777) == 0600,
       "keygen: the secret key is 0600 under umask 000");
  }
  /* /dev/zero as a seed file is refused, not read forever */
  want(2, "keygen -a ML-DSA-44 --seed /dev/zero -o q.z", NULL);
#endif
  /* a secret key in the folder is not sealed */
  rmdirs("qrv2");
  mkd("qrv2");
  wrs("qrv2/a", "x\n");
  want(0, "keygen -a ML-DSA-44 -o qrv2/me", NULL);
  want(2, "seal -k qrv2/me qrv2", NULL);
  ok(has("q.err", "qrv2/me starts like a noqtis secret key") ||
     has("q.err", "me starts like a noqtis secret key"),
     "seal: a secret key in the folder is refused, by name");
  ok(!exists("qrv2/noqtis.sig"), "seal: nothing written");
  /* the other refusals say what they are, not "a secret key" */
  remove("qrv2/me");
  remove("qrv2/me.pub");
  want(0, "keygen -a ML-DSA-44 -o q.sw", NULL);
  want(0, "keygen -a ML-DSA-44 -o q.sw2", NULL);
  want(2, "seal -k q.sw -p q.sw2.pub qrv2", NULL);
  ok(has("q.err", "are not one key pair") &&
     !has("q.err", "secret key (noqtis-key-1"),
     "seal: a key pair that is not one says so");
#ifndef _WIN32
  /* (Windows cannot make the name) */
  wrs("qrv2/a:b", "x\n");
  want(2, "seal -k q.sw qrv2", NULL);
  ok(has("q.err", "is one noqtis refuses") && has("q.err", "a:b"),
     "seal: a refused name is named");
  remove("qrv2/a:b");
#endif
  /* a seed in hex on the command line is warned about */
  want(0, "keygen -a ML-DSA-44 --seed "
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
          "-o q.sd", NULL);
  ok(has("q.err", "warning: a seed given as hex"), "keygen --seed hex warns");
  /* signing a manifest as a plain file is warned about */
  want(0, "sign -k q.rk -o q.ms qrv/noqtis.json", NULL);
  ok(has("q.err", "is a capsule manifest"), "sign: a manifest is warned about");
  rmdirs("qrv");
  rmdirs("qrv2");
}

/* noqtis idcard, and check --card */
static void tidc(void) {
  want(0, "keygen -a ML-DSA-44 -o q.idk", NULL);
  want(0, "keygen -a ML-DSA-65 -o q.idk2", NULL);
  want(0, "keygen -a Ed25519 -o q.ide", NULL);
  want(0, "idcard -k q.idk --name \"Ada Lovelace\" --orcid "
       "https://orcid.org/0000-0002-1694-233x --email ada@example.org "
       "--url https://example.org/ada --affil AES -o q.icard", NULL);
  ok(has("q.icard", "\"orcid\":\"0000-0002-1694-233X\"") &&
     !has("q.icard", "orcid.org"),
     "idcard: the bare ORCID iD, its X in upper case");
  ok(has("q.icard", "\"format\":\"noqtis-idcard-1\""), "idcard: the format");
  want(0, "idcard --verify q.icard", NULL);
  ok(has("q.out", "name     Ada Lovelace\n") &&
     has("q.out", "orcid    0000-0002-1694-233X\n") &&
     has("q.out", "email    ada@example.org\n") &&
     has("q.out", "url      https://example.org/ada\n") &&
     has("q.out", "affil    AES\n") && has("q.out", "alg      ML-DSA-44\n") &&
     has("q.out", "q.icard: OK (self-signed"),
     "idcard --verify: every field");
  want(0, "idcard --verify q.icard -p q.idk.pub", NULL);
  ok(has("q.out", "q.icard: OK (the -p key)"), "idcard --verify -p");
  want(1, "idcard --verify q.icard -p q.idk2.pub", NULL);
  ok(has("q.err", "another key"), "idcard --verify -p: another key");
  want(0, "idcard -k q.idk --name A", NULL);
  ok(has("q.out", "\"name\":\"A\"") && !has("q.out", "\"orcid\""),
     "idcard: to stdout, only the fields given");
  /* each field refused names its option */
  want(2, "idcard -k q.idk --name A --orcid 0000-0002-1825-0098", NULL);
  ok(has("q.err", "--orcid 0000-0002-1825-0098") &&
     has("q.err", "check digit"), "idcard: a wrong ORCID check digit");
  want(2, "idcard -k q.idk --name A --email ada", NULL);
  ok(has("q.err", "--email"), "idcard: a bad e-mail address");
  want(2, "idcard -k q.idk --name A --url http://example.org", NULL);
  ok(has("q.err", "--url"), "idcard: a page not on https://");
  want(2, "idcard -k q.idk --name \" A\"", NULL);
  ok(has("q.err", "--name"), "idcard: a name with a leading space");
  want(2, "idcard -k q.idk --name A --affil \"\"", NULL);
  ok(has("q.err", "--affil"), "idcard: an empty affiliation");
  want(2, "idcard -k q.ide --name A", NULL);
  ok(has("q.err", "not Ed25519"), "idcard: Ed25519 alone is refused");
  want(2, "idcard -k q.idk -p q.idk2.pub --name A", NULL);
  want(2, "idcard -k q.idk.pub --name A", NULL);
  want(2, "idcard --name A", NULL);
  want(2, "idcard -k q.idk", NULL);
  want(2, "idcard -k q.idk --name A extra", NULL);
  want(2, "idcard --verify q.icard -k q.idk", NULL);
  /* a created time past the year 9999 is named as such */
  sde("253402300800");
  want(2, "idcard -k q.idk --name A", NULL);
  ok(has("q.err", "up to the year 9999") && !has("q.err", "key pair"),
     "idcard: SOURCE_DATE_EPOCH past 9999 is named");
  sde("253402300799");
  want(0, "idcard -k q.idk --name A", NULL);
  ok(has("q.out", "\"created\":\"9999-12-31T23:59:59Z\""),
     "idcard: the last second of 9999");
  sde(NULL);
  want(2, "idcard --verify q.icard --name A", NULL);
  want(2, "idcard -k q.idk --name A -o q.icard", NULL);
  ok(has("q.icard", "Ada Lovelace"), "idcard: an existing card is kept");
  want(0, "idcard -k q.idk --name A -o q.icard5", NULL);
  want(0, "idcard -k q.idk --name B -o q.icard5 -f", NULL);
  ok(has("q.icard5", "\"name\":\"B\""), "idcard -f replaces a card");
  /* changed cards */
  cp("q.icard", "q.icard3");
  sub("q.icard3", "Ada Lovelace", "Ada Lovelacf");
  want(1, "idcard --verify q.icard3", NULL);
  ok(has("q.err", "signature does not verify"), "idcard: a changed name");
  cp("q.icard", "q.icard6");
  sub("q.icard6", "{\"affil\"", "{ \"affil\"");
  want(1, "idcard --verify q.icard6", NULL);
  ok(has("q.err", "not a noqtis-idcard-1 card"),
     "idcard: a card not in canonical form");
  want(1, "idcard --verify q.idk.pub", NULL);
  want(2, "idcard --verify nosuch", NULL);
  /* check --card: who sealed the folder */
  rmdirs("qic");
  mkd("qic");
  wrs("qic/a.txt", "alpha\n");
  want(0, "seal -k q.idk qic", NULL);
  want(0, "check -p q.idk.pub --card q.icard qic", NULL);
  ok(has("q.out", "ok    card ") &&
     has("q.out", "sealed by Ada Lovelace (ORCID 0000-0002-1694-233X, "
                  "ada@example.org, https://example.org/ada, AES)"),
     "check --card: the sealer named");
  want(0, "check --json -p q.idk.pub --card q.icard qic", NULL);
  ok(has("q.out", "{\"check\":\"card\",\"ok\":true") &&
     has("q.out", "\"card\":{\"name\":\"Ada Lovelace\",\"orcid\":"
                  "\"0000-0002-1694-233X\""),
     "check --json --card");
  want(0, "check --card q.icard qic", NULL);
  ok(has("q.err", "the card is signed by the seal's own key"),
     "check --card without -p: the card is the seal key's word");
  want(0, "idcard -k q.idk2 --name B -o q.icard4", NULL);
  want(1, "check -p q.idk.pub --card q.icard4 qic", NULL);
  ok(has("q.out", "FAIL  card ") && has("q.out", "another key") &&
     has("q.err", "noqtis check: card: "),
     "check --card: a card of another key fails, with advice");
  want(1, "check --json -p q.idk.pub --card q.icard4 qic", NULL);
  ok(has("q.out", "{\"check\":\"card\",\"ok\":false") &&
     !has("q.out", "\"card\":{"), "check --json --card: another key");
  want(1, "check -p q.idk.pub --card q.icard3 qic", NULL);
  ok(has("q.out", "the card does not verify") &&
     has("q.err", "noqtis check: card: "),
     "check --card: a changed card fails, with advice");
  want(1, "check -p q.idk.pub --card q.icard6 qic", NULL);
  want(2, "check -p q.idk.pub --card nosuch qic", NULL);
  want(2, "check -p q.idk.pub --card q.icard --proof q.icard", NULL);
  ok(has("q.err", "--card apply to a capsule folder"),
     "check --card does not apply to --proof");
  /* a changed file fails the check with a good card */
  wrs("qic/a.txt", "beta\n");
  want(1, "check -p q.idk.pub --card q.icard qic", NULL);
  ok(has("q.out", "ok    card "), "check --card: the card row stands");
  /* a card is not a seal, nor a seal a card */
  cp("q.icard", "qic/noqtis.sig");
  want(1, "check -p q.idk.pub qic", NULL);
  want(1, "idcard --verify qic/noqtis.json", NULL);
  rmdirs("qic");
}

int main(int argc, char **argv) {
  static const char *sigs[] = {
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHAKE-128f"
  };
  static const char *slh[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f"
  };
  static const char *kems[] = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "HQC-128", "HQC-192",
    "HQC-256"
  };
  const char *all = getenv("NQCLIALL");
  size_t i;
  if (argc != 2 && argc != 4) {
    fprintf(stderr, "usage: tcli <path to noqtis> [<path to tsad> "
            "<tests/ in the source tree>]\n");
    return 2;
  }
  exe = argv[1];
  if (argc == 4) {
    tsad = argv[2];
    srcdir = argv[3];
  }
  if (getenv("NQCLIWRAP") != NULL) {
    static char w[1024];
    sn(w, sizeof w, "%s ", getenv("NQCLIWRAP"));
    wrap = w;
  }
  /* a fresh folder each run: a second run in the same build (the
   * Docker image runs the tests again) must not meet the first one's
   * files */
  exe = absp(exe, 0);
  if (tsad != NULL) tsad = absp(tsad, 1);
  if (srcdir != NULL) srcdir = absp(srcdir, 2);
  rmdirs("tcli.run");
  mkd("tcli.run");
#ifdef _WIN32
  if (_chdir("tcli.run") != 0) {
#else
  if (chdir("tcli.run") != 0) {
#endif
    fprintf(stderr, "tcli: cannot enter tcli.run\n");
    return 2;
  }
  tbasic();
  for (i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
    tsig(sigs[i], i == 0 || i == 3);
  if (all != NULL && strcmp(all, "1") == 0) {
    for (i = 0; i < sizeof slh / sizeof slh[0]; i++)
      tsig(slh[i], 0);
  }
  tdet();
  for (i = 0; i < sizeof kems / sizeof kems[0]; i++)
    tkem(kems[i]);
  thash();
  tcap();
  tinsp();
  treview();
  tidc();
  if (tsad != NULL) {
    tts();
    tremote();
    texport();
    trefuse();
    tbl();
  }
  printf("tcli: %d checks, %d failed\n", nrun, nbad);
  return nbad == 0 ? 0 : 1;
}
