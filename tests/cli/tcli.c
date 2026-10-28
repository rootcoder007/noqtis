/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * Black-box tests of the noqtis tool: runs it the way a user does (through
 * the shell, stdout and stderr to files) and checks exit codes, outputs
 * and the files it writes.
 *
 *   tcli <path to noqtis>
 *
 * NQCLIWRAP, when set, is put in front of every command (for example
 * "valgrind -q --error-exitcode=9 --leak-check=full"). NQCLIALL=1 runs
 * every SLH-DSA parameter set instead of a sample.
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/wait.h>
#endif

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
  snprintf(c, sizeof c, "if exist %s rmdir /s /q %s", d, d);
#else
  snprintf(c, sizeof c, "rm -rf %s", d);
#endif
  shell(c);
}

static void mkd(const char *d) {
  char c[256];
  snprintf(c, sizeof c, "mkdir %s", d);
  shell(c);
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
  snprintf(m, sizeof m, "%s: no secret key bytes on stdout/stderr", what);
  ok(!leak, m);
}

static void tsig(const char *alg, int full) {
  char a[512], m[256];
  snprintf(m, sizeof m, "%s round trip", alg);
  remove("q.k");
  remove("q.k.pub");
  remove("q.k2");
  remove("q.k2.pub");
  remove("q.sig");
  remove("q.m.sig");
  wrs("q.m", "the data an analysis used\n");
  snprintf(a, sizeof a, "keygen -a %s -o q.k", alg);
  want(0, a, NULL);
  nosec("q.k", alg);
  snprintf(m, sizeof m, "noqtis-key-1 %s sec\n", alg);
  ok(has("q.k", m), "secret key file header");
  snprintf(m, sizeof m, "noqtis-key-1 %s pub\n", alg);
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
  snprintf(a, sizeof a, "keygen -a %s -o q.k2", alg);
  want(0, a, NULL);
  want(1, "verify -p q.k2.pub -s q.m.sig q.m", NULL);
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
  snprintf(a, sizeof a, "keygen -a ml-dsa-44 --seed %s -o q.d1", xi);
  want(0, a, NULL);
  snprintf(a, sizeof a, "keygen -a ML-DSA-44 --seed %s -o q.d2", xi);
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
  snprintf(a, sizeof a, "keygen -a SLH-DSA-SHAKE-128f --seed %s%s -o q.d3",
           xi, "000102030405060708090a0b0c0d0e0f");
  want(0, a, NULL);
  snprintf(a, sizeof a, "keygen -a SLH-DSA-SHAKE-128f --seed %s%s -o q.d4",
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
  snprintf(a, sizeof a, "keygen -a %s -o q.e", alg);
  want(0, a, NULL);
  nosec("q.e", alg);
  want(0, "enc -p q.e.pub -o q.ct q.ss1", NULL);
  want(0, "dec -k q.e -o q.ss2 q.ct", NULL);
  s1 = rd("q.ss1", &n1);
  s2 = rd("q.ss2", &n2);
  snprintf(m, sizeof m, "%s: enc and dec agree", alg);
  ok(s1 != NULL && s2 != NULL && n1 == 32 && n2 == 32 &&
     memcmp(s1, s2, 32) == 0, m);
#ifndef _WIN32
  ok(priv("q.ss1") && priv("q.ss2"), "shared secret files are owner-only");
#endif
  if (s1 != NULL && n1 == 32) {
    hex(s1, 32, h);
    snprintf(m, sizeof m, "%s: no shared secret on stdout", alg);
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
  snprintf(m, sizeof m, "%s: a tampered ciphertext changes the secret", alg);
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
  if (argc != 2) {
    fprintf(stderr, "usage: tcli <path to noqtis>\n");
    return 2;
  }
  exe = argv[1];
  if (getenv("NQCLIWRAP") != NULL) {
    static char w[1024];
    snprintf(w, sizeof w, "%s ", getenv("NQCLIWRAP"));
    wrap = w;
  }
  remove("q.k");
  remove("q.k.pub");
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
  printf("tcli: %d checks, %d failed\n", nrun, nbad);
  return nbad == 0 ? 0 : 1;
}
