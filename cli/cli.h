/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * The noqtis command-line tool: shared declarations. The tool uses only
 * the public API in noqtis.h.
 */
#ifndef NQCLI_H
#define NQCLI_H

#include <noqtis.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* exit codes */
#define NCOK 0   /* success; a signature or capsule verified */
#define NCBAD 1  /* verification failed, a digest differs */
#define NCUSE 2  /* usage, file or library error */

/* ---- options ---- */

/* One option: -s, --long; arg 1 when it takes a value (stored in *val),
 * else *flag is set to 1. */
typedef struct {
  char s;
  const char *l;
  int arg;
  const char **val;
  int *flag;
} ncopt;

/* Parses argv[1..argc-1] (argv[0] is the command name); moves the
 * positional arguments to the front of argv and stores their count in
 * *npos. Prints an error and returns NCUSE on a bad option, NCOK
 * otherwise. -h/--help sets *help. */
int ncargs(const char *cmd, int argc, char **argv, const ncopt *o,
           size_t n, int *npos, int *help);

/* ---- messages ---- */

void ncmsg(const char *cmd, const char *fmt, ...);
/* Prints the usage of cmd to f; 0 if cmd is unknown. */
int ncuse(FILE *f, const char *cmd);
/* Prints "noqtis <cmd>: <what>: <nqerr(rc)>" and returns NCUSE. */
int nclib(const char *cmd, const char *what, int rc);

/* ---- files (io.c) ---- */

/* Opens a UTF-8 path on every OS. */
FILE *ncfopen(const char *path, const char *mode);
/* Reads a whole file ("-" is stdin) into a new buffer. sec: unbuffered,
 * and every intermediate copy is wiped. The caller frees with ncfree. */
int ncrd(const char *path, int sec, uint8_t **buf, size_t *len);
/* Creates path for writing: refuses an existing file unless force; sec
 * gives owner-only permissions (0600 on POSIX). */
FILE *ncopen(const char *path, int force, int sec);
/* Writes len bytes to a new file (see ncopen); removes it on failure. */
int ncwr(const char *path, const uint8_t *b, size_t len, int force,
         int sec);
/* Prints why path could not be created; returns NCUSE. */
int ncwfail(const char *cmd, const char *path, int force);
/* 1 when path names an existing file. */
int ncexist(const char *path);
/* Closes f; removes path when bad or when the close fails. 0 on success. */
int ncclose(FILE *f, const char *path, int bad);
/* Wipes (when sec) and frees. */
void ncfree(void *p, size_t len, int sec);
/* stdin/stdout in binary mode (Windows). */
void ncbin(void);

/* ---- encodings (b64.c), constant time ---- */

size_t ncb64n(size_t len);  /* encoded length with a newline every 64 */
void ncb64e(const uint8_t *in, size_t len, char *out);
/* Decodes, ignoring line breaks; NQEDEC on anything else. */
int ncb64d(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);
void nchexe(const uint8_t *in, size_t len, char *out);  /* 2*len chars */
/* NQEDEC unless in is exactly 2*n hex digits. */
int nchexd(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);

/* ---- algorithms and keys (key.c) ---- */

typedef struct {
  int kem;     /* 0 signature, 1 KEM */
  int alg;     /* nqsalg or nqkalg */
  const char *name;
} ncalg;

/* Finds an algorithm by name (case-insensitive). NQENOSUP if unknown. */
int ncfind(const char *name, ncalg *a);
/* Public and secret key sizes. */
int ncksz(const ncalg *a, size_t *pk, size_t *sk);

typedef struct {
  ncalg a;
  int sec;
  uint8_t *b;
  size_t n;
} nckey;

/* Reads a key file; sec is the kind the caller needs (1 secret). */
int nckrd(const char *cmd, const char *path, int sec, nckey *k);
void nckfree(nckey *k);
/* Writes a key file to an already opened f. */
int nckwr(FILE *f, const ncalg *a, int sec, const uint8_t *b, size_t n);

/* A hash by its command-line name (sha256, sha3-256, ...). */
int nchalg(const char *name, nqhalg *h);
const char *nchname(nqhalg h);

/* ---- commands ---- */

int nckeygen(int argc, char **argv);
int ncsign(int argc, char **argv);
int ncvrfy(int argc, char **argv);
int ncenc(int argc, char **argv);
int ncdec(int argc, char **argv);
int nchash(int argc, char **argv);
int ncseal(int argc, char **argv);
int ncchk(int argc, char **argv);

#endif /* NQCLI_H */
