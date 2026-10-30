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
/* s with control characters escaped, for printing to a terminal */
const char *ncesc(const char *s);

#define NCOK 0   /* success; a signature or capsule verified */
#define NCBAD 1  /* verification failed, a digest differs */
#define NCUSE 2  /* usage, file or library error */

/* ---- options ---- */

/* One option: -s, --long; arg 1 when it takes a value (stored in *val),
 * NCMANY when it may be given up to NCMAXV times (val is then an array
 * of NCMAXV and *flag counts the values), else *flag is set to 1. */
#define NCMANY 2
#define NCMAXV 32
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
/* whether path is a folder (following links) */
int ncisdir(const char *path);
/* ncrd that refuses (NQELIM) an input over max bytes, so /dev/zero or a
 * huge file cannot fill memory or run forever */
int ncrdx(const char *path, int sec, size_t max, uint8_t **buf,
          size_t *len);
#define NCRDMAX ((size_t)1 << 30) /* a message or list: 1 GiB */
#define NCRDSMALL ((size_t)1 << 20) /* a key, signature, anchor: 1 MiB */
/* Creates path for writing: refuses an existing file unless force; sec
 * gives owner-only permissions (0600 on POSIX). */
FILE *ncopen(const char *path, int force, int sec);
/* Writes len bytes to a new file (see ncopen); removes it on failure. */
int ncwr(const char *path, const uint8_t *b, size_t len, int force,
         int sec);
/* Makes the folder path (owner-only on POSIX). NCOK or NCUSE. */
int ncmkdir(const char *path);
/* Removes the file path, or the empty folder path; 0 on success. */
int ncrmfile(const char *path);
int ncrmdir(const char *path);
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

/* ---- the network (net.c) ---- */

/* POSTs body (an RFC 3161 request) to an http:// URL (or https://, with
 * NQTLS) and returns the reply's body in a new buffer (free it). NCUSE
 * with a sentence in err on any failure: the URL, the connection, TLS,
 * the HTTP status or type. The trust anchors for https:// are the PEM
 * bundle SSL_CERT_FILE names, else the system's. */
int nchttp(const char *url, const uint8_t *body, size_t n, uint8_t **out,
           size_t *outn, char *err, size_t cap);
/* GETs url and returns the body (at most max bytes) in a new buffer
 * (free it), following at most 5 redirects, never one from https:// to
 * anything else. Within 120 s in all. */
int ncget(const char *url, size_t max, uint8_t **out, size_t *outn,
          char *err, size_t cap);
/* NCOK when url is one nchttp can send to (http://host[:port][/path],
 * or https:// with NQTLS); else NCUSE and why in err. No network. */
int ncurlok(const char *url, char *err, size_t cap);

/* ---- remote capsules (rem.c) ---- */

typedef struct ncrem ncrem;
/* 1 when s is an http:// or https:// URL */
int ncisurl(const char *s);
/* Fetches the capsule served at url (its folder) into a new temporary
 * folder: the seal and the manifest, then, when those check under co's
 * key and anchors, the listed files (co's only, when set), each at most
 * its listed size. Problems fetching are printed, and the check of the
 * folder reports what is missing. NCOK with *out set, or NCUSE. */
int ncremget(const char *url, const nqcopt *co, ncrem **out);
const char *ncremdir(const ncrem *m);
/* Removes everything ncremget wrote, then frees m. */
void ncremfree(ncrem *m);

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
int ncprove(int argc, char **argv);
int ncrot(int argc, char **argv);
int ncrev(int argc, char **argv);
int ncinsp(int argc, char **argv);
int ncts(int argc, char **argv);

#endif /* NQCLI_H */
