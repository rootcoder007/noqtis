/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqd internals: memory, growing buffers, the JSON tree with its strict
 * reader and canonical (RFC 8785) writer, the CSV reader and the column
 * summaries. Not part of the public API; nqd uses only noqtis.h of the
 * core. */
#ifndef NQDINT_H
#define NQDINT_H

/* MinGW with the old C runtime (msvcrt, as R 4.1 for Windows uses) prints a
 * 64-bit count (%llu) only through MinGW's own printf family, which this
 * asks for; it must come before the first system header. */
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "noqtis.h"
#include "nqd.h"

/* the format a message function is checked against: on MinGW the one its
 * headers name for the printf family in use */
#if defined(__MINGW32__) && defined(__MINGW_PRINTF_FORMAT)
#define QDFMT(f, v) __attribute__((format(__MINGW_PRINTF_FORMAT, f, v)))
#elif defined(__GNUC__) || defined(__clang__)
#define QDFMT(f, v) __attribute__((format(printf, f, v)))
#else
#define QDFMT(f, v)
#endif

/* ---- memory ---- */

/* malloc and free; no realloc (the core's allocator hook has none, and
 * nqd keeps to the same pattern: grow by copy) */
void *qdmal(size_t n);
void qdfree(void *p);
/* a copy of n bytes of s, NUL-terminated; NULL when out of memory */
char *qddup(const char *s, size_t n);

/* ---- a growing byte buffer ---- */

typedef struct {
  char *b;
  size_t n;
  size_t cap;
  int err; /* NQEMEM or NQELIM once a write failed; later writes no-op */
  size_t max; /* 0: no limit beyond memory */
} dbuf;

void qdbput(dbuf *b, const char *s, size_t n);
void qdbstr(dbuf *b, const char *s);
void qdbch(dbuf *b, char c);
void qdbfree(dbuf *b);
/* The buffer's text into out (cap bytes, NUL added when room); NQEBUF
 * with *outlen set when cap is too small. */
int qdbout(const dbuf *b, char *out, size_t cap, size_t *outlen);

/* ---- JSON ---- */

enum { DJNULL = 1, DJFALSE, DJTRUE, DJNUM, DJSTR, DJARR, DJOBJ };

typedef struct djs djs;
struct djs {
  int t;
  char *s;  /* STR: decoded UTF-8, NUL-terminated (no NUL inside) */
  size_t sl;
  double d; /* NUM */
  djs **k;  /* ARR, OBJ: children in order */
  char **key; /* OBJ: keys */
  size_t *kl;
  size_t n;
  size_t cap;
};

#define DJDEPTH 32
#define DJKIDS ((size_t)1 << 24)

/* Parses one JSON value spanning buf[0..len): strict RFC 8259, UTF-8,
 * no duplicate keys, no \u0000, numbers finite. NQOK, or NQEDEC/NQELIM/
 * NQEMEM with a sentence (and byte offset) in why. */
int qdjparse(const char *buf, size_t len, djs **out, char *why, size_t cap);
void qdjfree(djs *v);
djs *qdjnew(int t);
djs *qdjstr(const char *s);
djs *qdjstrn(const char *s, size_t n);
djs *qdjnum(double d);
/* a deep copy */
djs *qdjcopy(const djs *v);
/* append kid to an ARR (takes it; frees it on failure) */
int qdjadd(djs *a, djs *kid);
/* set key of an OBJ to kid, replacing (and freeing) an old value */
int qdjset(djs *o, const char *key, djs *kid);
const djs *qdjget(const djs *o, const char *key);
djs *qdjgetw(djs *o, const char *key);
/* removes key from an OBJ; 1 when it was there */
int qdjdel(djs *o, const char *key);
/* removes and frees element i of an ARR */
void qdjrm(djs *a, size_t i);
/* RFC 8785 canonical text of v */
void qdjwrite(const djs *v, dbuf *b);
/* an integer-valued NUM that fits in int64 (|v| <= 2^53) */
int qdjint(const djs *v, int64_t *out);
/* the shortest round-trip ECMAScript form of d (RFC 8785 section
 * 3.2.2.3) in out (at least 32 bytes); NQEARG for NaN or infinity */
int qdnumfmt(double d, char *out);
/* strict decimal syntax of s[0..n) to a double, whatever the C locale;
 * json 1: JSON's grammar; json 0: also a leading '+', ".5", "5." */
int qdnumrd(const char *s, size_t n, int json, double *d);
/* the UTF-16 order of RFC 8785 for keys: <0, 0, >0 */
int qdkcmp(const char *a, size_t al, const char *b, size_t bl);
/* 1 when s[0..n) is valid UTF-8 without NUL */
int qdutf8(const char *s, size_t n);

/* ---- why ---- */

void qdwhy(char *why, size_t cap, const char *fmt, ...)
    QDFMT(3, 4)
    ;

/* ---- the record ---- */

/* Validates the tree of a record against noqtis-data-1 (members, types,
 * sorted and unique keyed arrays). NQOK or NQEDEC with why. */
int qdrecok(const djs *r, char *why, size_t cap);
/* Validates one element of array member m (or the object m). */
int qdelemok(const char *m, const djs *e, char *why, size_t cap);

/* 1 when s[0..n) is a valid calendar date YYYY-MM-DD */
int qddate(const char *s, size_t n);
/* the record's tree, for the other nqd modules */
const djs *qdrectree(const nqdrec *r);

/* ---- reports ---- */

int qdrepadd(nqdrep *r, const char *check, int ok, const char *fmt, ...)
    QDFMT(4, 5)
    ;
nqdrep *qdrepnew(void);
/* attaches a copy of the JSON text j to the last row */
int qdrepjson(nqdrep *r, const char *j);

/* ---- statistics (dft.c) ---- */

/* the upper tail of chi-square with df degrees of freedom at x2 */
double qdchisq(double x2, double df);
/* P(K > x) of the Kolmogorov distribution (R's limit, tol 1e-6) */
double qdkolm(double x);
/* P(D >= d) exactly, for two samples of m and n with no ties */
double qdsmir(double d, int m, int n);
/* PSI and Jensen-Shannon divergence of two count vectors */
void qdpsi(const double *a, const double *b, size_t k, double *psi,
           double *js);
/* chi-square homogeneity of the 2 x k table (a; b): p, X^2 and df */
double qdhomog(const double *a, const double *b, size_t k, double *x2,
               double *df);
/* Benford's first-digit test of nine counts: p, X^2 */
double qdbenf(const double *d, double *x2);
/* the first significant digit of a number's text, 0 for zero */
int qdfdig(const char *s, size_t n);

/* ---- CSV (csv.c) ---- */

#define QDCSVFIELD ((size_t)1 << 20)  /* bytes in a field */
#define QDCSVREC ((size_t)16 << 20)   /* bytes in a record */
#define QDCSVNF ((size_t)16384)       /* fields in a record */

typedef struct {
  int (*rd)(void *u, char *b, size_t cap, size_t *got);
  void *u;
  int own; /* 1: u is a FILE to close; 2: memory to free */
  char buf[65536];
  size_t bn, bi;
  int eof, bom;
  char delim;
  size_t maxfield, maxfields, maxrec;
  char *rec; /* the fields of the record, each ended by NUL */
  size_t reclen, reccap;
  size_t *off;
  size_t nf, offcap;
  uint64_t line;    /* the line the next record starts on */
  uint64_t recline; /* the line the current record started on */
  uint64_t nrec;
  char why[200];
} qdcsv;

/* a reader of the file path, or of n bytes at p (kept, not copied) */
int qdcsvfile(qdcsv *c, const char *path, char delim);
int qdcsvmem(qdcsv *c, const char *p, size_t n, char delim);
/* the next record: NQOK with *got 1, or *got 0 at the end; NQEDEC or
 * NQELIM with c->why on a malformed file, NQEIO, NQEMEM */
int qdcsvnext(qdcsv *c, int *got);
/* field i of the current record (NUL-terminated), its length in *len */
const char *qdcsvf(const qdcsv *c, size_t i, size_t *len);
void qdcsvclose(qdcsv *c);

/* value classes of a CSV field (sch.c) */
#define QDTBOOL 1u
#define QDTINT 2u
#define QDTREAL 4u
#define QDTDATE 8u
/* the classes s[0..n) belongs to; *d its number when QDTREAL */
unsigned qdvclass(const char *s, size_t n, double *d);
/* big-endian 64 bits at p */
uint64_t qdld64(const uint8_t *p);

/* ---- regular expressions (rx.c) ---- */

typedef struct qdrx qdrx;
/* compiles the pattern p[0..n) of a regex rule (noqtis-data(5) lists its
 * syntax): NQOK, NQEDEC with a sentence in why, NQEMEM */
int qdrxcomp(const char *p, size_t n, qdrx **out, char *why, size_t cap);
/* 1 when the pattern matches somewhere in s[0..n), else 0; in time
 * linear in n times the pattern's length */
int qdrxrun(qdrx *x, const char *s, size_t n);
void qdrxfree(qdrx *x);

/* the "schema" rows of nqdchk for one schemas element (sch.c); sy is
 * " [synthetic]" or "" */
int qdschk(nqdrep *rep, const char *dir, const djs *sch, const char *sy);

/* ---- files ---- */

/* fopen of a UTF-8 path (wide on Windows) */
FILE *qdfopen(const char *path, const char *mode);
/* dir/rel into out; NQEARG for a rel that is not a capsule path
 * (empty, absolute, "..", ".", backslash, control character, over 4096
 * bytes) */
int qdjoin(const char *dir, const char *rel, char *out, size_t cap);
/* reads a whole file of at most max bytes into a new buffer (NUL
 * added); NQEIO when it cannot be read, NQELIM when too large */
int qdread(const char *path, size_t max, char **buf, size_t *len);
/* writes len bytes to path through path.tmp and a rename */
int qdwrite(const char *path, const char *b, size_t len);
/* SHA-256 and size of a file */
int qdsha(const char *path, uint8_t h[32], uint64_t *size);
void qdhex(const uint8_t *in, size_t n, char *out);
/* a new file for writing, never an existing one or a link (NULL then) */
FILE *qdfnew(const char *path);
/* makes a folder; removes a file (isdir 0) or an empty folder */
int qdmkdir(const char *path);
int qdrm(const char *path, int isdir);

/* ---- bundles (bnd.c) ---- */

/* The bundle reader's input and output. rd puts up to n bytes at b and
 * their count in *got, 0 only at the end (NQOK, or NQEIO). put is called
 * with QDBBEG and an entry's path and size, QDBDAT with each piece of
 * its bytes, QDBEND when it ends; anything but NQOK stops the reader
 * with that code. */
enum { QDBBEG = 1, QDBDAT, QDBEND };
typedef struct {
  int (*rd)(void *u, uint8_t *b, size_t n, size_t *got);
  void *u;
  int (*put)(void *s, int op, const char *path, uint64_t size,
             const uint8_t *b, size_t n);
  void *s;
} qdbio;
/* reads one whole noqtis-bundle-1: NQOK, or NQEDEC/NQELIM with why */
int qdbread(const qdbio *io, char *why, size_t cap);

#endif /* NQDINT_H */
