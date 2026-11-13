/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqd internals: memory, growing buffers, the JSON tree with its strict
 * reader and canonical (RFC 8785) writer, the CSV reader and the column
 * summaries. Not part of the public API; nqd uses only noqtis.h of the
 * core. */
#ifndef NQDINT_H
#define NQDINT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "noqtis.h"
#include "nqd.h"

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
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 3, 4)))
#endif
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
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;
nqdrep *qdrepnew(void);

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

#endif /* NQDINT_H */
