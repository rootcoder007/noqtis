/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A strict JSON reader (RFC 8259): UTF-8 only, no comments, no trailing
 * commas, no duplicate keys, depth and size limits, no recursion. Numbers
 * are kept as their text. Internal: used by the ACVP harnesses, the tests
 * and the capsule layer. */
#ifndef NQJSON_H
#define NQJSON_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  NQJNULL = 1, NQJFALSE, NQJTRUE, NQJNUM, NQJSTR, NQJARR, NQJOBJ
} nqjtype;

typedef struct nqjs nqjs;

struct nqjs {
  nqjtype type;
  /* NUM: its text; STR: decoded UTF-8 (may hold NUL; see len) */
  char *str;
  size_t len;
  /* ARR / OBJ: children in document order; for OBJ, keys[i] (of length
   * klen[i]) is the key of kids[i] */
  nqjs **kids;
  char **keys;
  size_t *klen;
  size_t n;
  size_t cap;
};

#define NQJDEPTH 64

/* Parses exactly one JSON value spanning all of buf (surrounding
 * whitespace allowed). On error returns NQEDEC (or NQELIM / NQEMEM) and,
 * when erroff is not NULL, the byte offset of the error. */
int nqjparse(const char *buf, size_t len, nqjs **out, size_t *erroff);
void nqjfree(nqjs *v);

/* Lookups; NULL when absent or of another type. */
const nqjs *nqjget(const nqjs *obj, const char *key);
const nqjs *nqjat(const nqjs *arr, size_t i);
/* The NUL-terminated text of a STR (NULL if not a string or if it holds an
 * embedded NUL). */
const char *nqjstr(const nqjs *v);
/* An integer NUM that fits in int64 (no fraction, no exponent). */
int nqjint(const nqjs *v, int64_t *out);
/* 1 for TRUE, 0 for FALSE, -1 otherwise. */
int nqjbool(const nqjs *v);

/* Reads a whole file into a fresh buffer (nqmal'd, NUL-terminated); free
 * with nqfree(buf, *len + 1). Refuses files over maxlen bytes. */
int nqreadf(const char *path, size_t maxlen, char **buf, size_t *len);

/* Hex: lower- or upper-case input of even length. */
int nqunhex(const char *hex, size_t hexlen, uint8_t *out, size_t cap,
            size_t *outlen);
/* out holds 2*len+1 bytes; lower case, NUL-terminated. */
void nqhex(const uint8_t *in, size_t len, char *out);

#endif /* NQJSON_H */
