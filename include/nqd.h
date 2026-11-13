/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * nqd: the data layer of noqtis. A data record (noqtis.data.json, format
 * noqtis-data-1, see noqtis-data(5)) says where each file of a capsule
 * came from, what shape it has and how it was summarised, so that the
 * capsule's seal (which lists the record like any other file) covers it
 * and `noqtis data check` can check the files against it.
 *
 * nqd is a separate library built only on the public API of noqtis.h;
 * it is not part of the audited core. It makes no network request:
 * where a source must be fetched, it builds the request and reads the
 * reply, and the caller moves the bytes. Every function returns NQOK
 * (0) or a negative NQE* code of noqtis.h. Strings are UTF-8.
 */
#ifndef NQD_H
#define NQD_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NQDAPI marks nqd's public functions, as NQAPI does the core's: a
 * Windows DLL build of nqd defines NQDBUILD and NQDLL. */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(NQDLL) && defined(NQDBUILD)
#    define NQDAPI __declspec(dllexport)
#  elif defined(NQDLL)
#    define NQDAPI __declspec(dllimport)
#  else
#    define NQDAPI
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define NQDAPI __attribute__((visibility("default")))
#else
#  define NQDAPI
#endif

/* the record's format and its file name in a capsule folder */
#define NQDFMT "noqtis-data-1"
#define NQDFILE "noqtis.data.json"
/* the largest record nqdload and nqdparse read */
#define NQDMAX ((size_t)64 << 20)

typedef struct nqdrec nqdrec;
typedef struct nqdrep nqdrep;

/* ---- records ---- */

/* A new record that holds only its format. */
NQDAPI int nqdnew(nqdrec **r);
/* Reads the n bytes of JSON text at json as a record: every member must
 * be one noqtis-data-1 defines, of its type, every required member
 * present, no key twice; arrays keyed by path or name are sorted here.
 * NQEDEC (NQELIM over NQDMAX bytes) with a sentence in why (cap bytes,
 * may be NULL) saying what is wrong and where. */
NQDAPI int nqdparse(const char *json, size_t n, nqdrec **r, char *why,
                    size_t cap);
/* nqdparse of dir/noqtis.data.json, which must also be in canonical
 * form (the bytes nqdjson writes). NQEIO when there is no record. */
NQDAPI int nqdload(const char *dir, nqdrec **r, char *why, size_t cap);
/* The record as canonical JSON (RFC 8785) to out (cap bytes, NUL added);
 * *outlen gets the length, also with NQEBUF when cap is too small. */
NQDAPI int nqdjson(const nqdrec *r, char *out, size_t cap, size_t *outlen);
/* Writes the record to dir/noqtis.data.json (through a temporary file
 * and a rename). */
NQDAPI int nqdsave(const nqdrec *r, const char *dir);
NQDAPI void nqdrfree(nqdrec *r);

/* Members: "sources", "schemas", "stats", "steps", "checks", "commits"
 * (arrays) and "env", "cite" (objects). nqdlen is the number of
 * elements of an array member, 1 or 0 for an object member, 0 for an
 * unknown name. */
NQDAPI size_t nqdlen(const nqdrec *r, const char *member);
/* Element i of member (i 0 for an object member) as canonical JSON. */
NQDAPI int nqdat(const nqdrec *r, const char *member, size_t i, char *out,
                  size_t cap, size_t *outlen);
/* Adds the element json (n bytes) to member, checked as nqdparse checks
 * it: "sources", "schemas" and "stats" are keyed by "path" and
 * "checks" by "name", and an element with the same key is replaced;
 * "steps" and "commits" are appended; "env" and "cite" are set. NQEDEC
 * with why for an element that is not valid. */
NQDAPI int nqdput(nqdrec *r, const char *member, const char *json, size_t n,
                  char *why, size_t cap);
/* Removes the element of member with key (its path or name), or, with
 * key NULL, the whole member. NQEIO when there is none such. */
NQDAPI int nqddel(nqdrec *r, const char *member, const char *key);

/* Sets field of the element of member with key (its path or name; NULL
 * for "env" or "cite") to the JSON value json (n bytes), or removes the
 * field when json is NULL; the element must still be valid after it
 * (NQEDEC with why otherwise, and nothing changes). NQEIO when there is
 * no such element. */
NQDAPI int nqdset(nqdrec *r, const char *member, const char *key,
                  const char *field, const char *json, size_t n, char *why,
                  size_t cap);
/* Records the SHA-256 and size of the file path (relative to dir, '/'
 * between folders) in its "sources" element, keeping the element's
 * other fields (url, retrieved, ...), or adds the element. NQEARG for a
 * path a capsule cannot hold, NQEIO when the file cannot be read. */
NQDAPI int nqdsrc(nqdrec *r, const char *dir, const char *path, char *why,
                  size_t cap);

/* ---- schemas of CSV files ---- */

/* How nqdinfer reads a file: delim 0 for ',' (else one byte, not a
 * quote or a line break); noheader 1 when the first line is data (the
 * columns are then named V1, V2, ...); ranges 1 to pin each number and
 * date column's smallest and largest value too. NULL: the defaults. */
typedef struct {
  char delim;
  int noheader;
  int ranges;
} nqdcsvopt;

/* The schema of the CSV file path in dir, as a "schemas" element in
 * canonical JSON: its columns with their names and types (bool, int,
 * real, date, text, the narrowest every value fits; "" and "NA" are
 * missing), whether each has missing values, and its number of rows,
 * pinned. NQEDEC with why for a file that is not CSV (RFC 4180) or has
 * rows of different lengths or a column name twice. */
NQDAPI int nqdinfer(const char *dir, const char *path, const nqdcsvopt *o,
                    char *out, size_t cap, size_t *outlen, char *why,
                    size_t wcap);
/* Checks the file of the "schemas" element schema (n bytes of JSON)
 * in dir against it: the header, every value's type, missing values,
 * ranges and sets, the row bounds and each rule. NQOK when every row
 * passed, NQEVRFY otherwise, with *rep set in both cases. */
NQDAPI int nqdschk(const char *dir, const char *schema, size_t n,
                   nqdrep **rep);

/* ---- checking ---- */

/* Checks the record in dir: that it parses and is canonical, that each
 * source file is there with its recorded SHA-256 and size, that each
 * schema's file matches its schema and rules, and lists the recorded
 * checks. NQOK when every row passed, NQEVRFY otherwise; *rep is set in
 * both cases (free with nqdrepfree). Rows of a synthetic source say so
 * in their detail. */
NQDAPI int nqdchk(const char *dir, nqdrep **rep);
NQDAPI size_t nqdrepn(const nqdrep *r);
NQDAPI int nqdrepi(const nqdrep *r, size_t i, const char **check, int *ok,
                   const char **detail);
NQDAPI void nqdrepfree(nqdrep *r);

#ifdef __cplusplus
}
#endif

#endif /* NQD_H */
