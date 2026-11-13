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
/* The element of a keyed member ("sources", "schemas", "stats" by path,
 * "checks" by name) with key, as nqdat writes it; NQEIO when there is
 * none, NQEARG for a member that is not keyed. */
NQDAPI int nqdkey(const nqdrec *r, const char *member, const char *key,
                  char *out, size_t cap, size_t *outlen);
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

/* ---- drift ---- */

/* The summaries of the CSV file path in dir as a "stats" element
 * (canonical JSON), of a fixed size whatever the file's: per column the
 * values present and missing ("" and NA), and for a numeric column (every
 * value a number) a quantile sketch of 1,001 points (every distinct
 * value when there are at most 1,001), the population stability index's
 * bins and counts and the first-digit counts; for any other column the
 * counts of its 1,000 most frequent values and of the rest. o as for
 * nqdinfer (its ranges unused). noqtis-drift(1) defines each. */
NQDAPI int nqdstats(const char *dir, const char *path, const nqdcsvopt *o,
                    char *out, size_t cap, size_t *outlen, char *why,
                    size_t wcap);
/* When nqddrift calls a column drifted (NULL: the defaults): PSI at or
 * over psifail (0.25) fails a column when both samples have at least
 * minn (1,000) values, and warns below; PSI at or over psiwarn (0.1), or
 * a KS or chi-square p-value below alpha (0.001), warns; with benford 1,
 * a Benford p-value below alpha warns too. */
typedef struct {
  double psiwarn;
  double psifail;
  double alpha;
  double minn;
  int benford;
} nqddopt;
/* Compares the CSV file at file (any path) with the "stats" element
 * stats (n bytes): one row per column, "drift" (passed or failed) or
 * "drift.warn" (passed, with a warning), each with its numbers as JSON
 * (nqdrepj). A column of the reference that is gone fails; a new one
 * warns. NQOK when no row failed, NQEVRFY otherwise; *rep is set in
 * both cases. */
NQDAPI int nqddrift(const char *stats, size_t n, const char *file,
                    const nqdcsvopt *o, const nqddopt *d, nqdrep **rep);

/* Calibrates the warnings of the "stats" element stats (n bytes) on the
 * nf CSV files files[] known not to have drifted from it (o as for
 * nqddrift): each is compared with it as nqddrift does, and every
 * column gets "cal": the number of files, the largest PSI, the smallest
 * KS or chi-square p-value and the smallest Benford p-value seen. The
 * element with them goes to out (cap bytes, NUL added; *outlen its
 * length, also with NQEBUF). nqddrift then warns of a calibrated column
 * only for a PSI above that largest one or a p-value below that
 * smallest one, besides its thresholds; failures do not change. NQEDEC
 * with why when a file lacks a column of the reference or holds values
 * of another kind. */
NQDAPI int nqddcal(const char *stats, size_t n, const char *const *files,
                   size_t nf, const nqdcsvopt *o, char *out, size_t cap,
                   size_t *outlen, char *why, size_t wcap);

/* ---- commitments and citations ---- */

/* A commitment to n bytes at m (a randomisation list, an analysis plan)
 * under the secret salt (16 to 1,024 bytes, from nqrand): hex gets the
 * 64 hex digits of SHA3-256("noqtis-commit-1" || 0x00 || the salt's
 * length, 8 bytes big-endian || salt || m), for a "commits" element.
 * Without the salt it says nothing of m; with it, anyone can check m. */
NQDAPI int nqdcommit(const uint8_t *salt, size_t sl, const uint8_t *m,
                     size_t n, char hex[65]);
/* NQOK when the record r has a commitment to m under salt (*idx, when
 * not NULL, gets its index in "commits"), NQEVRFY when none matches;
 * every recorded digest is compared, in constant time. */
NQDAPI int nqdreveal(const nqdrec *r, const uint8_t *salt, size_t sl,
                     const uint8_t *m, size_t n, size_t *idx);
/* How to cite the data, from the record's "cite": NQDCFF writes a
 * CITATION.cff (1.2.0), NQDBIB a BibTeX entry, to out (cap bytes, NUL
 * added; *outlen its length, also with NQEBUF). NQEIO when the record
 * has no cite. */
#define NQDCFF 1
#define NQDBIB 2
NQDAPI int nqdcite(const nqdrec *r, int fmt, char *out, size_t cap,
                   size_t *outlen);

/* ---- reports ---- */

/* A report of the capsule in dir to out (cap bytes, NUL added; *outlen
 * its length, also with NQEBUF): NQDMD Markdown, NQDTXT plain text. It
 * says whether every check passed and how many failed, lists the rows
 * of crep (the capsule's check, from nqchkx; NULL when the folder is
 * not sealed, which counts as a failed check), then what the data
 * record says (sources, schemas, drift summaries, environment, steps,
 * recorded checks, commitments, citation) and the rows of drep (from
 * nqdchk; NULL to have it run here; no record, no rows). A value never
 * breaks its line or table cell: a line break is a space, and in
 * Markdown each character that could be read as markup is escaped with
 * one backslash. */
#define NQDMD 1
#define NQDTXT 2
NQDAPI int nqdrpt(const char *dir, const nqrep *crep, const nqdrep *drep,
                  int fmt, char *out, size_t cap, size_t *outlen);

/* ---- differences ---- */

/* What changed from the capsule in a to the one in b: one "file" row
 * per file added, removed or changed in the manifests (when both are
 * sealed), and one row per difference of their data records: sources,
 * schemas (columns added, removed or retyped, rows), stats (counts,
 * medians, the PSI between the two), env, steps, checks, commits, cite.
 * Every difference is a failed row. NQOK when nothing differs,
 * NQEVRFY otherwise, with *rep set. */
NQDAPI int nqddiff(const char *a, const char *b, nqdrep **rep);

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
/* the numbers of row i as canonical JSON, or NULL when it has none */
NQDAPI const char *nqdrepj(const nqdrep *r, size_t i);
NQDAPI void nqdrepfree(nqdrep *r);

#ifdef __cplusplus
}
#endif

#endif /* NQD_H */
