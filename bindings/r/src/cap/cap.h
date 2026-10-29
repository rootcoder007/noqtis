/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Capsules (DESIGN.md, "Capsule format, version 1"): the manifest
 * noqtis.json, the seal noqtis.sig, the canonical JSON writer (RFC 8785),
 * base64, path rules and the portable folder walk. Internal.
 *
 * Every allocation goes through nqmal/nqfree (the nqsetal hook). */
#ifndef NQCAP_H
#define NQCAP_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"
#include "core/json.h"
#include "der/x509.h"

#define NQCMAN "noqtis.json"
#define NQCSIG "noqtis.sig"
#define NQCFMT "noqtis-capsule-1"
#define NQCSFMT "noqtis-seal-1"
#define NQCCTX "noqtis-capsule-1"

#define NQCMANMAX ((size_t)512 << 20) /* noqtis.json */
#define NQCSIGMAX ((size_t)1 << 20)  /* noqtis.sig */
#define NQCMETAMAX ((size_t)1 << 20) /* the meta text given to nqseal */
#define NQCPATHMAX 4096              /* bytes in one relative path */
#define NQCDEPTH 64                  /* directory levels below the top */
#define NQCFILES 2000000             /* entries in one capsule */
#define NQCNUMMAX 512                /* bytes in one JSON number */
#define NQCANC 32                    /* TSA anchors given to nqchkt */
#define NQCMAXINT 9007199254740991ull /* 2^53 - 1: exact in a double */

/* The limits in force: the constants above, lowered only by the tests
 * (not thread safe; never raised past the constants). */
typedef struct {
  size_t man;   /* NQCMANMAX */
  size_t files; /* NQCFILES */
  size_t path;  /* NQCPATHMAX */
  size_t depth; /* NQCDEPTH */
} nqclimt;
extern nqclimt nqclim;

/* which limit a walk or seal ran into (nqclist.lim, nqcseal's *why) */
enum { NQCLFILES = 1, NQCLPATH, NQCLDEPTH, NQCLMAN, NQCLMETA };

/* ---- growable buffer: an error sticks (err) and later puts do nothing */

typedef struct {
  char *p;
  size_t n;
  size_t cap;
  int err;
} nqcbuf;

void nqcput(nqcbuf *b, const char *s, size_t n);
void nqcputs(nqcbuf *b, const char *s);
void nqcbfree(nqcbuf *b);

/* ---- canonical JSON (RFC 8785) ---- */

/* A string, quoted and escaped; s is UTF-8 (may hold NUL). */
void nqcjstr(nqcbuf *b, const char *s, size_t n);
/* A JSON number given as its text, in ECMAScript Number form. NQEDEC for
 * text that is not a finite number, NQELIM over NQCNUMMAX bytes. */
int nqcjnum(nqcbuf *b, const char *txt, size_t n);
/* A non-negative integer up to NQCMAXINT. */
void nqcjint(nqcbuf *b, uint64_t v);
/* A whole parsed value, keys sorted by UTF-16 code units, no recursion. */
int nqcjval(nqcbuf *b, const nqjs *v);
/* <0, 0, >0: the RFC 8785 key order of two UTF-8 strings. */
int nqcjcmp(const char *a, size_t an, const char *b, size_t bn);

/* ---- base64 (RFC 4648 section 4, padded, strict) ---- */

size_t nqb64n(size_t n); /* encoded length, without the NUL */
void nqb64e(const uint8_t *in, size_t n, char *out);
int nqb64d(const char *s, size_t n, uint8_t *out, size_t cap,
           size_t *outlen);

/* ---- sorting: a stable merge sort of an index array ---- */

typedef int (*nqccmp)(const void *ctx, size_t a, size_t b);
int nqcsort(size_t *idx, size_t n, nqccmp cmp, const void *ctx);

/* ---- paths ---- */

/* 1 when the UTF-8 bytes are valid (no overlongs, no surrogates). */
int nqcutf8(const char *s, size_t n);
/* 1 when one name (a segment) may appear in a capsule: valid UTF-8, no
 * control character, no '/', '\\' or ':', not "." or "..", not empty. */
int nqcname(const char *s, size_t n);
/* Normalises a manifest path: drops empty and "." segments; NQEDEC for
 * a leading '/', "..", NUL, or a segment nqcname refuses. out holds cap
 * bytes; *outlen excludes the NUL written after it. */
int nqcnorm(const char *p, size_t n, char *out, size_t cap,
            size_t *outlen);
/* ASCII case-folded comparison (case collisions). */
int nqcfold(const char *a, size_t an, const char *b, size_t bn);

/* ---- RFC 3339 times ---- */

/* "YYYY-MM-DDTHH:MM:SSZ" (21 bytes with the NUL), years 1970-9999. */
int nqctime(int64_t t, char out[21]);
/* 1 when s is an RFC 3339 UTC date-time: the form above, optionally
 * with fractional seconds before the 'Z'. */
int nqctchk(const char *s, size_t n);

/* ---- the folder ---- */

enum { NQCREG = 1, NQCLNK, NQCODD, NQCBAD };

typedef struct {
  char *path;   /* relative, '/' separated, NUL-terminated */
  size_t len;
  int kind;     /* NQCREG, NQCLNK (symlink, reparse point), NQCODD (not a
                 * regular file or folder), NQCBAD (name refused) */
  uint64_t size;
} nqcent;

typedef struct {
  nqcent *e;
  size_t n;
  size_t cap;
  int lim; /* NQCL* when the walk stopped at a limit (NQELIM) */
} nqclist;

/* Lists every entry under dir without following links, sorted by path
 * bytes, leaving out noqtis.json and noqtis.sig at the top. Folders are
 * walked, not listed; a link or a refused name is listed, not entered. */
int nqcwalk(const char *dir, nqclist *l);
void nqclfree(nqclist *l);
/* Streams dir/rel (a regular file, never through a link) into SHA-256
 * and SHA3-256. */
int nqcdig(const char *dir, const char *rel, uint64_t *size,
           uint8_t s2[32], uint8_t s3[32]);
/* Reads dir/name (at most max bytes, never through a link) into a fresh
 * NUL-terminated buffer; free with nqfree(*buf, *n + 1). The size is
 * checked before anything is read, and again if the file grows while it
 * is read (NQELIM either way). */
int nqcread(const char *dir, const char *name, size_t max, char **buf,
            size_t *n);
/* Writes n bytes to dir/name, replacing it. */
int nqcwrite(const char *dir, const char *name, const char *buf, size_t n);

/* ---- seal ---- */

/* nqseal with the creation time given and, when rnd is not NULL, the
 * signing randomness (nqsignd), for reproducible capsules and tests.
 * When it returns NQELIM, *why (if not NULL) is the NQCL* limit hit. */
int nqcseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, const char *meta,
            const char *tsa, int64_t created, const uint8_t *rnd,
            size_t rndlen, int *why);
/* "too many files", "path too long", ... for an NQCL* code; NULL for 0. */
const char *nqclwhy(int lim);

/* ---- timestamps ---- */

/* The nqxops src/der uses to check a TSA's token and certificates. */
const nqxops *nqcxops(void);

#endif /* NQCAP_H */
