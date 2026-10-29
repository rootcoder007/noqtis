/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* What the ACVP harnesses share: reading a request (the "prompt" a CAVP
 * lab's ACVP server sends), writing the response through the canonical
 * JSON writer of src/cap, and the semantic comparison of a response
 * with an expected-results file.
 *
 * A request is either the vector set object itself (ACVP-Server
 * gen-val files) or, as a live server sends it, [{"acvVersion": ...},
 * {vector set}]; the response takes the same form. */
#ifndef NQACV_H
#define NQACV_H

#include <stddef.h>
#include <stdint.h>

#include "cap/cap.h"
#include "core/json.h"

/* ---- reading ---- */

/* Reads and parses a JSON file; NULL (and a message) on failure. */
nqjs *acvld(const char *path);
/* The vector set object, and its testGroups array (NULL if absent). */
const nqjs *acvset(const nqjs *v);
const nqjs *acvgrps(const nqjs *v);
/* A field of the test, else of its group (keys some servers move). */
const nqjs *acvfld(const nqjs *t, const nqjs *g, const char *key);
/* An unsigned integer given as a JSON number or a decimal string. */
int acvu(const nqjs *o, const char *key, uint64_t *out);
/* The text of a string field, or NULL. */
const char *acvs(const nqjs *o, const char *key);
/* 1 when the string field key is val. */
int acvis(const nqjs *o, const char *key, const char *val);
/* A hex field decoded into a fresh buffer (at least one byte allocated,
 * so an empty field is not NULL); NULL when missing or not hex. */
uint8_t *acvhex(const nqjs *v, size_t *n);
/* An nqhalg by its ACVP name ("SHA2-256", "SHA3-512", "SHAKE-128",
 * "SHA2-512/224", ...); -1 when unknown. */
int acvhalg(const char *name);

/* ---- writing ---- */

typedef struct {
  nqcbuf b;
  int first[16]; /* the next item at each depth is the first */
  int d;
  int wrap;      /* the request was [{"acvVersion"}, {...}] */
} acvw;

/* Starts the response to request pr: the wrapper, the vector set's
 * identifying fields, and "testGroups":[. */
void acvbeg(acvw *w, const nqjs *pr);
/* {"tgId":tg,"tests":[ ... ]} */
void acvgbeg(acvw *w, uint64_t tg);
void acvgend(acvw *w);
/* {"tcId":tc ... } */
void acvtbeg(acvw *w, uint64_t tc);
void acvtend(acvw *w);
/* "key": an object or array opened inside the current test (key NULL
 * inside an array), and its end */
void acvobj(acvw *w, const char *key);
void acvarr(acvw *w, const char *key);
void acvclose(acvw *w, char c);
/* "key":<upper-case hex>, "key":true|false, "key":n */
void acvkhex(acvw *w, const char *key, const uint8_t *p, size_t n);
void acvkbool(acvw *w, const char *key, int b);
void acvkint(acvw *w, const char *key, uint64_t v);

/* ---- the program ---- */

/* One harness: answers every test of request pr into w. Returns NQOK,
 * or an error after printing which test it could not answer. *omit
 * counts the tests left out on purpose (a mode the library does not
 * provide, or NQFAST / NQSLSUB sampling), each named on stderr. */
typedef int (*acvfn)(const nqjs *pr, acvw *w, long *omit);

/*   <name> <request.json> <response.json> [<expected.json>]
 * Writes the response; with an expected-results file, compares the two
 * (acvcmp) and fails unless every answered test matches and exactly
 * the omitted ones are missing. Exit 0 on success, 1 otherwise. */
int acvmain(int argc, char **argv, const char *name, acvfn run);

/* Compares a response with expected results: the same tests (tgId,
 * tcId), and in each the same fields with equal values (objects in any
 * key order, hex strings in any case). *match and *miss get the tests
 * that match and the expected tests the response lacks; returns the
 * number of differences (wrong or extra tests). */
long acvcmp(const nqjs *exp, const nqjs *resp, long *match, long *miss);

#endif /* NQACV_H */
