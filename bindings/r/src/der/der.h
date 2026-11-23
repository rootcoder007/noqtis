/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* A strict DER reader (X.690 clause 10, with the X.509 profile's limits).
 * Internal: used by the X.509, OCSP, CRL and RFC 3161 parsers.
 *
 * Nothing here allocates or recurses. A cursor (nqdcur) walks the
 * elements of one level of the caller's bytes; nqddown opens a
 * constructed element as a new cursor one level deeper. nqdwalk checks a
 * whole tree with an explicit stack. Every length is checked against the
 * bytes that remain in its parent before anything is read.
 *
 * Rules enforced on every element:
 * - definite lengths only, in the shortest form (no leading zero length
 *   octet, the long form only for 128 and above), at most 4 length
 *   octets;
 * - tag numbers in the shortest form, at most NQDTAGMAX, no high-form
 *   universal tags, no universal tag 0 (end-of-contents);
 * - universal SEQUENCE and SET constructed, every other universal type
 *   primitive (DER has no constructed strings), and only the universal
 *   types the PKIX formats use;
 * - at most NQDDEPTH levels of nesting.
 * nqdwalk also checks the contents of every universal primitive (see
 * nqdprim) and that the elements of every universal SET are in DER
 * order. */
#ifndef NQDER_H
#define NQDER_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

#define NQDDEPTH 32         /* the deepest nesting accepted */
#define NQDTAGMAX 0x1fffffu /* the largest tag number (three septets) */

/* tag classes */
#define NQDUNI 0
#define NQDAPP 1
#define NQDCTX 2
#define NQDPRV 3

/* universal tags */
#define NQDBOOL 1
#define NQDINT 2
#define NQDBITS 3
#define NQDOCT 4
#define NQDNULL 5
#define NQDOID 6
#define NQDENUM 10
#define NQDUTF8 12
#define NQDSEQ 16
#define NQDSET 17
#define NQDNUMS 18
#define NQDPRT 19
#define NQDT61 20
#define NQDVTX 21
#define NQDIA5 22
#define NQDUTC 23
#define NQDGEN 24
#define NQDGRA 25
#define NQDVIS 26
#define NQDGNR 27
#define NQDUNIS 28
#define NQDBMP 30

/* A byte range in the caller's buffer. */
typedef struct {
  const uint8_t *p;
  size_t n;
} nqspan;

/* One element. */
typedef struct {
  uint8_t cls;     /* NQDUNI, NQDAPP, NQDCTX or NQDPRV */
  uint8_t con;     /* 1 when constructed */
  uint32_t tag;
  nqspan v;        /* the contents */
  nqspan raw;      /* identifier, length and contents */
  unsigned depth;  /* 0 for an element at the top */
} nqdtlv;

/* A cursor over the elements of one level. */
typedef struct {
  const uint8_t *p;
  size_t pos;
  size_t end;
  unsigned depth;  /* the depth of the elements it returns */
} nqdcur;

/* Reads the identifier and length at p (n bytes available) into t, with
 * t->depth 0; the contents must fit in n. No content checks. */
int nqdhdr(const uint8_t *p, size_t n, nqdtlv *t);

/* A cursor over the top-level elements of p. */
void nqdinit(nqdcur *c, const uint8_t *p, size_t n);
/* 1 when no element is left. */
int nqdend(const nqdcur *c);
/* The next element; NQEDEC at the end or on a malformed header. */
int nqdnext(nqdcur *c, nqdtlv *t);
/* The next element without moving past it. */
int nqdpeek(const nqdcur *c, nqdtlv *t);
/* A cursor over the contents of a constructed element; NQEDEC for a
 * primitive one, NQELIM beyond NQDDEPTH. */
int nqddown(const nqdtlv *t, nqdcur *in);
/* The next element, which must have class cls, constructed bit con and
 * tag number tag; NQEDEC otherwise. */
int nqdget(nqdcur *c, unsigned cls, unsigned con, uint32_t tag,
           nqdtlv *t);
/* As nqdget, but the element is optional: *got is 0 (and nothing is
 * consumed) when the next element is absent or of another tag. */
int nqdopt(nqdcur *c, unsigned cls, unsigned con, uint32_t tag,
           nqdtlv *t, int *got);
/* NQOK when the cursor is at its end, NQEDEC otherwise. */
int nqddone(const nqdcur *c);

/* Checks that p is exactly one element (no trailing bytes) and that its
 * whole tree follows every rule above, contents included; t gets the
 * element when not NULL. */
int nqdone(const uint8_t *p, size_t n, nqdtlv *t);
/* The tree check of nqdone on an element already read. */
int nqdwalk(const uint8_t *p, size_t n);
/* The contents check for one universal primitive of tag tag: BOOLEAN
 * 00/FF, INTEGER and ENUMERATED minimal, NULL empty, OID canonical, BIT
 * STRING padding zero, the character sets of the string types and valid
 * UTF-8 / BMP / Universal strings, and the exact DER forms of UTCTime
 * and GeneralizedTime. */
int nqdprim(uint32_t tag, const uint8_t *v, size_t n);

/* ---- typed helpers; each checks the element's class and tag ---- */

/* BOOLEAN: *b is 0 or 1. */
int nqdbool(const nqdtlv *t, int *b);
/* INTEGER, minimal; *mag gets the magnitude without a leading 00 sign
 * octet and *neg whether it is negative. */
int nqdint(const nqdtlv *t, nqspan *mag, int *neg);
/* An INTEGER (or, for nqdenum, ENUMERATED) that fits in int64. */
int nqdi64(const nqdtlv *t, int64_t *v);
int nqdenum(const nqdtlv *t, int64_t *v);
/* OBJECT IDENTIFIER: canonical base-128, at least two arcs, no arc above
 * 2^32 - 1, at most 64 arcs. */
int nqdoidok(const uint8_t *v, size_t n);
int nqdoid(const nqdtlv *t, nqspan *oid);
/* 1 when t is an OID whose contents are the n bytes at oid. */
int nqdoideq(const nqdtlv *t, const uint8_t *oid, size_t n);
/* BIT STRING; *bits gets the octets after the unused-bits octet. */
int nqdbits(const nqdtlv *t, nqspan *bits, unsigned *unused);
/* A BIT STRING with no unused bits (keys and signatures). */
int nqdbit0(const nqdtlv *t, nqspan *bits);
/* A named-bit BIT STRING (DER: no trailing zero bits) of at most 32
 * bits; bit i of *bits is named bit i (bit 0 is the first). */
int nqdnbits(const nqdtlv *t, uint32_t *bits);
/* NULL. */
int nqdnull(const nqdtlv *t);

/* Times. UTCTime YYMMDDHHMMSSZ (years 1950-2049) and GeneralizedTime
 * YYYYMMDDHHMMSS[.f]Z, digits only, Z only, no trailing zero in the
 * fraction, every field in range (no leap second). *secs gets seconds
 * since 1970-01-01T00:00:00Z, *nsec (may be NULL) the fraction in
 * nanoseconds (at most nine fraction digits).
 * NQDTFRAC allows a fraction (RFC 3161 genTime); NQDT5280 applies
 * RFC 5280 4.1.2.5 (UTCTime through 2049, GeneralizedTime from 2050,
 * no fraction). */
#define NQDTFRAC 1u
#define NQDT5280 2u
int nqdtime(const nqdtlv *t, unsigned flags, int64_t *secs, uint32_t *nsec);

/* 1 when the spans hold the same bytes. */
int nqdseq(nqspan a, nqspan b);

/* ---- the writer (wr.c) ---- */

/* A growing buffer of DER. An error sticks in err (NQEMEM, NQELIM for a
 * length past 2^32 - 1, NQEARG for a time out of range); calls after it
 * do nothing. */
typedef struct {
  uint8_t *p;
  size_t n;
  size_t cap;
  int err;
} nqdw;

/* identifier octets beside the universal tags above */
#define NQDWSEQ 0x30u            /* SEQUENCE */
#define NQDWSET 0x31u            /* SET */
#define NQDWCTX(n) (0x80u | (n)) /* [n] IMPLICIT, primitive */
#define NQDWCON(n) (0xa0u | (n)) /* [n], constructed */

void nqdwini(nqdw *w);
void nqdwfree(nqdw *w);
/* Bytes as they are (an element made elsewhere). */
void nqdwraw(nqdw *w, const uint8_t *p, size_t n);
/* A primitive element: the identifier octet id, the contents v. */
void nqdwtlv(nqdw *w, unsigned id, const uint8_t *v, size_t n);
/* Opens a constructed element with the identifier octet id; the mark
 * goes to nqdwclose once its contents are written. */
size_t nqdwopen(nqdw *w, unsigned id);
void nqdwclose(nqdw *w, size_t mark);
/* INTEGER: a non-negative value, or the magnitude mag of one (leading
 * zeros dropped, a 00 added when the top bit is set). */
void nqdwuint(nqdw *w, uint64_t v);
void nqdwmag(nqdw *w, const uint8_t *mag, size_t n);
/* OBJECT IDENTIFIER (its contents), NULL, BOOLEAN, OCTET STRING, a BIT
 * STRING with no unused bits, UTF8String. */
void nqdwoid(nqdw *w, const uint8_t *oid, size_t n);
void nqdwnull(nqdw *w);
void nqdwbool(nqdw *w, int b);
void nqdwoct(nqdw *w, const uint8_t *p, size_t n);
void nqdwbits(nqdw *w, const uint8_t *p, size_t n);
void nqdwutf8(nqdw *w, const char *s, size_t n);
/* A time t (seconds since 1970, to 9999): UTCTime through 2049 and
 * GeneralizedTime from 2050 (RFC 5280), or with gen GeneralizedTime
 * always. */
void nqdwtime(nqdw *w, int64_t t, int gen);
/* Ends the writer: NQOK with the bytes in a new buffer of exactly *n
 * bytes (nqfree(*out, *n ? *n : 1)), or the error that stuck; the
 * writer is freed either way. */
int nqdwend(nqdw *w, uint8_t **out, size_t *n);

#endif /* NQDER_H */
