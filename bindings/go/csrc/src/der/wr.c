/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* A DER writer (X.690 clause 10): definite lengths in the shortest form,
 * what the reader of der.c accepts. Internal: used to build
 * certificates and CMS structures.
 *
 * A writer (nqdw) is a buffer that grows; an error (no memory, a length
 * past 2^32 - 1) sticks, later calls do nothing, and nqdwend reports it.
 * A constructed element is opened with nqdwopen, which returns a mark,
 * filled by further calls, and closed with nqdwclose(mark), which writes
 * its length. */
#include <string.h>

#include "core/int.h"
#include "der/der.h"

void nqdwini(nqdw *w) { memset(w, 0, sizeof *w); }

void nqdwfree(nqdw *w) {
  if (w->p != NULL) nqfree(w->p, w->cap);
  memset(w, 0, sizeof *w);
}

static int room(nqdw *w, size_t more) {
  uint8_t *q;
  size_t cap;
  if (w->err != NQOK) return 0;
  if (more > (size_t)-1 - w->n) {
    w->err = NQELIM;
    return 0;
  }
  if (w->n + more <= w->cap) return 1;
  cap = w->cap < 256 ? 256 : w->cap;
  while (cap < w->n + more) {
    if (cap > (size_t)-1 / 2) {
      w->err = NQELIM;
      return 0;
    }
    cap *= 2;
  }
  q = (uint8_t *)nqmal(cap);
  if (q == NULL) {
    w->err = NQEMEM;
    return 0;
  }
  if (w->n > 0) memcpy(q, w->p, w->n);
  if (w->p != NULL) nqfree(w->p, w->cap);
  w->p = q;
  w->cap = cap;
  return 1;
}

void nqdwraw(nqdw *w, const uint8_t *p, size_t n) {
  if (n == 0 || !room(w, n)) return;
  memcpy(w->p + w->n, p, n);
  w->n += n;
}

/* the length octets of n into l; their number: one, or one that
 * counts them and up to eight more (a size_t of 64 bits) */
static size_t lenof(size_t n, uint8_t l[9]) {
  uint8_t b[8];
  size_t k = 8, i;
  if (n < 128) {
    l[0] = (uint8_t)n;
    return 1;
  }
  for (i = 0; i < 8; i++) b[i] = (uint8_t)((uint64_t)n >> (8 * (7 - i)));
  while (k > 1 && b[8 - k] == 0) k--;
  l[0] = (uint8_t)(0x80 | k);
  for (i = 0; i < 8; i++)
    if (i < k) l[1 + i] = b[8 - k + i];
  return 1 + k;
}

void nqdwtlv(nqdw *w, unsigned id, const uint8_t *v, size_t n) {
  uint8_t l[9];
  size_t ln;
  if (n > 0xffffffffu) {
    if (w->err == NQOK) w->err = NQELIM;
    return;
  }
  ln = lenof(n, l);
  if (!room(w, 1 + ln + n)) return;
  w->p[w->n++] = (uint8_t)id;
  memcpy(w->p + w->n, l, ln);
  w->n += ln;
  if (n > 0) memcpy(w->p + w->n, v, n);
  w->n += n;
}

size_t nqdwopen(nqdw *w, unsigned id) {
  size_t mark = w->n;
  /* the identifier and one length octet: nqdwclose makes room for more */
  if (room(w, 2)) {
    w->p[w->n++] = (uint8_t)id;
    w->p[w->n++] = 0;
  }
  return mark;
}

void nqdwclose(nqdw *w, size_t mark) {
  uint8_t l[9];
  size_t n, ln;
  if (w->err != NQOK) return;
  n = w->n - mark - 2;
  if (n > 0xffffffffu) {
    w->err = NQELIM;
    return;
  }
  ln = lenof(n, l);
  if (ln > 1) {
    if (!room(w, ln - 1)) return;
    memmove(w->p + mark + 1 + ln, w->p + mark + 2, n);
    w->n += ln - 1;
  }
  memcpy(w->p + mark + 1, l, ln);
}

void nqdwuint(nqdw *w, uint64_t v) {
  uint8_t b[9];
  size_t n = 0, i;
  for (i = 0; i < 8; i++) b[1 + i] = (uint8_t)(v >> (8 * (7 - i)));
  b[0] = 0;
  /* the shortest form: no leading 00 unless the next bit is set */
  while (n < 8 && b[n] == 0 && (b[n + 1] & 0x80) == 0) n++;
  nqdwtlv(w, NQDINT, b + n, 9 - n);
}

void nqdwmag(nqdw *w, const uint8_t *mag, size_t n) {
  size_t mark;
  while (n > 1 && mag[0] == 0) {
    mag++;
    n--;
  }
  if (n == 0) {
    nqdwuint(w, 0);
    return;
  }
  if ((mag[0] & 0x80) == 0) {
    nqdwtlv(w, NQDINT, mag, n);
    return;
  }
  mark = nqdwopen(w, NQDINT);
  nqdwraw(w, (const uint8_t *)"\0", 1);
  nqdwraw(w, mag, n);
  nqdwclose(w, mark);
}

void nqdwoid(nqdw *w, const uint8_t *oid, size_t n) {
  nqdwtlv(w, NQDOID, oid, n);
}

void nqdwnull(nqdw *w) { nqdwtlv(w, NQDNULL, NULL, 0); }

void nqdwbool(nqdw *w, int b) {
  uint8_t v = b ? 0xff : 0x00;
  nqdwtlv(w, NQDBOOL, &v, 1);
}

void nqdwoct(nqdw *w, const uint8_t *p, size_t n) {
  nqdwtlv(w, NQDOCT, p, n);
}

void nqdwbits(nqdw *w, const uint8_t *p, size_t n) {
  size_t mark = nqdwopen(w, NQDBITS);
  nqdwraw(w, (const uint8_t *)"\0", 1);
  nqdwraw(w, p, n);
  nqdwclose(w, mark);
}

void nqdwutf8(nqdw *w, const char *s, size_t n) {
  nqdwtlv(w, NQDUTF8, (const uint8_t *)s, n);
}

/* civil date of days since 1970-01-01 */
static void civil(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
  int64_t era, doe, yoe, doy, mp;
  z += 719468;
  era = (z >= 0 ? z : z - 146096) / 146097;
  doe = z - era * 146097;
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  mp = (5 * doy + 2) / 153;
  *d = (unsigned)(doy - (153 * mp + 2) / 5 + 1);
  *m = (unsigned)(mp < 10 ? mp + 3 : mp - 9);
  *y = yoe + era * 400 + (*m <= 2);
}

static void two(char *o, unsigned v) {
  o[0] = (char)('0' + v / 10 % 10);
  o[1] = (char)('0' + v % 10);
}

void nqdwtime(nqdw *w, int64_t t, int gen) {
  char s[16];
  int64_t days, rem, y;
  unsigned m, d;
  if (t < 0 || t > 253402300799ll) {
    if (w->err == NQOK) w->err = NQEARG;
    return;
  }
  days = t / 86400;
  rem = t % 86400;
  civil(days, &y, &m, &d);
  /* RFC 5280 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050;
   * gen asks for GeneralizedTime whatever the year (CMS signingTime
   * follows the same rule, RFC 3161 genTime does not) */
  if (!gen && y >= 1950 && y <= 2049) {
    two(s, (unsigned)(y % 100));
    two(s + 2, m);
    two(s + 4, d);
    two(s + 6, (unsigned)(rem / 3600));
    two(s + 8, (unsigned)(rem % 3600 / 60));
    two(s + 10, (unsigned)(rem % 60));
    s[12] = 'Z';
    nqdwtlv(w, NQDUTC, (const uint8_t *)s, 13);
    return;
  }
  two(s, (unsigned)(y / 100));
  two(s + 2, (unsigned)(y % 100));
  two(s + 4, m);
  two(s + 6, d);
  two(s + 8, (unsigned)(rem / 3600));
  two(s + 10, (unsigned)(rem % 3600 / 60));
  two(s + 12, (unsigned)(rem % 60));
  s[14] = 'Z';
  nqdwtlv(w, NQDGEN, (const uint8_t *)s, 15);
}

int nqdwend(nqdw *w, uint8_t **out, size_t *n) {
  int rc = w->err;
  if (rc != NQOK) {
    nqdwfree(w);
    return rc;
  }
  /* an exact buffer, so that the caller frees it by its length */
  *out = (uint8_t *)nqmal(w->n > 0 ? w->n : 1);
  if (*out == NULL) {
    nqdwfree(w);
    return NQEMEM;
  }
  if (w->n > 0) memcpy(*out, w->p, w->n);
  *n = w->n;
  nqdwfree(w);
  return NQOK;
}
