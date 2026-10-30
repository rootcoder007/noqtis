/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The strict DER reader: headers, cursors, the tree check and the typed
 * helpers. See der.h for the rules. */
#include <string.h>

#include "der/der.h"

/* The universal tags the PKIX formats use, and whether each is
 * constructed: 1 primitive, 2 constructed, 0 not accepted. */
static int unikind(uint32_t tag) {
  switch (tag) {
  case NQDSEQ:
  case NQDSET:
    return 2;
  case NQDBOOL: case NQDINT: case NQDBITS: case NQDOCT: case NQDNULL:
  case NQDOID: case NQDENUM: case NQDUTF8: case NQDNUMS: case NQDPRT:
  case NQDT61: case NQDVTX: case NQDIA5: case NQDUTC: case NQDGEN:
  case NQDGRA: case NQDVIS: case NQDGNR: case NQDUNIS: case NQDBMP:
    return 1;
  default:
    return 0;
  }
}

int nqdhdr(const uint8_t *p, size_t n, nqdtlv *t) {
  size_t i = 0, len;
  uint32_t tag;
  uint8_t id, b;
  if (p == NULL || t == NULL || n < 2) {
    return NQEDEC;
  }
  id = p[i++];
  t->cls = (uint8_t)(id >> 6);
  t->con = (uint8_t)((id >> 5) & 1u);
  tag = (uint32_t)(id & 0x1fu);
  if (tag == 0x1fu) {
    unsigned k = 0;
    tag = 0;
    do {
      if (i >= n) {
        return NQEDEC;
      }
      b = p[i++];
      if (k == 0 && (b & 0x7fu) == 0) {
        return NQEDEC; /* a leading zero septet */
      }
      if (++k > 3) {
        return NQELIM;
      }
      tag = (tag << 7) | (uint32_t)(b & 0x7fu);
    } while ((b & 0x80u) != 0);
    if (tag < 0x1fu) {
      return NQEDEC; /* 0..30 take the one-octet form */
    }
    if (t->cls == NQDUNI) {
      return NQEDEC;
    }
  }
  if (t->cls == NQDUNI) {
    int k = unikind(tag);
    if (k == 0) {
      return NQEDEC;
    }
    if ((k == 2) != (t->con == 1)) {
      return NQEDEC;
    }
  }
  t->tag = tag;
  if (i >= n) {
    return NQEDEC;
  }
  b = p[i++];
  if (b < 0x80u) {
    len = b;
  } else {
    size_t nb = (size_t)(b & 0x7fu), k;
    if (nb == 0) {
      return NQEDEC; /* indefinite: BER only */
    }
    if (nb > 4) {
      return NQELIM;
    }
    /* i < n is implied by nb <= n - i with nb >= 1; stated so that
     * a reader (and CodeQL) need not derive it */
    if (i >= n || nb > n - i) {
      return NQEDEC;
    }
    if (p[i] == 0) {
      return NQEDEC; /* not the shortest form */
    }
    if (nb == 1 && p[i] < 0x80u) {
      return NQEDEC; /* the short form would do */
    }
    len = 0;
    for (k = 0; k < nb; k++) {
      len = (len << 8) | (size_t)p[i++];
    }
  }
  if (len > n - i) {
    return NQEDEC;
  }
  t->v.p = p + i;
  t->v.n = len;
  t->raw.p = p;
  t->raw.n = i + len;
  t->depth = 0;
  return NQOK;
}

void nqdinit(nqdcur *c, const uint8_t *p, size_t n) {
  c->p = p;
  c->pos = 0;
  c->end = p == NULL ? 0 : n;
  c->depth = 0;
}

int nqdend(const nqdcur *c) {
  return c->pos >= c->end;
}

int nqdpeek(const nqdcur *c, nqdtlv *t) {
  int r = NQEDEC;
  if (c->pos >= c->end) {
    return NQEDEC;
  }
  r = nqdhdr(c->p + c->pos, c->end - c->pos, t);
  if (r != NQOK) {
    return r;
  }
  t->depth = c->depth;
  return NQOK;
}

int nqdnext(nqdcur *c, nqdtlv *t) {
  int r = nqdpeek(c, t);
  if (r == NQOK) {
    c->pos += t->raw.n;
  }
  return r;
}

int nqddown(const nqdtlv *t, nqdcur *in) {
  if (!t->con) {
    return NQEDEC;
  }
  if (t->depth + 1 > NQDDEPTH) {
    return NQELIM;
  }
  in->p = t->v.p;
  in->pos = 0;
  in->end = t->v.n;
  in->depth = t->depth + 1;
  return NQOK;
}

static int same(const nqdtlv *t, unsigned cls, unsigned con, uint32_t tag) {
  return t->cls == cls && t->con == con && t->tag == tag;
}

int nqdget(nqdcur *c, unsigned cls, unsigned con, uint32_t tag,
           nqdtlv *t) {
  int r = nqdpeek(c, t);
  if (r != NQOK) {
    return r;
  }
  if (!same(t, cls, con, tag)) {
    return NQEDEC;
  }
  c->pos += t->raw.n;
  return NQOK;
}

int nqdopt(nqdcur *c, unsigned cls, unsigned con, uint32_t tag,
           nqdtlv *t, int *got) {
  int r = NQEDEC;
  *got = 0;
  if (nqdend(c)) {
    return NQOK;
  }
  r = nqdpeek(c, t);
  if (r != NQOK) {
    return r;
  }
  if (same(t, cls, con, tag)) {
    c->pos += t->raw.n;
    *got = 1;
  }
  return NQOK;
}

int nqddone(const nqdcur *c) {
  return nqdend(c) ? NQOK : NQEDEC;
}

/* ---- contents of the universal primitives ---- */

static int intok(const uint8_t *v, size_t n) {
  if (n == 0) {
    return 0;
  }
  if (n > 1 && ((v[0] == 0x00 && v[1] < 0x80u) ||
                (v[0] == 0xffu && v[1] >= 0x80u))) {
    return 0;
  }
  return 1;
}

int nqdoidok(const uint8_t *v, size_t n) {
  size_t i = 0, arcs = 1;
  if (n == 0) {
    return 0;
  }
  while (i < n) {
    uint64_t a = 0;
    unsigned k = 0;
    if (v[i] == 0x80u) {
      return 0; /* a leading zero septet */
    }
    for (;;) {
      if (i >= n) {
        return 0; /* the last octet has its top bit set */
      }
      if (++k > 5) {
        return 0;
      }
      a = (a << 7) | (uint64_t)(v[i] & 0x7fu);
      if ((v[i++] & 0x80u) == 0) {
        break;
      }
    }
    if (a > 0xffffffffu && arcs > 1) {
      return 0;
    }
    if (arcs == 1 && a > 0xffffffffu + (uint64_t)80) {
      return 0;
    }
    arcs += 1;
    if (arcs > 64) {
      return 0;
    }
  }
  return 1;
}

static int bitsok(const uint8_t *v, size_t n) {
  unsigned u;
  if (n == 0) {
    return 0;
  }
  u = v[0];
  if (u > 7 || (n == 1 && u != 0)) {
    return 0;
  }
  if (u != 0 && (v[n - 1] & ((1u << u) - 1u)) != 0) {
    return 0;
  }
  return 1;
}

static int utf8ok(const uint8_t *v, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint32_t c = v[i], min;
    size_t k, m;
    if (c < 0x80u) {
      i++;
      continue;
    }
    if ((c & 0xe0u) == 0xc0u) {
      m = 1;
      c &= 0x1fu;
      min = 0x80u;
    } else if ((c & 0xf0u) == 0xe0u) {
      m = 2;
      c &= 0x0fu;
      min = 0x800u;
    } else if ((c & 0xf8u) == 0xf0u) {
      m = 3;
      c &= 0x07u;
      min = 0x10000u;
    } else {
      return 0;
    }
    if (m > n - i - 1) {
      return 0;
    }
    for (k = 1; k <= m; k++) {
      if ((v[i + k] & 0xc0u) != 0x80u) {
        return 0;
      }
      c = (c << 6) | (uint32_t)(v[i + k] & 0x3fu);
    }
    if (c < min || c > 0x10ffffu || (c >= 0xd800u && c <= 0xdfffu)) {
      return 0;
    }
    i += m + 1;
  }
  return 1;
}

static int printok(uint8_t c) {
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9')) {
    return 1;
  }
  return strchr(" '()+,-./:=?", (int)c) != NULL && c != 0;
}

static int strok(uint32_t tag, const uint8_t *v, size_t n) {
  size_t i;
  switch (tag) {
  case NQDUTF8:
    return utf8ok(v, n);
  case NQDNUMS:
    for (i = 0; i < n; i++) {
      if (v[i] != ' ' && (v[i] < '0' || v[i] > '9')) {
        return 0;
      }
    }
    return 1;
  case NQDPRT:
    for (i = 0; i < n; i++) {
      if (!printok(v[i])) {
        return 0;
      }
    }
    return 1;
  case NQDIA5:
    for (i = 0; i < n; i++) {
      if (v[i] >= 0x80u) {
        return 0;
      }
    }
    return 1;
  case NQDVIS:
    for (i = 0; i < n; i++) {
      if (v[i] < 0x20u || v[i] > 0x7eu) {
        return 0;
      }
    }
    return 1;
  case NQDBMP:
    if (n % 2 != 0) {
      return 0;
    }
    for (i = 0; i < n; i += 2) {
      if (v[i] >= 0xd8u && v[i] <= 0xdfu) {
        return 0;
      }
    }
    return 1;
  case NQDUNIS:
    if (n % 4 != 0) {
      return 0;
    }
    for (i = 0; i < n; i += 4) {
      uint32_t c = ((uint32_t)v[i] << 24) | ((uint32_t)v[i + 1] << 16) |
                   ((uint32_t)v[i + 2] << 8) | (uint32_t)v[i + 3];
      if (c > 0x10ffffu || (c >= 0xd800u && c <= 0xdfffu)) {
        return 0;
      }
    }
    return 1;
  default:
    return 1; /* T.61, Videotex, Graphic, General: any octets */
  }
}

/* ---- times ---- */

static int dig2(const uint8_t *s, unsigned *v) {
  if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') {
    return 0;
  }
  *v = (unsigned)(s[0] - '0') * 10u + (unsigned)(s[1] - '0');
  return 1;
}

static int leap(unsigned y) {
  return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static unsigned mdays(unsigned y, unsigned m) {
  static const unsigned d[12] = {31, 28, 31, 30, 31, 30,
                                 31, 31, 30, 31, 30, 31};
  return m == 2 && leap(y) ? 29u : d[m - 1];
}

/* Days from 1970-01-01 to y-m-d (proleptic Gregorian, y >= 1). */
static int64_t days(unsigned y, unsigned m, unsigned d) {
  int64_t yy = (int64_t)y - (m <= 2 ? 1 : 0);
  int64_t era = yy / 400;
  int64_t yoe = yy - era * 400;
  int64_t mp = (int64_t)(m > 2 ? m - 3 : m + 9);
  int64_t doy = (153 * mp + 2) / 5 + (int64_t)d - 1;
  int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

/* Parses a UTCTime (gen 0) or GeneralizedTime (gen 1) contents. */
static int tparse(const uint8_t *v, size_t n, int gen, int frac,
                  int64_t *secs, uint32_t *nsec, unsigned *year) {
  unsigned y, c, mo, d, h, mi, s;
  size_t i;
  uint32_t ns = 0;
  if (gen) {
    if (n < 15 || !dig2(v, &c) || !dig2(v + 2, &y)) {
      return 0;
    }
    y += c * 100u;
    v += 4;
    n -= 4;
  } else {
    if (n != 13 || !dig2(v, &y)) {
      return 0;
    }
    y += y >= 50 ? 1900u : 2000u;
    v += 2;
    n -= 2;
  }
  /* MMDDHHMMSS then [.f] Z */
  if (!dig2(v, &mo) || !dig2(v + 2, &d) || !dig2(v + 4, &h) ||
      !dig2(v + 6, &mi) || !dig2(v + 8, &s)) {
    return 0;
  }
  if (y == 0 || mo < 1 || mo > 12 || d < 1 || d > mdays(y, mo) || h > 23 ||
      mi > 59 || s > 59) {
    return 0;
  }
  v += 10;
  n -= 10;
  if (n > 1) {
    uint32_t sc = 100000000u;
    if (!gen || !frac || v[0] != '.' || n < 3) {
      return 0;
    }
    if (n - 2 > 9) {
      return 0;
    }
    for (i = 1; i + 1 < n; i++) {
      if (v[i] < '0' || v[i] > '9') {
        return 0;
      }
      ns += (uint32_t)(v[i] - '0') * sc;
      sc /= 10u;
    }
    if (v[n - 2] == '0') {
      return 0; /* trailing zero in the fraction */
    }
    v += n - 1;
    n = 1;
  }
  if (n != 1 || v[0] != 'Z') {
    return 0;
  }
  if (secs != NULL) {
    *secs = days(y, mo, d) * 86400 + (int64_t)h * 3600 + (int64_t)mi * 60 +
            (int64_t)s;
  }
  if (nsec != NULL) {
    *nsec = ns;
  }
  if (year != NULL) {
    *year = y;
  }
  return 1;
}

int nqdprim(uint32_t tag, const uint8_t *v, size_t n) {
  int ok;
  switch (tag) {
  case NQDBOOL:
    ok = n == 1 && (v[0] == 0x00 || v[0] == 0xffu);
    break;
  case NQDINT:
  case NQDENUM:
    ok = intok(v, n);
    break;
  case NQDBITS:
    ok = bitsok(v, n);
    break;
  case NQDNULL:
    ok = n == 0;
    break;
  case NQDOID:
    ok = nqdoidok(v, n);
    break;
  case NQDUTC:
    ok = tparse(v, n, 0, 0, NULL, NULL, NULL);
    break;
  case NQDGEN:
    ok = tparse(v, n, 1, 1, NULL, NULL, NULL);
    break;
  case NQDOCT:
    ok = 1;
    break;
  default:
    ok = strok(tag, v, n);
    break;
  }
  return ok ? NQOK : NQEDEC;
}

/* X.690 11.6: SET OF elements ascend, compared as octet strings with the
 * shorter padded with zero octets. 1 when a may precede b. */
static int setle(const uint8_t *a, size_t an, const uint8_t *b, size_t bn) {
  size_t m = an < bn ? an : bn, i;
  int c = memcmp(a, b, m);
  if (c != 0) {
    return c < 0;
  }
  for (i = m; i < an; i++) {
    if (a[i] != 0) {
      return 0;
    }
  }
  return 1;
}

int nqdwalk(const uint8_t *p, size_t n) {
  size_t end[NQDDEPTH + 1];
  size_t pst[NQDDEPTH + 1], pln[NQDDEPTH + 1];
  uint8_t set[NQDDEPTH + 1];
  unsigned d = 0;
  size_t pos = 0;
  int top = 0;
  if (p == NULL) {
    return NQEDEC;
  }
  end[0] = n;
  set[0] = 0;
  pln[0] = 0;
  pst[0] = 0;
  for (;;) {
    nqdtlv t;
    int r = NQEDEC;
    size_t hl;
    while (d > 0 && pos == end[d]) {
      d--;
    }
    if (d == 0) {
      if (pos == n) {
        break;
      }
      if (top) {
        return NQEDEC; /* bytes after the element */
      }
      top = 1;
    }
    r = nqdhdr(p + pos, end[d] - pos, &t);
    if (r != NQOK) {
      return r;
    }
    if (set[d]) {
      if (pln[d] != 0 && !setle(p + pst[d], pln[d], p + pos, t.raw.n)) {
        return NQEDEC;
      }
      pst[d] = pos;
      pln[d] = t.raw.n;
    }
    hl = t.raw.n - t.v.n;
    if (t.con) {
      if (d + 1 > NQDDEPTH) {
        return NQELIM;
      }
      d++;
      end[d] = pos + t.raw.n;
      set[d] = (uint8_t)(t.cls == NQDUNI && t.tag == NQDSET);
      pln[d] = 0;
      pst[d] = 0;
      pos += hl;
    } else {
      if (t.cls == NQDUNI) {
        r = nqdprim(t.tag, t.v.p, t.v.n);
        if (r != NQOK) {
          return r;
        }
      }
      pos += t.raw.n;
    }
  }
  return top ? NQOK : NQEDEC;
}

int nqdone(const uint8_t *p, size_t n, nqdtlv *t) {
  nqdtlv x;
  int r = NQEDEC;
  if (p == NULL) {
    return NQEDEC;
  }
  r = nqdhdr(p, n, &x);
  if (r != NQOK) {
    return r;
  }
  if (x.raw.n != n) {
    return NQEDEC;
  }
  r = nqdwalk(p, n);
  if (r != NQOK) {
    return r;
  }
  if (t != NULL) {
    *t = x;
  }
  return NQOK;
}

/* ---- typed helpers ---- */

static int isuni(const nqdtlv *t, uint32_t tag) {
  return t->cls == NQDUNI && t->con == 0 && t->tag == tag;
}

int nqdbool(const nqdtlv *t, int *b) {
  if (!isuni(t, NQDBOOL) || nqdprim(NQDBOOL, t->v.p, t->v.n) != NQOK) {
    return NQEDEC;
  }
  *b = t->v.p[0] != 0;
  return NQOK;
}

int nqdint(const nqdtlv *t, nqspan *mag, int *neg) {
  if (!isuni(t, NQDINT) || !intok(t->v.p, t->v.n)) {
    return NQEDEC;
  }
  if (neg != NULL) {
    *neg = (t->v.p[0] & 0x80u) != 0;
  }
  if (mag != NULL) {
    mag->p = t->v.p;
    mag->n = t->v.n;
    if (mag->n > 1 && mag->p[0] == 0) {
      mag->p++;
      mag->n--;
    }
  }
  return NQOK;
}

static int i64of(const uint8_t *v, size_t n, int64_t *out) {
  uint64_t u;
  size_t i;
  if (!intok(v, n) || n > 8) {
    return NQELIM;
  }
  u = (v[0] & 0x80u) ? ~(uint64_t)0 : 0;
  for (i = 0; i < n; i++) {
    u = (u << 8) | (uint64_t)v[i];
  }
  if (u > (uint64_t)INT64_MAX) {
    /* negative: two's complement back to int64 without overflow */
    *out = -(int64_t)(~u) - 1;
  } else {
    *out = (int64_t)u;
  }
  return NQOK;
}

int nqdi64(const nqdtlv *t, int64_t *v) {
  if (!isuni(t, NQDINT) || !intok(t->v.p, t->v.n)) {
    return NQEDEC;
  }
  return i64of(t->v.p, t->v.n, v);
}

int nqdenum(const nqdtlv *t, int64_t *v) {
  if (!isuni(t, NQDENUM) || !intok(t->v.p, t->v.n)) {
    return NQEDEC;
  }
  return i64of(t->v.p, t->v.n, v);
}

int nqdoid(const nqdtlv *t, nqspan *oid) {
  if (!isuni(t, NQDOID) || !nqdoidok(t->v.p, t->v.n)) {
    return NQEDEC;
  }
  if (oid != NULL) {
    *oid = t->v;
  }
  return NQOK;
}

int nqdoideq(const nqdtlv *t, const uint8_t *oid, size_t n) {
  return isuni(t, NQDOID) && t->v.n == n && memcmp(t->v.p, oid, n) == 0 &&
         nqdoidok(t->v.p, t->v.n);
}

int nqdbits(const nqdtlv *t, nqspan *bits, unsigned *unused) {
  if (!isuni(t, NQDBITS) || !bitsok(t->v.p, t->v.n)) {
    return NQEDEC;
  }
  if (bits != NULL) {
    bits->p = t->v.p + 1;
    bits->n = t->v.n - 1;
  }
  if (unused != NULL) {
    *unused = t->v.p[0];
  }
  return NQOK;
}

int nqdbit0(const nqdtlv *t, nqspan *bits) {
  unsigned u;
  int r = nqdbits(t, bits, &u);
  if (r != NQOK) {
    return r;
  }
  return u == 0 ? NQOK : NQEDEC;
}

int nqdnbits(const nqdtlv *t, uint32_t *bits) {
  nqspan b;
  unsigned u, i;
  uint32_t out = 0;
  int r = nqdbits(t, &b, &u);
  if (r != NQOK) {
    return r;
  }
  if (b.n > 4) {
    return NQELIM;
  }
  if (b.n > 0 && (b.p[b.n - 1] & (1u << u)) == 0) {
    return NQEDEC; /* DER removes trailing zero bits */
  }
  for (i = 0; i < 8u * (unsigned)b.n; i++) {
    if (b.p[i / 8] & (0x80u >> (i % 8))) {
      out |= (uint32_t)1 << i;
    }
  }
  *bits = out;
  return NQOK;
}

int nqdnull(const nqdtlv *t) {
  return isuni(t, NQDNULL) && t->v.n == 0 ? NQOK : NQEDEC;
}

int nqdtime(const nqdtlv *t, unsigned flags, int64_t *secs, uint32_t *nsec) {
  unsigned y;
  int gen;
  if (isuni(t, NQDUTC)) {
    gen = 0;
  } else if (isuni(t, NQDGEN)) {
    gen = 1;
  } else {
    return NQEDEC;
  }
  if (!tparse(t->v.p, t->v.n, gen, (flags & NQDTFRAC) != 0 &&
              (flags & NQDT5280) == 0, secs, nsec, &y)) {
    return NQEDEC;
  }
  if ((flags & NQDT5280) != 0) {
    if (gen ? y < 2050 : y >= 2050) {
      return NQEDEC;
    }
  }
  return NQOK;
}

int nqdseq(nqspan a, nqspan b) {
  return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}
