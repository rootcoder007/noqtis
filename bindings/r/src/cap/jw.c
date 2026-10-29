/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The canonical JSON writer (RFC 8785, JCS): no whitespace, object keys
 * sorted by UTF-16 code units, strings with the minimal escapes, numbers
 * in the ECMAScript Number form (the shortest text that reads back as the
 * same double). No recursion: nested values use an explicit stack. */
#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"

/* ---- buffer ---- */

void nqcput(nqcbuf *b, const char *s, size_t n) {
  if (b->err != NQOK || n == 0) return;
  if (b->cap - b->n < n) {
    size_t nc = b->cap < 256 ? 256 : b->cap;
    char *np;
    while (nc - b->n < n) {
      if (nc > (size_t)-1 / 2) {
        b->err = NQELIM;
        return;
      }
      nc *= 2;
    }
    np = (char *)nqmal(nc);
    if (np == NULL) {
      b->err = NQEMEM;
      return;
    }
    if (b->n != 0) memcpy(np, b->p, b->n);
    nqfree(b->p, b->cap);
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
}

void nqcputs(nqcbuf *b, const char *s) { nqcput(b, s, strlen(s)); }

void nqcbfree(nqcbuf *b) {
  nqfree(b->p, b->cap);
  b->p = NULL;
  b->n = 0;
  b->cap = 0;
}

/* ---- strings ---- */

void nqcjstr(nqcbuf *b, const char *s, size_t n) {
  static const char hx[] = "0123456789abcdef";
  size_t i, run = 0;
  nqcput(b, "\"", 1);
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    const char *e = NULL;
    char u[6];
    if (c == '"') {
      e = "\\\"";
    } else if (c == '\\') {
      e = "\\\\";
    } else if (c == '\b') {
      e = "\\b";
    } else if (c == '\f') {
      e = "\\f";
    } else if (c == '\n') {
      e = "\\n";
    } else if (c == '\r') {
      e = "\\r";
    } else if (c == '\t') {
      e = "\\t";
    } else if (c < 0x20) {
      u[0] = '\\';
      u[1] = 'u';
      u[2] = '0';
      u[3] = '0';
      u[4] = hx[c >> 4];
      u[5] = hx[c & 15];
    } else {
      continue;
    }
    nqcput(b, s + run, i - run);
    if (e != NULL) {
      nqcputs(b, e);
    } else {
      nqcput(b, u, 6);
    }
    run = i + 1;
  }
  nqcput(b, s + run, n - run);
  nqcput(b, "\"", 1);
}

/* ---- numbers ---- */

void nqcjint(nqcbuf *b, uint64_t v) {
  char t[24];
  size_t i = sizeof t;
  do {
    t[--i] = (char)('0' + (int)(v % 10));
    v /= 10;
  } while (v != 0);
  nqcput(b, t + i, sizeof t - i);
}

static void zeros(nqcbuf *b, long k) {
  while (k-- > 0) nqcput(b, "0", 1);
}

int nqcjnum(nqcbuf *b, const char *txt, size_t n) {
  char in[NQCNUMMAX + 64];
  char tmp[48];
  char dig[24];
  const char *dp;
  size_t dpl, i, o = 0, k = 0;
  double x, y;
  char *end;
  long e, nn;
  int p;
  if (n == 0) return NQEDEC;
  if (n > NQCNUMMAX) return NQELIM;
  /* strtod and snprintf follow the locale's decimal point */
  dp = localeconv()->decimal_point;
  dpl = dp == NULL ? 0 : strlen(dp);
  if (dpl == 0 || dpl > 8) {
    dp = ".";
    dpl = 1;
  }
  for (i = 0; i < n; i++) {
    char c = txt[i];
    if (c == '.') {
      memcpy(in + o, dp, dpl);
      o += dpl;
    } else if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == 'e' ||
               c == 'E') {
      in[o++] = c;
    } else {
      return NQEDEC;
    }
  }
  in[o] = 0;
  errno = 0;
  x = strtod(in, &end);
  if (end != in + o || !isfinite(x)) return NQEDEC;
  if (x == 0.0) {
    nqcput(b, "0", 1);
    return b->err;
  }
  if (x < 0) {
    nqcput(b, "-", 1);
    x = -x;
  }
  for (p = 1; p <= 17; p++) {
    snprintf(tmp, sizeof tmp, "%.*e", p - 1, x);
    y = strtod(tmp, NULL);
    if (y == x) break;
  }
  for (i = 0; tmp[i] != 0 && tmp[i] != 'e'; i++) {
    if (tmp[i] >= '0' && tmp[i] <= '9' && k < sizeof dig) dig[k++] = tmp[i];
  }
  if (tmp[i] != 'e' || k == 0) return NQEDEC;
  e = strtol(tmp + i + 1, NULL, 10);
  while (k > 1 && dig[k - 1] == '0') k--;
  nn = e + 1;
  if ((long)k <= nn && nn <= 21) {
    nqcput(b, dig, k);
    zeros(b, nn - (long)k);
  } else if (0 < nn && nn <= 21) {
    nqcput(b, dig, (size_t)nn);
    nqcput(b, ".", 1);
    nqcput(b, dig + nn, k - (size_t)nn);
  } else if (-6 < nn && nn <= 0) {
    nqcput(b, "0.", 2);
    zeros(b, -nn);
    nqcput(b, dig, k);
  } else {
    nqcput(b, dig, 1);
    if (k > 1) {
      nqcput(b, ".", 1);
      nqcput(b, dig + 1, k - 1);
    }
    nqcput(b, nn - 1 >= 0 ? "e+" : "e-", 2);
    nqcjint(b, (uint64_t)(nn - 1 >= 0 ? nn - 1 : 1 - nn));
  }
  return b->err;
}

/* ---- key order: UTF-16 code units ---- */

static uint32_t nextcp(const unsigned char *p, size_t n, size_t *i) {
  uint32_t c = p[*i];
  size_t k = 0, j;
  if (c >= 0xf0) {
    k = 3;
    c &= 7;
  } else if (c >= 0xe0) {
    k = 2;
    c &= 15;
  } else if (c >= 0xc0) {
    k = 1;
    c &= 31;
  }
  if (n - *i <= k) k = 0; /* invalid tail: compare as bytes */
  for (j = 1; j <= k; j++) c = (c << 6) | (p[*i + j] & 0x3fu);
  *i += k + 1;
  return c;
}

static void u16(uint32_t c, uint32_t *hi, uint32_t *lo) {
  if (c < 0x10000) {
    *hi = c;
    *lo = 0;
  } else {
    c -= 0x10000;
    *hi = 0xd800 + (c >> 10);
    *lo = 0xdc00 + (c & 0x3ff);
  }
}

int nqcjcmp(const char *a, size_t an, const char *b, size_t bn) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  size_t i = 0, j = 0;
  while (i < an && j < bn) {
    uint32_t ca = nextcp(pa, an, &i), cb = nextcp(pb, bn, &j);
    uint32_t ha, la, hb, lb;
    if (ca == cb) continue;
    u16(ca, &ha, &la);
    u16(cb, &hb, &lb);
    if (ha != hb) return ha < hb ? -1 : 1;
    return la < lb ? -1 : 1;
  }
  if (i < an) return 1;
  if (j < bn) return -1;
  return 0;
}

/* ---- whole values ---- */

typedef struct {
  const nqjs *v;
  size_t i;
  size_t *ord; /* OBJ: kids in key order */
} frame;

static int keycmp(const void *ctx, size_t a, size_t b) {
  const nqjs *o = (const nqjs *)ctx;
  return nqcjcmp(o->keys[a], o->klen[a], o->keys[b], o->klen[b]);
}

static int push(frame *st, size_t *d, const nqjs *v) {
  size_t i;
  if (*d >= NQJDEPTH + 1) return NQELIM;
  st[*d].v = v;
  st[*d].i = 0;
  st[*d].ord = NULL;
  if (v->type == NQJOBJ && v->n > 0) {
    int rc;
    if (v->n > (size_t)-1 / sizeof(size_t)) return NQELIM;
    st[*d].ord = (size_t *)nqmal(v->n * sizeof(size_t));
    if (st[*d].ord == NULL) return NQEMEM;
    for (i = 0; i < v->n; i++) st[*d].ord[i] = i;
    (*d)++;
    rc = nqcsort(st[*d - 1].ord, v->n, keycmp, v);
    if (rc != NQOK) return rc;
    for (i = 1; i < v->n; i++) {
      if (keycmp(v, st[*d - 1].ord[i - 1], st[*d - 1].ord[i]) == 0) {
        return NQEDEC; /* duplicate key */
      }
    }
    return NQOK;
  }
  (*d)++;
  return NQOK;
}

int nqcjval(nqcbuf *b, const nqjs *v) {
  frame st[NQJDEPTH + 1];
  size_t d = 0;
  const nqjs *cur = v;
  int rc = NQOK;
  if (v == NULL) return NQEARG;
  for (;;) {
    if (cur != NULL) {
      switch (cur->type) {
      case NQJNULL:
        nqcputs(b, "null");
        break;
      case NQJTRUE:
        nqcputs(b, "true");
        break;
      case NQJFALSE:
        nqcputs(b, "false");
        break;
      case NQJNUM:
        rc = nqcjnum(b, cur->str, cur->len);
        break;
      case NQJSTR:
        nqcjstr(b, cur->str, cur->len);
        break;
      case NQJARR:
        nqcput(b, "[", 1);
        rc = push(st, &d, cur);
        break;
      case NQJOBJ:
        nqcput(b, "{", 1);
        rc = push(st, &d, cur);
        break;
      default:
        rc = NQEDEC;
        break;
      }
      cur = NULL;
      if (rc != NQOK) break;
    }
    if (d == 0) break;
    {
      frame *f = &st[d - 1];
      if (f->i == f->v->n) {
        nqcput(b, f->v->type == NQJOBJ ? "}" : "]", 1);
        if (f->ord != NULL) nqfree(f->ord, f->v->n * sizeof(size_t));
        d--;
        continue;
      }
      if (f->i > 0) nqcput(b, ",", 1);
      if (f->v->type == NQJOBJ) {
        size_t k = f->ord[f->i];
        nqcjstr(b, f->v->keys[k], f->v->klen[k]);
        nqcput(b, ":", 1);
        cur = f->v->kids[k];
      } else {
        cur = f->v->kids[f->i];
      }
      f->i++;
    }
  }
  while (d > 0) {
    d--;
    if (st[d].ord != NULL) nqfree(st[d].ord, st[d].v->n * sizeof(size_t));
  }
  if (rc != NQOK) return rc;
  return b->err;
}
