/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* JSON for nqd: a strict reader without recursion (an explicit stack of
 * at most DJDEPTH containers) and the canonical writer of RFC 8785, so a
 * record written by any binding is the same bytes. Numbers are IEEE
 * doubles, formatted as ECMAScript does (shortest round trip), read and
 * written the same whatever the C locale. */
#include "int.h"

#include <float.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- memory and buffers ---- */

void *qdmal(size_t n) {
  return malloc(n == 0 ? 1 : n);
}

void qdfree(void *p) {
  free(p);
}

char *qddup(const char *s, size_t n) {
  char *d;
  if (n == (size_t)-1)
    return NULL;
  d = (char *)qdmal(n + 1);
  if (d != NULL) {
    if (n)
      memcpy(d, s, n);
    d[n] = '\0';
  }
  return d;
}

void qdbput(dbuf *b, const char *s, size_t n) {
  if (b->err || n == 0)
    return;
  if (n > (size_t)-1 / 2 - b->n || (b->max && b->n + n > b->max)) {
    b->err = NQELIM;
    return;
  }
  if (b->n + n + 1 > b->cap) {
    size_t nc = b->cap ? b->cap : 256;
    char *nb;
    while (nc < b->n + n + 1)
      nc *= 2;
    nb = (char *)qdmal(nc);
    if (nb == NULL) {
      b->err = NQEMEM;
      return;
    }
    if (b->n)
      memcpy(nb, b->b, b->n);
    qdfree(b->b);
    b->b = nb;
    b->cap = nc;
  }
  memcpy(b->b + b->n, s, n);
  b->n += n;
  b->b[b->n] = '\0';
}

void qdbstr(dbuf *b, const char *s) {
  qdbput(b, s, strlen(s));
}

void qdbch(dbuf *b, char c) {
  qdbput(b, &c, 1);
}

void qdbfree(dbuf *b) {
  qdfree(b->b);
  b->b = NULL;
  b->n = b->cap = 0;
}

int qdbout(const dbuf *b, char *out, size_t cap, size_t *outlen) {
  if (b->err)
    return b->err;
  if (outlen != NULL)
    *outlen = b->n;
  if (out == NULL || cap < b->n + 1)
    return NQEBUF;
  if (b->n)
    memcpy(out, b->b, b->n);
  out[b->n] = '\0';
  return NQOK;
}

void qdwhy(char *why, size_t cap, const char *fmt, ...) {
  va_list ap;
  if (why == NULL || cap == 0)
    return;
  va_start(ap, fmt);
  vsnprintf(why, cap, fmt, ap);
  va_end(ap);
}

/* ---- UTF-8 ---- */

/* Decodes one code point at s (n bytes left); its length, or 0 when the
 * bytes there are not valid UTF-8 (overlong, surrogate, over U+10FFFF,
 * cut short). */
static size_t u8dec(const unsigned char *s, size_t n, uint32_t *cp) {
  uint32_t c;
  size_t l, i;
  if (n == 0)
    return 0;
  c = s[0];
  if (c < 0x80) {
    *cp = c;
    return 1;
  } else if (c >= 0xc2 && c <= 0xdf) {
    l = 2;
    c &= 0x1f;
  } else if (c >= 0xe0 && c <= 0xef) {
    l = 3;
    c &= 0x0f;
  } else if (c >= 0xf0 && c <= 0xf4) {
    l = 4;
    c &= 0x07;
  } else {
    return 0;
  }
  if (n < l)
    return 0;
  for (i = 1; i < l; i++) {
    if ((s[i] & 0xc0) != 0x80)
      return 0;
    c = (c << 6) | (s[i] & 0x3f);
  }
  if ((l == 3 && c < 0x800) || (l == 4 && c < 0x10000) || c > 0x10ffff ||
      (c >= 0xd800 && c <= 0xdfff))
    return 0;
  *cp = c;
  return l;
}

int qdutf8(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s;
  size_t i = 0;
  while (i < n) {
    uint32_t cp;
    size_t l = u8dec(p + i, n - i, &cp);
    if (l == 0 || cp == 0)
      return 0;
    i += l;
  }
  return 1;
}

/* the next UTF-16 code unit of s, keeping a pending low surrogate */
static int u16next(const unsigned char *s, size_t n, size_t *i,
                   uint32_t *pend, uint32_t *u) {
  uint32_t cp;
  size_t l;
  if (*pend) {
    *u = *pend;
    *pend = 0;
    return 1;
  }
  if (*i >= n)
    return 0;
  l = u8dec(s + *i, n - *i, &cp);
  if (l == 0) {
    /* not reached for validated text; order by the byte */
    cp = s[*i];
    l = 1;
  }
  *i += l;
  if (cp >= 0x10000) {
    cp -= 0x10000;
    *u = 0xd800 + (cp >> 10);
    *pend = 0xdc00 + (cp & 0x3ff);
  } else {
    *u = cp;
  }
  return 1;
}

int qdkcmp(const char *a, size_t al, const char *b, size_t bl) {
  const unsigned char *x = (const unsigned char *)a;
  const unsigned char *y = (const unsigned char *)b;
  size_t i = 0, j = 0;
  uint32_t pa = 0, pb = 0;
  for (;;) {
    uint32_t ua, ub;
    int ha = u16next(x, al, &i, &pa, &ua);
    int hb = u16next(y, bl, &j, &pb, &ub);
    if (!ha || !hb)
      return ha - hb;
    if (ua != ub)
      return ua < ub ? -1 : 1;
  }
}

/* ---- numbers ---- */

/* the C locale's decimal point (one or more bytes) */
static const char *dpoint(void) {
  const struct lconv *l = localeconv();
  return l != NULL && l->decimal_point != NULL && l->decimal_point[0] != 0
             ? l->decimal_point
             : ".";
}

int qdnumrd(const char *s, size_t n, int json, double *d) {
  char buf[96];
  const char *dp = dpoint();
  size_t i = 0, o = 0, dl = strlen(dp), dig = 0;
  char *end;
  double v;
  if (n == 0 || n > 64)
    return NQEDEC;
  if (s[i] == '-' || (!json && s[i] == '+'))
    buf[o++] = s[i++];
  if (i < n && s[i] == '0') {
    buf[o++] = s[i++];
    dig = 1;
    if (!json)
      while (i < n && s[i] >= '0' && s[i] <= '9')
        buf[o++] = s[i++];
  } else {
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      buf[o++] = s[i++];
      dig++;
    }
  }
  if (dig == 0 && (json || i >= n || s[i] != '.'))
    return NQEDEC;
  if (i < n && s[i] == '.') {
    size_t f = 0;
    i++;
    memcpy(buf + o, dp, dl);
    o += dl;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      buf[o++] = s[i++];
      f++;
    }
    if (f == 0 && (json || dig == 0))
      return NQEDEC;
  }
  if (i < n && (s[i] == 'e' || s[i] == 'E')) {
    size_t e = 0;
    buf[o++] = s[i++];
    if (i < n && (s[i] == '+' || s[i] == '-'))
      buf[o++] = s[i++];
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      buf[o++] = s[i++];
      e++;
    }
    if (e == 0)
      return NQEDEC;
  }
  if (i != n)
    return NQEDEC;
  buf[o] = '\0';
  v = strtod(buf, &end);
  if (*end != '\0' || !isfinite(v))
    return NQEDEC;
  *d = v == 0 ? 0.0 : v; /* no negative zero */
  return NQOK;
}

int qdnumfmt(double d, char *out) {
  char t[48], dg[24];
  const char *dp = dpoint();
  size_t dl = strlen(dp), k = 0, i;
  int p, e, nexp;
  char *o = out, *ep;
  if (!isfinite(d))
    return NQEARG;
  if (d == 0) {
    strcpy(out, "0");
    return NQOK;
  }
  for (p = 1; p <= 17; p++) {
    double r;
    char c[48];
    size_t ci = 0, ti;
    snprintf(t, sizeof t, "%.*e", p - 1, d);
    /* back to '.' for the comparison read: qdnumrd wants '.' */
    for (ti = 0; t[ti] != 0 && ci < sizeof c - 1;) {
      if (strncmp(t + ti, dp, dl) == 0) {
        c[ci++] = '.';
        ti += dl;
      } else {
        c[ci++] = t[ti++];
      }
    }
    c[ci] = '\0';
    strcpy(t, c);
    if (qdnumrd(t, strlen(t), 0, &r) == NQOK && r == d)
      break;
  }
  /* t: [-]d[.ddd]e(+|-)xx */
  i = 0;
  if (t[0] == '-') {
    *o++ = '-';
    i = 1;
  }
  for (; t[i] != 'e' && t[i] != 0; i++)
    if (t[i] != '.')
      dg[k++] = t[i];
  ep = t + i + 1;
  e = atoi(ep);
  while (k > 1 && dg[k - 1] == '0')
    k--;
  nexp = e + 1;
  if ((int)k <= nexp && nexp <= 21) {
    memcpy(o, dg, k);
    o += k;
    for (p = 0; p < nexp - (int)k; p++)
      *o++ = '0';
  } else if (0 < nexp && nexp <= 21) {
    memcpy(o, dg, (size_t)nexp);
    o += nexp;
    *o++ = '.';
    memcpy(o, dg + nexp, k - (size_t)nexp);
    o += k - (size_t)nexp;
  } else if (-6 < nexp && nexp <= 0) {
    *o++ = '0';
    *o++ = '.';
    for (p = 0; p < -nexp; p++)
      *o++ = '0';
    memcpy(o, dg, k);
    o += k;
  } else {
    *o++ = dg[0];
    if (k > 1) {
      *o++ = '.';
      memcpy(o, dg + 1, k - 1);
      o += k - 1;
    }
    o += sprintf(o, "e%c%d", nexp - 1 < 0 ? '-' : '+',
                 nexp - 1 < 0 ? 1 - nexp : nexp - 1);
  }
  *o = '\0';
  return NQOK;
}

/* ---- nodes ---- */

djs *qdjnew(int t) {
  djs *v = (djs *)qdmal(sizeof *v);
  if (v != NULL) {
    memset(v, 0, sizeof *v);
    v->t = t;
  }
  return v;
}

djs *qdjstrn(const char *s, size_t n) {
  djs *v = qdjnew(DJSTR);
  if (v != NULL && (v->s = qddup(s, n)) == NULL) {
    qdfree(v);
    return NULL;
  }
  if (v != NULL)
    v->sl = n;
  return v;
}

djs *qdjstr(const char *s) {
  return qdjstrn(s, strlen(s));
}

djs *qdjnum(double d) {
  djs *v;
  if (!isfinite(d))
    return NULL;
  v = qdjnew(DJNUM);
  if (v != NULL)
    v->d = d == 0 ? 0.0 : d;
  return v;
}

void qdjfree(djs *v) {
  size_t i;
  if (v == NULL)
    return;
  /* depth is bounded by DJDEPTH, so is this recursion */
  for (i = 0; i < v->n; i++) {
    qdjfree(v->k[i]);
    if (v->key != NULL)
      qdfree(v->key[i]);
  }
  qdfree(v->k);
  qdfree(v->key);
  qdfree(v->kl);
  qdfree(v->s);
  qdfree(v);
}

static int grow(djs *c) {
  size_t nc = c->cap ? c->cap * 2 : 8, i;
  djs **k;
  char **ks = NULL;
  size_t *kl = NULL;
  if (c->n >= DJKIDS)
    return NQELIM;
  k = (djs **)qdmal(nc * sizeof *k);
  if (k == NULL)
    return NQEMEM;
  if (c->t == DJOBJ) {
    ks = (char **)qdmal(nc * sizeof *ks);
    kl = (size_t *)qdmal(nc * sizeof *kl);
    if (ks == NULL || kl == NULL) {
      qdfree(k);
      qdfree(ks);
      qdfree(kl);
      return NQEMEM;
    }
  }
  for (i = 0; i < c->n; i++) {
    k[i] = c->k[i];
    if (ks != NULL) {
      ks[i] = c->key[i];
      kl[i] = c->kl[i];
    }
  }
  qdfree(c->k);
  qdfree(c->key);
  qdfree(c->kl);
  c->k = k;
  c->key = ks;
  c->kl = kl;
  c->cap = nc;
  return NQOK;
}

int qdjadd(djs *a, djs *kid) {
  int rc;
  if (a == NULL || kid == NULL || a->t != DJARR) {
    qdjfree(kid);
    return kid == NULL ? NQEMEM : NQEARG;
  }
  if (a->n == a->cap && (rc = grow(a)) != NQOK) {
    qdjfree(kid);
    return rc;
  }
  a->k[a->n++] = kid;
  return NQOK;
}

static size_t keyat(const djs *o, const char *key, size_t kl) {
  size_t i;
  for (i = 0; i < o->n; i++)
    if (o->kl[i] == kl && memcmp(o->key[i], key, kl) == 0)
      return i;
  return (size_t)-1;
}

int qdjset(djs *o, const char *key, djs *kid) {
  size_t kl, i;
  int rc;
  if (o == NULL || kid == NULL || o->t != DJOBJ) {
    qdjfree(kid);
    return kid == NULL ? NQEMEM : NQEARG;
  }
  kl = strlen(key);
  i = keyat(o, key, kl);
  if (i != (size_t)-1) {
    qdjfree(o->k[i]);
    o->k[i] = kid;
    return NQOK;
  }
  if (o->n == o->cap && (rc = grow(o)) != NQOK) {
    qdjfree(kid);
    return rc;
  }
  if ((o->key[o->n] = qddup(key, kl)) == NULL) {
    qdjfree(kid);
    return NQEMEM;
  }
  o->kl[o->n] = kl;
  o->k[o->n++] = kid;
  return NQOK;
}

const djs *qdjget(const djs *o, const char *key) {
  size_t i;
  if (o == NULL || o->t != DJOBJ)
    return NULL;
  i = keyat(o, key, strlen(key));
  return i == (size_t)-1 ? NULL : o->k[i];
}

djs *qdjgetw(djs *o, const char *key) {
  return (djs *)(uintptr_t)qdjget(o, key);
}

int qdjdel(djs *o, const char *key) {
  size_t i, j;
  if (o == NULL || o->t != DJOBJ)
    return 0;
  i = keyat(o, key, strlen(key));
  if (i == (size_t)-1)
    return 0;
  qdjfree(o->k[i]);
  qdfree(o->key[i]);
  for (j = i + 1; j < o->n; j++) {
    o->k[j - 1] = o->k[j];
    o->key[j - 1] = o->key[j];
    o->kl[j - 1] = o->kl[j];
  }
  o->n--;
  return 1;
}

void qdjrm(djs *a, size_t i) {
  size_t j;
  if (a == NULL || a->t != DJARR || i >= a->n)
    return;
  qdjfree(a->k[i]);
  for (j = i + 1; j < a->n; j++)
    a->k[j - 1] = a->k[j];
  a->n--;
}

/* deep copy without recursion beyond DJDEPTH (trees nqd builds or parsed
 * are at most that deep) */
djs *qdjcopy(const djs *v) {
  djs *c;
  size_t i;
  if (v == NULL)
    return NULL;
  c = qdjnew(v->t);
  if (c == NULL)
    return NULL;
  c->d = v->d;
  if (v->s != NULL && (c->sl = v->sl, c->s = qddup(v->s, v->sl)) == NULL) {
    qdfree(c);
    return NULL;
  }
  for (i = 0; i < v->n; i++) {
    djs *k = qdjcopy(v->k[i]);
    int rc;
    if (k == NULL) {
      qdjfree(c);
      return NULL;
    }
    if (v->t == DJOBJ) {
      char *key = qddup(v->key[i], v->kl[i]);
      if (key == NULL) {
        qdjfree(k);
        qdjfree(c);
        return NULL;
      }
      rc = qdjset(c, key, k);
      qdfree(key);
    } else {
      rc = qdjadd(c, k);
    }
    if (rc != NQOK) {
      qdjfree(c);
      return NULL;
    }
  }
  return c;
}

int qdjint(const djs *v, int64_t *out) {
  if (v == NULL || v->t != DJNUM || v->d != floor(v->d) ||
      fabs(v->d) > 9007199254740992.0)
    return 0;
  *out = (int64_t)v->d;
  return 1;
}

/* ---- the reader ---- */

typedef struct {
  const char *b;
  size_t n;
  size_t i;
  char *why;
  size_t wcap;
} rd;

static int rderr(rd *r, int rc, const char *what) {
  qdwhy(r->why, r->wcap, "byte %lu: %s", (unsigned long)r->i, what);
  return rc;
}

static void ws(rd *r) {
  while (r->i < r->n && (r->b[r->i] == ' ' || r->b[r->i] == '\t' ||
                         r->b[r->i] == '\n' || r->b[r->i] == '\r'))
    r->i++;
}

static int hex4(const char *s, uint32_t *v) {
  int i;
  *v = 0;
  for (i = 0; i < 4; i++) {
    char c = s[i];
    *v <<= 4;
    if (c >= '0' && c <= '9')
      *v |= (uint32_t)(c - '0');
    else if (c >= 'a' && c <= 'f')
      *v |= (uint32_t)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
      *v |= (uint32_t)(c - 'A' + 10);
    else
      return 0;
  }
  return 1;
}

static size_t u8enc(uint32_t cp, char *o) {
  if (cp < 0x80) {
    o[0] = (char)cp;
    return 1;
  } else if (cp < 0x800) {
    o[0] = (char)(0xc0 | (cp >> 6));
    o[1] = (char)(0x80 | (cp & 0x3f));
    return 2;
  } else if (cp < 0x10000) {
    o[0] = (char)(0xe0 | (cp >> 12));
    o[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
    o[2] = (char)(0x80 | (cp & 0x3f));
    return 3;
  }
  o[0] = (char)(0xf0 | (cp >> 18));
  o[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
  o[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
  o[3] = (char)(0x80 | (cp & 0x3f));
  return 4;
}

/* a string at r->i (the opening quote), decoded into a new buffer */
static int rdstr(rd *r, char **out, size_t *outl) {
  size_t s = ++r->i, n = 0, o = 0;
  char *b;
  /* the decoded text is never longer than the escaped one */
  while (r->i < r->n && r->b[r->i] != '"') {
    if (r->b[r->i] == '\\')
      r->i++;
    r->i++;
  }
  if (r->i >= r->n)
    return rderr(r, NQEDEC, "a string is not closed");
  n = r->i - s;
  b = (char *)qdmal(n + 1);
  if (b == NULL)
    return NQEMEM;
  r->i = s;
  while (r->b[r->i] != '"') {
    unsigned char c = (unsigned char)r->b[r->i];
    if (c < 0x20) {
      qdfree(b);
      return rderr(r, NQEDEC, "a control character in a string");
    }
    if (c == '\\') {
      char e = r->b[r->i + 1];
      uint32_t cp;
      r->i += 2;
      switch (e) {
      case '"': b[o++] = '"'; break;
      case '\\': b[o++] = '\\'; break;
      case '/': b[o++] = '/'; break;
      case 'b': b[o++] = '\b'; break;
      case 'f': b[o++] = '\f'; break;
      case 'n': b[o++] = '\n'; break;
      case 'r': b[o++] = '\r'; break;
      case 't': b[o++] = '\t'; break;
      case 'u':
        if (r->n - r->i < 4 || !hex4(r->b + r->i, &cp)) {
          qdfree(b);
          return rderr(r, NQEDEC, "a bad \\u escape");
        }
        r->i += 4;
        if (cp >= 0xd800 && cp <= 0xdbff) {
          uint32_t lo;
          if (r->n - r->i < 6 || r->b[r->i] != '\\' ||
              r->b[r->i + 1] != 'u' || !hex4(r->b + r->i + 2, &lo) ||
              lo < 0xdc00 || lo > 0xdfff) {
            qdfree(b);
            return rderr(r, NQEDEC, "a lone surrogate in a \\u escape");
          }
          r->i += 6;
          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
          qdfree(b);
          return rderr(r, NQEDEC, "a lone surrogate in a \\u escape");
        } else if (cp == 0) {
          qdfree(b);
          return rderr(r, NQEDEC, "\\u0000 in a string");
        }
        o += u8enc(cp, b + o);
        break;
      default:
        qdfree(b);
        return rderr(r, NQEDEC, "an unknown escape in a string");
      }
    } else {
      uint32_t cp;
      size_t l = u8dec((const unsigned char *)r->b + r->i, r->n - r->i, &cp);
      if (l == 0) {
        qdfree(b);
        return rderr(r, NQEDEC, "invalid UTF-8 in a string");
      }
      memcpy(b + o, r->b + r->i, l);
      o += l;
      r->i += l;
    }
  }
  r->i++;
  b[o] = '\0';
  *out = b;
  *outl = o;
  return NQOK;
}

static int rdscalar(rd *r, djs **out) {
  const char *p = r->b + r->i;
  size_t left = r->n - r->i, s;
  djs *v;
  int rc;
  if (*p == '"') {
    char *str;
    size_t l;
    if ((rc = rdstr(r, &str, &l)) != NQOK)
      return rc;
    if ((v = qdjnew(DJSTR)) == NULL) {
      qdfree(str);
      return NQEMEM;
    }
    v->s = str;
    v->sl = l;
    *out = v;
    return NQOK;
  }
  if (left >= 4 && memcmp(p, "null", 4) == 0) {
    r->i += 4;
    return (*out = qdjnew(DJNULL)) != NULL ? NQOK : NQEMEM;
  }
  if (left >= 4 && memcmp(p, "true", 4) == 0) {
    r->i += 4;
    return (*out = qdjnew(DJTRUE)) != NULL ? NQOK : NQEMEM;
  }
  if (left >= 5 && memcmp(p, "false", 5) == 0) {
    r->i += 5;
    return (*out = qdjnew(DJFALSE)) != NULL ? NQOK : NQEMEM;
  }
  s = r->i;
  while (r->i < r->n && (r->b[r->i] == '-' || r->b[r->i] == '+' ||
                         r->b[r->i] == '.' || r->b[r->i] == 'e' ||
                         r->b[r->i] == 'E' ||
                         (r->b[r->i] >= '0' && r->b[r->i] <= '9')))
    r->i++;
  if (r->i == s)
    return rderr(r, NQEDEC, "not a JSON value");
  {
    double d;
    if (qdnumrd(r->b + s, r->i - s, 1, &d) != NQOK) {
      r->i = s;
      return rderr(r, NQEDEC, "a bad or out-of-range number");
    }
    if ((v = qdjnum(d)) == NULL)
      return NQEMEM;
  }
  *out = v;
  return NQOK;
}

int qdjparse(const char *buf, size_t len, djs **out, char *why, size_t cap) {
  rd r;
  djs *st[DJDEPTH];
  char *pk[DJDEPTH]; /* the key waiting for its value, per object */
  size_t pkl[DJDEPTH];
  int top = -1, rc = NQOK;
  djs *root = NULL;
  r.b = buf;
  r.n = len;
  r.i = 0;
  r.why = why;
  r.wcap = cap;
  *out = NULL;
  if (why != NULL && cap)
    why[0] = '\0';
  ws(&r);
  for (;;) {
    djs *v = NULL;
    ws(&r);
    if (r.i >= r.n) {
      rc = rderr(&r, NQEDEC, "the text ends early");
      goto fail;
    }
    /* a value */
    if (buf[r.i] == '{' || buf[r.i] == '[') {
      int t = buf[r.i] == '{' ? DJOBJ : DJARR;
      if (top + 1 >= DJDEPTH) {
        rc = rderr(&r, NQELIM, "nested deeper than 32 levels");
        goto fail;
      }
      if ((v = qdjnew(t)) == NULL) {
        rc = NQEMEM;
        goto fail;
      }
      r.i++;
    } else {
      if ((rc = rdscalar(&r, &v)) != NQOK)
        goto fail;
    }
    /* attach it */
    if (top < 0) {
      root = v;
    } else if (st[top]->t == DJARR) {
      if ((rc = qdjadd(st[top], v)) != NQOK)
        goto fail;
    } else {
      if (st[top]->n == st[top]->cap && (rc = grow(st[top])) != NQOK) {
        qdjfree(v);
        goto fail;
      }
      st[top]->key[st[top]->n] = pk[top];
      st[top]->kl[st[top]->n] = pkl[top];
      st[top]->k[st[top]->n++] = v;
      pk[top] = NULL;
    }
    if (v->t == DJOBJ || v->t == DJARR) {
      st[++top] = v;
      pk[top] = NULL;
      ws(&r);
      if (r.i < r.n && buf[r.i] == (v->t == DJOBJ ? '}' : ']')) {
        r.i++;
        top--;
        goto closed;
      }
      if (v->t == DJOBJ)
        goto key;
      continue;
    }
  closed:
    /* after a value: a comma or the end of containers */
    for (;;) {
      if (top < 0) {
        ws(&r);
        if (r.i != r.n) {
          rc = rderr(&r, NQEDEC, "text after the JSON value");
          goto fail;
        }
        *out = root;
        return NQOK;
      }
      ws(&r);
      if (r.i >= r.n) {
        rc = rderr(&r, NQEDEC, "the text ends early");
        goto fail;
      }
      if (buf[r.i] == ',') {
        r.i++;
        break;
      }
      if (buf[r.i] == (st[top]->t == DJOBJ ? '}' : ']')) {
        r.i++;
        top--;
        continue;
      }
      rc = rderr(&r, NQEDEC, "expected a comma or the end of a container");
      goto fail;
    }
    if (st[top]->t == DJARR)
      continue;
  key:
    ws(&r);
    if (r.i >= r.n || buf[r.i] != '"') {
      rc = rderr(&r, NQEDEC, "expected a key in quotes");
      goto fail;
    }
    {
      char *k;
      size_t kl, j;
      if ((rc = rdstr(&r, &k, &kl)) != NQOK)
        goto fail;
      for (j = 0; j < st[top]->n; j++) {
        if (st[top]->kl[j] == kl && memcmp(st[top]->key[j], k, kl) == 0) {
          qdfree(k);
          rc = rderr(&r, NQEDEC, "a duplicate key");
          goto fail;
        }
      }
      pk[top] = k;
      pkl[top] = kl;
    }
    ws(&r);
    if (r.i >= r.n || buf[r.i] != ':') {
      rc = rderr(&r, NQEDEC, "expected a colon after a key");
      goto fail;
    }
    r.i++;
  }
fail:
  for (; top >= 0; top--)
    if (st[top]->t == DJOBJ)
      qdfree(pk[top]);
  qdjfree(root);
  return rc;
}

/* ---- the canonical writer ---- */

static void wstr(dbuf *b, const char *s, size_t n) {
  size_t i, run = 0;
  qdbch(b, '"');
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    const char *e = NULL;
    char u[8];
    switch (c) {
    case '"': e = "\\\""; break;
    case '\\': e = "\\\\"; break;
    case '\b': e = "\\b"; break;
    case '\f': e = "\\f"; break;
    case '\n': e = "\\n"; break;
    case '\r': e = "\\r"; break;
    case '\t': e = "\\t"; break;
    default:
      if (c < 0x20) {
        snprintf(u, sizeof u, "\\u%04x", c);
        e = u;
      }
    }
    if (e != NULL) {
      qdbput(b, s + run, i - run);
      qdbstr(b, e);
      run = i + 1;
    }
  }
  qdbput(b, s + run, n - run);
  qdbch(b, '"');
}

/* the order of an object's members: indices sorted by key (insertion
 * sort: records' objects are small) */
static void korder(const djs *o, size_t *ix) {
  size_t i, j;
  for (i = 0; i < o->n; i++) {
    size_t v = ix[i] = i;
    for (j = i; j > 0 && qdkcmp(o->key[ix[j - 1]], o->kl[ix[j - 1]],
                               o->key[v], o->kl[v]) > 0;
         j--)
      ix[j] = ix[j - 1];
    ix[j] = v;
  }
}

void qdjwrite(const djs *v, dbuf *b) {
  /* explicit stack of (node, next child, order) */
  const djs *st[DJDEPTH + 1];
  size_t at[DJDEPTH + 1];
  size_t *ord[DJDEPTH + 1];
  int top = 0;
  st[0] = v;
  at[0] = 0;
  ord[0] = NULL;
  for (;;) {
    const djs *c = st[top];
    if (b->err)
      break;
    if (at[top] == 0 && (c->t == DJOBJ || c->t == DJARR)) {
      qdbch(b, c->t == DJOBJ ? '{' : '[');
      if (c->t == DJOBJ && c->n) {
        ord[top] = (size_t *)qdmal(c->n * sizeof(size_t));
        if (ord[top] == NULL) {
          b->err = NQEMEM;
          break;
        }
        korder(c, ord[top]);
      }
    }
    if (c->t == DJOBJ || c->t == DJARR) {
      if (at[top] < c->n) {
        size_t i = c->t == DJOBJ ? ord[top][at[top]] : at[top];
        if (at[top])
          qdbch(b, ',');
        if (c->t == DJOBJ) {
          wstr(b, c->key[i], c->kl[i]);
          qdbch(b, ':');
        }
        at[top]++;
        if (top + 1 > DJDEPTH) {
          b->err = NQELIM;
          break;
        }
        top++;
        st[top] = c->k[i];
        at[top] = 0;
        ord[top] = NULL;
        continue;
      }
      qdbch(b, c->t == DJOBJ ? '}' : ']');
      qdfree(ord[top]);
      ord[top] = NULL;
    } else {
      char nb[40];
      switch (c->t) {
      case DJNULL: qdbstr(b, "null"); break;
      case DJTRUE: qdbstr(b, "true"); break;
      case DJFALSE: qdbstr(b, "false"); break;
      case DJNUM:
        if (qdnumfmt(c->d, nb) != NQOK)
          b->err = NQEARG;
        else
          qdbstr(b, nb);
        break;
      default: wstr(b, c->s, c->sl);
      }
    }
    if (top == 0)
      break;
    top--;
  }
  for (; top >= 0; top--)
    qdfree(ord[top]);
}
