/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Base64, sorting, path rules and RFC 3339 times for the capsule layer. */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"

nqclimt nqclim = {NQCMANMAX, NQCFILES, NQCPATHMAX, NQCDEPTH};

const char *nqclwhy(int lim) {
  switch (lim) {
  case NQCLFILES:
    return "too many files";
  case NQCLPATH:
    return "path too long";
  case NQCLDEPTH:
    return "folder too deep";
  case NQCLMAN:
    return "manifest too large";
  case NQCLMETA:
    return "meta too large";
  default:
    return NULL;
  }
}

/* ---- base64 ---- */

static const char b64t[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t nqb64n(size_t n) { return (n + 2) / 3 * 4; }

void nqb64e(const uint8_t *in, size_t n, char *out) {
  size_t i, o = 0;
  for (i = 0; i + 3 <= n; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                 in[i + 2];
    out[o++] = b64t[(v >> 18) & 63];
    out[o++] = b64t[(v >> 12) & 63];
    out[o++] = b64t[(v >> 6) & 63];
    out[o++] = b64t[v & 63];
  }
  if (n - i == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = b64t[(v >> 18) & 63];
    out[o++] = b64t[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (n - i == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = b64t[(v >> 18) & 63];
    out[o++] = b64t[(v >> 12) & 63];
    out[o++] = b64t[(v >> 6) & 63];
    out[o++] = '=';
  }
  out[o] = 0;
}

static int b64v(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int nqb64d(const char *s, size_t n, uint8_t *out, size_t cap,
           size_t *outlen) {
  size_t i, o = 0, pad = 0, need;
  if (s == NULL || outlen == NULL || (out == NULL && cap != 0)) {
    return NQEARG;
  }
  if (n % 4 != 0) return NQEDEC;
  if (n > 0 && s[n - 1] == '=') pad++;
  if (n > 1 && s[n - 2] == '=') pad++;
  need = n / 4 * 3 - pad;
  if (need > cap) return NQEBUF;
  for (i = 0; i < n; i += 4) {
    int a = b64v((unsigned char)s[i]), b = b64v((unsigned char)s[i + 1]);
    int c, d;
    uint32_t v;
    int last = i + 4 == n;
    c = (last && pad == 2) ? 0 : b64v((unsigned char)s[i + 2]);
    d = (last && pad >= 1) ? 0 : b64v((unsigned char)s[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) return NQEDEC;
    v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) |
        (uint32_t)d;
    /* canonical: the bits the padding drops must be zero */
    if (last && pad == 2 && (b & 15) != 0) return NQEDEC;
    if (last && pad == 1 && (c & 3) != 0) return NQEDEC;
    out[o++] = (uint8_t)(v >> 16);
    if (!(last && pad == 2)) out[o++] = (uint8_t)(v >> 8);
    if (!(last && pad >= 1)) out[o++] = (uint8_t)v;
  }
  *outlen = o;
  return NQOK;
}

/* ---- sorting ---- */

int nqcsort(size_t *idx, size_t n, nqccmp cmp, const void *ctx) {
  size_t *tmp, w, i;
  if (n < 2) return NQOK;
  if (n > (size_t)-1 / sizeof(size_t)) return NQELIM;
  tmp = (size_t *)nqmal(n * sizeof(size_t));
  if (tmp == NULL) return NQEMEM;
  for (w = 1; w < n; w = w > n / 2 ? n : 2 * w) {
    for (i = 0; i < n; i += 2 * w) {
      size_t lo = i, mid = i + w < n ? i + w : n;
      size_t hi = mid + w < n && w <= n - mid ? mid + w : n;
      size_t a = lo, b = mid, o = lo;
      while (a < mid && b < hi) {
        if (cmp(ctx, idx[b], idx[a]) < 0) {
          tmp[o++] = idx[b++];
        } else {
          tmp[o++] = idx[a++];
        }
      }
      while (a < mid) tmp[o++] = idx[a++];
      while (b < hi) tmp[o++] = idx[b++];
    }
    memcpy(idx, tmp, n * sizeof(size_t));
  }
  nqfree(tmp, n * sizeof(size_t));
  return NQOK;
}

/* ---- paths ---- */

int nqcutf8(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s;
  size_t i = 0;
  while (i < n) {
    uint32_t c = p[i], u;
    size_t k, j;
    if (c < 0x80) {
      i++;
      continue;
    }
    if (c >= 0xc2 && c <= 0xdf) {
      k = 1;
      u = c & 0x1f;
    } else if (c >= 0xe0 && c <= 0xef) {
      k = 2;
      u = c & 0x0f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      k = 3;
      u = c & 0x07;
    } else {
      return 0;
    }
    if (n - i <= k) return 0;
    for (j = 1; j <= k; j++) {
      if ((p[i + j] & 0xc0) != 0x80) return 0;
      u = (u << 6) | (p[i + j] & 0x3fu);
    }
    if (k == 2 && u < 0x800) return 0;
    if (k == 3 && (u < 0x10000 || u > 0x10ffff)) return 0;
    if (u >= 0xd800 && u <= 0xdfff) return 0;
    i += k + 1;
  }
  return 1;
}

int nqcname(const char *s, size_t n) {
  size_t i;
  if (n == 0) return 0;
  if (n == 1 && s[0] == '.') return 0;
  if (n == 2 && s[0] == '.' && s[1] == '.') return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c == ':') {
      return 0;
    }
  }
  return nqcutf8(s, n);
}

int nqcnorm(const char *p, size_t n, char *out, size_t cap,
            size_t *outlen) {
  size_t i = 0, o = 0;
  if (p == NULL || out == NULL || outlen == NULL || cap == 0) return NQEARG;
  if (n == 0 || p[0] == '/') return NQEDEC;
  if (memchr(p, 0, n) != NULL) return NQEDEC;
  while (i < n) {
    size_t j = i, sl;
    while (j < n && p[j] != '/') j++;
    sl = j - i;
    if (sl == 0 || (sl == 1 && p[i] == '.')) {
      i = j + 1;
      continue;
    }
    if (!nqcname(p + i, sl)) return NQEDEC;
    if (o + (o != 0) + sl + 1 > cap) return NQELIM;
    if (o != 0) out[o++] = '/';
    memcpy(out + o, p + i, sl);
    o += sl;
    i = j + 1;
  }
  if (o == 0) return NQEDEC;
  out[o] = 0;
  *outlen = o;
  return NQOK;
}

static unsigned char lower(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

int nqcfold(const char *a, size_t an, const char *b, size_t bn) {
  size_t i, m = an < bn ? an : bn;
  for (i = 0; i < m; i++) {
    unsigned char x = lower((unsigned char)a[i]);
    unsigned char y = lower((unsigned char)b[i]);
    if (x != y) return x < y ? -1 : 1;
  }
  if (an != bn) return an < bn ? -1 : 1;
  return 0;
}

/* ---- times ---- */

static void put2(char *o, unsigned v) {
  o[0] = (char)('0' + v / 10 % 10);
  o[1] = (char)('0' + v % 10);
}

int nqctime(int64_t t, char out[21]) {
  int64_t days, z, era, doe, yoe, y, doy, mp, d, m, s;
  if (t < 0 || t > 253402300799LL) return NQEARG;
  days = t / 86400;
  s = t % 86400;
  z = days + 719468;
  era = z / 146097;
  doe = z - era * 146097;
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = yoe + era * 400;
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;
  put2(out, (unsigned)(y / 100));
  put2(out + 2, (unsigned)(y % 100));
  out[4] = '-';
  put2(out + 5, (unsigned)m);
  out[7] = '-';
  put2(out + 8, (unsigned)d);
  out[10] = 'T';
  put2(out + 11, (unsigned)(s / 3600));
  out[13] = ':';
  put2(out + 14, (unsigned)(s / 60 % 60));
  out[16] = ':';
  put2(out + 17, (unsigned)(s % 60));
  out[19] = 'Z';
  out[20] = 0;
  return NQOK;
}

static int num(const char *s, size_t i, size_t k, unsigned *v) {
  size_t j;
  *v = 0;
  for (j = i; j < i + k; j++) {
    if (s[j] < '0' || s[j] > '9') return 0;
    *v = *v * 10 + (unsigned)(s[j] - '0');
  }
  return 1;
}

int nqctchk(const char *s, size_t n) {
  static const unsigned dim[12] = {31, 29, 31, 30, 31, 30,
                                   31, 31, 30, 31, 30, 31};
  unsigned y, mo, d, h, mi, se;
  size_t i;
  if (s == NULL || n < 20) return 0;
  if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
      s[16] != ':') {
    return 0;
  }
  if (!num(s, 0, 4, &y) || !num(s, 5, 2, &mo) || !num(s, 8, 2, &d) ||
      !num(s, 11, 2, &h) || !num(s, 14, 2, &mi) || !num(s, 17, 2, &se)) {
    return 0;
  }
  if (mo < 1 || mo > 12 || d < 1 || d > dim[mo - 1] || h > 23 || mi > 59 ||
      se > 60) {
    return 0;
  }
  if (mo == 2 && d == 29 &&
      !((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) {
    return 0;
  }
  i = 19;
  if (s[i] == '.') {
    i++;
    if (i >= n || s[i] < '0' || s[i] > '9') return 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') i++;
  }
  return i + 1 == n && s[i] == 'Z';
}
