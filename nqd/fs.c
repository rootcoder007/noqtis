/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqd: files (UTF-8 paths, wide on Windows), capsule paths, digests, and
 * the check report. The only platform code of nqd. */
#include "int.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN32
static wchar_t *wide(const char *s) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  wchar_t *w;
  if (n <= 0)
    return NULL;
  w = (wchar_t *)malloc((size_t)n * sizeof *w);
  if (w != NULL &&
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
    free(w);
    w = NULL;
  }
  return w;
}
#endif

FILE *qdfopen(const char *path, const char *mode) {
#ifdef _WIN32
  wchar_t *p = wide(path), *m = wide(mode);
  FILE *f = NULL;
  if (p != NULL && m != NULL)
    f = _wfopen(p, m);
  free(p);
  free(m);
  return f;
#else
  return fopen(path, mode);
#endif
}

static int drename(const char *from, const char *to) {
#ifdef _WIN32
  wchar_t *a = wide(from), *b = wide(to);
  int ok = a != NULL && b != NULL &&
           MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING) != 0;
  free(a);
  free(b);
  return ok ? 0 : -1;
#else
  return rename(from, to);
#endif
}

static int dremove(const char *path) {
#ifdef _WIN32
  wchar_t *a = wide(path);
  int ok = a != NULL && DeleteFileW(a) != 0;
  free(a);
  return ok ? 0 : -1;
#else
  return remove(path);
#endif
}

/* the rules of a capsule path (noqtis-capsule(5)), as nqd needs them */
int qdjoin(const char *dir, const char *rel, char *out, size_t cap) {
  size_t n = strlen(rel), i, seg = 0;
  if (n == 0 || n > 4096 || rel[0] == '/' || !qdutf8(rel, n))
    return NQEARG;
  for (i = 0; i <= n; i++) {
    unsigned char c = (unsigned char)rel[i];
    if (c == '/' || c == 0) {
      size_t l = i - seg;
      if (l == 0 || (l == 1 && rel[seg] == '.') ||
          (l == 2 && rel[seg] == '.' && rel[seg + 1] == '.'))
        return NQEARG;
      seg = i + 1;
    } else if (c < 0x20 || c == 0x7f || c == '\\' || c == ':') {
      return NQEARG;
    }
  }
  if (dir == NULL || *dir == '\0')
    dir = ".";
  if ((size_t)snprintf(out, cap, "%s/%s", dir, rel) >= cap)
    return NQELIM;
  return NQOK;
}

int qdread(const char *path, size_t max, char **buf, size_t *len) {
  FILE *f = qdfopen(path, "rb");
  dbuf b;
  char t[8192];
  size_t k;
  memset(&b, 0, sizeof b);
  b.max = max;
  *buf = NULL;
  *len = 0;
  if (f == NULL)
    return NQEIO;
  while ((k = fread(t, 1, sizeof t, f)) > 0) {
    qdbput(&b, t, k);
    if (b.err)
      break;
  }
  if (ferror(f) && !b.err)
    b.err = NQEIO;
  fclose(f);
  if (b.err) {
    qdbfree(&b);
    return b.err;
  }
  if (b.b == NULL && (b.b = qddup("", 0)) == NULL)
    return NQEMEM;
  *buf = b.b;
  *len = b.n;
  return NQOK;
}

int qdwrite(const char *path, const char *b, size_t len) {
  char tmp[4200];
  FILE *f;
  int bad;
  if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", path) >= sizeof tmp)
    return NQELIM;
  f = qdfopen(tmp, "wb");
  if (f == NULL)
    return NQEIO;
  bad = fwrite(b, 1, len, f) != len;
  bad |= fclose(f) != 0;
  if (bad || drename(tmp, path) != 0) {
    dremove(tmp);
    return NQEIO;
  }
  return NQOK;
}

int qdsha(const char *path, uint8_t h[32], uint64_t *size) {
  FILE *f = qdfopen(path, "rb");
  nqhctx c;
  uint8_t t[16384];
  size_t k;
  uint64_t n = 0;
  int rc;
  if (f == NULL)
    return NQEIO;
  if ((rc = nqhini(&c, NQS256)) != NQOK) {
    fclose(f);
    return rc;
  }
  while ((k = fread(t, 1, sizeof t, f)) > 0) {
    nqhupd(&c, t, k);
    n += k;
  }
  rc = ferror(f) ? NQEIO : NQOK;
  fclose(f);
  if (rc == NQOK)
    rc = nqhfin(&c, h, 32);
  *size = n;
  return rc;
}

void qdhex(const uint8_t *in, size_t n, char *out) {
  static const char x[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = x[in[i] >> 4];
    out[2 * i + 1] = x[in[i] & 15];
  }
  out[2 * n] = '\0';
}

/* ---- reports ---- */

typedef struct {
  char *check;
  char *detail;
  int ok;
} drow;

struct nqdrep {
  drow *r;
  size_t n;
  size_t cap;
};

nqdrep *qdrepnew(void) {
  nqdrep *r = (nqdrep *)qdmal(sizeof *r);
  if (r != NULL)
    memset(r, 0, sizeof *r);
  return r;
}

int qdrepadd(nqdrep *r, const char *check, int ok, const char *fmt, ...) {
  char sb[1024];
  va_list ap;
  int n;
  drow w;
  if (r->n == r->cap) {
    size_t nc = r->cap ? r->cap * 2 : 16, i;
    drow *nr;
    if (nc > ((size_t)1 << 26))
      return NQELIM;
    nr = (drow *)qdmal(nc * sizeof *nr);
    if (nr == NULL)
      return NQEMEM;
    for (i = 0; i < r->n; i++)
      nr[i] = r->r[i];
    qdfree(r->r);
    r->r = nr;
    r->cap = nc;
  }
  va_start(ap, fmt);
  n = vsnprintf(sb, sizeof sb, fmt, ap);
  va_end(ap);
  if (n < 0)
    sb[0] = '\0';
  w.check = qddup(check, strlen(check));
  if (n >= (int)sizeof sb) {
    w.detail = (char *)qdmal((size_t)n + 1);
    if (w.detail != NULL) {
      va_start(ap, fmt);
      vsnprintf(w.detail, (size_t)n + 1, fmt, ap);
      va_end(ap);
    }
  } else {
    w.detail = qddup(sb, strlen(sb));
  }
  w.ok = ok != 0;
  if (w.check == NULL || w.detail == NULL) {
    qdfree(w.check);
    qdfree(w.detail);
    return NQEMEM;
  }
  r->r[r->n++] = w;
  return NQOK;
}

size_t nqdrepn(const nqdrep *r) {
  return r == NULL ? 0 : r->n;
}

int nqdrepi(const nqdrep *r, size_t i, const char **check, int *ok,
            const char **detail) {
  if (r == NULL || i >= r->n)
    return NQEARG;
  if (check != NULL)
    *check = r->r[i].check;
  if (ok != NULL)
    *ok = r->r[i].ok;
  if (detail != NULL)
    *detail = r->r[i].detail;
  return NQOK;
}

void nqdrepfree(nqdrep *r) {
  size_t i;
  if (r == NULL)
    return;
  for (i = 0; i < r->n; i++) {
    qdfree(r->r[i].check);
    qdfree(r->r[i].detail);
  }
  qdfree(r->r);
  qdfree(r);
}
