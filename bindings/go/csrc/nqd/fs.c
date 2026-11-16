/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqd: files (UTF-8 paths, wide on Windows), capsule paths, digests, and
 * the check report. The only platform code of nqd. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE /* O_NOFOLLOW is hidden under plain POSIX */
#endif
#endif

#include "int.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <wchar.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define WMAX 4200 /* as the joined paths below: a longer path is not opened */

/* the path as UTF-16 in w, which holds WMAX wide characters and is the
 * caller's own array: nothing is allocated, so a path cannot fail for
 * want of memory and be taken for a file that is not there. 0 when the
 * text is not UTF-8 or does not fit */
static int wide(const char *s, wchar_t *w) {
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, WMAX) >
         0;
}
#endif

FILE *qdfopen(const char *path, const char *mode) {
#ifdef _WIN32
  wchar_t p[WMAX], m[16];
  if (!wide(path, p) ||
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, mode, -1, m, 16) <= 0)
    return NULL;
  return _wfopen(p, m);
#else
  return fopen(path, mode);
#endif
}

static int drename(const char *from, const char *to) {
#ifdef _WIN32
  wchar_t a[WMAX], b[WMAX];
  int ok = wide(from, a) && wide(to, b) &&
           MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING) != 0;
  return ok ? 0 : -1;
#else
  return rename(from, to);
#endif
}

static int dremove(const char *path) {
#ifdef _WIN32
  wchar_t a[WMAX];
  int ok = wide(path, a) && DeleteFileW(a) != 0;
  return ok ? 0 : -1;
#else
  return remove(path);
#endif
}

FILE *qdfnew(const char *path) {
#ifdef _WIN32
  wchar_t p[WMAX];
  int fd = wide(path, p) ? _wopen(p, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
                                  _S_IREAD | _S_IWRITE)
                         : -1;
  FILE *f = fd >= 0 ? _fdopen(fd, "wb") : NULL;
  if (fd >= 0 && f == NULL)
    _close(fd);
  return f;
#else
  /* never an existing file, nor a link where the file goes (O_EXCL), and
   * rw-r--r-- before the umask: fopen's rw-rw-rw- leaves a new file
   * writable by everyone under a umask of 0 */
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
  FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;
  if (fd >= 0 && f == NULL)
    close(fd);
  return f;
#endif
}

int qdmkdir(const char *path) {
#ifdef _WIN32
  wchar_t p[WMAX];
  int r = wide(path, p) && _wmkdir(p) == 0;
  return r ? NQOK : NQEIO;
#else
  return mkdir(path, 0755) == 0 ? NQOK : NQEIO;
#endif
}

int qdrm(const char *path, int isdir) {
#ifdef _WIN32
  wchar_t p[WMAX];
  int r = wide(path, p) && (isdir ? _wrmdir(p) : _wunlink(p)) == 0;
  return r ? NQOK : NQEIO;
#else
  return (isdir ? rmdir(path) : unlink(path)) == 0 ? NQOK : NQEIO;
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

/* reads f to its end (and closes it) */
static int readf(FILE *f, size_t max, char **buf, size_t *len) {
  dbuf b;
  char t[8192];
  size_t k;
  memset(&b, 0, sizeof b);
  b.max = max;
  *buf = NULL;
  *len = 0;
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
  /* exactly len + 1 bytes, the size the caller frees */
  *buf = b.b != NULL && b.cap == b.n + 1 ? b.b
                                         : qddup(b.b != NULL ? b.b : "", b.n);
  *len = b.n;
  if (*buf != b.b)
    qdbfree(&b);
  if (*buf == NULL) {
    *len = 0;
    return NQEMEM;
  }
  return NQOK;
}

int qdread(const char *path, size_t max, char **buf, size_t *len) {
  FILE *f = qdfopen(path, "rb");
  *buf = NULL;
  *len = 0;
  if (f == NULL)
    return NQEIO;
  return readf(f, max, buf, len);
}

/* The k-th name (0 to 15) a file is written through before it is
 * renamed into place: ".noqtis.<pid, 8 hex><k, 8 hex>.tmp" in its folder.
 * The tool's own temporary files share the ".noqtis.<16 hex>.tmp" shape,
 * so a seal never takes one left behind for data (nqctmpnm), and the
 * tool knows the first name to remove when a signal stops the write.
 * WASI has no process ids: random bits stand in. */
static void tmpnm(char *out, size_t cap, unsigned k) {
  unsigned long pid;
#if defined(_WIN32)
  pid = (unsigned long)GetCurrentProcessId();
#elif defined(__wasi__)
  uint8_t r[4] = {0, 0, 0, 0};
  (void)nqrand(r, sizeof r);
  pid = (unsigned long)r[0] | (unsigned long)r[1] << 8 |
        (unsigned long)r[2] << 16 | (unsigned long)r[3] << 24;
#else
  pid = (unsigned long)getpid();
#endif
  snprintf(out, cap, ".noqtis.%08lx%08x.tmp", pid & 0xffffffffUL, k);
}

int qdwrite(const char *path, const char *b, size_t len) {
  char tmp[4200], nm[40];
  const char *sl = strrchr(path, '/');
  size_t dl = sl != NULL ? (size_t)(sl - path) + 1 : 0;
  FILE *f = NULL;
  unsigned k;
  int bad;
#ifdef _WIN32
  const char *s2 = strrchr(path, '\\');
  if (s2 != NULL && s2 + 1 > path + dl)
    dl = (size_t)(s2 - path) + 1;
#endif
  /* a new file (O_EXCL), never one left there or a link planted in its
   * place */
  for (k = 0; k < 16 && f == NULL; k++) {
    tmpnm(nm, sizeof nm, k);
    if (dl + strlen(nm) >= sizeof tmp)
      return NQELIM;
    memcpy(tmp, path, dl);
    strcpy(tmp + dl, nm);
    f = qdfnew(tmp);
  }
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

/* the SHA-256 and size of f's bytes (and closes it) */
static int shaf(FILE *f, uint8_t h[32], uint64_t *size) {
  nqhctx c;
  uint8_t t[16384];
  size_t k;
  uint64_t n = 0;
  int rc;
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

int qdsha(const char *path, uint8_t h[32], uint64_t *size) {
  FILE *f = qdfopen(path, "rb");
  if (f == NULL)
    return NQEIO;
  return shaf(f, h, size);
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
  char *json;
  int ok;
} drow;

struct nqdrep {
  drow *r;
  size_t n;
  size_t cap;
  int err; /* a row that could not be added: the report is not whole */
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
      return r->err = NQELIM;
    nr = (drow *)qdmal(nc * sizeof *nr);
    if (nr == NULL)
      return r->err = NQEMEM;
    for (i = 0; i < r->n; i++)
      nr[i] = r->r[i];
    qdfree(r->r, r->cap * sizeof *r->r);
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
  w.json = NULL;
  if (w.check == NULL || w.detail == NULL) {
    qdfree(w.check, strlen(check) + 1);
    if (w.detail != NULL)
      qdfree(w.detail, strlen(w.detail) + 1);
    return r->err = NQEMEM;
  }
  r->r[r->n++] = w;
  return NQOK;
}

int qdrepjson(nqdrep *r, const char *j) {
  if (r->n == 0)
    return NQEARG;
  if (r->r[r->n - 1].json != NULL)
    qdfree(r->r[r->n - 1].json, strlen(r->r[r->n - 1].json) + 1);
  r->r[r->n - 1].json = qddup(j, strlen(j));
  return r->r[r->n - 1].json != NULL ? NQOK : (r->err = NQEMEM);
}

int qdrepout(nqdrep *r, nqdrep **out, int rc) {
  int e = r->err;
  if (e != NQOK) {
    nqdrepfree(r);
    *out = NULL;
    return e;
  }
  *out = r;
  return rc;
}

const char *nqdrepj(const nqdrep *r, size_t i) {
  return r == NULL || i >= r->n ? NULL : r->r[i].json;
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
    qdfree(r->r[i].check, strlen(r->r[i].check) + 1);
    qdfree(r->r[i].detail, strlen(r->r[i].detail) + 1);
    if (r->r[i].json != NULL)
      qdfree(r->r[i].json, strlen(r->r[i].json) + 1);
  }
  qdfree(r->r, r->cap * sizeof *r->r);
  qdfree(r, sizeof *r);
}

/* ---- paths under a capsule folder, never through a link ---- */

#ifndef _WIN32
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* NQEARG when name exists in the folder fd but could not be opened as
 * asked (a link, or a file where a folder is wanted), NQEIO when it is
 * not there */
static int whyat(int fd, const char *name) {
  struct stat st;
  return fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 ? NQEARG : NQEIO;
}

/* The folder that holds rel's last component, opened from dir one
 * component at a time with O_DIRECTORY | O_NOFOLLOW, so no component of
 * rel is ever a link followed (as the capsule walk of the core opens
 * them; dir itself, the folder the caller named, may be a link), and
 * that last component's name. */
static int parentat(const char *dir, const char *rel, int *pfd,
                    const char **last) {
  int fd = open(dir != NULL && *dir ? dir : ".",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC), nfd, rc;
  char nm[256];
  const char *s = rel, *e;
  if (fd < 0)
    return NQEIO;
  while ((e = strchr(s, '/')) != NULL) {
    size_t cl = (size_t)(e - s);
    if (cl == 0 || cl >= sizeof nm) {
      close(fd);
      return NQEARG;
    }
    memcpy(nm, s, cl);
    nm[cl] = '\0';
    nfd = openat(fd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (nfd < 0) {
      rc = whyat(fd, nm);
      close(fd);
      return rc;
    }
    close(fd);
    fd = nfd;
    s = e + 1;
  }
  if (strlen(s) >= sizeof nm) {
    close(fd);
    return NQEARG;
  }
  *pfd = fd;
  *last = s;
  return NQOK;
}
#else
/* NQEARG when a folder on the way to rel, or rel itself, is a reparse
 * point (a link or junction), NQEIO when one is missing; mustfile: rel
 * must exist */
static int noreparse(const char *dir, const char *rel, int mustfile) {
  char p[4200];
  size_t dl = strlen(dir), i;
  if (dl + 1 + strlen(rel) >= sizeof p)
    return NQELIM;
  memcpy(p, dir, dl);
  p[dl] = '/';
  for (i = 0;; i++) {
    char c = rel[i];
    if (c == '/' || c == '\0') {
      wchar_t w[WMAX];
      DWORD a;
      p[dl + 1 + i] = '\0';
      a = wide(p, w) ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
      if (a == INVALID_FILE_ATTRIBUTES) {
        if (c == '\0' && !mustfile)
          return NQOK;
        return NQEIO;
      }
      if ((a & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
          (c == '/' && (a & FILE_ATTRIBUTE_DIRECTORY) == 0) ||
          (c == '\0' && (a & FILE_ATTRIBUTE_DIRECTORY) != 0))
        return NQEARG;
      if (c == '\0')
        return NQOK;
    }
    p[dl + 1 + i] = c;
  }
}
#endif

int qdopen(const char *dir, const char *rel, FILE **f) {
  char p[4200];
  int rc;
  *f = NULL;
  if ((rc = qdjoin(dir, rel, p, sizeof p)) != NQOK)
    return rc;
#ifdef _WIN32
  {
    wchar_t w[WMAX];
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION fi;
    int fd;
    if ((rc = noreparse(dir != NULL && *dir ? dir : ".", rel, 1)) != NQOK)
      return rc;
    if (!wide(p, w))
      return NQEIO;
    /* the path itself, never a reparse point's target, checked on the
     * open handle */
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    NULL);
    if (h == INVALID_HANDLE_VALUE)
      return NQEIO;
    if (!GetFileInformationByHandle(h, &fi) ||
        (fi.dwFileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
          FILE_ATTRIBUTE_DEVICE)) != 0) {
      CloseHandle(h);
      return NQEARG;
    }
    fd = _open_osfhandle((intptr_t)h, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
      CloseHandle(h);
      return NQEIO;
    }
    if ((*f = _fdopen(fd, "rb")) == NULL) {
      _close(fd);
      return NQEIO;
    }
    return NQOK;
  }
#else
  {
    int pfd, fd, fl;
    const char *last;
    struct stat st;
    if ((rc = parentat(dir, rel, &pfd, &last)) != NQOK)
      return rc;
    /* O_NONBLOCK keeps a FIFO from blocking the open; cleared after */
    fd = openat(pfd, last, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    rc = fd < 0 ? whyat(pfd, last) : NQOK;
    close(pfd);
    if (fd < 0)
      return rc;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (fl = fcntl(fd, F_GETFL)) < 0 ||
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) != 0) {
      close(fd);
      return NQEARG;
    }
    if ((*f = fdopen(fd, "rb")) == NULL) {
      close(fd);
      return NQEIO;
    }
    return NQOK;
  }
#endif
}

FILE *qdfnewat(const char *dir, const char *rel) {
  char p[4200];
  if (qdjoin(dir, rel, p, sizeof p) != NQOK)
    return NULL;
#ifdef _WIN32
  if (noreparse(dir != NULL && *dir ? dir : ".", rel, 0) != NQOK)
    return NULL;
  return qdfnew(p);
#else
  {
    int pfd, fd;
    const char *last;
    FILE *f;
    if (parentat(dir, rel, &pfd, &last) != NQOK)
      return NULL;
    fd = openat(pfd, last, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    close(pfd);
    if (fd < 0)
      return NULL;
    if ((f = fdopen(fd, "wb")) == NULL)
      close(fd);
    return f;
  }
#endif
}

int qdwriteat(const char *dir, const char *rel, const char *b, size_t len) {
  char p[4200];
  int rc;
  if ((rc = qdjoin(dir, rel, p, sizeof p)) != NQOK)
    return rc;
#ifdef _WIN32
  if ((rc = noreparse(dir != NULL && *dir ? dir : ".", rel, 0)) != NQOK)
    return rc;
  return qdwrite(p, b, len);
#else
  {
    int pfd, fd, bad = 0;
    const char *last;
    char tmp[40];
    struct stat st;
    size_t done = 0;
    unsigned j;
    if ((rc = parentat(dir, rel, &pfd, &last)) != NQOK)
      return rc;
    /* the file itself may be new or a plain file, never a link */
    if (fstatat(pfd, last, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        !S_ISREG(st.st_mode)) {
      close(pfd);
      return NQEARG;
    }
    /* a new file (O_EXCL), never one left there or a link planted in
     * its place */
    for (j = 0, fd = -1; j < 16 && fd < 0; j++) {
      tmpnm(tmp, sizeof tmp, j);
      fd = openat(pfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                  O_CLOEXEC, 0644);
    }
    if (fd < 0) {
      close(pfd);
      return NQEIO;
    }
    while (done < len) {
      ssize_t k = write(fd, b + done, len - done);
      if (k <= 0) {
        bad = 1;
        break;
      }
      done += (size_t)k;
    }
    bad |= close(fd) != 0;
    if (bad || renameat(pfd, tmp, pfd, last) != 0) {
      unlinkat(pfd, tmp, 0);
      close(pfd);
      return NQEIO;
    }
    close(pfd);
    return NQOK;
  }
#endif
}

int qdreadat(const char *dir, const char *rel, size_t max, char **buf,
             size_t *len) {
  FILE *f;
  int rc;
  *buf = NULL;
  *len = 0;
  if ((rc = qdopen(dir, rel, &f)) != NQOK)
    return rc;
  return readf(f, max, buf, len);
}

int qdshaat(const char *dir, const char *rel, uint8_t h[32],
            uint64_t *size) {
  FILE *f;
  int rc;
  *size = 0;
  if ((rc = qdopen(dir, rel, &f)) != NQOK)
    return rc;
  return shaf(f, h, size);
}
