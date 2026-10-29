/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The capsule folder: a walk that never follows a link (POSIX lstat,
 * Windows reparse points), streamed digests, and reads and writes that
 * refuse links (O_NOFOLLOW; FILE_ATTRIBUTE_REPARSE_POINT). Paths are
 * UTF-8 with '/' inside the capsule; Windows converts them to UTF-16. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE /* O_NOFOLLOW is hidden under plain POSIX */
#endif
#endif

#include <stdio.h>
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"

#if defined(_WIN32)
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef O_NOFOLLOW
#error "noqtis: the capsule layer needs O_NOFOLLOW"
#endif
#endif

/* ---- the list ---- */

static int addent(nqclist *l, const char *p, size_t n, int kind,
                  uint64_t size) {
  nqcent *e;
  if (l->n >= nqclim.files) {
    l->lim = NQCLFILES;
    return NQELIM;
  }
  if (l->n == l->cap) {
    size_t nc = l->cap == 0 ? 64 : l->cap * 2;
    nqcent *ne = (nqcent *)nqmal(nc * sizeof(nqcent));
    if (ne == NULL) return NQEMEM;
    if (l->n != 0) memcpy(ne, l->e, l->n * sizeof(nqcent));
    nqfree(l->e, l->cap * sizeof(nqcent));
    l->e = ne;
    l->cap = nc;
  }
  e = &l->e[l->n];
  e->path = (char *)nqmal(n + 1);
  if (e->path == NULL) return NQEMEM;
  memcpy(e->path, p, n);
  e->path[n] = 0;
  e->len = n;
  e->kind = kind;
  e->size = size;
  l->n++;
  return NQOK;
}

void nqclfree(nqclist *l) {
  size_t i;
  if (l == NULL) return;
  for (i = 0; i < l->n; i++) nqfree(l->e[i].path, l->e[i].len + 1);
  nqfree(l->e, l->cap * sizeof(nqcent));
  l->e = NULL;
  l->n = 0;
  l->cap = 0;
}

static int pathcmp(const void *ctx, size_t a, size_t b) {
  const nqclist *l = (const nqclist *)ctx;
  size_t m = l->e[a].len < l->e[b].len ? l->e[a].len : l->e[b].len;
  int c = memcmp(l->e[a].path, l->e[b].path, m);
  if (c != 0) return c;
  if (l->e[a].len != l->e[b].len) return l->e[a].len < l->e[b].len ? -1 : 1;
  return 0;
}

static int sortl(nqclist *l) {
  size_t *idx, i;
  nqcent *ne;
  int rc;
  if (l->n < 2) return NQOK;
  idx = (size_t *)nqmal(l->n * sizeof(size_t));
  ne = (nqcent *)nqmal(l->cap * sizeof(nqcent));
  if (idx == NULL || ne == NULL) {
    nqfree(idx, l->n * sizeof(size_t));
    nqfree(ne, l->cap * sizeof(nqcent));
    return NQEMEM;
  }
  for (i = 0; i < l->n; i++) idx[i] = i;
  rc = nqcsort(idx, l->n, pathcmp, l);
  if (rc == NQOK) {
    for (i = 0; i < l->n; i++) ne[i] = l->e[idx[i]];
    memcpy(l->e, ne, l->n * sizeof(nqcent));
  }
  nqfree(idx, l->n * sizeof(size_t));
  nqfree(ne, l->cap * sizeof(nqcent));
  return rc;
}

/* dir + "/" + rel (rel may be empty), in a fresh buffer of *n + 1 */
static char *join(const char *dir, const char *rel, size_t *n) {
  size_t dl = strlen(dir), rl = strlen(rel);
  char *p;
  if (dl > NQCPATHMAX * 4 || rl > NQCPATHMAX) return NULL;
  p = (char *)nqmal(dl + rl + 2);
  if (p == NULL) return NULL;
  memcpy(p, dir, dl);
  *n = dl;
  if (rl != 0) {
    p[(*n)++] = '/';
    memcpy(p + *n, rel, rl);
    *n += rl;
  }
  p[*n] = 0;
  return p;
}

/* folders still to walk: relative paths */
typedef struct {
  char **p;
  size_t *len;
  size_t n;
  size_t cap;
} dstack;

static int dpush(dstack *s, const char *p, size_t n) {
  char *c;
  if (s->n == s->cap) {
    size_t nc = s->cap == 0 ? 16 : s->cap * 2, i;
    char **np = (char **)nqmal(nc * sizeof(char *));
    size_t *nl = (size_t *)nqmal(nc * sizeof(size_t));
    if (np == NULL || nl == NULL) {
      nqfree(np, nc * sizeof(char *));
      nqfree(nl, nc * sizeof(size_t));
      return NQEMEM;
    }
    for (i = 0; i < s->n; i++) {
      np[i] = s->p[i];
      nl[i] = s->len[i];
    }
    nqfree(s->p, s->cap * sizeof(char *));
    nqfree(s->len, s->cap * sizeof(size_t));
    s->p = np;
    s->len = nl;
    s->cap = nc;
  }
  c = (char *)nqmal(n + 1);
  if (c == NULL) return NQEMEM;
  memcpy(c, p, n);
  c[n] = 0;
  s->p[s->n] = c;
  s->len[s->n] = n;
  s->n++;
  return NQOK;
}

static void dfree(dstack *s) {
  size_t i;
  for (i = 0; i < s->n; i++) nqfree(s->p[i], s->len[i] + 1);
  nqfree(s->p, s->cap * sizeof(char *));
  nqfree(s->len, s->cap * sizeof(size_t));
}

static size_t depth(const char *p, size_t n) {
  size_t i, d = 1;
  for (i = 0; i < n; i++) d += p[i] == '/';
  return d;
}

/* one directory entry named nm (UTF-8) inside the folder rel */
typedef struct {
  nqclist *l;
  dstack *s;
  const char *rel;
  size_t rl;
} wctx;

static int child(wctx *w, const char *nm, size_t nl, int isdir, int kind,
                 uint64_t size) {
  char buf[NQCPATHMAX + 1];
  size_t n = 0;
  if ((nl == 1 && nm[0] == '.') || (nl == 2 && nm[0] == '.' && nm[1] == '.'))
    return NQOK;
  if (w->rl == 0 && ((nl == strlen(NQCMAN) && memcmp(nm, NQCMAN, nl) == 0) ||
                     (nl == strlen(NQCSIG) && memcmp(nm, NQCSIG, nl) == 0))) {
    return NQOK;
  }
  if (w->rl + 1 + nl > nqclim.path) {
    w->l->lim = NQCLPATH;
    return NQELIM;
  }
  if (w->rl != 0) {
    memcpy(buf, w->rel, w->rl);
    n = w->rl;
    buf[n++] = '/';
  }
  memcpy(buf + n, nm, nl);
  n += nl;
  buf[n] = 0;
  if (!nqcname(nm, nl)) return addent(w->l, buf, n, NQCBAD, 0);
  if (kind == NQCREG && isdir) {
    if (depth(buf, n) > nqclim.depth) {
      w->l->lim = NQCLDEPTH;
      return NQELIM;
    }
    return dpush(w->s, buf, n);
  }
  return addent(w->l, buf, n, kind, size);
}

#if defined(_WIN32)

static wchar_t *wide(const char *s, size_t *bytes) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  wchar_t *w;
  if (n <= 0) return NULL;
  *bytes = (size_t)n * sizeof(wchar_t);
  w = (wchar_t *)nqmal(*bytes);
  if (w == NULL) return NULL;
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
    nqfree(w, *bytes);
    return NULL;
  }
  return w;
}

static int walk1(wctx *w, const char *full) {
  size_t fl = strlen(full), wb;
  char *pat = (char *)nqmal(fl + 3);
  wchar_t *wp;
  WIN32_FIND_DATAW fd;
  HANDLE h;
  int rc = NQOK;
  if (pat == NULL) return NQEMEM;
  memcpy(pat, full, fl);
  memcpy(pat + fl, "/*", 3);
  wp = wide(pat, &wb);
  nqfree(pat, fl + 3);
  if (wp == NULL) return NQEIO;
  h = FindFirstFileW(wp, &fd);
  nqfree(wp, wb);
  if (h == INVALID_HANDLE_VALUE) return NQEIO;
  do {
    char nm[NQCPATHMAX * 3 + 1];
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fd.cFileName,
                                -1, nm, (int)sizeof nm, NULL, NULL);
    DWORD a = fd.dwFileAttributes;
    uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    if (n <= 1) {
      /* not valid UTF-16: list it under a placeholder name */
      rc = addent(w->l, "?", 1, NQCBAD, 0);
    } else if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
      rc = child(w, nm, (size_t)n - 1, 0, NQCLNK, 0);
    } else if (a & FILE_ATTRIBUTE_DIRECTORY) {
      rc = child(w, nm, (size_t)n - 1, 1, NQCREG, 0);
    } else if (a & FILE_ATTRIBUTE_DEVICE) {
      rc = child(w, nm, (size_t)n - 1, 0, NQCODD, 0);
    } else {
      rc = child(w, nm, (size_t)n - 1, 0, NQCREG, sz);
    }
  } while (rc == NQOK && FindNextFileW(h, &fd));
  if (rc == NQOK && GetLastError() != ERROR_NO_MORE_FILES) rc = NQEIO;
  FindClose(h);
  return rc;
}

/* Opens the path itself, never a link's target (FILE_FLAG_OPEN_REPARSE_
 * POINT), then checks on the open handle that it is a plain file, so no
 * one can swap in a link between the check and the open. */
static FILE *openh(const char *path, int wr) {
  size_t wb;
  wchar_t *wp = wide(path, &wb);
  BY_HANDLE_FILE_INFORMATION fi;
  HANDLE h;
  FILE *f;
  int fd;
  if (wp == NULL) return NULL;
  h = CreateFileW(wp, wr ? GENERIC_WRITE : GENERIC_READ,
                  wr ? 0 : FILE_SHARE_READ, NULL,
                  wr ? CREATE_NEW : OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                  NULL);
  nqfree(wp, wb);
  if (h == INVALID_HANDLE_VALUE) return NULL;
  if (!GetFileInformationByHandle(h, &fi) ||
      (fi.dwFileAttributes &
       (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
        FILE_ATTRIBUTE_DEVICE)) != 0 ||
      (wr && !SetEndOfFile(h))) {
    CloseHandle(h);
    return NULL;
  }
  fd = _open_osfhandle((intptr_t)h, wr ? (_O_WRONLY | _O_BINARY)
                                       : (_O_RDONLY | _O_BINARY));
  if (fd < 0) {
    CloseHandle(h);
    return NULL;
  }
  f = _fdopen(fd, wr ? "wb" : "rb");
  if (f == NULL) _close(fd); /* closes the handle too */
  return f;
}

static FILE *openr(const char *path) { return openh(path, 0); }

static FILE *openw(const char *path) { return openh(path, 1); }

/* Moves the finished temporary file over path, unless path is a link
 * (reparse point) or a folder; a hard link at path is replaced, never
 * written through. */
static int replacef(const char *tmp, const char *path) {
  size_t tb, pb;
  wchar_t *wt = wide(tmp, &tb), *wp = wide(path, &pb);
  DWORD a;
  int rc = NQOK;
  if (wt == NULL || wp == NULL) {
    rc = NQEMEM;
  } else {
    a = GetFileAttributesW(wp);
    if (a != INVALID_FILE_ATTRIBUTES &&
        (a & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
              FILE_ATTRIBUTE_DEVICE)) != 0) {
      rc = NQEIO;
    } else if (!MoveFileExW(wt, wp, MOVEFILE_REPLACE_EXISTING |
                                        MOVEFILE_WRITE_THROUGH)) {
      rc = NQEIO;
    }
  }
  if (wt != NULL) nqfree(wt, tb);
  if (wp != NULL) nqfree(wp, pb);
  return rc;
}

static void rmtmp(const char *tmp) {
  size_t tb;
  wchar_t *wt = wide(tmp, &tb);
  if (wt == NULL) return;
  DeleteFileW(wt);
  nqfree(wt, tb);
}

static unsigned long mypid(void) {
  return (unsigned long)GetCurrentProcessId();
}

static int flush(FILE *f) { return fflush(f) == 0 ? NQOK : NQEIO; }

#else

static int walk1(wctx *w, const char *full) {
  DIR *d = opendir(full);
  struct dirent *de;
  int rc = NQOK;
  if (d == NULL) return NQEIO;
  for (;;) {
    struct stat st;
    char *cp;
    size_t cn, nl;
    errno = 0;
    de = readdir(d);
    if (de == NULL) {
      if (errno != 0) rc = NQEIO;
      break;
    }
    nl = strlen(de->d_name);
    if ((nl == 1 && de->d_name[0] == '.') ||
        (nl == 2 && de->d_name[0] == '.' && de->d_name[1] == '.')) {
      continue;
    }
    if (w->rl + 1 + nl > nqclim.path) {
      w->l->lim = NQCLPATH;
      rc = NQELIM;
      break;
    }
    cp = join(full, de->d_name, &cn);
    if (cp == NULL) {
      rc = NQEMEM;
      break;
    }
    if (lstat(cp, &st) != 0) {
      rc = NQEIO;
    } else if (S_ISLNK(st.st_mode)) {
      rc = child(w, de->d_name, nl, 0, NQCLNK, 0);
    } else if (S_ISDIR(st.st_mode)) {
      rc = child(w, de->d_name, nl, 1, NQCREG, 0);
    } else if (S_ISREG(st.st_mode)) {
      rc = child(w, de->d_name, nl, 0, NQCREG, (uint64_t)st.st_size);
    } else {
      rc = child(w, de->d_name, nl, 0, NQCODD, 0);
    }
    nqfree(cp, cn + 1);
    if (rc != NQOK) break;
  }
  closedir(d);
  return rc;
}

/* O_NONBLOCK, so that a FIFO under a capsule's name does not block the
 * open forever; it is refused below like any file that is not plain,
 * and the flag is cleared for the reads. */
static FILE *openr(const char *path) {
  struct stat st;
  FILE *f;
  int fl, fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return NULL;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      (fl = fcntl(fd, F_GETFL)) < 0 ||
      fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) != 0) {
    close(fd);
    return NULL;
  }
  f = fdopen(fd, "rb");
  if (f == NULL) close(fd);
  return f;
}

/* A new file only (O_EXCL): nqcwrite writes a temporary file and then
 * renames it, so an existing name (a hard link to a file outside the
 * folder, say) is replaced, never written through. */
static FILE *openw(const char *path) {
  struct stat st;
  FILE *f;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
  if (fd < 0) return NULL;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return NULL;
  }
  f = fdopen(fd, "wb");
  if (f == NULL) close(fd);
  return f;
}

/* Renames the finished temporary file to path, unless path is a link,
 * a folder or a special file. */
static int replacef(const char *tmp, const char *path) {
  struct stat st;
  if (lstat(path, &st) == 0 && !S_ISREG(st.st_mode)) return NQEIO;
  return rename(tmp, path) == 0 ? NQOK : NQEIO;
}

static void rmtmp(const char *tmp) { unlink(tmp); }

static unsigned long mypid(void) { return (unsigned long)getpid(); }

static int flush(FILE *f) {
  return fflush(f) == 0 && fsync(fileno(f)) == 0 ? NQOK : NQEIO;
}

#endif

int nqcwalk(const char *dir, nqclist *l) {
  dstack s;
  int rc = NQOK;
  if (dir == NULL || l == NULL) return NQEARG;
  memset(l, 0, sizeof *l);
  memset(&s, 0, sizeof s);
  rc = dpush(&s, "", 0);
  while (rc == NQOK && s.n > 0) {
    char *rel = s.p[s.n - 1];
    size_t rl = s.len[s.n - 1], fl = 0;
    char *full;
    wctx w;
    s.n--;
    full = join(dir, rel, &fl);
    if (full == NULL) {
      nqfree(rel, rl + 1);
      rc = NQEMEM;
      break;
    }
    w.l = l;
    w.s = &s;
    w.rel = rel;
    w.rl = rl;
    rc = walk1(&w, full);
    nqfree(full, fl + 1);
    nqfree(rel, rl + 1);
  }
  dfree(&s);
  if (rc == NQOK) rc = sortl(l);
  if (rc != NQOK) nqclfree(l);
  return rc;
}

int nqcdig(const char *dir, const char *rel, uint64_t *size,
           uint8_t s2[32], uint8_t s3[32]) {
  unsigned char buf[16384];
  nqhctx c2, c3;
  size_t fl = 0, k;
  uint64_t tot = 0;
  char *full;
  FILE *f;
  int rc = NQOK;
  if (dir == NULL || rel == NULL || size == NULL) return NQEARG;
  full = join(dir, rel, &fl);
  if (full == NULL) return NQEMEM;
  f = openr(full);
  nqfree(full, fl + 1);
  if (f == NULL) return NQEIO;
  if (nqhini(&c2, NQS256) != NQOK || nqhini(&c3, NQS3256) != NQOK) {
    fclose(f);
    return NQEARG;
  }
  while ((k = fread(buf, 1, sizeof buf, f)) > 0) {
    nqhupd(&c2, buf, k);
    nqhupd(&c3, buf, k);
    tot += k;
  }
  if (ferror(f)) rc = NQEIO;
  fclose(f);
  if (rc == NQOK) {
    nqhfin(&c2, s2, 32);
    nqhfin(&c3, s3, 32);
    *size = tot;
  }
  nqwipe(&c2, sizeof c2);
  nqwipe(&c3, sizeof c3);
  return rc;
}

/* the size of an open file, without reading it */
static int fsize(FILE *f, uint64_t *sz) {
#if defined(_WIN32)
  __int64 e;
  if (_fseeki64(f, 0, SEEK_END) != 0 || (e = _ftelli64(f)) < 0 ||
      _fseeki64(f, 0, SEEK_SET) != 0) {
    return NQEIO;
  }
#else
  off_t e;
  if (fseeko(f, 0, SEEK_END) != 0 || (e = ftello(f)) < 0 ||
      fseeko(f, 0, SEEK_SET) != 0) {
    return NQEIO;
  }
#endif
  *sz = (uint64_t)e;
  return NQOK;
}

int nqcread(const char *dir, const char *name, size_t max, char **buf,
            size_t *n) {
  size_t fl = 0, len = 0, k, want;
  uint64_t sz = 0;
  char *full, *b, extra;
  FILE *f;
  int rc;
  if (dir == NULL || name == NULL || buf == NULL || n == NULL) {
    return NQEARG;
  }
  full = join(dir, name, &fl);
  if (full == NULL) return NQEMEM;
  f = openr(full);
  nqfree(full, fl + 1);
  if (f == NULL) return NQEIO;
  rc = fsize(f, &sz);
  if (rc == NQOK && sz > max) rc = NQELIM; /* refused before reading */
  if (rc != NQOK) {
    fclose(f);
    return rc;
  }
  want = (size_t)sz;
  b = (char *)nqmal(want + 1);
  if (b == NULL) {
    fclose(f);
    return NQEMEM;
  }
  while (len < want && (k = fread(b + len, 1, want - len, f)) > 0) {
    len += k;
  }
  /* a file that grew while it was read is refused */
  if (len == want && fread(&extra, 1, 1, f) == 1) rc = NQELIM;
  if (rc == NQOK && ferror(f)) rc = NQEIO;
  fclose(f);
  if (rc != NQOK) {
    nqfree(b, want + 1);
    return rc;
  }
  if (len != want) {
    /* it shrank: hand back a buffer of exactly len + 1 */
    char *o = (char *)nqmal(len + 1);
    if (o == NULL) {
      nqfree(b, want + 1);
      return NQEMEM;
    }
    memcpy(o, b, len);
    nqfree(b, want + 1);
    b = o;
  }
  b[len] = 0;
  *buf = b;
  *n = len;
  return NQOK;
}

/* Writes name in dir through a temporary file in the same folder
 * (.<name>.<pid>.<k>.tmp, created new) that is then renamed over name:
 * a reader sees the old file or the new one, never half of one, and an
 * existing name is replaced rather than written through. */
int nqcwrite(const char *dir, const char *name, const char *buf, size_t n) {
  size_t fl = 0, tl = 0;
  char *full, *tmp = NULL, tn[96];
  FILE *f = NULL;
  unsigned k;
  int rc = NQOK;
  if (dir == NULL || name == NULL || (buf == NULL && n != 0)) return NQEARG;
  if (strlen(name) > 40) return NQEARG;
  full = join(dir, name, &fl);
  if (full == NULL) return NQEMEM;
  for (k = 0; k < 16 && f == NULL; k++) {
    snprintf(tn, sizeof tn, ".%s.%lu.%u.tmp", name, mypid(), k);
    if (tmp != NULL) nqfree(tmp, tl + 1);
    tmp = join(dir, tn, &tl);
    if (tmp == NULL) {
      nqfree(full, fl + 1);
      return NQEMEM;
    }
    f = openw(tmp);
  }
  if (f == NULL) {
    rc = NQEIO;
  } else {
    if (n != 0 && fwrite(buf, 1, n, f) != n) rc = NQEIO;
    if (rc == NQOK) rc = flush(f);
    if (fclose(f) != 0) rc = NQEIO;
    if (rc == NQOK) rc = replacef(tmp, full);
    if (rc != NQOK) rmtmp(tmp);
  }
  nqfree(tmp, tl + 1);
  nqfree(full, fl + 1);
  return rc;
}
