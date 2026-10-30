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
  const char *dir; /* the capsule folder */
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

static FILE *openw(const char *path) { return openh(path, 1); }

/* The final path of an open handle (\\?\C:\...), or NULL. */
static wchar_t *finalp(HANDLE h, size_t *bytes) {
  DWORD n = GetFinalPathNameByHandleW(h, NULL, 0, FILE_NAME_NORMALIZED);
  wchar_t *w;
  if (n == 0) return NULL;
  *bytes = ((size_t)n + 1) * sizeof(wchar_t);
  w = (wchar_t *)nqmal(*bytes);
  if (w == NULL) return NULL;
  if (GetFinalPathNameByHandleW(h, w, n + 1, FILE_NAME_NORMALIZED) == 0 ||
      GetFinalPathNameByHandleW(h, w, n + 1, FILE_NAME_NORMALIZED) > n) {
    nqfree(w, *bytes);
    return NULL;
  }
  return w;
}

/* Opens rel inside dir for reading, refusing it unless the opened file's
 * final path lies under the folder's own: a folder on the way swapped for
 * a junction or link while a seal or check runs is refused, not
 * followed. */
static FILE *openin(const char *dir, const char *rel) {
  size_t fl = 0, rb = 0, db = 0, dn, dwb = 0;
  char *full = join(dir, rel, &fl);
  wchar_t *wd, *rp = NULL, *dp = NULL;
  HANDLE dh;
  FILE *f;
  int ok = 0;
  if (full == NULL) return NULL;
  f = openh(full, 0);
  nqfree(full, fl + 1);
  if (f == NULL) return NULL;
  wd = wide(dir, &dwb);
  dh = wd == NULL ? INVALID_HANDLE_VALUE
                  : CreateFileW(wd, 0, FILE_SHARE_READ | FILE_SHARE_WRITE |
                                           FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (wd != NULL) nqfree(wd, dwb);
  if (dh != INVALID_HANDLE_VALUE) {
    dp = finalp(dh, &db);
    CloseHandle(dh);
  }
  rp = finalp((HANDLE)_get_osfhandle(_fileno(f)), &rb);
  if (dp != NULL && rp != NULL) {
    dn = wcslen(dp);
    while (dn > 0 && dp[dn - 1] == L'\\') dn--;
    ok = wcslen(rp) > dn + 1 && _wcsnicmp(rp, dp, dn) == 0 &&
         rp[dn] == L'\\';
  }
  if (dp != NULL) nqfree(dp, db);
  if (rp != NULL) nqfree(rp, rb);
  if (!ok) {
    fclose(f);
    return NULL;
  }
  return f;
}

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

static void droptmp(const char *tmp) {
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

/* Opens rel (rl bytes, '/'-separated) under dir without following a link
 * anywhere in rel: each folder on the way is opened with openat
 * (O_DIRECTORY | O_NOFOLLOW) from the one before, so a folder swapped for
 * a link while a seal or check runs is refused, not followed (dir itself,
 * the folder the caller named, may be a link). isdir: rel is a folder
 * ("" is dir). A file must be plain; O_NONBLOCK keeps a FIFO from
 * blocking the open and is cleared after. Returns an fd, or -1. */
static int openat1(const char *dir, const char *rel, size_t rl, int isdir) {
  int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC), nfd, fl;
  char nm[256]; /* one component; no allocation, so no NQEMEM to report */
  size_t i = 0;
  struct stat st;
  if (fd < 0) return -1;
  if (rl == 0) {
    if (isdir) return fd;
    close(fd);
    return -1;
  }
  while (fd >= 0) {
    const char *s = rel + i, *e = (const char *)memchr(s, '/', rl - i);
    size_t cl = e == NULL ? rl - i : (size_t)(e - s);
    int last = e == NULL;
    if (cl == 0 || cl >= sizeof nm || (cl == 1 && s[0] == '.') ||
        (cl == 2 && s[0] == '.' && s[1] == '.')) {
      nfd = -1;
    } else {
      memcpy(nm, s, cl);
      nm[cl] = '\0';
      if (!last || isdir) {
        nfd = openat(fd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      } else {
        nfd = openat(fd, nm, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
      }
    }
    close(fd);
    fd = nfd;
    if (last) break;
    i += cl + 1;
  }
  if (fd >= 0 && !isdir &&
      (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
       (fl = fcntl(fd, F_GETFL)) < 0 ||
       fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) != 0)) {
    close(fd);
    fd = -1;
  }
  return fd;
}

static FILE *openin(const char *dir, const char *rel) {
  FILE *f;
  int fd = openat1(dir, rel, strlen(rel), 0);
  if (fd < 0) return NULL;
  f = fdopen(fd, "rb");
  if (f == NULL) close(fd);
  return f;
}

static int walk1(wctx *w, const char *full) {
  int dfd = openat1(w->dir, w->rel, w->rl, 1);
  DIR *d = dfd < 0 ? NULL : fdopendir(dfd);
  struct dirent *de;
  int rc = NQOK;
  (void)full;
  if (d == NULL) {
    if (dfd >= 0) close(dfd);
    return NQEIO;
  }
  for (;;) {
    struct stat st;
    size_t nl;
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
    if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
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
    if (rc != NQOK) break;
  }
  closedir(d);
  return rc;
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

static void droptmp(const char *tmp) { unlink(tmp); }

#if defined(__wasi__)
/* WASI has no process ids: random bits keep two writers' temporary
 * names apart instead (O_EXCL still refuses a clash) */
static unsigned long mypid(void) {
  uint8_t b[4] = {0, 0, 0, 0};
  (void)nqrand(b, sizeof b);
  return (unsigned long)b[0] | (unsigned long)b[1] << 8 |
         (unsigned long)b[2] << 16 | (unsigned long)b[3] << 24;
}
#else
static unsigned long mypid(void) { return (unsigned long)getpid(); }
#endif

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
    w.dir = dir;
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

/* whether the first bytes of a file are a noqtis secret key's header
 * line, "noqtis-key-1 <alg> sec" */
static int seckey(const unsigned char *b, size_t n) {
  static const char mg[] = "noqtis-key-1 ";
  const unsigned char *e;
  size_t m = sizeof mg - 1;
  if (n < m + 5 || memcmp(b, mg, m) != 0) return 0;
  e = (const unsigned char *)memchr(b, '\n', n);
  if (e == NULL) return 0;
  if (e > b && e[-1] == '\r') e--;
  return (size_t)(e - b) >= m + 5 && memcmp(e - 4, " sec", 4) == 0;
}

int nqcsec(const char *dir, const char *rel, int *sec) {
  unsigned char buf[16384]; /* nqcdigx's first read, so both agree */
  size_t k;
  FILE *f;
  int rc = NQOK;
  if (dir == NULL || rel == NULL || sec == NULL) return NQEARG;
  *sec = 0;
  f = openin(dir, rel);
  if (f == NULL) return NQEIO;
  k = fread(buf, 1, sizeof buf, f);
  if (ferror(f)) rc = NQEIO;
  else *sec = seckey(buf, k);
  fclose(f);
  return rc;
}

int nqcdig(const char *dir, const char *rel, uint64_t *size,
           uint8_t s2[32], uint8_t s3[32]) {
  return nqcdigx(dir, rel, (uint64_t)-1, size, s2, s3, NULL);
}

int nqcdigx(const char *dir, const char *rel, uint64_t max, uint64_t *size,
            uint8_t s2[32], uint8_t s3[32], int *sec) {
  unsigned char buf[16384];
  nqhctx c2, c3;
  size_t k;
  uint64_t tot = 0;
  FILE *f;
  int rc = NQOK;
  if (dir == NULL || rel == NULL || size == NULL) return NQEARG;
  f = openin(dir, rel);
  if (f == NULL) return NQEIO;
  if (nqhini(&c2, NQS256) != NQOK || nqhini(&c3, NQS3256) != NQOK) {
    fclose(f);
    return NQEARG;
  }
  if (sec != NULL) *sec = 0;
  while ((k = fread(buf, 1, sizeof buf, f)) > 0) {
    if (tot == 0 && sec != NULL) *sec = seckey(buf, k);
    nqhupd(&c2, buf, k);
    nqhupd(&c3, buf, k);
    tot += k;
    /* a file swapped for a bigger (or sparse) one fails without being
     * read to its end */
    if (tot > max) break;
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
  size_t len = 0, k, want;
  uint64_t sz = 0;
  char *b, extra;
  FILE *f;
  int rc;
  if (dir == NULL || name == NULL || buf == NULL || n == NULL) {
    return NQEARG;
  }
  f = openin(dir, name);
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
    if (rc != NQOK) droptmp(tmp);
  }
  nqfree(tmp, tl + 1);
  nqfree(full, fl + 1);
  return rc;
}
