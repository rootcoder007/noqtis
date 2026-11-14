/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: files. UTF-8 paths everywhere, owner-only secret files, and no
 * overwrite unless asked. Platform-specific, as net.c is. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE /* O_NOFOLLOW is hidden under plain POSIX */
#endif
#endif

#include "cli.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
/* A new UTF-16 copy of a UTF-8 string; NULL on failure. */
static wchar_t *wide(const char *s) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  wchar_t *w;
  if (n <= 0)
    return NULL;
  w = (wchar_t *)malloc((size_t)n * sizeof *w);
  if (w == NULL)
    return NULL;
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
    free(w);
    return NULL;
  }
  return w;
}
#endif

void ncbin(void) {
#ifdef _WIN32
  (void)_setmode(_fileno(stdin), _O_BINARY);
  (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
}

FILE *ncfopen(const char *path, const char *mode) {
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

int ncgmtime(time_t t, struct tm *tm) {
#ifdef _WIN32
  return gmtime_s(tm, &t) == 0 ? NCOK : NCUSE;
#else
  return gmtime_r(&t, tm) != NULL ? NCOK : NCUSE;
#endif
}

int ncexist(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  struct _stat64 st;
  int r = p != NULL && _wstat64(p, &st) == 0;
  free(p);
  return r;
#else
  struct stat st;
  return stat(path, &st) == 0;
#endif
}

int ncisreg(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  struct _stat64 st;
  int r = p != NULL && _wstat64(p, &st) == 0 && (st.st_mode & _S_IFREG);
  free(p);
  return r;
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

int ncisdir(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  struct _stat64 st;
  int r = p != NULL && _wstat64(p, &st) == 0 && (st.st_mode & _S_IFDIR);
  free(p);
  return r;
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static int rmpath(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  int r = p != NULL ? _wunlink(p) : -1;
  free(p);
  return r;
#else
  return unlink(path);
#endif
}

int ncmkdir(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  int r = p != NULL && _wmkdir(p) == 0;
  free(p);
  return r ? NCOK : NCUSE;
#else
  return mkdir(path, 0700) == 0 ? NCOK : NCUSE;
#endif
}

int ncrmfile(const char *path) {
  return rmpath(path);
}

int ncrmdir(const char *path) {
#ifdef _WIN32
  wchar_t *p = wide(path);
  int r = p != NULL ? _wrmdir(p) : -1;
  free(p);
  return r;
#else
  return rmdir(path);
#endif
}

void ncfree(void *p, size_t len, int sec) {
  if (p == NULL)
    return;
  if (sec)
    nqwipe(p, len);
  free(p);
}

/* Reads from descriptor fd into b (cap bytes) up to a newline (not
 * kept, nor a carriage return before it) or the end; one byte at a
 * time, so nothing past the line is taken from a shared pipe. NQELIM
 * when the line is longer than cap, NQEIO when fd cannot be read. */
int ncrdfd(int fd, uint8_t *b, size_t cap, size_t *n) {
  size_t k = 0;
  *n = 0;
  for (;;) {
    unsigned char c;
#ifdef _WIN32
    int r = _read(fd, &c, 1);
#else
    ssize_t r = read(fd, &c, 1);
    if (r < 0 && errno == EINTR)
      continue;
#endif
    if (r < 0)
      return NQEIO;
    if (r == 0 || c == '\n')
      break;
    if (k == cap) {
      nqwipe(&c, 1);
      return NQELIM;
    }
    b[k++] = c;
    nqwipe(&c, 1);
  }
  if (k > 0 && b[k - 1] == '\r')
    k--;
  *n = k;
  return NQOK;
}

int ncrd(const char *path, int sec, uint8_t **buf, size_t *len) {
  return ncrdx(path, sec, NCRDMAX, buf, len);
}

int ncrdx(const char *path, int sec, size_t max, uint8_t **buf,
          size_t *len) {
  FILE *f;
  uint8_t *b = NULL;
  size_t n = 0, cap = 0;
  int std = strcmp(path, "-") == 0;
  *buf = NULL;
  *len = 0;
  f = std ? stdin : ncfopen(path, "rb");
  if (f == NULL)
    return NQEIO;
  /* no stdio buffer holds a copy of a secret */
  if (sec && !std)
    setvbuf(f, NULL, _IONBF, 0);
  for (;;) {
    size_t got;
    if (n == cap) {
      size_t nc = cap == 0 ? 4096 : cap * 2;
      uint8_t *nb;
      if (nc <= cap || nc > (size_t)-1 / 2) {
        ncfree(b, cap, sec);
        if (!std)
          fclose(f);
        return NQELIM;
      }
      nb = (uint8_t *)malloc(nc);
      if (nb == NULL) {
        ncfree(b, cap, sec);
        if (!std)
          fclose(f);
        return NQEMEM;
      }
      if (n > 0)
        memcpy(nb, b, n);
      ncfree(b, cap, sec);
      b = nb;
      cap = nc;
    }
    got = fread(b + n, 1, cap - n, f);
    n += got;
    if (got == 0)
      break;
    if (n > max) {
      ncfree(b, cap, sec);
      if (!std)
        fclose(f);
      return NQELIM;
    }
  }
  if (ferror(f)) {
    ncfree(b, cap, sec);
    if (!std)
      fclose(f);
    return NQEIO;
  }
  if (!std)
    fclose(f);
  /* shrink the capacity bookkeeping away: callers wipe n bytes, so the
   * unused tail is wiped here */
  if (sec && cap > n)
    nqwipe(b + n, cap - n);
  *buf = b;
  *len = n;
  return NQOK;
}

FILE *ncopen(const char *path, int force, int sec) {
  int fd = -1, tries;
  FILE *f;
  for (tries = 0; tries < 2; tries++) {
#ifdef _WIN32
    wchar_t *p = wide(path);
    if (p == NULL)
      return NULL;
    /* owner-only on Windows comes from the folder's ACL */
    fd = _wopen(p, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                _S_IREAD | _S_IWRITE);
    free(p);
#else
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
              sec ? (mode_t)0600 : (mode_t)0666);
#endif
    if (fd >= 0 || errno != EEXIST || !force)
      break;
    /* replace: remove first, so the new file never inherits the old
     * one's permissions or follows a link */
    if (rmpath(path) != 0)
      return NULL;
  }
  if (fd < 0)
    return NULL;
#ifndef _WIN32
  /* the mode whatever the umask: a public key or signature 0644, never
   * group- or world-writable (a .pub is a trust anchor), a secret 0600 */
  if (fchmod(fd, sec ? (mode_t)0600 : (mode_t)0644) != 0) {
    close(fd);
    return NULL;
  }
#endif
#ifdef _WIN32
  f = _fdopen(fd, "wb");
  if (f == NULL)
    _close(fd);
#else
  f = fdopen(fd, "wb");
  if (f == NULL)
    close(fd);
#endif
  if (f != NULL && sec)
    setvbuf(f, NULL, _IONBF, 0);
  return f;
}

int ncclose(FILE *f, const char *path, int bad) {
  if (fflush(f) != 0 || ferror(f))
    bad = 1;
  if (fclose(f) != 0)
    bad = 1;
  if (bad) {
    (void)rmpath(path);
    return NQEIO;
  }
  return NQOK;
}

int ncwr(const char *path, const uint8_t *b, size_t len, int force,
         int sec) {
  FILE *f = ncopen(path, force, sec);
  if (f == NULL)
    return NQEIO;
  return ncclose(f, path, fwrite(b, 1, len, f) != len);
}

int ncwfail(const char *cmd, const char *path, int force) {
  if (!force && ncexist(path))
    ncmsg(cmd, "%s exists (use --force to replace it)", path);
  else
    ncmsg(cmd, "cannot write %s", path);
  return NCUSE;
}

/* ---- folders under a folder (noqtis seal -r, check -r) ---- */

static int addf(char ***v, size_t *n, size_t *cap, const char *p) {
  if (*n == *cap) {
    size_t nc = *cap ? *cap * 2 : 64, i;
    char **nv;
    if (nc > NCWALKMAX * 2)
      return NCUSE;
    nv = (char **)malloc(nc * sizeof *nv);
    if (nv == NULL)
      return NCUSE;
    for (i = 0; i < *n; i++)
      nv[i] = (*v)[i];
    free(*v);
    *v = nv;
    *cap = nc;
  }
  if (((*v)[*n] = (char *)malloc(strlen(p) + 1)) == NULL)
    return NCUSE;
  strcpy((*v)[(*n)++], p);
  return NCOK;
}

#ifdef _WIN32
/* the folders inside dir (one level), not reparse points, appended to v */
static int subdirs(const char *dir, char ***v, size_t *n, size_t *cap) {
  char pat[4200];
  wchar_t *w;
  WIN32_FIND_DATAW fd;
  HANDLE h;
  int rc = NCOK;
  snprintf(pat, sizeof pat, "%s/*", dir);
  if ((w = wide(pat)) == NULL)
    return NCUSE;
  h = FindFirstFileW(w, &fd);
  free(w);
  if (h == INVALID_HANDLE_VALUE)
    return NCOK;
  do {
    char nm[1024], p[4200];
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nm, sizeof nm,
                            NULL, NULL) <= 0)
      continue;
    snprintf(p, sizeof p, "%s/%s", dir, nm);
    rc = addf(v, n, cap, p);
  } while (rc == NCOK && FindNextFileW(h, &fd));
  FindClose(h);
  return rc;
}
#endif

static int bydepth(const void *a, const void *b) {
  const char *x = *(const char *const *)a, *y = *(const char *const *)b;
  size_t dx = 0, dy = 0;
  for (; *x; x++)
    dx += *x == '/';
  for (; *y; y++)
    dy += *y == '/';
  if (dx != dy)
    return dx < dy ? 1 : -1;
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}

#ifndef _WIN32
/* one open folder of the walk: its descriptor, a DIR on a dup of it (a
 * descriptor fdopendir takes over is not to be used again), and the
 * length of its path */
typedef struct {
  int fd;
  DIR *d;
  size_t plen;
} ncwlv;

static int wpush(ncwlv *l, int fd, size_t plen) {
  int dd = dup(fd);
  l->fd = fd;
  l->plen = plen;
  l->d = dd < 0 ? NULL : fdopendir(dd);
  if (l->d == NULL) {
    if (dd >= 0)
      close(dd);
    close(fd);
    return NCUSE;
  }
  return NCOK;
}
#endif

int ncwalk(const char *dir, char ***out, size_t *n) {
  char **v = NULL;
  size_t nv = 0, cap = 0, i;
  int rc;
#ifdef _WIN32
  rc = addf(&v, &nv, &cap, dir);
  /* breadth first over a list that grows: no recursion */
  for (i = 0; rc == NCOK && i < nv; i++) {
    const char *p;
    size_t dep = 0;
    for (p = v[i] + strlen(dir); *p; p++)
      dep += *p == '/';
    if (dep < 64)
      rc = subdirs(v[i], &v, &nv, &cap);
    if (nv > NCWALKMAX)
      rc = NCUSE;
  }
#else
  /* by descriptor, depth first over an explicit stack of at most 64
   * open folders (two descriptors each): every folder is reached with
   * openat(O_DIRECTORY | O_NOFOLLOW) from the one above it, never by its
   * path, so a folder swapped for a link is not followed, here or one
   * level down */
  ncwlv st[64];
  int top = 0, fd;
  char path[4200];
  if (strlen(dir) >= sizeof path)
    return NCUSE;
  strcpy(path, dir);
  fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || wpush(&st[0], fd, strlen(path)) != NCOK)
    return NCUSE;
  rc = addf(&v, &nv, &cap, path);
  while (top >= 0) {
    struct dirent *e;
    struct stat sb;
    size_t l;
    int nfd;
    if (rc != NCOK || (e = readdir(st[top].d)) == NULL) {
      closedir(st[top].d);
      close(st[top].fd);
      if (--top >= 0)
        path[st[top].plen] = '\0';
      continue;
    }
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    if (fstatat(st[top].fd, e->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(sb.st_mode))
      continue;
    l = st[top].plen;
    if (l + 1 + strlen(e->d_name) >= sizeof path)
      continue;
    nfd = openat(st[top].fd, e->d_name,
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (nfd < 0)
      continue; /* a link now, or gone: not listed */
    path[l] = '/';
    strcpy(path + l + 1, e->d_name);
    rc = addf(&v, &nv, &cap, path);
    if (rc == NCOK && nv > NCWALKMAX)
      rc = NCUSE;
    if (rc != NCOK || top + 1 >= 64) {
      /* listed, not descended: 64 levels at most */
      close(nfd);
      path[l] = '\0';
      continue;
    }
    if (wpush(&st[top + 1], nfd, strlen(path)) != NCOK) {
      rc = NCUSE;
      path[l] = '\0';
      continue;
    }
    top++;
  }
#endif
  if (rc != NCOK) {
    for (i = 0; i < nv; i++)
      free(v[i]);
    free(v);
    return NCUSE;
  }
  qsort(v, nv, sizeof *v, bydepth);
  *out = v;
  *n = nv;
  return NCOK;
}

#ifndef _WIN32
static int ncenterfd(const char *top, const char *path) {
  const char *r = path + strlen(top);
  int fd = open(top, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (strncmp(path, top, strlen(top)) != 0 || (*r != '\0' && *r != '/')) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  while (fd >= 0 && *r) {
    char nm[1024];
    size_t k;
    int nfd;
    while (*r == '/')
      r++;
    for (k = 0; r[k] && r[k] != '/'; k++)
      ;
    if (k == 0)
      break;
    if (k >= sizeof nm) {
      close(fd);
      return -1;
    }
    memcpy(nm, r, k);
    nm[k] = '\0';
    r += k;
    nfd = openat(fd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    fd = nfd;
  }
  return fd;
}
#endif

const char *ncenter(const char *top, const char *path) {
#ifdef _WIN32
  (void)top;
  return path;
#else
  int fd = ncenterfd(top, path), rc;
  if (fd < 0)
    return NULL;
  rc = fchdir(fd);
  close(fd);
  return rc == 0 ? "." : NULL;
#endif
}

int nchome(void) {
#ifdef _WIN32
  return 0;
#else
  return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
}

void ncunhome(int fd) {
#ifdef _WIN32
  (void)fd;
#else
  if (fd >= 0)
    close(fd);
#endif
}

int ncback(int fd) {
#ifdef _WIN32
  (void)fd;
  return NCOK;
#else
  int rc = fd >= 0 ? fchdir(fd) : -1;
  return rc == 0 ? NCOK : NCUSE;
#endif
}

char *ncabs(const char *p) {
  char *o;
#ifndef _WIN32
  char cwd[4096];
  if (p[0] != '/' && strstr(p, "://") == NULL &&
      getcwd(cwd, sizeof cwd) != NULL) {
    o = (char *)malloc(strlen(cwd) + strlen(p) + 2);
    if (o != NULL)
      sprintf(o, "%s/%s", cwd, p);
    return o;
  }
#endif
  o = (char *)malloc(strlen(p) + 1);
  if (o != NULL)
    strcpy(o, p);
  return o;
}

#ifdef NQTEST
/* a test hook for -r (tests/nqd/cli.sh): when path is the folder
 * NQTESTSWAP names, it is renamed and a link to NQTESTSWAPTO put in its
 * place, between the walk and the run on it, without timing */
void nctswap(const char *path) {
#ifndef _WIN32
  const char *s = getenv("NQTESTSWAP"), *t = getenv("NQTESTSWAPTO");
  char was[4200];
  if (s == NULL || t == NULL || strcmp(s, path) != 0)
    return;
  snprintf(was, sizeof was, "%s.was", path);
  if (rename(path, was) != 0 || symlink(t, path) != 0)
    fprintf(stderr, "nctswap: %s: %s\n", path, strerror(errno));
#else
  (void)path;
#endif
}
#endif
