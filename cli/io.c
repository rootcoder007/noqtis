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

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
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
