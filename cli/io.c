/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: files. UTF-8 paths everywhere, owner-only secret files, and no
 * overwrite unless asked. Platform-specific, as net.c is. */
#ifndef _WIN32
#if defined(__linux__)
#define _GNU_SOURCE /* syscall(), for a rename that never replaces */
#endif
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
#include <signal.h>
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
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
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

int64_t ncnow(void) {
  const char *e = getenv("SOURCE_DATE_EPOCH");
  int64_t v = 0;
  size_t i;
  if (e == NULL || e[0] == '\0')
    return (int64_t)time(NULL);
  /* the rule the library's seal applies, so every command takes or
   * refuses the same values: digits only, at most the end of 9999 */
  for (i = 0; e[i] != '\0'; i++) {
    if (e[i] < '0' || e[i] > '9' || i >= 12)
      return -1;
    v = v * 10 + (e[i] - '0');
  }
  return v <= 253402300799LL ? v : -1;
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

/* ---- outputs under a temporary name ----
 *
 * A file the tool writes (ncopen, ncwr) is written to a new temporary
 * name in the same folder, ".noqtis.<16 hex digits>.tmp" (short, so a
 * long file name never makes it too long for the file system), created
 * with O_EXCL and O_NOFOLLOW, so never through a link; ncclose gives it
 * its name only once it is whole, so an output cut short by a failure
 * or a signal never stands under the name asked for. A command with
 * more than one output keeps each whole one under its temporary name
 * (nckeep) and names them all at once (ncput), so a failure on the last
 * leaves none of them. A file the library writes, or a folder the tool
 * fills, gets its temporary name the same way (nctmpf, nctmpd).
 *
 * The paths in pnd are removed on SIGINT, SIGTERM, SIGHUP and SIGXFSZ
 * (and, for an output of this file's own, at exit) before the process
 * ends; a signal the process ignored when the first was armed stays
 * ignored. A file is removed through a descriptor of the folder it was
 * made in (unlinkat), so a folder renamed or replaced while the command
 * runs does not keep it. While a folder is filled (nctmpd), whose tree
 * a signal handler cannot remove safely, a signal is held: the command
 * stops at its next step (ncstop), removes the folder, and then ends as
 * the signal would have ended it. Only SIGKILL or a power cut can leave
 * a temporary name behind (and on Windows a signal, as an open file
 * cannot be removed there, and a folder renamed while the command runs,
 * which has no unlinkat). */
/* FreeBSD, OpenBSD and DragonFly show SIGXFSZ only to XSI or BSD code,
 * not under the plain POSIX this file asks for; its number is 25 on
 * each of them */
#if !defined(SIGXFSZ) && (defined(__FreeBSD__) || defined(__OpenBSD__) || \
                          defined(__DragonFly__))
#define SIGXFSZ 25
#endif
#define NCPEND 8
static char pnd[NCPEND][4200];
static volatile sig_atomic_t pon[NCPEND];
static FILE *pfh[NCPEND];      /* the output written to pnd[i], or NULL */
static int pfrc[NCPEND];       /* its force */
static char pfin[NCPEND][4200]; /* the name it gets */
static int pown[NCPEND]; /* made here (not ncpend alone): removed at exit */
static int pisd[NCPEND]; /* a folder (nctmpd) */
#ifndef _WIN32
static int pdfd[NCPEND]; /* the folder it is in, open; -1: by its path */
static size_t pbs[NCPEND]; /* where its last component starts in pnd */
#endif
static int npon = 0, pexit = 0;
static volatile sig_atomic_t pheld = 0, pgot = 0;
static const int psig[] = {SIGINT, SIGTERM
#ifdef SIGHUP
                           , SIGHUP
#endif
#ifdef SIGXFSZ
                           , SIGXFSZ /* a write over ulimit -f */
#endif
};
#define NPSIG (sizeof psig / sizeof psig[0])
static void (*pold[NPSIG])(int);

static int addf(char ***v, size_t *n, size_t *cap, const char *p);

/* removes the file of slot i; async-signal-safe on POSIX */
static void rmone(int i) {
#ifdef _WIN32
  (void)rmpath(pnd[i]);
#else
  if (pdfd[i] >= 0)
    (void)unlinkat(pdfd[i], pnd[i] + pbs[i], 0);
  else
    (void)unlink(pnd[i]);
#endif
}

/* removes the folder p (cap bytes of room, used to build the paths
 * below it and restored) and everything in it; a link in it is removed,
 * never followed. The names of a folder are read before any is removed,
 * so one descriptor is open at a time, however deep the tree. */
static void rmtree(char *p, size_t cap) {
  char **nm = NULL;
  size_t n = 0, c = 0, i, l = strlen(p);
#ifdef _WIN32
  char pat[4200];
  wchar_t *w = wide(p);
  WIN32_FIND_DATAW fd;
  HANDLE h;
  DWORD a = w != NULL ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
  if (a == INVALID_FILE_ATTRIBUTES) {
    free(w);
    return;
  }
  if (!(a & FILE_ATTRIBUTE_DIRECTORY) || (a & FILE_ATTRIBUTE_REPARSE_POINT)) {
    /* a file, or a junction or link itself, not what it leads to */
    if (a & FILE_ATTRIBUTE_DIRECTORY)
      (void)_wrmdir(w);
    else
      (void)_wunlink(w);
    free(w);
    return;
  }
  free(w);
  snprintf(pat, sizeof pat, "%s/*", p);
  w = wide(pat);
  h = w != NULL ? FindFirstFileW(w, &fd) : INVALID_HANDLE_VALUE;
  free(w);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      char u[1024];
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        continue;
      if (WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, u, sizeof u, NULL,
                              NULL) <= 0 ||
          addf(&nm, &n, &c, u) != NCOK)
        break;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
#else
  struct dirent *e;
  DIR *d = NULL;
  /* p is opened as a folder, without following a link: what it is is
   * learnt from the descriptor read below, not from a look at the name
   * that a change of the name could outdate */
  int fd = open(p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    int isf = errno == ENOTDIR || errno == ELOOP || errno == EMLINK;
#ifdef EFTYPE
    isf = isf || errno == EFTYPE;
#endif
    if (isf) {
      (void)unlink(p);
      return;
    }
    if (errno == ENOENT)
      return;
  } else if ((d = fdopendir(fd)) == NULL) {
    (void)close(fd);
  }
  if (d != NULL) {
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
        continue;
      if (addf(&nm, &n, &c, e->d_name) != NCOK)
        break;
    }
    closedir(d);
  }
#endif
  for (i = 0; i < n; i++) {
    if (l + 1 + strlen(nm[i]) < cap) {
      p[l] = '/';
      strcpy(p + l + 1, nm[i]);
      rmtree(p, cap);
      p[l] = '\0';
    }
    free(nm[i]);
  }
  free(nm);
  (void)ncrmdir(p);
}

static void onpend(int s) {
  int i;
  if (pheld) {
    /* a folder is being filled: the command removes it and then ends
     * (ncdone); a write over ulimit -f fails meanwhile */
    if (!pgot)
      pgot = s;
    signal(s, onpend);
    return;
  }
  for (i = 0; i < NCPEND; i++)
    if (pon[i] && !pisd[i]) {
#ifdef _WIN32
      remove(pnd[i]);
#else
      rmone(i);
#endif
    }
  signal(s, SIG_DFL);
  raise(s);
}

static void atpend(void) {
  int i;
  for (i = 0; i < NCPEND; i++) {
    if (!pon[i] || !pown[i])
      continue;
    if (pisd[i])
      rmtree(pnd[i], sizeof pnd[i]);
    else
      rmone(i);
  }
}

/* signals held back while a slot is filled in, so the handler never
 * sees one half made */
#ifndef _WIN32
static int hold(sigset_t *os) {
  sigset_t bs;
  size_t k;
  sigemptyset(&bs);
  for (k = 0; k < NPSIG; k++)
    sigaddset(&bs, psig[k]);
  return sigprocmask(SIG_BLOCK, &bs, os) == 0;
}
#define HOLD sigset_t os_; int held_ = hold(&os_)
#define UNHOLD                                                               \
  do {                                                                       \
    if (held_)                                                               \
      (void)sigprocmask(SIG_SETMASK, &os_, NULL);                            \
  } while (0)
#else
#define HOLD int held_ = 0
#define UNHOLD (void)held_
#endif

int ncpend(const char *path) {
  size_t k;
  int i;
  if (strlen(path) >= sizeof pnd[0])
    return -1;
  for (i = 0; i < NCPEND && pon[i]; i++)
    ;
  if (i == NCPEND)
    return -1;
  /* the length was checked above */
  snprintf(pnd[i], sizeof pnd[i], "%s", path);
  pfh[i] = NULL;
  pown[i] = 0;
  pisd[i] = 0;
#ifndef _WIN32
  pdfd[i] = -1;
  pbs[i] = 0;
#endif
  if (npon++ == 0) {
    for (k = 0; k < NPSIG; k++) {
      pold[k] = signal(psig[k], onpend);
      if (pold[k] == SIG_IGN)
        signal(psig[k], SIG_IGN);
    }
  }
  pon[i] = 1;
  return i;
}

void ncunpend(int i) {
  size_t k;
  if (i < 0 || i >= NCPEND || !pon[i])
    return;
  pon[i] = 0;
  pfh[i] = NULL;
#ifndef _WIN32
  if (pdfd[i] >= 0)
    close(pdfd[i]);
  pdfd[i] = -1;
#endif
  if (--npon == 0) {
    for (k = 0; k < NPSIG; k++)
      signal(psig[k], pold[k] == SIG_ERR ? SIG_DFL : pold[k]);
  }
}

int ncpendown(const char *dir, const char *name) {
  char p[4200];
  unsigned long pid;
  int n;
#ifdef _WIN32
  pid = (unsigned long)GetCurrentProcessId();
#else
  pid = (unsigned long)getpid();
#endif
  n = snprintf(p, sizeof p, "%s/.%s.%lu.0.tmp", dir, name, pid);
  return n > 0 && (size_t)n < sizeof p ? ncpend(p) : -1;
}

void ncpendseal(const char *dir, int sl[2]) {
  sl[0] = ncpendown(dir, "noqtis.json");
  sl[1] = ncpendown(dir, "noqtis.sig");
}

int ncpendrec(const char *dir) {
  char p[4200];
  unsigned long pid;
  int n;
#ifdef _WIN32
  pid = (unsigned long)GetCurrentProcessId();
#else
  pid = (unsigned long)getpid();
#endif
  /* the first name nqd writes a record through (qdwriteat, nqd/fs.c) */
  n = snprintf(p, sizeof p, "%s/.noqtis.%08lx00000000.tmp", dir,
               pid & 0xffffffffUL);
  return n > 0 && (size_t)n < sizeof p ? ncpend(p) : -1;
}

/* the temporary name of path into t: ".noqtis.<16 hex>.tmp" beside it */
static int tmpnm(const char *path, char *t, size_t cap) {
  const char *b = strrchr(path, '/');
  uint8_t rb[8];
  char hx[17];
  int n;
#ifdef _WIN32
  const char *b2 = strrchr(path, '\\');
  if (b2 != NULL && (b == NULL || b2 > b))
    b = b2;
#endif
  b = b != NULL ? b + 1 : path;
  if (*b == '\0' || nqrand(rb, sizeof rb) != NQOK)
    return NCUSE;
  /* written out here, not with nchexe(): this file is also built on its
   * own into a test program that has no b64.c */
  for (n = 0; n < (int)sizeof rb; n++) {
    hx[2 * n] = "0123456789abcdef"[rb[n] >> 4];
    hx[2 * n + 1] = "0123456789abcdef"[rb[n] & 15];
  }
  hx[16] = '\0';
  n = snprintf(t, cap, "%.*s.noqtis.%s.tmp", (int)(b - path), path, hx);
  return n < 0 || (size_t)n >= cap ? NCUSE : NCOK;
}

#ifndef _WIN32
/* the folder of path, opened, and where path's last component starts */
static int dirof(const char *path, size_t *bs) {
  const char *b = strrchr(path, '/');
  char d[4200];
  size_t n;
  *bs = 0;
  if (b == NULL)
    return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  n = (size_t)(b - path);
  *bs = n + 1;
  if (n >= sizeof d)
    return -1;
  memcpy(d, path, n);
  d[n] = '\0';
  return open(n == 0 ? "/" : d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

/* The folder the first rl bytes of r name under the open folder fd
 * (taken over), reached one component at a time by openat with
 * O_DIRECTORY | O_NOFOLLOW, so no link on the way is ever followed, as
 * the walk of a folder to seal reaches its folders; with mk a component
 * that is not there is made (owner-only, as ncmkdir). The descriptor,
 * or -1 when a component is a link, not a folder, or cannot be made. */
static int ncdirat(int fd, const char *r, size_t rl, int mk) {
  const char *e = r + rl;
  while (fd >= 0 && r < e) {
    char nm[1024];
    size_t k;
    int nfd;
    while (r < e && *r == '/')
      r++;
    for (k = 0; r + k < e && r[k] != '/'; k++)
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
    if (nfd < 0 && mk && errno == ENOENT && mkdirat(fd, nm, 0700) == 0)
      nfd = openat(fd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    fd = nfd;
  }
  return fd;
}
#endif

#ifndef _WIN32
/* gives t the name p only when nothing has that name. Where the kernel
 * has a rename that refuses to replace (Linux 3.15, macOS 10.12) it
 * decides, in one step; elsewhere, and on a file system without one,
 * the name is looked at first and a name made in between is replaced. */
static int mvnew(int d, const char *t, const char *p) {
  struct stat st;
#if defined(__linux__) && defined(SYS_renameat2)
  /* 1 is RENAME_NOREPLACE */
  if (syscall(SYS_renameat2, d, t, d, p, 1u) == 0)
    return NCOK;
  if (errno != ENOSYS && errno != EINVAL && errno != EPERM)
    return NCUSE;
#elif defined(__APPLE__) && defined(RENAME_EXCL)
  if (renameatx_np(d, t, d, p, RENAME_EXCL) == 0)
    return NCOK;
  if (errno != ENOTSUP)
    return NCUSE;
#endif
  if (fstatat(d, p, &st, AT_SYMLINK_NOFOLLOW) == 0)
    return NCUSE;
  return renameat(d, t, d, p) == 0 ? NCOK : NCUSE;
}
#endif

/* gives the whole temporary file of slot i its name: over a file there
 * only with force, and never through a link at that name. It is named in
 * the folder it was made in, by descriptor where it has one, so a folder
 * on the way swapped for a link meanwhile does not take it elsewhere. */
static int place(int i) {
#ifdef _WIN32
  wchar_t *wt = wide(pnd[i]), *wp = wide(pfin[i]);
  int ok = wt != NULL && wp != NULL &&
           MoveFileExW(wt, wp, pfrc[i] ? MOVEFILE_REPLACE_EXISTING : 0);
  free(wt);
  free(wp);
  return ok ? NCOK : NCUSE;
#else
  int d = pdfd[i] >= 0 ? pdfd[i] : AT_FDCWD;
  const char *t = pdfd[i] >= 0 ? pnd[i] + pbs[i] : pnd[i];
  const char *p = pdfd[i] >= 0 ? pfin[i] + pbs[i] : pfin[i];
  if (pfrc[i])
    return renameat(d, t, d, p) == 0 ? NCOK : NCUSE;
  /* a hard link fails on a name that is there (even a link); a file
   * system without hard links gets a rename that does not replace */
  if (linkat(d, t, d, p, 0) == 0) {
    (void)unlinkat(d, t, 0);
    return NCOK;
  }
  if (errno == EEXIST)
    return NCUSE;
  return mvnew(d, t, p);
#endif
}

/* gives the filled temporary folder t its name p, which must not be
 * there: a folder is never replaced (rename would take an empty one) */
static int placed(const char *t, const char *p) {
#ifdef _WIN32
  wchar_t *wt = wide(t), *wp = wide(p);
  int ok = wt != NULL && wp != NULL && MoveFileExW(wt, wp, 0);
  free(wt);
  free(wp);
  return ok ? NCOK : NCUSE;
#else
  return mvnew(AT_FDCWD, t, p);
#endif
}

/* a signal held while a folder was filled ends the process now, as it
 * would have: what is still pending is removed first */
static void ncdone(void) {
  int s = (int)pgot, i;
  if (pheld || !s)
    return;
  for (i = 0; i < NCPEND; i++)
    if (pon[i] && pown[i] && pisd[i])
      rmtree(pnd[i], sizeof pnd[i]);
    else if (pon[i] && pown[i])
      rmone(i);
  for (i = 0; i < NCPEND; i++)
    if (pon[i] && !pown[i])
      rmone(i);
  signal(s, SIG_DFL);
  raise(s);
}

/* removes what slot i holds and frees it */
static void drop(int i) {
  int d;
  if (i < 0 || i >= NCPEND || !pon[i])
    return;
  d = pisd[i];
  if (d)
    rmtree(pnd[i], sizeof pnd[i]);
  else
    rmone(i);
  ncunpend(i);
  if (d) {
    pheld--;
    ncdone();
  }
}

/* fills in slot i for the output path (force), whose temporary name it
 * holds; dfd/bs: its folder, as dirof gives */
static void own(int i, const char *path, int force, int dfd, size_t bs) {
  /* shorter than its temporary name, which fitted in the same size */
  snprintf(pfin[i], sizeof pfin[i], "%s", path);
  pfrc[i] = force;
  pown[i] = 1;
#ifndef _WIN32
  pbs[i] = bs;
  pdfd[i] = dfd;
#else
  (void)dfd;
  (void)bs;
#endif
  if (!pexit)
    pexit = atexit(atpend) == 0;
}

/* ncopen; dfd (taken over) is path's folder already opened, bs where
 * path's last component starts, or dfd -1 to open it by path here */
static FILE *openin(const char *path, int force, int sec, int dfd,
                    size_t bs) {
  char t[4200];
  int fd = -1, tries, i;
  FILE *f;
  /* refused at once, not after the output is written (with dfd, the
   * caller looked at the name in the folder) */
  if ((dfd < 0 && !force && ncexist(path)) || pgot) {
#ifndef _WIN32
    if (dfd >= 0)
      close(dfd);
#endif
    return NULL;
  }
  {
    /* The file is made and its name noted for removal with the signals
     * held back: one that arrived between the two would end the process
     * with the temporary file there and nothing to remove it. Held back,
     * it is delivered once the name is noted. */
    HOLD;
    for (tries = 0; tries < 4 && fd < 0; tries++) {
      if (tmpnm(path, t, sizeof t) != NCOK)
        break;
#ifdef _WIN32
      {
        wchar_t *p = wide(t);
        if (p == NULL)
          break;
        /* owner-only on Windows comes from the folder's ACL */
        fd = _wopen(p, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                    _S_IREAD | _S_IWRITE);
        free(p);
      }
#else
      /* made in the folder it is removed from, by descriptor */
      if (tries == 0 && dfd < 0)
        dfd = dirof(t, &bs);
      if (dfd >= 0)
        fd = openat(dfd, t + bs,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    sec ? (mode_t)0600 : (mode_t)0666);
      else
        fd = open(t, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  sec ? (mode_t)0600 : (mode_t)0666);
#endif
      if (fd < 0 && errno != EEXIST)
        break;
    }
    i = fd >= 0 ? ncpend(t) : -1;
    if (i >= 0) {
      own(i, path, force, dfd, bs);
      dfd = -1;
    }
    UNHOLD;
  }
#ifndef _WIN32
  if (dfd >= 0)
    close(dfd);
#endif
  if (fd < 0)
    return NULL;
  if (i < 0) {
#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif
    (void)rmpath(t);
    return NULL;
  }
#ifndef _WIN32
  /* the mode whatever the umask: a public key or signature 0644, never
   * group- or world-writable (a .pub is a trust anchor), a secret 0600 */
  if (fchmod(fd, sec ? (mode_t)0600 : (mode_t)0644) != 0) {
    close(fd);
    drop(i);
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
  if (f == NULL) {
    drop(i);
    return NULL;
  }
  if (sec)
    setvbuf(f, NULL, _IONBF, 0);
  pfh[i] = f;
  return f;
}

FILE *ncopen(const char *path, int force, int sec) {
  return openin(path, force, sec, -1, 0);
}

FILE *ncopenat(const char *dir, const char *rel, int force, int sec) {
  char p[4200];
  const char *s = rel, *e;
  int n = snprintf(p, sizeof p, "%s/%s", dir, rel);
  if (n < 0 || (size_t)n >= sizeof p)
    return NULL;
  /* never out of dir: no empty, "." or ".." component */
  for (;;) {
    size_t k;
    e = strchr(s, '/');
    k = e != NULL ? (size_t)(e - s) : strlen(s);
    if (k == 0 || (k == 1 && s[0] == '.') ||
        (k == 2 && s[0] == '.' && s[1] == '.'))
      return NULL;
    if (e == NULL)
      break;
    s = e + 1;
  }
#ifdef _WIN32
  {
    /* No openat here: each folder on the way is looked at, made when
     * missing, and refused when it is a reparse point (a link or a
     * junction); so is the file itself */
    size_t i;
    for (i = strlen(dir) + 1;; i++) {
      char c = p[i];
      wchar_t *w;
      DWORD a;
      if (c != '/' && c != '\0')
        continue;
      p[i] = '\0';
      w = wide(p);
      a = w != NULL ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
      if (a == INVALID_FILE_ATTRIBUTES && c == '/' && w != NULL &&
          _wmkdir(w) == 0)
        a = FILE_ATTRIBUTE_DIRECTORY;
      free(w);
      p[i] = c;
      if (c == '/' && (a == INVALID_FILE_ATTRIBUTES ||
                       (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                       (a & FILE_ATTRIBUTE_DIRECTORY) == 0))
        return NULL;
      if (c == '\0') {
        if (a != INVALID_FILE_ATTRIBUTES &&
            (!force || (a & (FILE_ATTRIBUTE_REPARSE_POINT |
                             FILE_ATTRIBUTE_DIRECTORY)) != 0))
          return NULL;
        return openin(p, force, sec, -1, 0);
      }
    }
  }
#else
  {
    struct stat st;
    size_t bs = (size_t)(strrchr(p, '/') - p) + 1;
    int fd = open(*dir ? dir : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    /* dir itself, the folder the caller named, may be a link; nothing
     * under it is followed */
    if (fd >= 0)
      fd = ncdirat(fd, rel, s - rel > 0 ? (size_t)(s - rel - 1) : 0, 1);
    if (fd < 0)
      return NULL;
    if (fstatat(fd, p + bs, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        (!force || !S_ISREG(st.st_mode))) {
      close(fd);
      return NULL;
    }
    return openin(p, force, sec, fd, bs);
  }
#endif
}

int ncwrat(const char *dir, const char *rel, const uint8_t *b, size_t len,
           int force, int sec) {
  char p[4200];
  FILE *f = ncopenat(dir, rel, force, sec);
  if (f == NULL)
    return NQEIO;
  snprintf(p, sizeof p, "%s/%s", dir, rel);
  return ncclose(f, p, fwrite(b, 1, len, f) != len);
}

int nckeep(FILE *f, int bad) {
  int i;
  for (i = 0; i < NCPEND && !(pon[i] && pfh[i] == f); i++)
    ;
  if (fflush(f) != 0 || ferror(f))
    bad = 1;
  if (fclose(f) != 0)
    bad = 1;
  if (i == NCPEND)
    return -1;
  pfh[i] = NULL;
  if (bad) {
    drop(i);
    return -1;
  }
  return i;
}

int ncput(const int *sl, int n) {
  int k, j;
  /* held back, no signal falls between two of the names: the outputs
   * are all there or none is */
  HOLD;
  for (k = 0; k < n; k++) {
    int i = sl[k];
    /* a folder filled while a signal waited is removed, not named */
    if (i < 0 || i >= NCPEND || !pon[i] || !pown[i] || (pisd[i] && pgot) ||
        (pisd[i] ? placed(pnd[i], pfin[i]) : place(i)) != NCOK)
      break;
  }
  for (j = 0; j < n; j++) {
    int i = sl[j];
    if (j >= k) {
      drop(i);
    } else {
      int d = pisd[i];
      ncunpend(i);
      if (d)
        pheld--;
    }
  }
  UNHOLD;
  ncdone();
  return k;
}

void ncdrop(int sl) {
  drop(sl);
}

int nctmpf(const char *path, int force, char *t, size_t cap) {
  int i, dfd = -1;
  size_t bs = 0;
  if ((!force && ncexist(path)) || pgot ||
      tmpnm(path, t, cap) != NCOK)
    return -1;
  {
    HOLD;
    i = ncpend(t);
#ifndef _WIN32
    if (i >= 0)
      dfd = dirof(t, &bs);
#endif
    if (i >= 0)
      own(i, path, force, dfd, bs);
    UNHOLD;
  }
  return i;
}

int nctmpd(const char *path, char *t, size_t cap) {
  int i;
  if (ncexist(path) || pgot ||
      tmpnm(path, t, cap) != NCOK)
    return -1;
  {
    HOLD;
    i = ncpend(t);
    if (i >= 0) {
      own(i, path, 0, -1, 0);
      pisd[i] = 1;
      pheld++;
    }
    UNHOLD;
  }
  return i;
}

int ncstop(void) {
  return pgot != 0;
}

int nctmpin(const char *path) {
  int i;
  if (pgot)
    return -1;
  {
    HOLD;
    i = ncpend(path);
    if (i >= 0) {
      own(i, path, 0, -1, 0);
      pisd[i] = 1;
      pheld++;
    }
    UNHOLD;
  }
  return i;
}

void ncbail(void) {
  /* outside the handler, where the folders can be removed */
  if (!pgot)
    return;
  pheld = 0;
  ncdone();
}

void ncpriv(int on) {
#ifndef _WIN32
  static mode_t was;
  static int set = 0;
  if (on && !set)
    was = umask(077);
  else if (!on && set)
    (void)umask(was);
  set = on != 0;
#else
  /* the temporary folder is the user's own (%TEMP%, by its ACL) */
  (void)on;
#endif
}

int ncclose(FILE *f, const char *path, int bad) {
  int i;
  for (i = 0; i < NCPEND && !(pon[i] && pfh[i] == f); i++)
    ;
  if (i == NCPEND) { /* not from ncopen */
    if (fflush(f) != 0 || ferror(f))
      bad = 1;
    if (fclose(f) != 0)
      bad = 1;
    if (bad)
      (void)rmpath(path);
    return bad ? NQEIO : NQOK;
  }
  i = nckeep(f, bad);
  return i >= 0 && ncput(&i, 1) == 1 ? NQOK : NQEIO;
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
static int subdirs(const char *cmd, const char *dir, char ***v, size_t *n,
                   size_t *cap, size_t *nl) {
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
        wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nm, sizeof nm,
                            NULL, NULL) <= 0)
      continue;
    snprintf(p, sizeof p, "%s/%s", dir, nm);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      /* a link or junction to a folder: named and refused, never
       * followed */
      ncmsg(cmd, "-r: %s is a link to a folder: refused, not followed",
            ncesc(p));
      (*nl)++;
      continue;
    }
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

int ncwalk(const char *cmd, const char *dir, char ***out, size_t *n,
           size_t *nl) {
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
      rc = subdirs(cmd, v[i], &v, &nv, &cap, nl);
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
    if (fstatat(st[top].fd, e->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0)
      continue;
    if (S_ISLNK(sb.st_mode)) {
      /* a link to a folder: named and refused, never followed (only its
       * target's type is looked at) */
      if (fstatat(st[top].fd, e->d_name, &sb, 0) == 0 &&
          S_ISDIR(sb.st_mode)) {
        ncmsg(cmd, "-r: %s/%s is a link to a folder: refused, not "
              "followed", ncesc(path), ncesc(e->d_name));
        (*nl)++;
      }
      continue;
    }
    if (!S_ISDIR(sb.st_mode))
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
  int fd;
  if (strncmp(path, top, strlen(top)) != 0 || (*r != '\0' && *r != '/'))
    return -1;
  fd = open(top, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  return fd < 0 ? -1 : ncdirat(fd, r, strlen(r), 0);
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
