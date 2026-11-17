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
#include <limits.h>
#include <stdio.h>
#include <sys/resource.h>
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

/* why the last file helper here failed (errno), for ncwhy */
static int ncerr;

const char *ncwhy(void) {
  static char b[256];
  if (ncerr == 0)
    return "";
  snprintf(b, sizeof b, ": %s", strerror(ncerr));
  return b;
}

FILE *ncfopen(const char *path, const char *mode) {
#ifdef _WIN32
  wchar_t *p = wide(path), *m = wide(mode);
  FILE *f = NULL;
  if (p != NULL && m != NULL)
    f = _wfopen(p, m);
  ncerr = f == NULL ? (errno != 0 ? errno : EINVAL) : 0;
  free(p);
  free(m);
  return f;
#else
  FILE *f = fopen(path, mode);
  ncerr = f == NULL ? errno : 0;
  return f;
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
  ncerr = r ? 0 : errno;
  free(p);
  return r ? NCOK : NCUSE;
#else
  int r = mkdir(path, 0700) == 0;
  ncerr = r ? 0 : errno;
  return r ? NCOK : NCUSE;
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
  ncerr = 0; /* a reason left by an earlier call is not this one */
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
    ncerr = errno;
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
 * The paths in pnd are removed on a signal of psig (siglist: every
 * signal whose default action ends the process and that can be caught;
 * on Windows SIGINT and SIGTERM) and, for an output of this file's own,
 * at exit, before the process ends; a signal the process ignored or
 * handled itself when the first was armed is left as it was. A file
 * the library writes through a temporary name of its own is noted when
 * it is made (nctmpev), so the one removed is the one made, never a
 * file that had that name. A file is removed through a descriptor of the folder it was
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
#if !defined(SIGXCPU) && (defined(__FreeBSD__) || defined(__OpenBSD__) || \
                          defined(__DragonFly__))
#define SIGXCPU 24
#endif
#if !defined(SIGVTALRM) && (defined(__FreeBSD__) || defined(__OpenBSD__) || \
                            defined(__DragonFly__))
#define SIGVTALRM 26
#endif
#if !defined(SIGPROF) && (defined(__FreeBSD__) || defined(__OpenBSD__) || \
                          defined(__DragonFly__))
#define SIGPROF 27
#endif
#define NCPEND 8
static char pnd[NCPEND][4200];
static volatile sig_atomic_t pon[NCPEND];
static FILE *pfh[NCPEND];      /* the output written to pnd[i], or NULL */
static int pfrc[NCPEND];       /* its force */
static char pfin[NCPEND][4200]; /* the name it gets */
static int pown[NCPEND]; /* made here (not ncpend alone): removed at exit */
static int pisd[NCPEND]; /* a folder (nctmpd) */
static int ptmp[NCPEND]; /* a temporary file the library made (nctmpev) */
#ifdef _WIN32
/* a file an interrupt puts back as it was instead of removing it: its
 * bytes and their count (ncsnappend) */
static const uint8_t *volatile pbk[NCPEND];
static volatile size_t pbkn[NCPEND];
#else
static int pdfd[NCPEND]; /* the folder it is in, open; -1: by its path */
static size_t pbs[NCPEND]; /* where its last component starts in pnd */
/* The files an interrupt puts back as they were (ncsnappend, nctree):
 * each in the folder it was read from, through a descriptor of that
 * folder opened before the command changed anything, so a folder renamed
 * or replaced by a link since cannot take the write elsewhere. The
 * entries of one group (a seal's noqtis.json and noqtis.sig) come back
 * together or, said on standard error, not at all. The list changes only
 * with the signals held, and the handler is in place for as long as it
 * holds anything (sigs). */
typedef struct {
  int dfd;         /* the folder */
  int grp;         /* the group: entries next to each other */
  int mine;        /* 1: the list frees b and closes dfd (nctree), 2: b
                    * only, dfd being the one of the group's first entry */
  int had;         /* 0: there was no such file; the put-back removes it */
  int mode;        /* its permission bits, set-ID and sticky ones too */
  long gid;        /* its group */
  const uint8_t *b; /* its bytes */
  size_t n;
  int st;          /* in bkput: 1 written under tn, 2 to be removed */
  char nm[64];     /* its name in the folder */
  char tn[32];     /* .noqtis.<16 hex>.tmp: the put-back's own file */
  char *msg;       /* the group's first entry: said when it fails */
} bkent;
static bkent *bk;
static volatile sig_atomic_t nbk;
static size_t cbk;
static int ngrp, keepon;
#endif
static int npon = 0, pexit = 0, pinst = 0;
static volatile sig_atomic_t pheld = 0, pgot = 0;
/* The signals the handler takes: every one whose default action ends the
 * process and that a handler can take safely. Left out: SIGKILL and
 * SIGSTOP (no handler can take them), the stops SIGTSTP, SIGTTIN and
 * SIGTTOU (the process waits and goes on with SIGCONT; one that ends it
 * meanwhile acts once it goes on), the ones ignored by default (SIGCHLD,
 * SIGCONT, SIGURG, SIGWINCH, SIGIO outside Linux), and the faults
 * SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGSYS and SIGTRAP: raised by
 * a bug, a debugger or the kernel in the middle of any call, they leave
 * the list (or the heap) in a state no handler can trust, so they end
 * the process as SIGKILL does. noqtis-seal(1) lists them; keep the two
 * in step. */
#define NPSIGMAX 64
static int psig[NPSIGMAX];
static size_t npsig;
#ifdef _WIN32
static void (*pold[NPSIGMAX])(int);
#else
static struct sigaction pold[NPSIGMAX];
static int pmine[NPSIGMAX]; /* the handler was put in place for it */
static int phome = -1;      /* the folder the command started in, open */
#endif

static void addsig(int s) {
  size_t k;
  for (k = 0; k < npsig; k++)
    if (psig[k] == s)
      return;
  if (npsig < NPSIGMAX)
    psig[npsig++] = s;
}

/* fills psig, once */
static void siglist(void) {
  static const int fx[] = {SIGINT, SIGTERM
#ifndef _WIN32
                           , SIGHUP, SIGQUIT, SIGPIPE, SIGALRM, SIGUSR1,
                           SIGUSR2
#ifdef SIGXFSZ
                           , SIGXFSZ /* a write over ulimit -f */
#endif
#ifdef SIGXCPU
                           , SIGXCPU /* ulimit -t */
#endif
#ifdef SIGVTALRM
                           , SIGVTALRM
#endif
#ifdef SIGPROF
                           , SIGPROF
#endif
#ifdef SIGPOLL
                           , SIGPOLL /* SIGIO on Linux */
#endif
#ifdef SIGSTKFLT
                           , SIGSTKFLT
#endif
#ifdef SIGPWR
                           , SIGPWR
#endif
#endif
  };
  size_t k;
  if (npsig > 0)
    return;
  for (k = 0; k < sizeof fx / sizeof fx[0]; k++)
    addsig(fx[k]);
#if !defined(_WIN32) && defined(SIGRTMIN) && defined(SIGRTMAX)
  {
    /* the real-time signals end the process too */
    int s;
    for (s = SIGRTMIN; s <= SIGRTMAX; s++)
      addsig(s);
  }
#endif
}

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

#ifndef _WIN32
/* Whether entry e's file is, right now, the bytes it had; when it is, it
 * gets its group and mode back (a refused build may have rewritten it
 * with the same bytes). Like everything bkput calls, async-signal-safe. */
static int bksame(const bkent *e) {
  char buf[4096];
  struct stat st;
  size_t at = 0;
  ssize_t r;
  int same, fd = openat(e->dfd, e->nm,
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    return 0;
  same = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
         (uintmax_t)st.st_size == (uintmax_t)e->n;
  while (same && at < e->n) {
    r = read(fd, buf, sizeof buf);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0 || (size_t)r > e->n - at ||
        memcmp(buf, e->b + at, (size_t)r) != 0)
      same = 0;
    else
      at += (size_t)r;
  }
  if (same) {
    /* the group first: a change of group may clear the set-ID bits */
    if ((long)st.st_gid != e->gid &&
        fchown(fd, (uid_t)-1, (gid_t)e->gid) != 0) {
      /* a group this user may not give: the file keeps the one it has */
    }
    if ((int)(st.st_mode & 07777) != e->mode)
      (void)fchmod(fd, (mode_t)e->mode);
  }
  (void)close(fd);
  return same;
}

/* writes entry e's bytes, with its group (where the owner may give it)
 * and its mode, to a new file of the tool's temporary shape, made with
 * O_EXCL so no file of the user's is ever written: 0, or -1 with nothing
 * left behind */
static int bkwrite(bkent *e) {
  size_t o = 0;
  int fd = -1, k, ok;
  for (k = 0; k < 8 && fd < 0; k++) {
    fd = openat(e->dfd, e->tn,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno != EEXIST)
      return -1;
    /* the name is taken: the next of the same shape */
    if (fd < 0)
      e->tn[8 + k] = e->tn[8 + k] == '9'   ? 'a'
                     : e->tn[8 + k] == 'f' ? '0'
                                           : (char)(e->tn[8 + k] + 1);
  }
  if (fd < 0)
    return -1;
  while (o < e->n) {
    ssize_t w = write(fd, e->b + o, e->n - o);
    if (w < 0 && errno == EINTR)
      continue;
    if (w <= 0)
      break;
    o += (size_t)w;
  }
  if (fchown(fd, (uid_t)-1, (gid_t)e->gid) != 0) {
    /* a group this user may not give: the file keeps the one it has */
  }
  /* the mode after the group, whose change clears the set-ID bits */
  ok = o == e->n && fchmod(fd, (mode_t)e->mode) == 0;
  ok = close(fd) == 0 && ok;
  if (!ok)
    (void)unlinkat(e->dfd, e->tn, 0);
  return ok ? 0 : -1;
}

/* Puts the entries a to z - 1 (one group) back as they were. Each file
 * that is no longer what it was is first written whole under a name of
 * its own; only when all are written are they renamed over their names
 * (and a file there was none of removed), so the group comes back
 * together. When it cannot, nothing is renamed and, with say, the
 * group's message goes to standard error. 1 when the group is back. */
static int bkput(size_t a, size_t z, int say) {
  size_t k;
  int ok = 1;
  for (k = a; k < z; k++) {
    bkent *e = &bk[k];
    e->st = !e->had ? 2 : bksame(e) ? 0 : bkwrite(e) == 0 ? 1 : -1;
    if (e->st < 0)
      ok = 0;
  }
  for (k = a; k < z; k++) {
    bkent *e = &bk[k];
    if (e->st == 1 &&
        (!ok || renameat(e->dfd, e->tn, e->dfd, e->nm) != 0)) {
      ok = 0;
      (void)unlinkat(e->dfd, e->tn, 0);
    } else if (ok && e->st == 2 && unlinkat(e->dfd, e->nm, 0) != 0 &&
               errno != ENOENT) {
      ok = 0;
    }
  }
  if (!ok && say && bk[a].msg != NULL) {
    ssize_t w = write(2, bk[a].msg, strlen(bk[a].msg));
    (void)w;
  }
  return ok;
}

/* puts every group back, the last noted first: the group of a build is
 * noted before the one of the seal inside it, and wins */
static void bkall(int say) {
  size_t z = (size_t)nbk, a;
  while (z > 0) {
    for (a = z - 1; a > 0 && bk[a - 1].grp == bk[z - 1].grp; a--)
      ;
    (void)bkput(a, z, say);
    z = a;
  }
}

/* the entries of group g: a to z - 1 (a == z when there are none) */
static void bkfind(int g, size_t *a, size_t *z) {
  size_t k;
  for (k = 0; k < (size_t)nbk && bk[k].grp != g; k++)
    ;
  *a = k;
  while (k < (size_t)nbk && bk[k].grp == g)
    k++;
  *z = k;
}

#ifdef SIGXFSZ
/* SIGXFSZ ignored, so a put-back write over ulimit -f fails with EFBIG
 * and raises no second signal; was gets the disposition it had. Set
 * again after the writes, it also drops one that came while held. */
static void noxfsz(struct sigaction *was) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGXFSZ, &sa, was);
}
#endif

/* SIGPIPE ignored for the rest of the process, which is ending: the
 * message of a put-back that fails, written to a standard error that is
 * a closed pipe, fails with EPIPE instead of ending the process before
 * the other groups are back; one held meanwhile is dropped */
static void nopipe(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGPIPE, &sa, NULL);
}
#else
/* writes slot i's kept bytes over its file */
static void putback(int i) {
  FILE *f = fopen(pnd[i], "wb");
  if (f != NULL) {
    (void)fwrite(pbk[i], 1, pbkn[i], f);
    (void)fclose(f);
  }
}
#endif

/* ends the process by signal s, as it would have ended without the
 * handler (on return from it, or at once outside it) */
static void die(int s) {
#ifdef _WIN32
  signal(s, SIG_DFL);
#else
  struct sigaction sa;
  /* a core dump (SIGQUIT, SIGXCPU, SIGXFSZ) goes to the folder the
   * command started in, never into a capsule seal -r is in */
  if (phome >= 0 && fchdir(phome) != 0) {
    /* it stays where it is */
  }
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(s, &sa, NULL);
#endif
  raise(s);
}

static void onpend(int s) {
  int i, e = errno;
  if (pheld) {
    /* a folder is being filled: the command removes it and then ends
     * (ncdone); a write over ulimit -f fails meanwhile */
    if (!pgot)
      pgot = s;
#ifdef _WIN32
    signal(s, onpend);
#endif
    errno = e;
    return;
  }
#if !defined(_WIN32) && defined(SIGXFSZ)
  noxfsz(NULL);
#endif
#ifndef _WIN32
  nopipe();
#endif
  for (i = 0; i < NCPEND; i++)
    if (pon[i] && !pisd[i]) {
#ifdef _WIN32
      if (pbk[i] != NULL) {
        putback(i);
        continue;
      }
      remove(pnd[i]);
#else
      rmone(i);
#endif
    }
#ifndef _WIN32
  bkall(1);
#endif
  die(s);
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
  siglist();
  sigemptyset(&bs);
  for (k = 0; k < npsig; k++)
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

/* The handler is in place exactly while a slot is pending or a file is
 * kept to put back: sigs runs after one is noted, before the command
 * changes anything, and after one is let go, when nothing is left to
 * undo; the dispositions the process had come back then. A signal the
 * process ignored, or that has a handler of its own (a profiler's
 * SIGPROF), is left as it is. While the handler runs, the others of
 * these signals wait, so one put-back runs at a time. */
static void sigs(void) {
  size_t k;
  int want = npon > 0;
#ifndef _WIN32
  want = want || nbk > 0;
#endif
  if (want == pinst)
    return;
  siglist();
  for (k = 0; k < npsig; k++) {
#ifdef _WIN32
    if (want) {
      pold[k] = signal(psig[k], onpend);
      if (pold[k] == SIG_IGN)
        signal(psig[k], SIG_IGN);
    } else {
      signal(psig[k], pold[k] == SIG_ERR ? SIG_DFL : pold[k]);
    }
#else
    if (want) {
      struct sigaction sa;
      size_t j;
      memset(&pold[k], 0, sizeof pold[k]);
      pold[k].sa_handler = SIG_DFL;
      pmine[k] = 0;
      if (sigaction(psig[k], NULL, &pold[k]) != 0 ||
          (pold[k].sa_flags & SA_SIGINFO) || pold[k].sa_handler != SIG_DFL)
        continue;
      memset(&sa, 0, sizeof sa);
      sa.sa_handler = onpend;
      sigemptyset(&sa.sa_mask);
      for (j = 0; j < npsig; j++)
        sigaddset(&sa.sa_mask, psig[j]);
      sa.sa_flags = SA_RESTART;
      pmine[k] = sigaction(psig[k], &sa, NULL) == 0;
    } else if (pmine[k]) {
      (void)sigaction(psig[k], &pold[k], NULL);
      pmine[k] = 0;
    }
#endif
  }
  pinst = want;
}

int ncpend(const char *path) {
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
  ptmp[i] = 0;
#ifdef _WIN32
  pbk[i] = NULL;
#else
  pdfd[i] = -1;
  pbs[i] = 0;
#endif
  npon++;
  sigs();
  pon[i] = 1;
  return i;
}

void ncunpend(int i) {
  if (i < 0 || i >= NCPEND || !pon[i])
    return;
  pon[i] = 0;
  pfh[i] = NULL;
#ifdef _WIN32
  pbk[i] = NULL;
#else
  if (pdfd[i] >= 0)
    close(pdfd[i]);
  pdfd[i] = -1;
#endif
  npon--;
  sigs();
}

/* Told by the library of each temporary file it writes a file through
 * (nqsettmp, nqdsettmp): with the signals held from just before the
 * attempt to make it until its name is noted, a signal either finds the
 * file not yet made or noted for removal, and a name that was taken
 * (the attempt failed) is never noted. Once the file is renamed into
 * place or removed, its name is let go. */
#ifndef _WIN32
static sigset_t tmask;
static int tblk;
#endif

void nctmpev(int ev, const char *path, void *user) {
  int i;
  (void)user;
  if (ev == NQTPRE) {
#ifndef _WIN32
    tblk = hold(&tmask);
#endif
    return;
  }
  if (ev == NQTNEW) {
    if ((i = ncpend(path)) >= 0)
      ptmp[i] = 1;
  } else if (ev == NQTEND) {
    for (i = 0; i < NCPEND; i++)
      if (pon[i] && ptmp[i] && strcmp(pnd[i], path) == 0) {
        ncunpend(i);
        break;
      }
    return;
  }
#ifndef _WIN32
  if (tblk)
    (void)sigprocmask(SIG_SETMASK, &tmask, NULL);
  tblk = 0;
#endif
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
  {
    /* held back, no other signal breaks into the put-back; the one
     * raised at the end ends the process once they are let through */
    HOLD;
#if !defined(_WIN32) && defined(SIGXFSZ)
    noxfsz(NULL);
#endif
#ifndef _WIN32
    nopipe();
#endif
    for (i = 0; i < NCPEND; i++)
      if (pon[i] && pown[i] && pisd[i])
        rmtree(pnd[i], sizeof pnd[i]);
      else if (pon[i] && pown[i])
        rmone(i);
    for (i = 0; i < NCPEND; i++)
      if (pon[i] && !pown[i])
        rmone(i);
#ifndef _WIN32
    bkall(1);
#endif
    die(s);
    UNHOLD;
  }
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
  ncerr = 0;
  if ((dfd < 0 && !force && ncexist(path)) || pgot) {
#ifndef _WIN32
    if (dfd >= 0)
      close(dfd);
#endif
    ncerr = pgot ? EINTR : EEXIST;
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
    if (fd < 0)
      ncerr = errno;
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
  ncerr = 0;
  for (i = 0; i < NCPEND && !(pon[i] && pfh[i] == f); i++)
    ;
  if (fflush(f) != 0 || ferror(f)) {
    ncerr = errno;
    bad = 1;
  }
  if (fclose(f) != 0) {
    ncerr = errno;
    bad = 1;
  }
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
        (pisd[i] ? placed(pnd[i], pfin[i]) : place(i)) != NCOK) {
      ncerr = errno;
      break;
    }
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
  ncerr = ncexist(path) ? EEXIST : pgot ? EINTR : 0;
  if (ncerr != 0 || tmpnm(path, t, cap) != NCOK)
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
    ncerr = 0;
    if (fflush(f) != 0 || ferror(f)) {
      ncerr = errno;
      bad = 1;
    }
    if (fclose(f) != 0) {
      ncerr = errno;
      bad = 1;
    }
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
    ncmsg(cmd, "cannot write %s%s", path, ncwhy());
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
  int dd = dup(fd), e;
  l->fd = fd;
  l->plen = plen;
  l->d = dd < 0 ? NULL : fdopendir(dd);
  if (l->d == NULL) {
    e = errno;
    if (dd >= 0)
      close(dd);
    close(fd);
    errno = e; /* why, for the caller */
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
    if (nv > NCWALKMAX) {
      errno = E2BIG;
      rc = NCUSE;
    }
  }
#else
  /* by descriptor, depth first over an explicit stack of at most 64
   * open folders (two descriptors each): every folder is reached with
   * openat(O_DIRECTORY | O_NOFOLLOW) from the one above it, never by its
   * path, so a folder swapped for a link is not followed, here or one
   * level down */
  /* A folder that cannot be opened or read for any reason but being gone
   * or a link now (no descriptor left, no permission, an I/O error)
   * stops the walk with that reason in errno: a capsule under it is
   * never skipped without a word. */
  ncwlv st[64];
  int top = 0, fd, werr = 0;
  char path[4200];
  if (strlen(dir) >= sizeof path) {
    errno = ENAMETOOLONG;
    return NCUSE;
  }
  strcpy(path, dir);
  fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || wpush(&st[0], fd, strlen(path)) != NCOK)
    return NCUSE;
  rc = addf(&v, &nv, &cap, path);
  if (rc != NCOK)
    werr = ENOMEM;
  while (top >= 0) {
    struct dirent *e = NULL;
    struct stat sb;
    size_t l;
    int nfd;
    if (rc == NCOK) {
      errno = 0;
      if ((e = readdir(st[top].d)) == NULL && errno != 0) {
        werr = errno;
        rc = NCUSE;
      }
    }
    if (rc != NCOK || e == NULL) {
      closedir(st[top].d);
      close(st[top].fd);
      if (--top >= 0)
        path[st[top].plen] = '\0';
      continue;
    }
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    if (fstatat(st[top].fd, e->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT) {
        werr = errno;
        rc = NCUSE;
      }
      continue;
    }
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
    if (nfd < 0) {
      /* a link now, or gone: not listed; anything else stops the walk */
      if (errno != ENOENT && errno != ELOOP && errno != ENOTDIR &&
          errno != EMLINK) {
        werr = errno;
        rc = NCUSE;
      }
      continue;
    }
    path[l] = '/';
    strcpy(path + l + 1, e->d_name);
    rc = addf(&v, &nv, &cap, path);
    if (rc != NCOK)
      werr = ENOMEM;
    if (rc == NCOK && nv > NCWALKMAX) {
      werr = E2BIG;
      rc = NCUSE;
    }
    if (rc != NCOK || top + 1 >= 64) {
      /* listed, not descended: 64 levels at most */
      close(nfd);
      path[l] = '\0';
      continue;
    }
    if (wpush(&st[top + 1], nfd, strlen(path)) != NCOK) {
      werr = errno;
      rc = NCUSE;
      path[l] = '\0';
      continue;
    }
    top++;
  }
  errno = werr;
#endif
  if (rc != NCOK) {
    int e = errno;
    for (i = 0; i < nv; i++)
      free(v[i]);
    free(v);
    errno = e;
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
  /* also where a signal's core dump goes (die) */
  phome = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  return phome;
#endif
}

void ncunhome(int fd) {
#ifdef _WIN32
  (void)fd;
#else
  if (fd >= 0 && fd == phome)
    phome = -1;
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
/* renames path to path.was and puts a link to t in its place */
static void swapto(const char *path, const char *t) {
#ifndef _WIN32
  char was[4200];
  snprintf(was, sizeof was, "%s.was", path);
  if (rename(path, was) != 0 || symlink(t, path) != 0)
    fprintf(stderr, "nctswap: %s: %s\n", path, strerror(errno));
#else
  (void)path;
  (void)t;
#endif
}

/* a test hook for -r (tests/nqd/cli.sh): when path is the folder
 * NQTESTSWAP names, it is renamed and a link to NQTESTSWAPTO put in its
 * place, between the walk and the run on it, without timing */
void nctswap(const char *path) {
  const char *s = getenv("NQTESTSWAP"), *t = getenv("NQTESTSWAPTO");
  if (s != NULL && t != NULL && strcmp(s, path) == 0)
    swapto(path, t);
}

/* a test hook for interrupts (tests/nqd/cli.sh): NQTESTKILL=<at>:<n>
 * sends the process SIGTERM, or the signal numbered NQTESTSIG, the n-th
 * time it reaches the point at ("sealed": a seal just written;
 * "between": seal -r between two capsules), after NQTESTKILLMV, when
 * set, is swapped for a link to NQTESTSWAPTO */
void nctkill(const char *at) {
  static int seen;
  const char *v = getenv("NQTESTKILL"), *m = getenv("NQTESTKILLMV"),
             *t = getenv("NQTESTSWAPTO"), *s = getenv("NQTESTSIG");
  size_t l = strlen(at);
  if (v == NULL || strncmp(v, at, l) != 0 || v[l] != ':' ||
      ++seen != atoi(v + l + 1))
    return;
  if (m != NULL && t != NULL)
    swapto(m, t);
  raise(s != NULL && atoi(s) > 0 ? atoi(s) : SIGTERM);
}

/* NQTESTFAIL=<at>:<n>: 1 the n-th time the point at is reached ("snap":
 * ncsnapget, which then fails as with no descriptor left, EMFILE) */
int nctfail(const char *at) {
  static int seen;
  const char *v = getenv("NQTESTFAIL");
  size_t l = strlen(at);
  return v != NULL && strncmp(v, at, l) == 0 && v[l] == ':' &&
         ++seen == atoi(v + l + 1);
}
#endif

#ifndef _WIN32
/* reads all of fd, a plain file of about hint bytes, up to max bytes,
 * into a new buffer */
static int rdall(int fd, size_t hint, size_t max, uint8_t **out,
                 size_t *len) {
  uint8_t *b = NULL;
  size_t n = 0, cap = hint < max ? hint + 1 : max + 1;
  for (;;) {
    ssize_t r;
    if (n == cap) {
      uint8_t *g;
      if (n > max || cap > (size_t)-1 / 2) {
        free(b);
        return NQELIM;
      }
      cap *= 2;
      if ((g = (uint8_t *)realloc(b, cap)) == NULL) {
        free(b);
        return NQEMEM;
      }
      b = g;
    } else if (b == NULL && (b = (uint8_t *)malloc(cap)) == NULL) {
      return NQEMEM;
    }
    r = read(fd, b + n, cap - n);
    if (r < 0 && errno == EINTR)
      continue;
    if (r < 0) {
      free(b);
      return NQEIO;
    }
    if (r == 0)
      break;
    n += (size_t)r;
  }
  if (n > max) {
    free(b);
    return NQELIM;
  }
  *out = b;
  *len = n;
  return NQOK;
}
#endif

int ncsnapsay(const char *cmd, const ncsnap *s, int rc) {
  int e = errno;
  if (rc == NCUSE)
    ncmsg(cmd, "%s is not a plain file that can be read (a link, a pipe, "
          "a folder): move it out of the way and run the command again",
          s->p);
  else if (e == EMFILE || e == ENFILE)
    ncmsg(cmd, "cannot read %s: %s: raise the open-file limit (ulimit -n) "
          "and run the command again; nothing was changed", s->p,
          strerror(e));
  else
    ncmsg(cmd, "cannot read %s: %s", s->p, strerror(e));
  return NCUSE;
}

int ncsnapget(ncsnap *s, const char *dir, const char *name) {
  struct stat st;
#ifndef _WIN32
  int fd, rc;
#endif
  s->b = NULL;
  s->n = 0;
  s->had = 0;
  s->mode = 0644;
  s->gid = -1;
  s->dfd = -1;
  s->sl = -1;
  if (snprintf(s->p, sizeof s->p, "%s/%s", dir, name) >= (int)sizeof s->p) {
    errno = ENAMETOOLONG;
    return NCBAD;
  }
#ifdef _WIN32
  if (stat(s->p, &st) != 0) {
    if (errno == ENOENT)
      return NCOK;
    return NCBAD;
  }
  if ((st.st_mode & S_IFMT) != S_IFREG)
    return NCUSE;
  s->mode = (int)(st.st_mode & 07777);
  if (ncrdx(s->p, 0, NCRDMAX, &s->b, &s->n) != NQOK) {
    errno = EIO;
    return NCBAD;
  }
#else
  /* the folder is kept open: what an interrupt puts back goes to this
   * folder, whatever is renamed or linked in its place meanwhile */
  if (strlen(name) >= sizeof bk->nm) {
    errno = ENAMETOOLONG;
    return NCBAD;
  }
#ifdef NQTEST
  if (nctfail("snap")) {
    errno = EMFILE;
    return NCBAD;
  }
#endif
  if ((s->dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
    snprintf(s->p, sizeof s->p, "%s", dir);
    return NCBAD;
  }
  /* the name itself, not what a link leads to: a link, a pipe or a folder
   * is no file to keep (a pipe would be read for ever) */
  fd = openat(s->dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    int e = errno, odd = e == ELOOP || e == EMLINK || e == ENXIO;
#ifdef EFTYPE
    odd = odd || e == EFTYPE;
#endif
    if (e == ENOENT)
      return NCOK;
    close(s->dfd);
    s->dfd = -1;
    /* a link (ELOOP; EMLINK, EFTYPE on BSD) or a socket (ENXIO) is not
     * a plain file; anything else (no descriptor left, no permission,
     * an I/O error) is said as it is */
    errno = e;
    return odd ? NCUSE : NCBAD;
  }
  rc = fstat(fd, &st) == 0 ? NCOK : NCBAD;
  if (rc == NCOK && !S_ISREG(st.st_mode))
    rc = NCUSE;
  if (rc == NCOK) {
    s->mode = (int)(st.st_mode & 07777);
    s->gid = (long)st.st_gid;
    switch (rdall(fd, (size_t)st.st_size, NCRDMAX, &s->b, &s->n)) {
    case NQOK:
      break;
    case NQEMEM:
      errno = ENOMEM;
      rc = NCBAD;
      break;
    case NQELIM:
      errno = EFBIG;
      rc = NCBAD;
      break;
    default:
      rc = NCBAD; /* the read's errno */
      break;
    }
  }
  if (rc != NCOK) {
    int e = errno;
    close(fd);
    close(s->dfd);
    s->dfd = -1;
    errno = e;
    return rc;
  }
  close(fd);
#endif
  s->had = 1;
  return NCOK;
}

#ifdef _WIN32
/* whether the file of s is, right now, the bytes that were kept */
static int snapsame(const ncsnap *s) {
  uint8_t *b = NULL;
  size_t n = 0;
  int same;
  if (ncrdx(s->p, 0, NCRDMAX, &b, &n) != NQOK)
    return 0;
  same = n == s->n && (n == 0 || memcmp(b, s->b, n) == 0);
  ncfree(b, n, 0);
  return same;
}

int ncsnappend(ncsnap *s, int n, const char *who) {
  int k;
  (void)who;
  for (k = 0; k < n; k++) {
    HOLD;
    s[k].sl = ncpend(s[k].p);
    if (s[k].sl >= 0 && s[k].had) {
      pbkn[s[k].sl] = s[k].n;
      pbk[s[k].sl] = s[k].b != NULL ? s[k].b : (const uint8_t *)"";
    }
    UNHOLD;
    if (s[k].sl < 0) {
      while (k-- > 0) {
        ncunpend(s[k].sl);
        s[k].sl = -1;
      }
      return NCUSE;
    }
  }
  return NCOK;
}

int ncsnapput(ncsnap *s, int n) {
  int k, rc = NCOK;
  for (k = 0; k < n; k++) {
    /* a file the command never changed is not written again: in a folder
     * that may not be written the build was refused, and nothing is
     * wrong */
    if (s[k].had ? !snapsame(&s[k]) &&
                       ncwr(s[k].p, s[k].b, s[k].n, 1, 0) != NQOK
                 : ncexist(s[k].p) && remove(s[k].p) != 0)
      rc = NCUSE;
  }
  for (k = 0; k < n; k++)
    ncsnapfree(&s[k]);
  return rc;
}
#else
int ncsnappend(ncsnap *s, int n, const char *who) {
  char tn[4][32], *msg = NULL;
  int k, g;
  if (n <= 0 || n > 4)
    return NCUSE;
  for (k = 0; k < n; k++)
    if (s[k].dfd < 0 || tmpnm(strrchr(s[k].p, '/') + 1, tn[k],
                              sizeof tn[k]) != NCOK)
      return NCUSE;
  if (who != NULL) {
    size_t l = strlen(who) + 160;
    if ((msg = (char *)malloc(l)) == NULL)
      return NCUSE;
    snprintf(msg, l, "noqtis: %s: stopped, and %s could not be put back "
             "as %s: check it\n", who,
             n == 1 ? "its file" : "its files",
             n == 1 ? "it was" : "they were");
  }
  {
    HOLD;
    if ((size_t)nbk + (size_t)n > cbk) {
      bkent *e = (bkent *)realloc(bk, (cbk + (size_t)n + 16) * sizeof *e);
      if (e == NULL) {
        UNHOLD;
        free(msg);
        return NCUSE;
      }
      bk = e;
      cbk += (size_t)n + 16;
    }
    g = ++ngrp;
    for (k = 0; k < n; k++) {
      bkent *e = &bk[(size_t)nbk + (size_t)k];
      memset(e, 0, sizeof *e);
      e->dfd = s[k].dfd;
      e->grp = g;
      e->had = s[k].had;
      e->mode = s[k].mode;
      e->gid = s[k].gid;
      e->b = s[k].b;
      e->n = s[k].n;
      snprintf(e->nm, sizeof e->nm, "%s", strrchr(s[k].p, '/') + 1);
      memcpy(e->tn, tn[k], sizeof e->tn);
      e->msg = k == 0 ? msg : NULL;
      s[k].sl = g;
    }
    nbk = (sig_atomic_t)(nbk + n);
    sigs();
    UNHOLD;
  }
  return NCOK;
}

/* lets group g go, with the signals held: its message is freed, and the
 * bytes and folder the list took over (nctree) */
static void bkdel(int g) {
  size_t a, z, k;
  bkfind(g, &a, &z);
  for (k = a; k < z; k++) {
    free(bk[k].msg);
    if (bk[k].mine)
      ncfree((void *)(uintptr_t)bk[k].b, bk[k].n, 0);
    if (bk[k].mine == 1)
      close(bk[k].dfd);
  }
  if (a == z)
    return;
  memmove(&bk[a], &bk[z], ((size_t)nbk - z) * sizeof *bk);
  nbk = (sig_atomic_t)((size_t)nbk - (z - a));
  if (nbk == 0) {
    free(bk);
    bk = NULL;
    cbk = 0;
  }
  sigs();
}

int ncsnapput(ncsnap *s, int n) {
  int k, ok = 0;
  /* held back, the handler cannot run during the put-back, nor between it
   * and letting the files go: it is one step */
  HOLD;
  if (s[0].sl >= 0 || ncsnappend(s, n, NULL) == NCOK) {
    size_t a, z;
#ifdef SIGXFSZ
    struct sigaction xf;
    noxfsz(&xf);
#endif
    bkfind(s[0].sl, &a, &z);
    ok = z > a && bkput(a, z, 0);
#ifdef SIGXFSZ
    noxfsz(NULL);
    (void)sigaction(SIGXFSZ, &xf, NULL);
#endif
  }
  for (k = 0; k < n; k++)
    ncsnapfree(&s[k]);
  UNHOLD;
  return ok ? NCOK : NCUSE;
}
#endif

int ncnofd = 0;

size_t nctreeon(unsigned long *lim) {
#ifndef _WIN32
  /* the folder of each capsule resealed stays open until the run ends */
  static int up;
  struct rlimit rl;
  *lim = 0;
  if (!up && getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
    rlim_t want = rl.rlim_max;
    rl.rlim_cur = want;
#ifdef OPEN_MAX
    /* macOS takes no more than OPEN_MAX */
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0 && want > OPEN_MAX)
      rl.rlim_cur = OPEN_MAX;
#endif
    (void)setrlimit(RLIMIT_NOFILE, &rl);
  }
  up = 1;
  keepon = 1;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur == RLIM_INFINITY ||
      rl.rlim_cur > (rlim_t)((size_t)-1 / 2))
    return (size_t)-1;
  *lim = (unsigned long)rl.rlim_cur;
  return rl.rlim_cur > NCFDRES ? (size_t)rl.rlim_cur - NCFDRES : 0;
#else
  *lim = 0;
  return (size_t)-1;
#endif
}

void nctree(ncsnap *s, int n) {
  int k;
#ifndef _WIN32
  if (keepon && n > 0 && s[0].sl >= 0) {
    size_t a, z, j;
    struct stat s0, sj;
    HOLD;
    bkfind(s[0].sl, &a, &z);
    for (j = a; j < z; j++) {
      bk[j].mine = 1;
      /* one descriptor for the folder of the group */
      if (j > a && fstat(bk[a].dfd, &s0) == 0 && fstat(bk[j].dfd, &sj) == 0 &&
          s0.st_dev == sj.st_dev && s0.st_ino == sj.st_ino) {
        close(bk[j].dfd);
        bk[j].dfd = bk[a].dfd;
        bk[j].mine = 2;
      }
    }
    /* the bytes and the folders are the list's now */
    for (k = 0; k < n; k++) {
      s[k].b = NULL;
      s[k].n = 0;
      s[k].had = 0;
      s[k].dfd = -1;
      s[k].sl = -1;
    }
    UNHOLD;
  }
#endif
  for (k = 0; k < n; k++)
    ncsnapfree(&s[k]);
}

void nctreeend(int back) {
#ifndef _WIN32
  size_t k = 0, a, z = (size_t)nbk;
  HOLD;
  if (back) {
#ifdef SIGXFSZ
    struct sigaction xf;
    noxfsz(&xf);
#endif
    /* the last noted first, as bkall */
    while (z > 0) {
      for (a = z - 1; a > 0 && bk[a - 1].grp == bk[z - 1].grp; a--)
        ;
      if (bk[a].mine)
        (void)bkput(a, z, 1);
      z = a;
    }
#ifdef SIGXFSZ
    noxfsz(NULL);
    (void)sigaction(SIGXFSZ, &xf, NULL);
#endif
  }
  while (k < (size_t)nbk) {
    if (bk[k].mine)
      bkdel(bk[k].grp);
    else
      k++;
  }
  keepon = 0;
  UNHOLD;
#else
  (void)back;
#endif
}

void ncsnapfree(ncsnap *s) {
#ifndef _WIN32
  if (s->sl >= 0) {
    HOLD;
    bkdel(s->sl);
    UNHOLD;
  }
  if (s->dfd >= 0)
    close(s->dfd);
  s->dfd = -1;
#else
  ncunpend(s->sl);
#endif
  s->sl = -1;
  if (s->b != NULL)
    ncfree(s->b, s->n, 0);
  s->b = NULL;
  s->n = 0;
  s->had = 0;
}

int ncsame(const char *a, const char *b) {
#ifndef _WIN32
  struct stat sa, sb;
  if (stat(a, &sa) == 0 && stat(b, &sb) == 0)
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
#endif
  return strcmp(a, b) == 0;
}
