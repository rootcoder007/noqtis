/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: the network. One HTTP/1.1 POST of an RFC 3161 request
 * (application/timestamp-query, RFC 3161 section 3.4) for seal --tsa,
 * and a GET (ncget), each with the reply read whole. http:// always;
 * https:// when noqtis is built with NQTLS, over the library's own TLS
 * 1.3 client (nqtlnew) with the trust anchors of SSL_CERT_FILE or the
 * system's PEM bundle, no other library, and Certificate Transparency
 * when NOQTIS_CT_LOGS names a log list (nqtlct). The other
 * platform-specific file beside io.c. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE /* SO_NOSIGPIPE is hidden under plain POSIX */
#endif
#endif

#include "cli.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sockt;
typedef int iolen; /* send and recv take an int length */
#define NOSOCK INVALID_SOCKET
#define sclose closesocket
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
typedef int sockt;
typedef size_t iolen;
#define NOSOCK (-1)
#define sclose close
#endif

/* a peer that closes early is an error to report, not SIGPIPE */
#ifdef MSG_NOSIGNAL
#define NCSEND MSG_NOSIGNAL
#else
#define NCSEND 0
#endif

#define NCWAIT 30          /* seconds to connect, and per read or write */
#define NCALL 120          /* seconds for a whole request, lookup included */
#define NCHDR 16384        /* the most header bytes read */
#define NCBODY (1u << 20)  /* the largest reply (noqtis.sig's own limit) */
#define NCCAMAX ((size_t)16 << 20) /* the largest CA bundle read */
#define NCCTMAX ((size_t)4 << 20)  /* the largest CT log list read */
#define NCHOPS 5           /* redirects ncget follows */

static void say(char *err, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, cap, fmt, ap);
  va_end(ap);
}

static int lower(int c) {
  return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/* 1 when s starts with p, ignoring ASCII case */
static int pre(const char *s, const char *p) {
  for (; *p != '\0'; s++, p++) {
    if (lower((unsigned char)*s) != lower((unsigned char)*p))
      return 0;
  }
  return 1;
}

typedef struct {
  char host[256];
  char port[6];
  const char *path;
  int v6;
  int tls;
  size_t po;       /* where the path starts in the URL (its length if none) */
} ncurl;

static int parse(const char *url, ncurl *u, char *err, size_t cap) {
  const char *h, *e, *p;
  size_t n;
  u->tls = 0;
  if (pre(url, "https://")) {
#ifdef NQTLSON
    u->tls = 1;
#else
    say(err, cap, "https:// is not supported (noqtis was built without "
        "its TLS client, NQTLS); the token is signed, so give the TSA's "
        "http:// URL");
    return NCUSE;
#endif
  } else if (!pre(url, "http://")) {
#ifdef NQTLSON
    say(err, cap, "not an http:// URL nor an https:// one");
#else
    say(err, cap, "not an http:// URL");
#endif
    return NCUSE;
  }
  h = url + (u->tls ? 8 : 7);
  u->v6 = 0;
  if (*h == '[') {
    e = strchr(h, ']');
    if (e == NULL) {
      say(err, cap, "an IPv6 address without its closing ]");
      return NCUSE;
    }
    h++;
    p = e + 1;
    u->v6 = 1;
  } else {
    e = h + strcspn(h, ":/?#@");
    p = e;
  }
  n = (size_t)(e - h);
  if (n == 0 || n >= sizeof u->host) {
    say(err, cap, "no host name, or one over 255 bytes");
    return NCUSE;
  }
  memcpy(u->host, h, n);
  u->host[n] = '\0';
  if (*p == '@' || memchr(u->host, '@', n) != NULL) {
    say(err, cap, "a user name in the URL is not supported");
    return NCUSE;
  }
  snprintf(u->port, sizeof u->port, "%s", u->tls ? "443" : "80");
  if (*p == ':') {
    unsigned long v = 0;
    size_t k = 0;
    for (p++; *p >= '0' && *p <= '9' && k < 5; p++, k++)
      v = v * 10 + (unsigned long)(*p - '0');
    if (k == 0 || v == 0 || v > 65535 || (*p != '\0' && *p != '/')) {
      say(err, cap, "the port is not a number from 1 to 65535");
      return NCUSE;
    }
    snprintf(u->port, sizeof u->port, "%lu", v);
  }
  if (*p != '\0' && *p != '/') {
    say(err, cap, "a query or fragment needs a path first (host/...)");
    return NCUSE;
  }
  u->path = *p == '/' ? p : "/";
  u->po = (size_t)(p - url);
  for (e = u->path; *e != '\0'; e++) {
    if ((unsigned char)*e <= 0x20 || *e == 0x7f) {
      say(err, cap, "the path holds a space or a control character");
      return NCUSE;
    }
  }
  return NCOK;
}

int ncurlok(const char *url, char *err, size_t cap) {
  ncurl u;
  return parse(url, &u, err, cap);
}

static void neterr(char *err, size_t cap, const char *what) {
#ifdef _WIN32
  say(err, cap, "%s (Winsock error %d)", what, WSAGetLastError());
#else
  say(err, cap, "%s (%s)", what, strerror(errno));
#endif
}

static int block(sockt s, int on) {
#ifdef _WIN32
  u_long nb = on ? 0 : 1;
  return ioctlsocket(s, (long)FIONBIO, &nb) == 0 ? 0 : -1;
#else
  int f = fcntl(s, F_GETFL, 0);
  if (f < 0)
    return -1;
  return fcntl(s, F_SETFL, on ? (f & ~O_NONBLOCK) : (f | O_NONBLOCK));
#endif
}

/* the end of the request under way: every wait stops at it, so a server
 * that sends a byte now and then cannot hold a request for longer than
 * NCALL seconds */
static time_t dline;

static long left(void) {
  time_t now = time(NULL);
  return now >= dline ? 0 : (long)(dline - now);
}

/* FD_SET: on 32-bit musl the macro converts the descriptor to unsigned,
 * which -Wsign-conversion refuses; the conversion is of a valid socket */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
static void fdadd(sockt s, fd_set *f) {
  FD_SET(s, f);
}
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/* waits until s is readable (rd) or writable, at most NCWAIT seconds and
 * never past the deadline; 0 when it is */
static int await(sockt s, int rd) {
  fd_set f, x;
  struct timeval tv;
  long l = left();
  if (l <= 0)
    return -1;
  FD_ZERO(&f);
  FD_ZERO(&x);
  fdadd(s, &f);
  fdadd(s, &x);
  tv.tv_sec = l < NCWAIT ? l : NCWAIT;
  tv.tv_usec = 0;
  /* the first argument is ignored on Windows */
  if (select((int)s + 1, rd ? &f : NULL, rd ? NULL : &f, &x, &tv) <= 0)
    return -1;
  return 0;
}

/* connects to one address within NCWAIT seconds */
static sockt dial(const struct addrinfo *a) {
  sockt s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
  int e = 0;
  socklen_t el = (socklen_t)sizeof e;
  if (s == NOSOCK)
    return NOSOCK;
#ifdef SO_NOSIGPIPE
  e = 1;
  (void)setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &e, sizeof e);
  e = 0;
#endif
  if (block(s, 0) != 0)
    goto bad;
  if (connect(s, a->ai_addr, (socklen_t)a->ai_addrlen) != 0) {
#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK)
      goto bad;
#else
    if (errno != EINPROGRESS)
      goto bad;
#endif
    if (await(s, 0) != 0 ||
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&e, &el) != 0 || e != 0)
      goto bad;
  }
  if (block(s, 1) != 0)
    goto bad;
  return s;
bad:
  sclose(s);
  return NOSOCK;
}

static int sendall(sockt s, const char *b, size_t n) {
  while (n > 0) {
    size_t c = n > 65536 ? 65536 : n;
    int k;
    if (await(s, 0) != 0)
      return -1;
    k = (int)send(s, b, (iolen)c, NCSEND);
    if (k <= 0)
      return -1;
    b += k;
    n -= (size_t)k;
  }
  return 0;
}

/* the value of header name (lower case, with the colon) in h, or NULL */
static const char *hval(const char *h, const char *name, size_t *len) {
  const char *l = strstr(h, "\r\n");
  while (l != NULL && l[2] != '\r') {
    l += 2;
    if (pre(l, name)) {
      const char *v = l + strlen(name), *e;
      while (*v == ' ' || *v == '\t')
        v++;
      e = strstr(v, "\r\n");
      if (e == NULL)
        return NULL;
      while (e > v && (e[-1] == ' ' || e[-1] == '\t'))
        e--;
      *len = (size_t)(e - v);
      return v;
    }
    l = strstr(l, "\r\n");
  }
  return NULL;
}

/* decodes a chunked body in place; -1 when it is malformed */
static long unchunk(uint8_t *b, size_t n) {
  size_t i = 0, o = 0;
  for (;;) {
    size_t v = 0, k = 0;
    while (i < n && k < 8) {
      int c = lower(b[i]);
      if (c >= '0' && c <= '9')
        v = v * 16 + (size_t)(c - '0');
      else if (c >= 'a' && c <= 'f')
        v = v * 16 + (size_t)(c - 'a' + 10);
      else
        break;
      i++;
      k++;
    }
    if (k == 0)
      return -1;
    while (i < n && b[i] != '\n')
      i++; /* chunk extensions */
    if (i >= n)
      return -1;
    i++;
    if (v == 0)
      return (long)o;
    if (v > n - i || n - i - v < 2 || b[i + v] != '\r' || b[i + v + 1] != '\n')
      return -1;
    memmove(b + o, b + i, v);
    o += v;
    i += v + 2;
  }
}

/* ---- a name lookup with a deadline: getaddrinfo on a thread ---- */

typedef struct {
  char host[256], port[8];
  struct addrinfo hint, *res;
  int rc, done, refs;
#ifdef _WIN32
  CRITICAL_SECTION mu;
  CONDITION_VARIABLE cv;
#else
  pthread_mutex_t mu;
  pthread_cond_t cv;
#endif
} nclook;

static void lkfree(nclook *q) {
  if (q->res != NULL)
    freeaddrinfo(q->res);
#ifdef _WIN32
  DeleteCriticalSection(&q->mu);
#else
  pthread_mutex_destroy(&q->mu);
  pthread_cond_destroy(&q->cv);
#endif
  free(q);
}

/* the last of the caller and the thread to let go frees q */
static void lkdrop(nclook *q, int keepres, struct addrinfo **res) {
  int last;
#ifdef _WIN32
  EnterCriticalSection(&q->mu);
#else
  pthread_mutex_lock(&q->mu);
#endif
  if (keepres && res != NULL) {
    *res = q->res;
    q->res = NULL;
  }
  last = --q->refs == 0;
#ifdef _WIN32
  LeaveCriticalSection(&q->mu);
#else
  pthread_mutex_unlock(&q->mu);
#endif
  if (last)
    lkfree(q);
}

#ifdef _WIN32
static DWORD WINAPI lkrun(LPVOID p) {
#else
static void *lkrun(void *p) {
#endif
  nclook *q = (nclook *)p;
  struct addrinfo *r = NULL;
  int k = getaddrinfo(q->host, q->port, &q->hint, &r);
#ifdef _WIN32
  EnterCriticalSection(&q->mu);
  q->rc = k;
  q->res = r;
  q->done = 1;
  WakeConditionVariable(&q->cv);
  LeaveCriticalSection(&q->mu);
#else
  pthread_mutex_lock(&q->mu);
  q->rc = k;
  q->res = r;
  q->done = 1;
  pthread_cond_signal(&q->cv);
  pthread_mutex_unlock(&q->mu);
#endif
  lkdrop(q, 0, NULL);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

/* getaddrinfo, given up after NCWAIT seconds (or at the deadline); 1 when
 * it timed out, else getaddrinfo's own result */
static int lookup(const char *host, const char *port,
                  const struct addrinfo *hint, struct addrinfo **res,
                  int *gai) {
  nclook *q = (nclook *)calloc(1, sizeof *q);
  long l = left();
  int to = 0;
  *res = NULL;
  *gai = EAI_FAIL;
  if (q == NULL || strlen(host) >= sizeof q->host ||
      strlen(port) >= sizeof q->port) {
    free(q);
    return 0;
  }
  snprintf(q->host, sizeof q->host, "%s", host);
  snprintf(q->port, sizeof q->port, "%s", port);
  q->hint = *hint;
  q->refs = 2;
  if (l > NCWAIT)
    l = NCWAIT;
#ifdef _WIN32
  {
    HANDLE t;
    InitializeCriticalSection(&q->mu);
    InitializeConditionVariable(&q->cv);
    t = CreateThread(NULL, 0, lkrun, q, 0, NULL);
    if (t == NULL) {
      lkfree(q);
      return 0;
    }
    CloseHandle(t);
    EnterCriticalSection(&q->mu);
    while (!q->done && !to)
      to = !SleepConditionVariableCS(&q->cv, &q->mu, (DWORD)(l * 1000));
    if (q->done)
      to = 0;
    *gai = q->rc;
    LeaveCriticalSection(&q->mu);
  }
#else
  {
    pthread_t t;
    struct timespec ts;
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->cv, NULL);
    if (pthread_create(&t, NULL, lkrun, q) != 0) {
      lkfree(q);
      return 0;
    }
    pthread_detach(t);
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += l;
    pthread_mutex_lock(&q->mu);
    while (!q->done && !to)
      to = pthread_cond_timedwait(&q->cv, &q->mu, &ts) != 0;
    if (q->done)
      to = 0;
    *gai = q->rc;
    pthread_mutex_unlock(&q->mu);
  }
#endif
  lkdrop(q, !to, res);
  return to;
}

/* ---- TLS (with NQTLS) ---- */

#ifdef NQTLSON
static int tlwr(void *user, const uint8_t *b, size_t n) {
  return sendall(*(sockt *)user, (const char *)b, n) == 0 ? NQOK : NQEIO;
}

static int tlrd(void *user, uint8_t *b, size_t cap, size_t *got) {
  sockt s = *(sockt *)user;
  int r;
  *got = 0;
  if (await(s, 1) != 0) return NQEIO;
  r = (int)recv(s, (char *)b, (iolen)(cap > 65536 ? 65536 : cap), 0);
  if (r < 0) return NQEIO;
  *got = (size_t)r;
  return NQOK;
}

/* the trust anchors: SSL_CERT_FILE, else the first system bundle found */
static int cafile(uint8_t **b, size_t *n, char *err, size_t cap) {
  static const char *const sys[] = {
      "/etc/ssl/certs/ca-certificates.crt", /* Debian, Ubuntu, Alpine */
      "/etc/pki/tls/certs/ca-bundle.crt",   /* RHEL, older Fedora */
      "/etc/ssl/certs/ca-bundle.crt",       /* Fedora */
      "/etc/ssl/cert.pem",                  /* macOS, the BSDs, Alpine */
      "/etc/ssl/ca-bundle.pem",             /* openSUSE */
      "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD ports */
  };
  const char *e = getenv("SSL_CERT_FILE");
  size_t i;
  if (e != NULL && *e != '\0') {
    if (ncrdx(e, 0, NCCAMAX, b, n) == NQOK) return NCOK;
    say(err, cap, "cannot read SSL_CERT_FILE %s", e);
    return NCUSE;
  }
  for (i = 0; i < sizeof sys / sizeof sys[0]; i++) {
    if (ncrdx(sys[i], 0, NCCAMAX, b, n) == NQOK) return NCOK;
  }
#ifdef _WIN32
  say(err, cap, "no trust anchors: the Windows certificate store is not "
      "read yet; set SSL_CERT_FILE to a PEM bundle");
#else
  say(err, cap, "no system CA bundle found; set SSL_CERT_FILE to a PEM "
      "bundle of trusted roots");
#endif
  return NCUSE;
}

/* the Certificate Transparency log list NOQTIS_CT_LOGS names: *b NULL
 * when it is not set (CT off) */
static int ctfile(uint8_t **b, size_t *n, char *err, size_t cap) {
  const char *e = getenv("NOQTIS_CT_LOGS");
  *b = NULL;
  *n = 0;
  if (e == NULL || *e == '\0') return NCOK;
  if (ncrdx(e, 0, NCCTMAX, b, n) == NQOK) return NCOK;
  say(err, cap, "cannot read NOQTIS_CT_LOGS %s", e);
  return NCUSE;
}

/* 1 when the reply in b (n bytes) is complete by its own framing: the
 * test for a TLS stream that ended without close_notify */
static int whole(const char *b, size_t n) {
  const char *he = strstr(b, "\r\n\r\n"), *v;
  size_t hl, vl = 0;
  if (he == NULL) return 0;
  hl = (size_t)(he - b) + 4;
  if ((v = hval(b, "transfer-encoding:", &vl)) != NULL && pre(v, "chunked")) {
    return n - hl >= 5 && memcmp(b + n - 5, "0\r\n\r\n", 5) == 0 &&
           (n - hl == 5 || b[n - 7] == '\r');
  }
  if ((v = hval(b, "content-length:", &vl)) != NULL) {
    unsigned long cl = 0;
    size_t i;
    for (i = 0; i < vl && v[i] >= '0' && v[i] <= '9' && cl <= NCBODY * 64;
         i++) {
      cl = cl * 10 + (unsigned long)(v[i] - '0');
    }
    return i == vl && i > 0 && n - hl >= cl;
  }
  return 0;
}
#endif

/* sends the request (head of hn bytes, then body) and reads the reply
 * whole into *buf (malloc'd, NUL-terminated, at most max bytes) */
static int xfer(const ncurl *u, const char *head, size_t hn,
                const uint8_t *bd, size_t n, size_t max, char **buf,
                size_t *got, char *err, size_t cap) {
  struct addrinfo hint, *res = NULL, *a;
  sockt s = NOSOCK;
  int rc = NCUSE, k;
#ifdef NQTLSON
  nqtls *t = NULL;
  uint8_t *ca = NULL, *ct = NULL;
  size_t can = 0, ctn = 0;
  nqtlio io;
#endif
#ifdef _WIN32
  static int up = 0;
  WSADATA wd;
  if (!up) {
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
      say(err, cap, "cannot start Winsock");
      return NCUSE;
    }
    up = 1;
  }
#endif
  *buf = NULL;
  *got = 0;
#ifdef NQTLSON
  if (u->tls && cafile(&ca, &can, err, cap) != NCOK) return NCUSE;
  if (u->tls && ctfile(&ct, &ctn, err, cap) != NCOK) {
    ncfree(ca, can, 0);
    return NCUSE;
  }
#endif
  memset(&hint, 0, sizeof hint);
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  if (lookup(u->host, u->port, &hint, &res, &k)) {
    say(err, cap, "cannot resolve %s (no answer in %d s)", u->host, NCWAIT);
    goto out;
  }
  if (k != 0 || res == NULL) {
    say(err, cap, "cannot resolve %s (%s)", u->host, gai_strerror(k));
    goto out;
  }
  for (a = res; a != NULL && s == NOSOCK; a = a->ai_next) s = dial(a);
  freeaddrinfo(res);
  if (s == NOSOCK) {
    say(err, cap, "cannot connect to %s port %s (refused, unreachable or "
        "no answer in %d s)", u->host, u->port, NCWAIT);
    goto out;
  }
  *buf = (char *)malloc(max + 1);
  if (*buf == NULL) {
    say(err, cap, "out of memory");
    goto out;
  }
#ifdef NQTLSON
  if (u->tls) {
    io.wr = tlwr;
    io.rd = tlrd;
    io.user = &s;
    k = nqtlnew(&t, u->host, ca, can, &io);
    if (k != NQOK) {
      say(err, cap, "TLS with %s: %s", u->host,
          k == NQEDEC ? "the CA bundle holds no usable certificate"
                      : nqerr(k));
      goto out;
    }
    if (ct != NULL && (k = nqtlct(t, ct, ctn)) != NQOK) {
      say(err, cap, "NOQTIS_CT_LOGS %s is not a log list noqtis can use "
          "(%s)", getenv("NOQTIS_CT_LOGS"), nqerr(k));
      goto out;
    }
    if ((k = nqtlhs(t)) != NQOK) {
      say(err, cap, "TLS with %s: %s", u->host, nqtlwhy(t));
      goto out;
    }
    if (nqtlwr(t, (const uint8_t *)head, hn) != NQOK ||
        (n > 0 && nqtlwr(t, bd, n) != NQOK)) {
      say(err, cap, "cannot send the request: %s", nqtlwhy(t));
      goto out;
    }
    for (;;) {
      size_t r = 0;
      if (*got == max) {
        say(err, cap, "the reply is over %lu bytes", (unsigned long)max);
        goto out;
      }
      k = nqtlrd(t, (uint8_t *)*buf + *got, max - *got, &r);
      if (k != NQOK) {
        (*buf)[*got] = '\0';
        /* a server that closes without close_notify after a reply
         * complete by its own length is common; anything less is cut */
        if (k == NQEIO && whole(*buf, *got)) break;
        say(err, cap, "TLS with %s: %s", u->host, nqtlwhy(t));
        goto out;
      }
      if (r == 0) break;
      *got += r;
    }
    (*buf)[*got] = '\0';
    (void)nqtlend(t);
    rc = NCOK;
    goto out;
  }
#endif
  if (sendall(s, head, hn) != 0 || sendall(s, (const char *)bd, n) != 0) {
    neterr(err, cap, "cannot send the request");
    goto out;
  }
  for (;;) {
    int r;
    if (*got == max) {
      say(err, cap, "the reply is over %lu bytes", (unsigned long)max);
      goto out;
    }
    if (await(s, 1) != 0) {
      say(err, cap, "no complete reply in %d s (at most %d s per read)",
          NCALL, NCWAIT);
      goto out;
    }
    r = (int)recv(s, *buf + *got, (iolen)(max - *got), 0);
    if (r < 0) {
      neterr(err, cap, "the connection failed while reading the reply");
      goto out;
    }
    if (r == 0) break;
    *got += (size_t)r;
  }
  (*buf)[*got] = '\0';
  rc = NCOK;
out:
#ifdef NQTLSON
  nqtlfree(t);
  if (ca != NULL) ncfree(ca, can, 0);
  if (ct != NULL) ncfree(ct, ctn, 0);
#endif
  if (s != NOSOCK) sclose(s);
  if (rc != NCOK) {
    free(*buf);
    *buf = NULL;
    *got = 0;
  }
  return rc;
}

/* the status line: HTTP/1.x and a three-digit code; *hl the header
 * bytes with the blank line */
static int status(const char *buf, int *code, size_t *hl, char *err,
                  size_t cap) {
  const char *he = strstr(buf, "\r\n\r\n");
  if (he == NULL || (size_t)(he - buf) > NCHDR ||
      (!pre(buf, "HTTP/1.1 ") && !pre(buf, "HTTP/1.0 ")) ||
      buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
      buf[11] < '0' || buf[11] > '9') {
    say(err, cap, "the reply is not HTTP/1.x");
    return NCUSE;
  }
  *hl = (size_t)(he - buf) + 4;
  *code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
  return NCOK;
}

/* the body after hl header bytes, decoded and copied to *out */
static int body(char *buf, size_t got, size_t hl, size_t max,
                uint8_t **out, size_t *outn, char *err, size_t cap) {
  const char *v;
  size_t vl = 0;
  long bl = (long)(got - hl);
  if ((v = hval(buf, "transfer-encoding:", &vl)) != NULL &&
      pre(v, "chunked")) {
    bl = unchunk((uint8_t *)buf + hl, got - hl);
    if (bl < 0) {
      say(err, cap, "the chunked reply is malformed or cut short");
      return NCUSE;
    }
  } else if ((v = hval(buf, "content-length:", &vl)) != NULL) {
    unsigned long cl = 0;
    size_t i;
    for (i = 0; i < vl && v[i] >= '0' && v[i] <= '9' && cl <= max; i++)
      cl = cl * 10 + (unsigned long)(v[i] - '0');
    if (i != vl || i == 0 || cl > got - hl) {
      say(err, cap, "the reply is shorter than its Content-Length");
      return NCUSE;
    }
    bl = (long)cl;
  }
  if (bl <= 0) {
    say(err, cap, "the reply is empty");
    return NCUSE;
  }
  *out = (uint8_t *)malloc((size_t)bl);
  if (*out == NULL) {
    say(err, cap, "out of memory");
    return NCUSE;
  }
  memcpy(*out, buf + hl, (size_t)bl);
  *outn = (size_t)bl;
  return NCOK;
}

/* the request head for u: method, path, Host (with a port other than
 * the scheme's) and the rest */
static int mkhead(const ncurl *u, const char *meth, const char *rest,
                  char *head, size_t hcap, size_t *hn, char *err,
                  size_t cap) {
  int dflt = strcmp(u->port, u->tls ? "443" : "80") == 0;
  int k = snprintf(head, hcap,
                   "%s %s HTTP/1.1\r\n"
                   "Host: %s%s%s%s%s\r\n"
                   "User-Agent: noqtis/%s\r\n"
                   "%s"
                   "Connection: close\r\n\r\n",
                   meth, u->path, u->v6 ? "[" : "", u->host,
                   u->v6 ? "]" : "", dflt ? "" : ":", dflt ? "" : u->port,
                   nqver(), rest);
  if (k < 0 || (size_t)k >= hcap) {
    say(err, cap, "the URL is too long");
    return NCUSE;
  }
  *hn = (size_t)k;
  return NCOK;
}

int nchttp(const char *url, const uint8_t *body0, size_t n, uint8_t **out,
           size_t *outn, char *err, size_t cap) {
  char head[1024], rest[200];
  char *buf = NULL;
  size_t got = 0, hl = 0, hn = 0, vl = 0;
  const char *v;
  int rc = NCUSE, code = 0;
  ncurl u;
  *out = NULL;
  *outn = 0;
  err[0] = '\0';
  if (parse(url, &u, err, cap) != NCOK) return NCUSE;
  snprintf(rest, sizeof rest,
           "Content-Type: application/timestamp-query\r\n"
           "Accept: application/timestamp-reply\r\n"
           "Content-Length: %lu\r\n",
           (unsigned long)n);
  if (mkhead(&u, "POST", rest, head, sizeof head, &hn, err, cap) != NCOK) {
    return NCUSE;
  }
  dline = time(NULL) + NCALL;
  if (xfer(&u, head, hn, body0, n, NCHDR + NCBODY, &buf, &got, err, cap) !=
          NCOK ||
      status(buf, &code, &hl, err, cap) != NCOK) {
    goto out;
  }
  if (code >= 300 && code < 400 &&
      (v = hval(buf, "location:", &vl)) != NULL) {
    say(err, cap, "HTTP %d: the TSA moved to %.*s; give that URL", code,
        (int)(vl > 200 ? 200 : vl), v);
    goto out;
  }
  if (code != 200) {
    const char *e = strstr(buf, "\r\n");
    say(err, cap, "HTTP %.*s", (int)(e - buf - 9 > 80 ? 80 : e - buf - 9),
        buf + 9);
    goto out;
  }
  v = hval(buf, "content-type:", &vl);
  if (v == NULL || (!pre(v, "application/timestamp-reply") &&
                    !pre(v, "application/timestamp-response"))) {
    say(err, cap, "the reply is %.*s, not application/timestamp-reply "
        "(is this the TSA's URL?)", v == NULL ? 12 : (int)(vl > 60 ? 60 : vl),
        v == NULL ? "of no type" : v);
    goto out;
  }
  rc = body(buf, got, hl, NCBODY, out, outn, err, cap);
out:
  free(buf);
  return rc;
}

/* the URL a Location of vl bytes at v names, from the URL cur (parsed
 * in u): absolute, scheme-relative (//host/...), a path (/...), or a
 * reference relative to cur's folder (RFC 3986 section 5.2, without
 * dot segments) */
static int redir(const char *cur, const ncurl *u, const char *v, size_t vl,
                 char *nx, size_t cap) {
  size_t pl = u->po, i, k = 0, sl = 0;
  const char *sch = u->tls ? "https:" : "http:";
  for (i = 0; i < vl && i < 10; i++) {
    if (v[i] == ':') {
      sl = i;
      break;
    }
    if (v[i] == '/' || v[i] == '?' || v[i] == '#') break;
  }
  if (sl > 0) {
    /* absolute */
  } else if (vl >= 2 && v[0] == '/' && v[1] == '/') {
    k = strlen(sch);
    if (k >= cap) return NCUSE;
    memcpy(nx, sch, k);
  } else if (v[0] == '/') {
    k = pl;
    if (k >= cap) return NCUSE;
    memcpy(nx, cur, k);
  } else {
    /* cur up to the last / of its path (before any query) */
    size_t e = pl;
    k = pl;
    for (e = pl; cur[e] != '\0' && cur[e] != '?' && cur[e] != '#'; e++) {
      if (cur[e] == '/') k = e + 1;
    }
    if (k == pl) {
      if (k + 1 >= cap) return NCUSE;
      memcpy(nx, cur, k);
      nx[k++] = '/';
    } else {
      if (k >= cap) return NCUSE;
      memcpy(nx, cur, k);
    }
  }
  if (k + vl >= cap) return NCUSE;
  memcpy(nx + k, v, vl);
  nx[k + vl] = '\0';
  return NCOK;
}

/* 1 when a redirect from a to b stays on a's server: the same host (in
 * any case) and port, or http on port 80 moving to https on 443. Any other
 * target is refused: a server could otherwise point the fetch at a
 * host only this machine reaches (localhost, the local network). */
static int samehost(const ncurl *a, const ncurl *b) {
  size_t i;
  for (i = 0; a->host[i] != '\0' || b->host[i] != '\0'; i++)
    if (lower((unsigned char)a->host[i]) != lower((unsigned char)b->host[i]))
      return 0;
  if (strcmp(a->port, b->port) == 0) return 1;
  return !a->tls && b->tls && strcmp(a->port, "80") == 0 &&
         strcmp(b->port, "443") == 0;
}

int ncget(const char *url, size_t max, uint8_t **out, size_t *outn,
          char *err, size_t cap) {
  char head[1024], cur[2048], nx[2048];
  char *buf = NULL;
  size_t got = 0, hl = 0, hn = 0, vl = 0;
  const char *v;
  int rc = NCUSE, code = 0, hop, was;
  ncurl u, o, t;
  *out = NULL;
  *outn = 0;
  err[0] = '\0';
  if (strlen(url) >= sizeof cur) {
    say(err, cap, "the URL is too long");
    return NCUSE;
  }
  snprintf(cur, sizeof cur, "%s", url);
  dline = time(NULL) + NCALL;
  for (hop = 0;; hop++) {
    if (parse(cur, &u, err, cap) != NCOK ||
        mkhead(&u, "GET", "Accept: */*\r\n", head, sizeof head, &hn, err,
               cap) != NCOK ||
        xfer(&u, head, hn, NULL, 0, NCHDR + max, &buf, &got, err, cap) !=
            NCOK ||
        status(buf, &code, &hl, err, cap) != NCOK) {
      break;
    }
    if (hop == 0) o = u;
    if (code == 301 || code == 302 || code == 303 || code == 307 ||
        code == 308) {
      v = hval(buf, "location:", &vl);
      if (v == NULL || vl == 0 || vl >= sizeof nx) {
        say(err, cap, "HTTP %d without a usable Location", code);
        break;
      }
      if (hop == NCHOPS) {
        say(err, cap, "more than %d redirects", NCHOPS);
        break;
      }
      was = u.tls;
      if (redir(cur, &u, v, vl, nx, sizeof nx) != NCOK) {
        say(err, cap, "the redirect's URL is too long");
        break;
      }
      /* https stays https: a redirect may never drop TLS */
      if (was && !pre(nx, "https://")) {
        say(err, cap, "a redirect from https:// to %.100s refused", nx);
        break;
      }
      if (parse(nx, &t, err, cap) != NCOK) break;
      if (!samehost(&o, &t)) {
        say(err, cap, "a redirect to another server refused: %.100s (give "
            "that URL if you trust it)", nx);
        break;
      }
      snprintf(cur, sizeof cur, "%s", nx);
      free(buf);
      buf = NULL;
      continue;
    }
    if (code != 200) {
      const char *e = strstr(buf, "\r\n");
      say(err, cap, "HTTP %.*s", (int)(e - buf - 9 > 80 ? 80 : e - buf - 9),
          buf + 9);
      break;
    }
    rc = body(buf, got, hl, max, out, outn, err, cap);
    break;
  }
  free(buf);
  return rc;
}
