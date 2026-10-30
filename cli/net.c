/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: the network, for seal --tsa only. One HTTP/1.1 POST of an RFC
 * 3161 request (application/timestamp-query, RFC 3161 section 3.4) over
 * plain TCP, and the reply read whole. http:// only: the token is signed,
 * so TLS would add no integrity, and the tool links no TLS library. The
 * other platform-specific file beside io.c. */
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
} ncurl;

static int parse(const char *url, ncurl *u, char *err, size_t cap) {
  const char *h, *e, *p;
  size_t n;
  if (pre(url, "https://")) {
    say(err, cap, "https:// is not supported (noqtis links no TLS "
        "library); the token is signed, so give the TSA's http:// URL");
    return NCUSE;
  }
  if (!pre(url, "http://")) {
    say(err, cap, "not an http:// URL");
    return NCUSE;
  }
  h = url + 7;
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
  strcpy(u->port, "80");
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
  FD_SET(s, &f);
  FD_SET(s, &x);
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
  strcpy(q->host, host);
  strcpy(q->port, port);
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

int nchttp(const char *url, const uint8_t *body, size_t n, uint8_t **out,
           size_t *outn, char *err, size_t cap) {
  struct addrinfo hint, *res = NULL, *a;
  char head[1024];
  char *buf = NULL;
  size_t got = 0, max = NCHDR + NCBODY, hl;
  const char *v, *he;
  size_t vl = 0;
  sockt s = NOSOCK;
  int rc = NCUSE, k, code;
  long bl;
#ifdef _WIN32
  static int up = 0;
  WSADATA wd;
#endif
  ncurl u;
  *out = NULL;
  *outn = 0;
  err[0] = '\0';
  if (parse(url, &u, err, cap) != NCOK)
    return NCUSE;
#ifdef _WIN32
  if (!up) {
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
      say(err, cap, "cannot start Winsock");
      return NCUSE;
    }
    up = 1;
  }
#endif
  memset(&hint, 0, sizeof hint);
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  dline = time(NULL) + NCALL;
  if (lookup(u.host, u.port, &hint, &res, &k)) {
    say(err, cap, "cannot resolve %s (no answer in %d s)", u.host, NCWAIT);
    return NCUSE;
  }
  if (k != 0 || res == NULL) {
    say(err, cap, "cannot resolve %s (%s)", u.host, gai_strerror(k));
    return NCUSE;
  }
  for (a = res; a != NULL && s == NOSOCK; a = a->ai_next)
    s = dial(a);
  freeaddrinfo(res);
  if (s == NOSOCK) {
    say(err, cap, "cannot connect to %s port %s (refused, unreachable or "
        "no answer in %d s)", u.host, u.port, NCWAIT);
    return NCUSE;
  }
  k = snprintf(head, sizeof head,
               "POST %s HTTP/1.1\r\n"
               "Host: %s%s%s%s%s\r\n"
               "User-Agent: noqtis/%s\r\n"
               "Content-Type: application/timestamp-query\r\n"
               "Accept: application/timestamp-reply\r\n"
               "Content-Length: %lu\r\n"
               "Connection: close\r\n\r\n",
               u.path, u.v6 ? "[" : "", u.host, u.v6 ? "]" : "",
               strcmp(u.port, "80") != 0 ? ":" : "",
               strcmp(u.port, "80") != 0 ? u.port : "", nqver(),
               (unsigned long)n);
  if (k < 0 || (size_t)k >= sizeof head) {
    say(err, cap, "the URL is too long");
    goto out;
  }
  if (sendall(s, head, (size_t)k) != 0 ||
      sendall(s, (const char *)body, n) != 0) {
    neterr(err, cap, "cannot send the request");
    goto out;
  }
  buf = (char *)malloc(max + 1);
  if (buf == NULL) {
    say(err, cap, "out of memory");
    goto out;
  }
  for (;;) {
    int r;
    if (got == max) {
      say(err, cap, "the reply is over %u bytes", (unsigned)max);
      goto out;
    }
    if (await(s, 1) != 0) {
      say(err, cap, "no complete reply in %d s (at most %d s per read)",
          NCALL, NCWAIT);
      goto out;
    }
    r = (int)recv(s, buf + got, (iolen)(max - got), 0);
    if (r < 0) {
      neterr(err, cap, "the connection failed while reading the reply");
      goto out;
    }
    if (r == 0)
      break;
    got += (size_t)r;
  }
  buf[got] = '\0';
  he = strstr(buf, "\r\n\r\n");
  if (he == NULL || (size_t)(he - buf) > NCHDR ||
      (!pre(buf, "HTTP/1.1 ") && !pre(buf, "HTTP/1.0 ")) ||
      buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
      buf[11] < '0' || buf[11] > '9') {
    say(err, cap, "the reply is not HTTP/1.x");
    goto out;
  }
  hl = (size_t)(he - buf) + 4;
  code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
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
  bl = (long)(got - hl);
  if ((v = hval(buf, "transfer-encoding:", &vl)) != NULL &&
      pre(v, "chunked")) {
    bl = unchunk((uint8_t *)buf + hl, got - hl);
    if (bl < 0) {
      say(err, cap, "the chunked reply is malformed or cut short");
      goto out;
    }
  } else if ((v = hval(buf, "content-length:", &vl)) != NULL) {
    unsigned long cl = 0;
    size_t i;
    for (i = 0; i < vl && v[i] >= '0' && v[i] <= '9' && cl <= NCBODY; i++)
      cl = cl * 10 + (unsigned long)(v[i] - '0');
    if (i != vl || i == 0 || cl > got - hl) {
      say(err, cap, "the reply is shorter than its Content-Length");
      goto out;
    }
    bl = (long)cl;
  }
  if (bl <= 0) {
    say(err, cap, "the reply is empty");
    goto out;
  }
  *out = (uint8_t *)malloc((size_t)bl);
  if (*out == NULL) {
    say(err, cap, "out of memory");
    goto out;
  }
  memcpy(*out, buf + hl, (size_t)bl);
  *outn = (size_t)bl;
  rc = NCOK;
out:
  free(buf);
  sclose(s);
  return rc;
}
