/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * A local time-stamping authority for tcli: an HTTP server on 127.0.0.1
 * that runs one client command and answers its requests, so that seal
 * --tsa is tested without the network.
 *
 *   tsad <cmd-file> <mode> [<arg>]
 *
 * The client command is read from <cmd-file>; "@PORT@" in it becomes the
 * server's port and "@DEAD@" a port nothing listens on. tsad serves until
 * the command exits and returns its exit status. Each request's body is
 * saved as q.tsq. Modes:
 *   ossl <file>   runs the shell command in <file> (which reads q.tsq and
 *                 writes q.tsr), then answers with q.tsr
 *   osslc <file>  the same, answered with chunked transfer coding
 *   file <path>   answers with the bytes of <path>
 *   chunk <path>  the same, chunked
 *   short <path>  the same, with a Content-Length one byte too large
 *   type <path>   the same, as text/html
 *   http <code>   answers with that status and no body (a Location for 3xx)
 *   junk          answers with bytes that are not HTTP
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sockt;
typedef int iolen;
#define NOSOCK INVALID_SOCKET
#define sclose closesocket
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int sockt;
typedef size_t iolen;
#define NOSOCK (-1)
#define sclose close
#endif

static const char *mode, *arg;
static int nserved;

/* the file p in a new buffer, NUL-terminated (it may be a command) */
static unsigned char *slurp(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  unsigned char *b = NULL;
  long l;
  *n = 0;
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) == 0 && (l = ftell(f)) >= 0 &&
      fseek(f, 0, SEEK_SET) == 0 && (b = malloc((size_t)l + 1)) != NULL &&
      fread(b, 1, (size_t)l, f) == (size_t)l) {
    b[l] = 0;
    *n = (size_t)l;
  } else {
    free(b);
    b = NULL;
  }
  fclose(f);
  return b;
}

static void put(sockt s, const void *b, size_t n) {
  const char *p = (const char *)b;
  while (n > 0) {
    int k = (int)send(s, p, (iolen)n, 0);
    if (k <= 0)
      return;
    p += k;
    n -= (size_t)k;
  }
}

static void puts2(sockt s, const char *t) {
  put(s, t, strlen(t));
}

/* reads one request; saves its body as q.tsq */
static int request(sockt s) {
  static char b[70000];
  size_t got = 0, hl = 0, cl = 0;
  char *e, *c;
  for (;;) {
    int k;
    if (got == sizeof b - 1)
      return -1;
    k = (int)recv(s, b + got, (iolen)(sizeof b - 1 - got), 0);
    if (k <= 0)
      return -1;
    got += (size_t)k;
    b[got] = '\0';
    if (hl == 0 && (e = strstr(b, "\r\n\r\n")) != NULL) {
      hl = (size_t)(e - b) + 4;
      c = strstr(b, "Content-Length: ");
      if (c == NULL || c > e)
        return -1;
      cl = (size_t)strtoul(c + 16, NULL, 10);
    }
    if (hl != 0 && got >= hl + cl)
      break;
  }
  {
    FILE *f = fopen("q.tsq", "wb");
    if (f == NULL)
      return -1;
    fwrite(b + hl, 1, cl, f);
    fclose(f);
  }
  return 0;
}

static void reply(sockt s, const unsigned char *b, size_t n, int chunked,
                  long extra, const char *type) {
  char h[256];
  if (chunked) {
    size_t half = n / 2;
    snprintf(h, sizeof h, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
             "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
             type);
    puts2(s, h);
    snprintf(h, sizeof h, "%lx;x=y\r\n", (unsigned long)half);
    puts2(s, h);
    put(s, b, half);
    snprintf(h, sizeof h, "\r\n%lX\r\n", (unsigned long)(n - half));
    puts2(s, h);
    put(s, b + half, n - half);
    puts2(s, "\r\n0\r\n\r\n");
    return;
  }
  snprintf(h, sizeof h, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
           "Content-Length: %lu\r\nConnection: close\r\n\r\n", type,
           (unsigned long)n + (unsigned long)extra);
  puts2(s, h);
  put(s, b, n);
}

static void serve(sockt s) {
  unsigned char *b = NULL;
  size_t n = 0;
  nserved++;
  if (request(s) != 0)
    return;
  if (strcmp(mode, "ossl") == 0 || strcmp(mode, "osslc") == 0) {
    size_t cn = 0;
    unsigned char *cmd = slurp(arg, &cn);
    int st = -2;
    remove("q.tsr");
    if (cmd != NULL && (st = system((const char *)cmd)) == 0)
      b = slurp("q.tsr", &n);
    free(cmd);
    if (b == NULL) {
      char h[128];
      snprintf(h, sizeof h, "HTTP/1.1 500 the local TSA failed (%d)\r\n"
               "Connection: close\r\n\r\n", st);
      puts2(s, h);
      return;
    }
    reply(s, b, n, mode[4] == 'c', 0, "application/timestamp-reply");
  } else if (strcmp(mode, "http") == 0) {
    char h[256];
    snprintf(h, sizeof h, "HTTP/1.1 %s Test\r\n%sContent-Length: 0\r\n"
             "Connection: close\r\n\r\n", arg,
             arg[0] == '3' ? "Location: http://tsa.example/new\r\n" : "");
    puts2(s, h);
  } else if (strcmp(mode, "junk") == 0) {
    puts2(s, "this is not HTTP\r\n\r\n");
  } else if ((b = slurp(arg, &n)) != NULL) {
    if (strcmp(mode, "type") == 0)
      reply(s, b, n, 0, 0, "text/html");
    else
      reply(s, b, n, strcmp(mode, "chunk") == 0,
            strcmp(mode, "short") == 0 ? 1 : 0,
            "application/timestamp-reply");
  }
  free(b);
}

static sockt lsn;
#ifdef _WIN32
static volatile int stop; /* set when the client is done */
#endif

static unsigned short listen1(sockt *out) {
  struct sockaddr_in a;
  socklen_t al = (socklen_t)sizeof a;
  sockt s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == NOSOCK)
    return 0;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(0x7f000001u) /* 127.0.0.1 */;
  a.sin_port = 0;
  if (bind(s, (struct sockaddr *)&a, (socklen_t)sizeof a) != 0 ||
      listen(s, 8) != 0 ||
      getsockname(s, (struct sockaddr *)&a, &al) != 0) {
    sclose(s);
    return 0;
  }
  *out = s;
  return ntohs(a.sin_port);
}

/* accepts and serves until stop; 0 when nothing is pending in 100 ms */
static int once(void) {
  fd_set f;
  struct timeval tv;
  sockt c;
  FD_ZERO(&f);
  FD_SET(lsn, &f);
  tv.tv_sec = 0;
  tv.tv_usec = 100000;
  if (select((int)lsn + 1, &f, NULL, NULL, &tv) <= 0)
    return 0;
  c = accept(lsn, NULL, NULL);
  if (c == NOSOCK)
    return 0;
  serve(c);
  sclose(c);
  return 1;
}

#ifdef _WIN32
static DWORD WINAPI loop(LPVOID p) {
  (void)p;
  while (!stop)
    once();
  return 0;
}
#endif

/* the command with @PORT@ and @DEAD@ replaced */
static char *subst(const char *t, unsigned short port, unsigned short dead) {
  size_t n = strlen(t), i, o = 0;
  char *r = malloc(n * 2 + 64);
  if (r == NULL)
    return NULL;
  for (i = 0; i < n;) {
    if (strncmp(t + i, "@PORT@", 6) == 0) {
      o += (size_t)sprintf(r + o, "%u", (unsigned)port);
      i += 6;
    } else if (strncmp(t + i, "@DEAD@", 6) == 0) {
      o += (size_t)sprintf(r + o, "%u", (unsigned)dead);
      i += 6;
    } else if (t[i] == '\n' || t[i] == '\r') {
      i++;
    } else {
      r[o++] = t[i++];
    }
  }
  r[o] = '\0';
  return r;
}

int main(int argc, char **argv) {
  unsigned char *t;
  size_t tn = 0;
  unsigned short port, dead;
  sockt d = NOSOCK;
  char *cmd;
  int st;
#ifdef _WIN32
  WSADATA wd;
  HANDLE th;
  if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
    return 99;
#endif
  if (argc < 3) {
    fprintf(stderr, "usage: tsad <cmd-file> <mode> [<arg>]\n");
    return 99;
  }
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN); /* a client that hangs up is not fatal */
#endif
  mode = argv[2];
  arg = argc > 3 ? argv[3] : "";
  t = slurp(argv[1], &tn);
  port = listen1(&lsn);
  dead = listen1(&d);
  if (d != NOSOCK)
    sclose(d); /* bound, then closed: a port that refuses */
  if (t == NULL || port == 0 || dead == 0) {
    fprintf(stderr, "tsad: cannot read %s or listen on 127.0.0.1\n",
            argv[1]);
    return 99;
  }
  cmd = subst((const char *)t, port, dead);
  free(t);
  if (cmd == NULL)
    return 99;
  fflush(stdout);
#ifdef _WIN32
  th = CreateThread(NULL, 0, loop, NULL, 0, NULL);
  if (th == NULL)
    return 99;
  st = system(cmd);
  stop = 1;
  WaitForSingleObject(th, INFINITE);
  CloseHandle(th);
#else
  {
    pid_t p = fork();
    int ws = 0, i;
    if (p < 0)
      return 99;
    if (p == 0) {
      sclose(lsn);
      execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
      _exit(127);
    }
    /* at most 300 s: a client that hangs fails, not the whole run */
    for (i = 0; i < 3000; i++) {
      pid_t w = waitpid(p, &ws, WNOHANG);
      if (w == p)
        break;
      if (once() == 0)
        continue;
    }
    if (i == 3000) {
      kill(p, SIGKILL);
      waitpid(p, &ws, 0);
      fprintf(stderr, "tsad: the client did not finish in 300 s\n");
      return 98;
    }
    st = WIFEXITED(ws) ? WEXITSTATUS(ws) : 97;
  }
#endif
  sclose(lsn);
  free(cmd);
  printf("tsad: served %d requests\n", nserved);
  return st;
}
