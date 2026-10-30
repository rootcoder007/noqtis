/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A test client for tests/tls/srv.sh: connects to 127.0.0.1 (or ::1
 * with -6) on a port, runs the TLS 1.3 client for a host name with the
 * given anchors, sends an HTTP/1.0 GET and prints what it learned:
 *
 *   tlcli [-1] [-6] host port anchors.pem [path]
 *
 * -1 sends the X25519MLKEM768 share only (a server without it must
 * answer with a HelloRetryRequest). Prints "ok <suite> <group> <hrr>
 * <bytes>" and the reply's first line, or "fail: <why>" and exits 1.
 * POSIX only; uses the internal API (nqtlmk, hooks). */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/json.h"
#include "core/int.h"
#include "tls/tls.h"

static int swr(void *u, const uint8_t *b, size_t n) {
  int s = *(int *)u;
  while (n > 0) {
    ssize_t k = send(s, b, n, 0);
    if (k <= 0) return NQEIO;
    b += k;
    n -= (size_t)k;
  }
  return NQOK;
}

static int srd(void *u, uint8_t *b, size_t cap, size_t *got) {
  ssize_t k = recv(*(int *)u, b, cap, 0);
  if (k < 0) return NQEIO;
  *got = (size_t)k;
  return NQOK;
}

int main(int argc, char **argv) {
  static uint8_t buf[1 << 20];
  int a = 1, one = 0, v6 = 0, s, rc;
  const char *path = "/";
  char req[512];
  char *ca = NULL;
  size_t can = 0, tot = 0, got = 0;
  nqtls *t = NULL;
  nqtlio io;
  nqtlhk hk;
  while (a < argc && argv[a][0] == '-') {
    if (strcmp(argv[a], "-1") == 0) one = 1;
    if (strcmp(argv[a], "-6") == 0) v6 = 1;
    a++;
  }
  if (argc - a < 3) {
    fprintf(stderr, "usage: tlcli [-1] [-6] host port anchors [path]\n");
    return 2;
  }
  if (argc - a > 3) path = argv[a + 3];
  if (nqreadf(argv[a + 2], 1u << 24, &ca, &can) != NQOK) {
    fprintf(stderr, "cannot read %s\n", argv[a + 2]);
    return 2;
  }
  if (v6) {
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons((uint16_t)atoi(argv[a + 1]));
    inet_pton(AF_INET6, "::1", &sa.sin6_addr);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    rc = connect(s, (struct sockaddr *)&sa, sizeof sa);
  } else {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[a + 1]));
    sa.sin_addr.s_addr = htonl(0x7f000001);
    s = socket(AF_INET, SOCK_STREAM, 0);
    rc = connect(s, (struct sockaddr *)&sa, sizeof sa);
  }
  if (s < 0 || rc != 0) {
    printf("fail: cannot connect\n");
    return 1;
  }
  io.wr = swr;
  io.rd = srd;
  io.user = &s;
  rc = nqtlmk(&t, argv[a], (const uint8_t *)ca, can, &io);
  nqfree(ca, can + 1);
  if (rc != NQOK) {
    printf("fail: nqtlmk %s\n", nqerr(rc));
    return 1;
  }
  memset(&hk, 0, sizeof hk);
  hk.one = one;
  nqtlhook(t, &hk);
  if ((rc = nqtlhand(t)) != NQOK) {
    printf("fail: %s (%s)\n", t->why, nqerr(rc));
    nqtlfree(t);
    close(s);
    return 1;
  }
  snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path,
           argv[a]);
  if ((rc = nqtlw(t, (const uint8_t *)req, strlen(req))) != NQOK) {
    printf("fail: %s\n", t->why);
    return 1;
  }
  for (;;) {
    rc = nqtlr(t, buf + tot, sizeof buf - tot - 1, &got);
    if (rc != NQOK || got == 0) break;
    tot += got;
  }
  buf[tot] = 0;
  printf("ok %04x %04x %d %lu%s\n", t->suite, t->grp, t->hrr,
         (unsigned long)tot, rc == NQOK ? "" : " (no close_notify)");
  if (rc != NQOK) printf("note: %s\n", t->why);
  {
    char *e = strstr((char *)buf, "\r\n");
    if (e != NULL) *e = 0;
    printf("%s\n", (char *)buf);
  }
  (void)nqtle(t);
  nqtlfree(t);
  close(s);
  return 0;
}
