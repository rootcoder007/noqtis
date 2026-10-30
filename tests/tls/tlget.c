/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A test driver for the tool's HTTP client, for tests/tls/srv.sh and
 * tests/tls/net.sh. It includes cli/net.c itself, to reach its static
 * redirect resolver:
 *
 *   tlget URL          GET: prints "ok <bytes> <first line of body>"
 *   tlget -p URL FILE  POST FILE as an RFC 3161 request: "ok <bytes>"
 *   tlget -r URL LOC   prints the URL a redirect to LOC from URL names
 *   tlget -s URL LOC   prints "same" when that redirect stays on URL's
 *                      server (and is followed), "other" when refused
 *
 * or "fail: <why>" and exit 1. */
#include "../../cli/net.c"

#include <stdio.h>

/* io.c reports through ncmsg */
void ncmsg(const char *cmd, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", cmd);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

int main(int argc, char **argv) {
  char err[512];
  uint8_t *out = NULL, *q = NULL;
  size_t n = 0, qn = 0, i;
  int rc;
  if (argc == 4 && strcmp(argv[1], "-r") == 0) {
    ncurl u;
    char nx[2048];
    if (parse(argv[2], &u, err, sizeof err) != NCOK ||
        redir(argv[2], &u, argv[3], strlen(argv[3]), nx, sizeof nx) !=
            NCOK) {
      printf("fail\n");
      return 1;
    }
    printf("%s\n", nx);
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "-s") == 0) {
    ncurl a, b;
    char nx[2048];
    if (parse(argv[2], &a, err, sizeof err) != NCOK ||
        redir(argv[2], &a, argv[3], strlen(argv[3]), nx, sizeof nx) !=
            NCOK ||
        parse(nx, &b, err, sizeof err) != NCOK) {
      printf("fail\n");
      return 1;
    }
    printf("%s\n", samehost(&a, &b) ? "same" : "other");
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "-p") == 0) {
    if (ncrdx(argv[3], 0, 1u << 20, &q, &qn) != NQOK) {
      printf("fail: cannot read %s\n", argv[3]);
      return 2;
    }
    rc = nchttp(argv[2], q, qn, &out, &n, err, sizeof err);
    ncfree(q, qn, 0);
  } else if (argc == 2) {
    rc = ncget(argv[1], (size_t)1 << 24, &out, &n, err, sizeof err);
  } else {
    fprintf(stderr, "usage: tlget URL | -p URL FILE | -r URL LOC | -s URL LOC\n");
    return 2;
  }
  if (rc != NCOK) {
    printf("fail: %s\n", err);
    return 1;
  }
  printf("ok %lu ", (unsigned long)n);
  for (i = 0; i < n && i < 60 && out[i] != '\n' && out[i] != '\r'; i++) {
    putchar(out[i] >= 0x20 && out[i] < 0x7f ? out[i] : '.');
  }
  putchar('\n');
  free(out);
  return 0;
}
