/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the text decoders: the library's base64
 * (capsules: strict, padded) and hex (vectors, manifests), the command
 * line tool's constant-time base64 (key files: line breaks allowed) and
 * hex, the capsule path normaliser and the RFC 3339 check. The two
 * base64 decoders must agree on any input without line breaks, the two
 * hex decoders on any input, and decoding what was encoded must give the
 * bytes back; a normalised path must normalise to itself. */
#include "fz.h"
#include "cap/cap.h"
#include "cli.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

static void b64(const char *s, size_t n) {
  uint8_t *a = (uint8_t *)malloc(n + 1), *b = (uint8_t *)malloc(n + 1);
  size_t an = 0, bn = 0;
  int ra, rb, lb = memchr(s, '\n', n) != NULL || memchr(s, '\r', n) != NULL;
  if (a == NULL || b == NULL) goto out;
  ra = nqb64d(s, n, a, n, &an);
  rb = ncb64d(s, n, b, n, &bn);
  if (!lb && ((ra == NQOK) != (rb == NQOK) ||
              (ra == NQOK && (an != bn || memcmp(a, b, an) != 0)))) {
    abort();
  }
  /* tight output buffers */
  if (ra == NQOK && an > 0 && nqb64d(s, n, a, an - 1, &an) != NQEBUF) {
    abort();
  }
  if (rb == NQOK && bn > 0 && ncb64d(s, n, b, bn - 1, &bn) == NQOK) {
    abort();
  }
out:
  free(a);
  free(b);
}

static void hex(const char *s, size_t n) {
  uint8_t *a = (uint8_t *)malloc(n / 2 + 1), *b = (uint8_t *)malloc(n / 2 + 1);
  size_t an = 0, bn = 0;
  int ra, rb;
  if (a == NULL || b == NULL) goto out;
  ra = nqunhex(s, n, a, n / 2, &an);
  rb = nchexd(s, n, b, n / 2, &bn);
  if ((ra == NQOK) != (rb == NQOK) ||
      (ra == NQOK && (an != bn || memcmp(a, b, an) != 0))) {
    abort();
  }
out:
  free(a);
  free(b);
}

/* encode, decode, compare */
static void trip(const uint8_t *p, size_t n) {
  size_t en = nqb64n(n), cn = ncb64n(n), k = 0;
  char *e = (char *)malloc(en + 1), *c = (char *)malloc(cn + 1);
  char *h = (char *)malloc(2 * n + 1);
  uint8_t *d = (uint8_t *)malloc(n + 1);
  if (e == NULL || c == NULL || h == NULL || d == NULL) goto out;
  nqb64e(p, n, e);
  if (strlen(e) != en || nqb64d(e, en, d, n, &k) != NQOK || k != n ||
      memcmp(d, p, n) != 0) {
    abort();
  }
  ncb64e(p, n, c);
  if (ncb64d(c, cn, d, n, &k) != NQOK || k != n || memcmp(d, p, n) != 0) {
    abort();
  }
  nqhex(p, n, h);
  if (nchexd(h, 2 * n, d, n, &k) != NQOK || k != n || memcmp(d, p, n) != 0) {
    abort();
  }
  nchexe(p, n, h);
  if (nqunhex(h, 2 * n, d, n, &k) != NQOK || k != n ||
      memcmp(d, p, n) != 0) {
    abort();
  }
out:
  free(e);
  free(c);
  free(h);
  free(d);
}

static void path(const char *s, size_t n) {
  static char a[NQCPATHMAX + 1], b[NQCPATHMAX + 1];
  size_t an = 0, bn = 0;
  if (nqcnorm(s, n, a, sizeof a, &an) != NQOK) return;
  if (an >= sizeof a || a[an] != 0 || strlen(a) != an) abort();
  if (nqcnorm(a, an, b, sizeof b, &bn) != NQOK || bn != an ||
      memcmp(a, b, an) != 0) {
    abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *s;
  if (size == 0) return 0;
  /* one exact copy without the selector byte, for ASan */
  s = (char *)fzdup(data + 1, size - 1);
  if (s == NULL) return 0;
  switch (data[0] & 3) {
  case 0:
    b64(s, size - 1);
    break;
  case 1:
    hex(s, size - 1);
    break;
  case 2:
    trip((const uint8_t *)s, size - 1);
    break;
  default:
    path(s, size - 1);
    (void)nqctchk(s, size - 1);
    (void)nqcutf8(s, size - 1);
    break;
  }
  free(s);
  return 0;
}
