/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the TLS client's certificate inputs: the input
 * cut in two (fzpart), the first piece as a trust-anchor bundle (PEM or
 * DER) and the second as a host name; every anchor parsed is then
 * matched against the name (nqtlname), the name is read as an address
 * (nqtlip), and the whole input as a ClientHello (nqtlscan). */
#include "fz.h"
#include "tls/tls.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  return 0;
}

static int nwr(void *u, const uint8_t *b, size_t n) {
  (void)u;
  (void)b;
  (void)n;
  return NQOK;
}

static int nrd(void *u, uint8_t *b, size_t cap, size_t *got) {
  (void)u;
  (void)b;
  (void)cap;
  *got = 0;
  return NQOK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const nqtlio io = {nwr, nrd, NULL};
  fzin in;
  nqtloff off;
  nqtls *t = NULL;
  const uint8_t *b, *h;
  size_t bn, hn, i;
  char host[300];
  uint8_t ip[16];
  int k;
  in.p = data;
  in.n = size;
  b = fzpart(&in, &bn);
  h = fzpart(&in, &hn);
  if (hn >= sizeof host) hn = sizeof host - 1;
  memcpy(host, h, hn);
  host[hn] = '\0';
  k = nqtlip(host, ip);
  (void)nqtlscan(data, size, &off);
  if (nqtlmk(&t, "localhost", b, bn, &io) != NQOK) return 0;
  for (i = 0; i < t->nanc; i++) {
    (void)nqtlname(&t->anc[i], host, k, ip);
    (void)nqtlname(&t->anc[i], "localhost", 0, NULL);
  }
  nqtlfree(t);
  return 0;
}
