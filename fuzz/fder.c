/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the DER reader, the X.509, OCSP and CRL parsers
 * and the RFC 3161 verifier. Signatures are accepted by a stub, so the
 * fuzzer reaches every check after them.
 *
 *   clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
 *     -Iinclude -Isrc src/der/ *.c src/core/ *.c src/hash/ *.c \
 *     fuzz/fder.c -o fder          (without the spaces before *.c)
 *   NQDFIX=tests/vectors/der/local ./fder corpus/ -max_total_time=600
 *
 * NQDFIX names the folder holding rsa_leaf_good.der, rsa_inter.der and
 * rsa_root.der: the path the OCSP and CRL checks run against. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/json.h"
#include "der/tsp.h"
#include "der/x509.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int yes(void *user, const nqxvreq *r) {
  (void)user;
  /* touch what the callback is given */
  return r->msg.n > 0 && r->sig.n > 0 && r->key->spki.n > 0 ? NQOK
                                                              : NQEVRFY;
}

static int sha1(void *user, const uint8_t *in, size_t len, uint8_t out[20]) {
  /* not SHA-1: any 20 bytes do for the parser */
  uint8_t d[32];
  (void)user;
  nqhash(NQS256, in, len, d, 32);
  memcpy(out, d, 20);
  return NQOK;
}

static const nqxops ops = {yes, sha1, NULL};
static nqcert fix[3];
static char *fixb[3];
static size_t fixn[3];
static int nfix = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  static const char *names[3] = {"rsa_leaf_good.der", "rsa_inter.der",
                                 "rsa_root.der"};
  const char *dir = getenv("NQDFIX");
  char path[512];
  int i;
  (void)argc;
  (void)argv;
  if (dir == NULL) {
    dir = "tests/vectors/der/local";
  }
  for (i = 0; i < 3; i++) {
    snprintf(path, sizeof path, "%s/%s", dir, names[i]);
    if (nqreadf(path, 1u << 20, &fixb[i], &fixn[i]) != NQOK ||
        nqcprs((const uint8_t *)fixb[i], fixn[i], &fix[i]) != NQOK) {
      fprintf(stderr, "fder: no fixture %s\n", path);
      return 0;
    }
  }
  nfix = 3;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqdtlv t;
  nqcert c;
  nqts *ts;
  nqdcur cur;
  int r;
  static nqts tsbuf;
  ts = &tsbuf;
  /* the reader alone, and a cursor walk of the top level */
  (void)nqdone(data, size, &t);
  nqdinit(&cur, data, size);
  while (nqdnext(&cur, &t) == NQOK) {
    nqdcur in;
    nqdtlv u;
    if (t.con && nqddown(&t, &in) == NQOK) {
      while (nqdnext(&in, &u) == NQOK) {
        int64_t v;
        uint32_t ns;
        (void)nqdi64(&u, &v);
        (void)nqdtime(&u, NQDTFRAC, &v, &ns);
        (void)nqdtime(&u, NQDT5280, &v, &ns);
      }
    }
  }
  /* a certificate, alone and as a one-link path */
  r = nqcprs(data, size, &c);
  if (r == NQOK) {
    const nqcert *path[NQXMAXPATH];
    nqxchk k;
    size_t np;
    (void)nqxneq(c.issuer, c.subject);
    k.anc = &c;
    k.nanc = 1;
    k.pool = &c;
    k.npool = 1;
    k.t = c.nb;
    k.eku = NQXEKUTS;
    k.ops = &ops;
    (void)nqchain(&c, &k, path, NQXMAXPATH, &np);
    if (nfix == 3) {
      k.anc = &fix[2];
      k.pool = &fix[1];
      (void)nqchain(&c, &k, path, NQXMAXPATH, &np);
    }
  }
  /* a token: verified against its own first certificate */
  r = nqtsprs(data, size, ts);
  if (r == NQOK && ts->ncert > 0) {
    nqcert anc;
    nqtsarg a;
    if (nqcprs(ts->certs[ts->ncert - 1].p, ts->certs[ts->ncert - 1].n,
               &anc) == NQOK) {
      memset(&a, 0, sizeof a);
      a.halg = ts->ialg;
      a.dig = ts->imp.p;
      a.diglen = ts->imp.n;
      a.nonce = ts->nonce.p;
      a.noncelen = ts->nonce.n;
      a.anc = &anc;
      a.nanc = 1;
      a.ops = &ops;
      (void)nqtsvrf(data, size, &a, ts);
    }
  }
  /* OCSP and CRL about the fixture path */
  if (nfix == 3) {
    const nqcert *path[3];
    int st;
    path[0] = &fix[0];
    path[1] = &fix[1];
    path[2] = &fix[2];
    (void)nqocsp(data, size, path, 3, 0, fix[0].nb + 3600, &ops, &st);
    (void)nqcrl(data, size, path, 3, 0, fix[0].nb + 3600, &ops);
    (void)nqcrl(data, size, path, 3, 1, fix[0].nb + 3600, &ops);
  }
  return 0;
}
