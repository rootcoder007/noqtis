/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the RFC 3161 parser and verifier: the input as a
 * TimeStampResp or bare token, verified against its own last
 * certificate with every signature accepted by a stub (to reach every
 * check after the signatures), and against the local TSA roots (RSA,
 * EC, ML-DSA, and the capsule tests' TSA) with the real verifiers. */
#include "fz.h"
#include "cap/cap.h"
#include "der/tsp.h"

static nqcert anc[4];
static size_t nanc = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  if (fzcert("rsa_root.der", &anc[nanc])) nanc++;
  if (fzcert("ec_root.der", &anc[nanc])) nanc++;
  if (fzcert("ml_root.der", &anc[nanc])) nanc++;
  if (fzcert("tsa_root.der", &anc[nanc])) nanc++;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static nqts ts, ts2;
  nqtsarg a;
  nqcert own;
  if (nqtsprs(data, size, &ts) != NQOK) return 0;
  memset(&a, 0, sizeof a);
  a.halg = ts.ialg;
  a.dig = ts.imp.p;
  a.diglen = ts.imp.n;
  a.nonce = ts.hasnonce ? ts.nonce.p : NULL;
  a.noncelen = ts.hasnonce ? ts.nonce.n : 0;
  a.pol = ts.policy.p;
  a.pollen = ts.policy.n;
  if (ts.ncert > 0 &&
      nqcprs(ts.certs[ts.ncert - 1].p, ts.certs[ts.ncert - 1].n, &own) ==
          NQOK) {
    a.anc = &own;
    a.nanc = 1;
    a.ops = &fzops;
    (void)nqtsvrf(data, size, &a, &ts2);
    /* and at a time of the caller's, with the anchor as an extra */
    a.extra = &own;
    a.nextra = 1;
    a.uset = 1;
    a.t = own.nb + 60;
    (void)nqtsvrf(data, size, &a, &ts2);
    a.extra = NULL;
    a.nextra = 0;
    a.uset = 0;
  }
  if (nanc > 0) {
    a.anc = anc;
    a.nanc = nanc;
    a.ops = nqcxops();
    (void)nqtsvrf(data, size, &a, &ts2);
  }
  return 0;
}
