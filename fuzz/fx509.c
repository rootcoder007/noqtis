/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the X.509 certificate parser and the path
 * checks: the input as a certificate, alone and as a one-link path,
 * then as a leaf under the local PKI (tests/vectors/der/local: rsa_inter
 * under rsa_root), with every signature accepted by a stub (to reach
 * the checks after it) and again with the real verifiers (RSA, ECDSA,
 * ML-DSA, SLH-DSA through src/cls and nqvrfy). */
#include "fz.h"
#include "cap/cap.h"

static nqcert anc[3], pool[2];
static size_t nanc = 0, npool = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  if (fzcert("rsa_root.der", &anc[nanc])) nanc++;
  if (fzcert("ec_root.der", &anc[nanc])) nanc++;
  if (fzcert("ml_root.der", &anc[nanc])) nanc++;
  if (fzcert("rsa_inter.der", &pool[npool])) npool++;
  if (fzcert("rsa_inter2.der", &pool[npool])) npool++;
  return 0;
}

static void chain(const nqcert *leaf, const nqcert *a, size_t na,
                  const nqcert *p, size_t np, int64_t t, uint32_t eku,
                  const nqxops *ops) {
  const nqcert *path[NQXMAXPATH];
  nqxchk k;
  size_t n = 0;
  k.anc = a;
  k.nanc = na;
  k.pool = p;
  k.npool = np;
  k.t = t;
  k.eku = eku;
  k.ops = ops;
  (void)nqchain(leaf, &k, path, NQXMAXPATH, &n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqcert c;
  size_t i;
  if (nqcprs(data, size, &c) != NQOK) return 0;
  (void)nqxneq(c.issuer, c.subject);
  for (i = 0; i < nanc; i++) {
    (void)nqxalias(&c, &anc[i]);
  }
  /* self-issued: the input is its own anchor and pool */
  chain(&c, &c, 1, &c, 1, c.nb, NQXEKUTS, &fzops);
  chain(&c, &c, 1, NULL, 0, c.na, 0, nqcxops());
  /* a leaf under the local PKI */
  if (nanc > 0) {
    chain(&c, anc, nanc, pool, npool, c.nb + 60, NQXEKUTS, &fzops);
    chain(&c, anc, nanc, pool, npool, c.nb + 60, 0, nqcxops());
  }
  /* the input as an intermediate */
  if (npool > 0) {
    chain(&pool[0], anc, nanc, &c, 1, pool[0].nb + 60, 0, &fzops);
  }
  return 0;
}
