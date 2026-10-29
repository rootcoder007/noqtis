/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the OCSP response and CRL checks: the input as
 * an OCSPResponse and as a CRL about rsa_leaf_good (issued by rsa_inter
 * under rsa_root, tests/vectors/der/local), and about rsa_inter itself,
 * with every signature accepted by a stub and again with the real
 * verifiers. */
#include "fz.h"
#include "cap/cap.h"

static nqcert leaf, inter, root;
static int ok = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  ok = fzcert("rsa_leaf_good.der", &leaf) && fzcert("rsa_inter.der", &inter) &&
       fzcert("rsa_root.der", &root);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const nqcert *path[3];
  int64_t t;
  int st;
  if (!ok) return 0;
  path[0] = &leaf;
  path[1] = &inter;
  path[2] = &root;
  t = leaf.nb + 3600;
  (void)nqocsp(data, size, path, 3, 0, t, &fzops, &st);
  (void)nqocsp(data, size, path, 3, 0, t, nqcxops(), &st);
  (void)nqocsp(data, size, path, 3, 1, t, &fzops, &st);
  (void)nqcrl(data, size, path, 3, 0, t, &fzops);
  (void)nqcrl(data, size, path, 3, 0, t, nqcxops());
  (void)nqcrl(data, size, path + 1, 2, 0, t, &fzops);
  return 0;
}
