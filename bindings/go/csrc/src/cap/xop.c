/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The signature callbacks src/der needs to check a timestamp token:
 * RSA PKCS#1 v1.5, RSA-PSS and ECDSA through src/cls, ML-DSA and SLH-DSA
 * through nqvrfy, and SHA-1 (ESS signingCertificate v1, key identifiers)
 * through src/hash. Anything else is NQENOSUP; a signature that does not
 * verify is NQEVRFY. */
#include "cap/cap.h"
#include "cls/cls.h"
#include "hash/h.h"

static int xvrfy(void *user, const nqxvreq *r) {
  nqck k;
  nqpss pp;
  int rc;
  (void)user;
  if (r == NULL || r->key == NULL) return NQEARG;
  if (r->alg.kind == NQXPQ) {
    rc = nqvrfy(r->alg.pq, r->key->key.p, r->key->key.n, r->msg.p,
                r->msg.n, NULL, 0, 0, r->sig.p, r->sig.n);
    return rc == NQOK ? NQOK : NQEVRFY;
  }
  if (r->dig == NULL || nqckey(&k, r->key->spki.p, r->key->spki.n) != NQOK) {
    return NQEVRFY;
  }
  switch (r->alg.kind) {
  case NQXRSA:
    rc = nqrsavh(&k, r->alg.h, r->dig, r->diglen, r->sig.p, r->sig.n);
    break;
  case NQXPSS:
    pp.h = r->alg.h;
    pp.mgf = r->alg.h;
    pp.slen = nqhlen(r->alg.h);
    rc = nqpssvh(&k, &pp, r->dig, r->diglen, r->sig.p, r->sig.n);
    break;
  case NQXECDSA:
    rc = nqecvh(&k, r->dig, r->diglen, r->sig.p, r->sig.n, 0);
    break;
  default:
    return NQENOSUP;
  }
  return rc == NQOK ? NQOK : NQEVRFY;
}

const nqxops *nqcxops(void) {
  static const nqxops ops = {xvrfy, nqs1hk, NULL};
  return &ops;
}
