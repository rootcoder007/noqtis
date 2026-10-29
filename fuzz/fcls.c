/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the classical public key parsers and verifiers
 * (src/cls): SubjectPublicKeyInfo, RSAPublicKey, SEC 1 points on P-256
 * and P-384, RSASSA-PSS-params and DER ECDSA signatures; then RSA
 * PKCS#1 v1.5, PSS and ECDSA verification with whatever key parsed.
 *
 * Input: a selector byte, then length-prefixed pieces (fz.h): the key,
 * the signature, the message. */
#include "fz.h"
#include "cls/cls.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

static const nqhalg hs[8] = {NQS256, NQS384, NQS512, NQS224,
                             NQS3256, NQS3512, NQSHK128, NQSHK256};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fzin in;
  unsigned sel;
  const uint8_t *kp, *sp, *mp, *r, *s;
  size_t kn, sn, mn, rl, sl;
  uint8_t *key, *sig, *msg;
  nqck k;
  nqpss pp;
  nqhalg h;
  int rc;
  in.p = data;
  in.n = size;
  sel = fzbyte(&in);
  kp = fzpart(&in, &kn);
  sp = fzpart(&in, &sn);
  mp = fzpart(&in, &mn);
  key = fzdup(kp, kn);
  sig = fzdup(sp, sn);
  msg = fzdup(mp, mn);
  if (key == NULL || sig == NULL || msg == NULL) goto out;
  h = hs[sel & 7];
  (void)nqcdsig(sig, sn, &r, &rl, &s, &sl);
  (void)nqpssp(&pp, key, kn);
  switch ((sel >> 3) & 3) {
  case 0:
    rc = nqckey(&k, key, kn);
    break;
  case 1:
    rc = nqrsapk(&k, key, kn);
    break;
  default:
    rc = nqecpk(&k, (sel >> 3) & 1 ? NQP384 : NQP256, key, kn);
    break;
  }
  if (rc != NQOK) goto out;
  if (k.kind == NQKRSA) {
    (void)nqrsav(&k, h, msg, mn, sig, sn);
    (void)nqrsavh(&k, h, msg, mn, sig, sn);
    pp.h = h;
    pp.mgf = (sel & 0x40) ? NQS256 : h;
    pp.slen = (sel & 0x80) ? 0 : nqhlen(h);
    if (k.pss == 2) pp = k.pp;
    (void)nqpssv(&k, &pp, msg, mn, sig, sn);
    (void)nqpssvh(&k, &pp, msg, mn, sig, sn);
  } else {
    (void)nqecv(&k, h, msg, mn, sig, sn, 0);
    (void)nqecv(&k, h, msg, mn, sig, sn, 1);
    (void)nqecvh(&k, msg, mn, sig, sn, (sel >> 5) & 1);
  }
out:
  free(key);
  free(sig);
  free(msg);
  return 0;
}
