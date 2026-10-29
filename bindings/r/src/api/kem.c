/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The public key-encapsulation functions of noqtis.h: dispatch onto
 * ML-KEM (src/mlkem, masked decapsulation) and HQC (src/hqc).
 *
 * Checked here for every algorithm alike: an unknown alg, a NULL pointer
 * or a seed of the wrong length is NQEARG; an output buffer smaller than
 * the algorithm's size is NQEBUF (larger is fine; the module sees the
 * exact size). Input keys and ciphertexts of the wrong length are the
 * module's NQEDEC. On every failure the outputs are zeroed. */
#include <string.h>

#include "hqc/hqc.h"
#include "mlkem/mlkem.h"

static int ishq(nqkalg alg) {
  return alg == NQHQC128 || alg == NQHQC192 || alg == NQHQC256;
}

static int sizes(nqkalg alg, nqksz *sz) {
  int k = nqmkk(alg);
  if (k != 0) {
    sz->pk = NQMKEK(k);
    sz->sk = NQMKDK(k);
    sz->ct = NQMKCT(k);
    sz->ss = NQMKSS;
    return NQOK;
  }
  if (ishq(alg)) {
    return nqhqsz(alg, sz);
  }
  return NQEARG;
}

/* m (ML-KEM) or m || salt (HQC): the encapsulation seed length. */
static size_t eseed(nqkalg alg) {
  switch (alg) {
  case NQHQC128:
    return NQHQM1 + NQHQSALT;
  case NQHQC192:
    return NQHQM3 + NQHQSALT;
  case NQHQC256:
    return NQHQM5 + NQHQSALT;
  default:
    return NQMKMSG;
  }
}

int nqksize(nqkalg alg, nqksz *sz) {
  nqksz s;
  int rc;
  if (sz == NULL) {
    return NQEARG;
  }
  rc = sizes(alg, &s);
  if (rc == NQOK) {
    *sz = s;
  }
  return rc;
}

static const char *const names[6] = {"ML-KEM-512", "ML-KEM-768",
                                     "ML-KEM-1024", "HQC-128", "HQC-192",
                                     "HQC-256"};

const char *nqkname(nqkalg alg) {
  if (alg < NQMLKEM512 || alg > NQHQC256) {
    return NULL;
  }
  return names[alg - NQMLKEM512];
}

int nqkfind(const char *name, nqkalg *alg) {
  unsigned i;
  if (name == NULL || alg == NULL) {
    return NQEARG;
  }
  for (i = 0; i < 6; i++) {
    if (strcmp(name, names[i]) == 0) {
      *alg = (nqkalg)(NQMLKEM512 + (int)i);
      return NQOK;
    }
  }
  return NQENOSUP;
}

/* Zeroes a and b (either may be NULL) and returns rc. */
static int fail(int rc, uint8_t *a, size_t alen, uint8_t *b, size_t blen) {
  if (a != NULL) {
    nqwipe(a, alen);
  }
  if (b != NULL) {
    nqwipe(b, blen);
  }
  return rc;
}

static int kbuf(nqkalg alg, const uint8_t *pk, size_t pklen,
                const uint8_t *sk, size_t sklen, nqksz *sz) {
  int rc = sizes(alg, sz);
  if (rc != NQOK) {
    return rc;
  }
  if (pk == NULL || sk == NULL) {
    return NQEARG;
  }
  return pklen < sz->pk || sklen < sz->sk ? NQEBUF : NQOK;
}

int nqkkg(nqkalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
          size_t sklen) {
  nqksz sz;
  int rc = kbuf(alg, pk, pklen, sk, sklen, &sz);
  if (rc != NQOK) {
    return fail(rc, pk, pklen, sk, sklen);
  }
  if (ishq(alg)) {
    rc = nqhqkg(alg, pk, sz.pk, sk, sz.sk);
  } else {
    rc = nqmkkg(nqmkk(alg), pk, sz.pk, sk, sz.sk);
  }
  return rc == NQOK ? NQOK : fail(rc, pk, sz.pk, sk, sz.sk);
}

int nqkkgd(nqkalg alg, const uint8_t *seed, size_t seedlen, uint8_t *pk,
           size_t pklen, uint8_t *sk, size_t sklen) {
  nqksz sz;
  int rc = kbuf(alg, pk, pklen, sk, sklen, &sz);
  if (rc == NQOK && (seed == NULL ||
                     seedlen != (ishq(alg) ? (size_t)NQHQSEED
                                           : (size_t)NQMKSEED))) {
    rc = NQEARG;
  }
  if (rc != NQOK) {
    return fail(rc, pk, pklen, sk, sklen);
  }
  if (ishq(alg)) {
    rc = nqhqkgd(alg, seed, seedlen, pk, sz.pk, sk, sz.sk);
  } else {
    rc = nqmkkgd(nqmkk(alg), seed, seedlen, pk, sz.pk, sk, sz.sk);
  }
  return rc == NQOK ? NQOK : fail(rc, pk, sz.pk, sk, sz.sk);
}

/* ct and ss buffers, and an input key that is not NULL. */
static int cbuf(nqkalg alg, const uint8_t *key, uint8_t *ct, size_t ctlen,
                uint8_t *ss, size_t sslen, nqksz *sz) {
  int rc = sizes(alg, sz);
  if (rc != NQOK) {
    return rc;
  }
  if (key == NULL || ct == NULL || ss == NULL) {
    return NQEARG;
  }
  return ctlen < sz->ct || sslen < sz->ss ? NQEBUF : NQOK;
}

/* seed NULL: fresh randomness inside the module. */
static int enc(nqkalg alg, const uint8_t *pk, size_t pklen,
               const uint8_t *seed, size_t seedlen, uint8_t *ct,
               size_t ctlen, uint8_t *ss, size_t sslen) {
  nqksz sz;
  int rc = cbuf(alg, pk, ct, ctlen, ss, sslen, &sz);
  if (rc != NQOK) {
    return fail(rc, ct, ctlen, ss, sslen);
  }
  if (ishq(alg)) {
    rc = seed == NULL
             ? nqhqenc(alg, pk, pklen, ct, sz.ct, ss, sz.ss)
             : nqhqencd(alg, pk, pklen, seed, seedlen, ct, sz.ct, ss,
                        sz.ss);
  } else {
    rc = seed == NULL
             ? nqmkenc(nqmkk(alg), pk, pklen, ct, sz.ct, ss, sz.ss)
             : nqmkencd(nqmkk(alg), pk, pklen, seed, seedlen, ct, sz.ct,
                        ss, sz.ss);
  }
  return rc == NQOK ? NQOK : fail(rc, ct, sz.ct, ss, sz.ss);
}

int nqenc(nqkalg alg, const uint8_t *pk, size_t pklen, uint8_t *ct,
          size_t ctlen, uint8_t *ss, size_t sslen) {
  return enc(alg, pk, pklen, NULL, 0, ct, ctlen, ss, sslen);
}

int nqencd(nqkalg alg, const uint8_t *pk, size_t pklen,
           const uint8_t *seed, size_t seedlen, uint8_t *ct, size_t ctlen,
           uint8_t *ss, size_t sslen) {
  nqksz sz;
  if (sizes(alg, &sz) != NQOK || seed == NULL ||
      seedlen != eseed(alg)) {
    return fail(NQEARG, ct, ct == NULL ? 0 : ctlen, ss,
                ss == NULL ? 0 : sslen);
  }
  return enc(alg, pk, pklen, seed, seedlen, ct, ctlen, ss, sslen);
}

int nqdec(nqkalg alg, const uint8_t *sk, size_t sklen, const uint8_t *ct,
          size_t ctlen, uint8_t *ss, size_t sslen) {
  nqksz sz;
  int rc = sizes(alg, &sz);
  if (rc == NQOK && (sk == NULL || ct == NULL || ss == NULL)) {
    rc = NQEARG;
  }
  if (rc == NQOK && sslen < sz.ss) {
    rc = NQEBUF;
  }
  if (rc != NQOK) {
    return fail(rc, ss, sslen, NULL, 0);
  }
  if (ishq(alg)) {
    rc = nqhqdec(alg, sk, sklen, ct, ctlen, ss, sz.ss);
  } else {
    rc = nqmkdec(nqmkk(alg), sk, sklen, ct, ctlen, ss, sz.ss);
  }
  return rc == NQOK ? NQOK : fail(rc, ss, sz.ss, NULL, 0);
}
