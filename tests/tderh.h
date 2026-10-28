/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Shared by tder.c, tx509.c and ttsp.c: fixture loading, a SHA-1 for the
 * OCSP / ESS forms that need one (test code only; the module takes it
 * through nqxops), and the signature oracle.
 *
 * The oracle is the stub verify callback. It accepts a signature only
 * when the exact (algorithm, key, signed bytes, signature) it is asked
 * about is listed in vectors/der/oracle.txt, and that file lists only
 * requests OpenSSL 3.5 verified independently (oracle.sh). So a test
 * sees what a correct verifier would say about the fixtures and about
 * any mutation of them: a mutated request can only verify by matching a
 * listed one exactly, which no mutation of the signed bytes, the key or
 * the signature does.
 *
 * Record mode (NQDREC=file in the environment) accepts everything and
 * appends each request to file, for oracle.sh. */
#ifndef TDERH_H
#define TDERH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/int.h"
#include "core/json.h"
#include "der/tsp.h"
#include "der/x509.h"
#include "hash/h.h"
#include "noqtis.h"

/* ---- files ---- */

typedef struct {
  uint8_t *p;
  size_t n;
} tdbuf;

static inline tdbuf tdread(const char *path) {
  tdbuf b = {NULL, 0};
  char *s = NULL;
  size_t n = 0;
  if (nqreadf(path, (size_t)1 << 22, &s, &n) != NQOK) {
    fprintf(stderr, "cannot read %s\n", path);
    return b;
  }
  b.p = (uint8_t *)s;
  b.n = n;
  return b;
}

static inline void tdfree(tdbuf *b) {
  if (b->p != NULL) {
    nqfree(b->p, b->n + 1);
  }
  b->p = NULL;
  b->n = 0;
}

/* name|hex lines (the rmoriebricklayer fixture format) */
#define TDMAXFX 64
typedef struct {
  char name[48];
  tdbuf b;
} tdfx;

static inline size_t tdlines(const char *path, tdfx *fx, size_t cap) {
  tdbuf f = tdread(path);
  size_t n = 0, i = 0;
  while (f.p != NULL && i < f.n && n < cap) {
    size_t j = i, bar, len;
    while (j < f.n && f.p[j] != '\n') {
      j++;
    }
    if (j > i && f.p[i] != '#') {
      for (bar = i; bar < j && f.p[bar] != '|'; bar++) {
      }
      len = bar - i < sizeof fx[n].name - 1 ? bar - i
                                            : sizeof fx[n].name - 1;
      memcpy(fx[n].name, f.p + i, len);
      fx[n].name[len] = 0;
      fx[n].b.n = (j - bar - 1) / 2;
      fx[n].b.p = (uint8_t *)nqmal(fx[n].b.n + 1);
      if (fx[n].b.p != NULL &&
          nqunhex((const char *)f.p + bar + 1, j - bar - 1, fx[n].b.p,
                  fx[n].b.n, &fx[n].b.n) == NQOK) {
        n++;
      }
    }
    i = j + 1;
  }
  tdfree(&f);
  return n;
}

static inline const tdbuf *tdget(const tdfx *fx, size_t n, const char *name) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (strcmp(fx[i].name, name) == 0) {
      return &fx[i].b;
    }
  }
  fprintf(stderr, "no fixture %s\n", name);
  return NULL;
}

/* ---- SHA-1 (FIPS 180-4), for the tests' nqxops only ---- */

static inline uint32_t tdrol(uint32_t x, unsigned k) {
  return (x << k) | (x >> (32u - k));
}

static inline void tdsha1blk(uint32_t h[5], const uint8_t *b) {
  uint32_t w[80], a, bb, c, d, e, f, k, t;
  unsigned i;
  for (i = 0; i < 16; i++) {
    w[i] = nqld32b(b + 4 * i);
  }
  for (i = 16; i < 80; i++) {
    w[i] = tdrol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }
  a = h[0];
  bb = h[1];
  c = h[2];
  d = h[3];
  e = h[4];
  for (i = 0; i < 80; i++) {
    if (i < 20) {
      f = (bb & c) | (~bb & d);
      k = 0x5a827999u;
    } else if (i < 40) {
      f = bb ^ c ^ d;
      k = 0x6ed9eba1u;
    } else if (i < 60) {
      f = (bb & c) | (bb & d) | (c & d);
      k = 0x8f1bbcdcu;
    } else {
      f = bb ^ c ^ d;
      k = 0xca62c1d6u;
    }
    t = tdrol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = tdrol(bb, 30);
    bb = a;
    a = t;
  }
  h[0] += a;
  h[1] += bb;
  h[2] += c;
  h[3] += d;
  h[4] += e;
}

static inline int tdsha1(void *user, const uint8_t *in, size_t len,
                  uint8_t out[20]) {
  uint32_t h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                   0xc3d2e1f0u};
  uint8_t blk[64];
  size_t i, r;
  (void)user;
  for (i = 0; i + 64 <= len; i += 64) {
    tdsha1blk(h, in + i);
  }
  r = len - i;
  memset(blk, 0, sizeof blk);
  memcpy(blk, in + i, r);
  blk[r] = 0x80;
  if (r >= 56) {
    tdsha1blk(h, blk);
    memset(blk, 0, sizeof blk);
  }
  nqst64b(blk + 56, (uint64_t)len * 8u);
  tdsha1blk(h, blk);
  for (i = 0; i < 5; i++) {
    nqst32b(out + 4 * i, h[i]);
  }
  return NQOK;
}

/* ---- the oracle ---- */

#define TDMAXOR 4096
static uint8_t tdor[TDMAXOR][32];
static size_t tdorn = 0;
static FILE *tdrec = NULL;
static unsigned long tdcalls = 0;

static inline void tdu32(nqs2ctx *c, size_t n) {
  uint8_t b[4];
  nqst32b(b, (uint32_t)n);
  nqs2upd(c, b, 4);
}

/* The oracle key of a request. */
static inline void tdkey(const nqxvreq *r, uint8_t out[32]) {
  nqs2ctx c;
  uint8_t a[3];
  a[0] = (uint8_t)r->alg.kind;
  a[1] = (uint8_t)r->alg.h;
  a[2] = (uint8_t)r->alg.pq;
  nqs2ini(&c, 32);
  nqs2upd(&c, a, 3);
  tdu32(&c, r->key->spki.n);
  nqs2upd(&c, r->key->spki.p, r->key->spki.n);
  tdu32(&c, r->msg.n);
  nqs2upd(&c, r->msg.p, r->msg.n);
  tdu32(&c, r->sig.n);
  nqs2upd(&c, r->sig.p, r->sig.n);
  nqs2fin(&c, out);
}

static inline void tdhexout(FILE *f, const uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    fprintf(f, "%02x", p[i]);
  }
}

#ifdef NQDCLS
#include "cls/cls.h"
/* With -DNQDCLS the classical signatures also go to the real verifiers
 * of src/cls, and every answer is compared with the oracle's. */
static unsigned long tddiff = 0;
static inline int tdcls(const nqxvreq *r) {
  nqck k;
  nqpss pp;
  if (nqckey(&k, r->key->spki.p, r->key->spki.n) != NQOK) {
    return NQEVRFY;
  }
  switch (r->alg.kind) {
  case NQXRSA:
    return nqrsavh(&k, r->alg.h, r->dig, r->diglen, r->sig.p, r->sig.n);
  case NQXPSS:
    pp.h = r->alg.h;
    pp.mgf = r->alg.h;
    pp.slen = nqhlen(r->alg.h);
    return nqpssvh(&k, &pp, r->dig, r->diglen, r->sig.p, r->sig.n);
  case NQXECDSA:
    return nqecvh(&k, r->dig, r->diglen, r->sig.p, r->sig.n, 0);
  default:
    return NQENOSUP;
  }
}
#endif

static inline int tdorv(const nqxvreq *r);

static inline int tdvrfy(void *user, const nqxvreq *r) {
  (void)user;
#ifdef NQDCLS
  if (tdrec == NULL && r->alg.kind != NQXPQ) {
    int a = tdcls(r), b = tdorv(r);
    if ((a == NQOK) != (b == NQOK)) {
      tddiff++;
      fprintf(stderr, "cls says %d, the oracle %d\n", a, b);
    }
    return a == NQOK ? NQOK : NQEVRFY;
  }
#endif
  return tdorv(r);
}

static inline int tdorv(const nqxvreq *r) {
  uint8_t k[32], d[NQHMAX];
  size_t i;
  tdcalls++;
  /* the digest the module passes is the digest of the message */
  if (r->alg.kind != NQXPQ) {
    if (r->dig == NULL || r->diglen != nqhlen(r->alg.h) ||
        nqhash(r->alg.h, r->msg.p, r->msg.n, d, r->diglen) != NQOK ||
        memcmp(d, r->dig, r->diglen) != 0) {
      return NQEARG;
    }
  }
  tdkey(r, k);
  if (tdrec != NULL) {
    tdhexout(tdrec, k, 32);
    fprintf(tdrec, " %d %d %d ", (int)r->alg.kind, (int)r->alg.h,
            (int)r->alg.pq);
    tdhexout(tdrec, r->key->spki.p, r->key->spki.n);
    fputc(' ', tdrec);
    tdhexout(tdrec, r->msg.p, r->msg.n);
    fputc(' ', tdrec);
    tdhexout(tdrec, r->sig.p, r->sig.n);
    fputc('\n', tdrec);
    return NQOK;
  }
  for (i = 0; i < tdorn; i++) {
    if (memcmp(tdor[i], k, 32) == 0) {
      return NQOK;
    }
  }
  return NQEVRFY;
}

/* Loads the oracle (or opens the record file). 1 in record mode. */
static inline int tdorinit(void) {
  const char *rec = getenv("NQDREC");
  tdbuf f;
  size_t i = 0;
  if (rec != NULL && rec[0] != 0) {
    tdrec = fopen(rec, "a");
    return tdrec != NULL;
  }
  f = tdread("vectors/der/oracle.txt");
  while (f.p != NULL && i + 64 <= f.n && tdorn < TDMAXOR) {
    size_t got = 0;
    if (nqunhex((const char *)f.p + i, 64, tdor[tdorn], 32, &got) == NQOK &&
        got == 32) {
      tdorn++;
    }
    while (i < f.n && f.p[i] != '\n') {
      i++;
    }
    i++;
  }
  tdfree(&f);
  return 0;
}

static inline void tdordone(void) {
  if (tdrec != NULL) {
    fclose(tdrec);
    tdrec = NULL;
  }
}

/* The oracle as nqxops, with (sha1 1) or without the test SHA-1. */
static inline const nqxops *tdops(int sha1) {
  static const nqxops with = {tdvrfy, tdsha1, NULL};
  static const nqxops without = {tdvrfy, NULL, NULL};
  return sha1 ? &with : &without;
}

/* 1 in the mutation loops' quick mode (NQDQUICK set: valgrind runs). */
static inline int tdquick(void) {
  const char *q = getenv("NQDQUICK");
  return q != NULL && q[0] != 0;
}

#endif /* TDERH_H */
