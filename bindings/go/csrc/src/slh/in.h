/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SLH-DSA internals shared by the files of src/slh/: the hash functions
 * of FIPS 205 section 11, addresses (section 4.2), and the WOTS+, XMSS,
 * FORS and hypertree layers (sections 5 to 8). */
#ifndef NQSLIN_H
#define NQSLIN_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/int.h"
#include "hash/h.h"
#include "slh/slh.h"

/* Constant-time checking (tests/tslhct.c, built with -DNQCTGRIND): values
 * FIPS 205 publishes anyway (the randomiser R, which fixes every tree and
 * leaf index, and each layer's root, which the verifier recomputes) are
 * marked defined, so the public branches on them are not reported. A
 * no-op otherwise. */
#ifdef NQCTGRIND
#include <valgrind/memcheck.h>
#define NQSLDECL(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define NQSLDECL(p, n) ((void)0)
#endif

#define NQSLNMX 32  /* the largest n */
#define NQSLLMX 67  /* the most WOTS+ chains (n = 32) */
#define NQSLKMX 35  /* the most FORS trees */
#define NQSLHMX 14  /* the tallest XMSS or FORS tree */
#define NQSLMMX 49  /* the longest H_msg output */

/* address types (FIPS 205 section 4.2) */
enum {
  NQSLWH = 0,  /* WOTS_HASH */
  NQSLWPK = 1, /* WOTS_PK */
  NQSLTR = 2,  /* TREE */
  NQSLFT = 3,  /* FORS_TREE */
  NQSLFR = 4,  /* FORS_ROOTS */
  NQSLWPR = 5, /* WOTS_PRF */
  NQSLFPR = 6  /* FORS_PRF */
};

/* The keys one operation works with. For SHA-2 it also keeps the hash
 * states after the padded PK.seed block that starts every F, H, T and PRF
 * call (section 11.2): SHA-256 always, SHA-512 when n > 16. */
typedef struct {
  const nqslp *p;
  uint8_t pks[NQSLNMX];  /* PK.seed */
  uint8_t sks[NQSLNMX];  /* SK.seed; zero in a verifier */
  nqs2ctx m2;
  nqs5ctx m5;
} nqslc;

/* ---- addresses: 32 bytes, big-endian words, FIPS 205 layout ---- */

static inline void nqsalay(uint8_t *a, uint32_t l) { nqst32b(a, l); }

static inline void nqsatree(uint8_t *a, uint64_t t) {
  nqst32b(a + 4, 0);
  nqst64b(a + 8, t);
}

/* setTypeAndClear */
static inline void nqsatype(uint8_t *a, uint32_t t) {
  nqst32b(a + 16, t);
  memset(a + 20, 0, 12);
}

static inline void nqsakp(uint8_t *a, uint32_t kp) { nqst32b(a + 20, kp); }
static inline uint32_t nqsagkp(const uint8_t *a) { return nqld32b(a + 20); }
/* chain address, or tree height */
static inline void nqsaw2(uint8_t *a, uint32_t v) { nqst32b(a + 24, v); }
/* hash address, or tree index */
static inline void nqsaw3(uint8_t *a, uint32_t v) { nqst32b(a + 28, v); }

/* ---- hash functions (hsh.c) ---- */

/* Fills c for p; sks NULL leaves SK.seed zero (verification). */
void nqslini(nqslc *c, const nqslp *p, const uint8_t *pks,
             const uint8_t *sks);
/* PRF(PK.seed, SK.seed, ADRS): n bytes. */
void nqslprf(const nqslc *c, const uint8_t *a, uint8_t *out);
/* F, H or T_l over nb n-byte blocks; out may overlap in. */
void nqslth(const nqslc *c, const uint8_t *a, const uint8_t *in,
            unsigned nb, uint8_t *out);
/* PRF_msg(SK.prf, opt_rand, M'), with M' = pre || msg: n bytes. */
void nqslpm(const nqslp *p, const uint8_t *skp, const uint8_t *rnd,
            const uint8_t *pre, size_t prelen, const uint8_t *msg,
            size_t msglen, uint8_t *out);
/* H_msg(R, PK.seed, PK.root, M'), with M' = pre || msg: p->m bytes. */
void nqslhm(const nqslp *p, const uint8_t *r, const uint8_t *pk,
            const uint8_t *pre, size_t prelen, const uint8_t *msg,
            size_t msglen, uint8_t *out);

/* ---- trees (tree.c) ---- */

/* The root of an XMSS tree (fors 0; a holds the layer and tree) or of FORS
 * tree number base >> p->a (fors 1; a also holds the key pair), with the
 * authentication path of the leaf whose index is leaf (counted, like
 * base, across the whole FORS forest) when auth is not NULL. */
void nqsltrh(const nqslc *c, int fors, const uint8_t *a, uint32_t base,
             unsigned ht, uint32_t leaf, uint8_t *root, uint8_t *auth);
/* FORS signature of md (algorithm 16) and the FORS public key; a holds
 * the layer, tree and key pair. */
void nqslfsg(const nqslc *c, const uint8_t *md, const uint8_t *a,
             uint8_t *sig, uint8_t *pk);
/* The FORS public key a signature gives (algorithm 17). */
void nqslffs(const nqslc *c, const uint8_t *sig, const uint8_t *md,
             const uint8_t *a, uint8_t *pk);
/* Hypertree signature of msg (n bytes) at tree and leaf (algorithm 12). */
void nqslhsg(const nqslc *c, const uint8_t *msg, uint64_t tree,
             uint32_t leaf, uint8_t *sig);
/* 1 when sig is a hypertree signature of msg under root (algorithm 13),
 * 0 otherwise. */
int nqslhvf(const nqslc *c, const uint8_t *msg, const uint8_t *sig,
            uint64_t tree, uint32_t leaf, const uint8_t *root);

#endif /* NQSLIN_H */
