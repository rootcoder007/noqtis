/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* WOTS+, XMSS, FORS and the hypertree: FIPS 205 sections 5 to 8.
 *
 * Trees are built bottom-up with an explicit stack (treehash), not the
 * recursive xmss_node / fors_node of the standard; the nodes are the same.
 * Every branch and index here depends on loop counters or on tree and
 * leaf indices, which come from the published randomiser R, never on
 * secret key material. */
#include <string.h>

#include "slh/in.h"

/* base_2b (algorithm 4): outlen b-bit digits of x, most significant
 * first. */
static void b2b(const uint8_t *x, unsigned b, unsigned outlen,
                uint32_t *out) {
  unsigned i, in = 0, bits = 0;
  uint32_t tot = 0;
  for (i = 0; i < outlen; i++) {
    while (bits < b) {
      tot = (tot << 8) | x[in++];
      bits += 8;
    }
    bits -= b;
    out[i] = (tot >> bits) & ((1u << b) - 1u);
    tot &= (1u << bits) - 1u;
  }
}

/* The WOTS+ digits of an n-byte message and its checksum (algorithms 7
 * and 10): len1 = 2n message digits, then len2 = 3. */
static void wdig(const nqslp *p, const uint8_t *msg, uint32_t *dig) {
  unsigned i, l1 = 2 * p->n;
  uint32_t cs = 0;
  uint8_t cb[2];
  b2b(msg, 4, l1, dig);
  for (i = 0; i < l1; i++) cs += 15u - dig[i];
  /* len2 * lg(w) = 12 bits: shift 4 to fill two bytes */
  cs <<= 4;
  cb[0] = (uint8_t)(cs >> 8);
  cb[1] = (uint8_t)cs;
  b2b(cb, 4, 3, dig + l1);
}

/* chain (algorithm 5): s steps of F from step i, in place. */
static void chn(const nqslc *c, uint8_t *x, uint32_t i, uint32_t s,
                uint8_t *a) {
  uint32_t j;
  for (j = i; j < i + s; j++) {
    nqsaw3(a, j);
    nqslth(c, a, x, 1, x);
  }
}

/* The WOTS+ secret of chain i of key pair kp under a (layer, tree). */
static void wsk(const nqslc *c, const uint8_t *a, uint32_t kp, uint32_t i,
                uint8_t *out) {
  uint8_t s[32];
  memcpy(s, a, 32);
  nqsatype(s, NQSLWPR);
  nqsakp(s, kp);
  nqsaw2(s, i);
  nqslprf(c, s, out);
}

/* The address of chain i of key pair kp, type WOTS_HASH. */
static void wha(const uint8_t *a, uint32_t kp, uint32_t i, uint8_t *h) {
  memcpy(h, a, 32);
  nqsatype(h, NQSLWH);
  nqsakp(h, kp);
  nqsaw2(h, i);
}

/* T_len over the chain ends: the compressed WOTS+ public key. */
static void wcmp(const nqslc *c, const uint8_t *a, uint32_t kp,
                 const uint8_t *tops, uint8_t *out) {
  uint8_t q[32];
  memcpy(q, a, 32);
  nqsatype(q, NQSLWPK);
  nqsakp(q, kp);
  nqslth(c, q, tops, c->p->len, out);
}

/* wots_pkGen (algorithm 6). */
static void wpk(const nqslc *c, const uint8_t *a, uint32_t kp,
                uint8_t *out) {
  uint8_t tops[NQSLLMX * NQSLNMX], h[32];
  unsigned i, n = c->p->n;
  for (i = 0; i < c->p->len; i++) {
    uint8_t *x = tops + (size_t)i * n;
    wsk(c, a, kp, i, x);
    wha(a, kp, i, h);
    chn(c, x, 0, 15, h);
  }
  wcmp(c, a, kp, tops, out);
  nqwipe(tops, sizeof tops);
}

/* wots_sign (algorithm 10). */
static void wsg(const nqslc *c, const uint8_t *a, uint32_t kp,
                const uint8_t *msg, uint8_t *sig) {
  uint32_t dig[NQSLLMX];
  uint8_t h[32];
  unsigned i, n = c->p->n;
  wdig(c->p, msg, dig);
  for (i = 0; i < c->p->len; i++) {
    uint8_t *x = sig + (size_t)i * n;
    wsk(c, a, kp, i, x);
    wha(a, kp, i, h);
    chn(c, x, 0, dig[i], h);
  }
}

/* wots_pkFromSig (algorithm 8). */
static void wfs(const nqslc *c, const uint8_t *a, uint32_t kp,
                const uint8_t *sig, const uint8_t *msg, uint8_t *out) {
  uint8_t tops[NQSLLMX * NQSLNMX], h[32];
  uint32_t dig[NQSLLMX];
  unsigned i, n = c->p->n;
  wdig(c->p, msg, dig);
  memcpy(tops, sig, (size_t)c->p->len * n);
  for (i = 0; i < c->p->len; i++) {
    wha(a, kp, i, h);
    chn(c, tops + (size_t)i * n, dig[i], 15u - dig[i], h);
  }
  wcmp(c, a, kp, tops, out);
}

/* The address of the interior nodes: TREE for XMSS, FORS_TREE (keeping
 * the key pair) for FORS. */
static void nda(const uint8_t *a, int fors, uint8_t *na) {
  uint32_t kp = nqsagkp(a);
  memcpy(na, a, 32);
  nqsatype(na, fors ? NQSLFT : NQSLTR);
  if (fors) nqsakp(na, kp);
}

/* A FORS leaf: F of the FORS secret at index g (algorithms 14, 15). */
static void flf(const nqslc *c, const uint8_t *a, uint32_t g,
                uint8_t *out) {
  uint8_t s[32];
  uint32_t kp = nqsagkp(a);
  memcpy(s, a, 32);
  nqsatype(s, NQSLFPR);
  nqsakp(s, kp);
  nqsaw3(s, g);
  nqslprf(c, s, out);
  nqsatype(s, NQSLFT);
  nqsakp(s, kp);
  nqsaw3(s, g);
  nqslth(c, s, out, 1, out);
}

void nqsltrh(const nqslc *c, int fors, const uint8_t *a, uint32_t base,
             unsigned ht, uint32_t leaf, uint8_t *root, uint8_t *auth) {
  uint8_t stk[(NQSLHMX + 1) * NQSLNMX], buf[2 * NQSLNMX], na[32];
  unsigned sh[NQSLHMX + 1], sp = 0, z, n = c->p->n;
  uint32_t i;
  if (n == 0 || n > NQSLNMX) return; /* table rows have n <= NQSLNMX */
  nda(a, fors, na);
  for (i = 0; i < ((uint32_t)1 << ht); i++) {
    uint32_t g = base + i;
    uint8_t *node = buf + n;
    if (fors) {
      flf(c, a, g, node);
    } else {
      wpk(c, a, g, node);
    }
    z = 0;
    for (;;) {
      /* this node, at height z, is the sibling on the leaf's path */
      if (auth != NULL && (((g >> z) ^ 1u) == (leaf >> z))) {
        memcpy(auth + (size_t)z * n, node, n);
      }
      if (sp == 0 || sh[sp - 1] != z) break;
      sp--;
      memcpy(buf, stk + (size_t)sp * n, n);
      z++;
      nqsaw2(na, z);
      nqsaw3(na, g >> z);
      nqslth(c, na, buf, 2, node);
    }
    memcpy(stk + (size_t)sp * n, node, n);
    sh[sp++] = z;
  }
  memcpy(root, stk, n);
  nqwipe(stk, sizeof stk);
  nqwipe(buf, sizeof buf);
}

/* The root from a node at height 0, index g, and its authentication path
 * (xmss_pkFromSig, algorithm 11; the loop of fors_pkFromSig, 17). */
static void aup(const nqslc *c, int fors, const uint8_t *a, uint32_t g,
                const uint8_t *node, const uint8_t *auth, unsigned ht,
                uint8_t *root) {
  uint8_t buf[2 * NQSLNMX], na[32], cur[NQSLNMX];
  unsigned z, n = c->p->n;
  if (n == 0 || n > NQSLNMX) return; /* table rows have n <= NQSLNMX */
  nda(a, fors, na);
  memcpy(cur, node, n);
  for (z = 0; z < ht; z++) {
    if (((g >> z) & 1u) == 0) {
      memcpy(buf, cur, n);
      memcpy(buf + n, auth + (size_t)z * n, n);
    } else {
      memcpy(buf, auth + (size_t)z * n, n);
      memcpy(buf + n, cur, n);
    }
    nqsaw2(na, z + 1);
    nqsaw3(na, g >> (z + 1));
    nqslth(c, na, buf, 2, cur);
  }
  memcpy(root, cur, n);
}

void nqslfsg(const nqslc *c, const uint8_t *md, const uint8_t *a,
             uint8_t *sig, uint8_t *pk) {
  const nqslp *p = c->p;
  uint32_t idx[NQSLKMX];
  uint8_t roots[NQSLKMX * NQSLNMX], s[32];
  unsigned i, n = p->n;
  uint32_t kp = nqsagkp(a);
  b2b(md, p->a, p->k, idx);
  for (i = 0; i < p->k; i++) {
    uint32_t base = (uint32_t)i << p->a, g = base + idx[i];
    /* fors_skGen (algorithm 14) */
    memcpy(s, a, 32);
    nqsatype(s, NQSLFPR);
    nqsakp(s, kp);
    nqsaw3(s, g);
    nqslprf(c, s, sig);
    nqsltrh(c, 1, a, base, p->a, g, roots + (size_t)i * n, sig + n);
    sig += (size_t)(p->a + 1) * n;
  }
  memcpy(s, a, 32);
  nqsatype(s, NQSLFR);
  nqsakp(s, kp);
  nqslth(c, s, roots, p->k, pk);
  nqwipe(roots, sizeof roots);
}

void nqslffs(const nqslc *c, const uint8_t *sig, const uint8_t *md,
             const uint8_t *a, uint8_t *pk) {
  const nqslp *p = c->p;
  uint32_t idx[NQSLKMX];
  uint8_t roots[NQSLKMX * NQSLNMX], s[32], lf[NQSLNMX];
  unsigned i, n = p->n;
  uint32_t kp = nqsagkp(a);
  b2b(md, p->a, p->k, idx);
  for (i = 0; i < p->k; i++) {
    uint32_t g = ((uint32_t)i << p->a) + idx[i];
    memcpy(s, a, 32);
    nqsatype(s, NQSLFT);
    nqsakp(s, kp);
    nqsaw3(s, g);
    nqslth(c, s, sig, 1, lf);
    aup(c, 1, a, g, lf, sig + n, p->a, roots + (size_t)i * n);
    sig += (size_t)(p->a + 1) * n;
  }
  memcpy(s, a, 32);
  nqsatype(s, NQSLFR);
  nqsakp(s, kp);
  nqslth(c, s, roots, p->k, pk);
}

void nqslhsg(const nqslc *c, const uint8_t *msg, uint64_t tree,
             uint32_t leaf, uint8_t *sig) {
  const nqslp *p = c->p;
  uint8_t root[NQSLNMX], a[32];
  unsigned j, n = p->n;
  memcpy(root, msg, n);
  for (j = 0; j < p->d; j++) {
    memset(a, 0, sizeof a);
    nqsalay(a, j);
    nqsatree(a, tree);
    /* xmss_sign (algorithm 10): the WOTS+ signature of the layer below's
     * root, then the authentication path; the tree's root is the next
     * layer's message */
    wsg(c, a, leaf, root, sig);
    sig += (size_t)p->len * n;
    nqsltrh(c, 0, a, 0, p->hp, leaf, root, sig);
    NQSLDECL(root, n);
    sig += (size_t)p->hp * n;
    leaf = (uint32_t)(tree & (((uint64_t)1 << p->hp) - 1u));
    tree >>= p->hp;
  }
}

int nqslhvf(const nqslc *c, const uint8_t *msg, const uint8_t *sig,
            uint64_t tree, uint32_t leaf, const uint8_t *root) {
  const nqslp *p = c->p;
  uint8_t node[NQSLNMX], lf[NQSLNMX], a[32];
  unsigned j, n = p->n;
  memcpy(node, msg, n);
  for (j = 0; j < p->d; j++) {
    memset(a, 0, sizeof a);
    nqsalay(a, j);
    nqsatree(a, tree);
    wfs(c, a, leaf, sig, node, lf);
    sig += (size_t)p->len * n;
    aup(c, 0, a, leaf, lf, sig, p->hp, node);
    sig += (size_t)p->hp * n;
    leaf = (uint32_t)(tree & (((uint64_t)1 << p->hp) - 1u));
    tree >>= p->hp;
  }
  return nqcteq(node, root, n);
}
