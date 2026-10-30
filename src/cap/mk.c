/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The Merkle tree of a noqtis-capsule-2 manifest, as RFC 6962 (section
 * 2.1) defines it: a leaf is SHA-256(0x00 || the entry's canonical
 * bytes), a node SHA-256(0x01 || left || right), a tree of n leaves is
 * split at the largest power of two below n, and the empty tree's hash is
 * SHA-256 of nothing. The audit path of a leaf lists the sibling hashes
 * from the leaf up. */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "hash/h.h"

void nqcmleaf(const char *e, size_t n, uint8_t out[32]) {
  nqs2ctx c;
  static const uint8_t z = 0;
  nqs2ini(&c, 32);
  nqs2upd(&c, &z, 1);
  nqs2upd(&c, (const uint8_t *)e, n);
  nqs2fin(&c, out);
}

static void node(const uint8_t l[32], const uint8_t r[32], uint8_t out[32]) {
  nqs2ctx c;
  static const uint8_t o = 1;
  nqs2ini(&c, 32);
  nqs2upd(&c, &o, 1);
  nqs2upd(&c, l, 32);
  nqs2upd(&c, r, 32);
  nqs2fin(&c, out);
}

/* the largest power of two below n (n >= 2) */
static size_t split(size_t n) {
  size_t k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/* MTH(D[lo, lo + n)); recursion depth is log2(n) + 1 (at most 22 for the
 * 2,000,000-entry limit) */
static void mth(const uint8_t *lv, size_t lo, size_t n, uint8_t out[32]) {
  uint8_t a[32], b[32];
  size_t k;
  if (n == 1) {
    memcpy(out, lv + 32 * lo, 32);
    return;
  }
  k = split(n);
  mth(lv, lo, k, a);
  mth(lv, lo + k, n - k, b);
  node(a, b, out);
}

void nqcmroot(const uint8_t *lv, size_t n, uint8_t out[32]) {
  if (n == 0) {
    nqhash(NQS256, NULL, 0, out, 32);
    return;
  }
  mth(lv, 0, n, out);
}

int nqcmpath(const uint8_t *lv, size_t n, size_t m, uint8_t *path,
             size_t cap, size_t *len) {
  size_t lo = 0, k, d = 0, i;
  /* the siblings, root down, written in reverse at the end */
  uint8_t st[NQCMDEPTH][32];
  *len = 0;
  if (m >= n) return NQEARG;
  while (n > 1) {
    if (d >= NQCMDEPTH) return NQELIM;
    k = split(n);
    if (m < k) {
      mth(lv, lo + k, n - k, st[d++]);
      n = k;
    } else {
      mth(lv, lo, k, st[d++]);
      lo += k;
      m -= k;
      n -= k;
    }
  }
  if (cap < d) return NQEBUF;
  for (i = 0; i < d; i++) memcpy(path + 32 * i, st[d - 1 - i], 32);
  *len = d;
  return NQOK;
}

int nqcmvrfy(const uint8_t leaf[32], size_t m, size_t n,
             const uint8_t *path, size_t len, const uint8_t root[32]) {
  /* RFC 9162 section 2.1.3.2, inclusion proof verification */
  uint8_t r[32];
  size_t fn = m, sn = n - 1, i;
  if (m >= n) return 0;
  memcpy(r, leaf, 32);
  for (i = 0; i < len; i++) {
    const uint8_t *p = path + 32 * i;
    if (sn == 0) return 0;
    if ((fn & 1) || fn == sn) {
      node(p, r, r);
      if (!(fn & 1)) {
        while (fn != 0 && !(fn & 1)) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      node(r, p, r);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn == 0 && memcmp(r, root, 32) == 0;
}
