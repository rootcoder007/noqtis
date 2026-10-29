/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ML-DSA (FIPS 204): parameter sets, the NTT over Z_q[X]/(X^256 + 1),
 * sampling, rounding and bit packing. Everything that touches a secret is
 * free of secret-dependent branches, indices and divisions. */
#include <string.h>

#include "core/int.h"
#include "hash/h.h"
#include "mldsa/md.h"
#include "mldsa/mldsa.h"

static const nqmdp sets[3] = {
    {NQMLDSA44, 4, 4, 2, 39, 78, 1 << 17, (NQMDQ - 1) / 88, 80, 32, 3, 18, 6,
     NQMD44PK, NQMD44SK, NQMD44SIG},
    {NQMLDSA65, 6, 5, 4, 49, 196, 1 << 19, (NQMDQ - 1) / 32, 55, 48, 4, 20,
     4, NQMD65PK, NQMD65SK, NQMD65SIG},
    {NQMLDSA87, 8, 7, 2, 60, 120, 1 << 19, (NQMDQ - 1) / 32, 75, 64, 3, 20,
     4, NQMD87PK, NQMD87SK, NQMD87SIG},
};

const nqmdp *nqmdpar(int alg) {
  if (alg == NQMLDSA44) return &sets[0];
  if (alg == NQMLDSA65) return &sets[1];
  if (alg == NQMLDSA87) return &sets[2];
  return NULL;
}

/* zetas[i] = 2^32 * 1753^brv8(i) mod q, centred; index 0 is never read */
static const int32_t zetas[NQMDN] = {
  0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347,
  2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103, 2725464,
  1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186,
  -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023,
  95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
  -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267,
  -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596, 811944,
  531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779, -3930395,
  -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
  -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
  3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
  -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
  -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
  -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
  189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
  1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
  2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
  266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
  900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500, -655327,
  -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
  286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341,
  2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016,
  1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058,
  1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642, -1279661,
  1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
  -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
  -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
  -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
  -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
  -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
  -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
  -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782};

/* ---- arithmetic ---- */

void nqmdntt(int32_t a[NQMDN]) {
  unsigned len, start, j, k = 0;
  for (len = 128; len > 0; len >>= 1) {
    for (start = 0; start < NQMDN; start += 2 * len) {
      int32_t z = zetas[++k];
      for (j = start; j < start + len; j++) {
        int32_t t = nqmdmr((int64_t)z * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

void nqmdint(int32_t a[NQMDN]) {
  const int32_t f = 41978; /* 2^64 / 256 mod q */
  unsigned len, start, j, k = NQMDN;
  for (len = 1; len < NQMDN; len <<= 1) {
    for (start = 0; start < NQMDN; start += 2 * len) {
      int32_t z = -zetas[--k];
      for (j = start; j < start + len; j++) {
        int32_t t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = nqmdmr((int64_t)z * a[j + len]);
      }
    }
  }
  for (j = 0; j < NQMDN; j++) a[j] = nqmdmr((int64_t)f * a[j]);
}

void nqmdpw(int32_t c[NQMDN], const int32_t a[NQMDN],
            const int32_t b[NQMDN]) {
  unsigned i;
  for (i = 0; i < NQMDN; i++) c[i] = nqmdmr((int64_t)a[i] * b[i]);
}

void nqmdpwa(int32_t c[NQMDN], const int32_t a[NQMDN],
             const int32_t b[NQMDN]) {
  unsigned i;
  for (i = 0; i < NQMDN; i++) c[i] += nqmdmr((int64_t)a[i] * b[i]);
}

void nqmdred(int32_t a[NQMDN]) {
  unsigned i;
  for (i = 0; i < NQMDN; i++) a[i] = nqmdrd(a[i]);
}

void nqmdcadd(int32_t a[NQMDN]) {
  unsigned i;
  for (i = 0; i < NQMDN; i++) a[i] = nqmdcq(a[i]);
}

/* ---- sampling ---- */

void nqmdunif(int32_t a[NQMDN], const uint8_t rho[32], uint16_t nonce) {
  uint8_t ext[34], buf[168];
  nqkctx c;
  unsigned ctr = 0, pos;
  memcpy(ext, rho, 32);
  ext[32] = (uint8_t)nonce;
  ext[33] = (uint8_t)(nonce >> 8);
  nqshkini(&c, 128);
  nqkabs(&c, ext, sizeof ext);
  while (ctr < NQMDN) {
    nqksqz(&c, buf, sizeof buf);
    for (pos = 0; ctr < NQMDN && pos + 3 <= sizeof buf; pos += 3) {
      uint32_t t = (uint32_t)buf[pos] | ((uint32_t)buf[pos + 1] << 8) |
                   ((uint32_t)(buf[pos + 2] & 0x7f) << 16);
      if (t < (uint32_t)NQMDQ) a[ctr++] = (int32_t)t;
    }
  }
}

void nqmdeta(const nqmdp *p, int32_t a[NQMDN], const uint8_t seed[64],
             uint16_t nonce) {
  uint8_t ext[66], buf[136];
  nqkctx c;
  unsigned ctr = 0, pos, h;
  memcpy(ext, seed, 64);
  ext[64] = (uint8_t)nonce;
  ext[65] = (uint8_t)(nonce >> 8);
  nqshkini(&c, 256);
  nqkabs(&c, ext, sizeof ext);
  while (ctr < NQMDN) {
    nqksqz(&c, buf, sizeof buf);
    for (pos = 0; ctr < NQMDN && pos < sizeof buf; pos++) {
      for (h = 0; h < 2 && ctr < NQMDN; h++) {
        uint32_t t = h ? (uint32_t)buf[pos] >> 4 : (uint32_t)buf[pos] & 15;
        uint32_t ok;
        int32_t v;
        if (p->eta == 2) {
          ok = (t - 15) >> 31; /* t < 15 */
          v = 2 - (int32_t)(t - ((205 * t) >> 10) * 5);
        } else {
          ok = (t - 9) >> 31; /* t < 9 */
          v = 4 - (int32_t)t;
        }
        /* RejBoundedPoly: which nibbles are rejected is not secret (they
         * are never used); the accepted values are */
        NQMDPUB(&ok, sizeof ok);
        if (ok) a[ctr++] = v;
      }
    }
  }
  nqwipe(ext, sizeof ext);
  nqwipe(buf, sizeof buf);
  nqwipe(&c, sizeof c);
}

void nqmdmask(const nqmdp *p, int32_t a[NQMDN], const uint8_t seed[64],
              uint16_t nonce) {
  uint8_t ext[66], buf[640];
  nqkctx c;
  memcpy(ext, seed, 64);
  ext[64] = (uint8_t)nonce;
  ext[65] = (uint8_t)(nonce >> 8);
  nqshkini(&c, 256);
  nqkabs(&c, ext, sizeof ext);
  nqksqz(&c, buf, 32 * (size_t)p->zb);
  nqmdzu(p, a, buf);
  nqwipe(ext, sizeof ext);
  nqwipe(buf, sizeof buf);
  nqwipe(&c, sizeof c);
}

void nqmdchal(const nqmdp *p, int32_t c[NQMDN], const uint8_t *ct) {
  uint8_t buf[136];
  nqkctx k;
  uint64_t signs = 0;
  unsigned i, b, pos = 8;
  nqshkini(&k, 256);
  nqkabs(&k, ct, p->ctl);
  nqksqz(&k, buf, sizeof buf);
  for (i = 0; i < 8; i++) signs |= (uint64_t)buf[i] << (8 * i);
  for (i = 0; i < NQMDN; i++) c[i] = 0;
  for (i = NQMDN - p->tau; i < NQMDN; i++) {
    do {
      if (pos >= sizeof buf) {
        nqksqz(&k, buf, sizeof buf);
        pos = 0;
      }
      b = buf[pos++];
    } while (b > i);
    c[i] = c[b];
    c[b] = 1 - 2 * (int32_t)(signs & 1);
    signs >>= 1;
  }
}

/* ---- rounding ---- */

int32_t nqmddec(const nqmdp *p, int32_t *a0, int32_t a) {
  int32_t a1 = (a + 127) >> 7;
  if (p->g2 == (NQMDQ - 1) / 88) {
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
  } else {
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
  }
  *a0 = a - a1 * 2 * p->g2;
  *a0 -= (((NQMDQ - 1) / 2 - *a0) >> 31) & NQMDQ;
  return a1;
}

uint32_t nqmdmkh(const nqmdp *p, int32_t a0, int32_t a1) {
  uint32_t gt = (uint32_t)(p->g2 - a0) >> 31;  /* a0 > gamma2 */
  uint32_t lt = (uint32_t)(a0 + p->g2) >> 31;  /* a0 < -gamma2 */
  uint32_t eq = 1u ^ (nqctmask((uint32_t)(a0 + p->g2)) & 1u);
  uint32_t nz = nqctmask((uint32_t)a1) & 1u;
  return gt | lt | (eq & nz);
}

int32_t nqmduse(const nqmdp *p, int32_t a, uint32_t h) {
  int32_t a0;
  int32_t a1 = nqmddec(p, &a0, a);
  if (h == 0) return a1;
  if (p->g2 == (NQMDQ - 1) / 88) {
    if (a0 > 0) return a1 == 43 ? 0 : a1 + 1;
    return a1 == 0 ? 43 : a1 - 1;
  }
  return a0 > 0 ? ((a1 + 1) & 15) : ((a1 - 1) & 15);
}

uint32_t nqmdchk(const int32_t a[NQMDN], int32_t b) {
  uint32_t bad = 0;
  unsigned i;
  for (i = 0; i < NQMDN; i++) {
    int32_t t = a[i] >> 31;
    t = a[i] - (t & 2 * a[i]);
    bad |= (uint32_t)(b - 1 - t) >> 31; /* |a| >= b */
  }
  return bad;
}

/* ---- packing ---- */

void nqmdbpk(uint8_t *r, const uint32_t v[NQMDN], unsigned n) {
  unsigned i, k;
  uint32_t m = (1u << n) - 1;
  memset(r, 0, 32 * (size_t)n);
  for (i = 0; i < NQMDN; i++) {
    size_t off = (size_t)i * n;
    unsigned sh = (unsigned)(off & 7), nb = (sh + n + 7) / 8;
    uint32_t x = (v[i] & m) << sh;
    uint8_t *q = r + (off >> 3);
    for (k = 0; k < nb; k++) q[k] = (uint8_t)(q[k] | (uint8_t)(x >> (8 * k)));
  }
}

void nqmdbun(uint32_t v[NQMDN], const uint8_t *a, unsigned n) {
  unsigned i, k;
  uint32_t m = (1u << n) - 1;
  for (i = 0; i < NQMDN; i++) {
    size_t off = (size_t)i * n;
    unsigned sh = (unsigned)(off & 7), nb = (sh + n + 7) / 8;
    const uint8_t *q = a + (off >> 3);
    uint32_t x = 0;
    for (k = 0; k < nb; k++) x |= (uint32_t)q[k] << (8 * k);
    v[i] = (x >> sh) & m;
  }
}

void nqmdt1p(uint8_t *r, const int32_t a[NQMDN]) {
  uint32_t v[NQMDN];
  unsigned i;
  for (i = 0; i < NQMDN; i++) v[i] = (uint32_t)a[i];
  nqmdbpk(r, v, 10);
}

void nqmdt1u(int32_t a[NQMDN], const uint8_t *r) {
  uint32_t v[NQMDN];
  unsigned i;
  nqmdbun(v, r, 10);
  for (i = 0; i < NQMDN; i++) a[i] = (int32_t)v[i];
}

void nqmdt0p(uint8_t *r, const int32_t a[NQMDN]) {
  uint32_t v[NQMDN];
  unsigned i;
  for (i = 0; i < NQMDN; i++) v[i] = (uint32_t)((1 << 12) - a[i]);
  nqmdbpk(r, v, 13);
  nqwipe(v, sizeof v);
}

void nqmdt0u(int32_t a[NQMDN], const uint8_t *r) {
  uint32_t v[NQMDN];
  unsigned i;
  nqmdbun(v, r, 13);
  for (i = 0; i < NQMDN; i++) a[i] = (1 << 12) - (int32_t)v[i];
  nqwipe(v, sizeof v);
}

void nqmdetp(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]) {
  uint32_t v[NQMDN];
  unsigned i;
  for (i = 0; i < NQMDN; i++) v[i] = (uint32_t)((int32_t)p->eta - a[i]);
  nqmdbpk(r, v, p->etab);
  nqwipe(v, sizeof v);
}

void nqmdetu(const nqmdp *p, int32_t a[NQMDN], const uint8_t *r) {
  uint32_t v[NQMDN];
  unsigned i;
  nqmdbun(v, r, p->etab);
  for (i = 0; i < NQMDN; i++) a[i] = (int32_t)p->eta - (int32_t)v[i];
  nqwipe(v, sizeof v);
}

void nqmdzp(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]) {
  uint32_t v[NQMDN];
  unsigned i;
  for (i = 0; i < NQMDN; i++) v[i] = (uint32_t)(p->g1 - a[i]);
  nqmdbpk(r, v, p->zb);
  nqwipe(v, sizeof v);
}

void nqmdzu(const nqmdp *p, int32_t a[NQMDN], const uint8_t *r) {
  uint32_t v[NQMDN];
  unsigned i;
  nqmdbun(v, r, p->zb);
  for (i = 0; i < NQMDN; i++) a[i] = p->g1 - (int32_t)v[i];
  nqwipe(v, sizeof v);
}

void nqmdw1p(const nqmdp *p, uint8_t *r, const int32_t a[NQMDN]) {
  uint32_t v[NQMDN];
  unsigned i;
  for (i = 0; i < NQMDN; i++) v[i] = (uint32_t)a[i];
  nqmdbpk(r, v, p->w1b);
  nqwipe(v, sizeof v);
}

/* ---- the matrix ---- */

void nqmdmat(const nqmdp *p, const uint8_t rho[32], nqmdpl *w0,
             const nqmdpl *v0, nqmdpl *w1, const nqmdpl *v1) {
  nqmdpl a;
  unsigned i, j;
  for (i = 0; i < p->k; i++) {
    for (j = 0; j < p->l; j++) {
      nqmdunif(a.c, rho, (uint16_t)((i << 8) + j));
      if (j == 0) {
        nqmdpw(w0[i].c, a.c, v0[0].c);
        if (w1 != NULL) nqmdpw(w1[i].c, a.c, v1[0].c);
      } else {
        nqmdpwa(w0[i].c, a.c, v0[j].c);
        if (w1 != NULL) nqmdpwa(w1[i].c, a.c, v1[j].c);
      }
    }
  }
}
