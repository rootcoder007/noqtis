/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ECDSA verification and ECDH over P-256 and P-384 (FIPS 186-5, SEC 1
 * 4.1.4, SP 800-56A 5.7.1.2). Field and scalar arithmetic in the
 * Montgomery domain; points in
 * projective coordinates with the complete addition formulas of Renes,
 * Costello and Batina (2016, algorithm 4, a = -3), which are also
 * correct for doubling and for the point at infinity (0 : 1 : 0), so no
 * case needs special handling. u1 G + u2 Q by a joint double-and-add
 * that adds a table entry (possibly infinity) at every bit. For ECDH,
 * k P with a fixed 4-bit window: four doublings and one addition of a
 * table entry per nibble, the entry read by a select over all sixteen,
 * so neither the time nor the memory addresses depend on k. */
#include <string.h>

#include "cls/cls.h"
#include "core/int.h"
#include "core/json.h"
#include "hash/h.h"

typedef struct {
  uint32_t x[NQEL], y[NQEL], z[NQEL];
} pt;

typedef struct {
  size_t nb;     /* bytes of p and of the order */
  nqcmod p;      /* the field prime */
  nqcmod q;      /* the group order (cofactor 1) */
  uint32_t b[NQEL], one[NQEL]; /* Montgomery, mod p */
  pt g;
} crv;

/* p, order, b, Gx, Gy (FIPS 186-5 / SP 800-186) */
static const char *const chx[2][5] = {
    {"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
     "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"},
    {"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
     "ffffffff0000000000000000ffffffff",
     "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
     "581a0db248b0a77aecec196accc52973",
     "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
     "c656398d8a2ed19d2a85c8edd3ec2aef",
     "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
     "5502f25dbf55296c3a545e3872760ab7",
     "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
     "0a60b1ce1d7e819d7a431d7c90ea0e5f"}};

static void ldhex(uint32_t *a, size_t nl, const char *h) {
  uint8_t b[48];
  size_t n = 0;
  nqunhex(h, strlen(h), b, sizeof b, &n);
  nqcld(a, nl, b, n);
}

static int cset(crv *c, int id) {
  uint32_t t[NQEL];
  size_t nl;
  if (id != NQP256 && id != NQP384) return NQENOSUP;
  memset(c, 0, sizeof *c);
  c->nb = id == NQP256 ? 32 : 48;
  nl = c->nb / 4;
  ldhex(t, nl, chx[id - 1][0]);
  nqcmset(&c->p, t, nl);
  ldhex(t, nl, chx[id - 1][1]);
  nqcmset(&c->q, t, nl);
  ldhex(t, nl, chx[id - 1][2]);
  nqcto(c->b, t, &c->p);
  memset(t, 0, sizeof t);
  t[0] = 1;
  nqcto(c->one, t, &c->p);
  ldhex(t, nl, chx[id - 1][3]);
  nqcto(c->g.x, t, &c->p);
  ldhex(t, nl, chx[id - 1][4]);
  nqcto(c->g.y, t, &c->p);
  memcpy(c->g.z, c->one, sizeof c->one);
  return NQOK;
}

#define FM(r, a, b) nqcmm(r, a, b, &c->p)
#define FA(r, a, b) nqcad(r, a, b, &c->p)
#define FS(r, a, b) nqcsu(r, a, b, &c->p)

/* r = a + b, complete (RCB16 algorithm 4); r may alias a or b. */
static void padd(const crv *c, pt *r, const pt *a, const pt *b) {
  uint32_t xx[NQEL], yy[NQEL], zz[NQEL], xy[NQEL], yz[NQEL], xz[NQEL];
  uint32_t t0[NQEL], t1[NQEL], u[NQEL], ym[NQEL], yp[NQEL], z3[NQEL];
  uint32_t bx[NQEL], x3[NQEL];
  FM(xx, a->x, b->x);
  FM(yy, a->y, b->y);
  FM(zz, a->z, b->z);
  FA(t0, a->x, a->y);
  FA(t1, b->x, b->y);
  FM(xy, t0, t1);
  FA(t0, xx, yy);
  FS(xy, xy, t0);
  FA(t0, a->y, a->z);
  FA(t1, b->y, b->z);
  FM(yz, t0, t1);
  FA(t0, yy, zz);
  FS(yz, yz, t0);
  FA(t0, a->x, a->z);
  FA(t1, b->x, b->z);
  FM(xz, t0, t1);
  FA(t0, xx, zz);
  FS(xz, xz, t0);
  /* 3 (xz - b zz) */
  FM(t0, c->b, zz);
  FS(u, xz, t0);
  FA(t0, u, u);
  FA(u, t0, u);
  FS(ym, yy, u);
  FA(yp, yy, u);
  /* 3 zz */
  FA(z3, zz, zz);
  FA(z3, z3, zz);
  /* 3 (b xz - 3 zz - xx) */
  FM(bx, c->b, xz);
  FS(bx, bx, z3);
  FS(bx, bx, xx);
  FA(t0, bx, bx);
  FA(bx, t0, bx);
  /* 3 xx - 3 zz */
  FA(x3, xx, xx);
  FA(x3, x3, xx);
  FS(x3, x3, z3);
  FM(t0, yp, xy);
  FM(t1, yz, bx);
  FS(r->x, t0, t1);
  FM(t0, yp, ym);
  FM(t1, x3, bx);
  FA(r->y, t0, t1);
  FM(t0, ym, yz);
  FM(t1, xy, x3);
  FA(r->z, t0, t1);
}

/* r = x^3 - 3x + b (Montgomery) */
static void rhs(const crv *c, uint32_t *r, const uint32_t *x) {
  uint32_t t[NQEL], u[NQEL];
  FM(t, x, x);
  FM(t, t, x);
  FA(u, x, x);
  FA(u, u, x);
  FS(t, t, u);
  FA(r, t, c->b);
}

int nqecpk(nqck *k, int id, const uint8_t *p, size_t len) {
  crv c;
  uint32_t x[NQEL], y[NQEL], xm[NQEL], ym[NQEL], r[NQEL], t[NQEL];
  uint32_t e[NQEL];
  size_t nb, nl, i;
  int rc;
  if (k == NULL || p == NULL) return NQEARG;
  memset(k, 0, sizeof *k);
  rc = cset(&c, id);
  if (rc != NQOK) return rc;
  nb = c.nb;
  nl = nb / 4;
  if (len == 1 + 2 * nb && p[0] == 0x04) {
    nqcld(x, nl, p + 1, nb);
    nqcld(y, nl, p + 1 + nb, nb);
    if (!nqclt(x, c.p.m, nl) || !nqclt(y, c.p.m, nl)) return NQEDEC;
    nqcto(xm, x, &c.p);
    nqcto(ym, y, &c.p);
    rhs(&c, r, xm);
    nqcmm(t, ym, ym, &c.p);
    if (!nqceq(t, r, nl)) return NQEDEC;
  } else if (len == 1 + nb && (p[0] == 0x02 || p[0] == 0x03)) {
    nqcld(x, nl, p + 1, nb);
    if (!nqclt(x, c.p.m, nl)) return NQEDEC;
    nqcto(xm, x, &c.p);
    rhs(&c, r, xm);
    /* p = 3 mod 4 for both curves: y = r^((p + 1) / 4) */
    memcpy(e, c.p.m, nl * sizeof *e);
    for (i = 0; i < nl && ++e[i] == 0; i++) {
    }
    for (i = 0; i < nl; i++) {
      e[i] = (e[i] >> 2) | (i + 1 < nl ? e[i + 1] << 30 : 0);
    }
    nqcpw(ym, r, e, nl, &c.p);
    nqcmm(t, ym, ym, &c.p);
    if (!nqceq(t, r, nl)) return NQEDEC; /* x is not on the curve */
    nqcfr(y, ym, &c.p);
    if ((y[0] & 1u) != (uint32_t)(p[0] & 1u)) {
      if (nqcz(y, nl)) return NQEDEC;
      nqcsb(y, c.p.m, y, nl);
    }
  } else {
    return NQEDEC; /* infinity (00), hybrid (06 / 07) or a bad length */
  }
  k->kind = NQKEC;
  k->crv = id;
  nqcst(k->x, nb, x, nl);
  nqcst(k->y, nb, y, nl);
  return NQOK;
}

/* r = the entry of tb at idx (0..n-1), reading all n. */
static void tsel(pt *r, const pt *tb, size_t n, uint32_t idx) {
  size_t j, i;
  memset(r, 0, sizeof *r);
  for (j = 0; j < n; j++) {
    uint32_t m = ~nqctmask(idx ^ (uint32_t)j);
    for (i = 0; i < NQEL; i++) {
      r->x[i] |= m & tb[j].x[i];
      r->y[i] |= m & tb[j].y[i];
      r->z[i] |= m & tb[j].z[i];
    }
  }
}

int nqecvh(const nqck *k, const uint8_t *dig, size_t dlen,
           const uint8_t *sig, size_t slen, int raw) {
  crv c;
  pt tb[4], a, s1;
  uint32_t r[NQEL], s[NQEL], e[NQEL], w[NQEL], u1[NQEL], u2[NQEL];
  uint32_t t[NQEL], d[NQEL], ok, cy;
  const uint8_t *rp, *sp;
  size_t rl, sl, nb, nl, i;
  if (k == NULL || k->kind != NQKEC || (dig == NULL && dlen > 0) ||
      sig == NULL || (raw != 0 && raw != 1)) {
    return NQEARG;
  }
  if (cset(&c, k->crv) != NQOK) return NQEARG;
  nb = c.nb;
  nl = nb / 4;
  if (raw) {
    if (slen != 2 * nb) return NQEVRFY;
    rp = sig;
    sp = sig + nb;
    rl = sl = nb;
  } else if (nqcdsig(sig, slen, &rp, &rl, &sp, &sl) != NQOK || rl > nb ||
             sl > nb) {
    return NQEVRFY;
  }
  nqcld(r, nl, rp, rl);
  nqcld(s, nl, sp, sl);
  if (nqcz(r, nl) || nqcz(s, nl) || !nqclt(r, c.q.m, nl) ||
      !nqclt(s, c.q.m, nl)) {
    return NQEVRFY;
  }
  /* e: the leftmost bits of the digest, as many as the order has (a
   * whole number of bytes for these curves), then mod q */
  nqcld(e, nl, dig, dlen < nb ? dlen : nb);
  cy = nqcsb(t, e, c.q.m, nl);
  for (i = 0; i < nl; i++) {
    e[i] = nqctsel(nqctmask(cy), e[i], t[i]);
  }
  /* w = s^(q - 2); u1 = e w, u2 = r w (plain, as w is Montgomery) */
  memset(t, 0, sizeof t);
  t[0] = 2;
  nqcsb(d, c.q.m, t, nl);
  nqcto(t, s, &c.q);
  nqcpw(w, t, d, nl, &c.q);
  nqcmm(u1, e, w, &c.q);
  nqcmm(u2, r, w, &c.q);
  /* table: infinity, G, Q, G + Q */
  memset(&tb[0], 0, sizeof tb[0]);
  memcpy(tb[0].y, c.one, sizeof c.one);
  tb[1] = c.g;
  nqcld(t, nl, k->x, nb);
  nqcto(tb[2].x, t, &c.p);
  nqcld(t, nl, k->y, nb);
  nqcto(tb[2].y, t, &c.p);
  memcpy(tb[2].z, c.one, sizeof c.one);
  padd(&c, &tb[3], &tb[1], &tb[2]);
  a = tb[0];
  for (i = 8 * nb; i-- > 0;) {
    uint32_t idx = ((u1[i / 32] >> (i % 32)) & 1u) |
                   (((u2[i / 32] >> (i % 32)) & 1u) << 1);
    padd(&c, &a, &a, &a);
    tsel(&s1, tb, 4, idx);
    padd(&c, &a, &a, &s1);
  }
  if (nqcz(a.z, nl)) return NQEVRFY;
  /* x(A) mod q == r: X == r Z, or X == (r + q) Z when r + q < p */
  nqcto(t, r, &c.p);
  nqcmm(t, t, a.z, &c.p);
  ok = nqceq(t, a.x, nl);
  cy = 0;
  for (i = 0; i < nl; i++) {
    uint64_t v = (uint64_t)r[i] + c.q.m[i] + cy;
    d[i] = (uint32_t)v;
    cy = (uint32_t)(v >> 32);
  }
  cy = (cy ^ 1u) & nqclt(d, c.p.m, nl);
  nqcto(t, d, &c.p);
  nqcmm(t, t, a.z, &c.p);
  ok |= cy & nqceq(t, a.x, nl);
  return ok ? NQOK : NQEVRFY;
}

int nqecv(const nqck *k, nqhalg h, const uint8_t *msg, size_t mlen,
          const uint8_t *sig, size_t slen, int raw) {
  uint8_t d[NQHMAX];
  size_t dl = nqhlen(h);
  if (k == NULL || (msg == NULL && mlen > 0)) return NQEARG;
  if (dl == 0) return NQENOSUP;
  if (nqhash(h, msg, mlen, d, dl) != NQOK) return NQEARG;
  return nqecvh(k, d, dl, sig, slen, raw);
}

/* ---- ECDH ---- */

uint32_t nqecsm(int id, const uint8_t *k, const uint8_t *p, uint8_t *x,
                uint8_t *y) {
  crv c;
  pt tb[16], a, s1;
  uint32_t t[NQEL], zi[NQEL], d[NQEL], f;
  size_t nb, nl, i;
  if (cset(&c, id) != NQOK) return 0;
  nb = c.nb;
  nl = nb / 4;
  /* tb[i] = i P, tb[0] infinity */
  memset(&tb[0], 0, sizeof tb[0]);
  memcpy(tb[0].y, c.one, sizeof c.one);
  if (p == NULL) {
    tb[1] = c.g;
  } else {
    memset(&tb[1], 0, sizeof tb[1]);
    nqcld(t, nl, p + 1, nb);
    nqcto(tb[1].x, t, &c.p);
    nqcld(t, nl, p + 1 + nb, nb);
    nqcto(tb[1].y, t, &c.p);
    memcpy(tb[1].z, c.one, sizeof c.one);
  }
  for (i = 2; i < 16; i++) padd(&c, &tb[i], &tb[i - 1], &tb[1]);
  a = tb[0];
  for (i = 0; i < 2 * nb; i++) {
    uint32_t w = (uint32_t)(k[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 15u;
    padd(&c, &a, &a, &a);
    padd(&c, &a, &a, &a);
    padd(&c, &a, &a, &a);
    padd(&c, &a, &a, &a);
    tsel(&s1, tb, 16, w);
    padd(&c, &a, &a, &s1);
  }
  /* affine: Z^-1 = Z^(p - 2), the exponent public */
  memset(t, 0, sizeof t);
  t[0] = 2;
  nqcsb(d, c.p.m, t, nl);
  nqcpw(zi, a.z, d, nl, &c.p);
  f = 1u ^ nqcz(a.z, nl);
  nqcmm(t, a.x, zi, &c.p);
  nqcfr(t, t, &c.p);
  nqcst(x, nb, t, nl);
  if (y != NULL) {
    nqcmm(t, a.y, zi, &c.p);
    nqcfr(t, t, &c.p);
    nqcst(y, nb, t, nl);
  }
  nqwipe(tb, sizeof tb);
  nqwipe(&a, sizeof a);
  nqwipe(&s1, sizeof s1);
  nqwipe(t, sizeof t);
  nqwipe(zi, sizeof zi);
  return f;
}

/* 1 when the nb-byte k is in [1, n - 1] */
static int skok(const crv *c, const uint8_t *k) {
  uint32_t v[NQEL];
  size_t nl = c->nb / 4;
  int ok;
  nqcld(v, nl, k, c->nb);
  ok = (int)(nqclt(v, c->q.m, nl) & (1u ^ nqcz(v, nl)));
  nqwipe(v, sizeof v);
  return ok;
}

int nqecpub(int id, const uint8_t *sk, uint8_t *pk) {
  crv c;
  int rc;
  if (sk == NULL || pk == NULL) return NQEARG;
  if ((rc = cset(&c, id)) != NQOK) return rc;
  if (!skok(&c, sk)) return NQEARG;
  pk[0] = 0x04;
  /* k G is never infinity for k in [1, n - 1] */
  (void)nqecsm(id, sk, NULL, pk + 1, pk + 1 + c.nb);
  return NQOK;
}

int nqeckg(int id, uint8_t *sk, uint8_t *pk) {
  crv c;
  int rc, i;
  if (sk == NULL || pk == NULL) return NQEARG;
  if ((rc = cset(&c, id)) != NQOK) return rc;
  /* rejection sampling: a draw is out of range with probability about
   * 2^-32 (P-256) or 2^-190 (P-384) */
  for (i = 0; i < 64; i++) {
    if ((rc = nqrand(sk, c.nb)) != NQOK) {
      nqwipe(sk, c.nb);
      return rc;
    }
    if (skok(&c, sk)) return nqecpub(id, sk, pk);
  }
  nqwipe(sk, c.nb);
  return NQERNG;
}

int nqecdh(int id, const uint8_t *sk, const uint8_t *peer, size_t plen,
           uint8_t *z) {
  crv c;
  nqck k;
  int rc;
  if (sk == NULL || peer == NULL || z == NULL) return NQEARG;
  if ((rc = cset(&c, id)) != NQOK) return rc;
  if (!skok(&c, sk)) return NQEARG;
  /* uncompressed only (RFC 8446 4.2.8.2), and on the curve */
  if (plen != 1 + 2 * c.nb || peer[0] != 0x04 ||
      nqecpk(&k, id, peer, plen) != NQOK) {
    return NQEDEC;
  }
  if (!nqecsm(id, sk, peer, z, NULL)) {
    nqwipe(z, c.nb);
    return NQEDEC;
  }
  return NQOK;
}
