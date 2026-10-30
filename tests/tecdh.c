/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ECDH over P-256 and P-384 (src/cls/ec.c): the OpenSSL known answers
 * in vectors/ossl/ecdh.json (public key from the private one, and the
 * shared x coordinate), fresh key pairs that must agree both ways, and
 * peers and scalars that must be refused: off the curve, infinity,
 * compressed or hybrid, the wrong length, a coordinate of p or more, a
 * scalar of 0 or n. The RFC 8448 P-256 exchange is checked in ttls.c. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "cls/cls.h"
#include "nqt.h"
#include "tvec.h"

static void kat(void) {
  nqjs *v = tvjs("vectors/ossl/ecdh.json");
  const nqjs *ts;
  size_t i, run = 0;
  if (v == NULL) {
    NQTCHK(0);
    return;
  }
  ts = nqjget(v, "tests");
  NQTCHK(ts != NULL && ts->n >= 16);
  for (i = 0; ts != NULL && i < ts->n; i++) {
    const nqjs *t = nqjat(ts, i);
    const char *c = nqjstr(nqjget(t, "crv"));
    uint8_t *sk, *pk, *peer, *z, o[97];
    size_t skn, pkn, pn, zn;
    int crv = c != NULL && strcmp(c, "P-384") == 0 ? NQP384 : NQP256;
    sk = tvhex(nqjget(t, "sk"), &skn);
    pk = tvhex(nqjget(t, "pk"), &pkn);
    peer = tvhex(nqjget(t, "peer"), &pn);
    z = tvhex(nqjget(t, "z"), &zn);
    if (sk != NULL && pk != NULL && peer != NULL && z != NULL &&
        skn == zn && pkn == 2 * skn + 1 && pn == pkn) {
      NQTEQI(nqecpub(crv, sk, o), NQOK);
      NQTEQM(o, pk, pkn);
      memset(o, 0, sizeof o);
      NQTEQI(nqecdh(crv, sk, peer, pn, o), NQOK);
      NQTEQM(o, z, zn);
      run++;
    } else {
      NQTCHK(0);
    }
    free(sk);
    free(pk);
    free(peer);
    free(z);
  }
  NQTEQI(run, 16);
  nqjfree(v);
}

/* two fresh key pairs agree, and every bad peer or scalar is refused */
static void pair(int crv, size_t nb) {
  uint8_t a[48], b[48], pa[97], pb[97], za[48], zb[48], p[98], k[48];
  size_t pl = 1 + 2 * nb, i;
  NQTEQI(nqeckg(crv, a, pa), NQOK);
  NQTEQI(nqeckg(crv, b, pb), NQOK);
  NQTEQI(pa[0], 4);
  NQTEQI(nqecdh(crv, a, pb, pl, za), NQOK);
  NQTEQI(nqecdh(crv, b, pa, pl, zb), NQOK);
  NQTEQM(za, zb, nb);
  /* off the curve: y + 1 */
  memcpy(p, pb, pl);
  p[pl - 1] ^= 1;
  NQTEQI(nqecdh(crv, a, p, pl, za), NQEDEC);
  /* infinity, as SEC 1 writes it, and as all zeros */
  p[0] = 0;
  NQTEQI(nqecdh(crv, a, p, 1, za), NQEDEC);
  memset(p, 0, pl);
  p[0] = 4;
  NQTEQI(nqecdh(crv, a, p, pl, za), NQEDEC);
  /* compressed (a valid point, but not allowed in TLS 1.3) and hybrid */
  memcpy(p, pb, 1 + nb);
  p[0] = (uint8_t)(2 + (pb[pl - 1] & 1));
  NQTEQI(nqecdh(crv, a, p, 1 + nb, za), NQEDEC);
  memcpy(p, pb, pl);
  p[0] = (uint8_t)(6 + (pb[pl - 1] & 1));
  NQTEQI(nqecdh(crv, a, p, pl, za), NQEDEC);
  /* the wrong length: short, long, the other curve's */
  NQTEQI(nqecdh(crv, a, pb, pl - 1, za), NQEDEC);
  memcpy(p, pb, pl);
  p[pl] = 0;
  NQTEQI(nqecdh(crv, a, p, pl + 1, za), NQEDEC);
  NQTEQI(nqecdh(crv, a, pb, crv == NQP256 ? 97 : 65, za), NQEDEC);
  /* x = p (all ones is above p for both curves) */
  memcpy(p, pb, pl);
  for (i = 1; i <= nb; i++) p[i] = 0xff;
  NQTEQI(nqecdh(crv, a, p, pl, za), NQEDEC);
  /* scalars 0 and all ones (above n) */
  memset(k, 0, sizeof k);
  NQTEQI(nqecdh(crv, k, pb, pl, za), NQEARG);
  NQTEQI(nqecpub(crv, k, p), NQEARG);
  memset(k, 0xff, sizeof k);
  NQTEQI(nqecdh(crv, k, pb, pl, za), NQEARG);
  NQTEQI(nqecpub(crv, k, p), NQEARG);
  /* the arguments */
  NQTEQI(nqecdh(crv, NULL, pb, pl, za), NQEARG);
  NQTEQI(nqecdh(crv, a, NULL, pl, za), NQEARG);
  NQTEQI(nqeckg(crv, NULL, pa), NQEARG);
  NQTEQI(nqeckg(3, a, pa), NQENOSUP);
}

/* the scalar n - 1 gives -G: x(G), and k = 1 gives G itself */
static void edge(void) {
  static const char *const gx =
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
  static const char *const n1 =
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
  uint8_t k[32], g[32], pk[65], z[32];
  NQTEQI(tvlit(gx, g, 32), 32);
  NQTEQI(tvlit(n1, k, 32), 32);
  NQTEQI(nqecpub(NQP256, k, pk), NQOK);
  NQTEQM(pk + 1, g, 32);
  memset(k, 0, 32);
  k[31] = 1;
  NQTEQI(nqecpub(NQP256, k, pk), NQOK);
  NQTEQM(pk + 1, g, 32);
  /* 1 times (n - 1) G */
  NQTEQI(tvlit(n1, k, 32), 32);
  NQTEQI(nqecpub(NQP256, k, pk), NQOK);
  memset(k, 0, 32);
  k[31] = 1;
  NQTEQI(nqecdh(NQP256, k, pk, 65, z), NQOK);
  NQTEQM(z, g, 32);
}

int main(void) {
  kat();
  pair(NQP256, 32);
  pair(NQP384, 48);
  edge();
  return nqtdone("tecdh");
}
