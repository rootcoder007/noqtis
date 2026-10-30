/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X.509 by position, names, path checks, OCSP and CRLs, against the
 * rmoriebricklayer 1.0.3 fixtures and the local throwaway PKI
 * (vectors/der/gen.sh), with the signature oracle of tderh.h; and the
 * exhaustive mutation test of every certificate, OCSP response and CRL
 * fixture. */
#include "nqt.h"
#include "tderh.h"

static tdfx fx[TDMAXFX];
static size_t nfx;
static int rec;

#define BL(name) tdget(fx, nfx, name)

/* local fixtures */
static const char *const locn[] = {
    "rsa_root",   "rsa_inter",     "rsa_tsa", "rsa_leaf_good",
    "rsa_leaf_rev", "rsa_leaf_unk", "rsa_resp", "rsa_inter2",
    "rsa_leaf_deep", "ec_root",     "ec_tsa",  "ml_root",
    "ml_tsa"};
#define NLOC (sizeof locn / sizeof locn[0])
static tdbuf locb[NLOC];
static nqcert locc[NLOC];

static const nqcert *L(const char *name) {
  size_t i;
  for (i = 0; i < NLOC; i++) {
    if (strcmp(locn[i], name) == 0) {
      return &locc[i];
    }
  }
  return NULL;
}

static void loadloc(void) {
  size_t i;
  char path[128];
  for (i = 0; i < NLOC; i++) {
    snprintf(path, sizeof path, "vectors/der/local/%s.der", locn[i]);
    locb[i] = tdread(path);
    NQTCHK(locb[i].p != NULL);
    NQTEQI(nqcprs(locb[i].p, locb[i].n, &locc[i]), NQOK);
  }
}

/* ---- parsing ---- */

static void tparse(void) {
  static const char *notcert[] = {
      "nc_crl", "ocsp_request", "ocsp_req_good", "ocsp_resp_good",
      "ocsp_resp_revoked", "ocsp_resp_unknown", "ocsp_resp_good_nocerts",
      "ocsp_resp_good_delegated", "ocsp_resp_ec_good", "ocsp_crl_pem",
      "ocsp_ec_sig512", "ocsp_ec_sig384", "ocsp_crl_der"};
  size_t i, j, ncert = 0;
  nqcert c;
  const nqcert *x;
  for (i = 0; i < nfx; i++) {
    int isnot = 0, r;
    for (j = 0; j < sizeof notcert / sizeof notcert[0]; j++) {
      if (strcmp(fx[i].name, notcert[j]) == 0) {
        isnot = 1;
      }
    }
    r = nqcprs(fx[i].b.p, fx[i].b.n, &c);
    if (isnot) {
      NQTCHK(r != NQOK);
    } else if (strcmp(fx[i].name, "chain_v1") == 0) {
      /* a version 1 certificate that carries extensions */
      NQTEQI(r, NQEDEC);
    } else {
      if (r != NQOK) {
        fprintf(stderr, "fixture %s: %d\n", fx[i].name, r);
      }
      NQTEQI(r, NQOK);
      ncert++;
      /* nameConstraints is critical in nc_ca and not handled here */
      NQTEQI(c.bad, strcmp(fx[i].name, "nc_ca") == 0);
    }
  }
  NQTEQI(ncert, 29);
  /* fields */
  x = L("rsa_root");
  NQTEQI(x->ver, 3);
  NQTEQI(x->ca, 1);
  NQTEQI(x->plen, -1);
  NQTEQI(x->ku, NQXKUCERT | NQXKUCRL);
  NQTEQI(x->key.type, NQXKRSA);
  NQTEQI(x->salg.kind, NQXRSA);
  NQTEQI(x->salg.h, NQS256);
  NQTCHK(nqxneq(x->issuer, x->subject));
  NQTEQI(x->na - x->nb, 3650 * 86400);
  x = L("rsa_inter");
  NQTEQI(x->salg.kind, NQXPSS);
  NQTEQI(x->salg.h, NQS256);
  NQTEQI(x->plen, 0);
  NQTCHK(nqdseq(x->aki, L("rsa_root")->ski));
  NQTCHK(nqxneq(x->issuer, L("rsa_root")->subject));
  NQTCHK(!nqxneq(x->issuer, x->subject));
  x = L("rsa_tsa");
  NQTEQI(x->ca, 0);
  NQTEQI(x->eku, NQXEKUTS);
  NQTEQI(x->ekucrit, 1);
  NQTEQI(x->ekun, 1);
  NQTEQI(x->ku, NQXKUSIG);
  NQTEQI(x->ext, NQXHASBC | NQXHASKU | NQXHASEKU | NQXHASSKI | NQXHASAKI);
  NQTEQI(L("rsa_resp")->eku, NQXEKUOCSP);
  NQTEQI(L("rsa_resp")->ekucrit, 0);
  NQTEQI(L("rsa_leaf_rev")->salg.h, NQS384);
  NQTEQI(L("rsa_leaf_unk")->salg.h, NQS512);
  x = L("ec_root");
  NQTEQI(x->key.type, NQXKEC);
  NQTEQI(x->key.curve, NQXP384);
  NQTEQI(x->key.key.n, 97);
  NQTEQI(L("ec_tsa")->key.curve, NQXP256);
  NQTEQI(L("ec_tsa")->salg.kind, NQXECDSA);
  NQTEQI(L("ec_tsa")->salg.h, NQS384);
  x = L("ml_root");
  NQTEQI(x->key.type, NQXKPQ);
  NQTEQI(x->key.pq, NQMLDSA65);
  NQTEQI(x->key.key.n, 1952);
  NQTEQI(x->salg.kind, NQXPQ);
  NQTEQI(x->salg.pq, NQMLDSA65);
  NQTEQI(L("ml_tsa")->key.pq, NQMLDSA44);
  NQTEQI(L("ml_tsa")->salg.pq, NQMLDSA65);
  /* trailing bytes, truncation, a NULL */
  {
    const tdbuf *b = &locb[0];
    uint8_t tmp[4096];
    NQTCHK(b->n + 1 <= sizeof tmp);
    memcpy(tmp, b->p, b->n);
    tmp[b->n] = 0;
    NQTEQI(nqcprs(tmp, b->n + 1, &c), NQEDEC);
    NQTEQI(nqcprs(tmp, b->n - 1, &c), NQEDEC);
    NQTEQI(nqcprs(NULL, 0, &c), NQEARG);
  }
}

/* ---- algorithm identifiers and keys ---- */

static int aid(const char *hex, nqxsig *s) {
  uint8_t b[128];
  size_t n = 0;
  nqdtlv t;
  if (nqunhex(hex, strlen(hex), b, sizeof b, &n) != NQOK ||
      nqdone(b, n, &t) != NQOK) {
    return -100;
  }
  return nqxsalg(&t, s);
}

static int hid(const char *hex, int sha1ok, nqhalg *h) {
  uint8_t b[128];
  size_t n = 0;
  nqdtlv t;
  if (nqunhex(hex, strlen(hex), b, sizeof b, &n) != NQOK ||
      nqdone(b, n, &t) != NQOK) {
    return -100;
  }
  return nqxhalg(&t, sha1ok, h);
}

static void talg(void) {
  nqxsig s;
  nqhalg h;
  /* sha256WithRSAEncryption: NULL parameters required */
  NQTEQI(aid("300d06092a864886f70d01010b0500", &s), NQOK);
  NQTEQI(s.kind, NQXRSA);
  NQTEQI(s.h, NQS256);
  NQTEQI(aid("300b06092a864886f70d01010b", &s), NQEDEC);
  NQTEQI(aid("300f06092a864886f70d01010b0500" "0500", &s), NQEDEC);
  NQTEQI(aid("301106092a864886f70d01010b05000500", &s), -100);
  NQTEQI(aid("300d06092a864886f70d01010c0500", &s), NQOK);
  NQTEQI(s.h, NQS384);
  NQTEQI(aid("300d06092a864886f70d01010d0500", &s), NQOK);
  NQTEQI(s.h, NQS512);
  /* sha1WithRSAEncryption, md5: not supported */
  NQTEQI(aid("300d06092a864886f70d0101050500", &s), NQENOSUP);
  NQTEQI(aid("300d06092a864886f70d0101040500", &s), NQENOSUP);
  /* ecdsa-with-SHA256/384/512: no parameters */
  NQTEQI(aid("300a06082a8648ce3d040302", &s), NQOK);
  NQTEQI(s.kind, NQXECDSA);
  NQTEQI(aid("300a06082a8648ce3d040303", &s), NQOK);
  NQTEQI(s.h, NQS384);
  NQTEQI(aid("300c06082a8648ce3d0403020500", &s), NQEDEC);
  NQTEQI(aid("300a06082a8648ce3d040301", &s), NQENOSUP);
  /* ML-DSA, SLH-DSA */
  NQTEQI(aid("300b0609608648016503040311", &s), NQOK);
  NQTEQI(s.kind, NQXPQ);
  NQTEQI(s.pq, NQMLDSA44);
  NQTEQI(aid("300b0609608648016503040313", &s), NQOK);
  NQTEQI(s.pq, NQMLDSA87);
  NQTEQI(aid("300b0609608648016503040314", &s), NQOK);
  NQTEQI(s.pq, NQSLH128S);
  NQTEQI(aid("300b060960864801650304031a", &s), NQOK);
  NQTEQI(s.pq, NQSLHK128S);
  NQTEQI(aid("300b060960864801650304031f", &s), NQOK);
  NQTEQI(s.pq, NQSLHK256F);
  NQTEQI(aid("300b0609608648016503040320", &s), NQENOSUP);
  NQTEQI(aid("300b0609608648016503040310", &s), NQENOSUP);
  NQTEQI(aid("300d06096086480165030403110500", &s), NQEDEC);
  /* RSASSA-PSS: SHA-256, MGF1-SHA-256, salt 32 */
  NQTEQI(aid("304106092a864886f70d01010a3034a00f300d0609608648016503040201"
             "0500a11c301a06092a864886f70d010108300d0609608648016503040201"
             "0500a203020120",
             &s),
         NQOK);
  NQTEQI(s.kind, NQXPSS);
  NQTEQI(s.h, NQS256);
  /* salt 20 */
  NQTEQI(aid("304106092a864886f70d01010a3034a00f300d0609608648016503040201"
             "0500a11c301a06092a864886f70d010108300d0609608648016503040201"
             "0500a203020114",
             &s),
         NQENOSUP);
  /* MGF1 with another hash */
  NQTEQI(aid("304106092a864886f70d01010a3034a00f300d0609608648016503040201"
             "0500a11c301a06092a864886f70d010108300d0609608648016503040202"
             "0500a203020120",
             &s),
         NQENOSUP);
  /* trailerField 1 written out: DER omits it */
  NQTEQI(aid("304606092a864886f70d01010a3039a00f300d0609608648016503040201"
             "0500a11c301a06092a864886f70d010108300d0609608648016503040201"
             "0500a203020120a303020101",
             &s),
         NQEDEC);
  /* the SHA-1 defaults */
  NQTEQI(aid("300f06092a864886f70d01010a3002" "3000", &s), NQENOSUP);
  NQTEQI(aid("300f06092a864886f70d01010a3000", &s), -100);
  NQTEQI(aid("300d06092a864886f70d01010a3000", &s), NQENOSUP);
  NQTEQI(aid("300b06092a864886f70d01010a", &s), NQENOSUP);
  /* digests */
  NQTEQI(hid("300d06096086480165030402010500", 0, &h), NQOK);
  NQTEQI(h, NQS256);
  NQTEQI(hid("300b0609608648016503040203", 0, &h), NQOK);
  NQTEQI(h, NQS512);
  NQTEQI(hid("300706052b0e03021a", 0, &h), NQENOSUP);
  NQTEQI(hid("300706052b0e03021a", 1, &h), NQOK);
  NQTEQI(h, 0);
  NQTEQI(hid("300906052b0e03021a0500", 1, &h), NQOK);
  NQTEQI(hid("300f06096086480165030402010400", 0, &h), -100);
  NQTEQI(hid("300d0609608648016503040201" "0400", 0, &h), NQEDEC);
  NQTEQI(hid("300d06096086480165030402040500", 0, &h), NQENOSUP);
  NQTEQI(hid("30020500", 0, &h), NQEDEC);
  NQTEQI(hid("3000", 0, &h), NQEDEC);
  NQTEQI(nqxhlen(NQS384), 48);
  NQTEQI(nqxhlen((nqhalg)0), 20);
  /* key and algorithm must agree */
  {
    nqxkey k;
    memset(&k, 0, sizeof k);
    s.kind = NQXRSA;
    k.type = NQXKEC;
    NQTEQI(nqxkeyok(&k, &s), NQEVRFY);
    k.type = NQXKRSA;
    NQTEQI(nqxkeyok(&k, &s), NQOK);
    k.type = NQXKPSS;
    NQTEQI(nqxkeyok(&k, &s), NQEVRFY);
    s.kind = NQXPSS;
    NQTEQI(nqxkeyok(&k, &s), NQOK);
    s.kind = NQXPQ;
    s.pq = NQMLDSA65;
    k.type = NQXKPQ;
    k.pq = NQMLDSA44;
    NQTEQI(nqxkeyok(&k, &s), NQEVRFY);
    k.pq = NQMLDSA65;
    NQTEQI(nqxkeyok(&k, &s), NQOK);
    s.kind = (nqxkind)0;
    NQTEQI(nqxkeyok(&k, &s), NQENOSUP);
  }
}

/* ---- names ---- */

static int neq(const char *a, const char *b) {
  uint8_t x[256], y[256];
  size_t nx = 0, ny = 0;
  nqspan sa, sb;
  if (nqunhex(a, strlen(a), x, sizeof x, &nx) != NQOK ||
      nqunhex(b, strlen(b), y, sizeof y, &ny) != NQOK) {
    return -1;
  }
  sa.p = x;
  sa.n = nx;
  sb.p = y;
  sb.n = ny;
  return nqxneq(sa, sb);
}

static void tname(void) {
  /* CN=Ab C (PrintableString) and variants */
  const char *base = "300f310d300b06035504031304416220" "43";
  NQTEQI(neq(base, base), 1);
  /* case and spaces fold */
  NQTEQI(neq(base, "3010310e300c060355040313056162202043"), 1);
  NQTEQI(neq(base, "3011310f300d06035504031306206162204320"), 1);
  /* UTF8String with the same text */
  NQTEQI(neq(base, "300f310d300b0603550403" "0c04416220" "43"), 1);
  /* another value, another attribute type */
  NQTEQI(neq(base, "300f310d300b06035504031304416220" "44"), 0);
  NQTEQI(neq(base, "300f310d300b060355040a1304416220" "43"), 0);
  /* IA5String compares exactly */
  NQTEQI(neq("300f310d300b06035504031604416220" "43",
             "300f310d300b06035504031604616220" "43"),
         0);
  NQTEQI(neq("300f310d300b06035504031604416220" "43",
             "300f310d300b0603550403" "1304416220" "43"),
         0);
  /* more RDNs, fewer RDNs */
  NQTEQI(neq(base,
             "301e310d300b06035504031304416220" "43"
             "310d300b06035504031304416220" "43"),
         0);
  NQTEQI(neq("3000", "3000"), 1);
  NQTEQI(neq(base, "3000"), 0);
  /* not Names */
  NQTEQI(neq("3002" "3100", "3002" "3100"), 0);
  NQTEQI(neq("0500", "0500"), 0);
  NQTEQI(neq(base, "300f310d300b06035504031304416220"), 0);
  /* a non-ASCII byte compares exactly */
  NQTEQI(neq("300f310d300b0603550403" "0c04c3a92043",
             "300f310d300b0603550403" "0c04c3892043"),
         0);
}

/* ---- paths ---- */

static int chain(const nqcert *leaf, const nqcert *anc, size_t nanc,
                 const nqcert *pool, size_t npool, int64_t t, uint32_t eku,
                 size_t *np) {
  const nqcert *path[NQXMAXPATH];
  nqxchk k;
  size_t n = 0;
  int r;
  k.anc = anc;
  k.nanc = nanc;
  k.pool = pool;
  k.npool = npool;
  k.t = t;
  k.eku = eku;
  k.ops = tdops(1);
  r = nqchain(leaf, &k, path, NQXMAXPATH, &n);
  if (np != NULL) {
    *np = n;
  }
  return r;
}

static void tchain(void) {
  const nqcert *tsa = L("rsa_tsa");
  int64_t t = tsa->nb + 86400;
  nqcert pool[4], anc[2], c;
  size_t np;
  pool[0] = *L("rsa_inter");
  anc[0] = *L("rsa_root");
  NQTEQI(chain(tsa, anc, 1, pool, 1, t, NQXEKUTS, &np), NQOK);
  NQTEQI(np, 3);
  NQTEQI(chain(tsa, anc, 1, pool, 1, t, 0, &np), NQOK);
  /* a purpose the leaf was not issued for */
  NQTEQI(chain(tsa, anc, 1, pool, 1, t, NQXEKUCODE, &np), NQEVRFY);
  NQTEQI(chain(L("rsa_leaf_good"), anc, 1, pool, 1, t, NQXEKUTS, &np),
         NQEVRFY);
  NQTEQI(chain(L("rsa_leaf_good"), anc, 1, pool, 1, t, 0, &np), NQOK);
  /* outside the validity window */
  NQTEQI(chain(tsa, anc, 1, pool, 1, tsa->nb - 1, 0, &np), NQEVRFY);
  NQTEQI(chain(tsa, anc, 1, pool, 1, tsa->na + 1, 0, &np), NQEVRFY);
  NQTEQI(chain(tsa, anc, 1, pool, 1, tsa->nb, 0, &np), NQOK);
  NQTEQI(chain(tsa, anc, 1, pool, 1, tsa->na, 0, &np), NQOK);
  /* no path: another anchor, no intermediate, the leaf as anchor */
  anc[1] = *L("ec_root");
  NQTEQI(chain(tsa, anc + 1, 1, pool, 1, t, 0, &np), NQEVRFY);
  NQTEQI(chain(tsa, anc, 2, pool, 1, t, 0, &np), NQOK);
  NQTEQI(chain(tsa, anc, 1, pool, 0, t, 0, &np), NQEVRFY);
  NQTEQI(chain(tsa, tsa, 1, pool, 1, t, 0, &np), NQEVRFY);
  /* the intermediate as anchor: a shorter path */
  NQTEQI(chain(tsa, pool, 1, NULL, 0, t, NQXEKUTS, &np), NQOK);
  NQTEQI(np, 2);
  /* a self-signed root alone has no path */
  NQTEQI(chain(&anc[0], anc, 1, NULL, 0, t, 0, &np), NQEVRFY);
  /* path length: rsa_inter allows no CA below it */
  pool[1] = *L("rsa_inter2");
  NQTEQI(chain(L("rsa_leaf_deep"), anc, 1, pool, 2, t, 0, &np), NQEVRFY);
  /* ... which holds once rsa_inter2 is the anchor */
  NQTEQI(chain(L("rsa_leaf_deep"), pool + 1, 1, NULL, 0, t, 0, &np), NQOK);
  /* rsa_inter2 itself is fine under rsa_inter */
  NQTEQI(chain(L("rsa_inter2"), anc, 1, pool, 1, t, 0, &np), NQOK);
  /* a leaf cannot issue: rsa_tsa as the "intermediate" of a cert it did
   * not sign fails on the names, and a non-CA anchor cannot issue */
  pool[2] = *L("rsa_tsa");
  NQTEQI(chain(L("rsa_leaf_good"), anc, 1, pool + 2, 1, t, 0, &np),
         NQEVRFY);
  /* a tampered signature */
  c = *tsa;
  {
    uint8_t tmp[4096];
    memcpy(tmp, c.raw.p, c.raw.n);
    tmp[c.raw.n - 1] ^= 1;
    NQTEQI(nqcprs(tmp, c.raw.n, &c), NQOK);
    NQTEQI(chain(&c, anc, 1, pool, 1, t, 0, &np), NQEVRFY);
  }
  /* an unrecognised critical extension makes the certificate unusable */
  c = *tsa;
  c.bad = 1;
  NQTEQI(chain(&c, anc, 1, pool, 1, t, 0, &np), NQEVRFY);
  /* an issuer without keyCertSign */
  pool[3] = *L("rsa_inter");
  pool[3].ku = NQXKUCRL;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, 0, &np), NQEVRFY);
  pool[3].ext &= ~(unsigned)NQXHASKU;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, 0, &np), NQEVRFY);
  pool[3] = *L("rsa_inter");
  pool[3].ca = 0;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, 0, &np), NQEVRFY);
  /* an issuer whose purposes exclude the leaf's */
  pool[3] = *L("rsa_inter");
  pool[3].ext |= NQXHASEKU;
  pool[3].eku = NQXEKUSRV;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, NQXEKUTS, &np), NQEVRFY);
  pool[3].eku = NQXEKUANY;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, NQXEKUTS, &np), NQOK);
  /* key identifiers that disagree */
  pool[3] = *L("rsa_inter");
  pool[3].ski.p = L("rsa_root")->ski.p;
  NQTEQI(chain(tsa, anc, 1, pool + 3, 1, t, 0, &np), NQEVRFY);
  /* anchors match by subject and key */
  NQTEQI(nqxalias(L("rsa_inter"), L("rsa_inter")), 1);
  NQTEQI(nqxalias(L("rsa_inter"), L("rsa_root")), 0);
  NQTEQI(nqxalias(L("rsa_inter2"), L("rsa_inter")), 0);
  NQTEQI(nqxalias(NULL, L("rsa_root")), 0);
  c = *L("rsa_inter");
  c.subject = L("rsa_root")->subject; /* same key, another name */
  NQTEQI(nqxalias(&c, L("rsa_inter")), 0);
  c = *L("rsa_inter");
  c.key.spki = L("rsa_root")->key.spki; /* same name, another key */
  NQTEQI(nqxalias(&c, L("rsa_inter")), 0);
  c = *L("rsa_inter");
  c.ski.n = 0; /* no SKI: the key bytes still decide */
  NQTEQI(nqxalias(&c, L("rsa_inter")), 1);
  /* EC and ML-DSA */
  anc[0] = *L("ec_root");
  NQTEQI(chain(L("ec_tsa"), anc, 1, NULL, 0, L("ec_tsa")->nb + 60, NQXEKUTS,
               &np),
         NQOK);
  anc[0] = *L("ml_root");
  NQTEQI(chain(L("ml_tsa"), anc, 1, NULL, 0, L("ml_tsa")->nb + 60, NQXEKUTS,
               &np),
         NQOK);
  anc[1] = *L("rsa_root");
  NQTEQI(chain(L("ml_tsa"), anc + 1, 1, NULL, 0, L("ml_tsa")->nb + 60, 0,
               &np),
         NQEVRFY);
  /* bad arguments */
  NQTEQI(chain(tsa, anc, 0, pool, 1, t, 0, &np), NQEARG);
  /* the rmoriebricklayer chains */
  {
    nqcert root, inter, leaf, e;
    int64_t at;
    NQTEQI(nqcprs(BL("chain_root")->p, BL("chain_root")->n, &root), NQOK);
    NQTEQI(nqcprs(BL("chain_inter")->p, BL("chain_inter")->n, &inter),
           NQOK);
    NQTEQI(nqcprs(BL("chain_leaf")->p, BL("chain_leaf")->n, &leaf), NQOK);
    at = leaf.nb + 86400;
    NQTEQI(chain(&leaf, &root, 1, &inter, 1, at, 0, &np), NQOK);
    NQTEQI(np, 3);
    /* chain_leaf2 was issued by chain_leaf, which is no CA */
    {
      nqcert two[2];
      two[0] = inter;
      two[1] = leaf;
      NQTEQI(nqcprs(BL("chain_leaf2")->p, BL("chain_leaf2")->n, &e), NQOK);
      NQTEQI(chain(&e, &root, 1, two, 2, at, 0, &np), NQEVRFY);
      /* nor is it an anchor that can issue */
      NQTEQI(chain(&e, &leaf, 1, NULL, 0, at, 0, &np), NQEVRFY);
    }
    /* chain_leaf512: SHA-512, straight under the root */
    NQTEQI(nqcprs(BL("chain_leaf512")->p, BL("chain_leaf512")->n, &leaf),
           NQOK);
    NQTEQI(chain(&leaf, &root, 1, NULL, 0, at, 0, &np), NQOK);
    NQTEQI(np, 2);
    NQTEQI(nqcprs(BL("chain_ec256")->p, BL("chain_ec256")->n, &e), NQOK);
    NQTEQI(nqcprs(BL("chain_ecleaf256")->p, BL("chain_ecleaf256")->n,
                  &leaf),
           NQOK);
    NQTEQI(chain(&leaf, &e, 1, NULL, 0, leaf.nb + 60, 0, &np), NQOK);
    NQTEQI(nqcprs(BL("chain_ec384")->p, BL("chain_ec384")->n, &e), NQOK);
    NQTEQI(nqcprs(BL("chain_ecleaf384")->p, BL("chain_ecleaf384")->n,
                  &leaf),
           NQOK);
    NQTEQI(chain(&leaf, &e, 1, NULL, 0, leaf.nb + 60, 0, &np), NQOK);
    /* a CA with a critical nameConstraints is unusable here */
    NQTEQI(nqcprs(BL("nc_ca")->p, BL("nc_ca")->n, &e), NQOK);
    NQTEQI(nqcprs(BL("nc_leaf_good")->p, BL("nc_leaf_good")->n, &leaf),
           NQOK);
    NQTEQI(chain(&leaf, &e, 1, NULL, 0, leaf.nb + 60, NQXEKUTS, &np),
           NQEVRFY);
    /* pol_ca issues the pol_* leaves */
    NQTEQI(nqcprs(BL("pol_ca")->p, BL("pol_ca")->n, &e), NQOK);
    NQTEQI(nqcprs(BL("pol_leaf_ok")->p, BL("pol_leaf_ok")->n, &leaf), NQOK);
    NQTEQI(chain(&leaf, &e, 1, NULL, 0, leaf.nb + 60, NQXEKUTS, &np), NQOK);
  }
}

/* ---- OCSP and CRLs ---- */

static tdbuf lread(const char *name) {
  char path[128];
  snprintf(path, sizeof path, "vectors/der/local/%s.der", name);
  return tdread(path);
}

static int ocsp(const char *name, const nqcert *leaf, int64_t t,
                const nqxops *ops, int *st) {
  const nqcert *path[3];
  tdbuf b = lread(name);
  int r;
  path[0] = leaf;
  path[1] = L("rsa_inter");
  path[2] = L("rsa_root");
  r = nqocsp(b.p, b.n, path, 3, 0, t, ops, st);
  tdfree(&b);
  return r;
}

static void tocsp(void) {
  const nqcert *good = L("rsa_leaf_good");
  int64_t t = good->nb + 3600;
  int st;
  NQTEQI(ocsp("o_good", good, t, tdops(1), &st), NQOK);
  NQTEQI(st, NQXGOOD);
  /* SHA-1 CertID needs the SHA-1 hook */
  NQTEQI(ocsp("o_good", good, t, tdops(0), &st), NQENOSUP);
  NQTEQI(ocsp("o_good256", good, t, tdops(0), &st), NQOK);
  NQTEQI(ocsp("o_nocerts", good, t, tdops(0), &st), NQOK);
  NQTEQI(ocsp("o_deleg", good, t, tdops(1), &st), NQOK);
  /* byKey responder id: SHA-1 of the key */
  NQTEQI(ocsp("o_keyid", good, t, tdops(1), &st), NQOK);
  NQTEQI(ocsp("o_keyid", good, t, tdops(0), &st), NQENOSUP);
  NQTEQI(ocsp("o_rev", L("rsa_leaf_rev"), t, tdops(1), &st), NQEVRFY);
  NQTEQI(st, NQXREVOKED);
  NQTEQI(ocsp("o_unk", L("rsa_leaf_unk"), t, tdops(1), &st), NQEVRFY);
  NQTEQI(st, NQXUNKNOWN);
  /* about another certificate */
  NQTEQI(ocsp("o_good", L("rsa_leaf_rev"), t, tdops(1), &st), NQEVRFY);
  NQTEQI(st, -1);
  NQTEQI(ocsp("o_rev", good, t, tdops(1), &st), NQEVRFY);
  /* freshness, 300 s either way */
  NQTEQI(ocsp("o_good", good, t + 31 * 86400, tdops(1), &st), NQEVRFY);
  NQTEQI(ocsp("o_good", good, good->nb - 3600, tdops(1), &st), NQEVRFY);
  /* the delegated responder is valid only for the issuer that signed it;
   * under another issuer the response is nobody's */
  {
    const nqcert *path[2];
    tdbuf b = lread("o_deleg");
    path[0] = good;
    path[1] = L("rsa_root");
    NQTEQI(nqocsp(b.p, b.n, path, 2, 0, t, tdops(1), &st), NQEVRFY);
    path[1] = L("rsa_inter");
    NQTEQI(nqocsp(b.p, b.n, path, 2, 0, t, tdops(1), &st), NQOK);
    NQTEQI(nqocsp(b.p, b.n, path, 1, 0, t, tdops(1), &st), NQEARG);
    NQTEQI(nqocsp(b.p, b.n, path, 2, 1, t, tdops(1), &st), NQEARG);
    tdfree(&b);
  }
  /* the rmoriebricklayer responses, at its test times */
  {
    nqcert leaf, ca, rv, ecca;
    const nqcert *path[2];
    int64_t at = 1791590400;    /* 2026-10-10 */
    int64_t late = 1796083200;  /* 2026-12-01 */
    int64_t early = 1788220800; /* 2026-09-01 */
    const tdbuf *g = BL("ocsp_resp_good");
    nqcprs(BL("ocsp_good")->p, BL("ocsp_good")->n, &leaf);
    nqcprs(BL("ocsp_ca")->p, BL("ocsp_ca")->n, &ca);
    nqcprs(BL("ocsp_revoked")->p, BL("ocsp_revoked")->n, &rv);
    nqcprs(BL("ocsp_ecca")->p, BL("ocsp_ecca")->n, &ecca);
    path[0] = &leaf;
    path[1] = &ca;
    NQTEQI(nqocsp(g->p, g->n, path, 2, 0, at, tdops(1), &st), NQOK);
    NQTEQI(nqocsp(g->p, g->n, path, 2, 0, late, tdops(1), &st), NQEVRFY);
    NQTEQI(nqocsp(g->p, g->n, path, 2, 0, early, tdops(1), &st), NQEVRFY);
    /* freshness: with and without nextUpdate (review of a4eec67, I1) */
    NQTEQI(nqocspnow(at - 60, at - 60, 1, at + 86400, at), 1);
    NQTEQI(nqocspnow(at - 60, at - 60, 1, at - 3600, at), 0);
    NQTEQI(nqocspnow(at + 3600, at - 60, 1, at + 86400, at), 0);
    NQTEQI(nqocspnow(at - 60, at + 3600, 1, at + 86400, at), 0);
    NQTEQI(nqocspnow(at - 60, at - 60, 1, at - 120, at), 0);
    NQTEQI(nqocspnow(at - 86400, at - 86400, 0, 0, at), 1);
    NQTEQI(nqocspnow(at - 8 * 86400, at - 8 * 86400, 0, 0, at), 0);
    NQTEQI(nqocspnow(at - 400 * 86400, at - 400 * 86400, 0, 0, at), 0);
    NQTEQI(nqocsp(BL("ocsp_resp_good_nocerts")->p,
                  BL("ocsp_resp_good_nocerts")->n, path, 2, 0, at, tdops(1),
                  &st),
           NQOK);
    NQTEQI(nqocsp(BL("ocsp_resp_good_delegated")->p,
                  BL("ocsp_resp_good_delegated")->n, path, 2, 0, at,
                  tdops(1), &st),
           NQOK);
    NQTEQI(nqocsp(BL("ocsp_resp_revoked")->p, BL("ocsp_resp_revoked")->n,
                  path, 2, 0, at, tdops(1), &st),
           NQEVRFY);
    path[0] = &rv;
    NQTEQI(nqocsp(BL("ocsp_resp_revoked")->p, BL("ocsp_resp_revoked")->n,
                  path, 2, 0, at, tdops(1), &st),
           NQEVRFY);
    NQTEQI(st, NQXREVOKED);
    NQTEQI(nqocsp(g->p, g->n, path, 2, 0, at, tdops(1), &st), NQEVRFY);
    path[0] = &leaf;
    path[1] = &ecca;
    NQTEQI(nqocsp(BL("ocsp_resp_good_delegated")->p,
                  BL("ocsp_resp_good_delegated")->n, path, 2, 0, at,
                  tdops(1), &st),
           NQEVRFY);
    {
      nqcert ecl;
      nqcprs(BL("ocsp_ecleaf")->p, BL("ocsp_ecleaf")->n, &ecl);
      path[0] = &ecl;
      NQTEQI(nqocsp(BL("ocsp_resp_ec_good")->p, BL("ocsp_resp_ec_good")->n,
                    path, 2, 0, at, tdops(1), &st),
             NQOK);
    }
  }
}

static int crl(const char *name, const nqcert *leaf, const nqcert *iss,
               int64_t t) {
  const nqcert *path[3];
  tdbuf b = lread(name);
  int r;
  path[0] = leaf;
  path[1] = iss;
  path[2] = L("rsa_root");
  r = nqcrl(b.p, b.n, path, 3, 0, t, tdops(1));
  tdfree(&b);
  return r;
}

static void tcrl(void) {
  const nqcert *good = L("rsa_leaf_good"), *in = L("rsa_inter");
  int64_t t = good->nb + 3600;
  NQTEQI(crl("rsa_crl", good, in, t), NQOK);
  NQTEQI(crl("rsa_crl", L("rsa_leaf_rev"), in, t), NQEVRFY);
  NQTEQI(crl("rsa_crl", L("rsa_leaf_unk"), in, t), NQOK);
  /* stale, and not yet issued */
  NQTEQI(crl("rsa_crl", good, in, t + 31 * 86400), NQEVRFY);
  NQTEQI(crl("rsa_crl", good, in, good->nb - 3600), NQEVRFY);
  /* the root's CRL does not cover what rsa_inter issued */
  NQTEQI(crl("rsa_crl_root", good, in, t), NQEVRFY);
  /* but covers rsa_inter itself */
  {
    const nqcert *path[2];
    tdbuf b = lread("rsa_crl_root");
    path[0] = in;
    path[1] = L("rsa_root");
    NQTEQI(nqcrl(b.p, b.n, path, 2, 0, t, tdops(0)), NQOK);
    /* not signed by a CA of the path */
    path[1] = L("ec_root");
    NQTEQI(nqcrl(b.p, b.n, path, 2, 0, t, tdops(0)), NQEVRFY);
    tdfree(&b);
  }
  /* the rmoriebricklayer CRLs */
  {
    nqcert leaf, ca, oca;
    const nqcert *path[2];
    int64_t at;
    nqcprs(BL("nc_leaf_good")->p, BL("nc_leaf_good")->n, &leaf);
    nqcprs(BL("nc_ca")->p, BL("nc_ca")->n, &ca);
    nqcprs(BL("ocsp_ca")->p, BL("ocsp_ca")->n, &oca);
    at = ca.nb + 86400;
    path[0] = &leaf;
    path[1] = &ca;
    NQTEQI(nqcrl(BL("nc_crl")->p, BL("nc_crl")->n, path, 2, 0, at, tdops(0)),
           NQEVRFY);
    NQTEQI(nqcrl(BL("nc_crl")->p, BL("nc_crl")->n, path, 2, 1, at, tdops(0)),
           NQOK);
    NQTEQI(nqcrl(BL("nc_crl")->p, BL("nc_crl")->n, path, 2, 1,
                 at + 365 * 86400, tdops(0)),
           NQEVRFY);
    NQTEQI(nqcrl(BL("ocsp_crl_der")->p, BL("ocsp_crl_der")->n, path, 2, 1,
                 at, tdops(0)),
           NQEVRFY);
    {
      uint8_t tmp[4096];
      const tdbuf *c = BL("nc_crl");
      memcpy(tmp, c->p, c->n);
      tmp[c->n - 1] ^= 1;
      NQTEQI(nqcrl(tmp, c->n, path, 2, 1, at, tdops(0)), NQEVRFY);
    }
    path[0] = &oca;
    path[1] = &oca;
    NQTEQI(nqcrl(BL("ocsp_crl_der")->p, BL("ocsp_crl_der")->n, path, 2, 1,
                 oca.nb + 86400, tdops(0)),
           NQOK);
  }
}

/* ---- mutations ---- */

typedef int (*chkfn)(const uint8_t *p, size_t n, const void *arg);

/* Flips every bit and every whole byte of p, one at a time; returns how
 * many mutations still pass chk. */
static unsigned long mutate(const uint8_t *p, size_t n, chkfn chk,
                            const void *arg, const char *what) {
  static uint8_t m[16384];
  unsigned long acc = 0, tried = 0;
  size_t i;
  unsigned k;
  if (n > sizeof m) {
    NQTCHK(n <= sizeof m);
    return 1;
  }
  memcpy(m, p, n);
  NQTEQI(chk(m, n, arg), NQOK);
  if (rec) {
    return 0; /* record mode: the clean check only */
  }
  for (i = 0; i < n; i++) {
    for (k = tdquick() ? 8 : 0; k <= 8; k++) {
      uint8_t x = (uint8_t)(k < 8 ? 1u << k : 0xffu);
      m[i] ^= x;
      tried++;
      if (chk(m, n, arg) == NQOK) {
        acc++;
        fprintf(stderr, "%s: mutation at %zu (^%02x) accepted\n", what, i,
                x);
      }
      m[i] ^= x;
    }
  }
  printf("%s: %lu mutations, %lu accepted\n", what, tried, acc);
  return acc;
}

typedef struct {
  const nqcert *iss;
  int64_t t;
} carg;

static int certchk(const uint8_t *p, size_t n, const void *arg) {
  const carg *a = (const carg *)arg;
  nqcert c;
  size_t np;
  int r = nqcprs(p, n, &c);
  if (r != NQOK) {
    return r;
  }
  if (nqxneq(a->iss->subject, a->iss->issuer)) {
    /* a self-signed root has no path of its own: its signature, under
     * the original's key, and its names and validity */
    if (c.bad || !nqxneq(c.issuer, a->iss->subject) || a->t < c.nb ||
        a->t > c.na) {
      return NQEVRFY;
    }
    return nqxvrfy(tdops(1), &a->iss->key, &c.salg, c.tbs, c.sig);
  }
  return chain(&c, a->iss, 1, NULL, 0, a->t, 0, &np);
}

typedef struct {
  const nqcert *const *path;
  size_t np;
  int64_t t;
  int crl;
} rarg;

static int revchk(const uint8_t *p, size_t n, const void *arg) {
  const rarg *a = (const rarg *)arg;
  if (a->crl) {
    return nqcrl(p, n, a->path, a->np, 0, a->t, tdops(1));
  }
  return nqocsp(p, n, a->path, a->np, 0, a->t, tdops(1), NULL);
}

/* ---- trust anchors: a root's serial is only a label ---- */

/* the certificate in src (outer and tbs SEQUENCEs in the 0x82 long form,
 * version [0] then serialNumber at offset 13) with its serialNumber TLV
 * replaced by ser */
static size_t reser(const tdbuf *src, const uint8_t *ser, size_t sn,
                    uint8_t *out, size_t cap) {
  size_t ol, tl, old, n;
  NQTCHK(src->n > 15 && src->p[1] == 0x82 && src->p[5] == 0x82 &&
         src->p[13] == 0x02 && src->p[14] < 0x80);
  old = 2 + (size_t)src->p[14];
  ol = ((size_t)src->p[2] << 8 | src->p[3]) - old + sn;
  tl = ((size_t)src->p[6] << 8 | src->p[7]) - old + sn;
  n = src->n - old + sn;
  NQTCHK(n <= cap);
  memcpy(out, src->p, 13);
  out[2] = (uint8_t)(ol >> 8);
  out[3] = (uint8_t)ol;
  out[6] = (uint8_t)(tl >> 8);
  out[7] = (uint8_t)tl;
  memcpy(out + 13, ser, sn);
  memcpy(out + 13 + sn, src->p + 13 + old, src->n - 13 - old);
  return n;
}

static void tanch(void) {
  static const uint8_t zero[] = {0x02, 0x01, 0x00};
  static const uint8_t neg[] = {0x02, 0x01, 0xff};
  static const uint8_t negl[] = {0x02, 0x02, 0x80, 0x01};
  static const uint8_t pad[] = {0x02, 0x02, 0x00, 0x01};
  static const uint8_t one[] = {0x02, 0x01, 0x01};
  static const uint8_t empty[] = {0x02, 0x00};
  static const uint8_t octs[] = {0x04, 0x01, 0x00};
  static const uint8_t big[] = {0x02, 0x15, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  static const struct {
    const uint8_t *s;
    size_t n;
    int leaf, anc;
  } cs[] = {
      {zero, sizeof zero, NQEDEC, NQOK},  {neg, sizeof neg, NQEDEC, NQOK},
      {negl, sizeof negl, NQEDEC, NQOK},  {pad, sizeof pad, NQEDEC, NQEDEC},
      {one, sizeof one, NQOK, NQOK},      {empty, sizeof empty, NQEDEC, NQEDEC},
      {octs, sizeof octs, NQEDEC, NQEDEC}, {big, sizeof big, NQELIM, NQELIM},
  };
  static uint8_t b[4096], ib[4096];
  size_t i, n, np;
  nqcert c, anc, pool;
  const tdbuf *root = &locb[0], *inter = &locb[1];
  const nqcert *tsa = L("rsa_tsa");
  NQTCHK(strcmp(locn[0], "rsa_root") == 0 &&
         strcmp(locn[1], "rsa_inter") == 0);
  for (i = 0; i < sizeof cs / sizeof cs[0]; i++) {
    n = reser(root, cs[i].s, cs[i].n, b, sizeof b);
    NQTEQI(nqcprs(b, n, &c), cs[i].leaf);
    NQTEQI(nqcprsa(b, n, &c), cs[i].anc);
    /* an intermediate is never an anchor: it stays strict */
    n = reser(inter, cs[i].s, cs[i].n, ib, sizeof ib);
    NQTEQI(nqcprs(ib, n, &c), cs[i].leaf);
  }
  /* a root with serial 0 still anchors the TSA's path: its key and name
   * are what the path checks */
  n = reser(root, zero, sizeof zero, b, sizeof b);
  NQTEQI(nqcprsa(b, n, &anc), NQOK);
  pool = *L("rsa_inter");
  NQTEQI(chain(tsa, &anc, 1, &pool, 1, tsa->nb + 86400, NQXEKUTS, &np),
         NQOK);
  NQTEQI(np, 3);
  /* the parsed fields are those of the strict parse of the original */
  NQTEQI(nqxneq(anc.subject, L("rsa_root")->subject), 1);
  NQTEQI(anc.nb == L("rsa_root")->nb && anc.na == L("rsa_root")->na, 1);
}

static void tmut(void) {
  static const char *pairs[][2] = {
      {"rsa_root", "rsa_root"},       {"rsa_inter", "rsa_root"},
      {"rsa_tsa", "rsa_inter"},       {"rsa_leaf_good", "rsa_inter"},
      {"rsa_resp", "rsa_inter"},      {"ec_root", "ec_root"},
      {"ec_tsa", "ec_root"},          {"ml_root", "ml_root"},
      {"ml_tsa", "ml_root"},
  };
  static const char *blpairs[][2] = {
      {"chain_leaf", "chain_inter"}, {"chain_inter", "chain_root"},
      {"chain_ecleaf384", "chain_ec384"}, {"ocsp_responder", "ocsp_ca"},
  };
  size_t i;
  unsigned long acc = 0;
  const nqcert *path[3];
  rarg ra;
  for (i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
    carg a;
    const nqcert *c = L(pairs[i][0]);
    a.iss = L(pairs[i][1]);
    a.t = c->nb + 60;
    acc += mutate(c->raw.p, c->raw.n, certchk, &a, pairs[i][0]);
  }
  for (i = 0; i < sizeof blpairs / sizeof blpairs[0]; i++) {
    carg a;
    nqcert c, iss;
    nqcprs(BL(blpairs[i][0])->p, BL(blpairs[i][0])->n, &c);
    nqcprs(BL(blpairs[i][1])->p, BL(blpairs[i][1])->n, &iss);
    a.iss = &iss;
    a.t = c.nb + 60;
    acc += mutate(c.raw.p, c.raw.n, certchk, &a, blpairs[i][0]);
  }
  /* OCSP: the good answers (direct, delegated, by key) and the CRL */
  path[1] = L("rsa_inter");
  path[2] = L("rsa_root");
  ra.path = path;
  ra.np = 3;
  ra.t = L("rsa_leaf_good")->nb + 3600;
  {
    static const char *names[] = {"o_good", "o_deleg", "o_keyid",
                                  "o_good256", "rsa_crl"};
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
      tdbuf b = lread(names[i]);
      path[0] = L("rsa_leaf_good");
      ra.crl = strcmp(names[i], "rsa_crl") == 0;
      acc += mutate(b.p, b.n, revchk, &ra, names[i]);
      tdfree(&b);
    }
  }
  {
    nqcert leaf, ca;
    const nqcert *bp[2];
    nqcprs(BL("ocsp_good")->p, BL("ocsp_good")->n, &leaf);
    nqcprs(BL("ocsp_ca")->p, BL("ocsp_ca")->n, &ca);
    bp[0] = &leaf;
    bp[1] = &ca;
    ra.path = bp;
    ra.np = 2;
    ra.t = 1791590400;
    ra.crl = 0;
    acc += mutate(BL("ocsp_resp_good_delegated")->p,
                  BL("ocsp_resp_good_delegated")->n, revchk, &ra,
                  "ocsp_resp_good_delegated");
  }
  /* no mutation is harmless in a certificate, an OCSP response or a CRL:
   * every byte is signed, or is the signature, or is checked against a
   * signed copy (the outer AlgorithmIdentifier), or decides the result
   * (responseStatus, responseType) */
  NQTEQI(acc, 0);
}

int main(void) {
  rec = tdorinit();
  nfx = tdlines("vectors/der/bricklayer-x509.txt", fx, TDMAXFX);
  NQTEQI(nfx, 43);
  loadloc();
  tparse();
  talg();
  tname();
  tchain();
  tocsp();
  tcrl();
  tanch();
  tmut();
  printf("tx509: %lu signature checks\n", tdcalls);
#ifdef NQDCLS
  printf("%s: cls and the oracle disagreed %lu times\n", __FILE__, tddiff);
  NQTEQI(tddiff, 0);
#endif
  tdordone();
  return nqtdone("tx509");
}
