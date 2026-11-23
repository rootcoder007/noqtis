/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * X.509 certificates for noqtis keys and the Cryptographic Message
 * Syntax over them: what S/MIME is made of.
 *
 * Certificates (RFC 5280): a self-signed one for a signature key, ML-DSA
 * (RFC 9881), SLH-DSA (RFC 9909) or Ed25519 (RFC 8410), which is a CA of
 * path length 0 so that it can issue the second kind: a certificate for
 * an ML-KEM key (RFC 9935) under the same name. A key's holder gives the
 * first to those who are to trust it, as an anchor.
 *
 * SignedData (RFC 5652, with RFC 9882, RFC 9814, RFC 8419): one signer,
 * signed attributes always written (content type, signing time, message
 * digest), the content inside or detached. Read: a SignedData of one
 * signer by any algorithm the X.509 code verifies, with or without
 * signed attributes, its signer's certificate checked to one of the
 * caller's anchors.
 *
 * AuthEnvelopedData (RFC 5083) with AES-256-GCM (RFC 5084), the content
 * key carried to each ML-KEM recipient in a KEMRecipientInfo (RFC 9629,
 * RFC 9936): HKDF-SHA-256 of the shared secret, AES Key Wrap.
 */
#include <string.h>

#include "aead/aead.h"
#include "cap/cap.h"
#include "core/int.h"
#include "der/der.h"
#include "der/x509.h"
#include "hash/h.h"

#define OID(name, ...) static const uint8_t name[] = {__VA_ARGS__}

OID(odata, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01);
OID(osigned, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02);
OID(oauthenv, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01,
    0x17);
OID(octype, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03);
OID(omd, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04);
OID(ostime, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05);
OID(osha256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
OID(osha384, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02);
OID(osha512, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03);
OID(oshake128, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b);
OID(oshake256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c);
OID(oed, 0x2b, 0x65, 0x70);
OID(ogcm128, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06);
OID(ogcm256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e);
OID(owrap128, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05);
OID(owrap256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d);
OID(oorikem, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x0d,
    0x03);
OID(ohkdf256, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03,
    0x1c);
OID(ocn, 0x55, 0x04, 0x03);
OID(obc, 0x55, 0x1d, 0x13);
OID(oku, 0x55, 0x1d, 0x0f);
OID(oeku, 0x55, 0x1d, 0x25);
OID(oski, 0x55, 0x1d, 0x0e);
OID(oaki, 0x55, 0x1d, 0x23);
OID(osan, 0x55, 0x1d, 0x11);
OID(omail, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04);
/* 2.16.840.1.101.3.4.3.<17..31> and 2.16.840.1.101.3.4.4.<1..3> */
static const uint8_t sigpre[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                 0x03, 0x04, 0x03};
static const uint8_t kempre[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                 0x03, 0x04, 0x04};

#define CMSMAX ((size_t)1 << 30) /* one message */
#define MAXCERT 16               /* certificates one SignedData carries */
#define MAXRCP 32                /* recipients of one message */
#define SATTRMAX 4096            /* signed attributes of one signer */

/* ---- algorithm identifiers ---- */

/* the OID of a signature algorithm a certificate can carry; 0 when
 * there is none (the hybrids have no standard encoding) */
static size_t sigoid(nqsalg a, uint8_t out[9]) {
  if (a == NQED25519) {
    memcpy(out, oed, sizeof oed);
    return sizeof oed;
  }
  if (a < NQMLDSA44 || a > NQSLHK256F) return 0;
  memcpy(out, sigpre, sizeof sigpre);
  out[8] = (uint8_t)(17 + (a - NQMLDSA44));
  return 9;
}

static void algid(nqdw *w, const uint8_t *oid, size_t n) {
  size_t m = nqdwopen(w, NQDWSEQ);
  nqdwoid(w, oid, n);
  nqdwclose(w, m);
}

static void sigaid(nqdw *w, nqsalg a) {
  uint8_t o[9];
  size_t n = sigoid(a, o);
  algid(w, o, n);
}

/* the digest a signer of algorithm a uses in CMS: SHA-512 for ML-DSA
 * (RFC 9882) and Ed25519 (RFC 8419); for SLH-DSA the hash of its tree
 * (RFC 9814) */
static nqhalg dalg(nqsalg a) {
  switch (a) {
  case NQSLH128S:
  case NQSLH128F:
    return NQS256;
  case NQSLHK128S:
  case NQSLHK128F:
    return NQSHK128;
  case NQSLHK192S:
  case NQSLHK192F:
  case NQSLHK256S:
  case NQSLHK256F:
    return NQSHK256;
  default:
    return NQS512;
  }
}

/* the bytes of a CMS digest: SHAKE128 gives 32, SHAKE256 64 (RFC 8702) */
static size_t dlen(nqhalg h) {
  return h == NQSHK128 ? 32 : h == NQSHK256 ? 64 : nqhlen(h);
}

static void daid(nqdw *w, nqhalg h) {
  switch (h) {
  case NQS256:
    algid(w, osha256, sizeof osha256);
    break;
  case NQS384:
    algid(w, osha384, sizeof osha384);
    break;
  case NQSHK128:
    algid(w, oshake128, sizeof oshake128);
    break;
  case NQSHK256:
    algid(w, oshake256, sizeof oshake256);
    break;
  default:
    algid(w, osha512, sizeof osha512);
    break;
  }
}

/* an AlgorithmIdentifier of a digest: its OID, parameters absent or
 * NULL */
static int dread(const nqdtlv *aid, nqhalg *h) {
  nqdcur c;
  nqdtlv oid, par;
  if (aid->cls != NQDUNI || aid->tag != NQDSEQ || nqddown(aid, &c) != NQOK ||
      nqdnext(&c, &oid) != NQOK || oid.cls != NQDUNI || oid.tag != NQDOID)
    return NQEDEC;
  if (!nqdend(&c) &&
      (nqdnext(&c, &par) != NQOK || nqdnull(&par) != NQOK ||
       nqddone(&c) != NQOK))
    return NQEDEC;
  if (nqdoideq(&oid, osha256, sizeof osha256))
    *h = NQS256;
  else if (nqdoideq(&oid, osha384, sizeof osha384))
    *h = NQS384;
  else if (nqdoideq(&oid, osha512, sizeof osha512))
    *h = NQS512;
  else if (nqdoideq(&oid, oshake128, sizeof oshake128))
    *h = NQSHK128;
  else if (nqdoideq(&oid, oshake256, sizeof oshake256))
    *h = NQSHK256;
  else
    return NQENOSUP;
  return NQOK;
}

/* ---- certificates ---- */

/* Name: one RDN, the common name */
static void name(nqdw *w, const char *cn) {
  size_t a = nqdwopen(w, NQDWSEQ), b = nqdwopen(w, NQDWSET),
         c = nqdwopen(w, NQDWSEQ);
  nqdwoid(w, ocn, sizeof ocn);
  nqdwutf8(w, cn, strlen(cn));
  nqdwclose(w, c);
  nqdwclose(w, b);
  nqdwclose(w, a);
}

/* one extension: the OID, critical or not, the value's DER */
static void ext(nqdw *w, const uint8_t *oid, size_t on, int crit,
                const uint8_t *v, size_t vn) {
  size_t m = nqdwopen(w, NQDWSEQ);
  nqdwoid(w, oid, on);
  if (crit) nqdwbool(w, 1);
  nqdwoct(w, v, vn);
  nqdwclose(w, m);
}

/* the key identifier of a public key: the first 20 bytes of its
 * SHA-256 (RFC 7093, method 1) */
static void keyid(const uint8_t *pk, size_t n, uint8_t id[20]) {
  uint8_t d[32];
  nqhash(NQS256, pk, n, d, 32);
  memcpy(id, d, 20);
}

/* SubjectPublicKeyInfo: the algorithm with no parameters, the key */
static void spki(nqdw *w, const uint8_t *oid, size_t on, const uint8_t *pk,
                 size_t n) {
  size_t m = nqdwopen(w, NQDWSEQ);
  algid(w, oid, on);
  nqdwbits(w, pk, n);
  nqdwclose(w, m);
}

/* the extensions both kinds carry: key usage (ku, with ub unused bits),
 * the purpose e-mail protection, the subject key identifier, and the
 * given subjectAltName value when there is one */
static void exts(nqdw *w, int ca, uint8_t ku, uint8_t ub, const uint8_t *pk,
                 size_t pkn, const uint8_t *aki, const uint8_t *san,
                 size_t sann) {
  static const uint8_t bcca[] = {0x30, 0x06, 0x01, 0x01, 0xff,
                                 0x02, 0x01, 0x00};
  uint8_t v[32], id[20];
  size_t x = nqdwopen(w, NQDWCON(3)), s = nqdwopen(w, NQDWSEQ);
  if (ca) ext(w, obc, sizeof obc, 1, bcca, sizeof bcca);
  v[0] = 0x03;
  v[1] = 0x02;
  v[2] = ub;
  v[3] = ku;
  ext(w, oku, sizeof oku, 1, v, 4);
  v[0] = 0x30;
  v[1] = (uint8_t)(2 + sizeof omail);
  v[2] = 0x06;
  v[3] = (uint8_t)sizeof omail;
  memcpy(v + 4, omail, sizeof omail);
  ext(w, oeku, sizeof oeku, 0, v, 4 + sizeof omail);
  keyid(pk, pkn, id);
  v[0] = 0x04;
  v[1] = 20;
  memcpy(v + 2, id, 20);
  ext(w, oski, sizeof oski, 0, v, 22);
  if (aki != NULL) {
    v[0] = 0x30;
    v[1] = 22;
    v[2] = 0x80;
    v[3] = 20;
    memcpy(v + 4, aki, 20);
    ext(w, oaki, sizeof oaki, 0, v, 24);
  }
  if (san != NULL) ext(w, osan, sizeof osan, 0, san, sann);
  nqdwclose(w, s);
  nqdwclose(w, x);
}

/* signs the TBSCertificate in t with the issuer's key and writes the
 * certificate to out */
static int certout(nqdw *t, nqsalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *pk, size_t pklen, uint8_t *out, size_t cap,
                   size_t *outlen) {
  nqdw w;
  nqssz sz;
  uint8_t *tbs = NULL, *sg = NULL, *c = NULL;
  size_t tn = 0, sn = 0, cn = 0, m;
  int rc = nqdwend(t, &tbs, &tn);
  if (rc != NQOK) return rc;
  memset(&sz, 0, sizeof sz);
  nqdwini(&w);
  rc = nqssize(alg, &sz);
  if (rc != NQOK) goto done;
  sg = (uint8_t *)nqmal(sz.sig);
  if (sg == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = nqsign(alg, sk, sklen, tbs, tn, NULL, 0, 0, sg, sz.sig, &sn);
  /* a certificate is checked before it is given out, as a seal is */
  if (rc == NQOK && pk != NULL)
    rc = nqvrfy(alg, pk, pklen, tbs, tn, NULL, 0, 0, sg, sn);
  if (rc == NQEVRFY) rc = NQEARG; /* the key pair does not match */
  if (rc != NQOK) goto done;
  m = nqdwopen(&w, NQDWSEQ);
  nqdwraw(&w, tbs, tn);
  sigaid(&w, alg);
  nqdwbits(&w, sg, sn);
  nqdwclose(&w, m);
  rc = nqdwend(&w, &c, &cn);
  if (rc != NQOK) goto done;
  *outlen = cn;
  if (cap < cn)
    rc = NQEBUF;
  else
    memcpy(out, c, cn);
done:
  nqdwfree(&w);
  if (tbs != NULL) nqfree(tbs, tn > 0 ? tn : 1);
  if (sg != NULL) nqfree(sg, sz.sig);
  if (c != NULL) nqfree(c, cn > 0 ? cn : 1);
  return rc;
}

/* the start of a TBSCertificate: version 3, a random positive serial
 * of 16 bytes, the issuer's algorithm */
static int tbshead(nqdw *t, nqsalg ialg, size_t *mark) {
  uint8_t ser[16];
  size_t v;
  int rc = nqrand(ser, sizeof ser);
  if (rc != NQOK) return rc;
  ser[0] = (uint8_t)((ser[0] & 0x7f) | 0x40);
  *mark = nqdwopen(t, NQDWSEQ);
  v = nqdwopen(t, NQDWCON(0));
  nqdwuint(t, 2);
  nqdwclose(t, v);
  nqdwtlv(t, NQDINT, ser, sizeof ser);
  sigaid(t, ialg);
  return NQOK;
}

int nqx5self(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *pk,
             size_t pklen, const char *cn, const char *email, int64_t nb,
             int64_t na, uint8_t *out, size_t cap, size_t *outlen) {
  nqdw t, s;
  nqssz sz;
  uint8_t o[9], *san = NULL;
  size_t on, m = 0, v, sn = 0, x;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || pk == NULL || cn == NULL || outlen == NULL ||
      (out == NULL && cap != 0) || !nqcdok(cn, email) || nb < 0 || na <= nb)
    return NQEARG;
  on = sigoid(alg, o);
  if (on == 0 || nqssize(alg, &sz) != NQOK) return NQENOSUP;
  if (pklen != sz.pk || !nqsxlen(alg, sklen)) return NQEARG;
  nqdwini(&t);
  nqdwini(&s);
  /* subjectAltName: rfc822Name, where S/MIME looks for the address */
  if (email != NULL) {
    x = nqdwopen(&s, NQDWSEQ);
    nqdwtlv(&s, NQDWCTX(1), (const uint8_t *)email, strlen(email));
    nqdwclose(&s, x);
    rc = nqdwend(&s, &san, &sn);
    if (rc != NQOK) return rc;
  }
  rc = tbshead(&t, alg, &m);
  if (rc != NQOK) goto done;
  name(&t, cn);
  v = nqdwopen(&t, NQDWSEQ);
  nqdwtime(&t, nb, 0);
  nqdwtime(&t, na, 0);
  nqdwclose(&t, v);
  name(&t, cn);
  spki(&t, o, on, pk, pklen);
  /* digitalSignature, nonRepudiation, keyCertSign: it signs mail and
   * the certificate of its holder's KEM key */
  exts(&t, 1, 0xc4, 2, pk, pklen, NULL, san, sn);
  nqdwclose(&t, m);
  rc = certout(&t, alg, sk, sklen, pk, pklen, out, cap, outlen);
done:
  nqdwfree(&t);
  if (san != NULL) nqfree(san, sn > 0 ? sn : 1);
  return rc;
}

int nqx5kem(nqsalg ialg, const uint8_t *isk, size_t isklen,
            const uint8_t *icert, size_t icertlen, nqkalg alg,
            const uint8_t *pk, size_t pklen, int64_t nb, int64_t na,
            uint8_t *out, size_t cap, size_t *outlen) {
  nqdw t;
  nqcert ic;
  nqksz kz;
  nqssz sz;
  uint8_t o[9], aki[20], *san = NULL;
  size_t m = 0, v, sn = 0;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (isk == NULL || icert == NULL || pk == NULL || outlen == NULL ||
      (out == NULL && cap != 0) || nb < 0 || na <= nb)
    return NQEARG;
  if (alg < NQMLKEM512 || alg > NQMLKEM1024 || nqksize(alg, &kz) != NQOK ||
      nqssize(ialg, &sz) != NQOK || sigoid(ialg, o) == 0)
    return NQENOSUP;
  if (pklen != kz.pk || !nqsxlen(ialg, isklen)) return NQEARG;
  rc = nqcprs(icert, icertlen, &ic);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  /* the issuer's certificate is one this key signs under, and a CA */
  if (!ic.ca || ic.key.key.n != sz.pk ||
      !((ialg == NQED25519 && ic.key.type == NQXKED) ||
        (ic.key.type == NQXKPQ && ic.key.pq == ialg)))
    return NQEARG;
  keyid(ic.key.key.p, ic.key.key.n, aki);
  if (ic.san.n > 0) {
    /* the same address: the GeneralNames, in their SEQUENCE again */
    nqdw s;
    nqdwini(&s);
    v = nqdwopen(&s, NQDWSEQ);
    nqdwraw(&s, ic.san.p, ic.san.n);
    nqdwclose(&s, v);
    rc = nqdwend(&s, &san, &sn);
    if (rc != NQOK) return rc;
  }
  nqdwini(&t);
  rc = tbshead(&t, ialg, &m);
  if (rc != NQOK) goto done;
  nqdwraw(&t, ic.subject.p, ic.subject.n);
  v = nqdwopen(&t, NQDWSEQ);
  nqdwtime(&t, nb, 0);
  nqdwtime(&t, na, 0);
  nqdwclose(&t, v);
  nqdwraw(&t, ic.subject.p, ic.subject.n);
  memcpy(o, kempre, sizeof kempre);
  o[8] = (uint8_t)(1 + (alg - NQMLKEM512));
  spki(&t, o, 9, pk, pklen);
  /* keyEncipherment (RFC 9629): a KEM key only receives */
  exts(&t, 0, 0x20, 5, pk, pklen, aki, san, sn);
  nqdwclose(&t, m);
  rc = certout(&t, ialg, isk, isklen, ic.key.key.p, ic.key.key.n, out, cap,
               outlen);
done:
  nqdwfree(&t);
  if (san != NULL) nqfree(san, sn > 0 ? sn : 1);
  return rc;
}

/* what a parsed certificate says, for the caller */
static void info(const nqcert *c, const uint8_t *der, size_t n, nqx5f *f) {
  nqdcur rdns, set, av;
  nqdtlv t, a, oid, val;
  memset(f, 0, sizeof *f);
  nqhash(NQS256, der, n, f->fp, 32);
  f->nb = c->nb;
  f->na = c->na;
  f->ca = c->ca;
  f->pkoff = (size_t)(c->key.key.p - der);
  f->pklen = c->key.key.n;
  if (c->key.type == NQXKPQ) {
    f->alg = (int)c->key.pq;
  } else if (c->key.type == NQXKED) {
    f->alg = (int)NQED25519;
  } else if (c->key.type == NQXKKEM) {
    f->kem = 1;
    f->alg = (int)c->key.kem;
  }
  /* the common name: the last one of the subject, when it is short
   * text */
  nqdinit(&rdns, c->subject.p, c->subject.n);
  if (nqdnext(&rdns, &t) == NQOK && nqddown(&t, &rdns) == NQOK) {
    while (nqdnext(&rdns, &t) == NQOK) {
      if (nqddown(&t, &set) != NQOK) break;
      while (nqdnext(&set, &a) == NQOK) {
        if (nqddown(&a, &av) != NQOK || nqdnext(&av, &oid) != NQOK ||
            nqdnext(&av, &val) != NQOK)
          continue;
        if (nqdoideq(&oid, ocn, sizeof ocn) && val.cls == NQDUNI &&
            (val.tag == NQDUTF8 || val.tag == NQDPRT || val.tag == NQDIA5) &&
            val.v.n > 0 && val.v.n < sizeof f->name &&
            nqcinok((const char *)val.v.p, val.v.n)) {
          memcpy(f->name, val.v.p, val.v.n);
          f->name[val.v.n] = '\0';
        }
      }
    }
  }
  /* the address: the first rfc822Name of the subjectAltName */
  nqdinit(&set, c->san.p, c->san.n);
  while (nqdnext(&set, &t) == NQOK) {
    size_t i;
    int ok = t.cls == NQDCTX && t.tag == 1 && !t.con && t.v.n > 0 &&
             t.v.n < sizeof f->email;
    for (i = 0; ok && i < t.v.n; i++)
      ok = t.v.p[i] > 0x20 && t.v.p[i] < 0x7f;
    if (ok) {
      memcpy(f->email, t.v.p, t.v.n);
      f->email[t.v.n] = '\0';
      break;
    }
  }
}

int nqx5info(const uint8_t *cert, size_t n, nqx5f *f) {
  nqcert c;
  int rc;
  if (f != NULL) memset(f, 0, sizeof *f);
  if (cert == NULL || f == NULL) return NQEARG;
  rc = nqcprs(cert, n, &c);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  info(&c, cert, n, f);
  return NQOK;
}

/* ---- SignedData: writing ---- */

/* one attribute: the type, and its one value already in DER */
static void attr(nqdw *w, const uint8_t *oid, size_t on, const uint8_t *v,
                 size_t vn) {
  size_t a = nqdwopen(w, NQDWSEQ), s;
  nqdwoid(w, oid, on);
  s = nqdwopen(w, NQDWSET);
  nqdwraw(w, v, vn);
  nqdwclose(w, s);
  nqdwclose(w, a);
}

/* the signed attributes as the SET that is signed: content type,
 * signing time, message digest, which is their DER order (the shorter
 * element first) */
static void sattrs(nqdw *w, int64_t at, const uint8_t *dig, size_t dn) {
  nqdw v;
  size_t s = nqdwopen(w, NQDWSET);
  nqdwini(&v);
  nqdwoid(&v, odata, sizeof odata);
  attr(w, octype, sizeof octype, v.p, v.n);
  v.n = 0;
  nqdwtime(&v, at, 0);
  attr(w, ostime, sizeof ostime, v.p, v.n);
  v.n = 0;
  nqdwoct(&v, dig, dn);
  attr(w, omd, sizeof omd, v.p, v.n);
  if (v.err != NQOK && w->err == NQOK) w->err = v.err;
  nqdwfree(&v);
  nqdwclose(w, s);
}

int nqcmssign(nqsalg alg, const uint8_t *sk, size_t sklen,
              const uint8_t *cert, size_t certlen, const uint8_t *msg,
              size_t n, int detached, int64_t at, uint8_t *out, size_t cap,
              size_t *outlen) {
  nqdw a, w;
  nqcert c;
  nqssz sz;
  nqhalg h = dalg(alg);
  uint8_t dig[NQHMAX], *sg = NULL, *o = NULL;
  size_t dn = dlen(h), sn = 0, on = 0, ci, x, sd, e, si, s1;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || cert == NULL || outlen == NULL ||
      (msg == NULL && n != 0) || (out == NULL && cap != 0) || at < 0)
    return NQEARG;
  if (n > CMSMAX) return NQELIM;
  memset(&sz, 0, sizeof sz);
  if (nqssize(alg, &sz) != NQOK || alg > NQED25519) return NQENOSUP;
  if (!nqsxlen(alg, sklen)) return NQEARG;
  rc = nqcprs(cert, certlen, &c);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  /* the certificate is this key's */
  if (c.key.key.n != sz.pk ||
      !((alg == NQED25519 && c.key.type == NQXKED) ||
        (c.key.type == NQXKPQ && c.key.pq == alg)))
    return NQEARG;
  nqdwini(&a);
  nqdwini(&w);
  rc = nqhash(h, msg, n, dig, dn);
  if (rc != NQOK) goto done;
  sattrs(&a, at, dig, dn);
  if (a.err != NQOK) {
    rc = a.err;
    goto done;
  }
  sg = (uint8_t *)nqmal(sz.sig);
  if (sg == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = nqsign(alg, sk, sklen, a.p, a.n, NULL, 0, 0, sg, sz.sig, &sn);
  if (rc == NQOK)
    rc = nqvrfy(alg, c.key.key.p, c.key.key.n, a.p, a.n, NULL, 0, 0, sg, sn);
  if (rc == NQEVRFY) rc = NQEARG; /* the key is not the certificate's */
  if (rc != NQOK) goto done;
  ci = nqdwopen(&w, NQDWSEQ);
  nqdwoid(&w, osigned, sizeof osigned);
  x = nqdwopen(&w, NQDWCON(0));
  sd = nqdwopen(&w, NQDWSEQ);
  nqdwuint(&w, 1);
  s1 = nqdwopen(&w, NQDWSET);
  daid(&w, h);
  nqdwclose(&w, s1);
  e = nqdwopen(&w, NQDWSEQ);
  nqdwoid(&w, odata, sizeof odata);
  if (!detached) {
    size_t ec = nqdwopen(&w, NQDWCON(0));
    nqdwoct(&w, msg, n);
    nqdwclose(&w, ec);
  }
  nqdwclose(&w, e);
  /* certificates [0]: the signer's */
  s1 = nqdwopen(&w, NQDWCON(0));
  nqdwraw(&w, cert, certlen);
  nqdwclose(&w, s1);
  s1 = nqdwopen(&w, NQDWSET);
  si = nqdwopen(&w, NQDWSEQ);
  nqdwuint(&w, 1);
  e = nqdwopen(&w, NQDWSEQ);
  nqdwraw(&w, c.issuer.p, c.issuer.n);
  nqdwtlv(&w, NQDINT, c.serial.p, c.serial.n);
  nqdwclose(&w, e);
  daid(&w, h);
  /* signedAttrs [0] IMPLICIT: the same bytes under the other tag */
  e = nqdwopen(&w, NQDWCON(0));
  {
    nqdtlv t;
    rc = nqdhdr(a.p, a.n, &t);
    if (rc != NQOK) goto done;
    nqdwraw(&w, t.v.p, t.v.n);
  }
  nqdwclose(&w, e);
  sigaid(&w, alg);
  nqdwoct(&w, sg, sn);
  nqdwclose(&w, si);
  nqdwclose(&w, s1);
  nqdwclose(&w, sd);
  nqdwclose(&w, x);
  nqdwclose(&w, ci);
  rc = nqdwend(&w, &o, &on);
  if (rc != NQOK) goto done;
  *outlen = on;
  if (cap < on)
    rc = NQEBUF;
  else
    memcpy(out, o, on);
done:
  nqdwfree(&a);
  nqdwfree(&w);
  if (sg != NULL) nqfree(sg, sz.sig);
  if (o != NULL) nqfree(o, on > 0 ? on : 1);
  return rc;
}

/* ---- SignedData: reading ---- */

typedef struct {
  nqspan ctype;            /* eContentType OID contents */
  nqspan content;          /* eContent; p NULL when detached */
  nqspan certs[MAXCERT];
  size_t ncert;
  int sver;                /* SignerInfo version: 1 or 3 */
  nqspan sidiss, sidser;   /* v1 */
  nqspan sidski;           /* v3 */
  nqhalg dalg;
  nqspan sattrs;           /* the contents of [0]; p NULL when absent */
  nqspan said;             /* signatureAlgorithm element */
  nqspan sig;
} sdata;

/* ContentInfo of the type oid: its content element */
static int cinfo(const uint8_t *p, size_t n, const uint8_t *oid, size_t on,
                 nqdtlv *body) {
  nqdtlv t, o, x;
  nqdcur c, in;
  int rc = nqdone(p, n, &t);
  if (rc != NQOK) return rc == NQEMEM || rc == NQELIM ? rc : NQEDEC;
  if (t.cls != NQDUNI || t.tag != NQDSEQ || nqddown(&t, &c) != NQOK ||
      nqdnext(&c, &o) != NQOK || !nqdoideq(&o, oid, on))
    return NQEDEC;
  if (nqdget(&c, NQDCTX, 1, 0, &x) != NQOK || nqddone(&c) != NQOK ||
      nqddown(&x, &in) != NQOK || nqdnext(&in, body) != NQOK ||
      nqddone(&in) != NQOK)
    return NQEDEC;
  return NQOK;
}

static int sdread(const uint8_t *p, size_t n, sdata *s) {
  nqdtlv body, t, e, o, x, dset;
  nqdcur c, in, sc;
  int64_t ver;
  int got = 0, rc;
  memset(s, 0, sizeof *s);
  rc = cinfo(p, n, osigned, sizeof osigned, &body);
  if (rc != NQOK) return rc;
  if (body.cls != NQDUNI || body.tag != NQDSEQ ||
      nqddown(&body, &c) != NQOK || nqdnext(&c, &t) != NQOK ||
      nqdi64(&t, &ver) != NQOK || ver < 1 || ver > 5)
    return NQEDEC;
  /* digestAlgorithms: checked against the signer's own below */
  if (nqdget(&c, NQDUNI, 1, NQDSET, &dset) != NQOK) return NQEDEC;
  /* encapContentInfo */
  if (nqdget(&c, NQDUNI, 1, NQDSEQ, &e) != NQOK ||
      nqddown(&e, &in) != NQOK || nqdnext(&in, &o) != NQOK ||
      nqdoid(&o, &s->ctype) != NQOK)
    return NQEDEC;
  if (!nqdend(&in)) {
    nqdcur oc;
    if (nqdget(&in, NQDCTX, 1, 0, &x) != NQOK || nqddone(&in) != NQOK ||
        nqddown(&x, &oc) != NQOK || nqdnext(&oc, &o) != NQOK ||
        nqddone(&oc) != NQOK || o.cls != NQDUNI || o.tag != NQDOCT)
      return NQEDEC;
    s->content = o.v;
    if (s->content.p == NULL) s->content.p = p; /* empty, and present */
  }
  /* certificates [0], crls [1] */
  if (nqdopt(&c, NQDCTX, 1, 0, &x, &got) != NQOK) return NQEDEC;
  if (got) {
    if (nqddown(&x, &in) != NQOK) return NQEDEC;
    while (!nqdend(&in)) {
      if (nqdnext(&in, &o) != NQOK) return NQEDEC;
      /* other forms of certificate are passed over */
      if (o.cls == NQDUNI && o.tag == NQDSEQ && s->ncert < MAXCERT)
        s->certs[s->ncert++] = o.raw;
    }
  }
  if (nqdopt(&c, NQDCTX, 1, 1, &x, &got) != NQOK) return NQEDEC;
  /* signerInfos: one signer */
  if (nqdget(&c, NQDUNI, 1, NQDSET, &t) != NQOK || nqddone(&c) != NQOK ||
      nqddown(&t, &in) != NQOK || nqdnext(&in, &e) != NQOK)
    return NQEDEC;
  if (!nqdend(&in)) return NQENOSUP;
  if (e.cls != NQDUNI || e.tag != NQDSEQ || nqddown(&e, &sc) != NQOK ||
      nqdnext(&sc, &t) != NQOK || nqdi64(&t, &ver) != NQOK)
    return NQEDEC;
  if (ver == 1) {
    nqdcur ic;
    if (nqdget(&sc, NQDUNI, 1, NQDSEQ, &t) != NQOK ||
        nqddown(&t, &ic) != NQOK ||
        nqdget(&ic, NQDUNI, 1, NQDSEQ, &o) != NQOK ||
        nqdget(&ic, NQDUNI, 0, NQDINT, &x) != NQOK || nqddone(&ic) != NQOK)
      return NQEDEC;
    s->sidiss = o.raw;
    s->sidser = x.v;
  } else if (ver == 3) {
    if (nqdget(&sc, NQDCTX, 0, 0, &t) != NQOK) return NQEDEC;
    s->sidski = t.v;
  } else {
    return NQEDEC;
  }
  s->sver = (int)ver;
  if (nqdnext(&sc, &t) != NQOK) return NQEDEC;
  rc = dread(&t, &s->dalg);
  if (rc != NQOK) return rc;
  /* the signer's digest algorithm is one of those the message lists
   * (RFC 5652 section 5.1) */
  {
    nqdcur dc;
    nqdtlv a;
    nqhalg h;
    int listed = 0;
    if (nqddown(&dset, &dc) != NQOK) return NQEDEC;
    while (!nqdend(&dc)) {
      if (nqdnext(&dc, &a) != NQOK) return NQEDEC;
      rc = dread(&a, &h);
      if (rc == NQEDEC) return rc;
      if (rc == NQOK && h == s->dalg) listed = 1;
    }
    if (!listed) return NQEDEC;
  }
  if (nqdopt(&sc, NQDCTX, 1, 0, &x, &got) != NQOK) return NQEDEC;
  if (got) {
    s->sattrs = x.v;
    if (s->sattrs.p == NULL || x.v.n == 0 || x.v.n > SATTRMAX - 8)
      return NQEDEC;
  }
  if (nqdget(&sc, NQDUNI, 1, NQDSEQ, &t) != NQOK ||
      nqdget(&sc, NQDUNI, 0, NQDOCT, &o) != NQOK)
    return NQEDEC;
  s->said = t.raw;
  s->sig = o.v;
  /* unsignedAttrs [1], when there */
  if (nqdopt(&sc, NQDCTX, 1, 1, &x, &got) != NQOK || nqddone(&sc) != NQOK)
    return NQEDEC;
  return NQOK;
}

/* the one value of an attribute's SET */
static int oneval(const nqdtlv *set, nqdtlv *v) {
  nqdcur c;
  if (set->cls != NQDUNI || set->tag != NQDSET || nqddown(set, &c) != NQOK ||
      nqdnext(&c, v) != NQOK || nqddone(&c) != NQOK)
    return NQEDEC;
  return NQOK;
}

/* the signed attributes: the content type and the digest they must
 * carry, once each, and the signing time when there is one */
static int sacheck(const sdata *s, const uint8_t *dig, size_t dn,
                   int64_t *stime, int *hast) {
  nqdcur c;
  nqdtlv a, o, set, v;
  int nct = 0, nmd = 0, nst = 0;
  nqdinit(&c, s->sattrs.p, s->sattrs.n);
  while (!nqdend(&c)) {
    nqdcur ac;
    if (nqdget(&c, NQDUNI, 1, NQDSEQ, &a) != NQOK ||
        nqddown(&a, &ac) != NQOK || nqdnext(&ac, &o) != NQOK ||
        o.cls != NQDUNI || o.tag != NQDOID || nqdnext(&ac, &set) != NQOK ||
        nqddone(&ac) != NQOK)
      return NQEDEC;
    if (nqdoideq(&o, octype, sizeof octype)) {
      nqspan t;
      if (oneval(&set, &v) != NQOK || nqdoid(&v, &t) != NQOK) return NQEDEC;
      if (!nqdseq(t, s->ctype)) return NQEVRFY;
      nct++;
    } else if (nqdoideq(&o, omd, sizeof omd)) {
      if (oneval(&set, &v) != NQOK || v.cls != NQDUNI || v.tag != NQDOCT)
        return NQEDEC;
      if (v.v.n != dn || !nqcteq(v.v.p, dig, dn)) return NQEVRFY;
      nmd++;
    } else if (nqdoideq(&o, ostime, sizeof ostime)) {
      if (oneval(&set, &v) != NQOK ||
          nqdtime(&v, NQDT5280, stime, NULL) != NQOK)
        return NQEDEC;
      nst++;
    }
  }
  if (nct != 1 || nmd != 1 || nst > 1) return NQEDEC;
  *hast = nst;
  return NQOK;
}

/* the signature algorithm of the signer; rsaEncryption means PKCS #1
 * v1.5 with the signer's digest */
static int sigalg(const sdata *s, nqxsig *g) {
  nqdtlv aid, oid, par;
  nqdcur c;
  int rc;
  if (nqdhdr(s->said.p, s->said.n, &aid) != NQOK ||
      nqddown(&aid, &c) != NQOK || nqdnext(&c, &oid) != NQOK)
    return NQEDEC;
  if (nqxoideq(&oid, &nqxoidrsa)) {
    if (nqdnext(&c, &par) != NQOK || nqdnull(&par) != NQOK ||
        nqddone(&c) != NQOK)
      return NQEDEC;
    memset(g, 0, sizeof *g);
    g->kind = NQXRSA;
    g->h = s->dalg;
    return NQOK;
  }
  rc = nqxsalg(&aid, g);
  if (rc != NQOK) return rc;
  if (g->kind != NQXPQ && g->kind != NQXED && g->h != s->dalg)
    return NQEVRFY;
  return NQOK;
}

/* whether the certificate c is the one the signer identifier names */
static int issigner(const sdata *s, const nqcert *c) {
  if (s->sver == 1)
    return nqdseq(s->sidiss, c->issuer) && nqdseq(s->sidser, c->serial);
  return (c->ext & NQXHASSKI) != 0 && nqdseq(s->sidski, c->ski);
}

int nqcmsvrfy(const uint8_t *cms, size_t n, const uint8_t *msg, size_t mlen,
              const uint8_t *const *anc, const size_t *anclen, size_t nanc,
              int64_t at, uint8_t *out, size_t cap, size_t *outlen,
              nqx5f *signer) {
  static const uint8_t setid = 0x31;
  sdata s;
  nqcert *cs = NULL, *as = NULL;
  const nqcert *leaf = NULL, *path[NQXMAXPATH];
  nqxsig g;
  nqxchk k;
  nqspan content, m, sg;
  uint8_t dig[NQHMAX], *sab = NULL;
  size_t i, dn, np = 0, sabn = 0;
  int64_t stime = 0;
  int hast = 0, rc, direct = 0;
  if (outlen != NULL) *outlen = 0;
  if (signer != NULL) memset(signer, 0, sizeof *signer);
  if (cms == NULL || (msg == NULL && mlen != 0) || anc == NULL ||
      anclen == NULL || nanc == 0 || nanc > MAXCERT ||
      (out == NULL && cap != 0))
    return NQEARG;
  if (n > CMSMAX || mlen > CMSMAX) return NQELIM;
  rc = sdread(cms, n, &s);
  if (rc != NQOK) return rc;
  /* the content: inside, or the caller's; both only when they agree */
  if (s.content.p != NULL) {
    content = s.content;
    if (msg != NULL &&
        (mlen != content.n ||
         (mlen > 0 && memcmp(msg, content.p, mlen) != 0)))
      return NQEVRFY;
  } else {
    if (msg == NULL) return NQEARG;
    content.p = msg;
    content.n = mlen;
  }
  dn = dlen(s.dalg);
  rc = nqhash(s.dalg, content.p, content.n, dig, dn);
  if (rc != NQOK) return rc;
  cs = (nqcert *)nqmal((s.ncert > 0 ? s.ncert : 1) * sizeof *cs);
  as = (nqcert *)nqmal(nanc * sizeof *as);
  if (cs == NULL || as == NULL) {
    rc = NQEMEM;
    goto done;
  }
  for (i = 0; i < nanc; i++) {
    if (anc[i] == NULL || nqcprs(anc[i], anclen[i], &as[i]) != NQOK) {
      rc = NQEARG;
      goto done;
    }
  }
  /* the signer's certificate: among those the message carries, else
   * among the anchors */
  for (i = 0; i < s.ncert; i++) {
    if (nqcprs(s.certs[i].p, s.certs[i].n, &cs[i]) != NQOK) {
      rc = NQEDEC;
      goto done;
    }
    if (leaf == NULL && issigner(&s, &cs[i])) leaf = &cs[i];
  }
  for (i = 0; leaf == NULL && i < nanc; i++) {
    if (issigner(&s, &as[i])) {
      leaf = &as[i];
      direct = 1;
    }
  }
  if (leaf == NULL) {
    rc = NQEVRFY;
    goto done;
  }
  /* what was signed: the attributes as a SET, or the content itself */
  if (s.sattrs.p != NULL) {
    nqdw w;
    rc = sacheck(&s, dig, dn, &stime, &hast);
    if (rc != NQOK) goto done;
    nqdwini(&w);
    nqdwtlv(&w, setid, s.sattrs.p, s.sattrs.n);
    rc = nqdwend(&w, &sab, &sabn);
    if (rc != NQOK) goto done;
    /* a SET in DER, as it must have been when it was signed */
    if (nqdwalk(sab, sabn) != NQOK) {
      rc = NQEDEC;
      goto done;
    }
    m.p = sab;
    m.n = sabn;
  } else {
    m = content;
  }
  rc = sigalg(&s, &g);
  if (rc != NQOK) goto done;
  sg = s.sig;
  rc = nqxvrfy(nqcxops(), &leaf->key, &g, m, sg);
  if (rc != NQOK) {
    rc = rc == NQEMEM ? rc : NQEVRFY;
    goto done;
  }
  /* the time the certificates must hold at: the caller's, else the
   * signing time, else now by the system clock */
  if (at <= 0) at = hast ? stime : nqcreal();
  /* a signer whose certificate is itself an anchor is trusted as it
   * is, within its validity; any other is chained to one */
  for (i = 0; !direct && i < nanc; i++) {
    direct = as[i].raw.n == leaf->raw.n &&
             memcmp(as[i].raw.p, leaf->raw.p, leaf->raw.n) == 0;
  }
  if (direct) {
    if (leaf->bad || at < leaf->nb - NQXSKEW || at > leaf->na + NQXSKEW) {
      rc = NQEVRFY;
      goto done;
    }
  } else {
    memset(&k, 0, sizeof k);
    k.anc = as;
    k.nanc = nanc;
    k.pool = cs;
    k.npool = s.ncert;
    k.t = at;
    k.eku = 0;
    k.ops = nqcxops();
    rc = nqchain(leaf, &k, path, NQXMAXPATH, &np);
    if (rc != NQOK) {
      rc = rc == NQEMEM ? rc : NQEVRFY;
      goto done;
    }
  }
  if (outlen != NULL) *outlen = content.n;
  if (out != NULL) {
    if (cap < content.n) {
      rc = NQEBUF;
      goto done;
    }
    if (content.n > 0) memcpy(out, content.p, content.n);
  }
  if (signer != NULL) info(leaf, leaf->raw.p, leaf->raw.n, signer);
done:
  if (cs != NULL) nqfree(cs, (s.ncert > 0 ? s.ncert : 1) * sizeof *cs);
  if (as != NULL) nqfree(as, nanc * sizeof *as);
  if (sab != NULL) nqfree(sab, sabn > 0 ? sabn : 1);
  return rc;
}

/* ---- AuthEnvelopedData ---- */

/* the key-encryption key of a KEM recipient (RFC 9629 section 5): HKDF
 * of the shared secret with the DER of CMSORIforKEMOtherInfo */
static int kek(const uint8_t *ss, size_t ssn, const uint8_t *wrap,
               size_t wn, size_t klen, const uint8_t *ukm, size_t un,
               int hasukm, uint8_t *out) {
  nqdw w;
  uint8_t prk[32], *inf = NULL;
  size_t in = 0, m;
  int rc;
  nqdwini(&w);
  m = nqdwopen(&w, NQDWSEQ);
  algid(&w, wrap, wn);
  nqdwuint(&w, klen);
  if (hasukm) {
    size_t u = nqdwopen(&w, NQDWCON(0));
    nqdwoct(&w, ukm, un);
    nqdwclose(&w, u);
  }
  nqdwclose(&w, m);
  rc = nqdwend(&w, &inf, &in);
  if (rc != NQOK) return rc;
  rc = nqhkx(NQS256, NULL, 0, ss, ssn, prk);
  if (rc == NQOK) rc = nqhke(NQS256, prk, sizeof prk, inf, in, out, klen);
  nqwipe(prk, sizeof prk);
  nqfree(inf, in > 0 ? in : 1);
  return rc;
}

/* one KEMRecipientInfo, in its [4] OtherRecipientInfo, for the
 * recipient certificate c */
static int rcpout(nqdw *w, const nqcert *c, const uint8_t *cek) {
  nqksz kz;
  uint8_t ct[1568], ss[32], kk[32], wk[40], o[9];
  const uint8_t *wo = c->key.kem == NQMLKEM512 ? owrap128 : owrap256;
  size_t kl = c->key.kem == NQMLKEM512 ? 16 : 32, a, b, e;
  int rc = nqksize(c->key.kem, &kz);
  if (rc != NQOK) return rc;
  rc = nqenc(c->key.kem, c->key.key.p, c->key.key.n, ct, kz.ct, ss, sizeof ss);
  if (rc == NQOK) rc = kek(ss, sizeof ss, wo, 9, kl, NULL, 0, 0, kk);
  if (rc == NQOK) rc = nqkwrap(kk, kl, cek, 32, wk);
  nqwipe(ss, sizeof ss);
  nqwipe(kk, sizeof kk);
  if (rc != NQOK) return rc;
  a = nqdwopen(w, NQDWCON(4));
  nqdwoid(w, oorikem, sizeof oorikem);
  b = nqdwopen(w, NQDWSEQ);
  nqdwuint(w, 0);
  e = nqdwopen(w, NQDWSEQ);
  nqdwraw(w, c->issuer.p, c->issuer.n);
  nqdwtlv(w, NQDINT, c->serial.p, c->serial.n);
  nqdwclose(w, e);
  memcpy(o, kempre, sizeof kempre);
  o[8] = (uint8_t)(1 + (c->key.kem - NQMLKEM512));
  algid(w, o, 9);
  nqdwoct(w, ct, kz.ct);
  algid(w, ohkdf256, sizeof ohkdf256);
  nqdwuint(w, kl);
  algid(w, wo, 9);
  nqdwoct(w, wk, 40);
  nqdwclose(w, b);
  nqdwclose(w, a);
  return w->err;
}

int nqcmsenc(const uint8_t *const *rcert, const size_t *rcertlen, size_t nr,
             const uint8_t *msg, size_t n, uint8_t *out, size_t cap,
             size_t *outlen) {
  nqdw w, r[MAXRCP];
  nqgcm g;
  nqcert c;
  uint8_t cek[32], nonce[12], tag[16], *ct = NULL, *o = NULL;
  size_t ord[MAXRCP], i, j, on = 0, ci, x, ae, s, e, p;
  int rc = NQOK;
  if (outlen != NULL) *outlen = 0;
  if (rcert == NULL || rcertlen == NULL || nr == 0 || nr > MAXRCP ||
      outlen == NULL || (msg == NULL && n != 0) || (out == NULL && cap != 0))
    return NQEARG;
  if (n > CMSMAX) return NQELIM;
  nqdwini(&w);
  for (i = 0; i < nr; i++) nqdwini(&r[i]);
  rc = nqrand(cek, sizeof cek);
  if (rc == NQOK) rc = nqrand(nonce, sizeof nonce);
  for (i = 0; rc == NQOK && i < nr; i++) {
    if (rcert[i] == NULL || nqcprs(rcert[i], rcertlen[i], &c) != NQOK ||
        c.key.type != NQXKKEM) {
      rc = NQEARG; /* not a certificate of an ML-KEM key */
      break;
    }
    rc = rcpout(&r[i], &c, cek);
    ord[i] = i;
  }
  if (rc != NQOK) goto done;
  /* a SET OF in DER: the recipients in the order of their encodings */
  for (i = 1; i < nr; i++) {
    for (j = i; j > 0; j--) {
      const nqdw *a = &r[ord[j - 1]], *b = &r[ord[j]];
      size_t m = a->n < b->n ? a->n : b->n;
      int cmp = memcmp(a->p, b->p, m);
      if (cmp < 0 || (cmp == 0 && a->n <= b->n)) break;
      p = ord[j];
      ord[j] = ord[j - 1];
      ord[j - 1] = p;
    }
  }
  ct = (uint8_t *)nqmal(n > 0 ? n : 1);
  if (ct == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = nqgcmk(&g, cek, sizeof cek);
  if (rc == NQOK)
    rc = nqgcme(&g, nonce, sizeof nonce, NULL, 0, msg, n, ct, tag);
  nqwipe(&g, sizeof g);
  if (rc != NQOK) goto done;
  ci = nqdwopen(&w, NQDWSEQ);
  nqdwoid(&w, oauthenv, sizeof oauthenv);
  x = nqdwopen(&w, NQDWCON(0));
  ae = nqdwopen(&w, NQDWSEQ);
  nqdwuint(&w, 0);
  s = nqdwopen(&w, NQDWSET);
  for (i = 0; i < nr; i++) nqdwraw(&w, r[ord[i]].p, r[ord[i]].n);
  nqdwclose(&w, s);
  e = nqdwopen(&w, NQDWSEQ);
  nqdwoid(&w, odata, sizeof odata);
  /* aes256-GCM, with GCMParameters: the nonce, a 16-byte tag */
  s = nqdwopen(&w, NQDWSEQ);
  nqdwoid(&w, ogcm256, sizeof ogcm256);
  p = nqdwopen(&w, NQDWSEQ);
  nqdwoct(&w, nonce, sizeof nonce);
  nqdwuint(&w, 16);
  nqdwclose(&w, p);
  nqdwclose(&w, s);
  nqdwtlv(&w, NQDWCTX(0), ct, n);
  nqdwclose(&w, e);
  nqdwoct(&w, tag, sizeof tag);
  nqdwclose(&w, ae);
  nqdwclose(&w, x);
  nqdwclose(&w, ci);
  rc = nqdwend(&w, &o, &on);
  if (rc != NQOK) goto done;
  *outlen = on;
  if (cap < on)
    rc = NQEBUF;
  else
    memcpy(out, o, on);
done:
  nqwipe(cek, sizeof cek);
  nqdwfree(&w);
  for (i = 0; i < nr; i++) nqdwfree(&r[i]);
  if (ct != NULL) nqfree(ct, n > 0 ? n : 1);
  if (o != NULL) nqfree(o, on > 0 ? on : 1);
  return rc;
}

/* tries one recipient: NQOK with the content key in cek when it is a
 * KEM recipient this secret key opens; NQEVRFY when it is not for this
 * key; NQEDEC when it is not a recipient at all */
static int rcptry(const nqdtlv *ri, nqkalg alg, const uint8_t *sk,
                  size_t sklen, const nqcert *own, uint8_t *cek,
                  size_t *ceklen) {
  nqdcur c, kc, ac;
  nqdtlv o, k, t, rid, kem, ct, kdf, kl, wrap, ek, ukm;
  nqksz kz;
  uint8_t ss[32], kk[32], ko[9];
  const uint8_t *wo;
  int64_t klen;
  size_t wkl;
  int got = 0, rc;
  /* [4] OtherRecipientInfo of the KEM kind; the others are not ours */
  if (ri->cls != NQDCTX || ri->tag != 4 || !ri->con) return NQEVRFY;
  if (nqddown(ri, &c) != NQOK || nqdnext(&c, &o) != NQOK) return NQEDEC;
  if (!nqdoideq(&o, oorikem, sizeof oorikem)) return NQEVRFY;
  if (nqdget(&c, NQDUNI, 1, NQDSEQ, &k) != NQOK || nqddone(&c) != NQOK ||
      nqddown(&k, &kc) != NQOK || nqdnext(&kc, &t) != NQOK ||
      nqdi64(&t, &klen) != NQOK || klen != 0 || nqdnext(&kc, &rid) != NQOK ||
      nqdget(&kc, NQDUNI, 1, NQDSEQ, &kem) != NQOK ||
      nqdget(&kc, NQDUNI, 0, NQDOCT, &ct) != NQOK ||
      nqdget(&kc, NQDUNI, 1, NQDSEQ, &kdf) != NQOK ||
      nqdget(&kc, NQDUNI, 0, NQDINT, &kl) != NQOK ||
      nqdi64(&kl, &klen) != NQOK ||
      nqdopt(&kc, NQDCTX, 1, 0, &ukm, &got) != NQOK ||
      nqdget(&kc, NQDUNI, 1, NQDSEQ, &wrap) != NQOK ||
      nqdget(&kc, NQDUNI, 0, NQDOCT, &ek) != NQOK || nqddone(&kc) != NQOK)
    return NQEDEC;
  /* named for another certificate: not this key's */
  if (own != NULL) {
    if (rid.cls == NQDUNI && rid.tag == NQDSEQ) {
      nqdcur rc2;
      nqdtlv is, sn;
      if (nqddown(&rid, &rc2) != NQOK ||
          nqdget(&rc2, NQDUNI, 1, NQDSEQ, &is) != NQOK ||
          nqdget(&rc2, NQDUNI, 0, NQDINT, &sn) != NQOK)
        return NQEDEC;
      if (!nqdseq(is.raw, own->issuer) || !nqdseq(sn.v, own->serial))
        return NQEVRFY;
    } else if (rid.cls == NQDCTX && rid.tag == 0) {
      if ((own->ext & NQXHASSKI) == 0 || !nqdseq(rid.v, own->ski))
        return NQEVRFY;
    } else {
      return NQEDEC;
    }
  }
  /* the KEM is this key's; HKDF with SHA-256; AES Key Wrap */
  memcpy(ko, kempre, sizeof kempre);
  ko[8] = (uint8_t)(1 + (alg - NQMLKEM512));
  if (nqddown(&kem, &ac) != NQOK || nqdnext(&ac, &o) != NQOK ||
      nqddone(&ac) != NQOK)
    return NQEDEC;
  if (!nqdoideq(&o, ko, 9)) return NQEVRFY;
  if (nqddown(&kdf, &ac) != NQOK || nqdnext(&ac, &o) != NQOK ||
      nqddone(&ac) != NQOK)
    return NQEDEC;
  if (!nqdoideq(&o, ohkdf256, sizeof ohkdf256)) return NQENOSUP;
  if (nqddown(&wrap, &ac) != NQOK || nqdnext(&ac, &o) != NQOK ||
      nqddone(&ac) != NQOK)
    return NQEDEC;
  if (nqdoideq(&o, owrap128, sizeof owrap128)) {
    wo = owrap128;
    wkl = 16;
  } else if (nqdoideq(&o, owrap256, sizeof owrap256)) {
    wo = owrap256;
    wkl = 32;
  } else {
    return NQENOSUP;
  }
  /* the length the sender names is the wrap algorithm's */
  if (klen != (int64_t)wkl) return NQEDEC;
  if (got) {
    nqdcur uc;
    nqdtlv u;
    if (nqddown(&ukm, &uc) != NQOK ||
        nqdget(&uc, NQDUNI, 0, NQDOCT, &u) != NQOK || nqddone(&uc) != NQOK)
      return NQEDEC;
    ukm = u;
  }
  if (nqksize(alg, &kz) != NQOK || ct.v.n != kz.ct ||
      (ek.v.n != 24 && ek.v.n != 40))
    return NQEDEC;
  rc = nqdec(alg, sk, sklen, ct.v.p, ct.v.n, ss, sizeof ss);
  if (rc == NQOK)
    rc = kek(ss, sizeof ss, wo, 9, wkl, got ? ukm.v.p : NULL,
             got ? ukm.v.n : 0, got, kk);
  if (rc == NQOK) rc = nqkunwrap(kk, wkl, ek.v.p, ek.v.n, cek);
  nqwipe(ss, sizeof ss);
  nqwipe(kk, sizeof kk);
  if (rc == NQOK) *ceklen = ek.v.n - 8;
  return rc;
}

int nqcmsdec(nqkalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *cert, size_t certlen, const uint8_t *cms,
             size_t n, uint8_t *out, size_t cap, size_t *outlen) {
  nqdtlv body, t, ri, e, o, par, nonce, icv, ect, mac, aa;
  nqdcur c, rc2, ec, pc;
  nqcert own;
  nqgcm g;
  nqksz kz;
  uint8_t cek[32], *aad = NULL;
  size_t ceklen = 0, aadn = 0, want;
  int64_t v;
  int got = 0, hasaa = 0, rc, found = NQEVRFY;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || cms == NULL || outlen == NULL ||
      (cert == NULL && certlen != 0) || (out == NULL && cap != 0))
    return NQEARG;
  if (alg < NQMLKEM512 || alg > NQMLKEM1024 || nqksize(alg, &kz) != NQOK)
    return NQENOSUP;
  if (sklen != kz.sk) return NQEARG;
  if (n > CMSMAX) return NQELIM;
  if (cert != NULL && nqcprs(cert, certlen, &own) != NQOK) return NQEARG;
  rc = cinfo(cms, n, oauthenv, sizeof oauthenv, &body);
  if (rc != NQOK) return rc;
  if (body.cls != NQDUNI || body.tag != NQDSEQ ||
      nqddown(&body, &c) != NQOK || nqdnext(&c, &t) != NQOK ||
      nqdi64(&t, &v) != NQOK || v != 0 ||
      nqdopt(&c, NQDCTX, 1, 0, &t, &got) != NQOK ||
      nqdget(&c, NQDUNI, 1, NQDSET, &t) != NQOK ||
      nqdget(&c, NQDUNI, 1, NQDSEQ, &e) != NQOK ||
      nqdopt(&c, NQDCTX, 1, 1, &aa, &hasaa) != NQOK ||
      nqdget(&c, NQDUNI, 0, NQDOCT, &mac) != NQOK ||
      nqdopt(&c, NQDCTX, 1, 2, &o, &got) != NQOK || nqddone(&c) != NQOK ||
      nqddown(&t, &rc2) != NQOK)
    return NQEDEC;
  /* the content: its type, AES-GCM with its parameters, the bytes */
  if (nqddown(&e, &ec) != NQOK || nqdnext(&ec, &o) != NQOK ||
      o.cls != NQDUNI || o.tag != NQDOID ||
      nqdget(&ec, NQDUNI, 1, NQDSEQ, &t) != NQOK ||
      nqddown(&t, &pc) != NQOK || nqdnext(&pc, &o) != NQOK)
    return NQEDEC;
  if (nqdoideq(&o, ogcm256, sizeof ogcm256))
    want = 32;
  else if (nqdoideq(&o, ogcm128, sizeof ogcm128))
    want = 16;
  else
    return NQENOSUP;
  if (nqdget(&pc, NQDUNI, 1, NQDSEQ, &par) != NQOK || nqddone(&pc) != NQOK ||
      nqddown(&par, &pc) != NQOK ||
      nqdget(&pc, NQDUNI, 0, NQDOCT, &nonce) != NQOK)
    return NQEDEC;
  v = 12; /* aes-ICVlen DEFAULT 12 */
  if (!nqdend(&pc) &&
      (nqdnext(&pc, &icv) != NQOK || nqdi64(&icv, &v) != NQOK ||
       nqddone(&pc) != NQOK))
    return NQEDEC;
  if (nonce.v.n != 12 || mac.v.n != (size_t)v || v < 12 || v > 16)
    return NQEDEC;
  ect.v.p = NULL;
  ect.v.n = 0;
  if (!nqdend(&ec) &&
      (nqdget(&ec, NQDCTX, 0, 0, &ect) != NQOK || nqddone(&ec) != NQOK))
    return NQEDEC;
  /* the recipient this key opens */
  while (!nqdend(&rc2)) {
    int r;
    if (nqdnext(&rc2, &ri) != NQOK) return NQEDEC;
    r = rcptry(&ri, alg, sk, sklen, cert != NULL ? &own : NULL, cek,
               &ceklen);
    if (r == NQOK) {
      found = NQOK;
      break;
    }
    if (r == NQEDEC || r == NQEMEM) return r;
    if (r == NQENOSUP) found = NQENOSUP;
  }
  if (found != NQOK) return found;
  rc = ceklen == want ? NQOK : NQEVRFY;
  /* authenticated attributes, when there: their DER as a SET is the
   * associated data (RFC 5083 section 2.2) */
  if (rc == NQOK && hasaa) {
    nqdw w;
    nqdwini(&w);
    nqdwtlv(&w, 0x31, aa.v.p, aa.v.n);
    rc = nqdwend(&w, &aad, &aadn);
  }
  if (rc == NQOK) {
    *outlen = ect.v.n;
    if (cap < ect.v.n) rc = NQEBUF;
  }
  if (rc == NQOK) rc = nqgcmk(&g, cek, ceklen);
  if (rc == NQOK) {
    rc = nqgcmd(&g, nonce.v.p, 12, aad, aadn, ect.v.p, ect.v.n, mac.v.p,
                mac.v.n, out);
    nqwipe(&g, sizeof g);
  }
  nqwipe(cek, sizeof cek);
  if (aad != NULL) nqfree(aad, aadn > 0 ? aadn : 1);
  if (rc != NQOK && rc != NQEBUF) *outlen = 0;
  return rc;
}

/* ---- S/MIME (RFC 8551): the messages above as MIME entities ---- */

#define SMMAX ((size_t)1 << 30)

/* the entity with every line ended by CRLF, as it is signed and
 * encrypted (RFC 8551 section 3.1.1): a lone LF or CR becomes CRLF */
static int canon(const char *in, size_t n, nqcbuf *b) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (in[i] == '\r') {
      nqcput(b, "\r\n", 2);
      if (i + 1 < n && in[i + 1] == '\n') i++;
    } else if (in[i] == '\n') {
      nqcput(b, "\r\n", 2);
    } else {
      nqcput(b, in + i, 1);
    }
  }
  return b->err;
}

/* base64 in lines of 64 characters, each ended by CRLF */
static int b64lines(nqcbuf *b, const uint8_t *in, size_t n) {
  char line[65];
  size_t i;
  for (i = 0; i < n; i += 48) {
    size_t k = n - i < 48 ? n - i : 48;
    nqb64e(in + i, k, line);
    nqcput(b, line, nqb64n(k));
    nqcput(b, "\r\n", 2);
  }
  return b->err;
}

/* the base64 of text (space and line ends between it passed over) into
 * a new buffer */
static int unb64(const char *in, size_t n, uint8_t **out, size_t *cap,
                 size_t *len) {
  char *t = (char *)nqmal(n + 1);
  size_t i, k = 0;
  int rc;
  if (t == NULL) return NQEMEM;
  for (i = 0; i < n; i++) {
    char c = in[i];
    if (c != ' ' && c != '\t' && c != '\r' && c != '\n') t[k++] = c;
  }
  *cap = k / 4 * 3 + 3;
  *out = (uint8_t *)nqmal(*cap);
  if (*out == NULL) {
    nqfree(t, n + 1);
    return NQEMEM;
  }
  rc = nqb64d(t, k, *out, *cap, len);
  nqfree(t, n + 1);
  if (rc != NQOK) {
    nqfree(*out, *cap);
    *out = NULL;
    return NQEDEC;
  }
  return NQOK;
}

static int lc(int c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; }

/* whether the n bytes at s start with the ASCII word w, letters of
 * either case alike */
static int starts(const char *s, size_t n, const char *w) {
  size_t i, l = strlen(w);
  if (n < l) return 0;
  for (i = 0; i < l; i++) {
    if (lc((unsigned char)s[i]) != lc((unsigned char)w[i])) return 0;
  }
  return 1;
}

/* the header of an entity: where its body starts (after the first
 * empty line; n when there is none) */
static size_t bodyat(const char *m, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (m[i] != '\n') continue;
    if (i + 1 < n && m[i + 1] == '\n') return i + 2;
    if (i + 2 < n && m[i + 1] == '\r' && m[i + 2] == '\n') return i + 3;
  }
  return n;
}

/* the value of the header field name (with its colon) in the header of
 * hn bytes, continuation lines unfolded into out; 0 when absent or
 * longer than cap */
static int field(const char *m, size_t hn, const char *name, char *out,
                 size_t cap) {
  size_t i = 0, o = 0;
  while (i < hn) {
    size_t e = i;
    while (e < hn && m[e] != '\n') e++;
    if (starts(m + i, e - i, name)) {
      i += strlen(name);
      for (;;) {
        for (; i < e; i++) {
          if (m[i] == '\r') continue;
          if (o + 1 >= cap) return 0;
          out[o++] = m[i];
        }
        /* a line that starts with space or a tab goes on */
        if (e + 1 < hn && (m[e + 1] == ' ' || m[e + 1] == '\t')) {
          i = e + 1;
          e = i;
          while (e < hn && m[e] != '\n') e++;
          continue;
        }
        break;
      }
      out[o] = '\0';
      return 1;
    }
    i = e + 1;
  }
  return 0;
}

/* the parameter name of a header value (name=value or name="value");
 * 0 when absent or longer than cap */
static int param(const char *v, const char *name, char *out, size_t cap) {
  size_t n = strlen(v), l = strlen(name), i, o = 0;
  for (i = 0; i < n; i++) {
    if (v[i] != ';') continue;
    i++;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    if (!starts(v + i, n - i, name) || i + l >= n || v[i + l] != '=') {
      i--;
      continue;
    }
    i += l + 1;
    if (i < n && v[i] == '"') {
      for (i++; i < n && v[i] != '"'; i++) {
        if (o + 1 >= cap) return 0;
        out[o++] = v[i];
      }
    } else {
      for (; i < n && v[i] != ';' && v[i] != ' ' && v[i] != '\t'; i++) {
        if (o + 1 >= cap) return 0;
        out[o++] = v[i];
      }
    }
    out[o] = '\0';
    return 1;
  }
  return 0;
}

/* gives the buffer b to the caller */
static int give(nqcbuf *b, char *out, size_t cap, size_t *outlen) {
  if (b->err != NQOK) return b->err;
  *outlen = b->n;
  if (cap < b->n) return NQEBUF;
  if (b->n > 0) memcpy(out, b->p, b->n);
  return NQOK;
}

/* an application/pkcs7-mime entity of the smime-type st around cms */
static int p7m(nqcbuf *b, const char *st, const uint8_t *cms, size_t n) {
  nqcputs(b, "MIME-Version: 1.0\r\n"
             "Content-Type: application/pkcs7-mime; smime-type=");
  nqcputs(b, st);
  nqcputs(b, "; name=\"smime.p7m\"\r\n"
             "Content-Transfer-Encoding: base64\r\n"
             "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n"
             "\r\n");
  return b64lines(b, cms, n);
}

int nqsmsign(nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *cert, size_t certlen, const char *entity,
             size_t n, int detached, int64_t at, char *out, size_t cap,
             size_t *outlen) {
  static const char *const mic[] = {"sha-256", "sha-384", "sha-512",
                                    "shake128", "shake256"};
  nqcbuf e, b;
  uint8_t *cms = NULL, rnd[16];
  char bd[48];
  size_t cc = 0, cn = 0;
  nqhalg h = dalg(alg);
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (entity == NULL || outlen == NULL || (out == NULL && cap != 0))
    return NQEARG;
  if (n > SMMAX) return NQELIM;
  memset(&e, 0, sizeof e);
  memset(&b, 0, sizeof b);
  rc = canon(entity, n, &e);
  if (rc != NQOK) goto done;
  /* a signature of any algorithm here, the certificate and the
   * attributes fit in this beside the content */
  cc = (detached ? 0 : e.n) + certlen + 65536;
  cms = (uint8_t *)nqmal(cc);
  if (cms == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = nqcmssign(alg, sk, sklen, cert, certlen, (const uint8_t *)e.p, e.n,
                 detached, at, cms, cc, &cn);
  if (rc != NQOK) goto done;
  if (!detached) {
    rc = p7m(&b, "signed-data", cms, cn);
  } else {
    rc = nqrand(rnd, sizeof rnd);
    if (rc != NQOK) goto done;
    memcpy(bd, "----noqtis-", 11);
    nqhex(rnd, sizeof rnd, bd + 11);
    nqcputs(&b, "MIME-Version: 1.0\r\n"
                "Content-Type: multipart/signed; "
                "protocol=\"application/pkcs7-signature\"; micalg=");
    nqcputs(&b, mic[h == NQS256 ? 0 : h == NQS384 ? 1 : h == NQSHK128 ? 3
                                 : h == NQSHK256 ? 4 : 2]);
    nqcputs(&b, "; boundary=\"");
    nqcputs(&b, bd);
    nqcputs(&b, "\"\r\n\r\nThis is an S/MIME signed message.\r\n\r\n--");
    nqcputs(&b, bd);
    nqcputs(&b, "\r\n");
    nqcput(&b, e.p, e.n);
    nqcputs(&b, "\r\n--");
    nqcputs(&b, bd);
    nqcputs(&b, "\r\nContent-Type: application/pkcs7-signature; "
                "name=\"smime.p7s\"\r\n"
                "Content-Transfer-Encoding: base64\r\n"
                "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"
                "\r\n");
    b64lines(&b, cms, cn);
    nqcputs(&b, "--");
    nqcputs(&b, bd);
    nqcputs(&b, "--\r\n");
    rc = b.err;
  }
  if (rc == NQOK) rc = give(&b, out, cap, outlen);
done:
  nqcbfree(&e);
  nqcbfree(&b);
  if (cms != NULL) nqfree(cms, cc);
  return rc;
}

/* a multipart/signed body split at its boundary: the first part's
 * bytes (what was signed) and the second part's body (the signature,
 * base64) */
static int split(const char *m, size_t n, const char *bd, const char **p1,
                 size_t *n1, const char **p2, size_t *n2) {
  size_t bl = strlen(bd), i, at[3], k = 0;
  /* the delimiter lines: "--" boundary at the start of a line */
  for (i = 0; i + 2 + bl <= n && k < 3; i++) {
    if ((i == 0 || m[i - 1] == '\n') && m[i] == '-' && m[i + 1] == '-' &&
        memcmp(m + i + 2, bd, bl) == 0) {
      at[k++] = i;
      i += 1 + bl;
    }
  }
  if (k != 3) return NQEDEC;
  /* the third is the closing one */
  if (at[2] + 4 + bl > n || m[at[2] + 2 + bl] != '-' ||
      m[at[2] + 3 + bl] != '-')
    return NQEDEC;
  /* the first part: after its delimiter's line end, to the line end
   * before the next delimiter, which belongs to the delimiter */
  i = at[0] + 2 + bl;
  while (i < at[1] && m[i] != '\n') i++;
  if (i >= at[1]) return NQEDEC;
  i++;
  *p1 = m + i;
  *n1 = at[1] - i;
  if (*n1 > 0 && (*p1)[*n1 - 1] == '\n') (*n1)--;
  if (*n1 > 0 && (*p1)[*n1 - 1] == '\r') (*n1)--;
  /* the second: its own header passed over */
  i = at[1] + 2 + bl;
  while (i < at[2] && m[i] != '\n') i++;
  if (i >= at[2]) return NQEDEC;
  i++;
  i += bodyat(m + i, at[2] - i);
  *p2 = m + i;
  *n2 = at[2] - i;
  return NQOK;
}

int nqsmvrfy(const char *mime, size_t n, const uint8_t *const *anc,
             const size_t *anclen, size_t nanc, int64_t at, char *out,
             size_t cap, size_t *outlen, nqx5f *signer) {
  char ct[1024], v[256];
  const char *p1, *p2;
  uint8_t *cms = NULL;
  nqcbuf e;
  size_t hn, n1 = 0, n2 = 0, cc = 0, cn = 0;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (signer != NULL) memset(signer, 0, sizeof *signer);
  if (mime == NULL || (out == NULL && cap != 0)) return NQEARG;
  if (n > SMMAX) return NQELIM;
  memset(&e, 0, sizeof e);
  hn = bodyat(mime, n);
  if (!field(mime, hn, "content-type:", ct, sizeof ct)) return NQEDEC;
  if (param(ct, "boundary", v, sizeof v) && v[0] != '\0') {
    /* multipart/signed: the first part is the content, as signed */
    rc = split(mime + hn, n - hn, v, &p1, &n1, &p2, &n2);
    if (rc != NQOK) return rc;
    rc = canon(p1, n1, &e);
    if (rc == NQOK) rc = unb64(p2, n2, &cms, &cc, &cn);
    if (rc == NQOK)
      rc = nqcmsvrfy(cms, cn, (const uint8_t *)(e.p != NULL ? e.p : ""), e.n,
                     anc, anclen, nanc, at, (uint8_t *)out, cap, outlen,
                     signer);
  } else {
    /* application/pkcs7-mime, signed-data: the content is inside */
    if (param(ct, "smime-type", v, sizeof v) && !starts(v, strlen(v) + 1,
                                                       "signed-data"))
      return NQEDEC;
    rc = unb64(mime + hn, n - hn, &cms, &cc, &cn);
    if (rc == NQOK)
      rc = nqcmsvrfy(cms, cn, NULL, 0, anc, anclen, nanc, at, (uint8_t *)out,
                     cap, outlen, signer);
  }
  nqcbfree(&e);
  if (cms != NULL) nqfree(cms, cc);
  return rc;
}

int nqsmenc(const uint8_t *const *rcert, const size_t *rcertlen, size_t nr,
            const char *entity, size_t n, char *out, size_t cap,
            size_t *outlen) {
  nqcbuf e, b;
  uint8_t *cms = NULL;
  size_t cc = 0, cn = 0;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (entity == NULL || outlen == NULL || (out == NULL && cap != 0))
    return NQEARG;
  if (n > SMMAX) return NQELIM;
  memset(&e, 0, sizeof e);
  memset(&b, 0, sizeof b);
  rc = canon(entity, n, &e);
  if (rc != NQOK) goto done;
  /* a recipient entry is under 2048 bytes for ML-KEM-1024 */
  cc = e.n + nr * 2048 + 256;
  cms = (uint8_t *)nqmal(cc);
  if (cms == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = nqcmsenc(rcert, rcertlen, nr, (const uint8_t *)e.p, e.n, cms, cc, &cn);
  if (rc == NQOK) rc = p7m(&b, "authEnveloped-data", cms, cn);
  if (rc == NQOK) rc = give(&b, out, cap, outlen);
done:
  nqcbfree(&e);
  nqcbfree(&b);
  if (cms != NULL) nqfree(cms, cc);
  return rc;
}

int nqsmdec(nqkalg alg, const uint8_t *sk, size_t sklen, const uint8_t *cert,
            size_t certlen, const char *mime, size_t n, char *out,
            size_t cap, size_t *outlen) {
  char ct[1024], v[64];
  uint8_t *cms = NULL;
  size_t hn, cc = 0, cn = 0;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (mime == NULL || outlen == NULL || (out == NULL && cap != 0))
    return NQEARG;
  if (n > SMMAX) return NQELIM;
  hn = bodyat(mime, n);
  if (!field(mime, hn, "content-type:", ct, sizeof ct) ||
      !starts(ct + strspn(ct, " \t"), strlen(ct), "application/pkcs7-mime"))
    return NQEDEC;
  if (param(ct, "smime-type", v, sizeof v) &&
      !starts(v, strlen(v) + 1, "authenveloped-data"))
    return NQEDEC;
  rc = unb64(mime + hn, n - hn, &cms, &cc, &cn);
  if (rc == NQOK)
    rc = nqcmsdec(alg, sk, sklen, cert, certlen, cms, cn, (uint8_t *)out, cap,
                  outlen);
  if (cms != NULL) nqfree(cms, cc);
  return rc;
}
