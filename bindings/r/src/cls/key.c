/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Public keys and parameters from DER: SubjectPublicKeyInfo (RFC 5280,
 * RFC 3279, RFC 4055, RFC 5480), RSAPublicKey (RFC 8017), RSASSA-PSS-params
 * and ECDSA-Sig-Value. A tiny strict DER reader for just these: one-byte
 * tags, definite minimal lengths, minimal positive INTEGERs, nothing
 * trailing. (The general DER reader is module der.) */
#include <string.h>

#include "cls/cls.h"

typedef struct {
  const uint8_t *p;
  size_t n;
} dv;

/* Reads one element with tag tag from the front of in; its contents go
 * to out. */
static int tlv(dv *in, uint8_t tag, dv *out) {
  size_t len, nb, i, hd;
  if (in->n < 2 || in->p[0] != tag) return NQEDEC;
  len = in->p[1];
  hd = 2;
  if (len >= 0x80) {
    nb = len & 0x7f;
    /* 0x80 is the indefinite form; more than 3 length bytes is more than
     * anything here can hold */
    if (nb == 0 || nb > 3 || in->n < 2 + nb || in->p[2] == 0) return NQEDEC;
    len = 0;
    for (i = 0; i < nb; i++) {
      len = (len << 8) | in->p[2 + i];
    }
    if (len < 0x80) return NQEDEC; /* the short form was required */
    hd = 2 + nb;
  }
  if (len > in->n - hd) return NQEDEC;
  out->p = in->p + hd;
  out->n = len;
  in->p += hd + len;
  in->n -= hd + len;
  return NQOK;
}

static int peek(const dv *in) { return in->n > 0 ? in->p[0] : -1; }

/* A non-negative INTEGER in minimal form; out is its magnitude without
 * the sign byte (a single 00 for zero). */
static int dint(dv *in, dv *out) {
  int rc = tlv(in, 0x02, out);
  if (rc != NQOK) return rc;
  if (out->n == 0 || (out->p[0] & 0x80)) return NQEDEC;
  if (out->p[0] == 0 && out->n > 1) {
    if (!(out->p[1] & 0x80)) return NQEDEC;
    out->p++;
    out->n--;
  }
  return NQOK;
}

static int oideq(const dv *o, const uint8_t *v, size_t n) {
  return o->n == n && memcmp(o->p, v, n) == 0;
}

static const uint8_t orsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                               0x0d, 0x01, 0x01, 0x01};
static const uint8_t opss[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                               0x0d, 0x01, 0x01, 0x0a};
static const uint8_t omgf[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                               0x0d, 0x01, 0x01, 0x08};
static const uint8_t oec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t o256[] = {0x2a, 0x86, 0x48, 0xce,
                               0x3d, 0x03, 0x01, 0x07};
static const uint8_t o384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};
/* 2.16.840.1.101.3.4.2: the NIST hash arc */
static const uint8_t ohash[] = {0x60, 0x86, 0x48, 0x01,
                                0x65, 0x03, 0x04, 0x02};

static const nqhalg harc[13] = {
    (nqhalg)0, NQS256, NQS384, NQS512, NQS224, NQS512T224, NQS512T256,
    NQS3224, NQS3256, NQS3384, NQS3512, NQSHK128, NQSHK256};

unsigned nqcho(nqhalg h) {
  unsigned i;
  for (i = 1; i < 13; i++) {
    if (harc[i] == h) return i;
  }
  return 0;
}

/* AlgorithmIdentifier of a SHA-2 / SHA-3 hash, parameters NULL or absent
 * (RFC 4055 2.1). */
static int hashid(dv *in, nqhalg *h) {
  dv a, o, z;
  int rc = tlv(in, 0x30, &a);
  if (rc == NQOK) rc = tlv(&a, 0x06, &o);
  if (rc == NQOK && a.n > 0) {
    rc = tlv(&a, 0x05, &z);
    if (rc == NQOK && (z.n != 0 || a.n != 0)) rc = NQEDEC;
  }
  if (rc != NQOK) return rc;
  if (o.n == sizeof ohash + 1 && memcmp(o.p, ohash, sizeof ohash) == 0 &&
      o.p[sizeof ohash] >= 1 && o.p[sizeof ohash] <= 10) {
    *h = harc[o.p[sizeof ohash]];
    return NQOK;
  }
  return NQENOSUP; /* SHA-1, SHAKE (not used with MGF1) or unknown */
}

/* The contents of RSASSA-PSS-params. */
static int pssin(dv in, nqpss *p) {
  dv x, m, o, v;
  int rc, sha1 = 0;
  size_t i;
  memset(p, 0, sizeof *p);
  p->slen = 20;
  if (peek(&in) == 0xa0) {
    rc = tlv(&in, 0xa0, &x);
    if (rc == NQOK) rc = hashid(&x, &p->h);
    if (rc == NQOK && x.n != 0) rc = NQEDEC;
    if (rc != NQOK) return rc;
  } else {
    sha1 = 1;
  }
  if (peek(&in) == 0xa1) {
    rc = tlv(&in, 0xa1, &x);
    if (rc == NQOK) rc = tlv(&x, 0x30, &m);
    if (rc == NQOK && x.n != 0) rc = NQEDEC;
    if (rc == NQOK) rc = tlv(&m, 0x06, &o);
    if (rc != NQOK) return rc;
    if (!oideq(&o, omgf, sizeof omgf)) return NQENOSUP;
    rc = hashid(&m, &p->mgf);
    if (rc == NQOK && m.n != 0) rc = NQEDEC;
    if (rc != NQOK) return rc;
  } else {
    sha1 = 1;
  }
  if (peek(&in) == 0xa2) {
    rc = tlv(&in, 0xa2, &x);
    if (rc == NQOK) rc = dint(&x, &v);
    if (rc == NQOK && x.n != 0) rc = NQEDEC;
    if (rc != NQOK) return rc;
    if (v.n > 2) return NQEDEC; /* more salt than any modulus holds */
    p->slen = 0;
    for (i = 0; i < v.n; i++) {
      p->slen = (p->slen << 8) | v.p[i];
    }
    if (p->slen == 20) return NQEDEC; /* DER omits the default */
  }
  /* trailerField: only the default (1) exists, and DER omits it */
  if (in.n != 0) return NQEDEC;
  return sha1 ? NQENOSUP : NQOK;
}

int nqpssp(nqpss *p, const uint8_t *der, size_t len) {
  dv in, s;
  int rc;
  if (p == NULL || der == NULL) return NQEARG;
  in.p = der;
  in.n = len;
  rc = tlv(&in, 0x30, &s);
  if (rc == NQOK && in.n != 0) rc = NQEDEC;
  if (rc == NQOK) rc = pssin(s, p);
  if (rc != NQOK) memset(p, 0, sizeof *p);
  return rc;
}

static int rsain(nqck *k, dv in) {
  dv s, n, e;
  uint32_t w[NQBL];
  size_t bits, i;
  uint8_t t;
  int rc = tlv(&in, 0x30, &s);
  if (rc == NQOK && in.n != 0) rc = NQEDEC;
  if (rc == NQOK) rc = dint(&s, &n);
  if (rc == NQOK) rc = dint(&s, &e);
  if (rc == NQOK && s.n != 0) rc = NQEDEC;
  if (rc != NQOK) return rc;
  if (n.n > NQRMAX / 8) return NQENOSUP;
  bits = 8 * (n.n - 1);
  for (t = n.p[0]; t != 0; t = (uint8_t)(t >> 1)) {
    bits++;
  }
  if (bits < NQRMIN) return NQENOSUP;
  if (!(n.p[n.n - 1] & 1)) return NQEDEC; /* an RSA modulus is odd */
  if (e.n > 4) return NQENOSUP;
  k->e = 0;
  for (i = 0; i < e.n; i++) {
    k->e = (k->e << 8) | e.p[i];
  }
  if (k->e < 3 || !(k->e & 1)) return NQEDEC;
  k->kind = NQKRSA;
  k->bits = bits;
  nqcld(w, (bits + 31) / 32, n.p, n.n);
  nqcmset(&k->n, w, (bits + 31) / 32);
  return NQOK;
}

int nqrsapk(nqck *k, const uint8_t *der, size_t len) {
  dv in;
  int rc;
  if (k == NULL || der == NULL) return NQEARG;
  memset(k, 0, sizeof *k);
  in.p = der;
  in.n = len;
  rc = rsain(k, in);
  if (rc != NQOK) memset(k, 0, sizeof *k);
  return rc;
}

int nqckey(nqck *k, const uint8_t *der, size_t len) {
  dv in, s, a, b, o, x;
  int rc, crv = 0;
  if (k == NULL || der == NULL) return NQEARG;
  memset(k, 0, sizeof *k);
  in.p = der;
  in.n = len;
  rc = tlv(&in, 0x30, &s);
  if (rc == NQOK && in.n != 0) rc = NQEDEC;
  if (rc == NQOK) rc = tlv(&s, 0x30, &a);
  if (rc == NQOK) rc = tlv(&s, 0x03, &b);
  if (rc == NQOK && s.n != 0) rc = NQEDEC;
  if (rc == NQOK) rc = tlv(&a, 0x06, &o);
  /* the BIT STRING of a key has no unused bits */
  if (rc == NQOK && (b.n < 1 || b.p[0] != 0)) rc = NQEDEC;
  if (rc != NQOK) goto out;
  b.p++;
  b.n--;
  if (oideq(&o, orsa, sizeof orsa)) {
    rc = tlv(&a, 0x05, &x); /* NULL parameters (RFC 3279 2.3.1) */
    if (rc == NQOK && (x.n != 0 || a.n != 0)) rc = NQEDEC;
    if (rc == NQOK) rc = rsain(k, b);
  } else if (oideq(&o, opss, sizeof opss)) {
    if (a.n == 0) {
      k->pss = 1;
    } else {
      rc = tlv(&a, 0x30, &x);
      if (rc == NQOK && a.n != 0) rc = NQEDEC;
      if (rc == NQOK) rc = pssin(x, &k->pp);
      k->pss = 2;
    }
    if (rc == NQOK) rc = rsain(k, b);
  } else if (oideq(&o, oec, sizeof oec)) {
    rc = tlv(&a, 0x06, &x); /* namedCurve only (RFC 5480 2.1.1) */
    if (rc == NQOK && a.n != 0) rc = NQEDEC;
    if (rc == NQOK) {
      if (oideq(&x, o256, sizeof o256)) {
        crv = NQP256;
      } else if (oideq(&x, o384, sizeof o384)) {
        crv = NQP384;
      } else {
        rc = NQENOSUP;
      }
    }
    if (rc == NQOK) rc = nqecpk(k, crv, b.p, b.n);
  } else {
    rc = NQENOSUP;
  }
out:
  if (rc != NQOK) memset(k, 0, sizeof *k);
  return rc;
}

int nqcdsig(const uint8_t *sig, size_t len, const uint8_t **r, size_t *rl,
            const uint8_t **s, size_t *sl) {
  dv in, q, a, b;
  int rc;
  in.p = sig;
  in.n = len;
  rc = tlv(&in, 0x30, &q);
  if (rc == NQOK && in.n != 0) rc = NQEDEC;
  if (rc == NQOK) rc = dint(&q, &a);
  if (rc == NQOK) rc = dint(&q, &b);
  if (rc == NQOK && q.n != 0) rc = NQEDEC;
  if (rc != NQOK) return rc;
  *r = a.p;
  *rl = a.n;
  *s = b.p;
  *sl = b.n;
  return NQOK;
}
