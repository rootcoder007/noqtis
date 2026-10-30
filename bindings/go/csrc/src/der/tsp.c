/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RFC 3161 timestamp tokens, by position. See tsp.h for the layout. */
#include <string.h>

#include "der/tsp.h"
#include "hash/h.h"

#define PKCS9(x) 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, x
static const uint8_t osd[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                              0x0d, 0x01, 0x07, 0x02};
static const uint8_t otst[] = {PKCS9(0x10), 0x01, 0x04};
static const uint8_t oct[] = {PKCS9(0x03)};
static const uint8_t omd[] = {PKCS9(0x04)};
static const uint8_t ost[] = {PKCS9(0x05)};
static const uint8_t oscv1[] = {PKCS9(0x10), 0x02, 0x0c};
static const uint8_t oscv2[] = {PKCS9(0x10), 0x02, 0x2f};

#define EQ(t, o) nqdoideq((t), (o), sizeof(o))

/* ---- TSTInfo ---- */

static int accuracy(const nqdtlv *t, nqts *ts) {
  nqdcur c;
  nqdtlv x;
  int r = NQEDEC, got;
  if ((r = nqddown(t, &c)) != NQOK ||
      (r = nqdopt(&c, NQDUNI, 0, NQDINT, &x, &got)) != NQOK) {
    return r;
  }
  if (got && ((r = nqdi64(&x, &ts->accs)) != NQOK || ts->accs < 0)) {
    return NQEDEC;
  }
  if ((r = nqdopt(&c, NQDCTX, 0, 0, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    x.cls = NQDUNI;
    x.tag = NQDINT;
    if (nqdi64(&x, &ts->accms) != NQOK || ts->accms < 1 ||
        ts->accms > 999) {
      return NQEDEC;
    }
  }
  if ((r = nqdopt(&c, NQDCTX, 0, 1, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    x.cls = NQDUNI;
    x.tag = NQDINT;
    if (nqdi64(&x, &ts->accus) != NQOK || ts->accus < 1 ||
        ts->accus > 999) {
      return NQEDEC;
    }
  }
  ts->hasacc = 1;
  return nqddone(&c);
}

/* A GeneralName element; a directoryName must hold a Name. */
static int gname(const nqdtlv *g) {
  if (g->cls != NQDCTX || g->tag > 8) {
    return NQEDEC;
  }
  if (g->tag == 4) {
    nqdcur c;
    nqdtlv x;
    int r = NQEDEC, e;
    if (!g->con || (r = nqddown(g, &c)) != NQOK ||
        (r = nqdnext(&c, &x)) != NQOK || (r = nqddone(&c)) != NQOK) {
      return NQEDEC;
    }
    return nqxname(&x, &e);
  }
  return NQOK;
}

static int tstinfo(nqts *ts) {
  nqdtlv top, x, y;
  nqdcur c, m;
  int64_t v;
  int r = NQEDEC, got, neg, b;
  if ((r = nqdone(ts->tst.p, ts->tst.n, &top)) != NQOK) {
    return r;
  }
  if (top.cls != NQDUNI || top.tag != NQDSEQ ||
      (r = nqddown(&top, &c)) != NQOK || (r = nqdnext(&c, &x)) != NQOK ||
      (r = nqdi64(&x, &v)) != NQOK) {
    return r == NQOK || r == NQELIM ? NQEDEC : r;
  }
  if (v != 1) {
    return NQEDEC;
  }
  if ((r = nqdnext(&c, &x)) != NQOK || (r = nqdoid(&x, &ts->policy)) != NQOK) {
    return r;
  }
  /* messageImprint */
  if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
      (r = nqddown(&x, &m)) != NQOK ||
      (r = nqdget(&m, NQDUNI, 1, NQDSEQ, &y)) != NQOK ||
      (r = nqxhalg(&y, 0, &ts->ialg)) != NQOK ||
      (r = nqdget(&m, NQDUNI, 0, NQDOCT, &y)) != NQOK ||
      (r = nqddone(&m)) != NQOK) {
    return r;
  }
  if (y.v.n != nqhlen(ts->ialg)) {
    return NQEDEC;
  }
  ts->imp = y.v;
  /* serialNumber: positive, at most 160 bits */
  if ((r = nqdnext(&c, &x)) != NQOK || (r = nqdint(&x, &y.v, &neg)) != NQOK) {
    return r;
  }
  if (neg || (x.v.n == 1 && x.v.p[0] == 0)) {
    return NQEDEC;
  }
  if (y.v.n > 20) {
    return NQELIM;
  }
  ts->serial = x.v;
  /* genTime */
  if ((r = nqdget(&c, NQDUNI, 0, NQDGEN, &x)) != NQOK ||
      (r = nqdtime(&x, NQDTFRAC, &ts->gt, &ts->gtns)) != NQOK) {
    return r;
  }
  if ((r = nqdopt(&c, NQDUNI, 1, NQDSEQ, &x, &got)) != NQOK) {
    return r;
  }
  if (got && (r = accuracy(&x, ts)) != NQOK) {
    return r;
  }
  if ((r = nqdopt(&c, NQDUNI, 0, NQDBOOL, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if (nqdbool(&x, &b) != NQOK || !b) {
      return NQEDEC; /* DER omits the default (FALSE) */
    }
    ts->ordering = 1;
  }
  if ((r = nqdopt(&c, NQDUNI, 0, NQDINT, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if (nqdint(&x, NULL, &neg) != NQOK || neg) {
      return NQEDEC;
    }
    ts->hasnonce = 1;
    ts->nonce = x.v;
  }
  if ((r = nqdopt(&c, NQDCTX, 1, 0, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    nqdcur g;
    if ((r = nqddown(&x, &g)) != NQOK || (r = nqdnext(&g, &y)) != NQOK ||
        (r = nqddone(&g)) != NQOK || (r = gname(&y)) != NQOK) {
      return r;
    }
    ts->tsa = y.raw;
  }
  if ((r = nqdopt(&c, NQDCTX, 1, 1, &x, &got)) != NQOK) {
    return r;
  }
  if (got && (r = nqxgext(&x)) != NQOK) {
    return r;
  }
  return nqddone(&c);
}

/* ---- signed attributes ---- */

/* The single value of an attribute: SET with exactly one element. */
static int oneval(const nqdtlv *set, nqdtlv *v) {
  nqdcur c;
  int r = NQEDEC;
  if (set->cls != NQDUNI || set->tag != NQDSET ||
      (r = nqddown(set, &c)) != NQOK || (r = nqdnext(&c, v)) != NQOK) {
    return NQEDEC;
  }
  return nqddone(&c);
}

/* ESS SigningCertificate (v 1) or SigningCertificateV2 (v 2): the first
 * ESSCertID, which names the signer. */
static int ess(const nqdtlv *val, int v, nqhalg *h, nqspan *hash,
               nqspan *is) {
  nqdcur c, s, e;
  nqdtlv x, y, z;
  int r = NQEDEC, got;
  if (val->cls != NQDUNI || val->tag != NQDSEQ ||
      (r = nqddown(val, &c)) != NQOK ||
      (r = nqdget(&c, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
      (r = nqddown(&x, &s)) != NQOK) {
    return NQEDEC;
  }
  if ((r = nqdopt(&c, NQDUNI, 1, NQDSEQ, &y, &got)) != NQOK ||
      (r = nqddone(&c)) != NQOK) {
    return r;
  }
  if (nqdend(&s)) {
    return NQEDEC;
  }
  /* the first ESSCertID; the rest (other certificates) are signed and
   * were checked as DER */
  if ((r = nqdget(&s, NQDUNI, 1, NQDSEQ, &y)) != NQOK ||
      (r = nqddown(&y, &e)) != NQOK) {
    return r;
  }
  *h = (nqhalg)0;
  if (v == 2) {
    *h = NQS256;
    if ((r = nqdopt(&e, NQDUNI, 1, NQDSEQ, &z, &got)) != NQOK) {
      return r;
    }
    if (got) {
      if ((r = nqxhalg(&z, 0, h)) != NQOK) {
        return r;
      }
      if (*h == NQS256) {
        return NQEDEC; /* DER omits the default */
      }
    }
  }
  if ((r = nqdget(&e, NQDUNI, 0, NQDOCT, &z)) != NQOK) {
    return r;
  }
  if (z.v.n != nqxhlen(*h)) {
    return NQEDEC;
  }
  *hash = z.v;
  is->p = NULL;
  is->n = 0;
  if ((r = nqdopt(&e, NQDUNI, 1, NQDSEQ, &z, &got)) != NQOK) {
    return r;
  }
  if (got) {
    *is = z.raw;
  }
  return nqddone(&e);
}

static int sattrs(nqts *ts) {
  nqdtlv top, a, oid, set, v;
  nqdcur c, ac, d;
  int r = NQEDEC, nct = 0, nmd = 0, nst = 0, n1 = 0, n2 = 0;
  if (ts->sattrs.n > NQTSSA) {
    return NQELIM;
  }
  memcpy(ts->sab, ts->sattrs.p, ts->sattrs.n);
  ts->sab[0] = 0x31;
  ts->sabn = ts->sattrs.n;
  /* the signed form: a DER SET OF, so in DER order */
  if ((r = nqdone(ts->sab, ts->sabn, &top)) != NQOK) {
    return r;
  }
  if ((r = nqddown(&top, &c)) != NQOK) {
    return r;
  }
  while (!nqdend(&c)) {
    if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &a)) != NQOK ||
        (r = nqddown(&a, &ac)) != NQOK || (r = nqdnext(&ac, &oid)) != NQOK ||
        (r = nqdoid(&oid, NULL)) != NQOK ||
        (r = nqdget(&ac, NQDUNI, 1, NQDSET, &set)) != NQOK ||
        (r = nqddone(&ac)) != NQOK) {
      return r == NQOK ? NQEDEC : r;
    }
    if (nqddown(&set, &d) != NQOK || nqdend(&d)) {
      return NQEDEC; /* at least one value */
    }
    /* no attribute type twice */
    {
      nqdcur e;
      nqdtlv b, bo;
      nqddown(&top, &e);
      for (;;) {
        nqdcur f;
        nqdnext(&e, &b);
        if (b.raw.p == a.raw.p) {
          break;
        }
        nqddown(&b, &f);
        nqdnext(&f, &bo);
        if (nqdseq(bo.v, oid.v)) {
          return NQEDEC;
        }
      }
    }
    if (EQ(&oid, oct)) {
      nct++;
      if ((r = oneval(&set, &v)) != NQOK) {
        return r;
      }
      if (!EQ(&v, otst)) {
        return NQEDEC;
      }
    } else if (EQ(&oid, omd)) {
      nmd++;
      if ((r = oneval(&set, &v)) != NQOK) {
        return r;
      }
      if (v.cls != NQDUNI || v.con || v.tag != NQDOCT) {
        return NQEDEC;
      }
      ts->md.p = ts->sattrs.p + (v.v.p - ts->sab);
      ts->md.n = v.v.n;
    } else if (EQ(&oid, ost)) {
      nst++;
      if ((r = oneval(&set, &v)) != NQOK ||
          (r = nqdtime(&v, NQDT5280, NULL, NULL)) != NQOK) {
        return r == NQOK ? NQEDEC : r;
      }
    } else if (EQ(&oid, oscv1) || EQ(&oid, oscv2)) {
      int ver = EQ(&oid, oscv1) ? 1 : 2;
      nqspan h, is;
      nqhalg al;
      if ((r = oneval(&set, &v)) != NQOK ||
          (r = ess(&v, ver, &al, &h, &is)) != NQOK) {
        return r;
      }
      /* the spans point into sab; move them to the token */
      h.p = ts->sattrs.p + (h.p - ts->sab);
      if (is.n) {
        is.p = ts->sattrs.p + (is.p - ts->sab);
      }
      if (ver == 1) {
        n1++;
        ts->ess1 = al;
        ts->esshash1 = h;
        ts->essis1 = is;
      } else {
        n2++;
        ts->ess2 = al;
        ts->esshash2 = h;
        ts->essis2 = is;
      }
    }
  }
  if (nct != 1 || nmd != 1 || nst > 1 || n1 > 1 || n2 > 1 ||
      n1 + n2 == 0) {
    return NQEDEC;
  }
  if (ts->md.n != nqhlen(ts->dalg)) {
    return NQEDEC;
  }
  ts->essv = n2 ? 2 : 1;
  return NQOK;
}

/* ---- SignedData ---- */

static int signer(nqdcur *sc, nqts *ts) {
  nqdtlv si, x, y;
  nqdcur c, d;
  int64_t v;
  int r = NQEDEC, neg, e;
  if ((r = nqdget(sc, NQDUNI, 1, NQDSEQ, &si)) != NQOK ||
      (r = nqddone(sc)) != NQOK || (r = nqddown(&si, &c)) != NQOK ||
      (r = nqdnext(&c, &x)) != NQOK || (r = nqdi64(&x, &v)) != NQOK) {
    return r == NQOK || r == NQELIM ? NQEDEC : r;
  }
  if (v != 1 && v != 3) {
    return NQEDEC;
  }
  ts->sver = (int)v;
  if ((r = nqdnext(&c, &x)) != NQOK) {
    return r;
  }
  if (v == 1) {
    if (x.cls != NQDUNI || x.tag != NQDSEQ || (r = nqddown(&x, &d)) != NQOK ||
        (r = nqdnext(&d, &y)) != NQOK || (r = nqxname(&y, &e)) != NQOK) {
      return NQEDEC;
    }
    if (e) {
      return NQEDEC;
    }
    ts->sidiss = y.raw;
    if ((r = nqdnext(&d, &y)) != NQOK || (r = nqdint(&y, NULL, &neg)) != NQOK ||
        (r = nqddone(&d)) != NQOK) {
      return NQEDEC;
    }
    ts->sidser = y.v;
  } else {
    if (x.cls != NQDCTX || x.con || x.tag != 0 || x.v.n == 0) {
      return NQEDEC;
    }
    ts->sidski = x.v;
  }
  if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &x)) != NQOK) {
    return r;
  }
  if ((r = nqxhalg(&x, 0, &ts->dalg)) != NQOK) {
    return r;
  }
  if ((r = nqdget(&c, NQDCTX, 1, 0, &x)) != NQOK) {
    return r == NQEDEC ? NQENOSUP : r; /* without signed attributes */
  }
  ts->sattrs = x.raw;
  if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &x)) != NQOK) {
    return r;
  }
  ts->said = x.raw;
  if ((r = nqdget(&c, NQDUNI, 0, NQDOCT, &x)) != NQOK) {
    return r;
  }
  if (x.v.n == 0) {
    return NQEDEC;
  }
  ts->sig = x.v;
  if (!nqdend(&c)) {
    if (nqdpeek(&c, &x) == NQOK && x.cls == NQDCTX && x.tag == 1) {
      return NQENOSUP; /* unsignedAttrs */
    }
    return NQEDEC;
  }
  return sattrs(ts);
}

static int sdata(const nqdtlv *t, nqts *ts) {
  nqdcur c, d, e;
  nqdtlv x, y, z;
  int64_t v;
  int r = NQEDEC, got;
  nqhalg h;
  if (t->cls != NQDUNI || t->tag != NQDSEQ || (r = nqddown(t, &c)) != NQOK ||
      (r = nqdnext(&c, &x)) != NQOK || (r = nqdi64(&x, &v)) != NQOK) {
    return r == NQOK || r == NQELIM ? NQEDEC : r;
  }
  if (v != 3) {
    return NQEDEC;
  }
  /* digestAlgorithms: one */
  if ((r = nqdget(&c, NQDUNI, 1, NQDSET, &x)) != NQOK ||
      (r = nqddown(&x, &d)) != NQOK ||
      (r = nqdget(&d, NQDUNI, 1, NQDSEQ, &y)) != NQOK ||
      (r = nqddone(&d)) != NQOK || (r = nqxhalg(&y, 0, &h)) != NQOK) {
    return r;
  }
  /* encapContentInfo */
  if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
      (r = nqddown(&x, &d)) != NQOK || (r = nqdnext(&d, &y)) != NQOK) {
    return r;
  }
  if (!EQ(&y, otst)) {
    return NQEDEC;
  }
  if ((r = nqdget(&d, NQDCTX, 1, 0, &y)) != NQOK ||
      (r = nqddone(&d)) != NQOK || (r = nqddown(&y, &e)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 0, NQDOCT, &z)) != NQOK ||
      (r = nqddone(&e)) != NQOK) {
    return r;
  }
  ts->tst = z.v;
  /* [0] certificates: Certificate elements only */
  if ((r = nqdopt(&c, NQDCTX, 1, 0, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if ((r = nqddown(&x, &d)) != NQOK) {
      return r;
    }
    while (!nqdend(&d)) {
      if ((r = nqdnext(&d, &y)) != NQOK) {
        return r;
      }
      if (y.cls != NQDUNI || y.tag != NQDSEQ) {
        return NQENOSUP; /* other CertificateChoices */
      }
      if (ts->ncert == NQTSCERTS) {
        return NQELIM;
      }
      ts->certs[ts->ncert++] = y.raw;
    }
  }
  if ((r = nqdpeek(&c, &x)) != NQOK) {
    return r;
  }
  if (x.cls == NQDCTX && x.tag == 1) {
    return NQENOSUP; /* crls */
  }
  if ((r = nqdget(&c, NQDUNI, 1, NQDSET, &x)) != NQOK ||
      (r = nqddone(&c)) != NQOK || (r = nqddown(&x, &d)) != NQOK ||
      (r = signer(&d, ts)) != NQOK) {
    return r;
  }
  if (h != ts->dalg) {
    return NQEDEC; /* digestAlgorithms lists the signer's */
  }
  return tstinfo(ts);
}

int nqtsprs(const uint8_t *p, size_t n, nqts *ts) {
  nqdtlv top, x, ci;
  nqdcur c, s;
  int r = NQEDEC, got;
  if (p == NULL || ts == NULL) {
    return NQEARG;
  }
  memset(ts, 0, sizeof *ts);
  ts->status = -1;
  if ((r = nqdone(p, n, &top)) != NQOK) {
    return r;
  }
  if (top.cls != NQDUNI || top.tag != NQDSEQ ||
      (r = nqddown(&top, &c)) != NQOK || (r = nqdpeek(&c, &x)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  ci = top;
  if (x.cls == NQDUNI && x.tag == NQDSEQ) {
    /* TimeStampResp: PKIStatusInfo, then the token */
    int64_t st;
    nqdtlv y;
    nqdnext(&c, &x);
    if ((r = nqddown(&x, &s)) != NQOK || (r = nqdnext(&s, &y)) != NQOK ||
        (r = nqdi64(&y, &st)) != NQOK) {
      return r == NQELIM ? NQEDEC : r;
    }
    if ((r = nqdopt(&s, NQDUNI, 1, NQDSEQ, &y, &got)) != NQOK) {
      return r;
    }
    if (got) {
      /* PKIFreeText: SEQUENCE SIZE (1..MAX) OF UTF8String */
      nqdcur f;
      nqdtlv z;
      if (nqddown(&y, &f) != NQOK || nqdend(&f)) {
        return NQEDEC;
      }
      while (!nqdend(&f)) {
        if ((r = nqdget(&f, NQDUNI, 0, NQDUTF8, &z)) != NQOK) {
          return r;
        }
      }
    }
    if ((r = nqdopt(&s, NQDUNI, 0, NQDBITS, &y, &got)) != NQOK) {
      return r;
    }
    if ((r = nqddone(&s)) != NQOK) {
      return r;
    }
    if (st < 0 || st > 5) {
      return NQEDEC;
    }
    ts->status = (int)st;
    if (st > 1 || got) {
      return NQEVRFY; /* not granted */
    }
    if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &ci)) != NQOK ||
        (r = nqddone(&c)) != NQOK) {
      return r;
    }
  }
  /* ContentInfo */
  ts->tok = ci.raw;
  if ((r = nqddown(&ci, &c)) != NQOK || (r = nqdnext(&c, &x)) != NQOK) {
    return r;
  }
  if (!EQ(&x, osd)) {
    return NQEDEC;
  }
  if ((r = nqdget(&c, NQDCTX, 1, 0, &x)) != NQOK ||
      (r = nqddone(&c)) != NQOK || (r = nqddown(&x, &s)) != NQOK ||
      (r = nqdnext(&s, &x)) != NQOK || (r = nqddone(&s)) != NQOK) {
    return r;
  }
  return sdata(&x, ts);
}

/* ---- verification ---- */

/* Strips leading zero octets. */
static nqspan strip(nqspan s) {
  while (s.n > 0 && s.p[0] == 0) {
    s.p++;
    s.n--;
  }
  return s;
}

/* The ESSCertID binding: the hash of the whole certificate, and the
 * IssuerSerial when present. */
static int essok(const nqxops *ops, const nqcert *c, nqhalg h, nqspan hash,
                 nqspan is) {
  uint8_t d[NQHMAX];
  int r = nqxdig(ops, h, c->raw.p, c->raw.n, d);
  if (r != NQOK) {
    return r;
  }
  if (hash.n != nqxhlen(h) || memcmp(d, hash.p, hash.n) != 0) {
    return NQEVRFY;
  }
  if (is.n) {
    nqdtlv t, g, dn, nm, sn;
    nqdcur c1, c2, c3;
    if (nqdhdr(is.p, is.n, &t) != NQOK || nqddown(&t, &c1) != NQOK ||
        nqdget(&c1, NQDUNI, 1, NQDSEQ, &g) != NQOK ||
        nqdnext(&c1, &sn) != NQOK || nqdint(&sn, NULL, NULL) != NQOK ||
        nqddone(&c1) != NQOK || nqddown(&g, &c2) != NQOK ||
        nqdget(&c2, NQDCTX, 1, 4, &dn) != NQOK || nqddone(&c2) != NQOK ||
        nqddown(&dn, &c3) != NQOK || nqdnext(&c3, &nm) != NQOK ||
        nqddone(&c3) != NQOK) {
      return NQEVRFY;
    }
    if (!nqdseq(nm.raw, c->issuer) || !nqdseq(sn.v, c->serial)) {
      return NQEVRFY;
    }
  }
  return NQOK;
}

/* The signature algorithm of the SignerInfo, which must agree with its
 * digest algorithm; rsaEncryption means PKCS #1 v1.5 with that digest. */
static int sigalg(const nqts *ts, nqxsig *s) {
  nqdtlv aid, oid, par;
  nqdcur c;
  int r = NQEDEC;
  if (nqdhdr(ts->said.p, ts->said.n, &aid) != NQOK ||
      nqddown(&aid, &c) != NQOK || nqdnext(&c, &oid) != NQOK) {
    return NQEDEC;
  }
  if (nqxoideq(&oid, &nqxoidrsa)) {
    if (nqdnext(&c, &par) != NQOK || nqdnull(&par) != NQOK ||
        nqddone(&c) != NQOK) {
      return NQEDEC;
    }
    s->kind = NQXRSA;
    s->h = ts->dalg;
    s->pq = (nqsalg)0;
    return NQOK;
  }
  if ((r = nqxsalg(&aid, s)) != NQOK) {
    return r;
  }
  if (s->kind != NQXPQ && s->h != ts->dalg) {
    return NQEVRFY;
  }
  return NQOK;
}

int nqtsvrf(const uint8_t *p, size_t n, const nqtsarg *a, nqts *ts) {
  nqcert all[NQTSCERTS + NQTSEXTRA];
  const nqcert *path[NQXMAXPATH];
  const nqcert *sc = NULL;
  size_t na = 0, i, j, np;
  uint8_t d[NQHMAX];
  nqxchk k;
  nqxsig s;
  nqspan msg;
  int r = NQEDEC;
  if (a == NULL || ts == NULL || a->ops == NULL ||
      (!a->self && (a->anc == NULL || a->nanc == 0)) ||
      (a->self && a->nanc != 0) || a->dig == NULL ||
      a->nextra > NQTSEXTRA ||
      (a->nextra > 0 && a->extra == NULL)) {
    return NQEARG;
  }
  if ((r = nqtsprs(p, n, ts)) != NQOK) {
    return r;
  }
  /* the imprint, the nonce, the policy */
  if (a->halg != ts->ialg || a->diglen != ts->imp.n ||
      memcmp(a->dig, ts->imp.p, ts->imp.n) != 0) {
    return NQEVRFY;
  }
  if (a->nonce != NULL) {
    nqspan want = {a->nonce, a->noncelen};
    if (!ts->hasnonce || !nqdseq(strip(want), strip(ts->nonce))) {
      return NQEVRFY;
    }
  }
  if (a->pol != NULL) {
    nqspan want = {a->pol, a->pollen};
    if (!nqdseq(want, ts->policy)) {
      return NQEVRFY;
    }
  }
  /* the certificates */
  for (i = 0; i < ts->ncert; i++) {
    if ((r = nqcprs(ts->certs[i].p, ts->certs[i].n, &all[na])) != NQOK) {
      /* a copy of a trust anchor (which may carry a serial nqcprs
       * refuses, nqcprsa) is the anchor, parsed as one */
      size_t ai, hit = 0;
      for (ai = 0; ai < a->nanc && !hit; ai++) {
        if (a->anc[ai].raw.n == ts->certs[i].n &&
            memcmp(a->anc[ai].raw.p, ts->certs[i].p, ts->certs[i].n) == 0) {
          all[na] = a->anc[ai];
          hit = 1;
        }
      }
      if (!hit) return r;
    }
    na++;
  }
  for (i = 0; i < a->nextra; i++) {
    all[na++] = a->extra[i];
  }
  /* the signer, by its sid */
  for (i = 0; i < na && sc == NULL; i++) {
    const nqcert *c = &all[i];
    if (ts->sver == 1) {
      if (nqdseq(ts->sidiss, c->issuer) && nqdseq(ts->sidser, c->serial)) {
        sc = c;
      }
    } else if (c->ski.n > 0) {
      if (nqdseq(ts->sidski, c->ski)) {
        sc = c;
      }
    } else if (a->ops->sha1 != NULL && ts->sidski.n == 20) {
      uint8_t h1[20];
      if (a->ops->sha1(a->ops->user, c->key.key.p, c->key.key.n, h1) ==
              NQOK &&
          memcmp(h1, ts->sidski.p, 20) == 0) {
        sc = c;
      }
    }
  }
  if (sc == NULL) {
    return NQEVRFY;
  }
  /* the signed attributes commit to this TSTInfo and this certificate */
  if ((r = nqxdig(a->ops, ts->dalg, ts->tst.p, ts->tst.n, d)) != NQOK) {
    return r;
  }
  if (memcmp(d, ts->md.p, ts->md.n) != 0) {
    return NQEVRFY;
  }
  if (ts->esshash2.n &&
      (r = essok(a->ops, sc, ts->ess2, ts->esshash2, ts->essis2)) != NQOK) {
    return r;
  }
  if (ts->esshash1.n &&
      (r = essok(a->ops, sc, ts->ess1, ts->esshash1, ts->essis1)) != NQOK) {
    return r;
  }
  /* the signature */
  if ((r = sigalg(ts, &s)) != NQOK) {
    return r;
  }
  msg.p = ts->sab;
  msg.n = ts->sabn;
  if ((r = nqxvrfy(a->ops, &sc->key, &s, msg, ts->sig)) != NQOK) {
    return r;
  }
  /* a TSA certificate: RFC 3161 2.3 */
  if ((sc->ext & NQXHASEKU) == 0 || !sc->ekucrit || sc->ekun != 1 ||
      sc->eku != NQXEKUTS) {
    return NQEVRFY;
  }
  if ((sc->ext & NQXHASKU) != 0 &&
      (sc->ku & (NQXKUSIG | NQXKUNR)) == 0) {
    return NQEVRFY;
  }
  /* no anchors: the signer's own validity, and no path */
  if (a->self) {
    return !sc->bad && ts->gt >= sc->nb && ts->gt <= sc->na ? NQOK
                                                            : NQEVRFY;
  }
  /* the path */
  k.anc = a->anc;
  k.nanc = a->nanc;
  k.pool = all;
  k.npool = na;
  k.t = a->uset ? a->t : ts->gt;
  k.eku = NQXEKUTS;
  k.ops = a->ops;
  if ((r = nqchain(sc, &k, path, NQXMAXPATH, &np)) != NQOK) {
    return r == NQELIM ? NQELIM : NQEVRFY;
  }
  /* every certificate the token carries is on the path, is byte-equal
   * to an anchor, or is an alias of an anchor: the anchor's subject and
   * key, whoever issued it (a cross-certificate, or a copy of the root).
   * It parsed strictly above; nothing else in it is used, since only the
   * configured anchor is trusted. */
  for (i = 0; i < ts->ncert; i++) {
    int on = 0;
    for (j = 0; j < np; j++) {
      if (nqdseq(path[j]->raw, all[i].raw)) {
        on = 1;
      }
    }
    for (j = 0; j < a->nanc; j++) {
      if (nqdseq(all[i].raw, a->anc[j].raw) ||
          nqxalias(&all[i], &a->anc[j])) {
        on = 1;
      }
    }
    if (!on) {
      return NQEVRFY;
    }
  }
  return NQOK;
}
