/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Revocation: OCSP responses (RFC 6960) and CRLs (RFC 5280 section 5),
 * read by position and checked against a path nqchain built. */
#include <string.h>

#include "der/x509.h"
#include "hash/h.h"

static const uint8_t obasic[] = {0x2b, 0x06, 0x01, 0x05, 0x05,
                                 0x07, 0x30, 0x01, 0x01};

#define MAXRCERT 4 /* certificates in one OCSP response */

/* [n] EXPLICIT Extensions */
static int xexts(const nqdtlv *t) {
  nqdcur c;
  nqdtlv s;
  int r = NQEDEC;
  if ((r = nqddown(t, &c)) != NQOK || (r = nqdnext(&c, &s)) != NQOK ||
      (r = nqddone(&c)) != NQOK) {
    return r;
  }
  if (s.cls != NQDUNI || s.tag != NQDSEQ) {
    return NQEDEC;
  }
  return nqxgext(&s);
}

/* A GeneralizedTime without fraction (RFC 5280 / 6960). */
static int gtime(const nqdtlv *t, int64_t *s) {
  if (t->cls != NQDUNI || t->tag != NQDGEN) {
    return NQEDEC;
  }
  return nqdtime(t, 0, s, NULL);
}

/* [n] EXPLICIT GeneralizedTime */
static int xgtime(const nqdtlv *t, int64_t *s) {
  nqdcur c;
  nqdtlv x;
  int r = NQEDEC;
  if ((r = nqddown(t, &c)) != NQOK || (r = nqdnext(&c, &x)) != NQOK ||
      (r = nqddone(&c)) != NQOK) {
    return r;
  }
  return gtime(&x, s);
}

/* 1 when the CertID names path[i] under path[i + 1]; NQ* < 0 on error. */
static int cidmatch(const nqdtlv *cid, const nqcert *c, const nqcert *iss,
                    const nqxops *ops) {
  nqdcur e;
  nqdtlv aid, nh, kh, ser;
  nqhalg h;
  uint8_t d[NQHMAX];
  size_t dl;
  int r = NQEDEC, m = 1;
  if (cid->cls != NQDUNI || cid->tag != NQDSEQ ||
      (r = nqddown(cid, &e)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 1, NQDSEQ, &aid)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 0, NQDOCT, &nh)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 0, NQDOCT, &kh)) != NQOK ||
      (r = nqdnext(&e, &ser)) != NQOK ||
      (r = nqdint(&ser, NULL, NULL)) != NQOK || (r = nqddone(&e)) != NQOK ||
      (r = nqxhalg(&aid, 1, &h)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  dl = nqxhlen(h);
  if (nh.v.n != dl || kh.v.n != dl) {
    return NQEDEC;
  }
  if ((r = nqxdig(ops, h, c->issuer.p, c->issuer.n, d)) != NQOK) {
    return r;
  }
  m &= memcmp(d, nh.v.p, dl) == 0;
  if ((r = nqxdig(ops, h, iss->key.key.p, iss->key.key.n, d)) != NQOK) {
    return r;
  }
  m &= memcmp(d, kh.v.p, dl) == 0;
  m &= nqdseq(ser.v, c->serial);
  return m;
}

/* The responder certificates of a BasicOCSPResponse: each is either a
 * certificate of the path or a delegated responder the issuer signed. */
static int rcerts(const nqdtlv *t, const nqcert *const *path, size_t np,
                  const nqcert *iss, int64_t tm, const nqxops *ops,
                  nqcert *rc, size_t *nrc) {
  nqdcur c, s;
  nqdtlv seq, x;
  int r = NQEDEC;
  size_t j;
  *nrc = 0;
  if ((r = nqddown(t, &c)) != NQOK ||
      (r = nqdget(&c, NQDUNI, 1, NQDSEQ, &seq)) != NQOK ||
      (r = nqddone(&c)) != NQOK || (r = nqddown(&seq, &s)) != NQOK) {
    return r;
  }
  while (!nqdend(&s)) {
    int inp = 0;
    if ((r = nqdnext(&s, &x)) != NQOK) {
      return r;
    }
    if (*nrc == MAXRCERT) {
      return NQELIM;
    }
    if ((r = nqcprs(x.raw.p, x.raw.n, &rc[*nrc])) != NQOK) {
      return r;
    }
    for (j = 0; j < np; j++) {
      if (nqdseq(path[j]->raw, rc[*nrc].raw)) {
        inp = 1;
      }
    }
    if (!inp) {
      const nqcert *d = &rc[*nrc];
      if (d->bad || (d->ext & NQXHASEKU) == 0 ||
          (d->eku & NQXEKUOCSP) == 0 || tm < d->nb || tm > d->na ||
          d->salg.kind == 0 || !nqxneq(d->issuer, iss->subject) ||
          nqxvrfy(ops, &iss->key, &d->salg, d->tbs, d->sig) != NQOK) {
        return NQEVRFY;
      }
    }
    (*nrc)++;
  }
  return NQOK;
}

int nqocsp(const uint8_t *p, size_t n, const nqcert *const *path,
           size_t np, size_t i, int64_t t, const nqxops *ops, int *st) {
  nqdcur c, rb, b, td, rs, sr, xc;
  nqdtlv top, x, bytes, basic, tbs, aid, sigb, rid, single, cst;
  nqcert rc[MAXRCERT];
  size_t nrc = 0, j;
  const nqcert *iss, *signer = NULL;
  nqspan sig;
  nqxsig salg;
  int64_t v, prod, thisu = 0, nextu = 0;
  int r = NQEDEC, got, hasnext = 0, hits = 0, status = -1;
  if (st != NULL) {
    *st = -1;
  }
  if (p == NULL || path == NULL || ops == NULL || i + 1 >= np) {
    return NQEARG;
  }
  iss = path[i + 1];
  if ((r = nqdone(p, n, &top)) != NQOK) {
    return r;
  }
  /* OCSPResponse */
  if (top.cls != NQDUNI || top.tag != NQDSEQ ||
      (r = nqddown(&top, &c)) != NQOK || (r = nqdnext(&c, &x)) != NQOK ||
      (r = nqdenum(&x, &v)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  if (v != 0) {
    return NQEVRFY; /* not "successful" */
  }
  if ((r = nqdget(&c, NQDCTX, 1, 0, &x)) != NQOK ||
      (r = nqddone(&c)) != NQOK || (r = nqddown(&x, &rb)) != NQOK ||
      (r = nqdget(&rb, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
      (r = nqddone(&rb)) != NQOK || (r = nqddown(&x, &rb)) != NQOK ||
      (r = nqdnext(&rb, &x)) != NQOK) {
    return r;
  }
  if (!nqdoideq(&x, obasic, sizeof obasic)) {
    return NQENOSUP;
  }
  if ((r = nqdget(&rb, NQDUNI, 0, NQDOCT, &bytes)) != NQOK ||
      (r = nqddone(&rb)) != NQOK ||
      (r = nqdone(bytes.v.p, bytes.v.n, &basic)) != NQOK) {
    return r;
  }
  /* BasicOCSPResponse */
  if (basic.cls != NQDUNI || basic.tag != NQDSEQ ||
      (r = nqddown(&basic, &b)) != NQOK ||
      (r = nqdget(&b, NQDUNI, 1, NQDSEQ, &tbs)) != NQOK ||
      (r = nqdget(&b, NQDUNI, 1, NQDSEQ, &aid)) != NQOK ||
      (r = nqdnext(&b, &sigb)) != NQOK ||
      (r = nqdbit0(&sigb, &sig)) != NQOK ||
      (r = nqxsalg(&aid, &salg)) != NQOK ||
      (r = nqdopt(&b, NQDCTX, 1, 0, &x, &got)) != NQOK ||
      (r = nqddone(&b)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  if (got && (r = rcerts(&x, path, np, iss, t, ops, rc, &nrc)) != NQOK) {
    return r;
  }
  /* ResponseData; version v1 only, which DER omits */
  if ((r = nqddown(&tbs, &td)) != NQOK || (r = nqdnext(&td, &rid)) != NQOK) {
    return r;
  }
  if ((r = nqdget(&td, NQDUNI, 0, NQDGEN, &x)) != NQOK ||
      (r = gtime(&x, &prod)) != NQOK ||
      (r = nqdget(&td, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
      (r = nqddown(&x, &rs)) != NQOK) {
    return r;
  }
  if (nqdend(&rs)) {
    return NQEDEC;
  }
  while (!nqdend(&rs)) {
    int m, s;
    int64_t tu, nu = 0;
    int hn = 0;
    if ((r = nqdget(&rs, NQDUNI, 1, NQDSEQ, &single)) != NQOK ||
        (r = nqddown(&single, &sr)) != NQOK ||
        (r = nqdnext(&sr, &x)) != NQOK) {
      return r;
    }
    m = cidmatch(&x, path[i], iss, ops);
    if (m < 0) {
      return m;
    }
    if ((r = nqdnext(&sr, &cst)) != NQOK) {
      return r;
    }
    if (cst.cls == NQDCTX && cst.tag == 0 && !cst.con && cst.v.n == 0) {
      s = NQXGOOD;
    } else if (cst.cls == NQDCTX && cst.tag == 2 && !cst.con &&
               cst.v.n == 0) {
      s = NQXUNKNOWN;
    } else if (cst.cls == NQDCTX && cst.tag == 1 && cst.con) {
      nqdtlv y;
      int64_t rt, why;
      if ((r = nqddown(&cst, &xc)) != NQOK ||
          (r = nqdnext(&xc, &y)) != NQOK || (r = gtime(&y, &rt)) != NQOK ||
          (r = nqdopt(&xc, NQDCTX, 1, 0, &y, &got)) != NQOK) {
        return r;
      }
      if (got) {
        nqdcur yc;
        nqdtlv z;
        if ((r = nqddown(&y, &yc)) != NQOK ||
            (r = nqdnext(&yc, &z)) != NQOK ||
            (r = nqddone(&yc)) != NQOK || (r = nqdenum(&z, &why)) != NQOK) {
          return r == NQELIM ? NQEDEC : r;
        }
        if (why < 0 || why > 10 || why == 7) {
          return NQEDEC;
        }
      }
      if ((r = nqddone(&xc)) != NQOK) {
        return r;
      }
      s = NQXREVOKED;
    } else {
      return NQEDEC;
    }
    if ((r = nqdnext(&sr, &x)) != NQOK || (r = gtime(&x, &tu)) != NQOK ||
        (r = nqdopt(&sr, NQDCTX, 1, 0, &x, &hn)) != NQOK) {
      return r;
    }
    if (hn && (r = xgtime(&x, &nu)) != NQOK) {
      return r;
    }
    if ((r = nqdopt(&sr, NQDCTX, 1, 1, &x, &got)) != NQOK) {
      return r;
    }
    if (got && (r = xexts(&x)) != NQOK) {
      return r;
    }
    if ((r = nqddone(&sr)) != NQOK) {
      return r;
    }
    if (m) {
      hits++;
      status = s;
      thisu = tu;
      nextu = nu;
      hasnext = hn;
    }
  }
  if ((r = nqdopt(&td, NQDCTX, 1, 1, &x, &got)) != NQOK) {
    return r;
  }
  if (got && (r = xexts(&x)) != NQOK) {
    return r;
  }
  if ((r = nqddone(&td)) != NQOK) {
    return r;
  }
  /* the responder: by name or by the SHA-1 of its key */
  if (rid.cls == NQDCTX && rid.con && (rid.tag == 1 || rid.tag == 2)) {
    nqdcur rc1;
    nqdtlv y;
    if ((r = nqddown(&rid, &rc1)) != NQOK || (r = nqdnext(&rc1, &y)) != NQOK ||
        (r = nqddone(&rc1)) != NQOK) {
      return r;
    }
    if (rid.tag == 1) {
      if (y.cls != NQDUNI || y.tag != NQDSEQ) {
        return NQEDEC;
      }
      if (nqxneq(y.raw, iss->subject)) {
        signer = iss;
      }
      for (j = 0; j < nrc && signer == NULL; j++) {
        if (nqxneq(y.raw, rc[j].subject)) {
          signer = &rc[j];
        }
      }
    } else {
      uint8_t d[20];
      if (y.cls != NQDUNI || y.con || y.tag != NQDOCT || y.v.n != 20) {
        return NQEDEC;
      }
      if ((r = nqxdig(ops, (nqhalg)0, iss->key.key.p, iss->key.key.n, d)) !=
          NQOK) {
        return r;
      }
      if (memcmp(d, y.v.p, 20) == 0) {
        signer = iss;
      }
      for (j = 0; j < nrc && signer == NULL; j++) {
        if ((r = nqxdig(ops, (nqhalg)0, rc[j].key.key.p, rc[j].key.key.n,
                        d)) != NQOK) {
          return r;
        }
        if (memcmp(d, y.v.p, 20) == 0) {
          signer = &rc[j];
        }
      }
    }
  } else {
    return NQEDEC;
  }
  if (signer == NULL) {
    return NQEVRFY;
  }
  /* a responder from the response is one rcerts accepted; one equal to
   * a path certificate must be the issuer itself */
  if (signer != iss && !nqdseq(signer->raw, iss->raw)) {
    int inp = 0;
    for (j = 0; j < np; j++) {
      if (nqdseq(path[j]->raw, signer->raw)) {
        inp = 1;
      }
    }
    if (inp) {
      return NQEVRFY;
    }
  }
  if ((r = nqxvrfy(ops, &signer->key, &salg, tbs.raw, sig)) != NQOK) {
    return r;
  }
  if (hits != 1) {
    return NQEVRFY; /* about another certificate, or ambiguous */
  }
  if (!nqocspnow(prod, thisu, hasnext, nextu, t)) {
    return NQEVRFY;
  }
  if (st != NULL) {
    *st = status;
  }
  return status == NQXGOOD ? NQOK : NQEVRFY;
}

int nqocspnow(int64_t prod, int64_t thisu, int hasnext, int64_t nextu,
              int64_t t) {
  if (prod > t + NQXSKEW || thisu > t + NQXSKEW) return 0;
  if (hasnext) return nextu >= thisu && nextu >= t - NQXSKEW;
  /* no nextUpdate: an old "good" could be replayed forever */
  return thisu >= t - NQXOCSPAGE - NQXSKEW;
}

int nqcrl(const uint8_t *p, size_t n, const nqcert *const *path,
          size_t np, size_t i, int64_t t, const nqxops *ops) {
  nqdcur c, tc, rl, ec;
  nqdtlv top, tbs, aid, sigb, x, iss, ent;
  nqspan sig;
  nqxsig salg;
  int64_t thisu, nextu, v;
  int r, got, ver = 1, listed = 0;
  size_t j;
  const nqcert *signer = NULL;
  if (p == NULL || path == NULL || ops == NULL || i >= np) {
    return NQEARG;
  }
  if ((r = nqdone(p, n, &top)) != NQOK) {
    return r;
  }
  if (top.cls != NQDUNI || top.tag != NQDSEQ ||
      (r = nqddown(&top, &c)) != NQOK ||
      (r = nqdget(&c, NQDUNI, 1, NQDSEQ, &tbs)) != NQOK ||
      (r = nqdget(&c, NQDUNI, 1, NQDSEQ, &aid)) != NQOK ||
      (r = nqdnext(&c, &sigb)) != NQOK || (r = nqddone(&c)) != NQOK ||
      (r = nqdbit0(&sigb, &sig)) != NQOK ||
      (r = nqxsalg(&aid, &salg)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  if ((r = nqddown(&tbs, &tc)) != NQOK ||
      (r = nqdopt(&tc, NQDUNI, 0, NQDINT, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if ((r = nqdi64(&x, &v)) != NQOK || v != 1) {
      return NQEDEC; /* if present, v2 */
    }
    ver = 2;
  }
  if ((r = nqdget(&tc, NQDUNI, 1, NQDSEQ, &x)) != NQOK) {
    return r;
  }
  if (!nqdseq(x.raw, aid.raw)) {
    return NQEDEC;
  }
  if ((r = nqdget(&tc, NQDUNI, 1, NQDSEQ, &iss)) != NQOK ||
      (r = nqdnext(&tc, &x)) != NQOK ||
      (r = nqdtime(&x, NQDT5280, &thisu, NULL)) != NQOK) {
    return r;
  }
  /* nextUpdate: required here */
  if ((r = nqdpeek(&tc, &x)) != NQOK) {
    return nqdend(&tc) ? NQEVRFY : r;
  }
  if (x.cls != NQDUNI || (x.tag != NQDUTC && x.tag != NQDGEN)) {
    return NQEVRFY;
  }
  if ((r = nqdnext(&tc, &x)) != NQOK ||
      (r = nqdtime(&x, NQDT5280, &nextu, NULL)) != NQOK) {
    return r;
  }
  if ((r = nqdopt(&tc, NQDUNI, 1, NQDSEQ, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if ((r = nqddown(&x, &rl)) != NQOK) {
      return r;
    }
    if (nqdend(&rl)) {
      return NQEDEC; /* absent rather than empty */
    }
    while (!nqdend(&rl)) {
      nqdtlv s;
      int64_t rd;
      if ((r = nqdget(&rl, NQDUNI, 1, NQDSEQ, &ent)) != NQOK ||
          (r = nqddown(&ent, &ec)) != NQOK || (r = nqdnext(&ec, &s)) != NQOK ||
          (r = nqdint(&s, NULL, NULL)) != NQOK ||
          (r = nqdnext(&ec, &x)) != NQOK ||
          (r = nqdtime(&x, NQDT5280, &rd, NULL)) != NQOK ||
          (r = nqdopt(&ec, NQDUNI, 1, NQDSEQ, &x, &got)) != NQOK) {
        return r == NQOK ? NQEDEC : r;
      }
      if (got) {
        if (ver != 2) {
          return NQEDEC;
        }
        if ((r = nqxgext(&x)) != NQOK) {
          return r;
        }
      }
      if ((r = nqddone(&ec)) != NQOK) {
        return r;
      }
      if (nqdseq(s.v, path[i]->serial)) {
        listed = 1;
      }
    }
  }
  if ((r = nqdopt(&tc, NQDCTX, 1, 0, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if (ver != 2) {
      return NQEDEC;
    }
    if ((r = xexts(&x)) != NQOK) {
      return r;
    }
  }
  if ((r = nqddone(&tc)) != NQOK) {
    return r;
  }
  /* the signer: a CA of the path named by the CRL's issuer */
  for (j = 0; j < np && signer == NULL; j++) {
    const nqcert *s = path[j];
    if (j == 0 && np > 1) {
      continue;
    }
    if (!nqxneq(iss.raw, s->subject) || !s->ca ||
        ((s->ext & NQXHASKU) != 0 && (s->ku & NQXKUCRL) == 0)) {
      continue;
    }
    if (nqxvrfy(ops, &s->key, &salg, tbs.raw, sig) == NQOK) {
      signer = s;
    }
  }
  if (signer == NULL) {
    return NQEVRFY;
  }
  if (!nqxneq(iss.raw, path[i]->issuer)) {
    return NQEVRFY; /* this CRL does not cover the certificate */
  }
  if (thisu > t + NQXSKEW || nextu < t - NQXSKEW || nextu < thisu) {
    return NQEVRFY;
  }
  return listed ? NQEVRFY : NQOK;
}
