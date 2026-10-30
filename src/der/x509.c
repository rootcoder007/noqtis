/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* X.509: algorithm identifiers, public keys, certificates by position,
 * names. */
#include <string.h>

#include "der/x509.h"
#include "hash/h.h"

/* ---- object identifiers ---- */

#define OID(name, ...)                                                    \
  static const uint8_t name##b[] = {__VA_ARGS__};                          \
  static const nqxoid name = {name##b, sizeof name##b}

static const uint8_t s256b[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x01};
static const uint8_t s384b[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x02};
static const uint8_t s512b[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x03};
static const uint8_t s1b[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};
static const uint8_t rsab[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                               0x0d, 0x01, 0x01, 0x01};
const nqxoid nqxoidsha256 = {s256b, sizeof s256b};
const nqxoid nqxoidsha384 = {s384b, sizeof s384b};
const nqxoid nqxoidsha512 = {s512b, sizeof s512b};
const nqxoid nqxoidsha1 = {s1b, sizeof s1b};
const nqxoid nqxoidrsa = {rsab, sizeof rsab};

/* 1.2.840.113549.1.1.x */
#define PKCS1(x) 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, x
OID(orsa256, PKCS1(0x0b));
OID(orsa384, PKCS1(0x0c));
OID(orsa512, PKCS1(0x0d));
OID(opss, PKCS1(0x0a));
OID(omgf1, PKCS1(0x08));
/* 1.2.840.10045 */
OID(oecpk, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
OID(oec256, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02);
OID(oec384, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03);
OID(oec512, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04);
OID(op256, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07);
OID(op384, 0x2b, 0x81, 0x04, 0x00, 0x22);
OID(op521, 0x2b, 0x81, 0x04, 0x00, 0x23);
/* 2.5.29.x */
OID(obc, 0x55, 0x1d, 0x13);
OID(oku, 0x55, 0x1d, 0x0f);
OID(oeku, 0x55, 0x1d, 0x25);
OID(oski, 0x55, 0x1d, 0x0e);
OID(oaki, 0x55, 0x1d, 0x23);
OID(osan, 0x55, 0x1d, 0x11);
OID(oanyeku, 0x55, 0x1d, 0x25, 0x00);

/* 2.16.840.1.101.3.4.3.17 .. 31: ML-DSA-44/65/87, then SLH-DSA in the
 * order of nqsalg */
static const uint8_t pqpre[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x03};

int nqxoideq(const nqdtlv *t, const nqxoid *o) {
  return nqdoideq(t, o->p, o->n);
}

/* ---- algorithm identifiers ---- */

/* Splits an AlgorithmIdentifier into its OID and optional parameters
 * (*hasp 0 when absent). */
static int aidsplit(const nqdtlv *aid, nqdtlv *oid, nqdtlv *par,
                    int *hasp) {
  nqdcur c;
  int r = NQEDEC;
  if (aid->cls != NQDUNI || aid->tag != NQDSEQ) {
    return NQEDEC;
  }
  r = nqddown(aid, &c);
  if (r != NQOK) {
    return r;
  }
  r = nqdnext(&c, oid);
  if (r != NQOK || nqdoid(oid, NULL) != NQOK) {
    return NQEDEC;
  }
  *hasp = 0;
  if (!nqdend(&c)) {
    r = nqdnext(&c, par);
    if (r != NQOK) {
      return r;
    }
    *hasp = 1;
  }
  return nqddone(&c);
}

int nqxhalg(const nqdtlv *aid, int sha1ok, nqhalg *h) {
  nqdtlv oid, par;
  int hasp, r = aidsplit(aid, &oid, &par, &hasp);
  if (r != NQOK) {
    return r;
  }
  if (hasp && nqdnull(&par) != NQOK) {
    return NQEDEC;
  }
  if (nqxoideq(&oid, &nqxoidsha256)) {
    *h = NQS256;
  } else if (nqxoideq(&oid, &nqxoidsha384)) {
    *h = NQS384;
  } else if (nqxoideq(&oid, &nqxoidsha512)) {
    *h = NQS512;
  } else if (sha1ok && nqxoideq(&oid, &nqxoidsha1)) {
    *h = (nqhalg)0;
  } else {
    return NQENOSUP;
  }
  return NQOK;
}

size_t nqxhlen(nqhalg h) {
  return h == 0 ? 20 : nqhlen(h);
}

int nqxdig(const nqxops *ops, nqhalg h, const uint8_t *in, size_t len,
           uint8_t *out) {
  if (h == 0) {
    if (ops == NULL || ops->sha1 == NULL) {
      return NQENOSUP;
    }
    return ops->sha1(ops->user, in, len, out) == NQOK ? NQOK : NQEARG;
  }
  return nqhash(h, in, len, out, nqhlen(h));
}

/* RSASSA-PSS-params with the hash h on both sides and salt hLen. */
static int pssparams(const nqdtlv *par, nqhalg *h) {
  nqdcur c, e, m;
  nqdtlv t, u, x;
  nqhalg h2;
  int64_t salt;
  int r = NQEDEC;
  if (par->cls != NQDUNI || par->tag != NQDSEQ) {
    return NQEDEC;
  }
  if ((r = nqddown(par, &c)) != NQOK) {
    return r;
  }
  /* [0] hashAlgorithm: the default (SHA-1) is not supported */
  if ((r = nqdget(&c, NQDCTX, 1, 0, &t)) != NQOK) {
    return NQENOSUP;
  }
  if ((r = nqddown(&t, &e)) != NQOK || (r = nqdnext(&e, &u)) != NQOK ||
      (r = nqddone(&e)) != NQOK || (r = nqxhalg(&u, 0, h)) != NQOK) {
    return r;
  }
  /* [1] maskGenAlgorithm: MGF1 with the same hash */
  if ((r = nqdget(&c, NQDCTX, 1, 1, &t)) != NQOK) {
    return NQENOSUP;
  }
  if ((r = nqddown(&t, &e)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 1, NQDSEQ, &u)) != NQOK ||
      (r = nqddone(&e)) != NQOK || (r = nqddown(&u, &m)) != NQOK ||
      (r = nqdnext(&m, &x)) != NQOK) {
    return r;
  }
  if (!nqxoideq(&x, &omgf1)) {
    return NQENOSUP;
  }
  if ((r = nqdnext(&m, &x)) != NQOK || (r = nqddone(&m)) != NQOK ||
      (r = nqxhalg(&x, 0, &h2)) != NQOK) {
    return r;
  }
  if (h2 != *h) {
    return NQENOSUP;
  }
  /* [2] saltLength: hLen */
  if ((r = nqdget(&c, NQDCTX, 1, 2, &t)) != NQOK) {
    return NQENOSUP;
  }
  if ((r = nqddown(&t, &e)) != NQOK || (r = nqdnext(&e, &u)) != NQOK ||
      (r = nqddone(&e)) != NQOK || (r = nqdi64(&u, &salt)) != NQOK) {
    return r == NQELIM ? NQENOSUP : r;
  }
  if (salt != (int64_t)nqhlen(*h)) {
    return NQENOSUP;
  }
  /* [3] trailerField: DER omits the only value allowed (1) */
  return nqddone(&c);
}

/* 1 and the algorithm when oid is one of the post-quantum ones. */
static int pqoid(const nqdtlv *oid, nqsalg *a) {
  uint8_t arc;
  if (oid->v.n != sizeof pqpre + 1 ||
      memcmp(oid->v.p, pqpre, sizeof pqpre) != 0) {
    return 0;
  }
  arc = oid->v.p[sizeof pqpre];
  if (arc >= 17 && arc <= 19) {
    *a = (nqsalg)(NQMLDSA44 + (arc - 17));
    return 1;
  }
  if (arc >= 20 && arc <= 31) {
    *a = (nqsalg)(NQSLH128S + (arc - 20));
    return 1;
  }
  return 0;
}

int nqxsalg(const nqdtlv *aid, nqxsig *s) {
  nqdtlv oid, par;
  int hasp, r = aidsplit(aid, &oid, &par, &hasp);
  if (r != NQOK) {
    return r;
  }
  memset(s, 0, sizeof *s);
  if (nqxoideq(&oid, &orsa256) || nqxoideq(&oid, &orsa384) ||
      nqxoideq(&oid, &orsa512)) {
    s->kind = NQXRSA;
    s->h = nqxoideq(&oid, &orsa256)   ? NQS256
           : nqxoideq(&oid, &orsa384) ? NQS384
                                      : NQS512;
    return hasp && nqdnull(&par) == NQOK ? NQOK : NQEDEC;
  }
  if (nqxoideq(&oid, &oec256) || nqxoideq(&oid, &oec384) ||
      nqxoideq(&oid, &oec512)) {
    s->kind = NQXECDSA;
    s->h = nqxoideq(&oid, &oec256)   ? NQS256
           : nqxoideq(&oid, &oec384) ? NQS384
                                     : NQS512;
    return hasp ? NQEDEC : NQOK;
  }
  if (nqxoideq(&oid, &opss)) {
    s->kind = NQXPSS;
    if (!hasp) {
      return NQENOSUP;
    }
    return pssparams(&par, &s->h);
  }
  if (pqoid(&oid, &s->pq)) {
    s->kind = NQXPQ;
    return hasp ? NQEDEC : NQOK;
  }
  return NQENOSUP;
}

/* ---- public keys ---- */

/* RSAPublicKey: two positive INTEGERs. */
static int rsakey(nqspan k) {
  nqdtlv t, a;
  nqdcur c;
  int neg, r = NQEDEC;
  if ((r = nqdone(k.p, k.n, &t)) != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.tag != NQDSEQ || nqddown(&t, &c) != NQOK) {
    return NQEDEC;
  }
  if (nqdnext(&c, &a) != NQOK || nqdint(&a, NULL, &neg) != NQOK || neg ||
      a.v.n < 2) {
    return NQEDEC;
  }
  if (nqdnext(&c, &a) != NQOK || nqdint(&a, NULL, &neg) != NQOK || neg ||
      (a.v.n == 1 && a.v.p[0] == 0)) {
    return NQEDEC;
  }
  return nqddone(&c);
}

static size_t pqklen(nqsalg a) {
  switch (a) {
  case NQMLDSA44:
    return 1312;
  case NQMLDSA65:
    return 1952;
  case NQMLDSA87:
    return 2592;
  case NQSLH128S: case NQSLH128F: case NQSLHK128S: case NQSLHK128F:
    return 32;
  case NQSLH192S: case NQSLH192F: case NQSLHK192S: case NQSLHK192F:
    return 48;
  default:
    return 64;
  }
}

int nqxspki(const nqdtlv *t, nqxkey *k) {
  nqdcur c;
  nqdtlv aid, bits, oid, par;
  int hasp, r = NQEDEC;
  memset(k, 0, sizeof *k);
  if (t->cls != NQDUNI || t->tag != NQDSEQ || nqddown(t, &c) != NQOK) {
    return NQEDEC;
  }
  if ((r = nqdget(&c, NQDUNI, 1, NQDSEQ, &aid)) != NQOK ||
      (r = nqdnext(&c, &bits)) != NQOK || (r = nqddone(&c)) != NQOK ||
      (r = nqdbit0(&bits, &k->key)) != NQOK ||
      (r = aidsplit(&aid, &oid, &par, &hasp)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  k->spki = t->raw;
  if (nqxoideq(&oid, &nqxoidrsa)) {
    if (!hasp || nqdnull(&par) != NQOK) {
      return NQEDEC;
    }
    k->type = NQXKRSA;
    return rsakey(k->key);
  }
  if (nqxoideq(&oid, &opss)) {
    k->type = NQXKPSS;
    return rsakey(k->key);
  }
  if (nqxoideq(&oid, &oecpk)) {
    size_t l;
    if (!hasp) {
      return NQEDEC;
    }
    if (nqxoideq(&par, &op256)) {
      k->curve = NQXP256;
      l = 32;
    } else if (nqxoideq(&par, &op384)) {
      k->curve = NQXP384;
      l = 48;
    } else if (nqxoideq(&par, &op521)) {
      k->curve = NQXP521;
      l = 66;
    } else {
      return NQOK; /* another curve: type 0 */
    }
    if (k->key.n == 0 || k->key.p[0] != 0x04) {
      k->curve = 0;
      return NQOK; /* compressed points are not supported */
    }
    if (k->key.n != 1 + 2 * l) {
      return NQEDEC;
    }
    k->type = NQXKEC;
    return NQOK;
  }
  if (pqoid(&oid, &k->pq)) {
    if (hasp || k->key.n != pqklen(k->pq)) {
      return NQEDEC;
    }
    k->type = NQXKPQ;
    return NQOK;
  }
  return NQOK;
}

int nqxkeyok(const nqxkey *key, const nqxsig *alg) {
  switch (alg->kind) {
  case NQXRSA:
    return key->type == NQXKRSA ? NQOK : NQEVRFY;
  case NQXPSS:
    return key->type == NQXKRSA || key->type == NQXKPSS ? NQOK : NQEVRFY;
  case NQXECDSA:
    return key->type == NQXKEC ? NQOK : NQEVRFY;
  case NQXPQ:
    return key->type == NQXKPQ && key->pq == alg->pq ? NQOK : NQEVRFY;
  default:
    return NQENOSUP;
  }
}

int nqxvrfy(const nqxops *ops, const nqxkey *key, const nqxsig *alg,
            nqspan msg, nqspan sig) {
  uint8_t dig[NQHMAX];
  nqxvreq q;
  int r = NQEDEC;
  if (ops == NULL || ops->vrfy == NULL) {
    return NQEARG;
  }
  if ((r = nqxkeyok(key, alg)) != NQOK) {
    return r;
  }
  q.alg = *alg;
  q.key = key;
  q.msg = msg;
  q.sig = sig;
  q.dig = NULL;
  q.diglen = 0;
  if (alg->kind != NQXPQ) {
    q.diglen = nqhlen(alg->h);
    if (nqhash(alg->h, msg.p, msg.n, dig, q.diglen) != NQOK) {
      return NQEARG;
    }
    q.dig = dig;
  }
  r = ops->vrfy(ops->user, &q);
  if (r == NQOK) {
    return NQOK;
  }
  return r == NQENOSUP ? NQENOSUP : NQEVRFY;
}

/* ---- names ---- */

/* Checks a Name: SEQUENCE OF RDN, each a non-empty SET OF
 * AttributeTypeAndValue { OID, value }. *empty gets whether it has no
 * RDN. */
int nqxname(const nqdtlv *t, int *empty) {
  nqdcur c, s, a;
  nqdtlv rdn, atv, x;
  int r = NQEDEC;
  if (t->cls != NQDUNI || t->tag != NQDSEQ) {
    return NQEDEC;
  }
  if ((r = nqddown(t, &c)) != NQOK) {
    return r;
  }
  *empty = nqdend(&c);
  while (!nqdend(&c)) {
    if ((r = nqdget(&c, NQDUNI, 1, NQDSET, &rdn)) != NQOK ||
        (r = nqddown(&rdn, &s)) != NQOK) {
      return r;
    }
    if (nqdend(&s)) {
      return NQEDEC;
    }
    while (!nqdend(&s)) {
      if ((r = nqdget(&s, NQDUNI, 1, NQDSEQ, &atv)) != NQOK ||
          (r = nqddown(&atv, &a)) != NQOK ||
          (r = nqdnext(&a, &x)) != NQOK || (r = nqdoid(&x, NULL)) != NQOK ||
          (r = nqdnext(&a, &x)) != NQOK || (r = nqddone(&a)) != NQOK) {
        return r == NQOK ? NQEDEC : r;
      }
    }
  }
  return NQOK;
}

static uint8_t lower(uint8_t c) {
  return c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : c;
}

/* The next character of a value under the basic folding, or -1 at the
 * end: leading and trailing spaces dropped, runs of spaces as one. */
static int fold(const nqspan *v, size_t *i) {
  if (*i >= v->n) {
    return -1;
  }
  if (v->p[*i] == ' ') {
    size_t j = *i;
    while (j < v->n && v->p[j] == ' ') {
      j++;
    }
    *i = j;
    return j >= v->n ? -1 : ' '; /* trailing spaces end the value */
  }
  return lower(v->p[(*i)++]);
}

static int valeq(const nqdtlv *a, const nqdtlv *b) {
  int fa = a->cls == NQDUNI && (a->tag == NQDPRT || a->tag == NQDUTF8);
  int fb = b->cls == NQDUNI && (b->tag == NQDPRT || b->tag == NQDUTF8);
  size_t i = 0, j = 0;
  if (!fa || !fb) {
    return a->cls == b->cls && a->con == b->con && a->tag == b->tag &&
           nqdseq(a->v, b->v);
  }
  /* skip leading spaces */
  while (i < a->v.n && a->v.p[i] == ' ') {
    i++;
  }
  while (j < b->v.n && b->v.p[j] == ' ') {
    j++;
  }
  for (;;) {
    int x = fold(&a->v, &i), y = fold(&b->v, &j);
    if (x != y) {
      return 0;
    }
    if (x < 0) {
      return 1;
    }
  }
}

int nqxneq(nqspan a, nqspan b) {
  nqdtlv ta, tb, ra, rb, xa, xb;
  nqdcur ca, cb, sa, sb, aa, ab;
  int e;
  if (nqdhdr(a.p, a.n, &ta) != NQOK || nqdhdr(b.p, b.n, &tb) != NQOK ||
      ta.raw.n != a.n || tb.raw.n != b.n || nqxname(&ta, &e) != NQOK ||
      nqxname(&tb, &e) != NQOK) {
    return 0;
  }
  if (nqdseq(a, b)) {
    return 1;
  }
  nqddown(&ta, &ca);
  nqddown(&tb, &cb);
  for (;;) {
    if (nqdend(&ca) || nqdend(&cb)) {
      return nqdend(&ca) && nqdend(&cb);
    }
    nqdnext(&ca, &ra);
    nqdnext(&cb, &rb);
    nqddown(&ra, &sa);
    nqddown(&rb, &sb);
    for (;;) {
      if (nqdend(&sa) || nqdend(&sb)) {
        if (!(nqdend(&sa) && nqdend(&sb))) {
          return 0;
        }
        break;
      }
      nqdnext(&sa, &xa);
      nqdnext(&sb, &xb);
      nqddown(&xa, &aa);
      nqddown(&xb, &ab);
      nqdnext(&aa, &xa);
      nqdnext(&ab, &xb);
      if (!nqdseq(xa.v, xb.v)) {
        return 0; /* attribute types */
      }
      nqdnext(&aa, &xa);
      nqdnext(&ab, &xb);
      if (!valeq(&xa, &xb)) {
        return 0;
      }
    }
  }
}

/* ---- extensions ---- */

int nqxgext(const nqdtlv *seq) {
  nqdcur e, f, g;
  nqdtlv x, oid, y, val;
  int r = NQEDEC, got, crit;
  if ((r = nqddown(seq, &e)) != NQOK) {
    return r;
  }
  if (nqdend(&e)) {
    return NQEDEC;
  }
  while (!nqdend(&e)) {
    if ((r = nqdget(&e, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
        (r = nqddown(&x, &f)) != NQOK || (r = nqdnext(&f, &oid)) != NQOK ||
        (r = nqdoid(&oid, NULL)) != NQOK ||
        (r = nqdopt(&f, NQDUNI, 0, NQDBOOL, &y, &got)) != NQOK) {
      return r == NQOK ? NQEDEC : r;
    }
    if (got) {
      if (nqdbool(&y, &crit) != NQOK || !crit) {
        return NQEDEC;
      }
      return NQENOSUP; /* a critical extension not handled here */
    }
    if ((r = nqdget(&f, NQDUNI, 0, NQDOCT, &val)) != NQOK ||
        (r = nqddone(&f)) != NQOK ||
        (r = nqdone(val.v.p, val.v.n, NULL)) != NQOK) {
      return r;
    }
    /* unique types */
    nqddown(seq, &g);
    for (;;) {
      nqdtlv z, zo;
      nqdcur h;
      nqdnext(&g, &z);
      if (z.raw.p == x.raw.p) {
        break;
      }
      nqddown(&z, &h);
      nqdnext(&h, &zo);
      if (nqdseq(zo.v, oid.v)) {
        return NQEDEC;
      }
    }
  }
  return NQOK;
}


static int extbc(nqspan v, nqcert *c) {
  nqdtlv t, x;
  nqdcur e;
  int b, r = NQEDEC, neg;
  int64_t pl;
  if ((r = nqdone(v.p, v.n, &t)) != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.tag != NQDSEQ || nqddown(&t, &e) != NQOK) {
    return NQEDEC;
  }
  if (!nqdend(&e)) {
    if (nqdpeek(&e, &x) != NQOK) {
      return NQEDEC;
    }
    if (x.cls == NQDUNI && x.tag == NQDBOOL) {
      nqdnext(&e, &x);
      if (nqdbool(&x, &b) != NQOK || !b) {
        return NQEDEC; /* DER omits the default (FALSE) */
      }
      c->ca = 1;
    }
  }
  if (!nqdend(&e)) {
    if ((r = nqdnext(&e, &x)) != NQOK || (r = nqdint(&x, NULL, &neg)) != NQOK) {
      return NQEDEC;
    }
    if (neg || !c->ca) {
      return NQEDEC;
    }
    r = nqdi64(&x, &pl);
    if (r != NQOK || pl > 255) {
      pl = 255; /* a bound this large is no bound at all */
    }
    c->plen = (int)pl;
  }
  return nqddone(&e);
}

static int extku(nqspan v, nqcert *c) {
  nqdtlv t;
  int r = nqdone(v.p, v.n, &t);
  if (r != NQOK) {
    return r;
  }
  if ((r = nqdnbits(&t, &c->ku)) != NQOK) {
    return r == NQELIM ? NQEDEC : r;
  }
  if (c->ku == 0 || (c->ku >> 9) != 0) {
    return NQEDEC; /* at least one bit; nine are defined */
  }
  return NQOK;
}

static int exteku(nqspan v, nqcert *c) {
  static const uint8_t kp[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03};
  nqdtlv t, x;
  nqdcur e, f;
  int r = NQEDEC;
  if ((r = nqdone(v.p, v.n, &t)) != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.tag != NQDSEQ || nqddown(&t, &e) != NQOK ||
      nqdend(&e)) {
    return NQEDEC;
  }
  while (!nqdend(&e)) {
    uint32_t bit = NQXEKUOTH;
    if (nqdnext(&e, &x) != NQOK || nqdoid(&x, NULL) != NQOK) {
      return NQEDEC;
    }
    /* no purpose twice */
    nqddown(&t, &f);
    for (;;) {
      nqdtlv y;
      nqdnext(&f, &y);
      if (y.raw.p == x.raw.p) {
        break;
      }
      if (nqdseq(y.v, x.v)) {
        return NQEDEC;
      }
    }
    if (x.v.n == sizeof kp + 1 && memcmp(x.v.p, kp, sizeof kp) == 0) {
      switch (x.v.p[sizeof kp]) {
      case 1: bit = NQXEKUSRV; break;
      case 2: bit = NQXEKUCLI; break;
      case 3: bit = NQXEKUCODE; break;
      case 4: bit = NQXEKUMAIL; break;
      case 8: bit = NQXEKUTS; break;
      case 9: bit = NQXEKUOCSP; break;
      default: break;
      }
    } else if (nqxoideq(&x, &oanyeku)) {
      bit = NQXEKUANY;
    }
    c->eku |= bit;
    c->ekun++;
  }
  return NQOK;
}

static int extski(nqspan v, nqcert *c) {
  nqdtlv t;
  int r = nqdone(v.p, v.n, &t);
  if (r != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.con || t.tag != NQDOCT || t.v.n == 0) {
    return NQEDEC;
  }
  c->ski = t.v;
  return NQOK;
}

static int extaki(nqspan v, nqcert *c) {
  nqdtlv t, x;
  nqdcur e;
  int r = NQEDEC, got, g1, g2;
  if ((r = nqdone(v.p, v.n, &t)) != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.tag != NQDSEQ || nqddown(&t, &e) != NQOK) {
    return NQEDEC;
  }
  if ((r = nqdopt(&e, NQDCTX, 0, 0, &x, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if (x.v.n == 0) {
      return NQEDEC;
    }
    c->aki = x.v;
  }
  if ((r = nqdopt(&e, NQDCTX, 1, 1, &x, &g1)) != NQOK) {
    return r;
  }
  if ((r = nqdopt(&e, NQDCTX, 0, 2, &x, &g2)) != NQOK) {
    return r;
  }
  if (g2 && nqdprim(NQDINT, x.v.p, x.v.n) != NQOK) {
    return NQEDEC;
  }
  if (g1 != g2) {
    return NQEDEC; /* issuer and serial come together */
  }
  return nqddone(&e);
}

/* subjectAltName: GeneralNames, SIZE (1..MAX); kept for the TLS client
 * to match a host name (src/tls/crt.c), whatever its criticality */
static int extsan(nqspan v, nqcert *c) {
  nqdtlv t;
  int r = nqdone(v.p, v.n, &t);
  if (r != NQOK) {
    return r;
  }
  if (t.cls != NQDUNI || t.tag != NQDSEQ || t.v.n == 0) {
    return NQEDEC;
  }
  c->san = t.v;
  return NQOK;
}

static int exts(const nqdtlv *t, nqcert *c) {
  nqspan seen[NQXMAXEXT];
  size_t ns = 0, i;
  nqdcur e, f;
  nqdtlv seq, x, oid, val;
  int r = NQEDEC;
  if ((r = nqddown(t, &e)) != NQOK ||
      (r = nqdget(&e, NQDUNI, 1, NQDSEQ, &seq)) != NQOK ||
      (r = nqddone(&e)) != NQOK || (r = nqddown(&seq, &e)) != NQOK) {
    return r;
  }
  if (nqdend(&e)) {
    return NQEDEC; /* SIZE (1..MAX) */
  }
  while (!nqdend(&e)) {
    int crit = 0, got;
    unsigned bit = 0;
    if ((r = nqdget(&e, NQDUNI, 1, NQDSEQ, &x)) != NQOK ||
        (r = nqddown(&x, &f)) != NQOK || (r = nqdnext(&f, &oid)) != NQOK ||
        (r = nqdoid(&oid, NULL)) != NQOK) {
      return r == NQOK ? NQEDEC : r;
    }
    if ((r = nqdopt(&f, NQDUNI, 0, NQDBOOL, &x, &got)) != NQOK) {
      return r;
    }
    if (got) {
      if (nqdbool(&x, &crit) != NQOK || !crit) {
        return NQEDEC; /* DER omits the default (FALSE) */
      }
    }
    if ((r = nqdget(&f, NQDUNI, 0, NQDOCT, &val)) != NQOK ||
        (r = nqddone(&f)) != NQOK) {
      return r;
    }
    if (ns == NQXMAXEXT) {
      return NQELIM;
    }
    for (i = 0; i < ns; i++) {
      if (nqdseq(seen[i], oid.v)) {
        return NQEDEC; /* RFC 5280 4.2: at most one of each */
      }
    }
    seen[ns++] = oid.v;
    if (nqxoideq(&oid, &obc)) {
      bit = NQXHASBC;
      r = extbc(val.v, c);
    } else if (nqxoideq(&oid, &oku)) {
      bit = NQXHASKU;
      r = extku(val.v, c);
    } else if (nqxoideq(&oid, &oeku)) {
      bit = NQXHASEKU;
      r = exteku(val.v, c);
      c->ekucrit = crit;
    } else if (nqxoideq(&oid, &oski)) {
      bit = NQXHASSKI;
      r = extski(val.v, c);
      if (crit) {
        return NQEDEC; /* MUST be non-critical */
      }
    } else if (nqxoideq(&oid, &osan)) {
      bit = NQXHASSAN;
      r = extsan(val.v, c);
    } else if (nqxoideq(&oid, &oaki)) {
      bit = NQXHASAKI;
      r = extaki(val.v, c);
      if (crit) {
        return NQEDEC;
      }
    } else {
      r = nqdone(val.v.p, val.v.n, NULL);
      if (crit) {
        c->bad = 1;
      }
    }
    if (r != NQOK) {
      return r;
    }
    c->ext |= bit;
  }
  return NQOK;
}

/* ---- certificates ---- */

static int prs(const uint8_t *p, size_t n, nqcert *c, int anchor) {
  nqdtlv top, tbs, aid, sig, t, x;
  nqdcur cc, tc, vc;
  int r = NQEDEC, got, neg, empty;
  if (p == NULL || c == NULL) {
    return NQEARG;
  }
  memset(c, 0, sizeof *c);
  c->plen = -1;
  if ((r = nqdone(p, n, &top)) != NQOK) {
    return r;
  }
  if (top.cls != NQDUNI || top.tag != NQDSEQ ||
      (r = nqddown(&top, &cc)) != NQOK ||
      (r = nqdget(&cc, NQDUNI, 1, NQDSEQ, &tbs)) != NQOK ||
      (r = nqdget(&cc, NQDUNI, 1, NQDSEQ, &aid)) != NQOK ||
      (r = nqdnext(&cc, &sig)) != NQOK || (r = nqddone(&cc)) != NQOK ||
      (r = nqdbit0(&sig, &c->sig)) != NQOK) {
    return r == NQOK ? NQEDEC : r;
  }
  c->raw = top.raw;
  c->tbs = tbs.raw;
  c->sigaid = aid.raw;
  r = nqxsalg(&aid, &c->salg);
  if (r == NQENOSUP) {
    memset(&c->salg, 0, sizeof c->salg); /* parsed; not verifiable here */
  } else if (r != NQOK) {
    return r;
  }
  if ((r = nqddown(&tbs, &tc)) != NQOK) {
    return r;
  }
  /* [0] EXPLICIT version DEFAULT v1 */
  c->ver = 1;
  if ((r = nqdopt(&tc, NQDCTX, 1, 0, &t, &got)) != NQOK) {
    return r;
  }
  if (got) {
    int64_t v;
    if ((r = nqddown(&t, &vc)) != NQOK || (r = nqdnext(&vc, &x)) != NQOK ||
        (r = nqddone(&vc)) != NQOK || (r = nqdi64(&x, &v)) != NQOK) {
      return r == NQELIM ? NQEDEC : r;
    }
    if (v != 1 && v != 2) {
      return NQEDEC; /* DER omits v1; nothing after v3 */
    }
    c->ver = (int)v + 1;
  }
  /* serialNumber: positive, at most 20 octets (RFC 5280 4.1.2.2). A
   * trust anchor is the caller's own choice, not a path's link: its
   * serial is only a label, so old roots with a serial of 0 or a negative
   * one (a high first octet with no 00 before it) are taken as they are;
   * the encoding itself is still DER */
  if ((r = nqdnext(&tc, &t)) != NQOK) {
    return r;
  }
  if (anchor) {
    if (t.cls != NQDUNI || t.con || t.tag != NQDINT || t.v.n == 0) {
      return NQEDEC;
    }
  } else {
    if ((r = nqdint(&t, NULL, &neg)) != NQOK) {
      return r;
    }
    if (neg || (t.v.n == 1 && t.v.p[0] == 0)) {
      return NQEDEC;
    }
  }
  if (t.v.n > 20) {
    return NQELIM;
  }
  c->serial = t.v;
  /* signature: the same AlgorithmIdentifier as outside */
  if ((r = nqdget(&tc, NQDUNI, 1, NQDSEQ, &t)) != NQOK) {
    return r;
  }
  if (!nqdseq(t.raw, c->sigaid)) {
    return NQEDEC;
  }
  /* issuer: not empty */
  if ((r = nqdnext(&tc, &t)) != NQOK || (r = nqxname(&t, &empty)) != NQOK) {
    return r;
  }
  if (empty) {
    return NQEDEC;
  }
  c->issuer = t.raw;
  /* validity */
  if ((r = nqdget(&tc, NQDUNI, 1, NQDSEQ, &t)) != NQOK ||
      (r = nqddown(&t, &vc)) != NQOK || (r = nqdnext(&vc, &x)) != NQOK ||
      (r = nqdtime(&x, NQDT5280, &c->nb, NULL)) != NQOK ||
      (r = nqdnext(&vc, &x)) != NQOK ||
      (r = nqdtime(&x, NQDT5280, &c->na, NULL)) != NQOK ||
      (r = nqddone(&vc)) != NQOK) {
    return r;
  }
  /* subject */
  if ((r = nqdnext(&tc, &t)) != NQOK || (r = nqxname(&t, &empty)) != NQOK) {
    return r;
  }
  c->subject = t.raw;
  /* subjectPublicKeyInfo */
  if ((r = nqdnext(&tc, &t)) != NQOK || (r = nqxspki(&t, &c->key)) != NQOK) {
    return r;
  }
  /* [1] issuerUniqueID, [2] subjectUniqueID: v2 and v3 */
  if ((r = nqdopt(&tc, NQDCTX, 0, 1, &t, &got)) != NQOK) {
    return r;
  }
  if (got && (c->ver < 2 || nqdprim(NQDBITS, t.v.p, t.v.n) != NQOK)) {
    return NQEDEC;
  }
  if ((r = nqdopt(&tc, NQDCTX, 0, 2, &t, &got)) != NQOK) {
    return r;
  }
  if (got && (c->ver < 2 || nqdprim(NQDBITS, t.v.p, t.v.n) != NQOK)) {
    return NQEDEC;
  }
  /* [3] extensions: v3 */
  if ((r = nqdopt(&tc, NQDCTX, 1, 3, &t, &got)) != NQOK) {
    return r;
  }
  if (got) {
    if (c->ver != 3) {
      return NQEDEC;
    }
    if ((r = exts(&t, c)) != NQOK) {
      return r;
    }
  }
  return nqddone(&tc);
}

int nqcprs(const uint8_t *p, size_t n, nqcert *c) {
  return prs(p, n, c, 0);
}

int nqcprsa(const uint8_t *p, size_t n, nqcert *c) {
  return prs(p, n, c, 1);
}
