/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The TLS 1.3 client handshake (RFC 8446 section 4) and the messages
 * after it. The server's flight is read in its one allowed order
 * (ServerHello, EncryptedExtensions, CertificateRequest when sent,
 * Certificate, CertificateVerify, Finished), each message parsed to its
 * last byte; an extension the client did not offer, a duplicate, a
 * value outside what was offered or trailing bytes end the handshake
 * with the alert section 6.2 names. The client learns what it offered by
 * reading its own ClientHello back (nqtlscan), so the checks and the
 * message never disagree. */
#include <string.h>
#include <time.h>

#include "core/int.h"
#include "tls/tls.h"
#include "xdh/xdh.h"

/* ---- reading ---- */

typedef struct {
  const uint8_t *p;
  size_t n;
} cur;

static int g8(cur *c, unsigned *v) {
  if (c->n < 1) return 0;
  *v = c->p[0];
  c->p++;
  c->n--;
  return 1;
}

static int g16(cur *c, unsigned *v) {
  if (c->n < 2) return 0;
  *v = ((unsigned)c->p[0] << 8) | c->p[1];
  c->p += 2;
  c->n -= 2;
  return 1;
}

static int gb(cur *c, size_t n, const uint8_t **p) {
  if (c->n < n) return 0;
  *p = c->p;
  c->p += n;
  c->n -= n;
  return 1;
}

/* a vector with an lb-byte length (1, 2 or 3) into v */
static int gv(cur *c, int lb, cur *v) {
  size_t n = 0;
  int i;
  if (c->n < (size_t)lb) return 0;
  for (i = 0; i < lb; i++) n = (n << 8) | c->p[i];
  c->p += lb;
  c->n -= (size_t)lb;
  v->p = c->p;
  v->n = n;
  return gb(c, n, &v->p);
}

/* ---- writing ---- */

typedef struct {
  uint8_t *b;
  size_t cap, n;
  int bad;
} wbuf;

static void p8(wbuf *w, unsigned v) {
  if (w->n + 1 > w->cap) {
    w->bad = 1;
    return;
  }
  w->b[w->n++] = (uint8_t)v;
}

static void p16(wbuf *w, unsigned v) {
  p8(w, (v >> 8) & 0xff);
  p8(w, v & 0xff);
}

static void pb(wbuf *w, const uint8_t *p, size_t n) {
  if (w->n + n > w->cap) {
    w->bad = 1;
    return;
  }
  if (n > 0) memcpy(w->b + w->n, p, n);
  w->n += n;
}

/* opens a vector with an lb-byte length; close it with pclose */
static size_t popen(wbuf *w, int lb) {
  size_t at = w->n;
  int i;
  for (i = 0; i < lb; i++) p8(w, 0);
  return at;
}

static void pclose(wbuf *w, size_t at, int lb) {
  size_t n;
  int i;
  if (w->bad) return;
  n = w->n - at - (size_t)lb;
  if (lb < 3 && n >> (8 * lb) != 0) {
    w->bad = 1;
    return;
  }
  for (i = 0; i < lb; i++) {
    w->b[at + (size_t)i] = (uint8_t)(n >> (8 * (lb - 1 - i)));
  }
}

/* ---- what this client offers ---- */

static const uint16_t suites[] = {NQTLA128, NQTLA256, NQTLC20};
static const uint16_t groups[] = {NQTLHYB, NQTLX25519};
/* CertificateVerify can use the first five; the RSA PKCS #1 v1.5
 * schemes are listed for the certificates only (section 4.2.3) */
static const uint16_t sigs[] = {0x0403, 0x0503, 0x0804, 0x0805, 0x0806,
                                0x0401, 0x0501, 0x0601};

static int has16(const uint16_t *a, size_t n, unsigned v) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (a[i] == v) return 1;
  }
  return 0;
}

/* ---- reading a ClientHello back ---- */

int nqtlscan(const uint8_t *ch, size_t n, nqtloff *o) {
  cur c, v, x, e, l;
  unsigned u, ty;
  memset(o, 0, sizeof *o);
  c.p = ch;
  c.n = n;
  if (!g8(&c, &u) || u != NQTLCH || !gv(&c, 3, &v) || c.n != 0) {
    return NQEDEC;
  }
  if (!g16(&v, &u) || u != 0x0303 || !gb(&v, 32, &o->rnd) ||
      !gv(&v, 1, &x) || x.n > 32) {
    return NQEDEC;
  }
  memcpy(o->sid, x.p, x.n);
  o->sidn = x.n;
  if (!gv(&v, 2, &x) || x.n == 0 || x.n % 2 != 0 || x.n / 2 > 8) {
    return NQEDEC;
  }
  while (g16(&x, &u)) o->suites[o->nsuite++] = (uint16_t)u;
  if (!gv(&v, 1, &x) || x.n != 1 || x.p[0] != 0 || !gv(&v, 2, &x) ||
      v.n != 0) {
    return NQEDEC;
  }
  while (x.n > 0) {
    if (!g16(&x, &ty) || !gv(&x, 2, &e) || o->next == NQTLXMAX ||
        has16(o->ext, o->next, ty)) {
      return NQEDEC;
    }
    o->ext[o->next++] = (uint16_t)ty;
    if (ty == 10) {
      if (!gv(&e, 2, &l) || e.n != 0 || l.n % 2 != 0 || l.n / 2 > 16) {
        return NQEDEC;
      }
      while (g16(&l, &u)) o->grp[o->ngrp++] = (uint16_t)u;
    } else if (ty == 51) {
      if (!gv(&e, 2, &l) || e.n != 0) return NQEDEC;
      while (l.n > 0) {
        cur k;
        if (!g16(&l, &u) || !gv(&l, 2, &k) || o->nks == 4) return NQEDEC;
        o->ks[o->nks++] = (uint16_t)u;
      }
    } else if (ty == 13) {
      if (!gv(&e, 2, &l) || e.n != 0 || l.n % 2 != 0 || l.n / 2 > 16) {
        return NQEDEC;
      }
      while (g16(&l, &u)) o->sig[o->nsig++] = (uint16_t)u;
    }
  }
  return NQOK;
}

/* ---- the transcript ---- */

static void thadd(nqtls *t, const uint8_t *m, size_t n) {
  nqfupd(&t->th, m, n);
}

/* the hash of the transcript so far */
static void thnow(const nqtls *t, uint8_t *out) {
  nqfctx c = t->th;
  nqffin(&c, out);
}

/* ---- the ClientHello ---- */

/* fresh key shares for the groups to send */
static int keys(nqtls *t, int hyb) {
  int rc;
  if (t->hk.xsk != NULL) {
    memcpy(t->xsk, t->hk.xsk, 32);
  } else if ((rc = nqrand(t->xsk, 32)) != NQOK) {
    return rc;
  }
  if (nqx25519b(t->xpk, t->xsk) != NQOK) return NQEARG;
  if (hyb) {
    if (t->kdk == NULL && (t->kdk = (uint8_t *)nqmal(NQHYBSK)) == NULL) {
      return NQEMEM;
    }
    /* the hybrid's X25519 key is also the X25519 share's: the draft
     * allows the reuse, and it saves one scalar multiplication */
    if ((rc = nqhybkg(t->xsk, t->kek, t->kdk)) != NQOK) return rc;
  }
  return NQOK;
}

/* writes the ClientHello for the groups in g (n of them) to t->ch */
static int mkch(nqtls *t, const uint16_t *g, size_t ng) {
  wbuf w;
  size_t a, b, c, d, i, hl = strlen(t->host);
  w.b = t->ch;
  w.cap = sizeof t->ch;
  w.n = 0;
  w.bad = 0;
  p8(&w, NQTLCH);
  a = popen(&w, 3);
  p16(&w, 0x0303);
  pb(&w, t->rnd, 32);
  p8(&w, 32);
  pb(&w, t->sid, 32);
  p16(&w, 2 * (unsigned)(sizeof suites / sizeof suites[0]));
  for (i = 0; i < sizeof suites / sizeof suites[0]; i++) p16(&w, suites[i]);
  p8(&w, 1);
  p8(&w, 0);
  b = popen(&w, 2);
  /* server_name (RFC 6066 section 3): a DNS name only */
  if (!t->ip) {
    p16(&w, 0);
    c = popen(&w, 2);
    d = popen(&w, 2);
    p8(&w, 0);
    p16(&w, (unsigned)hl);
    pb(&w, (const uint8_t *)t->host, hl);
    pclose(&w, d, 2);
    pclose(&w, c, 2);
  }
  /* supported_versions: TLS 1.3 only */
  p16(&w, 43);
  p16(&w, 3);
  p8(&w, 2);
  p16(&w, 0x0304);
  /* supported_groups */
  p16(&w, 10);
  p16(&w, 2 + 2 * (unsigned)(sizeof groups / sizeof groups[0]));
  p16(&w, 2 * (unsigned)(sizeof groups / sizeof groups[0]));
  for (i = 0; i < sizeof groups / sizeof groups[0]; i++) p16(&w, groups[i]);
  /* key_share: the hybrid share is ML-KEM-768's key, then X25519's */
  p16(&w, 51);
  c = popen(&w, 2);
  d = popen(&w, 2);
  for (i = 0; i < ng; i++) {
    p16(&w, g[i]);
    if (g[i] == NQTLHYB) {
      p16(&w, NQTLHEK);
      pb(&w, t->kek, sizeof t->kek);
    } else {
      p16(&w, 32);
      pb(&w, t->xpk, 32);
    }
  }
  pclose(&w, d, 2);
  pclose(&w, c, 2);
  /* signature_algorithms */
  p16(&w, 13);
  p16(&w, 2 + 2 * (unsigned)(sizeof sigs / sizeof sigs[0]));
  p16(&w, 2 * (unsigned)(sizeof sigs / sizeof sigs[0]));
  for (i = 0; i < sizeof sigs / sizeof sigs[0]; i++) p16(&w, sigs[i]);
  /* the HelloRetryRequest's cookie, echoed */
  if (t->ckn > 0) {
    p16(&w, 44);
    c = popen(&w, 2);
    d = popen(&w, 2);
    pb(&w, t->ck, t->ckn);
    pclose(&w, d, 2);
    pclose(&w, c, 2);
  }
  pclose(&w, b, 2);
  pclose(&w, a, 3);
  if (w.bad) return NQELIM;
  t->chn = w.n;
  return NQOK;
}

/* sends ClientHello number k (1 or 2) */
static int sendch(nqtls *t, int k) {
  const uint8_t *hc = k == 1 ? t->hk.ch1 : t->hk.ch2;
  size_t hn = k == 1 ? t->hk.ch1n : t->hk.ch2n;
  int rc;
  if (hc != NULL) {
    if (hn > sizeof t->ch) return nqtlfail(t, NQEARG, -1, "hook too long");
    memcpy(t->ch, hc, hn);
    t->chn = hn;
    if (k == 1 && t->hk.xsk != NULL) {
      memcpy(t->xsk, t->hk.xsk, 32);
    }
  } else {
    uint16_t g[2];
    size_t ng = 0;
    if (k == 1) {
      if ((rc = nqrand(t->rnd, 32)) != NQOK ||
          (rc = nqrand(t->sid, 32)) != NQOK) {
        return nqtlfail(t, rc, -1, "the random source failed");
      }
      g[ng++] = NQTLHYB;
      if (!t->hk.one) g[ng++] = NQTLX25519;
    } else if (t->hrrg != 0) {
      g[ng++] = t->hrrg;
    } else {
      /* a cookie only: the same shares again */
      size_t i;
      for (i = 0; i < t->off.nks && ng < 2; i++) g[ng++] = t->off.ks[i];
    }
    if ((k == 1 || t->hrrg != 0) &&
        (rc = keys(t, g[0] == NQTLHYB)) != NQOK) {
      return nqtlfail(t, rc, -1, rc == NQERNG ? "the random source failed"
                                               : "out of memory");
    }
    if ((rc = mkch(t, g, ng)) != NQOK) {
      return nqtlfail(t, rc, -1, "the ClientHello does not fit");
    }
  }
  if (nqtlscan(t->ch, t->chn, &t->off) != NQOK) {
    return nqtlfail(t, NQEDEC, -1, "the ClientHello does not parse");
  }
  if (t->thon) thadd(t, t->ch, t->chn);
  return nqtlsend(t, NQTLHS, t->ch, t->chn);
}

/* ---- ServerHello and HelloRetryRequest ---- */

static const uint8_t hrrmagic[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
    0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

#define BAD(a, s) return nqtlfail(t, NQEDEC, (a), (s))

/* the (EC)DHE secret for the server's share of group g */
static int kex(nqtls *t, unsigned g, cur *ks, uint8_t *ss, size_t *sn) {
  int rc;
  if (t->hk.ss != NULL) {
    if (t->hk.ssn > 64) return nqtlfail(t, NQEARG, -1, "hook too long");
    memcpy(ss, t->hk.ss, t->hk.ssn);
    *sn = t->hk.ssn;
    return NQOK;
  }
  if (g == NQTLX25519) {
    if (ks->n != 32) BAD(47, "the server's X25519 share is not 32 bytes");
    if (nqx25519(ss, t->xsk, ks->p) != NQOK) {
      BAD(47, "the server's X25519 share is of small order");
    }
    *sn = 32;
    return NQOK;
  }
  if (g == NQTLHYB) {
    if (t->kdk == NULL) BAD(47, "the server chose a share that was not sent");
    rc = nqhybdec(t->kdk, ks->p, ks->n, ss);
    if (rc == NQEDEC) {
      BAD(47, "the server's X25519MLKEM768 share is not 1120 bytes");
    }
    if (rc == NQEVRFY) {
      BAD(47, "the server's X25519 share is of small order");
    }
    if (rc != NQOK) {
      return nqtlfail(t, rc, 80, "ML-KEM-768 decapsulation failed");
    }
    *sn = NQHYBSS;
    return NQOK;
  }
  BAD(47, "the server chose a group it was not offered");
}

/* parses a ServerHello (or HelloRetryRequest); *retry 1 for the latter */
static int onsh(nqtls *t, const uint8_t *m, size_t n, int *retry) {
  cur c, v, x, e;
  unsigned u, suite, grp = 0, ty;
  const uint8_t *rnd;
  uint16_t seen[8];
  size_t ns = 0;
  int ver = 0, hrr, hasks = 0, hasck = 0;
  cur ks;
  c.p = m + 4;
  c.n = n - 4;
  ks.p = NULL;
  ks.n = 0;
  if (m[0] != NQTLSH) BAD(10, "the server did not answer with a ServerHello");
  if (!g16(&c, &u) || !gb(&c, 32, &rnd) || !gv(&c, 1, &v) ||
      !g16(&c, &suite) || !g8(&c, &ty) || !gv(&c, 2, &x) || c.n != 0) {
    BAD(50, "a malformed ServerHello");
  }
  if (u != 0x0303) {
    return nqtlfail(t, NQENOSUP, 70, "the server does not speak TLS 1.3");
  }
  hrr = memcmp(rnd, hrrmagic, 32) == 0;
  if (v.n != t->off.sidn || (v.n > 0 && memcmp(v.p, t->off.sid, v.n) != 0)) {
    BAD(47, "the ServerHello does not echo the session id");
  }
  if (!has16(t->off.suites, t->off.nsuite, suite) ||
      nqtlsh((uint16_t)suite) == 0) {
    BAD(47, "the server chose a cipher suite it was not offered");
  }
  if (ty != 0) BAD(47, "the server chose a compression method");
  while (x.n > 0) {
    if (!g16(&x, &ty) || !gv(&x, 2, &e)) BAD(50, "a malformed extension");
    if (has16(seen, ns, ty) || ns == 8) BAD(47, "an extension twice");
    seen[ns++] = (uint16_t)ty;
    if (!has16(t->off.ext, t->off.next, ty) && !(hrr && ty == 44)) {
      BAD(110, "the ServerHello holds an extension that was not offered");
    }
    if (ty == 43) {
      if (!g16(&e, &u) || e.n != 0) BAD(50, "a malformed supported_versions");
      if (u != 0x0304) {
        return nqtlfail(t, NQENOSUP, 47, "the server chose a version other "
                        "than TLS 1.3");
      }
      ver = 1;
    } else if (ty == 51) {
      if (!g16(&e, &grp)) BAD(50, "a malformed key_share");
      if (hrr) {
        if (e.n != 0) BAD(50, "a malformed key_share");
      } else if (!gv(&e, 2, &ks) || ks.n == 0 || e.n != 0) {
        BAD(50, "a malformed key_share");
      }
      hasks = 1;
    } else if (ty == 44 && hrr) {
      cur ck;
      if (!gv(&e, 2, &ck) || ck.n == 0 || e.n != 0) {
        BAD(50, "a malformed cookie");
      }
      if (ck.n > sizeof t->ck) {
        return nqtlfail(t, NQELIM, 80, "the server's cookie is over 1 KiB");
      }
      memcpy(t->ck, ck.p, ck.n);
      t->ckn = ck.n;
      hasck = 1;
    } else {
      /* pre_shared_key and the rest: never offered */
      BAD(110, "the ServerHello holds an extension that was not offered");
    }
  }
  if (!ver) {
    return nqtlfail(t, NQENOSUP, 70, "the server does not speak TLS 1.3");
  }
  *retry = hrr;
  if (hrr) {
    if (t->hrr) BAD(10, "a second HelloRetryRequest");
    if (!hasks && !hasck) {
      BAD(47, "a HelloRetryRequest that changes nothing");
    }
    if (hasks && (!has16(t->off.grp, t->off.ngrp, grp) ||
                  has16(t->off.ks, t->off.nks, grp))) {
      BAD(47, "the HelloRetryRequest asks for a group it may not");
    }
    t->hrr = 1;
    t->hrrg = hasks ? (uint16_t)grp : 0;
    t->hrrs = (uint16_t)suite;
    return NQOK;
  }
  if (t->hrr && suite != t->hrrs) {
    BAD(47, "the ServerHello's suite differs from the HelloRetryRequest's");
  }
  if (!hasks) BAD(109, "the ServerHello has no key_share");
  if (!has16(t->off.ks, t->off.nks, grp) ||
      (t->hrr && t->hrrg != 0 && grp != t->hrrg)) {
    BAD(47, "the server chose a key share that was not sent");
  }
  t->suite = (uint16_t)suite;
  t->grp = (uint16_t)grp;
  /* the key shares are spent here */
  {
    uint8_t ss[64], es[NQHMAX], th[NQHMAX];
    size_t sn = 0;
    int rc = kex(t, grp, &ks, ss, &sn);
    nqwipe(t->xsk, sizeof t->xsk);
    if (t->kdk != NULL) nqwipe(t->kdk, NQHYBSK);
    if (rc != NQOK) {
      nqwipe(ss, sizeof ss);
      return rc;
    }
    if (!t->thon) {
      t->h = nqtlsh(t->suite);
      t->hl = nqhlen(t->h);
      nqfini(&t->th, t->h);
      t->thon = 1;
      thadd(t, t->ch, t->chn);
    }
    thadd(t, m, n);
    thnow(t, th);
    rc = nqtlnext(t->h, NULL, NULL, 0, es);
    if (rc == NQOK) rc = nqtlnext(t->h, es, ss, sn, t->sec);
    if (rc == NQOK) rc = nqtlder(t->h, t->sec, "c hs traffic", th, t->chs);
    if (rc == NQOK) rc = nqtlder(t->h, t->sec, "s hs traffic", th, t->shs);
    nqwipe(ss, sizeof ss);
    nqwipe(es, sizeof es);
    if (rc != NQOK) return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  return NQOK;
}

/* after a HelloRetryRequest: the transcript restarts with
 * message_hash(ClientHello1) and the HelloRetryRequest (4.4.1) */
static int onhrr(nqtls *t, const uint8_t *m, size_t n) {
  uint8_t mh[4 + NQHMAX];
  t->h = nqtlsh(t->hrrs);
  t->hl = nqhlen(t->h);
  mh[0] = NQTLMH;
  mh[1] = 0;
  mh[2] = 0;
  mh[3] = (uint8_t)t->hl;
  if (nqhash(t->h, t->ch, t->chn, mh + 4, t->hl) != NQOK) {
    return nqtlfail(t, NQEARG, 80, "the transcript hash failed");
  }
  nqfini(&t->th, t->h);
  t->thon = 1;
  thadd(t, mh, 4 + t->hl);
  thadd(t, m, n);
  return NQOK;
}

/* ---- the encrypted flight ---- */

/* EncryptedExtensions: only what was offered and may appear here */
static int onee(nqtls *t, const uint8_t *m, size_t n) {
  cur c, x, e;
  unsigned ty, u;
  uint16_t seen[NQTLXMAX];
  size_t ns = 0;
  c.p = m + 4;
  c.n = n - 4;
  if (!gv(&c, 2, &x) || c.n != 0) BAD(50, "malformed EncryptedExtensions");
  while (x.n > 0) {
    if (!g16(&x, &ty) || !gv(&x, 2, &e)) BAD(50, "a malformed extension");
    if (has16(seen, ns, ty) || ns == NQTLXMAX) BAD(47, "an extension twice");
    seen[ns++] = (uint16_t)ty;
    if (!has16(t->off.ext, t->off.next, ty)) {
      BAD(110, "EncryptedExtensions holds an extension that was not "
          "offered");
    }
    if (ty == 0) {
      if (e.n != 0) BAD(50, "a malformed server_name");
    } else if (ty == 10) {
      cur l;
      if (!gv(&e, 2, &l) || e.n != 0 || l.n == 0 || l.n % 2 != 0) {
        BAD(50, "a malformed supported_groups");
      }
    } else if (ty == 28) {
      /* record_size_limit (RFC 8449), when a hook's hello offered it */
      if (!g16(&e, &u) || e.n != 0) BAD(50, "a malformed record_size_limit");
      if (u < 64) BAD(47, "a record_size_limit below 64");
      t->rsl = u;
    } else {
      BAD(110, "EncryptedExtensions holds an extension not allowed there");
    }
  }
  thadd(t, m, n);
  return NQOK;
}

static int oncr(nqtls *t, const uint8_t *m, size_t n) {
  cur c, x, e, ctx;
  unsigned ty;
  uint16_t seen[NQTLXMAX];
  size_t ns = 0;
  int sa = 0;
  c.p = m + 4;
  c.n = n - 4;
  if (!gv(&c, 1, &ctx) || !gv(&c, 2, &x) || c.n != 0 || x.n < 2) {
    BAD(50, "a malformed CertificateRequest");
  }
  while (x.n > 0) {
    if (!g16(&x, &ty) || !gv(&x, 2, &e)) BAD(50, "a malformed extension");
    if (has16(seen, ns, ty) || ns == NQTLXMAX) BAD(47, "an extension twice");
    seen[ns++] = (uint16_t)ty;
    if (ty == 13) sa = 1;
  }
  if (!sa) BAD(109, "a CertificateRequest without signature_algorithms");
  memcpy(t->crctx, ctx.p, ctx.n);
  t->crctxn = ctx.n;
  t->creq = 1;
  thadd(t, m, n);
  return NQOK;
}

static int oncert(nqtls *t, const uint8_t *m, size_t n) {
  cur c, ctx, l, d, x;
  int rc;
  if (t->cm != NULL) BAD(10, "a second Certificate");
  t->cm = (uint8_t *)nqmal(n);
  if (t->cm == NULL) return nqtlfail(t, NQEMEM, 80, "out of memory");
  memcpy(t->cm, m, n);
  t->cmn = n;
  c.p = t->cm + 4;
  c.n = n - 4;
  if (!gv(&c, 1, &ctx) || !gv(&c, 3, &l) || c.n != 0) {
    BAD(50, "a malformed Certificate");
  }
  if (ctx.n != 0) BAD(47, "the server's Certificate has a request context");
  if (l.n == 0) BAD(50, "the server sent no certificate");
  t->ncrt = 0;
  while (l.n > 0) {
    if (!gv(&l, 3, &d) || d.n == 0 || !gv(&l, 2, &x)) {
      BAD(50, "a malformed CertificateEntry");
    }
    /* status_request and signed_certificate_timestamp were not offered */
    if (x.n != 0) {
      BAD(110, "a CertificateEntry extension that was not offered");
    }
    if (t->ncrt == NQTLCMAX) {
      return nqtlfail(t, NQELIM, 42, "the server sent more than 10 "
                      "certificates");
    }
    rc = nqcprs(d.p, d.n, &t->crt[t->ncrt]);
    if (rc != NQOK) {
      if (t->ncrt == 0) {
        return nqtlfail(t, rc, rc == NQENOSUP ? 43 : 42,
                        "the server's certificate does not parse");
      }
      /* an extra certificate that does not parse cannot be on the path;
       * leave it out */
      continue;
    }
    t->ncrt++;
  }
  thadd(t, t->cm, n);
  if (!t->hk.nopath) {
    int64_t now = t->hk.now != 0 ? t->hk.now : (int64_t)time(NULL);
    if ((rc = nqtlpath(t, now)) != NQOK) return rc;
  }
  return NQOK;
}

static int oncv(nqtls *t, const uint8_t *m, size_t n) {
  cur c, s;
  unsigned sch;
  uint8_t th[NQHMAX];
  int rc;
  c.p = m + 4;
  c.n = n - 4;
  if (!g16(&c, &sch) || !gv(&c, 2, &s) || c.n != 0) {
    BAD(50, "a malformed CertificateVerify");
  }
  /* a scheme offered and allowed in handshake signatures */
  if (!has16(t->off.sig, t->off.nsig, sch) ||
      (sch != 0x0403 && sch != 0x0503 && sch != 0x0804 && sch != 0x0805 &&
       sch != 0x0806)) {
    BAD(47, "a CertificateVerify scheme that was not offered");
  }
  thnow(t, th);
  if (!t->hk.nocv && (rc = nqtlcv(t, (uint16_t)sch, th, s.p, s.n)) != NQOK) {
    return rc;
  }
  t->cvs = (uint16_t)sch;
  thadd(t, m, n);
  return NQOK;
}

/* the Finished MAC of base over the transcript hash th */
static int fmac(const nqtls *t, const uint8_t *base, const uint8_t *th,
                uint8_t *out) {
  uint8_t fk[NQHMAX];
  nqmctx mc;
  int rc = nqtlexp(t->h, base, "finished", NULL, 0, fk, t->hl);
  if (rc == NQOK) rc = nqmini(&mc, t->h, fk, t->hl);
  if (rc == NQOK) {
    nqmupd(&mc, th, t->hl);
    nqmfin(&mc, out);
  }
  nqwipe(fk, sizeof fk);
  return rc;
}

static int onfin(nqtls *t, const uint8_t *m, size_t n) {
  uint8_t th[NQHMAX], v[NQHMAX], z[NQHMAX], fin[4 + NQHMAX];
  int rc, ok;
  if (n != 4 + t->hl) BAD(50, "a malformed Finished");
  thnow(t, th);
  if ((rc = fmac(t, t->shs, th, v)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  ok = nqcteq(v, m + 4, t->hl);
  if (!ok) {
    return nqtlfail(t, NQEVRFY, 51, "the server's Finished does not "
                    "verify");
  }
  thadd(t, m, n);
  thnow(t, th);
  /* master secret, application traffic secrets (7.1) */
  memset(z, 0, sizeof z);
  rc = nqtlnext(t->h, t->sec, z, t->hl, t->sec);
  if (rc == NQOK) rc = nqtlder(t->h, t->sec, "s ap traffic", th, t->rk.sec);
  if (rc == NQOK) rc = nqtlder(t->h, t->sec, "c ap traffic", th, z);
  if (rc != NQOK) return nqtlfail(t, rc, 80, "the key schedule failed");
  if ((rc = nqtlflat(t)) != NQOK) return rc;
  if ((rc = nqtlkeys(&t->rk, t->suite, t->h, t->rk.sec)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  t->st = NQTLSFIN;
  /* the client's flight: change_cipher_spec in compatibility mode
   * (appendix D.4), then under the handshake key an empty Certificate
   * if one was asked for, and Finished */
  if (t->off.sidn > 0) {
    static const uint8_t one = 1;
    if ((rc = nqtlsend(t, NQTLCCS, &one, 1)) != NQOK) return rc;
  }
  if ((rc = nqtlkeys(&t->wk, t->suite, t->h, t->chs)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  if (t->creq) {
    uint8_t cm[4 + 1 + 255 + 3];
    size_t k = 0, len = 1 + t->crctxn + 3;
    cm[k++] = NQTLCERT;
    cm[k++] = 0;
    cm[k++] = (uint8_t)(len >> 8);
    cm[k++] = (uint8_t)len;
    cm[k++] = (uint8_t)t->crctxn;
    memcpy(cm + k, t->crctx, t->crctxn);
    k += t->crctxn;
    cm[k++] = 0;
    cm[k++] = 0;
    cm[k++] = 0;
    thadd(t, cm, k);
    if ((rc = nqtlsend(t, NQTLHS, cm, k)) != NQOK) return rc;
    thnow(t, th);
  } else {
    thnow(t, th);
  }
  fin[0] = NQTLFIN;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = (uint8_t)t->hl;
  if ((rc = fmac(t, t->chs, th, fin + 4)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  thadd(t, fin, 4 + t->hl);
  if ((rc = nqtlsend(t, NQTLHS, fin, 4 + t->hl)) != NQOK) return rc;
  if ((rc = nqtlkeys(&t->wk, t->suite, t->h, z)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  nqwipe(z, sizeof z);
  nqwipe(t->chs, sizeof t->chs);
  nqwipe(t->shs, sizeof t->shs);
  t->st = NQTLUP;
  return NQOK;
}

int nqtlhand(nqtls *t) {
  const uint8_t *m;
  size_t n;
  int rc, retry = 0;
  if (t->err != 0) return t->err;
  if (t->st == NQTLUP) return NQOK;
  if (t->chn != 0) return nqtlfail(t, NQESTATE, -1, "handshake restarted");
  if ((rc = sendch(t, 1)) != NQOK) return rc;
  if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  if ((rc = onsh(t, m, n, &retry)) != NQOK) return rc;
  if (retry) {
    if ((rc = nqtlflat(t)) != NQOK || (rc = onhrr(t, m, n)) != NQOK) {
      return rc;
    }
    /* the second ClientHello goes out unprotected, so the record
     * version is 0x0303 from here on (put in rec.c reads t->hrr) */
    if ((rc = sendch(t, 2)) != NQOK) return rc;
    if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
    if ((rc = onsh(t, m, n, &retry)) != NQOK) return rc;
    if (retry) BAD(10, "a second HelloRetryRequest");
  }
  /* the ServerHello ends its record; the handshake key takes over */
  if ((rc = nqtlflat(t)) != NQOK) return rc;
  if ((rc = nqtlkeys(&t->rk, t->suite, t->h, t->shs)) != NQOK) {
    return nqtlfail(t, rc, 80, "the key schedule failed");
  }
  t->st = NQTLSHS;
  if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  if (m[0] != NQTLEE) BAD(10, "no EncryptedExtensions after the ServerHello");
  if ((rc = onee(t, m, n)) != NQOK) return rc;
  if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  if (m[0] == NQTLCR) {
    if ((rc = oncr(t, m, n)) != NQOK) return rc;
    if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  }
  if (m[0] != NQTLCERT) BAD(10, "no Certificate from the server");
  if ((rc = oncert(t, m, n)) != NQOK) return rc;
  if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  if (m[0] != NQTLCV) BAD(10, "no CertificateVerify from the server");
  if ((rc = oncv(t, m, n)) != NQOK) return rc;
  if ((rc = nqtlmsg(t, &m, &n)) != NQOK) return rc;
  if (m[0] != NQTLFIN) BAD(10, "no Finished from the server");
  return onfin(t, m, n);
}

/* ---- after the handshake ---- */

/* application_traffic_secret_N+1 and its keys */
static int upd(nqtls *t, nqtlkey *k) {
  uint8_t s[NQHMAX];
  int rc = nqtlexp(t->h, k->sec, "traffic upd", NULL, 0, s, t->hl);
  if (rc == NQOK) rc = nqtlkeys(k, t->suite, t->h, s);
  nqwipe(s, sizeof s);
  return rc == NQOK ? NQOK : nqtlfail(t, rc, 80, "the key update failed");
}

int nqtlpost(nqtls *t, const uint8_t *m, size_t n) {
  cur c, x;
  unsigned u;
  const uint8_t *p;
  int rc;
  c.p = m + 4;
  c.n = n - 4;
  if (m[0] == NQTLNST) {
    /* a ticket: checked for form, never used */
    uint32_t life;
    if (!gb(&c, 4, &p)) BAD(50, "a malformed NewSessionTicket");
    life = nqld32b(p);
    if (!gb(&c, 4, &p) || !gv(&c, 1, &x) || !gv(&c, 2, &x) || x.n == 0 ||
        !gv(&c, 2, &x) || c.n != 0) {
      BAD(50, "a malformed NewSessionTicket");
    }
    if (life > 604800) BAD(47, "a ticket lifetime over seven days");
    return NQOK;
  }
  if (m[0] == NQTLKU) {
    if (!g8(&c, &u) || c.n != 0) BAD(50, "a malformed KeyUpdate");
    if (u > 1) BAD(47, "a KeyUpdate request that is neither 0 nor 1");
    if ((rc = nqtlflat(t)) != NQOK) return rc;
    /* the next read secret (7.2), and the write one when asked */
    if ((rc = upd(t, &t->rk)) != NQOK) return rc;
    if (u == 1 && !t->sent) {
      static const uint8_t ku[5] = {NQTLKU, 0, 0, 1, 0};
      if ((rc = nqtlsend(t, NQTLHS, ku, 5)) != NQOK) return rc;
      return upd(t, &t->wk);
    }
    return NQOK;
  }
  BAD(10, "an unexpected handshake message after the handshake");
}
