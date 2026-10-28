/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RFC 3161 tokens: real ones from five public TSAs, the local OpenSSL
 * TSA's (vectors/der/gen.sh) and rmoriebricklayer 1.0.3's, verified
 * against their anchors with the signature oracle of tderh.h; the
 * failure cases; and the exhaustive mutation test of every token.
 *
 * Mutations proven harmless (and so allowed to verify):
 * - the PKIStatus of a TimeStampResp turned from 0 (granted) into 1
 *   (grantedWithMods): both grant the token, which is the same signed
 *   token either way, and nqts.status reports which;
 * - octets of a PKIFreeText statusString that leave it valid UTF-8: the
 *   text is advisory and outside the token (ts.ssl.com sends
 *   "Operation Okay").
 * - octets of an embedded alias of the trust anchor (a certificate with
 *   the anchor's subject and SubjectPublicKeyInfo, whoever issued it: a
 *   cross-certificate of a self-signed root, or a copy of the root
 *   itself) when the mutated certificate still parses strictly and is
 *   still an alias: nothing in it but its subject and key is used, and
 *   those are the configured anchor's, which is all that is trusted.
 * Everything else in a response is either signed (TSTInfo, signed
 * attributes, certificates on the path), the signature, checked against
 * a signed copy, or decides the result, so no other mutation may
 * verify. */
#include "nqt.h"
#include "tderh.h"

typedef struct {
  const char *file;   /* under vectors/der/, or bl:name */
  const char *anchor; /* likewise */
  const char *data;   /* likewise */
  nqhalg h;
  const char *nonce;  /* key in nonces.txt, or NULL */
  int sha1;           /* an ESS signingCertificate (v1): needs SHA-1 */
  int mut;            /* run the mutation test on it */
} tk;

static const tk toks[] = {
    {"local/l_rsa.tsr", "local/rsa_root.der", "local/data.txt", NQS256,
     "l_rsa", 0, 1},
    {"local/l_rsa.tok", "local/rsa_root.der", "local/data.txt", NQS256,
     "l_rsa", 0, 0},
    {"local/l_rsa384.tsr", "local/rsa_root.der", "local/data.txt", NQS384,
     "l_rsa384", 0, 0},
    {"local/l_rsa_nonce0.tsr", "local/rsa_root.der", "local/data.txt",
     NQS512, NULL, 0, 0},
    {"local/l_ec.tsr", "local/ec_root.der", "local/data.txt", NQS256,
     "l_ec", 1, 1},
    {"local/l_ec.tok", "local/ec_root.der", "local/data.txt", NQS256,
     "l_ec", 1, 0},
    {"public/r-freetsa.org-sha256.tsr", "public/anchor-freetsa.org.der",
     "public/data.txt", NQS256, "q-sha256", 1, 1},
    {"public/r-freetsa.org-sha384.tsr", "public/anchor-freetsa.org.der",
     "public/data.txt", NQS384, "q-sha384", 1, 0},
    {"public/r-freetsa.org-sha512.tsr", "public/anchor-freetsa.org.der",
     "public/data.txt", NQS512, "q-sha512", 1, 0},
    {"public/r-timestamp.digicert.com-sha256.tsr",
     "public/anchor-timestamp.digicert.com.der", "public/data.txt", NQS256,
     "q-sha256", 1, 1},
    {"public/r-timestamp.digicert.com-sha384.tsr",
     "public/anchor-timestamp.digicert.com.der", "public/data.txt", NQS384,
     "q-sha384", 1, 0},
    {"public/r-timestamp.digicert.com-sha512.tsr",
     "public/anchor-timestamp.digicert.com.der", "public/data.txt", NQS512,
     "q-sha512", 1, 0},
    {"public/r-timestamp.digicert.com-sha256.tsr",
     "public/anchor-digicert-g4.der", "public/data.txt", NQS256,
     "q-sha256", 1, 1},
    {"public/r-timestamp.digicert.com-sha384.tsr",
     "public/anchor-digicert-g4.der", "public/data.txt", NQS384,
     "q-sha384", 1, 0},
    {"public/r-timestamp.digicert.com-sha512.tsr",
     "public/anchor-digicert-g4.der", "public/data.txt", NQS512,
     "q-sha512", 1, 0},
    {"public/r-timestamp.sectigo.com-sha256.tsr",
     "public/anchor-sectigo-r46.der", "public/data.txt", NQS256,
     "q-sha256", 1, 1},
    {"public/r-ts.ssl.com-sha256.tsr", "public/anchor-ts.ssl.com.der",
     "public/data.txt", NQS256, "q-sha256", 0, 1},
    {"public/r-ssl-nonce0.tsr", "public/anchor-ts.ssl.com.der",
     "public/data.txt", NQS256, NULL, 0, 0},
    {"public/r-timestamp.sectigo.com-sha256.tsr",
     "public/anchor-timestamp.sectigo.com.der", "public/data.txt", NQS256,
     "q-sha256", 1, 1},
    {"public/r-timestamp.globalsign.com-sha256.tsr",
     "public/anchor-timestamp.globalsign.com.der", "public/data.txt",
     NQS256, "q-sha256", 0, 1},
    {"bl:rsa_token", "bl:ca", "bl:payload", NQS256, NULL, 0, 1},
    {"bl:ecdsa_token", "bl:ca", "bl:payload", NQS256, NULL, 0, 1},
};
#define NTOK (sizeof toks / sizeof toks[0])

static tdfx bl[16];
static size_t nbl;
static tdfx nonces[16];
static size_t nnon;
static int rec;

/* A fixture's bytes; *own says whether to free them. */
static tdbuf get(const char *name, int *own) {
  tdbuf b = {NULL, 0};
  char path[160];
  if (strncmp(name, "bl:", 3) == 0) {
    const tdbuf *x = tdget(bl, nbl, name + 3);
    *own = 0;
    return x == NULL ? b : *x;
  }
  *own = 1;
  snprintf(path, sizeof path, "vectors/der/%s", name);
  return tdread(path);
}

/* nonces.txt lines are name|hex or name|- */
static void loadnonces(const char *path) {
  tdbuf f = tdread(path);
  size_t i = 0;
  while (f.p != NULL && i < f.n && nnon < 16) {
    size_t j = i, bar;
    while (j < f.n && f.p[j] != '\n') {
      j++;
    }
    for (bar = i; bar < j && f.p[bar] != '|'; bar++) {
    }
    if (bar < j && bar - i < sizeof nonces[0].name && f.p[bar + 1] != '-') {
      memcpy(nonces[nnon].name, f.p + i, bar - i);
      nonces[nnon].name[bar - i] = 0;
      nonces[nnon].b.n = (j - bar - 1) / 2;
      nonces[nnon].b.p = (uint8_t *)nqmal(nonces[nnon].b.n + 1);
      if (nqunhex((const char *)f.p + bar + 1, j - bar - 1, nonces[nnon].b.p,
                  nonces[nnon].b.n, &nonces[nnon].b.n) == NQOK) {
        nnon++;
      }
    }
    i = j + 1;
  }
  tdfree(&f);
}

/* Everything a check needs for one token. */
typedef struct {
  const tk *t;
  nqcert anc;
  uint8_t dig[NQHMAX];
  const tdbuf *nonce;
  nqtsarg a;
  nqts ts;
} ctx;

static int setup(const tk *t, ctx *c, tdbuf *anc, int *aown) {
  tdbuf d;
  int down, r;
  memset(c, 0, sizeof *c);
  c->t = t;
  *anc = get(t->anchor, aown);
  if (anc->p == NULL || nqcprs(anc->p, anc->n, &c->anc) != NQOK) {
    return -1;
  }
  d = get(t->data, &down);
  if (d.p == NULL) {
    return -1;
  }
  r = nqhash(t->h, d.p, d.n, c->dig, nqhlen(t->h));
  if (down) {
    tdfree(&d);
  }
  if (r != NQOK) {
    return -1;
  }
  c->nonce = t->nonce == NULL ? NULL : tdget(nonces, nnon, t->nonce);
  c->a.halg = t->h;
  c->a.dig = c->dig;
  c->a.diglen = nqhlen(t->h);
  if (c->nonce != NULL) {
    c->a.nonce = c->nonce->p;
    c->a.noncelen = c->nonce->n;
  }
  c->a.anc = &c->anc;
  c->a.nanc = 1;
  c->a.ops = tdops(1);
  return 0;
}

static int vrfy(const uint8_t *p, size_t n, ctx *c) {
  return nqtsvrf(p, n, &c->a, &c->ts);
}

/* ---- the allowed mutations of a TimeStampResp ---- */

typedef struct {
  size_t lo[8], hi[8]; /* [lo, hi) ranges of harmless positions */
  size_t n;
} harm;

static void harmless(const uint8_t *p, size_t n, harm *h) {
  nqdtlv top, si, x;
  nqdcur c, s, f;
  h->n = 0;
  if (nqdhdr(p, n, &top) != NQOK || nqddown(&top, &c) != NQOK ||
      nqdnext(&c, &si) != NQOK || si.tag != NQDSEQ ||
      nqddown(&si, &s) != NQOK || nqdnext(&s, &x) != NQOK) {
    return; /* a bare token: nothing is harmless */
  }
  h->lo[h->n] = (size_t)(x.v.p - p);
  h->hi[h->n++] = (size_t)(x.v.p - p) + x.v.n;
  if (nqdnext(&s, &x) == NQOK && x.tag == NQDSEQ && nqddown(&x, &f) == NQOK) {
    nqdtlv u;
    while (!nqdend(&f) && nqdnext(&f, &u) == NQOK && h->n < 8) {
      h->lo[h->n] = (size_t)(u.v.p - p);
      h->hi[h->n++] = (size_t)(u.v.p - p) + u.v.n;
    }
  }
}

static int inharm(const harm *h, size_t i) {
  size_t k;
  for (k = 0; k < h->n; k++) {
    if (i >= h->lo[k] && i < h->hi[k]) {
      return 1;
    }
  }
  return 0;
}

static unsigned long nharm = 0, nbad = 0, ntried = 0, nalias = 0;

/* The embedded certificates that are aliases of the anchor: [lo, hi)
 * offsets in the token. */
static size_t aliases(const uint8_t *p, size_t n, const nqcert *anc,
                      size_t *lo, size_t *hi, size_t cap) {
  static nqts ts;
  size_t i, k = 0;
  if (nqtsprs(p, n, &ts) != NQOK) {
    return 0;
  }
  for (i = 0; i < ts.ncert && k < cap; i++) {
    nqcert c;
    if (nqcprs(ts.certs[i].p, ts.certs[i].n, &c) == NQOK &&
        nqxalias(&c, anc)) {
      lo[k] = (size_t)(ts.certs[i].p - p);
      hi[k++] = (size_t)(ts.certs[i].p - p) + ts.certs[i].n;
    }
  }
  return k;
}

/* 1 when the mutated token still carries, at [lo, hi), a certificate
 * that parses and is an alias of anc. */
static int stillalias(const uint8_t *p, size_t n, size_t lo, size_t hi,
                      const nqcert *anc) {
  nqcert c;
  return hi <= n && nqcprs(p + lo, hi - lo, &c) == NQOK &&
         nqxalias(&c, anc);
}

static void mutate(const tdbuf *b, ctx *c) {
  static uint8_t m[16384];
  harm h;
  size_t i;
  unsigned k;
  unsigned long acc = 0, ok = 0, tried = 0;
  if (b->n > sizeof m) {
    NQTCHK(b->n <= sizeof m);
    return;
  }
  size_t alo[4], ahi[4], na, q;
  unsigned long al = 0;
  memcpy(m, b->p, b->n);
  harmless(m, b->n, &h);
  na = aliases(m, b->n, &c->anc, alo, ahi, 4);
  for (i = 0; i < b->n; i++) {
    for (k = tdquick() ? 8 : 0; k <= 8; k++) {
      uint8_t x = k < 8 ? (uint8_t)(1u << k) : 0xffu;
      m[i] ^= x;
      tried++;
      if (vrfy(m, b->n, c) == NQOK) {
        int ina = 0;
        for (q = 0; q < na; q++) {
          if (i >= alo[q] && i < ahi[q] &&
              stillalias(m, b->n, alo[q], ahi[q], &c->anc)) {
            ina = 1;
          }
        }
        if (ina) {
          al++; /* inside an anchor alias, subject and key unchanged */
        } else if (inharm(&h, i)) {
          ok++;
          /* a status mutation is reported */
          if (i == h.lo[0]) {
            NQTEQI(c->ts.status, 1);
          }
        } else {
          acc++;
          fprintf(stderr, "%s: mutation at %zu (^%02x) accepted\n",
                  c->t->file, i, x);
        }
      }
      m[i] ^= x;
    }
  }
  printf("%s: %lu mutations, %lu accepted as harmless (status), %lu in "
         "an anchor alias, %lu accepted otherwise\n",
         c->t->file, tried, ok, al, acc);
  nharm += ok;
  nalias += al;
  nbad += acc;
  ntried += tried;
}

/* ---- the tokens ---- */

static void ttoken(const tk *t) {
  ctx c;
  tdbuf tb, ab;
  int town, aown, r;
  uint8_t save;
  tb = get(t->file, &town);
  NQTCHK(tb.p != NULL);
  if (tb.p == NULL || setup(t, &c, &ab, &aown) != 0) {
    NQTCHK(0);
    return;
  }
  r = vrfy(tb.p, tb.n, &c);
  if (r != NQOK) {
    fprintf(stderr, "%s: %d\n", t->file, r);
  }
  NQTEQI(r, NQOK);
  NQTCHK(c.ts.status == 0 || (c.ts.status == -1 &&
                              strstr(t->file, ".tsr") == NULL));
  NQTEQI(c.ts.ialg, t->h);
  NQTCHK(c.ts.gt > 1700000000);
  NQTCHK(c.ts.hasnonce == (t->nonce != NULL) ||
         strncmp(t->file, "bl:", 3) == 0);
  if (rec) {
    goto out;
  }
  /* SHA-1 only where an ESS signingCertificate (v1) needs it */
  c.a.ops = tdops(0);
  r = vrfy(tb.p, tb.n, &c);
  if (r != (t->sha1 ? NQENOSUP : NQOK)) {
    fprintf(stderr, "%s without SHA-1: %d\n", t->file, r);
  }
  NQTEQI(r, t->sha1 ? NQENOSUP : NQOK);
  c.a.ops = tdops(1);
  /* the data */
  c.dig[0] ^= 1;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
  c.dig[0] ^= 1;
  c.a.halg = t->h == NQS256 ? NQS512 : NQS256;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
  c.a.halg = t->h;
  c.a.diglen--;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
  c.a.diglen++;
  /* the nonce: another one, or one the token does not answer */
  if (c.nonce != NULL) {
    save = c.nonce->p[c.nonce->n - 1];
    c.nonce->p[c.nonce->n - 1] ^= 1;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
    c.nonce->p[c.nonce->n - 1] = save;
    /* leading zero octets do not change the number */
    {
      uint8_t z[80];
      memset(z, 0, 3);
      memcpy(z + 3, c.nonce->p, c.nonce->n);
      c.a.nonce = z;
      c.a.noncelen = c.nonce->n + 3;
      NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
      c.a.nonce = c.nonce->p;
      c.a.noncelen = c.nonce->n;
    }
  } else if (strncmp(t->file, "bl:", 3) != 0) {
    static const uint8_t n1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    c.a.nonce = n1;
    c.a.noncelen = 8;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
    c.a.nonce = NULL;
    c.a.noncelen = 0;
  }
  /* the policy */
  {
    nqspan pol = c.ts.policy;
    uint8_t other[64];
    c.a.pol = pol.p;
    c.a.pollen = pol.n;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
    memcpy(other, pol.p, pol.n);
    other[pol.n - 1] ^= 1;
    c.a.pol = other;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
    c.a.pol = NULL;
    c.a.pollen = 0;
  }
  /* the time the path is checked at */
  c.a.uset = 1;
  c.a.t = c.ts.gt;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
  c.a.t = c.ts.gt + (int64_t)30 * 365 * 86400;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
  c.a.t = 0;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
  c.a.uset = 0;
  /* another anchor */
  {
    nqcert other;
    int own;
    tdbuf ob = get(strncmp(t->anchor, "local/rsa", 9) == 0
                       ? "local/ec_root.der"
                       : "local/rsa_root.der",
                   &own);
    NQTEQI(nqcprs(ob.p, ob.n, &other), NQOK);
    c.a.anc = &other;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
    c.a.anc = &c.anc;
    if (own) {
      tdfree(&ob);
    }
  }
  /* arguments */
  c.a.nanc = 0;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEARG);
  c.a.nanc = 1;
  NQTEQI(vrfy(tb.p, tb.n - 1, &c), NQEDEC);
  if (t->mut) {
    mutate(&tb, &c);
  }
out:
  if (town) {
    tdfree(&tb);
  }
  if (aown) {
    tdfree(&ab);
  }
}

/* DigiCert's token carries the cross-certificate of its root G4 (issued
 * by Assured ID Root CA). Anchored at the self-signed G4, that
 * certificate is an alias of the anchor (same subject, same key) and the
 * token verifies; these are the cases around that rule. */
static uint8_t dm[16384];

static int dvrfy(const tdbuf *tb, ctx *c, size_t at, uint8_t x) {
  int r;
  memcpy(dm, tb->p, tb->n);
  dm[at] ^= x;
  r = vrfy(dm, tb->n, c);
  return r;
}

static void tdigicert(void) {
  tk t = toks[9];
  ctx c;
  tdbuf tb, ab;
  int town, aown;
  size_t i, xi = 0, ci = 0;
  nqts ts;
  nqcert x, ca1;
  t.anchor = "public/anchor-digicert-g4.der";
  tb = get(t.file, &town);
  if (setup(&t, &c, &ab, &aown) != 0 || tb.n > sizeof dm) {
    NQTCHK(0);
    return;
  }
  NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
  /* find the cross-certificate and the intermediate CA1 */
  NQTEQI(nqtsprs(tb.p, tb.n, &ts), NQOK);
  NQTEQI(ts.ncert, 3);
  memset(&x, 0, sizeof x);
  memset(&ca1, 0, sizeof ca1);
  for (i = 0; i < ts.ncert; i++) {
    nqcert y;
    NQTEQI(nqcprs(ts.certs[i].p, ts.certs[i].n, &y), NQOK);
    if (nqxalias(&y, &c.anc)) {
      xi = i;
      x = y;
    } else if (y.ca) {
      ci = i;
      ca1 = y;
    }
  }
  NQTCHK(!nqdseq(x.raw, c.anc.raw)); /* an alias, not the anchor */
  NQTCHK(nqxneq(x.issuer, x.subject) == 0);
  NQTCHK(ci != xi);
  if (x.raw.p == NULL || ca1.raw.p == NULL) {
    NQTCHK(0);
    return;
  }
  /* one byte of the alias's key (inside the modulus): no longer an
   * alias, so off the path */
  NQTEQI(dvrfy(&tb, &c, (size_t)(x.key.key.p - tb.p) + 100, 0x01),
         NQEVRFY);
  /* its subject: the last octet of the last RDN's value */
  NQTEQI(dvrfy(&tb, &c, (size_t)(x.subject.p - tb.p) + x.subject.n - 1,
               0x01),
         NQEVRFY);
  /* not strict DER: the signature's unused-bits octet */
  NQTEQI(dvrfy(&tb, &c, (size_t)(x.sig.p - tb.p) - 1, 0x01), NQEDEC);
  /* a mutated non-alias embedded certificate: CA1's signature */
  NQTEQI(dvrfy(&tb, &c, (size_t)(ca1.sig.p - tb.p) + 10, 0x01), NQEVRFY);
  /* and inside the alias outside subject and key (its signature): the
   * one harmless class */
  NQTEQI(dvrfy(&tb, &c, (size_t)(x.sig.p - tb.p) + 10, 0x01), NQOK);
  /* still refused with an unrelated anchor */
  {
    int own;
    nqcert other;
    tdbuf ob = get("local/rsa_root.der", &own);
    NQTEQI(nqcprs(ob.p, ob.n, &other), NQOK);
    c.a.anc = &other;
    NQTEQI(vrfy(tb.p, tb.n, &c), NQEVRFY);
    c.a.anc = &c.anc;
    if (own) {
      tdfree(&ob);
    }
  }
  if (town) {
    tdfree(&tb);
  }
  if (aown) {
    tdfree(&ab);
  }
}

/* A token that carries a copy of its self-signed root: a mutated copy
 * that still parses with the same subject and key is tolerated (only the
 * configured anchor is trusted; the alias class), one whose key or
 * subject changed is refused. */
static void trootcopy(void) {
  static const size_t which[] = {6, 20, 21};  /* freetsa, bl:rsa, bl:ec */
  size_t w;
  for (w = 0; w < sizeof which / sizeof which[0]; w++) {
    const tk *t = &toks[which[w]];
    ctx c;
    tdbuf tb, ab;
    int town, aown, found = 0;
    size_t i;
    nqts ts;
    tb = get(t->file, &town);
    if (setup(t, &c, &ab, &aown) != 0 || tb.n > sizeof dm) {
      NQTCHK(0);
      return;
    }
    NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
    NQTEQI(nqtsprs(tb.p, tb.n, &ts), NQOK);
    for (i = 0; i < ts.ncert; i++) {
      nqcert y;
      if (nqcprs(ts.certs[i].p, ts.certs[i].n, &y) == NQOK &&
          nqdseq(y.raw, c.anc.raw)) {
        found = 1;
        /* its signature, its serial: subject and key unchanged */
        NQTEQI(dvrfy(&tb, &c, (size_t)(y.sig.p - tb.p) + 10, 0x01), NQOK);
        NQTEQI(dvrfy(&tb, &c, (size_t)(y.serial.p - tb.p), 0x01), NQOK);
        nalias += 2;
        /* its key, its subject */
        NQTEQI(dvrfy(&tb, &c, (size_t)(y.key.key.p - tb.p) + 40, 0x01),
               NQEVRFY);
        NQTEQI(dvrfy(&tb, &c, (size_t)(y.subject.p - tb.p) + y.subject.n -
                                  1,
                     0x01),
               NQEVRFY);
      }
    }
    if (found != 1) {
      fprintf(stderr, "%s: no root copy\n", t->file);
    }
    NQTEQI(found, 1);
    if (town) {
      tdfree(&tb);
    }
    if (aown) {
      tdfree(&ab);
    }
  }
}

/* A token whose certificates are not in it: the caller supplies them. */
static void textra(void) {
  /* the bare bricklayer token with its embedded certificates moved to
   * extra is not available as such, so: the local EC token, with the
   * TSA certificate supplied twice (embedded and extra) */
  tk t = toks[4];
  ctx c;
  tdbuf tb, ab, xb;
  int town, aown, xown;
  nqcert x;
  tb = get(t.file, &town);
  if (setup(&t, &c, &ab, &aown) != 0) {
    NQTCHK(0);
    return;
  }
  xb = get("local/ec_tsa.der", &xown);
  NQTEQI(nqcprs(xb.p, xb.n, &x), NQOK);
  c.a.extra = &x;
  c.a.nextra = 1;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQOK);
  c.a.nextra = NQTSEXTRA + 1;
  NQTEQI(vrfy(tb.p, tb.n, &c), NQEARG);
  tdfree(&xb);
  tdfree(&tb);
  tdfree(&ab);
}

/* PKIStatusInfo forms, by hand */
static void tstatus(void) {
  struct {
    const char *hex;
    int want;
  } v[] = {
      {"3005" "3003020102", NQEVRFY},       /* rejection */
      {"3005" "3003020103", NQEVRFY},       /* waiting */
      {"3005" "3003020106", NQEDEC},        /* not a PKIStatus */
      {"3005" "30030201ff", NQEDEC},        /* negative */
      {"3005" "3003020100", NQEDEC},        /* granted, no token */
      {"3009" "3007020100" "03020780", NQEVRFY}, /* granted, failInfo */
      {"300b" "3009020102" "3004" "0c024f4b", NQEVRFY},
      {"300b" "3009020102" "3004" "0c02c080", NQEDEC},  /* bad UTF-8 */
      {"3007" "3005020102" "3000", NQEDEC},  /* empty PKIFreeText */
      {"3000", NQEDEC},
      {"3003" "020100", NQEDEC},
  };
  size_t i;
  for (i = 0; i < sizeof v / sizeof v[0]; i++) {
    uint8_t b[64];
    size_t n = 0;
    nqts ts;
    NQTEQI(nqunhex(v[i].hex, strlen(v[i].hex), b, sizeof b, &n), NQOK);
    NQTEQI(nqtsprs(b, n, &ts), v[i].want);
  }
  NQTEQI(nqtsprs(NULL, 0, NULL), NQEARG);
}

int main(void) {
  size_t i;
  rec = tdorinit();
  nbl = tdlines("vectors/der/bricklayer-tsp.txt", bl, 16);
  NQTEQI(nbl, 7);
  loadnonces("vectors/der/local/nonces.txt");
  loadnonces("vectors/der/public/nonces.txt");
  NQTEQI(nnon, 6);
  for (i = 0; i < NTOK; i++) {
    ttoken(&toks[i]);
  }
  if (!rec) {
    tdigicert();
    trootcopy();
    textra();
    tstatus();
    printf("ttsp: %lu mutations, %lu harmless (status) accepted, %lu "
           "anchor-alias accepted, %lu other accepted\n",
           ntried, nharm, nalias, nbad);
    NQTEQI(nbad, 0);
    printf("ttsp: %lu signature checks\n", tdcalls);
  }
#ifdef NQDCLS
  printf("%s: cls and the oracle disagreed %lu times\n", __FILE__, tddiff);
  NQTEQI(tddiff, 0);
#endif
  tdordone();
  return nqtdone("ttsp");
}
