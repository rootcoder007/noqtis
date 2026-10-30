/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * Identity cards (noqtis-idcard-1): the holder of a signing key says who
 * they are (a name and, when given, an ORCID iD, an e-mail address, a web
 * page and an affiliation), signed by that key under its own context, so
 * that a card is never taken for a seal or a key statement. The card is
 * self-signed: it shows that whoever holds the key wrote it and that it
 * is unchanged, not that the name is true; the key's fingerprint, given
 * where people already know the holder, is what ties the two.
 */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "core/json.h"

/* 1 when the n bytes of valid UTF-8 at s hold a C1 control character
 * (U+0080 to U+009F, encoded 0xc2 0x80..0x9f), which a terminal may obey
 * as it does C0 */
static int c1(const char *s, size_t n) {
  size_t i;
  for (i = 0; i + 1 < n; i++) {
    if ((unsigned char)s[i] == 0xc2 && (unsigned char)s[i + 1] >= 0x80 &&
        (unsigned char)s[i + 1] <= 0x9f)
      return 1;
  }
  return 0;
}

/* a name or an affiliation: short text (nqcinok: valid UTF-8, no C0
 * control or DEL), no C1 control, no space at either end */
static int txt(const char *s, size_t n) {
  return nqcinok(s, n) && !c1(s, n) && s[0] != ' ' && s[n - 1] != ' ';
}

/* local@domain.tld: one '@', a dot inside the domain, no space */
static int mail(const char *s, size_t n) {
  size_t i, at = n, dot = 0;
  if (n < 5 || n > NQCARDEMAIL || !nqcutf8(s, n) || c1(s, n)) return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == 0x7f) return 0;
    if (c == '@') {
      if (at != n) return 0;
      at = i;
    } else if (c == '.' && at != n) {
      dot = i;
    }
  }
  return at > 0 && at != n && dot > at + 1 && dot + 1 < n;
}

/* https:// and a host, no space */
static int web(const char *s, size_t n) {
  size_t i;
  if (n < 9 || n > NQCARDURL || memcmp(s, "https://", 8) != 0 ||
      s[8] == '/' || !nqcutf8(s, n) || c1(s, n)) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == 0x7f) return 0;
  }
  return 1;
}

/* a bare ORCID iD, 0000-0002-1825-0097: 16 digits in groups of four,
 * the last its ISO 7064 MOD 11-2 check digit (10 written X) */
int nqcorcid(const char *s, size_t n) {
  unsigned t = 0, r;
  size_t i, k = 0;
  if (s == NULL || n != 19) return 0;
  for (i = 0; i < 19; i++) {
    char c = s[i];
    if (i == 4 || i == 9 || i == 14) {
      if (c != '-') return 0;
    } else if (k < 15) {
      if (c < '0' || c > '9') return 0;
      t = (t + (unsigned)(c - '0')) * 2;
      k++;
    }
  }
  r = (12 - t % 11) % 11;
  return s[18] == (r == 10 ? 'X' : (char)('0' + r));
}

/* the ORCID iD as given (bare, or its orcid.org address, x for X) in
 * its bare form into out; 0 when it is not one */
static int orcid(const char *s, char out[20]) {
  static const char *const pre[] = {"https://orcid.org/", "http://orcid.org/",
                                    "https://www.orcid.org/",
                                    "http://www.orcid.org/"};
  size_t i, n = strlen(s);
  for (i = 0; i < sizeof pre / sizeof pre[0]; i++) {
    size_t l = strlen(pre[i]);
    if (n > l && memcmp(s, pre[i], l) == 0) {
      s += l;
      n -= l;
      break;
    }
  }
  if (n != 19) return 0;
  memcpy(out, s, 19);
  out[19] = 0;
  if (out[18] == 'x') out[18] = 'X';
  return nqcorcid(out, 19);
}

int nqcdbody(nqcbuf *b, const char *an, const char *at, const char *pkb,
             const char *name, const char *orc, const char *email,
             const char *url, const char *affil, const char *sig) {
  /* the members in RFC 8785 order; those not given are left out */
  if (affil != NULL) {
    nqcputs(b, "{\"affil\":");
    nqcjstr(b, affil, strlen(affil));
    nqcputs(b, ",\"alg\":");
  } else {
    nqcputs(b, "{\"alg\":");
  }
  nqcjstr(b, an, strlen(an));
  nqcputs(b, ",\"created\":\"");
  nqcputs(b, at);
  nqcputs(b, "\"");
  if (email != NULL) {
    nqcputs(b, ",\"email\":");
    nqcjstr(b, email, strlen(email));
  }
  nqcputs(b, ",\"format\":\"" NQCDFMT "\",\"key\":\"");
  nqcputs(b, pkb);
  nqcputs(b, "\",\"name\":");
  nqcjstr(b, name, strlen(name));
  if (orc != NULL) {
    nqcputs(b, ",\"orcid\":\"");
    nqcputs(b, orc);
    nqcputs(b, "\"");
  }
  if (sig != NULL) {
    nqcputs(b, ",\"signature\":\"");
    nqcputs(b, sig);
    nqcputs(b, "\"");
  }
  if (url != NULL) {
    nqcputs(b, ",\"url\":");
    nqcjstr(b, url, strlen(url));
  }
  nqcputs(b, "}");
  return b->err;
}

/* every text field but the ORCID iD (which orcid() reads), checked */
static int fields(const char *name, const char *email, const char *url,
                  const char *affil) {
  return name != NULL && strlen(name) <= NQCNAMEMAX &&
         txt(name, strlen(name)) &&
         (email == NULL || mail(email, strlen(email))) &&
         (url == NULL || web(url, strlen(url))) &&
         (affil == NULL ||
          (strlen(affil) <= NQCNAMEMAX && txt(affil, strlen(affil))));
}

int nqcard(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *pk,
           size_t pklen, const char *name, const char *orc,
           const char *email, const char *url, const char *affil,
           int64_t created, char *out, size_t cap, size_t *outlen) {
  nqcbuf b, o;
  nqssz sz;
  uint8_t *sg = NULL;
  char ts[21], id[20], *pkb = NULL, *sgb = NULL;
  size_t n = 0;
  int rc = NQOK;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || pk == NULL || outlen == NULL ||
      (out == NULL && cap != 0) || !fields(name, email, url, affil) ||
      (orc != NULL && !orcid(orc, id))) {
    return NQEARG;
  }
  /* cards are for post-quantum keys, as seals and statements are */
  if (alg == NQED25519 || nqssize(alg, &sz) != NQOK) return NQENOSUP;
  if (pklen != sz.pk || sklen != sz.sk || pklen > NQCARDPK) return NQEARG;
  if (nqctime(created, ts) != NQOK) return NQEARG;
  memset(&b, 0, sizeof b);
  memset(&o, 0, sizeof o);
  pkb = (char *)nqmal(nqb64n(pklen) + 1);
  sg = (uint8_t *)nqmal(sz.sig);
  sgb = (char *)nqmal(nqb64n(sz.sig) + 1);
  if (pkb == NULL || sg == NULL || sgb == NULL) {
    rc = NQEMEM;
    goto out;
  }
  nqb64e(pk, pklen, pkb);
  rc = nqcdbody(&b, nqsname(alg), ts, pkb, name, orc != NULL ? id : NULL,
                email, url, affil, NULL);
  if (rc != NQOK) goto out;
  rc = nqsign(alg, sk, sklen, (const uint8_t *)b.p, b.n,
              (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg, sz.sig, &n);
  /* a card is checked before it is given out, as a seal is */
  if (rc == NQOK)
    rc = nqvrfy(alg, pk, pklen, (const uint8_t *)b.p, b.n,
                (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg, n);
  if (rc == NQEVRFY) rc = NQEARG; /* the key pair does not match */
  if (rc != NQOK) goto out;
  nqb64e(sg, n, sgb);
  rc = nqcdbody(&o, nqsname(alg), ts, pkb, name, orc != NULL ? id : NULL,
                email, url, affil, sgb);
  if (rc != NQOK) goto out;
  *outlen = o.n;
  if (cap < o.n) {
    rc = NQEBUF;
    goto out;
  }
  memcpy(out, o.p, o.n);
out:
  nqcbfree(&b);
  nqcbfree(&o);
  if (pkb != NULL) nqfree(pkb, nqb64n(pklen) + 1);
  if (sg != NULL) nqfree(sg, sz.sig);
  if (sgb != NULL) nqfree(sgb, nqb64n(sz.sig) + 1);
  return rc;
}

/* member k of o: a string without NUL, or NULL; *n its length */
static const char *mem(const nqjs *o, const char *k, size_t *n) {
  const nqjs *v = nqjget(o, k);
  const char *s = nqjstr(v);
  *n = s != NULL ? v->len : 0;
  return s;
}

/* the field s (n bytes) into a buffer of cap bytes, "" when absent */
static void cp(char *d, size_t cap, const char *s, size_t n) {
  if (s == NULL || n >= cap) n = 0;
  if (n > 0) memcpy(d, s, n);
  d[n] = 0;
}

int nqcardvrfy(const char *card, size_t n, const uint8_t *pk, size_t pklen,
               nqcardf *f) {
  static const char *const nm[] = {"affil", "alg",   "created",
                                   "email", "format", "key",
                                   "name",  "orcid", "signature",
                                   "url"};
  nqjs *v = NULL;
  nqcbuf c, body;
  nqssz sz;
  nqsalg alg = NQMLDSA44;
  const char *an, *at, *fm, *kb, *sb, *name, *orc, *email, *url, *affil;
  size_t anl, atl, fml, kbl, sbl, namel, orcl, emaill, urll, affill, i, j,
      got = 0, req = 0;
  uint8_t *sg = NULL;
  int64_t t = 0;
  int rc;
  if (f != NULL) memset(f, 0, sizeof *f);
  if (card == NULL || f == NULL || (pk == NULL && pklen != 0)) return NQEARG;
  if (n > NQCARDMAX) return NQELIM;
  memset(&c, 0, sizeof c);
  memset(&body, 0, sizeof body);
  memset(&sz, 0, sizeof sz);
  rc = nqjparse(card, n, &v, NULL);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  /* only the card's canonical bytes are read: a card says one thing */
  rc = v->type == NQJOBJ ? nqcjval(&c, v) : NQEDEC;
  if (rc == NQOK && (c.n != n || memcmp(c.p, card, n) != 0)) rc = NQEDEC;
  if (rc != NQOK) goto out;
  for (i = 0; i < v->n; i++) {
    for (j = 0; j < sizeof nm / sizeof nm[0]; j++) {
      if (v->klen[i] == strlen(nm[j]) &&
          memcmp(v->keys[i], nm[j], v->klen[i]) == 0)
        break;
    }
    if (j == sizeof nm / sizeof nm[0]) {
      rc = NQEDEC;
      goto out;
    }
  }
  an = mem(v, "alg", &anl);
  at = mem(v, "created", &atl);
  fm = mem(v, "format", &fml);
  kb = mem(v, "key", &kbl);
  name = mem(v, "name", &namel);
  sb = mem(v, "signature", &sbl);
  orc = mem(v, "orcid", &orcl);
  email = mem(v, "email", &emaill);
  url = mem(v, "url", &urll);
  affil = mem(v, "affil", &affill);
  /* every member present is a string, and the six every card has are */
  for (j = 0; j < sizeof nm / sizeof nm[0]; j++) {
    const char *s;
    size_t l;
    if (nqjget(v, nm[j]) == NULL) continue;
    s = mem(v, nm[j], &l);
    if (s == NULL) {
      rc = NQEDEC;
      goto out;
    }
    got++;
  }
  req = (size_t)((orc != NULL) + (email != NULL) + (url != NULL) +
                 (affil != NULL));
  if (got != v->n || an == NULL || at == NULL || fm == NULL || kb == NULL ||
      name == NULL || sb == NULL || got != 6 + req ||
      strcmp(fm, NQCDFMT) != 0 || !nqctparse(at, atl, &t) ||
      !fields(name, email, url, affil) ||
      (orc != NULL && !nqcorcid(orc, orcl))) {
    rc = NQEDEC;
    goto out;
  }
  if (nqsfind(an, &alg) != NQOK || alg == NQED25519 ||
      nqssize(alg, &sz) != NQOK || sz.pk > NQCARDPK) {
    rc = NQEDEC;
    goto out;
  }
  sg = (uint8_t *)nqmal(sz.sig);
  if (sg == NULL) {
    rc = NQEMEM;
    goto out;
  }
  if (nqb64d(kb, kbl, f->pk, sizeof f->pk, &f->pklen) != NQOK ||
      f->pklen != sz.pk ||
      nqb64d(sb, sbl, sg, sz.sig, &got) != NQOK || got != sz.sig) {
    rc = NQEDEC;
    goto out;
  }
  rc = nqcdbody(&body, an, at, kb, name, orc, email, url, affil, NULL);
  if (rc != NQOK) goto out;
  rc = nqvrfy(alg, f->pk, f->pklen, (const uint8_t *)body.p, body.n,
              (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg, sz.sig);
  if (rc != NQOK) goto out;
  /* the key the caller trusts, when given, is the card's */
  if (pk != NULL &&
      (pklen != f->pklen || memcmp(pk, f->pk, pklen) != 0)) {
    rc = NQEVRFY;
    goto out;
  }
  f->alg = alg;
  nqhash(NQS256, f->pk, f->pklen, f->fp, 32);
  f->created = t;
  cp(f->utc, sizeof f->utc, at, atl);
  cp(f->name, sizeof f->name, name, namel);
  cp(f->orcid, sizeof f->orcid, orc, orcl);
  cp(f->email, sizeof f->email, email, emaill);
  cp(f->url, sizeof f->url, url, urll);
  cp(f->affil, sizeof f->affil, affil, affill);
out:
  if (rc != NQOK) memset(f, 0, sizeof *f);
  if (sg != NULL) nqfree(sg, sz.sig);
  nqcbfree(&c);
  nqcbfree(&body);
  nqjfree(v);
  return rc;
}
