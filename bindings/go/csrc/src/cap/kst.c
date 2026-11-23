/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * A key store: a folder of other people's public keys, who they say they
 * are, who else vouches for that, and how far the store's owner trusts
 * each of them to vouch.
 *
 * The folder is flat. For a key whose fingerprint (the SHA-256 of the
 * public key, 64 hex digits) is F:
 *
 *   F.pub      the key, as noqtis keygen writes one
 *              ("noqtis-key-1 <alg> pub", then base64)
 *   F.meta     {"email":"...","name":"...","trust":N}, canonical JSON
 *   F.card     its identity card (noqtis-idcard-1), when it came with one
 *   F.I.cert   a certification (noqtis-cert-1) of F by the key I
 *
 * A certification says that the holder of I has checked that key F
 * belongs to the name and address it carries. A key is valid, taken to
 * belong to its name, when the owner trusts it ultimately (their own
 * keys), or it is certified by one valid key trusted fully, or by three
 * valid keys trusted marginally; one or two marginal ones make it
 * marginally valid. Certifications are followed five levels from an
 * ultimately trusted key.
 *
 * The folder is the owner's own state: what is in it was checked when it
 * was put there (a card's and a certification's signature, a key's
 * fingerprint), and trust is whatever F.meta says. Whoever can write the
 * folder decides what it trusts.
 */
#include <stdio.h>
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "core/json.h"

#define FMT "noqtis-cert-1"
#define KEYHDR "noqtis-key-1 "
#define PUBMAX ((size_t)64 << 10)  /* F.pub */
#define METAMAX ((size_t)4 << 10)  /* F.meta */
#define CERTMAX ((size_t)64 << 10) /* one certification */
#define PKMAX 8192                 /* the largest public key (HQC-256) */
#define DEPTH 5

/* ---- names of the files ---- */

static void fname(const uint8_t fp[32], const char *ext, char out[80]) {
  nqhex(fp, 32, out);
  memcpy(out + 64, ext, strlen(ext) + 1);
}

static void cname(const uint8_t fp[32], const uint8_t ifp[32],
                  char out[144]) {
  nqhex(fp, 32, out);
  out[64] = '.';
  nqhex(ifp, 32, out + 65);
  memcpy(out + 129, ".cert", 6);
}

/* 64 lowercase hex digits at s into fp; 0 when they are not */
static int fphex(const char *s, uint8_t fp[32]) {
  size_t i, k;
  for (i = 0; i < 64; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return nqunhex(s, 64, fp, 32, &k) == NQOK && k == 32;
}

/* removes dir/name; a file that is not there is not an error */
static void drop(const char *dir, const char *name) {
  size_t dl = strlen(dir), nl = strlen(name);
  char *p = (char *)nqmal(dl + nl + 2);
  if (p == NULL) return;
  memcpy(p, dir, dl);
  p[dl] = '/';
  memcpy(p + dl + 1, name, nl + 1);
  (void)remove(p);
  nqfree(p, dl + nl + 2);
}

/* ---- F.pub ---- */

static int putpub(const char *dir, int kem, int alg, const uint8_t *pk,
                  size_t pklen, const uint8_t fp[32]) {
  const char *an = kem ? nqkname((nqkalg)alg) : nqsname((nqsalg)alg);
  nqcbuf b;
  char nm[80], line[65];
  size_t i;
  int rc;
  memset(&b, 0, sizeof b);
  nqcputs(&b, KEYHDR);
  nqcputs(&b, an);
  nqcputs(&b, " pub\n");
  for (i = 0; i < pklen; i += 48) {
    size_t k = pklen - i < 48 ? pklen - i : 48;
    nqb64e(pk + i, k, line);
    nqcput(&b, line, nqb64n(k));
    nqcputs(&b, "\n");
  }
  rc = b.err;
  if (rc == NQOK) {
    fname(fp, ".pub", nm);
    rc = nqcwrite(dir, nm, b.p, b.n);
  }
  nqcbfree(&b);
  return rc;
}

/* a key file's text (n bytes): the algorithm and the key */
static int parsepub(const char *buf, size_t n, int *kem, int *alg,
                    uint8_t *pk, size_t cap, size_t *pklen) {
  char an[64], *t = NULL;
  size_t i, o = 0, al;
  nqsalg sa;
  nqkalg ka;
  const char *sp, *nl;
  int rc;
  if (n < sizeof KEYHDR || memcmp(buf, KEYHDR, sizeof KEYHDR - 1) != 0)
    return NQEDEC;
  nl = (const char *)memchr(buf, '\n', n);
  if (nl == NULL) return NQEDEC;
  sp = buf + sizeof KEYHDR - 1;
  al = (size_t)(nl - sp);
  if (al < 5 || al - 4 >= sizeof an || memcmp(nl - 4, " pub", 4) != 0)
    return NQEDEC;
  memcpy(an, sp, al - 4);
  an[al - 4] = '\0';
  if (nqsfind(an, &sa) == NQOK) {
    *kem = 0;
    *alg = (int)sa;
  } else if (nqkfind(an, &ka) == NQOK) {
    *kem = 1;
    *alg = (int)ka;
  } else {
    return NQENOSUP;
  }
  t = (char *)nqmal(n + 1);
  if (t == NULL) return NQEMEM;
  for (i = (size_t)(nl - buf) + 1; i < n; i++) {
    if (buf[i] != '\n' && buf[i] != '\r') t[o++] = buf[i];
  }
  rc = nqb64d(t, o, pk, cap, pklen);
  if (rc != NQOK && rc != NQEBUF) rc = NQEDEC;
  nqfree(t, n + 1);
  return rc;
}

/* reads F.pub: the algorithm and the key, whose SHA-256 must be F */
static int getpub(const char *dir, const uint8_t fp[32], int *kem, int *alg,
                  uint8_t *pk, size_t cap, size_t *pklen) {
  char nm[80], *buf = NULL;
  size_t n = 0;
  uint8_t dg[32];
  int rc;
  fname(fp, ".pub", nm);
  rc = nqcread(dir, nm, PUBMAX, &buf, &n);
  if (rc != NQOK) return rc;
  rc = parsepub(buf, n, kem, alg, pk, cap, pklen);
  if (rc == NQOK) {
    /* the file is the key its name says */
    nqhash(NQS256, pk, *pklen, dg, 32);
    if (memcmp(dg, fp, 32) != 0) rc = NQEDEC;
  }
  nqfree(buf, n + 1);
  return rc;
}

/* ---- F.meta ---- */

static int putmeta(const char *dir, const uint8_t fp[32], const char *name,
                   const char *email, int trust) {
  nqcbuf b;
  char nm[80];
  int rc;
  memset(&b, 0, sizeof b);
  nqcputs(&b, "{\"email\":");
  nqcjstr(&b, email, strlen(email));
  nqcputs(&b, ",\"name\":");
  nqcjstr(&b, name, strlen(name));
  nqcputs(&b, ",\"trust\":");
  nqcjint(&b, (uint64_t)trust);
  nqcputs(&b, "}");
  rc = b.err;
  if (rc == NQOK) {
    fname(fp, ".meta", nm);
    rc = nqcwrite(dir, nm, b.p, b.n);
  }
  nqcbfree(&b);
  return rc;
}

static int getmeta(const char *dir, const uint8_t fp[32], char name[256],
                   char email[255], int *trust) {
  char nm[80], *buf = NULL;
  size_t n = 0;
  nqjs *v = NULL;
  const nqjs *jn, *je;
  const char *s, *e;
  int64_t t = -1;
  int rc;
  fname(fp, ".meta", nm);
  rc = nqcread(dir, nm, METAMAX, &buf, &n);
  if (rc != NQOK) return rc;
  rc = nqjparse(buf, n, &v, NULL);
  if (rc != NQOK) {
    rc = rc == NQEMEM ? rc : NQEDEC;
    goto out;
  }
  rc = NQEDEC;
  if (v->type != NQJOBJ || v->n != 3) goto out;
  jn = nqjget(v, "name");
  je = nqjget(v, "email");
  s = nqjstr(jn);
  e = nqjstr(je);
  if (s == NULL || e == NULL || nqjint(nqjget(v, "trust"), &t) != NQOK ||
      t < NQKTUNK || t > NQKTULT || jn->len == 0 || jn->len > 255 ||
      je->len > 254 || !nqcdok(s, je->len != 0 ? e : NULL))
    goto out;
  memcpy(name, s, jn->len + 1);
  memcpy(email, e, je->len + 1);
  *trust = (int)t;
  rc = NQOK;
out:
  nqjfree(v);
  nqfree(buf, n + 1);
  return rc;
}

/* ---- certifications ---- */

/* the signed body, or with sig the whole certification; the members in
 * RFC 8785 order */
static int body(nqcbuf *b, const char *an, const char *at, const char *email,
                const char *ifp, const char *kfp, const char *kan,
                const char *name, const char *sig) {
  nqcputs(b, "{\"alg\":");
  nqcjstr(b, an, strlen(an));
  nqcputs(b, ",\"created\":\"");
  nqcputs(b, at);
  nqcputs(b, "\",\"email\":");
  nqcjstr(b, email, strlen(email));
  nqcputs(b, ",\"format\":\"" FMT "\",\"issuer\":\"");
  nqcputs(b, ifp);
  nqcputs(b, "\",\"key\":\"");
  nqcputs(b, kfp);
  nqcputs(b, "\",\"keyalg\":");
  nqcjstr(b, kan, strlen(kan));
  nqcputs(b, ",\"name\":");
  nqcjstr(b, name, strlen(name));
  if (sig != NULL) {
    nqcputs(b, ",\"signature\":\"");
    nqcputs(b, sig);
    nqcputs(b, "\"");
  }
  nqcputs(b, "}");
  return b->err;
}

/* member k of o: a string without NUL, or NULL */
static const char *mem(const nqjs *o, const char *k, size_t *n) {
  const nqjs *v = nqjget(o, k);
  const char *s = nqjstr(v);
  *n = s != NULL ? v->len : 0;
  return s;
}

/* what a certification says, read from its canonical bytes; the
 * signature is not checked here */
typedef struct {
  nqsalg alg;
  uint8_t ifp[32], kfp[32];
  char name[256], email[255], kan[64], at[21];
  const char *sig; /* in the parsed value */
  size_t siglen;
} certf;

static int certread(const char *c, size_t n, nqjs **vp, certf *f) {
  static const char *const nm[] = {"alg",    "created", "email",
                                   "format", "issuer",  "key",
                                   "keyalg", "name",    "signature"};
  nqcbuf cb;
  nqjs *v = NULL;
  const char *an, *at, *em, *fm, *is, *ky, *ka, *na;
  size_t anl, atl, eml, fml, isl, kyl, kal, nal, j;
  int64_t t;
  int rc;
  *vp = NULL;
  if (n > CERTMAX) return NQELIM;
  memset(&cb, 0, sizeof cb);
  rc = nqjparse(c, n, &v, NULL);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  rc = v->type == NQJOBJ ? nqcjval(&cb, v) : NQEDEC;
  if (rc == NQOK && (cb.n != n || memcmp(cb.p, c, n) != 0)) rc = NQEDEC;
  nqcbfree(&cb);
  if (rc != NQOK) goto bad;
  rc = NQEDEC;
  if (v->n != sizeof nm / sizeof nm[0]) goto bad;
  for (j = 0; j < sizeof nm / sizeof nm[0]; j++) {
    size_t l;
    if (mem(v, nm[j], &l) == NULL) goto bad;
  }
  an = mem(v, "alg", &anl);
  at = mem(v, "created", &atl);
  em = mem(v, "email", &eml);
  fm = mem(v, "format", &fml);
  is = mem(v, "issuer", &isl);
  ky = mem(v, "key", &kyl);
  ka = mem(v, "keyalg", &kal);
  na = mem(v, "name", &nal);
  f->sig = mem(v, "signature", &f->siglen);
  if (strcmp(fm, FMT) != 0 || atl != 20 || !nqctparse(at, atl, &t) ||
      isl != 64 || kyl != 64 || !fphex(is, f->ifp) || !fphex(ky, f->kfp) ||
      nal == 0 || nal > 255 || eml > 254 || kal == 0 || kal >= sizeof f->kan ||
      !nqcdok(na, eml != 0 ? em : NULL) || nqsfind(an, &f->alg) != NQOK ||
      f->alg == NQED25519)
    goto bad;
  memcpy(f->name, na, nal + 1);
  memcpy(f->email, em, eml + 1);
  memcpy(f->kan, ka, kal + 1);
  memcpy(f->at, at, 21);
  *vp = v;
  return NQOK;
bad:
  nqjfree(v);
  return rc;
}

/* NQOK when the certification c verifies under the issuer's key pk */
static int certvrfy(const certf *f, const uint8_t *pk, size_t pklen) {
  nqcbuf b;
  nqssz sz;
  uint8_t *sg = NULL;
  char ih[65], kh[65];
  size_t got = 0;
  int rc;
  if (nqssize(f->alg, &sz) != NQOK) return NQEDEC;
  if (pklen != sz.pk) return NQEVRFY;
  memset(&b, 0, sizeof b);
  sg = (uint8_t *)nqmal(sz.sig);
  if (sg == NULL) return NQEMEM;
  nqhex(f->ifp, 32, ih);
  nqhex(f->kfp, 32, kh);
  if (nqb64d(f->sig, f->siglen, sg, sz.sig, &got) != NQOK || got != sz.sig) {
    rc = NQEDEC;
    goto out;
  }
  rc = body(&b, nqsname(f->alg), f->at, f->email, ih, kh, f->kan, f->name,
            NULL);
  if (rc == NQOK)
    rc = nqvrfy(f->alg, pk, pklen, (const uint8_t *)b.p, b.n,
                (const uint8_t *)FMT, strlen(FMT), 0, sg, sz.sig);
out:
  nqcbfree(&b);
  nqfree(sg, sz.sig);
  return rc;
}

/* ---- the store, read whole ---- */

typedef struct {
  uint8_t kfp[32], ifp[32];
} edge;

typedef struct {
  nqkse *e;
  size_t n, an; /* used, allocated */
  edge *c;
  size_t nc, anc;
} store;

static void sfree(store *s) {
  if (s->e != NULL) nqfree(s->e, s->an * sizeof *s->e);
  if (s->c != NULL) nqfree(s->c, s->anc * sizeof *s->c);
  memset(s, 0, sizeof *s);
}

static size_t idx(const store *s, const uint8_t fp[32]) {
  size_t i;
  for (i = 0; i < s->n; i++) {
    if (memcmp(s->e[i].fp, fp, 32) == 0) return i;
  }
  return s->n;
}

/* which of a listing's names are keys and certifications of the store:
 * 1 for F.pub, 2 for F.I.cert, 0 otherwise */
static int kind(const nqcent *e, uint8_t fp[32], uint8_t ifp[32]) {
  if (e->kind != NQCREG) return 0;
  if (e->len == 68 && memcmp(e->path + 64, ".pub", 4) == 0 &&
      fphex(e->path, fp))
    return 1;
  if (e->len == 134 && e->path[64] == '.' &&
      memcmp(e->path + 129, ".cert", 5) == 0 && fphex(e->path, fp) &&
      fphex(e->path + 65, ifp))
    return 2;
  return 0;
}

/* whether the certification of k by i still says what k's entry says:
 * a key whose name was changed loses the certifications of the old one */
static int certnow(const char *dir, const nqkse *k, const uint8_t ifp[32]) {
  char nm[144], *buf = NULL;
  size_t n = 0;
  nqjs *v = NULL;
  certf f;
  int ok = 0;
  cname(k->fp, ifp, nm);
  if (nqcread(dir, nm, CERTMAX, &buf, &n) != NQOK) return 0;
  if (certread(buf, n, &v, &f) == NQOK) {
    ok = memcmp(f.kfp, k->fp, 32) == 0 && memcmp(f.ifp, ifp, 32) == 0 &&
         strcmp(f.name, k->name) == 0 && strcmp(f.email, k->email) == 0;
    nqjfree(v);
  }
  nqfree(buf, n + 1);
  return ok;
}

/* validity, as the header of this file tells it: level by level, a
 * key vouching only once it was fully valid at the level before */
static int valid(store *s) {
  uint8_t *pv;
  size_t i, j, lvl;
  if (s->n == 0) return NQOK;
  pv = (uint8_t *)nqmal(s->n);
  if (pv == NULL) return NQEMEM;
  for (i = 0; i < s->n; i++) {
    s->e[i].valid = s->e[i].trust == NQKTULT ? NQKVFULL : NQKVNONE;
    pv[i] = s->e[i].valid == NQKVFULL;
  }
  for (lvl = 0; lvl < DEPTH; lvl++) {
    int moved = 0;
    for (i = 0; i < s->n; i++) {
      size_t full = 0, marg = 0;
      int v;
      if (s->e[i].valid == NQKVFULL) continue;
      for (j = 0; j < s->nc; j++) {
        size_t is;
        if (memcmp(s->c[j].kfp, s->e[i].fp, 32) != 0) continue;
        is = idx(s, s->c[j].ifp);
        if (is == s->n || is == i || s->e[is].kem || !pv[is]) continue;
        if (s->e[is].trust >= NQKTFULL) full++;
        if (s->e[is].trust == NQKTMARG) marg++;
      }
      v = full >= 1 || marg >= 3 ? NQKVFULL
                                 : marg >= 1 ? NQKVMARG : NQKVNONE;
      if (v > s->e[i].valid) {
        s->e[i].valid = v;
        moved = 1;
      }
    }
    for (i = 0; i < s->n; i++) pv[i] = s->e[i].valid == NQKVFULL;
    if (!moved) break;
  }
  nqfree(pv, s->n);
  return NQOK;
}

static int load(const char *dir, store *s) {
  nqclist l;
  size_t i;
  uint8_t fp[32], ifp[32], pk[PKMAX];
  int rc;
  memset(s, 0, sizeof *s);
  memset(&l, 0, sizeof l);
  rc = nqcwalk(dir, &l);
  if (rc != NQOK) goto out;
  for (i = 0; i < l.n; i++) {
    int k = kind(&l.e[i], fp, ifp);
    s->an += k == 1;
    s->anc += k == 2;
  }
  if (s->an > 0) s->e = (nqkse *)nqmal(s->an * sizeof *s->e);
  if (s->anc > 0) s->c = (edge *)nqmal(s->anc * sizeof *s->c);
  if ((s->an > 0 && s->e == NULL) || (s->anc > 0 && s->c == NULL)) {
    rc = NQEMEM;
    goto out;
  }
  if (s->an > 0) memset(s->e, 0, s->an * sizeof *s->e);
  /* the keys, in the order of their fingerprints (the walk's order) */
  for (i = 0; i < l.n; i++) {
    nqkse *e;
    char nm[80];
    if (kind(&l.e[i], fp, ifp) != 1) continue;
    e = &s->e[s->n];
    memcpy(e->fp, fp, 32);
    rc = getpub(dir, fp, &e->kem, &e->alg, pk, sizeof pk, &e->pklen);
    if (rc == NQOK) rc = getmeta(dir, fp, e->name, e->email, &e->trust);
    if (rc != NQOK) goto out;
    fname(fp, ".card", nm);
    e->card = nqchas(dir, nm);
    s->n++;
  }
  /* the certifications that still say what their key's entry says */
  for (i = 0; i < l.n; i++) {
    size_t k;
    if (kind(&l.e[i], fp, ifp) != 2) continue;
    k = idx(s, fp);
    if (k == s->n || !certnow(dir, &s->e[k], ifp)) continue;
    memcpy(s->c[s->nc].kfp, fp, 32);
    memcpy(s->c[s->nc].ifp, ifp, 32);
    s->nc++;
    s->e[k].ncert++;
  }
  rc = valid(s);
out:
  nqclfree(&l);
  if (rc != NQOK) sfree(s);
  return rc;
}

/* ---- the public functions ---- */

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; }

/* whether hay holds needle, ASCII letters of either case alike */
static int holds(const char *hay, const char *needle) {
  size_t hn = strlen(hay), nn = strlen(needle), i, j;
  if (nn > hn) return 0;
  for (i = 0; i + nn <= hn; i++) {
    for (j = 0; j < nn; j++) {
      if (lower((unsigned char)hay[i + j]) != lower((unsigned char)needle[j]))
        break;
    }
    if (j == nn) return 1;
  }
  return 0;
}

/* whether the entry answers q: the start of its fingerprint (8 hex
 * digits or more), or text in its name, its address or its algorithm's
 * name (a holder's signature key and KEM key bear one name) */
static int match(const nqkse *e, const char *q) {
  const char *an = e->kem ? nqkname((nqkalg)e->alg) : nqsname((nqsalg)e->alg);
  size_t n = strlen(q), i;
  char hx[65];
  int hex = n >= 8 && n <= 64;
  for (i = 0; hex && i < n; i++) {
    int c = lower((unsigned char)q[i]);
    hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  }
  if (hex) {
    nqhex(e->fp, 32, hx);
    for (i = 0; i < n; i++) {
      if (hx[i] != lower((unsigned char)q[i])) break;
    }
    if (i == n) return 1;
  }
  return holds(e->name, q) || holds(e->email, q) ||
         (an != NULL && holds(an, q));
}

int nqkslist(const char *dir, const char *q, nqkse *e, size_t cap,
             size_t *n) {
  store s;
  size_t i, k = 0;
  int rc;
  if (n != NULL) *n = 0;
  if (dir == NULL || n == NULL || (e == NULL && cap != 0) ||
      (q != NULL && q[0] == '\0'))
    return NQEARG;
  rc = load(dir, &s);
  if (rc != NQOK) return rc;
  for (i = 0; i < s.n; i++) {
    if (q != NULL && !match(&s.e[i], q)) continue;
    if (k < cap) e[k] = s.e[i];
    k++;
  }
  *n = k;
  sfree(&s);
  return k > cap ? NQEBUF : NQOK;
}

int nqksget(const char *dir, const uint8_t fp[32], int *kem, int *alg,
            uint8_t *pk, size_t cap, size_t *pklen) {
  int k = 0, a = 0, rc;
  if (pklen != NULL) *pklen = 0;
  if (dir == NULL || fp == NULL || pklen == NULL || (pk == NULL && cap != 0))
    return NQEARG;
  rc = getpub(dir, fp, &k, &a, pk, cap, pklen);
  if (rc != NQOK) {
    *pklen = 0;
    return rc;
  }
  if (kem != NULL) *kem = k;
  if (alg != NULL) *alg = a;
  return NQOK;
}

int nqksadd(const char *dir, int kem, int alg, const uint8_t *pk,
            size_t pklen, const char *name, const char *email,
            const char *card, size_t cardlen, uint8_t fp[32]) {
  nqcardf *f = NULL;
  nqssz sz;
  nqksz kz;
  char nm[80], on[256], oe[255];
  uint8_t d[32];
  int trust = NQKTUNK, rc;
  if (dir == NULL || pk == NULL || (card == NULL && cardlen != 0) ||
      (kem != 0 && kem != 1))
    return NQEARG;
  memset(&sz, 0, sizeof sz);
  memset(&kz, 0, sizeof kz);
  if (kem ? nqksize((nqkalg)alg, &kz) != NQOK
          : nqssize((nqsalg)alg, &sz) != NQOK)
    return NQENOSUP;
  if (pklen != (kem ? kz.pk : sz.pk) || pklen > PKMAX) return NQEARG;
  nqhash(NQS256, pk, pklen, d, 32);
  if (card != NULL) {
    /* the card names the key: who it is comes from the card alone */
    if (kem || name != NULL || email != NULL) return NQEARG;
    f = (nqcardf *)nqmal(sizeof *f);
    if (f == NULL) return NQEMEM;
    rc = nqcardvrfy(card, cardlen, pk, pklen, f);
    if (rc != NQOK || f->alg != (nqsalg)alg) {
      nqfree(f, sizeof *f);
      return rc != NQOK ? rc : NQEVRFY;
    }
    name = f->name;
    email = f->email;
  } else if (name == NULL || name[0] == '\0' || strlen(name) > 255 ||
             (email != NULL && email[0] != '\0' && strlen(email) > 254) ||
             !nqcdok(name, email != NULL && email[0] != '\0' ? email : NULL)) {
    return NQEARG;
  }
  if (email == NULL) email = "";
  /* a key that is there keeps the trust it was given */
  if (getmeta(dir, d, on, oe, &trust) != NQOK) trust = NQKTUNK;
  rc = putpub(dir, kem, alg, pk, pklen, d);
  if (rc == NQOK) rc = putmeta(dir, d, name, email, trust);
  if (rc == NQOK && card != NULL) {
    fname(d, ".card", nm);
    rc = nqcwrite(dir, nm, card, cardlen);
  }
  if (f != NULL) nqfree(f, sizeof *f);
  if (rc == NQOK && fp != NULL) memcpy(fp, d, 32);
  return rc;
}

int nqkstrust(const char *dir, const uint8_t fp[32], int level) {
  char name[256], email[255];
  int old, rc;
  if (dir == NULL || fp == NULL || level < NQKTUNK || level > NQKTULT)
    return NQEARG;
  rc = getmeta(dir, fp, name, email, &old);
  if (rc != NQOK) return rc;
  return putmeta(dir, fp, name, email, level);
}

int nqksdel(const char *dir, const uint8_t fp[32]) {
  nqclist l;
  uint8_t a[32], b[32];
  char nm[80];
  size_t i;
  int rc;
  if (dir == NULL || fp == NULL) return NQEARG;
  fname(fp, ".pub", nm);
  if (!nqchas(dir, nm)) return NQEIO;
  memset(&l, 0, sizeof l);
  rc = nqcwalk(dir, &l);
  if (rc != NQOK) {
    nqclfree(&l);
    return rc;
  }
  /* the certifications of it and by it go with it */
  for (i = 0; i < l.n; i++) {
    if (kind(&l.e[i], a, b) == 2 &&
        (memcmp(a, fp, 32) == 0 || memcmp(b, fp, 32) == 0))
      drop(dir, l.e[i].path);
  }
  nqclfree(&l);
  fname(fp, ".card", nm);
  drop(dir, nm);
  fname(fp, ".meta", nm);
  drop(dir, nm);
  fname(fp, ".pub", nm);
  drop(dir, nm);
  /* gone, or it could not be removed */
  return nqchas(dir, nm) ? NQEIO : NQOK;
}

int nqkscert(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *pk, size_t pklen, const uint8_t fp[32],
             int64_t at, char *out, size_t cap, size_t *outlen) {
  nqcbuf b, o;
  nqssz sz;
  uint8_t tpk[PKMAX], ifp[32], *sg = NULL;
  char name[256], email[255], ts[21], ih[65], kh[65], nm[144], *sgb = NULL;
  const char *kan;
  size_t tl = 0, n = 0;
  int kem = 0, ta = 0, trust = 0, rc;
  if (outlen != NULL) *outlen = 0;
  if (dir == NULL || sk == NULL || pk == NULL || fp == NULL ||
      (out == NULL && cap != 0))
    return NQEARG;
  /* certifications are by post-quantum keys, as cards and seals are */
  if (alg == NQED25519 || nqssize(alg, &sz) != NQOK) return NQENOSUP;
  if (pklen != sz.pk || !nqsxlen(alg, sklen)) return NQEARG;
  if (nqctime(at, ts) != NQOK) return NQEARG;
  rc = getpub(dir, fp, &kem, &ta, tpk, sizeof tpk, &tl);
  if (rc == NQOK) rc = getmeta(dir, fp, name, email, &trust);
  if (rc != NQOK) return rc;
  kan = kem ? nqkname((nqkalg)ta) : nqsname((nqsalg)ta);
  nqhash(NQS256, pk, pklen, ifp, 32);
  nqhex(ifp, 32, ih);
  nqhex(fp, 32, kh);
  memset(&b, 0, sizeof b);
  memset(&o, 0, sizeof o);
  sg = (uint8_t *)nqmal(sz.sig);
  sgb = (char *)nqmal(nqb64n(sz.sig) + 1);
  if (sg == NULL || sgb == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = body(&b, nqsname(alg), ts, email, ih, kh, kan, name, NULL);
  if (rc != NQOK) goto done;
  rc = nqsign(alg, sk, sklen, (const uint8_t *)b.p, b.n,
              (const uint8_t *)FMT, strlen(FMT), 0, sg, sz.sig, &n);
  /* checked before it is kept or given out */
  if (rc == NQOK)
    rc = nqvrfy(alg, pk, pklen, (const uint8_t *)b.p, b.n,
                (const uint8_t *)FMT, strlen(FMT), 0, sg, n);
  if (rc == NQEVRFY) rc = NQEARG; /* the key pair does not match */
  if (rc != NQOK) goto done;
  nqb64e(sg, n, sgb);
  rc = body(&o, nqsname(alg), ts, email, ih, kh, kan, name, sgb);
  if (rc != NQOK) goto done;
  /* the room for it first: a call that fails keeps nothing */
  if (out != NULL && cap < o.n) {
    if (outlen != NULL) *outlen = o.n;
    rc = NQEBUF;
    goto done;
  }
  cname(fp, ifp, nm);
  rc = nqcwrite(dir, nm, o.p, o.n);
  if (rc != NQOK) goto done;
  if (outlen != NULL) *outlen = o.n;
  if (out != NULL) memcpy(out, o.p, o.n);
done:
  nqcbfree(&b);
  nqcbfree(&o);
  if (sg != NULL) nqfree(sg, sz.sig);
  if (sgb != NULL) nqfree(sgb, nqb64n(sz.sig) + 1);
  return rc;
}

int nqkscput(const char *dir, const char *cert, size_t n) {
  nqjs *v = NULL;
  certf f;
  uint8_t pk[PKMAX];
  char name[256], email[255], nm[144];
  const char *kan;
  size_t pl = 0;
  int kem = 0, alg = 0, trust = 0, rc;
  if (dir == NULL || cert == NULL) return NQEARG;
  rc = certread(cert, n, &v, &f);
  if (rc != NQOK) return rc;
  /* the key it is about is here, under the name it says */
  rc = getpub(dir, f.kfp, &kem, &alg, pk, sizeof pk, &pl);
  if (rc == NQOK) rc = getmeta(dir, f.kfp, name, email, &trust);
  if (rc != NQOK) goto done;
  kan = kem ? nqkname((nqkalg)alg) : nqsname((nqsalg)alg);
  if (strcmp(kan, f.kan) != 0 || strcmp(name, f.name) != 0 ||
      strcmp(email, f.email) != 0) {
    rc = NQEVRFY;
    goto done;
  }
  /* and so is the key that made it, of the algorithm it names */
  rc = getpub(dir, f.ifp, &kem, &alg, pk, sizeof pk, &pl);
  if (rc != NQOK) goto done;
  if (kem || (nqsalg)alg != f.alg) {
    rc = NQEVRFY;
    goto done;
  }
  rc = certvrfy(&f, pk, pl);
  if (rc != NQOK) goto done;
  cname(f.kfp, f.ifp, nm);
  rc = nqcwrite(dir, nm, cert, n);
done:
  nqjfree(v);
  return rc;
}

/* ---- bundles: a key and what it vouches for as its own, to publish ---- */

#define LCARD "NOQTIS IDENTITY CARD"
#define LKEY "NOQTIS PUBLIC KEY"
#define LCERT "NOQTIS CERTIFICATION"
#define BNDMAX ((size_t)1 << 20)

static int armput(nqcbuf *b, const char *label, const char *in, size_t n) {
  size_t len = 0, got = 0;
  char *t;
  int rc = nqarmlen(label, n, &len);
  if (rc != NQOK) return rc;
  t = (char *)nqmal(len);
  if (t == NULL) return NQEMEM;
  rc = nqarmenc(label, (const uint8_t *)in, n, t, len, &got);
  if (rc == NQOK) {
    nqcput(b, t, got);
    rc = b->err;
  }
  nqfree(t, len);
  return rc;
}

int nqksurl(const char *email, char *url, size_t cap) {
  static const char pre[] = "https://", mid[] = "/.well-known/noqtis/";
  const char *at;
  char lo[255], hx[65];
  uint8_t d[32];
  size_t n, ll, dl, i, need;
  if (email == NULL || url == NULL) return NQEARG;
  n = strlen(email);
  if (n == 0 || n > 254 || !nqcdok("x", email)) return NQEARG;
  at = strchr(email, '@');
  ll = (size_t)(at - email);
  dl = n - ll - 1;
  /* the host goes into a URL: letters, digits, dots and hyphens only */
  for (i = 0; i < dl; i++) {
    int c = lower((unsigned char)at[1 + i]);
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
          c == '-'))
      return NQEARG;
  }
  for (i = 0; i < ll; i++) lo[i] = (char)lower((unsigned char)email[i]);
  nqhash(NQS256, (const uint8_t *)lo, ll, d, 32);
  nqhex(d, 20, hx);
  need = sizeof pre - 1 + dl + sizeof mid - 1 + 40 + 1;
  if (need > cap) return NQEBUF;
  memcpy(url, pre, sizeof pre - 1);
  n = sizeof pre - 1;
  for (i = 0; i < dl; i++) url[n++] = (char)lower((unsigned char)at[1 + i]);
  memcpy(url + n, mid, sizeof mid - 1);
  n += sizeof mid - 1;
  memcpy(url + n, hx, 41);
  return NQOK;
}

int nqksexp(const char *dir, const uint8_t fp[32], char *out, size_t cap,
            size_t *outlen) {
  store s;
  nqcbuf b;
  char nm[144], *buf = NULL;
  size_t n = 0, me, j;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (dir == NULL || fp == NULL || outlen == NULL ||
      (out == NULL && cap != 0))
    return NQEARG;
  memset(&b, 0, sizeof b);
  rc = load(dir, &s);
  if (rc != NQOK) return rc;
  me = idx(&s, fp);
  if (me == s.n) {
    rc = NQEIO;
    goto done;
  }
  /* a bundle starts with the card: only a key that has one is published */
  if (s.e[me].kem || !s.e[me].card) {
    rc = NQEARG;
    goto done;
  }
  fname(fp, ".card", nm);
  rc = nqcread(dir, nm, NQCARDMAX, &buf, &n);
  if (rc != NQOK) goto done;
  rc = armput(&b, LCARD, buf, n);
  nqfree(buf, n + 1);
  buf = NULL;
  /* then every other key it certified under its own name and address */
  for (j = 0; j < s.nc && rc == NQOK; j++) {
    size_t k;
    if (memcmp(s.c[j].ifp, fp, 32) != 0 || memcmp(s.c[j].kfp, fp, 32) == 0)
      continue;
    k = idx(&s, s.c[j].kfp);
    if (k == s.n || strcmp(s.e[k].name, s.e[me].name) != 0 ||
        strcmp(s.e[k].email, s.e[me].email) != 0)
      continue;
    fname(s.e[k].fp, ".pub", nm);
    rc = nqcread(dir, nm, PUBMAX, &buf, &n);
    if (rc != NQOK) break;
    rc = armput(&b, LKEY, buf, n);
    nqfree(buf, n + 1);
    buf = NULL;
    if (rc != NQOK) break;
    cname(s.e[k].fp, fp, nm);
    rc = nqcread(dir, nm, CERTMAX, &buf, &n);
    if (rc != NQOK) break;
    rc = armput(&b, LCERT, buf, n);
    nqfree(buf, n + 1);
    buf = NULL;
  }
  if (rc != NQOK) goto done;
  *outlen = b.n;
  if (cap < b.n) {
    rc = NQEBUF;
    goto done;
  }
  if (b.n > 0) memcpy(out, b.p, b.n);
done:
  nqcbfree(&b);
  sfree(&s);
  return rc;
}

/* the next armor of a bundle at *at: its label, and its bytes in a new
 * buffer of *cap bytes (nqfree); NQOK with *len, or NQEDEC. *at moves
 * past it. */
static int nextarm(const char *b, size_t n, size_t *at, char *label,
                   char **out, size_t *cap, size_t *len) {
  static const char endm[] = "\n-----END ";
  size_t i = *at, e, sl;
  int rc;
  while (i < n && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' ||
                   b[i] == '\n'))
    i++;
  /* the END line of this armor, and the end of that line */
  for (e = i; e + sizeof endm - 1 <= n; e++) {
    if (memcmp(b + e, endm, sizeof endm - 1) == 0) break;
  }
  if (e + sizeof endm - 1 > n) return NQEDEC;
  e += sizeof endm - 1;
  while (e < n && b[e] != '\n') e++;
  if (e < n) e++;
  sl = e - i;
  *out = (char *)nqmal(sl + 1);
  if (*out == NULL) return NQEMEM;
  *cap = sl + 1;
  rc = nqarmdec(b + i, sl, label, NQARMLAB, (uint8_t *)*out, sl, len);
  if (rc != NQOK) {
    nqfree(*out, *cap);
    *out = NULL;
    return rc == NQEMEM ? rc : NQEDEC;
  }
  *at = e;
  return NQOK;
}

/* whether only space follows at */
static int ended(const char *b, size_t n, size_t at) {
  for (; at < n; at++) {
    if (b[at] != ' ' && b[at] != '\t' && b[at] != '\r' && b[at] != '\n')
      return 0;
  }
  return 1;
}

static int sameci(const char *a, const char *b) {
  for (; *a != '\0' && *b != '\0'; a++, b++) {
    if (lower((unsigned char)*a) != lower((unsigned char)*b)) return 0;
  }
  return *a == *b;
}

int nqksimp(const char *dir, const char *bundle, size_t n, const char *email,
            uint8_t fp[32], size_t *nkeys) {
  nqcardf *f = NULL;
  char label[NQARMLAB], *a = NULL, *c = NULL, nm[144];
  size_t at = 0, ac = 0, al = 0, cc = 0, cl = 0, count = 0;
  uint8_t pk[PKMAX], kfp[32], cfp[32];
  int rc;
  if (nkeys != NULL) *nkeys = 0;
  if (dir == NULL || bundle == NULL) return NQEARG;
  if (n > BNDMAX) return NQELIM;
  f = (nqcardf *)nqmal(sizeof *f);
  if (f == NULL) return NQEMEM;
  /* the card first: it says whose keys these are */
  rc = nextarm(bundle, n, &at, label, &a, &ac, &al);
  if (rc != NQOK) goto done;
  if (strcmp(label, LCARD) != 0) {
    rc = NQEDEC;
    goto done;
  }
  rc = nqcardvrfy(a, al, NULL, 0, f);
  if (rc != NQOK) goto done;
  /* asked for an address: the card is that address's, or it is not
   * the answer */
  if (email != NULL && !sameci(email, f->email)) {
    rc = NQEVRFY;
    goto done;
  }
  rc = nqksadd(dir, 0, (int)f->alg, f->pk, f->pklen, NULL, NULL, a, al, cfp);
  if (rc != NQOK) goto done;
  count = 1;
  nqfree(a, ac);
  a = NULL;
  /* then pairs: a key, and the card key's certification of it under
   * the card's own name and address */
  while (!ended(bundle, n, at)) {
    nqjs *v = NULL;
    certf cf;
    size_t pl = 0;
    int kem = 0, alg = 0;
    rc = nextarm(bundle, n, &at, label, &a, &ac, &al);
    if (rc != NQOK) goto done;
    if (strcmp(label, LKEY) != 0) {
      rc = NQEDEC;
      goto done;
    }
    rc = parsepub(a, al, &kem, &alg, pk, sizeof pk, &pl);
    if (rc != NQOK) {
      if (rc == NQEBUF) rc = NQEDEC;
      goto done;
    }
    nqhash(NQS256, pk, pl, kfp, 32);
    rc = nextarm(bundle, n, &at, label, &c, &cc, &cl);
    if (rc != NQOK) goto done;
    if (strcmp(label, LCERT) != 0) {
      rc = NQEDEC;
      goto done;
    }
    rc = certread(c, cl, &v, &cf);
    if (rc != NQOK) goto done;
    if (memcmp(cf.ifp, cfp, 32) != 0 || memcmp(cf.kfp, kfp, 32) != 0 ||
        cf.alg != f->alg || strcmp(cf.name, f->name) != 0 ||
        strcmp(cf.email, f->email) != 0 ||
        strcmp(cf.kan, kem ? nqkname((nqkalg)alg) : nqsname((nqsalg)alg)) !=
            0)
      rc = NQEVRFY;
    else
      rc = certvrfy(&cf, f->pk, f->pklen);
    nqjfree(v);
    if (rc != NQOK) goto done;
    /* verified: the key goes in under the card's name, with it */
    rc = nqksadd(dir, kem, alg, pk, pl, f->name,
                 f->email[0] != '\0' ? f->email : NULL, NULL, 0, NULL);
    if (rc != NQOK) goto done;
    cname(kfp, cfp, nm);
    rc = nqcwrite(dir, nm, c, cl);
    if (rc != NQOK) goto done;
    count++;
    nqfree(a, ac);
    a = NULL;
    nqfree(c, cc);
    c = NULL;
  }
  if (fp != NULL) memcpy(fp, cfp, 32);
done:
  if (nkeys != NULL) *nkeys = count;
  if (a != NULL) nqfree(a, ac);
  if (c != NULL) nqfree(c, cc);
  nqfree(f, sizeof *f);
  return rc;
}
