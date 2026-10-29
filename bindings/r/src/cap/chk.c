/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqchk: checks a capsule against its seal and reports every check, one
 * row each. Check names (stable, for the CLI and scripts):
 *   seal.read seal.parse seal.canonical seal.fields seal.format seal.alg
 *   seal.context seal.key seal.signature
 *   manifest.read manifest.digest manifest.parse manifest.canonical
 *   manifest.fields manifest.format manifest.created manifest.order
 *   key signature timestamp folder
 *   path   (one per refused or duplicate path)
 *   file   (one per listed file: present, regular, size, both digests)
 *   extra  (one per regular file present but not listed)
 *   unsafe (one per link, reparse point, special file or refused name)
 * nqchkt also takes TSA trust anchors (DER certificates): with anchors the
 * seal must carry a timestamp that verifies under one of them; without,
 * a timestamp present is a failing row (it cannot be checked).
 * The result is NQOK only when every row passed, NQEVRFY otherwise (the
 * report is still returned); NQEARG and NQEMEM return no report. */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "der/tsp.h"

typedef struct {
  const char *chk;
  int ok;
  char *det;
  size_t dn;
} row;

struct nqrep {
  row *r;
  size_t n;
  size_t cap;
  int err;
  int bad;
};

/* adds a row whose detail is a, b and c joined (b, c may be NULL) */
static void add(nqrep *r, const char *chk, int ok, const char *a,
                const char *b, const char *c) {
  size_t al = a ? strlen(a) : 0, bl = b ? strlen(b) : 0;
  size_t cl = c ? strlen(c) : 0;
  row *w;
  if (r->err != NQOK) return;
  if (r->n == r->cap) {
    size_t nc = r->cap == 0 ? 32 : r->cap * 2;
    row *nr = (row *)nqmal(nc * sizeof(row));
    if (nr == NULL) {
      r->err = NQEMEM;
      return;
    }
    if (r->n != 0) memcpy(nr, r->r, r->n * sizeof(row));
    nqfree(r->r, r->cap * sizeof(row));
    r->r = nr;
    r->cap = nc;
  }
  w = &r->r[r->n];
  w->dn = al + bl + cl + 1;
  w->det = (char *)nqmal(w->dn);
  if (w->det == NULL) {
    r->err = NQEMEM;
    return;
  }
  if (al) memcpy(w->det, a, al);
  if (bl) memcpy(w->det + al, b, bl);
  if (cl) memcpy(w->det + al + bl, c, cl);
  w->det[al + bl + cl] = 0;
  w->chk = chk;
  w->ok = ok != 0;
  if (!ok) r->bad = 1;
  r->n++;
}

size_t nqrepn(const nqrep *r) { return r == NULL ? 0 : r->n; }

int nqrepi(const nqrep *r, size_t i, const char **check, int *ok,
           const char **detail) {
  if (r == NULL || i >= r->n) return NQEARG;
  if (check != NULL) *check = r->r[i].chk;
  if (ok != NULL) *ok = r->r[i].ok;
  if (detail != NULL) *detail = r->r[i].det;
  return NQOK;
}

void nqrepfree(nqrep *r) {
  size_t i;
  if (r == NULL) return;
  for (i = 0; i < r->n; i++) nqfree(r->r[i].det, r->r[i].dn);
  nqfree(r->r, r->cap * sizeof(row));
  nqfree(r, sizeof *r);
}

/* ---- helpers ---- */

/* a string member without NUL, or NULL */
static const char *str(const nqjs *o, const char *k, size_t *n) {
  const nqjs *v = nqjget(o, k);
  const char *s = nqjstr(v);
  if (s != NULL && n != NULL) *n = v->len;
  return s;
}

/* every key of o is one of names[0..nn); the first nreq are required */
static int keys(const nqjs *o, const char *const *names, size_t nn,
                size_t nreq) {
  size_t i, j;
  for (i = 0; i < o->n; i++) {
    for (j = 0; j < nn; j++) {
      if (o->klen[i] == strlen(names[j]) &&
          memcmp(o->keys[i], names[j], o->klen[i]) == 0) {
        break;
      }
    }
    if (j == nn) return 0;
  }
  for (j = 0; j < nreq; j++) {
    if (nqjget(o, names[j]) == NULL) return 0;
  }
  return 1;
}

/* 64 lower-case hex digits */
static int hex32(const char *s, size_t n, uint8_t out[32]) {
  size_t i, k;
  if (s == NULL || n != 64) return 0;
  for (i = 0; i < n; i++) {
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
      return 0;
    }
  }
  return nqunhex(s, n, out, 32, &k) == NQOK && k == 32;
}

/* parses buf into an object and checks it is in canonical form */
static int canon(const char *buf, size_t n, nqjs **v, int *iscanon) {
  nqcbuf c;
  int rc = nqjparse(buf, n, v, NULL);
  *iscanon = 0;
  if (rc != NQOK) return rc;
  if ((*v)->type != NQJOBJ) return NQEDEC;
  memset(&c, 0, sizeof c);
  rc = nqcjval(&c, *v);
  if (rc == NQOK) *iscanon = c.n == n && memcmp(c.p, buf, n) == 0;
  nqcbfree(&c);
  return rc == NQEMEM ? rc : NQOK;
}

/* ---- the seal ---- */

typedef struct {
  int ok;          /* every seal row passed so far */
  nqsalg alg;
  nqssz sz;
  const char *an;
  const char *ctx;
  size_t ctxlen;
  uint8_t mh[32];
  uint8_t *pk;
  size_t pkn;
  uint8_t *sig;
  size_t sign;
  const char *tsb;  /* timestamp, base64, or NULL */
  size_t tsn;
  nqjs *v;
} seal;

static void rdseal(nqrep *r, const char *dir, seal *s) {
  static const char *const nm[] = {"alg",        "context",
                                   "format",     "manifest_sha256",
                                   "public_key", "signature",
                                   "timestamp"};
  char *b = NULL;
  size_t n = 0, fl = 0, k;
  const char *f, *mh, *pk, *sg;
  size_t mhn = 0, pkl = 0, sgl = 0;
  int rc, c;
  s->ok = 0;
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &b, &n);
  if (rc == NQEMEM) {
    r->err = rc;
    return;
  }
  add(r, "seal.read", rc == NQOK, NQCSIG, rc == NQOK ? "" : ": ",
      rc == NQOK ? NULL : nqerr(rc));
  if (rc != NQOK) return;
  rc = canon(b, n, &s->v, &c);
  nqfree(b, n + 1);
  if (rc == NQEMEM) {
    r->err = rc;
    return;
  }
  add(r, "seal.parse", rc == NQOK, rc == NQOK ? "a JSON object" : "",
      rc == NQOK ? NULL : nqerr(rc), NULL);
  if (rc != NQOK) return;
  add(r, "seal.canonical", c,
      c ? "canonical JSON" : "not canonical JSON (RFC 8785)", NULL, NULL);
  f = str(s->v, "format", &fl);
  s->an = str(s->v, "alg", NULL);
  s->ctx = str(s->v, "context", &s->ctxlen);
  mh = str(s->v, "manifest_sha256", &mhn);
  pk = str(s->v, "public_key", &pkl);
  sg = str(s->v, "signature", &sgl);
  s->tsb = str(s->v, "timestamp", &s->tsn);
  rc = keys(s->v, nm, 7, 6) && f && s->an && s->ctx && mh && pk && sg &&
       (nqjget(s->v, "timestamp") == NULL || s->tsb != NULL);
  add(r, "seal.fields", rc,
      rc ? "the fields of noqtis-seal-1"
         : "missing, unknown or mistyped fields", NULL, NULL);
  if (!rc) return;
  rc = fl == strlen(NQCSFMT) && memcmp(f, NQCSFMT, fl) == 0;
  add(r, "seal.format", rc, "\"", f, "\"");
  if (!rc) return;
  rc = nqsfind(s->an, &s->alg) == NQOK && nqssize(s->alg, &s->sz) == NQOK;
  add(r, "seal.alg", rc, s->an, rc ? NULL : ": not known", NULL);
  if (!rc) return;
  rc = s->ctxlen <= 255;
  add(r, "seal.context", rc, "\"", s->ctx, "\"");
  if (!rc) return;
  s->pk = (uint8_t *)nqmal(s->sz.pk);
  s->sig = (uint8_t *)nqmal(s->sz.sig);
  if (s->pk == NULL || s->sig == NULL) {
    r->err = NQEMEM;
    return;
  }
  rc = nqb64d(pk, pkl, s->pk, s->sz.pk, &k) == NQOK && k == s->sz.pk;
  s->pkn = k;
  add(r, "seal.key", rc,
      rc ? "a public key of the right size"
         : "public_key is not base64 of the algorithm's key size",
      NULL, NULL);
  if (!rc) return;
  rc = nqb64d(sg, sgl, s->sig, s->sz.sig, &k) == NQOK && k == s->sz.sig;
  s->sign = k;
  add(r, "seal.signature", rc,
      rc ? "a signature of the right size"
         : "signature is not base64 of the algorithm's signature size",
      NULL, NULL);
  if (!rc) return;
  rc = hex32(mh, mhn, s->mh);
  if (!rc) {
    add(r, "seal.fields", 0, "manifest_sha256 is not 64 lower-case hex",
        NULL, NULL);
    return;
  }
  s->ok = 1;
}

/* ---- the timestamp ---- */

typedef struct {
  const uint8_t *const *p;
  const size_t *n;
  size_t k;
} ancs;

/* the token's imprint must be its hash of the signature; with anchors,
 * the token must verify under one of them (nqtsvrf); without, a token is
 * never accepted (fail closed) */
static void chkts(nqrep *r, const seal *s, const ancs *an) {
  uint8_t *tok = NULL;
  size_t cap = s->tsn / 4 * 3, n = 0, dl = 0, i;
  nqts *ts = NULL;
  nqcert *c = NULL;
  uint8_t d[64];
  char gt[21];
  int rc;
  if (s->tsb == NULL) {
    if (an->k != 0) {
      add(r, "timestamp", 0,
          "no timestamp in the seal, but TSA anchors were given", NULL,
          NULL);
    }
    return;
  }
  if (cap == 0) {
    add(r, "timestamp", 0, "empty timestamp", NULL, NULL);
    return;
  }
  tok = (uint8_t *)nqmal(cap);
  ts = (nqts *)nqmal(sizeof(nqts));
  if (an->k != 0) c = (nqcert *)nqmal(an->k * sizeof(nqcert));
  if (tok == NULL || ts == NULL || (an->k != 0 && c == NULL)) {
    r->err = NQEMEM;
    goto out;
  }
  rc = nqb64d(s->tsb, s->tsn, tok, cap, &n);
  if (rc == NQOK) rc = nqtsprs(tok, n, ts);
  if (rc != NQOK) {
    add(r, "timestamp", 0, "not an RFC 3161 token: ", nqerr(rc), NULL);
    goto out;
  }
  dl = nqhlen(ts->ialg);
  rc = dl != 0 && dl <= sizeof d && dl == ts->imp.n &&
       nqhash(ts->ialg, s->sig, s->sign, d, dl) == NQOK &&
       memcmp(d, ts->imp.p, dl) == 0;
  if (!rc) {
    add(r, "timestamp", 0, "the token's imprint is not the signature's",
        NULL, NULL);
    goto out;
  }
  if (an->k == 0) {
    add(r, "timestamp", 0,
        "not checked: no TSA trust anchors given (the imprint matches the "
        "signature)", NULL, NULL);
    goto out;
  }
  for (i = 0; i < an->k; i++) {
    if (nqcprs(an->p[i], an->n[i], &c[i]) != NQOK) {
      add(r, "timestamp", 0, "a TSA anchor is not a certificate", NULL,
          NULL);
      goto out;
    }
  }
  {
    nqtsarg ta;
    memset(&ta, 0, sizeof ta);
    ta.halg = ts->ialg;
    ta.dig = d;
    ta.diglen = dl;
    ta.anc = c;
    ta.nanc = an->k;
    ta.ops = nqcxops();
    rc = nqtsvrf(tok, n, &ta, ts);
  }
  if (rc == NQEMEM) {
    r->err = rc;
  } else if (rc != NQOK) {
    add(r, "timestamp", 0, "the token does not verify under the TSA "
        "anchors: ", nqerr(rc), NULL);
  } else {
    if (nqctime(ts->gt, gt) != NQOK) memcpy(gt, "out of range", 13);
    add(r, "timestamp", 1, "RFC 3161 token over the signature verifies "
        "under a TSA anchor; genTime ", gt, NULL);
  }
out:
  nqfree(tok, cap);
  nqfree(ts, sizeof(nqts));
  nqfree(c, an->k * sizeof(nqcert));
}

/* ---- the manifest, read as a stream ----
 *
 * noqtis.json is read in its canonical layout only,
 *   {"created":S,"files":[E,...],"format":S[,"meta":{...}]}
 *   E = {"path":S,"sha256":H,"sha3_256":H,"size":N}
 * one entry at a time: each is checked against the folder as it is read,
 * so memory is the manifest bytes (the signature covers them exactly),
 * the folder list and the report, never a tree of the manifest. Anything
 * else stops the scan; a small manifest is then parsed as JSON only to
 * say what is wrong (not JSON, not canonical, wrong fields). */

#define DIAGMAX ((size_t)16 << 20) /* the largest manifest diagnosed */

typedef struct {
  const char *m;
  size_t n;
  size_t i;
  const char *err; /* why the scan stopped */
} scan;

static int lit(scan *c, const char *s) {
  size_t k = strlen(s);
  if (c->n - c->i < k || memcmp(c->m + c->i, s, k) != 0) return 0;
  c->i += k;
  return 1;
}

static int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* a string in canonical form; decodes at most cap bytes into out, *len
 * is the whole decoded length */
static int cstr(scan *c, char *out, size_t cap, size_t *len) {
  size_t p = c->i, o = 0, st;
  if (p >= c->n || c->m[p] != '"') return 0;
  st = ++p;
  while (p < c->n && c->m[p] != '"') {
    unsigned char ch = (unsigned char)c->m[p], v;
    if (ch < 0x20) return 0;
    if (ch == '\\') {
      if (c->n - p < 2) return 0;
      switch (c->m[p + 1]) {
      case '"':
        v = '"';
        break;
      case '\\':
        v = '\\';
        break;
      case 'b':
        v = 8;
        break;
      case 'f':
        v = 12;
        break;
      case 'n':
        v = 10;
        break;
      case 'r':
        v = 13;
        break;
      case 't':
        v = 9;
        break;
      case 'u': {
        int a, b;
        if (c->n - p < 6 || c->m[p + 2] != '0' || c->m[p + 3] != '0') {
          return 0;
        }
        a = hexv(c->m[p + 4]);
        b = hexv(c->m[p + 5]);
        if (a < 0 || b < 0) return 0;
        v = (unsigned char)(a * 16 + b);
        if (v >= 0x20 || v == 8 || v == 9 || v == 10 || v == 12 || v == 13) {
          return 0; /* not the canonical escape */
        }
        p += 4;
        break;
      }
      default:
        return 0;
      }
      p += 2;
    } else {
      v = ch;
      p++;
    }
    if (o < cap) out[o] = (char)v;
    o++;
  }
  if (p >= c->n || !nqcutf8(c->m + st, p - st)) return 0;
  if (o < cap) out[o] = 0;
  *len = o;
  c->i = p + 1;
  return 1;
}

static int chex(scan *c, uint8_t out[32]) {
  if (c->n - c->i < 66 || c->m[c->i] != '"' || c->m[c->i + 65] != '"') {
    return 0;
  }
  if (!hex32(c->m + c->i + 1, 64, out)) return 0;
  c->i += 66;
  return 1;
}

static int cint(scan *c, uint64_t *v) {
  size_t p = c->i, k = 0;
  *v = 0;
  if (p < c->n && c->m[p] == '0') {
    c->i = p + 1;
    return 1;
  }
  while (p < c->n && c->m[p] >= '0' && c->m[p] <= '9') {
    if (++k > 16) return 0;
    *v = *v * 10 + (uint64_t)(c->m[p] - '0');
    p++;
  }
  if (k == 0 || *v > NQCMAXINT) return 0;
  c->i = p;
  return 1;
}

static int bytecmp(const char *a, size_t an, const char *b, size_t bn) {
  int c = memcmp(a, b, an < bn ? an : bn);
  if (c != 0) return c;
  return an == bn ? 0 : (an < bn ? -1 : 1);
}

static long find(const nqclist *l, const char *p, size_t n) {
  size_t lo = 0, hi = l->n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = bytecmp(l->e[mid].path, l->e[mid].len, p, n);
    if (c == 0) return (long)mid;
    if (c < 0) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return -1;
}

typedef struct {
  char raw[NQCPATHMAX + 2];
  size_t rawn;
  char norm[NQCPATHMAX + 1];
  size_t nn;
  uint64_t size;
  uint8_t s2[32];
  uint8_t s3[32];
} ent;

/* one entry, checked against the folder list l (NULL: not listed) */
static void chkent(nqrep *r, const char *dir, const nqclist *l,
                   unsigned char *seen, ent *e) {
  uint8_t s2[32], s3[32];
  uint64_t size = 0;
  long k;
  int rc;
  if (e->rawn > nqclim.path) {
    add(r, "path", 0, "a listed path is too long (path too long)", NULL,
        NULL);
    return;
  }
  rc = nqcnorm(e->raw, e->rawn, e->norm, sizeof e->norm, &e->nn);
  if (rc != NQOK) {
    add(r, "path", 0, e->raw,
        ": refused (absolute, \"..\", NUL, or a name noqtis refuses)",
        NULL);
    return;
  }
  if (e->nn != e->rawn || memcmp(e->norm, e->raw, e->nn) != 0) {
    add(r, "path", 0, e->raw, ": not in normal form; normalised: ",
        e->norm);
  }
  if (l == NULL) return;
  k = find(l, e->norm, e->nn);
  if (k < 0) {
    add(r, "file", 0, e->norm, ": missing", NULL);
    return;
  }
  if (seen[k]) {
    add(r, "path", 0, e->norm, ": listed twice", NULL);
    return;
  }
  seen[k] = 1;
  if (l->e[k].kind == NQCLNK) {
    add(r, "file", 0, e->norm, ": a symbolic link or reparse point", NULL);
    return;
  }
  if (l->e[k].kind != NQCREG) {
    add(r, "file", 0, e->norm, ": not a regular file", NULL);
    return;
  }
  rc = nqcdig(dir, e->norm, &size, s2, s3);
  if (rc == NQEMEM) {
    r->err = rc;
  } else if (rc != NQOK) {
    add(r, "file", 0, e->norm, ": unreadable: ", nqerr(rc));
  } else if (size != e->size) {
    add(r, "file", 0, e->norm, ": size differs", NULL);
  } else if (memcmp(s2, e->s2, 32) != 0) {
    add(r, "file", 0, e->norm, ": sha256 differs", NULL);
  } else if (memcmp(s3, e->s3, 32) != 0) {
    add(r, "file", 0, e->norm, ": sha3_256 differs", NULL);
  } else {
    add(r, "file", 1, e->norm, NULL, NULL);
  }
}

static int foldcmp(const void *ctx, size_t a, size_t b) {
  const nqclist *l = (const nqclist *)ctx;
  return nqcfold(l->e[a].path, l->e[a].len, l->e[b].path, l->e[b].len);
}

/* the folder entries the manifest did not list, and listed paths that
 * differ only in case */
static void chkrest(nqrep *r, const nqclist *l, const unsigned char *seen) {
  size_t *idx, i, m = 0;
  for (i = 0; i < l->n; i++) {
    if (seen[i]) continue;
    switch (l->e[i].kind) {
    case NQCREG:
      add(r, "extra", 0, l->e[i].path, ": not in the manifest", NULL);
      break;
    case NQCLNK:
      add(r, "unsafe", 0, l->e[i].path, ": a symbolic link or reparse point",
          NULL);
      break;
    case NQCODD:
      add(r, "unsafe", 0, l->e[i].path, ": not a regular file or folder",
          NULL);
      break;
    default:
      add(r, "unsafe", 0, l->e[i].path, ": a name noqtis refuses", NULL);
      break;
    }
  }
  if (l->n < 2) return;
  idx = (size_t *)nqmal(l->n * sizeof(size_t));
  if (idx == NULL) {
    r->err = NQEMEM;
    return;
  }
  for (i = 0; i < l->n; i++) {
    if (seen[i]) idx[m++] = i;
  }
  if (nqcsort(idx, m, foldcmp, l) != NQOK) {
    r->err = NQEMEM;
  } else {
    for (i = 1; i < m; i++) {
      if (foldcmp(l, idx[i - 1], idx[i]) == 0) {
        add(r, "path", 0, l->e[idx[i - 1]].path, " and ",
            l->e[idx[i]].path);
        add(r, "path", 0, "(the two paths above differ only in case)", NULL,
            NULL);
      }
    }
  }
  nqfree(idx, l->n * sizeof(size_t));
}

/* what is wrong with a manifest the scan refused, for a small one */
static void diag(nqrep *r, const char *buf, size_t n, const scan *c) {
  static const char *const nm[] = {"created", "files", "format", "meta"};
  char at[24];
  nqjs *v = NULL;
  int rc, cn = 0;
  {
    size_t i = sizeof at - 1, x = c->i;
    at[i] = 0;
    do {
      at[--i] = (char)('0' + (int)(x % 10));
      x /= 10;
    } while (x != 0 && i > 0);
    memmove(at, at + i, sizeof at - i);
  }
  if (n > DIAGMAX) {
    add(r, "manifest.parse", 0, "not in the canonical noqtis-capsule-1 "
        "layout at byte ", at, NULL);
    return;
  }
  rc = canon(buf, n, &v, &cn);
  if (rc == NQEMEM) {
    r->err = rc;
  } else if (rc != NQOK) {
    add(r, "manifest.parse", 0, "not a JSON object: ", nqerr(rc), NULL);
  } else if (!cn) {
    add(r, "manifest.parse", 1, "a JSON object", NULL, NULL);
    add(r, "manifest.canonical", 0, "not canonical JSON (RFC 8785)", NULL,
        NULL);
  } else if (!keys(v, nm, 4, 3)) {
    add(r, "manifest.parse", 1, "a JSON object", NULL, NULL);
    add(r, "manifest.fields", 0, "missing or unknown fields", NULL, NULL);
  } else {
    add(r, "manifest.parse", 1, "a JSON object", NULL, NULL);
    add(r, "manifest.fields", 0, c->err, " at byte ", at);
  }
  nqjfree(v);
}

/* what nqinsp reads from a manifest the scan accepted */
typedef struct {
  uint64_t files;
  uint64_t bytes;
  int big;          /* the sizes add up past 2^64 - 1 */
  char cr[64];      /* created */
  const char *meta; /* the canonical meta object in the manifest, or NULL */
  size_t metan;
} insp;

/* scans the manifest; with l (the folder), checks each entry as read; with
 * in, collects what nqinsp reports */
static void chkman(nqrep *r, const char *dir, const char *buf, size_t n,
                   const nqclist *l, insp *in) {
  char cr[64], fmt[64];
  size_t crn = 0, fmn = 0, cnt = 0;
  unsigned char *seen = NULL;
  ent *e = NULL, *prev = NULL;
  scan c;
  int order = 1;
  c.m = buf;
  c.n = n;
  c.i = 0;
  c.err = "not in the canonical noqtis-capsule-1 layout";
  if (l != NULL && l->n != 0) {
    seen = (unsigned char *)nqmal(l->n);
    if (seen == NULL) {
      r->err = NQEMEM;
      return;
    }
    memset(seen, 0, l->n);
  }
  e = (ent *)nqmal(sizeof(ent));
  prev = (ent *)nqmal(sizeof(ent));
  if (e == NULL || prev == NULL) {
    r->err = NQEMEM;
    goto out;
  }
  prev->rawn = (size_t)-1;
  if (!lit(&c, "{\"created\":") || !cstr(&c, cr, sizeof cr, &crn) ||
      crn >= sizeof cr || !lit(&c, ",\"files\":[")) {
    c.err = "created is not the first field, or not a short string";
    goto bad;
  }
  if (!lit(&c, "]")) {
    for (;;) {
      ent *t;
      if (!lit(&c, "{\"path\":") ||
          !cstr(&c, e->raw, sizeof e->raw, &e->rawn)) {
        c.err = "a files entry does not start with a canonical path";
        goto bad;
      }
      if (!lit(&c, ",\"sha256\":") || !chex(&c, e->s2) ||
          !lit(&c, ",\"sha3_256\":") || !chex(&c, e->s3)) {
        c.err = "a files entry has no sha256 and sha3_256 of 64 "
                "lower-case hex";
        goto bad;
      }
      if (!lit(&c, ",\"size\":") || !cint(&c, &e->size) || !lit(&c, "}")) {
        c.err = "a files entry has no size (an integer up to 2^53-1) "
                "or more fields";
        goto bad;
      }
      if (++cnt > nqclim.files) {
        add(r, "manifest.fields", 0, "too many files listed (too many "
            "files)", NULL, NULL);
        goto out;
      }
      if (order && prev->rawn != (size_t)-1 && e->rawn <= NQCPATHMAX &&
          prev->rawn <= NQCPATHMAX &&
          bytecmp(prev->raw, prev->rawn, e->raw, e->rawn) >= 0) {
        order = 0;
      }
      chkent(r, dir, l, seen, e);
      if (r->err != NQOK) goto out;
      if (in != NULL) {
        if (in->bytes > UINT64_MAX - e->size) in->big = 1;
        in->bytes += e->size;
      }
      t = prev;
      prev = e;
      e = t;
      if (lit(&c, "]")) break;
      if (!lit(&c, ",")) {
        c.err = "files entries are not separated by a comma";
        goto bad;
      }
    }
  }
  if (!lit(&c, ",\"format\":") || !cstr(&c, fmt, sizeof fmt, &fmn) ||
      fmn >= sizeof fmt) {
    c.err = "format does not follow files, or is not a short string";
    goto bad;
  }
  if (lit(&c, ",\"meta\":")) {
    size_t ms = c.i, ml;
    nqjs *v = NULL;
    int cn = 0, rc;
    if (n - ms < 2 || buf[n - 1] != '}') {
      c.err = "meta does not end the manifest";
      goto bad;
    }
    ml = n - 1 - ms;
    if (ml > NQCMETAMAX) {
      add(r, "manifest.fields", 0, "meta too large", NULL, NULL);
      goto out;
    }
    rc = canon(buf + ms, ml, &v, &cn);
    nqjfree(v);
    if (rc == NQEMEM) {
      r->err = rc;
      goto out;
    }
    if (rc != NQOK || !cn) {
      c.i = ms;
      c.err = "meta is not a canonical JSON object";
      goto bad;
    }
    if (in != NULL) {
      in->meta = buf + ms;
      in->metan = ml;
    }
  } else if (!lit(&c, "}") || c.i != n) {
    c.err = "unknown fields after format, or bytes after the manifest";
    goto bad;
  }
  add(r, "manifest.parse", 1, "a JSON object", NULL, NULL);
  add(r, "manifest.canonical", 1, "canonical JSON", NULL, NULL);
  add(r, "manifest.fields", 1, "the fields of noqtis-capsule-1", NULL, NULL);
  {
    int ok = fmn == strlen(NQCFMT) && memcmp(fmt, NQCFMT, fmn) == 0;
    add(r, "manifest.format", ok, "\"", fmt, "\"");
    ok = nqctchk(cr, crn);
    add(r, "manifest.created", ok, cr, ok ? NULL : ": not RFC 3339 UTC",
        NULL);
  }
  add(r, "manifest.order", order,
      order ? "files sorted by path, no repeats" : "files not sorted by path",
      NULL, NULL);
  if (in != NULL) {
    in->files = cnt;
    memcpy(in->cr, cr, crn + 1);
  }
  if (l != NULL) chkrest(r, l, seen);
  goto out;
bad:
  diag(r, buf, n, &c);
out:
  nqfree(e, sizeof(ent));
  nqfree(prev, sizeof(ent));
  if (seen != NULL) nqfree(seen, l->n);
}

int nqchk(const char *dir, const uint8_t *trust, size_t trustlen,
          nqrep **rep) {
  return nqchkt(dir, trust, trustlen, NULL, NULL, 0, rep);
}

int nqchkt(const char *dir, const uint8_t *trust, size_t trustlen,
           const uint8_t *const *anc, const size_t *anclen, size_t nanc,
           nqrep **rep) {
  ancs an;
  size_t i;
  nqrep *r;
  seal s;
  char *mb = NULL;
  size_t mn = 0;
  nqclist l;
  int rc, mok, lok;
  if (rep != NULL) *rep = NULL;
  if (dir == NULL || rep == NULL || (trust == NULL && trustlen != 0)) {
    return NQEARG;
  }
  if (nanc > NQCANC) return NQELIM;
  if (nanc != 0 && (anc == NULL || anclen == NULL)) return NQEARG;
  for (i = 0; i < nanc; i++) {
    if (anc[i] == NULL || anclen[i] == 0) return NQEARG;
  }
  an.p = anc;
  an.n = anclen;
  an.k = nanc;
  r = (nqrep *)nqmal(sizeof *r);
  if (r == NULL) return NQEMEM;
  memset(r, 0, sizeof *r);
  memset(&s, 0, sizeof s);
  memset(&l, 0, sizeof l);

  rdseal(r, dir, &s);

  rc = nqcread(dir, NQCMAN, nqclim.man, &mb, &mn);
  if (rc == NQEMEM) r->err = rc;
  if (rc == NQELIM) {
    add(r, "manifest.read", 0, NQCMAN, ": manifest too large", NULL);
  } else {
    add(r, "manifest.read", rc == NQOK, NQCMAN, rc == NQOK ? "" : ": ",
        rc == NQOK ? NULL : nqerr(rc));
  }
  mok = rc == NQOK;
  if (mok && s.ok) {
    uint8_t h[32];
    rc = nqhash(NQS256, (const uint8_t *)mb, mn, h, 32) == NQOK &&
         memcmp(h, s.mh, 32) == 0;
    add(r, "manifest.digest", rc,
        rc ? "SHA-256 of noqtis.json matches the seal"
           : "SHA-256 of noqtis.json differs from manifest_sha256",
        NULL, NULL);
  }

  if (s.ok) {
    const uint8_t *key = s.pk;
    size_t kn = s.pkn;
    if (trust != NULL) {
      int same = trustlen == s.pkn && memcmp(trust, s.pk, s.pkn) == 0;
      add(r, "key", same,
          same ? "the seal's key is the trusted key"
               : "the seal's key is not the trusted key", NULL, NULL);
      key = trust;
      kn = trustlen;
    } else {
      add(r, "key", 1,
          "not pinned: accepted the public key in the seal (no trusted "
          "key given)", NULL, NULL);
    }
    if (mok) {
      rc = nqvrfy(s.alg, key, kn, (const uint8_t *)mb, mn,
                  (const uint8_t *)s.ctx, s.ctxlen, 0, s.sig, s.sign);
      add(r, "signature", rc == NQOK, s.an,
          rc == NQOK ? " signature over noqtis.json is valid"
                     : " signature over noqtis.json does not verify",
          NULL);
    }
    chkts(r, &s, &an);
  }

  if (mok && r->err == NQOK) {
    rc = nqcwalk(dir, &l);
    lok = rc == NQOK;
    if (rc == NQEMEM) {
      r->err = rc;
    } else if (rc == NQELIM && nqclwhy(l.lim) != NULL) {
      add(r, "folder", 0, "cannot list: ", nqclwhy(l.lim), NULL);
    } else {
      add(r, "folder", lok, lok ? "listed" : "cannot list: ",
          lok ? NULL : nqerr(rc), NULL);
    }
    if (r->err == NQOK) chkman(r, dir, mb, mn, lok ? &l : NULL, NULL);
    nqclfree(&l);
  }

  if (mb != NULL) nqfree(mb, mn + 1);
  nqjfree(s.v);
  nqfree(s.pk, s.sz.pk);
  nqfree(s.sig, s.sz.sig);
  if (r->err != NQOK) {
    rc = r->err;
    nqrepfree(r);
    return rc;
  }
  if (r->n == 0) add(r, "seal.read", 0, "nothing checked", NULL, NULL);
  *rep = r;
  return r->bad ? NQEVRFY : NQOK;
}

/* ---- nqinsp: what a capsule says, nothing checked ---- */

static void u64s(uint64_t v, char out[24]) {
  char t[24];
  size_t i = 0, j = 0;
  do {
    t[i++] = (char)('0' + (int)(v % 10));
    v /= 10;
  } while (v != 0);
  while (i > 0) out[j++] = t[--i];
  out[j] = 0;
}

int nqinsp(const char *dir, nqrep **rep) {
  nqrep *r;
  seal s;
  insp in;
  char *mb = NULL;
  size_t mn = 0;
  int rc;
  if (rep != NULL) *rep = NULL;
  if (dir == NULL || rep == NULL) return NQEARG;
  r = (nqrep *)nqmal(sizeof *r);
  if (r == NULL) return NQEMEM;
  memset(r, 0, sizeof *r);
  memset(&s, 0, sizeof s);
  memset(&in, 0, sizeof in);
  /* the same strict readers as nqchk: the seal, then the manifest in its
   * canonical layout; no digest, signature, timestamp or file is checked */
  rdseal(r, dir, &s);
  rc = nqcread(dir, NQCMAN, nqclim.man, &mb, &mn);
  if (rc == NQEMEM) r->err = rc;
  if (rc == NQELIM) {
    add(r, "manifest.read", 0, NQCMAN, ": manifest too large", NULL);
  } else {
    add(r, "manifest.read", rc == NQOK, NQCMAN, rc == NQOK ? "" : ": ",
        rc == NQOK ? NULL : nqerr(rc));
  }
  if (rc == NQOK && r->err == NQOK) chkman(r, dir, mb, mn, NULL, &in);
  if (r->err == NQOK && !r->bad && s.ok) {
    uint8_t fp[32];
    char hx[65], num[24];
    add(r, "info.format", 1, NQCFMT, NULL, NULL);
    add(r, "info.alg", 1, s.an, NULL, NULL);
    if (nqhash(NQS256, s.pk, s.pkn, fp, 32) == NQOK) {
      nqhex(fp, 32, hx);
      add(r, "info.key", 1, hx, NULL, NULL);
    }
    add(r, "info.created", 1, in.cr, NULL, NULL);
    u64s(in.files, num);
    add(r, "info.files", 1, num, NULL, NULL);
    u64s(in.bytes, num);
    add(r, "info.bytes", 1, in.big ? "more than 18446744073709551615" : num,
        NULL, NULL);
    add(r, "info.timestamp", 1, s.tsb != NULL ? "present" : "none", NULL,
        NULL);
    if (in.meta != NULL) {
      /* canonical JSON escapes NUL, so the copy is a C string */
      char *m = (char *)nqmal(in.metan + 1);
      if (m == NULL) {
        r->err = NQEMEM;
      } else {
        memcpy(m, in.meta, in.metan);
        m[in.metan] = 0;
        add(r, "info.meta", 1, m, NULL, NULL);
        nqfree(m, in.metan + 1);
      }
    }
  }
  if (mb != NULL) nqfree(mb, mn + 1);
  nqjfree(s.v);
  nqfree(s.pk, s.sz.pk);
  nqfree(s.sig, s.sz.sig);
  if (r->err != NQOK) {
    rc = r->err;
    nqrepfree(r);
    return rc;
  }
  *rep = r;
  return r->bad ? NQEDEC : NQOK;
}
