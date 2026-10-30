/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqchk: checks a capsule against its seal and reports every check, one
 * row each. Check names (stable, for the CLI and scripts):
 *   seal.read seal.parse seal.canonical seal.fields seal.format seal.alg
 *   seal.context seal.key seal.signature
 *   manifest.read manifest.digest manifest.parse manifest.canonical
 *   manifest.fields manifest.format manifest.created manifest.order
 *   manifest.merkle   (format 2)
 *   key signature timestamp folder
 *   path   (one per refused or duplicate path)
 *   file   (one per listed file: present, regular, size, both digests)
 *   extra  (one per regular file present but not listed)
 *   unsafe (one per link, reparse point, special file or refused name)
 *   partial (nqchkx with only: which files were checked)
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

/* v in decimal */
static void u64t(uint64_t v, char out[24]) {
  char t[24];
  size_t i = sizeof t - 1, j = 0;
  t[i] = 0;
  do {
    t[--i] = (char)('0' + (int)(v % 10));
    v /= 10;
  } while (v != 0 && i > 0);
  while (t[i] != 0) out[j++] = t[i++];
  out[j] = 0;
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
  int ver;         /* 1: noqtis-seal-1, 2: noqtis-seal-2 */
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

static void rdsealb(nqrep *r, const char *b, size_t n, seal *s) {
  static const char *const n1[] = {"alg",        "context",
                                   "format",     "manifest_sha256",
                                   "public_key", "signature",
                                   "timestamp"};
  static const char *const n2[] = {"alg",        "context",
                                   "format",     "head_sha256",
                                   "public_key", "signature",
                                   "timestamp"};
  size_t fl = 0, k;
  const char *f, *mh, *pk, *sg;
  size_t mhn = 0, pkl = 0, sgl = 0;
  int rc, c;
  s->ok = 0;
  rc = canon(b, n, &s->v, &c);
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
  s->ver = f != NULL && fl == strlen(NQCSFMT2) &&
                   memcmp(f, NQCSFMT2, fl) == 0
               ? 2
               : 1;
  s->an = str(s->v, "alg", NULL);
  s->ctx = str(s->v, "context", &s->ctxlen);
  mh = str(s->v, s->ver == 2 ? "head_sha256" : "manifest_sha256", &mhn);
  pk = str(s->v, "public_key", &pkl);
  sg = str(s->v, "signature", &sgl);
  s->tsb = str(s->v, "timestamp", &s->tsn);
  rc = keys(s->v, s->ver == 2 ? n2 : n1, 7, 6) && f && s->an && s->ctx &&
       mh && pk && sg &&
       (nqjget(s->v, "timestamp") == NULL || s->tsb != NULL);
  add(r, "seal.fields", rc,
      rc ? (s->ver == 2 ? "the fields of noqtis-seal-2"
                        : "the fields of noqtis-seal-1")
         : "missing, unknown or mistyped fields", NULL, NULL);
  if (!rc) return;
  rc = s->ver == 2 || (fl == strlen(NQCSFMT) && memcmp(f, NQCSFMT, fl) == 0);
  add(r, "seal.format", rc, "\"", f, "\"");
  if (!rc) return;
  /* one row: known, and post-quantum (Ed25519 alone is not; a hybrid
   * is) */
  {
    int known =
        nqsfind(s->an, &s->alg) == NQOK && nqssize(s->alg, &s->sz) == NQOK;
    rc = known && s->alg != NQED25519;
    add(r, "seal.alg", rc, s->an,
        rc ? NULL
           : (known ? ": not post-quantum (use ML-DSA, SLH-DSA or a hybrid)"
                    : ": not known"),
        NULL);
  }
  if (!rc) return;
  /* only the capsule context of the seal's format: a signature made for
   * anything else (a plain `noqtis sign`, another protocol's context,
   * the other format) is never a seal */
  {
    const char *want = s->ver == 2 ? NQCCTX2 : NQCCTX;
    rc = s->ctxlen == strlen(want) && memcmp(s->ctx, want, s->ctxlen) == 0;
    add(r, "seal.context", rc, "\"", s->ctx,
        rc ? "\""
           : (s->ver == 2 ? "\": not the capsule context \"" NQCCTX2 "\""
                          : "\": not the capsule context \"" NQCCTX "\""));
  }
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
    add(r, "seal.fields", 0,
        s->ver == 2 ? "head_sha256 is not 64 lower-case hex"
                    : "manifest_sha256 is not 64 lower-case hex",
        NULL, NULL);
    return;
  }
  s->ok = 1;
}

static void rdseal(nqrep *r, const char *dir, seal *s) {
  char *b = NULL;
  size_t n = 0;
  int rc;
  s->ok = 0;
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &b, &n);
  if (rc == NQEMEM) {
    r->err = rc;
    return;
  }
  add(r, "seal.read", rc == NQOK, NQCSIG, rc == NQOK ? "" : ": ",
      rc == NQOK ? NULL : nqerr(rc));
  if (rc != NQOK) return;
  rdsealb(r, b, n, s);
  nqfree(b, n + 1);
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

/* where the "files" member starts (*fs) and where "format" starts (*fe)
 * in a manifest in the canonical layout; 0 when it is not */
static int head(const char *buf, size_t n, size_t *fs, size_t *fe) {
  scan c;
  char t[1];
  size_t k;
  uint8_t h[32];
  uint64_t v;
  c.m = buf;
  c.n = n;
  c.i = 0;
  c.err = NULL;
  if (!lit(&c, "{\"created\":") || !cstr(&c, t, 0, &k) || !lit(&c, ",")) {
    return 0;
  }
  *fs = c.i;
  if (!lit(&c, "\"files\":[")) return 0;
  if (!lit(&c, "]")) {
    for (;;) {
      if (!lit(&c, "{\"path\":") || !cstr(&c, t, 0, &k) ||
          !lit(&c, ",\"sha256\":") || !chex(&c, h) ||
          !lit(&c, ",\"sha3_256\":") || !chex(&c, h) ||
          !lit(&c, ",\"size\":") || !cint(&c, &v) || !lit(&c, "}")) {
        return 0;
      }
      if (lit(&c, "]")) break;
      if (!lit(&c, ",")) return 0;
    }
  }
  if (!lit(&c, ",")) return 0;
  *fe = c.i;
  return lit(&c, "\"format\":");
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
  /* the size the folder listing saw first, then the bytes, reading at
   * most one byte past the listed size (a 1 TiB sparse file in place of
   * a small one fails at once, not after hashing it all) */
  if (l->e[k].size != e->size) {
    add(r, "file", 0, e->norm, ": size differs", NULL);
    return;
  }
  rc = nqcdigx(dir, e->norm, e->size, &size, s2, s3, NULL);
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
/* the members after "format" of a format 2 manifest: inputs, merkle (the
 * root must be of the leaves lv[0..cnt)), meta */
static void tail2(nqrep *r, const char *buf, size_t n, size_t at,
                  const uint8_t *lv, size_t cnt, insp *in) {
  static const char *const nm[] = {"merkle", "inputs", "meta"};
  nqcbuf o;
  nqjs *v = NULL;
  const nqjs *mk, *ins, *mt;
  uint8_t root[32], want[32];
  int64_t lvs = -1;
  int rc, cn = 0, ok;
  size_t i;
  memset(&o, 0, sizeof o);
  /* buf[at] is the comma after format; the rest, braced, is an object */
  if (at >= n || buf[at] != ',' || buf[n - 1] != '}') {
    add(r, "manifest.fields", 0, "no merkle member (noqtis-capsule-2)",
        NULL, NULL);
    return;
  }
  nqcput(&o, "{", 1);
  nqcput(&o, buf + at + 1, n - at - 1);
  if (o.err != NQOK) {
    r->err = o.err;
    nqcbfree(&o);
    return;
  }
  rc = canon(o.p, o.n, &v, &cn);
  if (rc == NQEMEM) {
    r->err = rc;
    goto out;
  }
  if (rc != NQOK || !cn || !keys(v, nm, 3, 1)) {
    add(r, "manifest.fields", 0, "the members after format are not "
        "merkle, inputs and meta in canonical form", NULL, NULL);
    goto out;
  }
  mk = nqjget(v, "merkle");
  ins = nqjget(v, "inputs");
  mt = nqjget(v, "meta");
  {
    static const char *const mn[] = {"alg", "leaves", "root"};
    const char *a = mk->type == NQJOBJ ? str(mk, "alg", NULL) : NULL;
    size_t rl = 0;
    const char *rs = mk->type == NQJOBJ ? str(mk, "root", &rl) : NULL;
    ok = mk->type == NQJOBJ && keys(mk, mn, 3, 3) && a != NULL &&
         strcmp(a, "sha256") == 0 &&
         nqjint(nqjget(mk, "leaves"), &lvs) == NQOK && hex32(rs, rl, want);
  }
  if (!ok) {
    add(r, "manifest.fields", 0, "merkle is not {alg: \"sha256\", leaves, "
        "root}", NULL, NULL);
    goto out;
  }
  ok = ins == NULL || (ins->type == NQJARR && ins->n >= 1 &&
                       ins->n <= NQCINMAX);
  for (i = 0; ok && ins != NULL && i < ins->n; i++) {
    static const char *const inm[] = {"capsule", "name"};
    const nqjs *e = nqjat(ins, i);
    size_t hl = 0, nl = 0;
    const char *h = e->type == NQJOBJ ? str(e, "capsule", &hl) : NULL;
    const char *nn = e->type == NQJOBJ ? str(e, "name", &nl) : NULL;
    uint8_t id[32];
    ok = e->type == NQJOBJ && keys(e, inm, 2, 2) && hex32(h, hl, id) &&
         nqcinok(nn, nl);
  }
  if (!ok) {
    add(r, "manifest.fields", 0, "inputs is not 1 to 1024 {capsule, name}",
        NULL, NULL);
    goto out;
  }
  if (mt != NULL) {
    nqcbuf q;
    memset(&q, 0, sizeof q);
    ok = mt->type == NQJOBJ && nqcjval(&q, mt) == NQOK &&
         q.n <= NQCMETAMAX;
    nqcbfree(&q);
    if (!ok) {
      add(r, "manifest.fields", 0, "meta is not a JSON object of at most "
          "1 MiB", NULL, NULL);
      goto out;
    }
    if (in != NULL) {
      /* meta is last: its canonical bytes end the manifest */
      size_t ml = q.n;
      in->meta = buf + n - 1 - ml;
      in->metan = ml;
    }
  }
  add(r, "manifest.parse", 1, "a JSON object", NULL, NULL);
  add(r, "manifest.canonical", 1, "canonical JSON", NULL, NULL);
  add(r, "manifest.fields", 1, "the fields of noqtis-capsule-2", NULL,
      NULL);
  nqcmroot(lv, cnt, root);
  ok = lvs >= 0 && (uint64_t)lvs == (uint64_t)cnt &&
       memcmp(root, want, 32) == 0;
  add(r, "manifest.merkle", ok,
      ok ? "the Merkle root is of the entries listed"
         : "the Merkle root or leaf count is not of the entries listed",
      NULL, NULL);
out:
  nqjfree(v);
  nqcbfree(&o);
}

/* a partial check: only these paths (normalised), hit[i] set when listed */
typedef struct {
  const char *const *p;
  size_t n;
  unsigned char *hit;
} flt;

/* the index of e's path in f, or -1 */
static long fltat(const flt *f, const ent *e) {
  size_t i;
  for (i = 0; i < f->n; i++) {
    if (strlen(f->p[i]) == e->rawn && memcmp(f->p[i], e->raw, e->rawn) == 0) {
      return (long)i;
    }
  }
  return -1;
}

/* the rows a partial check ends with: paths not listed, and what was not
 * checked */
static void fltend(nqrep *r, const flt *f, size_t cnt) {
  size_t i, k = 0;
  char a[24], b[24];
  for (i = 0; i < f->n; i++) {
    if (f->hit[i]) {
      k++;
    } else {
      add(r, "file", 0, f->p[i], ": not in the manifest", NULL);
    }
  }
  u64t(k, a);
  u64t(cnt, b);
  add(r, "partial", 1, a, " of ", b);
  add(r, "partial", 1, "only the files given were checked: the other listed "
      "files, and files present but not listed, were not", NULL, NULL);
}

static void chkman(nqrep *r, const char *dir, const char *buf, size_t n,
                   const nqclist *l, insp *in, int ver, const flt *f) {
  char cr[64], fmt[64];
  size_t crn = 0, fmn = 0, cnt = 0, lvc = 0, es = 0;
  uint8_t *lv = NULL;
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
      es = c.i;
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
      if (ver == 2) {
        if (cnt == lvc) {
          size_t nc = lvc == 0 ? 64 : lvc * 2;
          uint8_t *nb = (uint8_t *)nqmal(nc * 32);
          if (nb == NULL) {
            r->err = NQEMEM;
            goto out;
          }
          if (lv != NULL) {
            memcpy(nb, lv, cnt * 32);
            nqfree(lv, lvc * 32);
          }
          lv = nb;
          lvc = nc;
        }
        nqcmleaf(buf + es, c.i - es, lv + 32 * cnt);
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
      if (f == NULL) {
        chkent(r, dir, l, seen, e);
      } else {
        long fi = fltat(f, e);
        if (fi >= 0 && !f->hit[fi]) {
          f->hit[fi] = 1;
          chkent(r, dir, l, seen, e);
        }
      }
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
  if (ver == 2) {
    int ok = fmn == strlen(NQCFMT2) && memcmp(fmt, NQCFMT2, fmn) == 0;
    size_t r0 = r->n;
    tail2(r, buf, n, c.i, lv, cnt, in);
    if (r->err != NQOK) goto out;
    if (r->n == r0 + 1) goto out; /* tail2 refused the members */
    add(r, "manifest.format", ok, "\"", fmt, "\"");
    ok = nqctchk(cr, crn);
    add(r, "manifest.created", ok, cr, ok ? NULL : ": not RFC 3339 UTC",
        NULL);
    add(r, "manifest.order", order,
        order ? "files sorted by path, no repeats"
              : "files not sorted by path",
        NULL, NULL);
    if (in != NULL) {
      in->files = cnt;
      memcpy(in->cr, cr, crn + 1);
    }
    if (f != NULL) {
      fltend(r, f, cnt);
    } else if (l != NULL) {
      chkrest(r, l, seen);
    }
    goto out;
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
  if (f != NULL) {
    fltend(r, f, cnt);
  } else if (l != NULL) {
    chkrest(r, l, seen);
  }
  goto out;
bad:
  diag(r, buf, n, &c);
out:
  nqfree(e, sizeof(ent));
  nqfree(prev, sizeof(ent));
  if (lv != NULL) nqfree(lv, lvc * 32);
  if (seen != NULL) nqfree(seen, l->n);
}

int nqchk(const char *dir, const uint8_t *trust, size_t trustlen,
          nqrep **rep) {
  return nqchkt(dir, trust, trustlen, NULL, NULL, 0, rep);
}

static int chk1(const char *dir, const nqcopt *o, int depth, nqrep **rep);

/* the first failing row of a report, for a one-line summary */
static void firstbad(const nqrep *r, char *out, size_t cap) {
  size_t i;
  for (i = 0; i < r->n; i++) {
    if (!r->r[i].ok) {
      size_t a = strlen(r->r[i].chk), b = r->r[i].dn;
      if (a + 2 + b + 1 > cap) b = cap > a + 3 ? cap - a - 3 : 0;
      if (a + 3 > cap) {
        out[0] = 0;
        return;
      }
      memcpy(out, r->r[i].chk, a);
      out[a] = ':';
      out[a + 1] = ' ';
      memcpy(out + a + 2, r->r[i].det, b);
      out[a + 2 + b] = 0;
      return;
    }
  }
  out[0] = 0;
}

/* each input of the format 2 manifest buf: found among o->lin by its id,
 * then checked the same way (its own inputs too, to NQCDEPTH levels) */
static void lineage(nqrep *r, const char *buf, size_t n, const nqcopt *o,
                    int depth) {
  size_t fs = 0, fe = 0, i, j;
  nqcbuf h;
  nqjs *v = NULL;
  const nqjs *ins;
  int cn = 0, rc;
  uint8_t *ids = NULL;
  memset(&h, 0, sizeof h);
  if (!head(buf, n, &fs, &fe)) return;
  nqcput(&h, buf, fs);
  nqcput(&h, buf + fe, n - fe);
  if (h.err != NQOK) {
    r->err = h.err;
    goto out;
  }
  rc = canon(h.p, h.n, &v, &cn);
  if (rc == NQEMEM) r->err = rc;
  if (rc != NQOK) goto out;
  ins = nqjget(v, "inputs");
  if (ins == NULL || ins->type != NQJARR) {
    add(r, "lineage", 1, "no inputs listed", NULL, NULL);
    goto out;
  }
  if (depth >= NQCDEPTH) {
    add(r, "lineage", 0, "inputs nested more than 64 levels deep", NULL,
        NULL);
    goto out;
  }
  /* the ids of the folders given, once */
  ids = (uint8_t *)nqmal(o->nlin * 33);
  if (ids == NULL) {
    r->err = NQEMEM;
    goto out;
  }
  for (j = 0; j < o->nlin; j++) {
    ids[33 * j + 32] = nqcapid(o->lin[j], ids + 33 * j) == NQOK;
  }
  for (i = 0; i < ins->n; i++) {
    const nqjs *e = nqjat(ins, i);
    size_t hl = 0, nl = 0;
    const char *hx = str(e, "capsule", &hl), *nm = str(e, "name", &nl);
    uint8_t id[32];
    if (!hex32(hx, hl, id) || nm == NULL) continue; /* refused earlier */
    for (j = 0; j < o->nlin; j++) {
      if (ids[33 * j + 32] && memcmp(ids + 33 * j, id, 32) == 0) break;
    }
    if (j == o->nlin) {
      add(r, "lineage", 0, nm, ": not found in the folders given; its id "
          "is ", hx);
      continue;
    }
    {
      nqcopt so;
      nqrep *sr = NULL;
      char why[300];
      /* the input's own seal decides its key: nothing is pinned */
      so = *o;
      so.trust = NULL;
      so.trustlen = 0;
      so.only = NULL;
      so.nonly = 0;
      rc = chk1(o->lin[j], &so, depth + 1, &sr);
      if (rc == NQEMEM) {
        r->err = rc;
        nqrepfree(sr);
        goto out;
      }
      if (rc == NQOK) {
        add(r, "lineage", 1, nm, ": checks, in ", o->lin[j]);
      } else {
        firstbad(sr, why, sizeof why);
        add(r, "lineage", 0, nm, ": does not check: ", why);
      }
      nqrepfree(sr);
    }
  }
out:
  if (ids != NULL) nqfree(ids, o->nlin * 33);
  nqjfree(v);
  nqcbfree(&h);
}

int nqchkt(const char *dir, const uint8_t *trust, size_t trustlen,
           const uint8_t *const *anc, const size_t *anclen, size_t nanc,
           nqrep **rep) {
  nqcopt o;
  memset(&o, 0, sizeof o);
  o.trust = trust;
  o.trustlen = trustlen;
  o.anc = anc;
  o.anclen = anclen;
  o.nanc = nanc;
  return nqchkx(dir, &o, rep);
}

int nqchkx(const char *dir, const nqcopt *o, nqrep **rep) {
  static const nqcopt none;
  if (rep != NULL) *rep = NULL;
  if (o == NULL) o = &none;
  /* key statements are not read yet: refuse rather than ignore them */
  if (o->nstmt != 0) return NQENOSUP;
  return chk1(dir, o, 0, rep);
}

static int chk1(const char *dir, const nqcopt *o, int depth, nqrep **rep) {
  const uint8_t *trust = o->trust;
  size_t trustlen = o->trustlen;
  const uint8_t *const *anc = o->anc;
  const size_t *anclen = o->anclen;
  size_t nanc = o->nanc;
  ancs an;
  size_t i;
  nqrep *r;
  seal s;
  char *mb = NULL;
  size_t mn = 0;
  nqclist l;
  nqcbuf hb;
  const uint8_t *sb;
  size_t sn;
  int rc, mok, lok, hok = 0;
  if (rep != NULL) *rep = NULL;
  memset(&hb, 0, sizeof hb);
  if (dir == NULL || rep == NULL || (trust == NULL && trustlen != 0)) {
    return NQEARG;
  }
  if (nanc > NQCANC) return NQELIM;
  if (nanc != 0 && (anc == NULL || anclen == NULL)) return NQEARG;
  if (o->nonly != 0 && o->only == NULL) return NQEARG;
  if (o->nlin != 0 && o->lin == NULL) return NQEARG;
  if (o->nonly > NQCFILES || o->nlin > NQCINMAX) return NQELIM;
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
  sb = (const uint8_t *)mb;
  sn = mn;
  if (mok && s.ok && s.ver == 2) {
    size_t fs = 0, fe = 0;
    if (head(mb, mn, &fs, &fe)) {
      nqcput(&hb, mb, fs);
      nqcput(&hb, mb + fe, mn - fe);
      if (hb.err != NQOK) r->err = hb.err;
      sb = (const uint8_t *)hb.p;
      sn = hb.n;
      hok = 1;
    }
  }
  if (mok && s.ok) {
    uint8_t h[32];
    if (s.ver == 2 && !hok) {
      add(r, "manifest.digest", 0, "the manifest's head cannot be found "
          "(not in the canonical noqtis-capsule-2 layout)", NULL, NULL);
    } else {
      rc = nqhash(NQS256, sb, sn, h, 32) == NQOK && memcmp(h, s.mh, 32) == 0;
      add(r, "manifest.digest", rc,
          s.ver == 2
              ? (rc ? "SHA-256 of the manifest's head matches the seal"
                    : "SHA-256 of the manifest's head differs from "
                      "head_sha256")
              : (rc ? "SHA-256 of noqtis.json matches the seal"
                    : "SHA-256 of noqtis.json differs from manifest_sha256"),
          NULL, NULL);
    }
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
    if (mok && (s.ver == 1 || hok)) {
      rc = nqvrfy(s.alg, key, kn, sb, sn, (const uint8_t *)s.ctx, s.ctxlen,
                  0, s.sig, s.sign);
      add(r, "signature", rc == NQOK, s.an,
          s.ver == 2 ? (rc == NQOK ? " signature over the manifest's head "
                                     "is valid"
                                   : " signature over the manifest's head "
                                     "does not verify")
                     : (rc == NQOK ? " signature over noqtis.json is valid"
                                   : " signature over noqtis.json does "
                                     "not verify"),
          NULL);
    } else if (mok) {
      add(r, "signature", 0, s.an, " signature not checked: no head",
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
    if (r->err == NQOK) {
      if (o->nonly > 0) {
        flt f;
        f.p = o->only;
        f.n = o->nonly;
        f.hit = (unsigned char *)nqmal(o->nonly);
        if (f.hit == NULL) {
          r->err = NQEMEM;
        } else {
          memset(f.hit, 0, o->nonly);
          chkman(r, dir, mb, mn, lok ? &l : NULL, NULL, s.ok ? s.ver : 1,
                 &f);
          nqfree(f.hit, o->nonly);
        }
      } else {
        chkman(r, dir, mb, mn, lok ? &l : NULL, NULL, s.ok ? s.ver : 1,
               NULL);
      }
    }
    nqclfree(&l);
  }
  if (r->err == NQOK && mok && s.ok && s.ver == 2 && o->nlin > 0) {
    lineage(r, mb, mn, o, depth);
  }

  nqcbfree(&hb);
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
  if (rc == NQOK && r->err == NQOK) {
    chkman(r, dir, mb, mn, NULL, &in, s.ok ? s.ver : 1, NULL);
  }
  if (r->err == NQOK && !r->bad && s.ok) {
    uint8_t fp[32];
    char hx[65], num[24];
    add(r, "info.format", 1, s.ver == 2 ? NQCFMT2 : NQCFMT, NULL, NULL);
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

/* ---- proofs (noqtis-proof-1): single files of a format 2 capsule ----
 *
 *   {"entries":[{"entry":E,"index":N,"path":[H,...]},...],
 *    "format":"noqtis-proof-1","head":HEAD,"seal":SEAL}
 *
 * E is the entry's canonical bytes as the manifest lists them, path its
 * Merkle audit path leaf upward, HEAD the manifest's head (what the seal
 * signs: its leaf count and root fix the tree), SEAL noqtis.sig. */

#define NQCPFMT "noqtis-proof-1"

/* one listed entry: where its bytes are in the manifest */
typedef struct {
  size_t a, b;
} span;

/* the entries of a manifest in the canonical layout, with their leaves */
static int spans(const char *buf, size_t n, span **sp, uint8_t **lv,
                 size_t *cnt, size_t *cap) {
  scan c;
  char t[1];
  size_t k;
  uint8_t h[32];
  uint64_t v;
  *sp = NULL;
  *lv = NULL;
  *cnt = 0;
  *cap = 0;
  c.m = buf;
  c.n = n;
  c.i = 0;
  c.err = NULL;
  if (!lit(&c, "{\"created\":") || !cstr(&c, t, 0, &k) ||
      !lit(&c, ",\"files\":[")) {
    return NQEDEC;
  }
  if (lit(&c, "]")) return NQOK;
  for (;;) {
    size_t a = c.i;
    if (!lit(&c, "{\"path\":") || !cstr(&c, t, 0, &k) ||
        !lit(&c, ",\"sha256\":") || !chex(&c, h) ||
        !lit(&c, ",\"sha3_256\":") || !chex(&c, h) ||
        !lit(&c, ",\"size\":") || !cint(&c, &v) || !lit(&c, "}")) {
      return NQEDEC;
    }
    if (*cnt == *cap) {
      size_t nc = *cap == 0 ? 64 : *cap * 2;
      span *ns = (span *)nqmal(nc * sizeof(span));
      uint8_t *nl = (uint8_t *)nqmal(nc * 32);
      if (ns == NULL || nl == NULL) {
        if (ns != NULL) nqfree(ns, nc * sizeof(span));
        if (nl != NULL) nqfree(nl, nc * 32);
        return NQEMEM;
      }
      if (*cap > 0) {
        memcpy(ns, *sp, *cnt * sizeof(span));
        memcpy(nl, *lv, *cnt * 32);
        nqfree(*sp, *cap * sizeof(span));
        nqfree(*lv, *cap * 32);
      }
      *sp = ns;
      *lv = nl;
      *cap = nc;
    }
    (*sp)[*cnt].a = a;
    (*sp)[*cnt].b = c.i;
    nqcmleaf(buf + a, c.i - a, *lv + 32 * *cnt);
    (*cnt)++;
    if (*cnt > nqclim.files) return NQELIM;
    if (lit(&c, "]")) return NQOK;
    if (!lit(&c, ",")) return NQEDEC;
  }
}

/* the decoded path of the entry at buf[s.a..s.b) */
static int spath(const char *buf, span s, char *out, size_t cap,
                 size_t *len) {
  scan c;
  c.m = buf;
  c.n = s.b;
  c.i = s.a;
  c.err = NULL;
  return lit(&c, "{\"path\":") && cstr(&c, out, cap, len) && *len < cap;
}

int nqprove(const char *dir, const char *const *paths, size_t np, char *out,
            size_t cap, size_t *outlen) {
  char *sb = NULL, *mb = NULL, *pa = NULL, *pn = NULL;
  size_t sn = 0, mn = 0, cnt = 0, scap = 0, fs = 0, fe = 0, i, j, np0 = np;
  span *sp = NULL;
  uint8_t *lv = NULL, root[32], want[32];
  size_t *idx = NULL;
  nqjs *sv = NULL, *hv = NULL;
  nqcbuf o, hb;
  int rc, cn = 0;
  if (outlen != NULL) *outlen = 0;
  if (dir == NULL || paths == NULL || np == 0 || outlen == NULL ||
      (out == NULL && cap != 0)) {
    return NQEARG;
  }
  if (np > NQCFILES) return NQELIM;
  memset(&o, 0, sizeof o);
  memset(&hb, 0, sizeof hb);
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &sb, &sn);
  if (rc == NQOK) rc = canon(sb, sn, &sv, &cn);
  if (rc == NQOK && !cn) rc = NQEDEC;
  if (rc == NQOK) {
    const char *f = str(sv, "format", NULL);
    if (f == NULL || strcmp(f, NQCSFMT2) != 0) rc = NQENOSUP;
  }
  if (rc == NQOK) rc = nqcread(dir, NQCMAN, nqclim.man, &mb, &mn);
  if (rc == NQOK && !head(mb, mn, &fs, &fe)) rc = NQEDEC;
  if (rc == NQOK) rc = spans(mb, mn, &sp, &lv, &cnt, &scap);
  if (rc == NQOK) {
    nqcput(&hb, mb, fs);
    nqcput(&hb, mb + fe, mn - fe);
    rc = hb.err;
  }
  /* the head's root must be of these entries */
  if (rc == NQOK) rc = canon(hb.p, hb.n, &hv, &cn);
  if (rc == NQOK) {
    const nqjs *mk = nqjget(hv, "merkle");
    size_t rl = 0;
    const char *rs = mk != NULL ? str(mk, "root", &rl) : NULL;
    nqcmroot(lv, cnt, root);
    if (!cn || !hex32(rs, rl, want) || memcmp(root, want, 32) != 0) {
      rc = NQEDEC;
    }
  }
  if (rc == NQOK) {
    idx = (size_t *)nqmal(np * sizeof(size_t));
    pa = (char *)nqmal(NQCPATHMAX + 2);
    pn = (char *)nqmal(NQCPATHMAX + 1);
    if (idx == NULL || pa == NULL || pn == NULL) rc = NQEMEM;
  }
  /* each path asked for, normalised, found among the entries */
  for (i = 0; rc == NQOK && i < np; i++) {
    size_t nl = 0, el = 0;
    if (paths[i] == NULL) {
      rc = NQEARG;
      break;
    }
    rc = nqcnorm(paths[i], strlen(paths[i]), pn, NQCPATHMAX + 1, &nl);
    if (rc != NQOK) break;
    for (j = 0; j < cnt; j++) {
      if (spath(mb, sp[j], pa, NQCPATHMAX + 2, &el) && el == nl &&
          memcmp(pa, pn, nl) == 0) {
        break;
      }
    }
    if (j == cnt) {
      rc = NQEIO; /* not listed */
      break;
    }
    idx[i] = j;
  }
  /* in index order, each once */
  if (rc == NQOK) {
    size_t a, b, m = 0;
    for (a = 1; a < np; a++) {
      size_t x = idx[a];
      for (b = a; b > 0 && idx[b - 1] > x; b--) idx[b] = idx[b - 1];
      idx[b] = x;
    }
    for (a = 0; a < np; a++) {
      if (m == 0 || idx[m - 1] != idx[a]) idx[m++] = idx[a];
    }
    np = m;
  }
  if (rc == NQOK) {
    uint8_t path[NQCMDEPTH * 32];
    char hx[65];
    nqcputs(&o, "{\"entries\":[");
    for (i = 0; rc == NQOK && i < np; i++) {
      size_t len = 0, k;
      rc = nqcmpath(lv, cnt, idx[i], path, NQCMDEPTH, &len);
      if (rc != NQOK) break;
      if (i > 0) nqcput(&o, ",", 1);
      nqcputs(&o, "{\"entry\":");
      nqcput(&o, mb + sp[idx[i]].a, sp[idx[i]].b - sp[idx[i]].a);
      nqcputs(&o, ",\"index\":");
      nqcjint(&o, (uint64_t)idx[i]);
      nqcputs(&o, ",\"path\":[");
      for (k = 0; k < len; k++) {
        if (k > 0) nqcput(&o, ",", 1);
        nqhex(path + 32 * k, 32, hx);
        nqcput(&o, "\"", 1);
        nqcputs(&o, hx);
        nqcput(&o, "\"", 1);
      }
      nqcputs(&o, "]}");
    }
    nqcputs(&o, "],\"format\":\"" NQCPFMT "\",\"head\":");
    nqcput(&o, hb.p, hb.n);
    nqcputs(&o, ",\"seal\":");
    nqcput(&o, sb, sn);
    nqcput(&o, "}", 1);
    if (rc == NQOK) rc = o.err;
  }
  if (rc == NQOK) {
    *outlen = o.n;
    if (o.n > cap) {
      rc = NQEBUF;
    } else {
      memcpy(out, o.p, o.n);
    }
  }
  if (idx != NULL) nqfree(idx, np0 * sizeof(size_t));
  if (pa != NULL) nqfree(pa, NQCPATHMAX + 2);
  if (pn != NULL) nqfree(pn, NQCPATHMAX + 1);
  if (sp != NULL) nqfree(sp, scap * sizeof(span));
  if (lv != NULL) nqfree(lv, scap * 32);
  if (sb != NULL) nqfree(sb, sn + 1);
  if (mb != NULL) nqfree(mb, mn + 1);
  nqjfree(sv);
  nqjfree(hv);
  nqcbfree(&o);
  nqcbfree(&hb);
  return rc;
}

/* one entry of a proof, checked against the head's tree; with dir, the
 * file there against the entry */
static void pent(nqrep *r, const nqjs *pe, uint64_t lvs, const uint8_t *root,
                 const char *dir, const nqclist *l, unsigned char *seen,
                 ent *e) {
  static const char *const nm[] = {"entry", "index", "path"};
  const nqjs *ev, *pv;
  nqcbuf eb;
  scan c;
  uint8_t leaf[32], path[NQCMDEPTH * 32];
  int64_t ix = -1;
  size_t i;
  int ok;
  memset(&eb, 0, sizeof eb);
  ev = pe->type == NQJOBJ ? nqjget(pe, "entry") : NULL;
  pv = pe->type == NQJOBJ ? nqjget(pe, "path") : NULL;
  ok = pe->type == NQJOBJ && keys(pe, nm, 3, 3) && ev->type == NQJOBJ &&
       pv->type == NQJARR && pv->n <= NQCMDEPTH &&
       nqjint(nqjget(pe, "index"), &ix) == NQOK && ix >= 0 &&
       (uint64_t)ix < lvs;
  for (i = 0; ok && i < pv->n; i++) {
    const nqjs *h = nqjat(pv, i);
    ok = h->type == NQJSTR && hex32(h->str, h->len, path + 32 * i);
  }
  if (ok) ok = nqcjval(&eb, ev) == NQOK;
  /* the entry in exactly the manifest's layout */
  if (ok) {
    c.m = eb.p;
    c.n = eb.n;
    c.i = 0;
    c.err = NULL;
    ok = lit(&c, "{\"path\":") &&
         cstr(&c, e->raw, sizeof e->raw, &e->rawn) &&
         e->rawn < sizeof e->raw && lit(&c, ",\"sha256\":") &&
         chex(&c, e->s2) && lit(&c, ",\"sha3_256\":") && chex(&c, e->s3) &&
         lit(&c, ",\"size\":") && cint(&c, &e->size) && lit(&c, "}") &&
         c.i == eb.n;
  }
  if (!ok) {
    add(r, "proof.entry", 0, "an entry is not {entry, index, path} with an "
        "entry in the manifest's layout", NULL, NULL);
    nqcbfree(&eb);
    return;
  }
  nqcmleaf(eb.p, eb.n, leaf);
  nqcbfree(&eb);
  ok = nqcmvrfy(leaf, (size_t)ix, (size_t)lvs, path, pv->n, root);
  add(r, "proof.entry", ok, e->raw,
      ok ? ": in the sealed Merkle tree"
         : ": its audit path does not lead to the sealed Merkle root",
      NULL);
  if (ok && dir != NULL) chkent(r, dir, l, seen, e);
}

int nqchkp(const char *proof, size_t n, const nqcopt *o, const char *dir,
           nqrep **rep) {
  static const char *const pn[] = {"entries", "format", "head", "seal"};
  static const char *const hn[] = {"created", "format", "merkle", "inputs",
                                   "meta"};
  nqrep *r;
  nqjs *v = NULL;
  const nqjs *es, *hd, *sl, *mk;
  nqcbuf sb, hb;
  seal s;
  ancs an;
  nqclist l;
  unsigned char *seen = NULL;
  ent *e = NULL;
  uint8_t root[32], h[32];
  int64_t lvs = -1;
  int rc, cn = 0, ok, lok = 0;
  size_t i;
  if (rep != NULL) *rep = NULL;
  static const nqcopt none;
  if (o == NULL) o = &none;
  if (proof == NULL || rep == NULL ||
      (o->trust == NULL && o->trustlen != 0)) {
    return NQEARG;
  }
  if (o->nanc > NQCANC) return NQELIM;
  if (o->nanc != 0 && (o->anc == NULL || o->anclen == NULL)) return NQEARG;
  an.p = o->anc;
  an.n = o->anclen;
  an.k = o->nanc;
  r = (nqrep *)nqmal(sizeof *r);
  if (r == NULL) return NQEMEM;
  memset(r, 0, sizeof *r);
  memset(&s, 0, sizeof s);
  memset(&sb, 0, sizeof sb);
  memset(&hb, 0, sizeof hb);
  memset(&l, 0, sizeof l);
  rc = n > NQCMANMAX ? NQELIM : canon(proof, n, &v, &cn);
  if (rc == NQEMEM) {
    r->err = rc;
    goto out;
  }
  add(r, "proof.parse", rc == NQOK, rc == NQOK ? "a JSON object" : "",
      rc == NQOK ? NULL : nqerr(rc), NULL);
  if (rc != NQOK) goto out;
  add(r, "proof.canonical", cn,
      cn ? "canonical JSON" : "not canonical JSON (RFC 8785)", NULL, NULL);
  if (!cn) goto out;
  es = nqjget(v, "entries");
  hd = nqjget(v, "head");
  sl = nqjget(v, "seal");
  {
    const char *f = str(v, "format", NULL);
    ok = keys(v, pn, 4, 4) && f != NULL && strcmp(f, NQCPFMT) == 0 &&
         es->type == NQJARR && es->n >= 1 && es->n <= NQCFILES &&
         hd->type == NQJOBJ && sl->type == NQJOBJ;
  }
  add(r, "proof.fields", ok,
      ok ? "the fields of noqtis-proof-1"
         : "not a noqtis-proof-1 proof (entries, format, head, seal)",
      NULL, NULL);
  if (!ok) goto out;
  /* the seal, as nqchk reads noqtis.sig */
  rc = nqcjval(&sb, sl);
  if (rc != NQOK) {
    r->err = rc;
    goto out;
  }
  rdsealb(r, sb.p, sb.n, &s);
  if (r->err != NQOK || !s.ok) goto out;
  if (s.ver != 2) {
    add(r, "seal.format", 0, "a proof needs a noqtis-seal-2 seal", NULL,
        NULL);
    goto out;
  }
  /* the head: what the seal signs */
  rc = nqcjval(&hb, hd);
  if (rc != NQOK) {
    r->err = rc;
    goto out;
  }
  ok = nqhash(NQS256, (const uint8_t *)hb.p, hb.n, h, 32) == NQOK &&
       memcmp(h, s.mh, 32) == 0;
  add(r, "manifest.digest", ok,
      ok ? "SHA-256 of the head matches the seal"
         : "SHA-256 of the head differs from head_sha256", NULL, NULL);
  {
    const char *f = str(hd, "format", NULL), *cr;
    size_t crn = 0, rl = 0;
    const char *rs;
    static const char *const mn[] = {"alg", "leaves", "root"};
    mk = nqjget(hd, "merkle");
    cr = str(hd, "created", &crn);
    rs = mk != NULL && mk->type == NQJOBJ ? str(mk, "root", &rl) : NULL;
    ok = keys(hd, hn, 5, 3) && f != NULL && strcmp(f, NQCFMT2) == 0 &&
         cr != NULL && nqctchk(cr, crn) && mk->type == NQJOBJ &&
         keys(mk, mn, 3, 3) && str(mk, "alg", NULL) != NULL &&
         strcmp(str(mk, "alg", NULL), "sha256") == 0 &&
         nqjint(nqjget(mk, "leaves"), &lvs) == NQOK && lvs >= 0 &&
         hex32(rs, rl, root);
  }
  add(r, "manifest.fields", ok,
      ok ? "the head of a noqtis-capsule-2 manifest"
         : "the head is not of a noqtis-capsule-2 manifest", NULL, NULL);
  if (!ok) goto out;
  {
    const uint8_t *key = s.pk;
    size_t kn = s.pkn;
    if (o->trust != NULL) {
      int same = o->trustlen == s.pkn && memcmp(o->trust, s.pk, s.pkn) == 0;
      add(r, "key", same,
          same ? "the seal's key is the trusted key"
               : "the seal's key is not the trusted key", NULL, NULL);
      key = o->trust;
      kn = o->trustlen;
    } else {
      add(r, "key", 1,
          "not pinned: accepted the public key in the seal (no trusted "
          "key given)", NULL, NULL);
    }
    rc = nqvrfy(s.alg, key, kn, (const uint8_t *)hb.p, hb.n,
                (const uint8_t *)s.ctx, s.ctxlen, 0, s.sig, s.sign);
    add(r, "signature", rc == NQOK, s.an,
        rc == NQOK ? " signature over the head is valid"
                   : " signature over the head does not verify", NULL);
  }
  chkts(r, &s, &an);
  if (r->err != NQOK) goto out;
  if (dir != NULL) {
    rc = nqcwalk(dir, &l);
    lok = rc == NQOK;
    if (rc == NQEMEM) {
      r->err = rc;
      goto out;
    }
    add(r, "folder", lok, lok ? "listed" : "cannot list: ",
        lok ? NULL : nqerr(rc), NULL);
    if (lok && l.n > 0) {
      seen = (unsigned char *)nqmal(l.n);
      if (seen == NULL) {
        r->err = NQEMEM;
        goto out;
      }
      memset(seen, 0, l.n);
    }
  }
  e = (ent *)nqmal(sizeof(ent));
  if (e == NULL) {
    r->err = NQEMEM;
    goto out;
  }
  for (i = 0; i < es->n && r->err == NQOK; i++) {
    pent(r, nqjat(es, i), (uint64_t)lvs, root, lok ? dir : NULL,
         lok ? &l : NULL, seen, e);
  }
  if (dir != NULL && lok) {
    add(r, "partial", 1, "only the proven files were checked: the "
        "capsule's other files are not in the proof", NULL, NULL);
  }
out:
  if (e != NULL) nqfree(e, sizeof(ent));
  if (seen != NULL) nqfree(seen, l.n);
  nqclfree(&l);
  nqjfree(v);
  nqjfree(s.v);
  nqfree(s.pk, s.sz.pk);
  nqfree(s.sig, s.sz.sig);
  nqcbfree(&sb);
  nqcbfree(&hb);
  if (r->err != NQOK) {
    rc = r->err;
    nqrepfree(r);
    return rc;
  }
  *rep = r;
  return r->bad ? NQEVRFY : NQOK;
}
