/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqseal: lists the folder, writes noqtis.json (canonical JSON), signs its
 * exact bytes with the FIPS 204/205 context "noqtis-capsule-1" and writes
 * noqtis.sig. The folder must hold only regular files and folders with
 * portable names; anything else (a link, a device, a refused name, two
 * paths equal but for ASCII case) makes it NQEARG and nothing is
 * written.
 *
 * nqseal2 writes format 2: the manifest also holds the inputs and a Merkle
 * tree over the entries (each leaf the hash of an entry's canonical
 * bytes), and the seal signs the head, the manifest without its "files"
 * member, with the context "noqtis-capsule-2". */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cap/cap.h"
#include "core/int.h"

/* SOURCE_DATE_EPOCH (reproducible builds) when set, else the clock;
 * -1 when SOURCE_DATE_EPOCH is not a plain decimal number. */
static int64_t now(void) {
  const char *e = getenv("SOURCE_DATE_EPOCH");
  int64_t v = 0;
  size_t i;
  if (e != NULL && e[0] != 0) {
    for (i = 0; e[i] != 0; i++) {
      if (e[i] < '0' || e[i] > '9' || i >= 12) return -1;
      v = v * 10 + (e[i] - '0');
    }
    return v;
  }
  return (int64_t)time(NULL);
}

static int foldcmp(const void *ctx, size_t a, size_t b) {
  const nqclist *l = (const nqclist *)ctx;
  return nqcfold(l->e[a].path, l->e[a].len, l->e[b].path, l->e[b].len);
}

int nqsealwhy(const char *dir, int *why, char *path, size_t cap) {
  nqclist l;
  size_t *idx = NULL, i;
  const char *p = NULL;
  int rc, w = 0;
  if (dir == NULL || why == NULL || (path == NULL && cap > 0)) return NQEARG;
  *why = 0;
  if (cap > 0) path[0] = 0;
  memset(&l, 0, sizeof l);
  rc = nqcwalk(dir, &l);
  for (i = 0; rc == NQOK && w == 0 && i < l.n; i++) {
    if (l.e[i].kind == NQCLNK) w = NQSWLINK;
    else if (l.e[i].kind == NQCODD) w = NQSWODD;
    else if (l.e[i].kind == NQCBAD) w = NQSWNAME;
    if (w != 0) p = l.e[i].path;
  }
  if (rc == NQOK && w == 0 && l.n >= 2) {
    idx = (size_t *)nqmal(l.n * sizeof(size_t));
    if (idx == NULL) rc = NQEMEM;
    for (i = 0; rc == NQOK && i < l.n; i++) idx[i] = i;
    if (rc == NQOK) rc = nqcsort(idx, l.n, foldcmp, &l);
    for (i = 1; rc == NQOK && w == 0 && i < l.n; i++) {
      if (foldcmp(&l, idx[i - 1], idx[i]) == 0) {
        w = NQSWCASE;
        p = l.e[idx[i]].path;
      }
    }
  }
  for (i = 0; rc == NQOK && w == 0 && i < l.n; i++) {
    int sec = 0;
    rc = nqcsec(dir, l.e[i].path, &sec);
    if (rc == NQOK && sec) {
      w = NQSWKEY;
      p = l.e[i].path;
    }
  }
  if (rc == NQOK && w != 0) {
    *why = w;
    if (cap > 0) {
      size_t n = strlen(p) < cap - 1 ? strlen(p) : cap - 1;
      memcpy(path, p, n);
      path[n] = 0;
    }
  }
  if (idx != NULL) nqfree(idx, l.n * sizeof(size_t));
  nqclfree(&l);
  return rc;
}

/* every entry a regular file, no two equal but for ASCII case */
static int sealable(const nqclist *l) {
  size_t *idx, i;
  int rc;
  for (i = 0; i < l->n; i++) {
    if (l->e[i].kind != NQCREG) return NQEARG;
    if (l->e[i].size > NQCMAXINT) return NQELIM;
  }
  if (l->n < 2) return NQOK;
  idx = (size_t *)nqmal(l->n * sizeof(size_t));
  if (idx == NULL) return NQEMEM;
  for (i = 0; i < l->n; i++) idx[i] = i;
  rc = nqcsort(idx, l->n, foldcmp, l);
  for (i = 1; rc == NQOK && i < l->n; i++) {
    if (foldcmp(l, idx[i - 1], idx[i]) == 0) rc = NQEARG;
  }
  nqfree(idx, l->n * sizeof(size_t));
  return rc;
}

int nqcinok(const char *s, size_t n) {
  size_t i;
  if (s == NULL || n == 0 || n > NQCNAMEMAX || !nqcutf8(s, n)) return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c == 0x7f) return 0;
  }
  return 1;
}

/* where the "files" member starts and where "format" starts, in format 2
 * the head is the manifest without the bytes between them */
typedef struct {
  int ver;
  const nqcin *in;
  size_t nin;
  size_t fs, fe;
  uint8_t *lv; /* the leaves, 32 bytes per entry */
} mopt;

static int manifest(const char *dir, const nqclist *l, const char *ts,
                    const nqjs *meta, nqcbuf *m, int *sec, mopt *o) {
  size_t i;
  int rc = NQOK;
  nqcputs(m, "{\"created\":");
  nqcjstr(m, ts, strlen(ts));
  nqcput(m, ",", 1);
  o->fs = m->n;
  nqcputs(m, "\"files\":[");
  for (i = 0; i < l->n; i++) {
    uint8_t s2[32], s3[32];
    char hx[65];
    uint64_t size = 0;
    size_t es;
    rc = nqcdigx(dir, l->e[i].path, (uint64_t)-1, &size, s2, s3, sec);
    if (rc != NQOK) return rc;
    /* a secret key in the folder would ship with the capsule */
    if (*sec) return NQEARG;
    if (size > NQCMAXINT) return NQELIM;
    if (m->n > nqclim.man) return NQELIM; /* stop early */
    if (i > 0) nqcput(m, ",", 1);
    es = m->n;
    nqcputs(m, "{\"path\":");
    nqcjstr(m, l->e[i].path, l->e[i].len);
    nqhex(s2, 32, hx);
    nqcputs(m, ",\"sha256\":\"");
    nqcputs(m, hx);
    nqhex(s3, 32, hx);
    nqcputs(m, "\",\"sha3_256\":\"");
    nqcputs(m, hx);
    nqcputs(m, "\",\"size\":");
    nqcjint(m, size);
    nqcput(m, "}", 1);
    if (o->ver == 2 && m->err == NQOK) {
      nqcmleaf(m->p + es, m->n - es, o->lv + 32 * i);
    }
  }
  nqcputs(m, "],");
  o->fe = m->n;
  if (o->ver == 2) {
    uint8_t root[32];
    char hx[65];
    nqcputs(m, "\"format\":\"" NQCFMT2 "\"");
    if (o->nin > 0) {
      nqcputs(m, ",\"inputs\":[");
      for (i = 0; i < o->nin; i++) {
        if (i > 0) nqcput(m, ",", 1);
        nqhex(o->in[i].id, 32, hx);
        nqcputs(m, "{\"capsule\":\"");
        nqcputs(m, hx);
        nqcputs(m, "\",\"name\":");
        nqcjstr(m, o->in[i].name, strlen(o->in[i].name));
        nqcput(m, "}", 1);
      }
      nqcput(m, "]", 1);
    }
    nqcmroot(o->lv, l->n, root);
    nqhex(root, 32, hx);
    nqcputs(m, ",\"merkle\":{\"alg\":\"sha256\",\"leaves\":");
    nqcjint(m, (uint64_t)l->n);
    nqcputs(m, ",\"root\":\"");
    nqcputs(m, hx);
    nqcputs(m, "\"}");
  } else {
    nqcputs(m, "\"format\":\"" NQCFMT "\"");
  }
  if (meta != NULL) {
    nqcputs(m, ",\"meta\":");
    rc = nqcjval(m, meta);
    if (rc != NQOK) return rc;
  }
  nqcput(m, "}", 1);
  return m->err;
}

static int sealjson(nqcbuf *s, int ver, const char *an, const uint8_t *mh,
                    const uint8_t *pk, size_t pklen, const uint8_t *sig,
                    size_t siglen) {
  char hx[65];
  size_t bn = nqb64n(pklen > siglen ? pklen : siglen) + 1;
  char *b = (char *)nqmal(bn);
  if (b == NULL) return NQEMEM;
  nqcputs(s, "{\"alg\":");
  nqcjstr(s, an, strlen(an));
  if (ver == 2) {
    nqcputs(s, ",\"context\":\"" NQCCTX2 "\",\"format\":\"" NQCSFMT2 "\"");
    nqhex(mh, 32, hx);
    nqcputs(s, ",\"head_sha256\":\"");
  } else {
    nqcputs(s, ",\"context\":\"" NQCCTX "\",\"format\":\"" NQCSFMT "\"");
    nqhex(mh, 32, hx);
    nqcputs(s, ",\"manifest_sha256\":\"");
  }
  nqcputs(s, hx);
  nqb64e(pk, pklen, b);
  nqcputs(s, "\",\"public_key\":\"");
  nqcputs(s, b);
  nqb64e(sig, siglen, b);
  nqcputs(s, "\",\"signature\":\"");
  nqcputs(s, b);
  nqcputs(s, "\"}");
  nqfree(b, bn);
  return s->err;
}

int nqcseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, const char *meta,
            const char *tsa, int64_t created, const uint8_t *rnd,
            size_t rndlen, int *why) {
  return nqcsealx(dir, alg, sk, sklen, pk, pklen, meta, tsa, created, rnd,
                  rndlen, 1, NULL, 0, why);
}

int nqcsealx(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *pk, size_t pklen, const char *meta,
             const char *tsa, int64_t created, const uint8_t *rnd,
             size_t rndlen, int ver, const nqcin *in, size_t nin,
             int *why) {
  static const uint8_t c1[] = NQCCTX, c2[] = NQCCTX2;
  const uint8_t *ctx = ver == 2 ? c2 : c1;
  size_t cl = (ver == 2 ? sizeof c2 : sizeof c1) - 1, i, lvn = 0;
  mopt o;
  nqcbuf hd;
  const uint8_t *sb; /* the signed bytes: the manifest, or its head */
  size_t sn;
  nqssz sz;
  const char *an;
  nqclist l;
  nqcbuf m, s;
  nqjs *mj = NULL;
  uint8_t *sig = NULL;
  uint8_t mh[32];
  size_t siglen = 0;
  char ts[21];
  int rc, sec = 0;
  if (why != NULL) *why = 0;
  if (dir == NULL || sk == NULL || pk == NULL) return NQEARG;
  if (ver != 1 && ver != 2) return NQEARG;
  if (nin > 0 && (ver != 2 || in == NULL)) return NQEARG;
  if (nin > NQCINMAX) return NQELIM;
  for (i = 0; i < nin; i++) {
    if (in[i].name == NULL || !nqcinok(in[i].name, strlen(in[i].name))) {
      return NQEARG;
    }
  }
  memset(&o, 0, sizeof o);
  memset(&hd, 0, sizeof hd);
  o.ver = ver;
  o.in = in;
  o.nin = nin;
  /* a timestamp needs a request to a TSA over the network, which the
   * library does not make; the CLI is to add it (DESIGN.md, M10) */
  if (tsa != NULL) return NQENOSUP;
  if (nqssize(alg, &sz) != NQOK) return NQEARG;
  /* Ed25519 alone is not post-quantum: never a seal */
  if (alg == NQED25519) return NQENOSUP;
  an = nqsname(alg);
  if (an == NULL) return NQENOSUP;
  if (sklen != sz.sk || pklen != sz.pk) return NQEARG;
  if (nqctime(created, ts) != NQOK) return NQEARG;
  if (meta != NULL) {
    size_t ml = strlen(meta);
    if (ml > NQCMETAMAX) {
      if (why != NULL) *why = NQCLMETA;
      return NQELIM;
    }
    rc = nqjparse(meta, ml, &mj, NULL);
    if (rc != NQOK) return rc;
    if (mj->type != NQJOBJ) {
      nqjfree(mj);
      return NQEDEC;
    }
  }
  memset(&m, 0, sizeof m);
  memset(&s, 0, sizeof s);
  rc = nqcwalk(dir, &l);
  if (rc != NQOK) {
    if (rc == NQELIM && why != NULL) *why = l.lim;
    nqjfree(mj);
    return rc;
  }
  rc = sealable(&l);
  if (rc == NQOK && ver == 2) {
    lvn = (l.n > 0 ? l.n : 1) * 32;
    o.lv = (uint8_t *)nqmal(lvn);
    if (o.lv == NULL) rc = NQEMEM;
  }
  if (rc == NQOK) rc = manifest(dir, &l, ts, mj, &m, &sec, &o);
  if (rc == NQEARG && sec && why != NULL) *why = NQCLSEC;
  if (rc == NQOK && m.n > nqclim.man) rc = NQELIM;
  if (rc == NQELIM && m.n > nqclim.man && why != NULL) *why = NQCLMAN;
  sb = (const uint8_t *)m.p;
  sn = m.n;
  if (rc == NQOK && ver == 2) {
    /* the head: the manifest without "files":[...], */
    nqcput(&hd, m.p, o.fs);
    nqcput(&hd, m.p + o.fe, m.n - o.fe);
    rc = hd.err;
    sb = (const uint8_t *)hd.p;
    sn = hd.n;
  }
  if (rc == NQOK) rc = nqhash(NQS256, sb, sn, mh, 32);
  if (rc == NQOK) {
    sig = (uint8_t *)nqmal(sz.sig);
    if (sig == NULL) rc = NQEMEM;
  }
  if (rc == NQOK) {
    if (rnd != NULL) {
      rc = nqsignd(alg, sk, sklen, sb, sn, ctx, cl, 0, rnd, rndlen, sig,
                   sz.sig, &siglen);
    } else {
      rc = nqsign(alg, sk, sklen, sb, sn, ctx, cl, 0, sig, sz.sig, &siglen);
    }
  }
  /* sk and pk must be one key pair: a seal that cannot verify is never
   * written */
  if (rc == NQOK &&
      nqvrfy(alg, pk, pklen, sb, sn, ctx, cl, 0, sig, siglen) != NQOK) {
    rc = NQEARG;
  }
  if (rc == NQOK) rc = sealjson(&s, ver, an, mh, pk, pklen, sig, siglen);
  if (rc == NQOK) rc = nqcwrite(dir, NQCMAN, m.p, m.n);
  if (rc == NQOK) rc = nqcwrite(dir, NQCSIG, s.p, s.n);
  nqfree(sig, sz.sig);
  if (o.lv != NULL) nqfree(o.lv, lvn);
  nqcbfree(&hd);
  nqcbfree(&m);
  nqcbfree(&s);
  nqclfree(&l);
  nqjfree(mj);
  return rc;
}

int nqseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
           const uint8_t *pk, size_t pklen, const char *meta,
           const char *tsa) {
  int64_t t = now();
  if (t < 0) return NQEARG;
  return nqcseal(dir, alg, sk, sklen, pk, pklen, meta, tsa, t, NULL, 0,
                 NULL);
}

int nqseal2(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, const char *meta,
            const nqcin *in, size_t nin) {
  int64_t t = now();
  if (t < 0) return NQEARG;
  return nqcsealx(dir, alg, sk, sklen, pk, pklen, meta, NULL, t, NULL, 0, 2,
                  in, nin, NULL);
}

int nqcapid(const char *dir, uint8_t id[32]) {
  char *b = NULL;
  size_t n = 0, hn = 0, i;
  nqjs *v = NULL;
  const nqjs *f, *h;
  int rc;
  if (dir == NULL || id == NULL) return NQEARG;
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &b, &n);
  if (rc != NQOK) return rc;
  rc = nqjparse(b, n, &v, NULL);
  nqfree(b, n + 1);
  if (rc != NQOK) return rc;
  f = nqjget(v, "format");
  rc = NQEDEC;
  if (f != NULL && f->type == NQJSTR) {
    h = strcmp(f->str, NQCSFMT2) == 0 ? nqjget(v, "head_sha256")
        : strcmp(f->str, NQCSFMT) == 0 ? nqjget(v, "manifest_sha256")
                                       : NULL;
    if (h != NULL && h->type == NQJSTR && (hn = h->len) == 64) {
      rc = NQOK;
      for (i = 0; i < 64 && rc == NQOK; i++) {
        char c = h->str[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) rc = NQEDEC;
      }
      if (rc == NQOK) rc = nqunhex(h->str, hn, id, 32, &hn);
      if (rc == NQOK && hn != 32) rc = NQEDEC;
    }
  }
  nqjfree(v);
  return rc;
}
