/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* RFC 4998 evidence records for a sealed capsule: noqtis.ers beside the
 * seal, an EvidenceRecord whose one data object is the seal file
 * (noqtis.sig, byte for byte). The seal's signature and the manifest it
 * covers bind the files; the record keeps the seal provably in existence
 * at the time of its first archive timestamp after that timestamp's TSA
 * certificate expires (timestamp renewal: a new timestamp over the last
 * one, in the same chain) or its hash weakens (hash-tree renewal: a new
 * chain whose first timestamp covers the seal and every chain before,
 * with another hash).
 *
 * What noqtis writes: version 1, digestAlgorithms, no cryptoInfos or
 * encryptionInfo, and archive timestamps that hold only their timeStamp,
 * an RFC 3161 token whose imprint is the hash itself (RFC 4998, 4.2: no
 * hash tree is needed for one object). What it reads, beyond that: the
 * digestAlgorithm, attributes (not used), reducedHashtree and
 * cryptoInfos (kept, not used) fields; encryptionInfo is NQENOSUP. The
 * hashes are SHA-256, SHA-384 and SHA-512, those the token reader takes.
 *
 * A hash-tree renewal's leaf is H(h(d) + ha), RFC 4998 5.2 step 4, with
 * ha the hash of the DER ArchiveTimeStampSequence of the chains before;
 * noqtis writes the two values in binary ascending order, as the RFC's
 * figure 4 and its hash trees do, and reads either order, and ha also
 * over the chains without the SEQUENCE header, for the readings other
 * implementations have taken of the text. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cap/cap.h"
#include "core/int.h"
#include "der/der.h"
#include "der/tsp.h"
#include "der/x509.h"

#define ERSN 64  /* archive timestamps in one record */
#define ERSL 32  /* lists in one reduced hash tree */
#define ERSH 256 /* hashes in one list */

typedef struct {
  nqspan ts;   /* the timeStamp element (a ContentInfo) */
  nqspan rht;  /* the reducedHashtree contents, when hasrht */
  int hasrht;
  nqhalg alg;  /* digestAlgorithm, else the token's imprint hash */
  int chain;   /* the chain it is in, from 0 */
  int first;   /* the first of its chain */
  int64_t gt;  /* the token's genTime */
  nqspan imp;  /* its imprint */
} ats;

typedef struct {
  unsigned algs;   /* digestAlgorithms: 1 SHA-256, 2 SHA-384, 4 SHA-512 */
  nqspan cinfo;    /* the [0] cryptoInfos element, or empty */
  nqspan seq;      /* the archiveTimeStampSequence element */
  nqspan ch[ERSN]; /* its chains */
  size_t nch;
  ats a[ERSN];
  size_t na;
} ers;

static unsigned abit(nqhalg h) {
  return h == NQS256 ? 1u : h == NQS384 ? 2u : h == NQS512 ? 4u : 0u;
}

/* Parses the record (n bytes) strictly; ts is scratch for the tokens. */
static int ersprs(const uint8_t *p, size_t n, ers *e, nqts *ts,
                  const char **why) {
  nqdtlv top, t, u, v, w;
  nqdcur c, d, f, g;
  int got, rc;
  memset(e, 0, sizeof *e);
  *why = "noqtis.ers is not a DER EvidenceRecord (RFC 4998)";
  rc = nqdone(p, n, &top);
  if (rc != NQOK) return rc == NQELIM ? rc : NQEDEC;
  if (top.cls != NQDUNI || top.tag != NQDSEQ || nqddown(&top, &c) != NQOK)
    return NQEDEC;
  if (nqdget(&c, NQDUNI, 0, NQDINT, &t) != NQOK || t.v.n != 1 ||
      t.v.p[0] != 1) {
    *why = "noqtis.ers is not an EvidenceRecord of version 1";
    return NQEDEC;
  }
  if (nqdget(&c, NQDUNI, 1, NQDSEQ, &t) != NQOK || nqddown(&t, &d) != NQOK ||
      nqdend(&d))
    return NQEDEC;
  while (!nqdend(&d)) {
    nqhalg h;
    unsigned b;
    if (nqdnext(&d, &u) != NQOK) return NQEDEC;
    rc = nqxhalg(&u, 0, &h);
    if (rc == NQENOSUP) {
      *why = "the evidence record uses a hash noqtis does not take (it "
             "takes SHA-256, SHA-384 and SHA-512)";
      return rc;
    }
    b = rc == NQOK ? abit(h) : 0;
    if (b == 0 || (e->algs & b) != 0) return NQEDEC;
    e->algs |= b;
  }
  if (nqdopt(&c, NQDCTX, 1, 0, &t, &got) != NQOK) return NQEDEC;
  if (got) e->cinfo = t.raw;
  if (nqdopt(&c, NQDCTX, 1, 1, &t, &got) != NQOK) return NQEDEC;
  if (got) {
    *why = "the evidence record is of encrypted data (encryptionInfo), "
           "which noqtis does not handle";
    return NQENOSUP;
  }
  if (nqdget(&c, NQDUNI, 1, NQDSEQ, &t) != NQOK || nqddone(&c) != NQOK ||
      nqddown(&t, &d) != NQOK || nqdend(&d))
    return NQEDEC;
  e->seq = t.raw;
  while (!nqdend(&d)) {
    int first = 1;
    if (nqdget(&d, NQDUNI, 1, NQDSEQ, &u) != NQOK || nqddown(&u, &f) != NQOK ||
        nqdend(&f))
      return NQEDEC;
    if (e->nch == ERSN) return NQELIM;
    e->ch[e->nch] = u.raw;
    while (!nqdend(&f)) {
      ats *a;
      if (e->na == ERSN) return NQELIM;
      a = &e->a[e->na];
      if (nqdget(&f, NQDUNI, 1, NQDSEQ, &v) != NQOK ||
          nqddown(&v, &g) != NQOK)
        return NQEDEC;
      a->chain = (int)e->nch;
      a->first = first;
      first = 0;
      a->alg = (nqhalg)0;
      if (nqdopt(&g, NQDCTX, 1, 0, &w, &got) != NQOK) return NQEDEC;
      if (got) {
        nqdtlv x = w; /* [0] IMPLICIT AlgorithmIdentifier */
        x.cls = NQDUNI;
        x.tag = NQDSEQ;
        rc = nqxhalg(&x, 0, &a->alg);
        if (rc != NQOK || abit(a->alg) == 0) {
          *why = "an archive timestamp uses a hash noqtis does not take";
          return rc == NQEDEC ? NQEDEC : NQENOSUP;
        }
      }
      if (nqdopt(&g, NQDCTX, 1, 1, &w, &got) != NQOK) return NQEDEC;
      if (nqdopt(&g, NQDCTX, 1, 2, &w, &got) != NQOK) return NQEDEC;
      if (got) {
        a->hasrht = 1;
        a->rht = w.v;
      }
      if (nqdget(&g, NQDUNI, 1, NQDSEQ, &w) != NQOK || nqddone(&g) != NQOK)
        return NQEDEC;
      a->ts = w.raw;
      rc = nqtsprs(w.raw.p, w.raw.n, ts);
      if (rc != NQOK || ts->status != -1) {
        *why = "an archive timestamp's timeStamp is not an RFC 3161 token "
               "in the form noqtis reads";
        return rc == NQEMEM ? rc : NQEDEC;
      }
      if (a->alg == 0) a->alg = ts->ialg;
      a->gt = ts->gt;
      a->imp = ts->imp;
      e->na++;
    }
    e->nch++;
  }
  *why = NULL;
  return NQOK;
}

/* the bytes of a span compared as unsigned, for the binary ascending
 * order of RFC 4998 (all of one length here) */
static int lt(const uint8_t *a, const uint8_t *b, size_t n) {
  return memcmp(a, b, n) < 0;
}

/* H over the k values v[0..k) of hl bytes each, in binary ascending order */
static int hsort(nqhalg h, const uint8_t **v, size_t k, size_t hl,
                 uint8_t *out) {
  nqhctx x;
  size_t i, j;
  int rc;
  for (i = 1; i < k; i++) { /* insertion sort: at most ERSH + 1 values */
    const uint8_t *t = v[i];
    for (j = i; j > 0 && lt(t, v[j - 1], hl); j--) v[j] = v[j - 1];
    v[j] = t;
  }
  rc = nqhini(&x, h);
  for (i = 0; rc == NQOK && i < k; i++) rc = nqhupd(&x, v[i], hl);
  if (rc == NQOK) rc = nqhfin(&x, out, hl);
  return rc;
}

/* The root that a's reduced hash tree gives over the leaf h (hl bytes):
 * h itself without a tree; else h must be in the first list, and each
 * list's sorted values hashed, that hash joining the next list. */
static int root(const ats *a, const uint8_t *h, size_t hl, uint8_t *out) {
  const uint8_t *v[ERSH + 1];
  uint8_t cur[64];
  nqdcur c, d;
  nqdtlv t, u;
  size_t lists = 0, k;
  int found;
  if (!a->hasrht) {
    memcpy(out, h, hl);
    return NQOK;
  }
  nqdinit(&c, a->rht.p, a->rht.n);
  if (nqdend(&c)) return NQEDEC;
  while (!nqdend(&c)) {
    if (++lists > ERSL) return NQELIM;
    if (nqdget(&c, NQDUNI, 1, NQDSEQ, &t) != NQOK || nqddown(&t, &d) != NQOK)
      return NQEDEC;
    k = 0;
    found = 0;
    if (lists > 1) v[k++] = cur;
    while (!nqdend(&d)) {
      if (nqdget(&d, NQDUNI, 0, NQDOCT, &u) != NQOK || u.v.n != hl)
        return NQEDEC;
      if (k == ERSH + 1) return NQELIM;
      if (lists == 1 && memcmp(u.v.p, h, hl) == 0) found = 1;
      v[k++] = u.v.p;
    }
    if (k == 0 || (lists == 1 && !found)) return NQEVRFY;
    if (hsort(a->alg, v, k, hl, cur) != NQOK) return NQEARG;
  }
  memcpy(out, cur, hl);
  return NQOK;
}

/* the DER header of tag and n content bytes to p, at most 6 bytes; a
 * length of 2^32 or more is never written (records are at most
 * NQCERSMAX), so 4 length bytes are enough. No loop: GCC 14 vectorises
 * one into a store it then warns overflows the buffer. */
static size_t hdr(uint8_t *p, uint8_t tag, size_t n) {
  p[0] = tag;
  if (n < 0x80) {
    p[1] = (uint8_t)n;
    return 2;
  }
  if (n < 0x100) {
    p[1] = 0x81;
    p[2] = (uint8_t)n;
    return 3;
  }
  if (n < 0x10000) {
    p[1] = 0x82;
    p[2] = (uint8_t)(n >> 8);
    p[3] = (uint8_t)n;
    return 4;
  }
  if (n < 0x1000000) {
    p[1] = 0x83;
    p[2] = (uint8_t)(n >> 16);
    p[3] = (uint8_t)(n >> 8);
    p[4] = (uint8_t)n;
    return 5;
  }
  p[1] = 0x84;
  p[2] = (uint8_t)(n >> 24);
  p[3] = (uint8_t)(n >> 16);
  p[4] = (uint8_t)(n >> 8);
  p[5] = (uint8_t)n;
  return 6;
}

/* The leaves a's imprint may stand on; *k of them, at most 4. */
static int leaves(const ers *e, size_t i, const uint8_t *sb, size_t sn,
                  uint8_t lv[4][64], size_t *k) {
  const ats *a = &e->a[i];
  size_t hl = nqhlen(a->alg);
  uint8_t hd[64], ha[2][64];
  int rc;
  *k = 0;
  if (!a->first) /* timestamp renewal: the timestamp before */
    return nqhash(a->alg, e->a[i - 1].ts.p, e->a[i - 1].ts.n, lv[(*k)++],
                  hl);
  rc = nqhash(a->alg, sb, sn, hd, hl);
  if (rc != NQOK || a->chain == 0) {
    if (rc == NQOK) memcpy(lv[(*k)++], hd, hl);
    return rc;
  }
  {
    /* hash-tree renewal: the seal and the chains before it */
    const uint8_t *p0 = e->ch[0].p;
    const nqspan *l = &e->ch[a->chain - 1];
    size_t pn = (size_t)(l->p + l->n - p0), j, m;
    uint8_t hb[6];
    nqhctx x;
    m = hdr(hb, 0x30, pn);
    rc = nqhini(&x, a->alg);
    if (rc == NQOK) rc = nqhupd(&x, hb, m);
    if (rc == NQOK) rc = nqhupd(&x, p0, pn);
    if (rc == NQOK) rc = nqhfin(&x, ha[0], hl);
    if (rc == NQOK) rc = nqhash(a->alg, p0, pn, ha[1], hl);
    for (j = 0; rc == NQOK && j < 2; j++) {
      const uint8_t *v[2];
      v[0] = hd;
      v[1] = ha[j];
      rc = hsort(a->alg, v, 2, hl, lv[(*k)++]);
      if (rc == NQOK) {
        uint8_t cat[128];
        memcpy(cat, hd, hl);
        memcpy(cat + hl, ha[j], hl);
        rc = nqhash(a->alg, cat, 2 * hl, lv[(*k)++], hl);
      }
    }
  }
  return rc;
}

/* Checks the record against the seal bytes: its hashes and order, each
 * hash link, and each token's signature, with anchors on a path valid at
 * its genTime and at the next one's (the last: at now), or, with no
 * anchors and self, each token alone (nqtsvrf's self). */
static int ersvrf(const ers *e, const uint8_t *sb, size_t sn,
                  const nqcert *anc, size_t nanc, int self, int64_t now,
                  nqts *ts, const char **why) {
  unsigned used = 0;
  size_t i, j, k, hl;
  uint8_t lv[4][64], r[64];
  int ok, rc;
  for (i = 0; i < e->na; i++) {
    const ats *a = &e->a[i];
    used |= abit(a->alg);
    if (!a->first && a->alg != e->a[i - 1].alg) {
      *why = "the archive timestamps of one chain use different hashes";
      return NQEVRFY;
    }
    if (i > 0 && a->gt < e->a[i - 1].gt) {
      *why = "the archive timestamps are not in the order of their times";
      return NQEVRFY;
    }
  }
  if (used != e->algs) {
    *why = "digestAlgorithms is not the set of hashes the record uses";
    return NQEVRFY;
  }
  for (i = 0; i < e->na; i++) {
    const ats *a = &e->a[i];
    hl = nqhlen(a->alg);
    if (a->imp.n != hl) {
      *why = "an archive timestamp's hash tree and token use different "
             "hashes";
      return NQEVRFY;
    }
    rc = leaves(e, i, sb, sn, lv, &k);
    if (rc != NQOK) return rc;
    ok = 0;
    for (j = 0; j < k && !ok; j++) {
      rc = root(a, lv[j], hl, r);
      if (rc == NQEDEC || rc == NQELIM) {
        *why = "a reduced hash tree is malformed";
        return rc;
      }
      ok = rc == NQOK && memcmp(r, a->imp.p, hl) == 0;
    }
    if (!ok) {
      *why = i == 0 ? "the first archive timestamp is not over this seal"
             : a->first
                 ? "a hash-tree renewal is not over this seal and the "
                   "chains before it"
                 : "a timestamp renewal is not over the timestamp before it";
      return NQEVRFY;
    }
  }
  for (i = 0; i < e->na; i++) {
    const ats *a = &e->a[i];
    nqtsarg ta;
    int pass;
    memset(&ta, 0, sizeof ta);
    ta.halg = a->alg;
    ta.dig = a->imp.p;
    ta.diglen = a->imp.n;
    ta.ops = nqcxops();
    if (nanc == 0) {
      if (!self) break;
      ta.self = 1;
      rc = nqtsvrf(a->ts.p, a->ts.n, &ta, ts);
      if (rc != NQOK) {
        *why = "an archive timestamp's token does not verify";
        return rc == NQEMEM ? rc : NQEVRFY;
      }
      continue;
    }
    ta.anc = anc;
    ta.nanc = nanc;
    for (pass = 0; pass < 2; pass++) {
      ta.uset = pass;
      ta.t = i + 1 < e->na ? e->a[i + 1].gt : now;
      rc = nqtsvrf(a->ts.p, a->ts.n, &ta, ts);
      if (rc != NQOK) {
        *why = pass == 0 ? "an archive timestamp's token does not verify "
                           "under the TSA anchors"
               : i + 1 < e->na
                   ? "an archive timestamp was renewed after its TSA "
                     "certificate stopped being valid"
                   : "the last archive timestamp's TSA certificate is not "
                     "valid now: the record needed renewing before";
        return rc == NQEMEM ? rc : NQEVRFY;
      }
    }
  }
  *why = NULL;
  return NQOK;
}

/* the anchors, parsed; NQEARG when one is not a certificate */
static int ancprs(const uint8_t *const *anc, const size_t *anclen,
                  size_t nanc, nqcert **c) {
  size_t i;
  *c = NULL;
  if (nanc == 0) return NQOK;
  if (nanc > NQCANC) return NQELIM;
  *c = (nqcert *)nqmal(nanc * sizeof(nqcert));
  if (*c == NULL) return NQEMEM;
  for (i = 0; i < nanc; i++) {
    if (anc[i] == NULL || anclen[i] == 0 ||
        nqcprsa(anc[i], anclen[i], &(*c)[i]) != NQOK)
      return NQEARG;
  }
  return NQOK;
}

/* what a request or a reply works on: the seal, the record there (when
 * one is), and the hash the next archive timestamp is over */
typedef struct {
  char *sb, *eb;
  size_t sn, en;
  ers *e;
  nqts *ts;
  nqcert *c;
  size_t nanc;
  nqhalg h;
  int how;          /* 0 a new record, 1 timestamp, 2 hash-tree renewal */
  uint8_t dig[64];  /* the imprint wanted */
} work;

static void wfree(work *w) {
  if (w->sb != NULL) nqfree(w->sb, w->sn + 1);
  if (w->eb != NULL) nqfree(w->eb, w->en + 1);
  nqfree(w->e, sizeof(ers));
  nqfree(w->ts, sizeof(nqts));
  nqfree(w->c, w->nanc * sizeof(nqcert));
  memset(w, 0, sizeof *w);
}

/* Reads the seal and any record, checks the record (with anchors, or
 * each token alone), and finds what the next archive timestamp covers
 * with hash h (0: the last chain's, SHA-256 for a new record). */
static int wopen(work *w, const char *dir, nqhalg h,
                 const uint8_t *const *anc, const size_t *anclen,
                 size_t nanc, const char **why) {
  int rc;
  memset(w, 0, sizeof *w);
  if (h != 0 && abit(h) == 0) return NQENOSUP;
  w->e = (ers *)nqmal(sizeof(ers));
  w->ts = (nqts *)nqmal(sizeof(nqts));
  if (w->e == NULL || w->ts == NULL) return NQEMEM;
  w->nanc = nanc;
  rc = ancprs(anc, anclen, nanc, &w->c);
  if (rc != NQOK) {
    *why = rc == NQEARG ? "a TSA anchor is not a DER X.509 certificate"
                        : NULL;
    return rc;
  }
  *why = "cannot read noqtis.sig";
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &w->sb, &w->sn);
  if (rc != NQOK) return rc;
  if (!nqchas(dir, NQCERS)) {
    w->how = 0;
    w->h = h != 0 ? h : NQS256;
    *why = NULL;
    return nqhash(w->h, (const uint8_t *)w->sb, w->sn, w->dig,
                  nqhlen(w->h));
  }
  *why = "cannot read noqtis.ers";
  rc = nqcread(dir, NQCERS, NQCERSMAX, &w->eb, &w->en);
  if (rc != NQOK) return rc;
  rc = ersprs((const uint8_t *)w->eb, w->en, w->e, w->ts, why);
  if (rc != NQOK) return rc;
  rc = ersvrf(w->e, (const uint8_t *)w->sb, w->sn, w->c, nanc, 1,
              (int64_t)time(NULL), w->ts, why);
  if (rc != NQOK) return rc;
  {
    const ats *l = &w->e->a[w->e->na - 1];
    w->h = h != 0 ? h : l->alg;
    if (w->h == l->alg) {
      w->how = 1;
      return nqhash(w->h, l->ts.p, l->ts.n, w->dig, nqhlen(w->h));
    }
  }
  {
    /* a new chain: H(sorted(H(seal), H(the chains so far))) */
    size_t hl = nqhlen(w->h);
    uint8_t hd[64], ha[64];
    const uint8_t *v[2];
    w->how = 2;
    rc = nqhash(w->h, (const uint8_t *)w->sb, w->sn, hd, hl);
    if (rc == NQOK)
      rc = nqhash(w->h, w->e->seq.p, w->e->seq.n, ha, hl);
    v[0] = hd;
    v[1] = ha;
    if (rc == NQOK) rc = hsort(w->h, v, 2, hl, w->dig);
    return rc;
  }
}

int nqersreq(const char *dir, nqhalg h, const uint8_t *nonce,
             size_t noncelen, uint8_t *req, size_t reqlen, size_t *outlen,
             const char **why) {
  const char *wy = NULL;
  work w;
  int rc;
  if (why == NULL) why = &wy;
  *why = NULL;
  if (outlen != NULL) *outlen = 0;
  if (dir == NULL || req == NULL || outlen == NULL ||
      (nonce == NULL && noncelen != 0) || noncelen > 32)
    return NQEARG;
  rc = wopen(&w, dir, h, NULL, NULL, 0, why);
  if (rc == NQOK)
    rc = nqtsmk(w.h, w.dig, nonce, noncelen, req, reqlen, outlen);
  wfree(&w);
  return rc;
}

static void put(uint8_t *o, size_t *n, const void *p, size_t k) {
  memcpy(o + *n, p, k);
  *n += k;
}

/* The record with tok (a ContentInfo) as its next archive timestamp, to
 * a fresh buffer *out of *on bytes. */
static int build(const work *w, const nqspan *tok, uint8_t **out,
                 size_t *on) {
  static const uint8_t ver[] = {0x02, 0x01, 0x01};
  static const uint8_t aid[3][15] = {
      {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
       0x02, 0x01, 0x05, 0x00},
      {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
       0x02, 0x02, 0x05, 0x00},
      {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
       0x02, 0x03, 0x05, 0x00}};
  const ers *e = w->how == 0 ? NULL : w->e;
  unsigned algs = (e != NULL ? e->algs : 0) | abit(w->h);
  uint8_t hb[6];
  size_t atsn, lastn = 0, chn, seqn, dan = 0, body, cap, n = 0, i, keep = 0;
  uint8_t *o;
  /* the new archive timestamp: SEQUENCE { timeStamp } */
  atsn = hdr(hb, 0x30, tok->n) + tok->n;
  if (w->how == 1) { /* into the last chain */
    const nqspan *l = &e->ch[e->nch - 1];
    nqdtlv t;
    if (nqdhdr(l->p, l->n, &t) != NQOK) return NQEDEC;
    lastn = t.v.n;
    chn = lastn + atsn;
    keep = e->nch - 1;
  } else {
    chn = atsn;
    keep = e != NULL ? e->nch : 0;
  }
  seqn = hdr(hb, 0x30, chn) + chn;
  for (i = 0; i < keep; i++) seqn += e->ch[i].n;
  for (i = 0; i < 3; i++)
    if (algs & (1u << i)) dan += sizeof aid[0];
  body = sizeof ver + hdr(hb, 0x30, dan) + dan +
         (e != NULL ? e->cinfo.n : 0) + hdr(hb, 0x30, seqn) + seqn;
  cap = body + 6;
  if (cap > NQCERSMAX) return NQELIM;
  o = (uint8_t *)nqmal(cap);
  if (o == NULL) return NQEMEM;
  n += hdr(o + n, 0x30, body);
  put(o, &n, ver, sizeof ver);
  n += hdr(o + n, 0x30, dan);
  for (i = 0; i < 3; i++)
    if (algs & (1u << i)) put(o, &n, aid[i], sizeof aid[0]);
  if (e != NULL && e->cinfo.n != 0) put(o, &n, e->cinfo.p, e->cinfo.n);
  n += hdr(o + n, 0x30, seqn);
  for (i = 0; i < keep; i++) put(o, &n, e->ch[i].p, e->ch[i].n);
  n += hdr(o + n, 0x30, chn);
  if (w->how == 1) {
    const nqspan *l = &e->ch[e->nch - 1];
    put(o, &n, l->p + (l->n - lastn), lastn);
  }
  n += hdr(o + n, 0x30, tok->n);
  put(o, &n, tok->p, tok->n);
  *out = o;
  *on = n;
  return NQOK;
}

/* strips leading zero octets of an INTEGER's contents and compares */
static int sameint(const uint8_t *a, size_t an, const uint8_t *b,
                   size_t bn) {
  while (an > 0 && a[0] == 0) {
    a++;
    an--;
  }
  while (bn > 0 && b[0] == 0) {
    b++;
    bn--;
  }
  return an == bn && memcmp(a, b, an) == 0;
}

int nqersput(const char *dir, nqhalg h, const uint8_t *rsp, size_t rsplen,
             const uint8_t *nonce, size_t noncelen,
             const uint8_t *const *anc, const size_t *anclen, size_t nanc,
             int64_t *gt, int *how, const char **why) {
  const char *wy = NULL;
  uint8_t *out = NULL;
  size_t on = 0, hl;
  nqtsarg ta;
  nqspan tok;
  work w;
  int rc;
  if (why == NULL) why = &wy;
  *why = NULL;
  if (gt != NULL) *gt = 0;
  if (how != NULL) *how = 0;
  if (dir == NULL || rsp == NULL || rsplen == 0 ||
      (nonce == NULL && noncelen != 0) ||
      (nanc != 0 && (anc == NULL || anclen == NULL)))
    return NQEARG;
  rc = wopen(&w, dir, h, anc, anclen, nanc, why);
  if (rc != NQOK) goto out; /* a record that does not check is not extended */
  rc = nqtsprs(rsp, rsplen, w.ts);
  if (rc == NQEVRFY && w.ts->status > 1) {
    *why = "the TSA did not grant the request (PKIStatus not 0 or 1)";
    goto out;
  }
  if (rc != NQOK) {
    *why = "the reply is not an RFC 3161 TimeStampResp or token in the "
           "form noqtis reads";
    rc = rc == NQEMEM ? rc : NQEVRFY;
    goto out;
  }
  hl = nqhlen(w.h);
  if (w.ts->ialg != w.h || w.ts->imp.n != hl ||
      memcmp(w.ts->imp.p, w.dig, hl) != 0) {
    *why = "the token's imprint is not the hash the request asked for";
    rc = NQEVRFY;
    goto out;
  }
  if (nonce != NULL &&
      (!w.ts->hasnonce ||
       !sameint(nonce, noncelen, w.ts->nonce.p, w.ts->nonce.n))) {
    *why = "the token's nonce is not the request's";
    rc = NQEVRFY;
    goto out;
  }
  if (w.how != 0 && w.ts->gt < w.e->a[w.e->na - 1].gt) {
    *why = "the token's genTime is before the record's last timestamp";
    rc = NQEVRFY;
    goto out;
  }
  memset(&ta, 0, sizeof ta);
  ta.halg = w.h;
  ta.dig = w.dig;
  ta.diglen = hl;
  ta.ops = nqcxops();
  ta.self = nanc == 0;
  ta.anc = w.c;
  ta.nanc = nanc;
  rc = nqtsvrf(rsp, rsplen, &ta, w.ts);
  if (rc != NQOK) {
    *why = nanc == 0
               ? "the token's signature or TSA certificate does not verify"
               : "the token does not verify under the TSA anchors";
    rc = rc == NQEMEM ? rc : NQEVRFY;
    goto out;
  }
  tok = w.ts->tok;
  rc = build(&w, &tok, &out, &on);
  if (rc == NQOK) {
    /* what is written must read back and check as a record */
    ers *e2 = (ers *)nqmal(sizeof(ers));
    const char *w2 = NULL;
    if (e2 == NULL) {
      rc = NQEMEM;
    } else {
      rc = ersprs(out, on, e2, w.ts, &w2);
      if (rc == NQOK)
        rc = ersvrf(e2, (const uint8_t *)w.sb, w.sn, w.c, nanc, 1,
                    (int64_t)time(NULL), w.ts, &w2);
      if (rc == NQOK && gt != NULL) *gt = e2->a[e2->na - 1].gt;
      nqfree(e2, sizeof(ers));
    }
    if (rc != NQOK) {
      *why = "the new record does not check (an internal error)";
      rc = NQEARG;
    }
  }
  if (rc == NQOK) {
    rc = nqcwrite(dir, NQCERS, (const char *)out, on);
    if (rc != NQOK) *why = "cannot write noqtis.ers";
  }
  if (rc == NQOK && how != NULL) *how = w.how;
out:
  if (out != NULL) nqfree(out, on);
  wfree(&w);
  return rc;
}

int nqcersck(const char *dir, const uint8_t *const *anc,
             const size_t *anclen, size_t nanc, int *present, char *msg,
             size_t cap) {
  const char *why = NULL;
  work w;
  int rc;
  char t[21];
  *present = 0;
  if (cap != 0) msg[0] = 0;
  if (dir == NULL || !nqchas(dir, NQCERS)) return NQOK;
  *present = 1;
  memset(&w, 0, sizeof w);
  w.e = (ers *)nqmal(sizeof(ers));
  w.ts = (nqts *)nqmal(sizeof(nqts));
  if (w.e == NULL || w.ts == NULL) {
    rc = NQEMEM;
    goto out;
  }
  w.nanc = nanc;
  rc = ancprs(anc, anclen, nanc, &w.c);
  if (rc != NQOK) {
    if (rc != NQEMEM) {
      snprintf(msg, cap, "a TSA anchor is not a certificate");
      rc = NQEVRFY;
    }
    goto out;
  }
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &w.sb, &w.sn);
  if (rc == NQOK) rc = nqcread(dir, NQCERS, NQCERSMAX, &w.eb, &w.en);
  if (rc != NQOK) {
    if (rc != NQEMEM) {
      snprintf(msg, cap, "cannot read noqtis.ers or noqtis.sig: %s",
               nqerr(rc));
      rc = NQEVRFY;
    }
    goto out;
  }
  rc = ersprs((const uint8_t *)w.eb, w.en, w.e, w.ts, &why);
  if (rc == NQOK)
    rc = ersvrf(w.e, (const uint8_t *)w.sb, w.sn, w.c, nanc, 0,
                (int64_t)time(NULL), w.ts, &why);
  if (rc == NQEMEM) goto out;
  if (rc != NQOK) {
    snprintf(msg, cap, "RFC 4998 evidence record: %s",
             why != NULL ? why : nqerr(rc));
    rc = NQEVRFY;
    goto out;
  }
  if (nqctime(w.e->a[0].gt, t) != NQOK) memcpy(t, "out of range", 13);
  if (nanc == 0) {
    snprintf(msg, cap, "RFC 4998 evidence record not checked: no TSA "
             "trust anchors given (its %u archive timestamps are linked "
             "to this seal)", (unsigned)w.e->na);
    rc = NQEVRFY;
    goto out;
  }
  snprintf(msg, cap, "RFC 4998 evidence record verifies under a TSA "
           "anchor: the seal existed at %s; %u archive timestamps in %u "
           "chains, the last valid now", t, (unsigned)w.e->na,
           (unsigned)w.e->nch);
  rc = NQOK;
out:
  wfree(&w);
  return rc;
}
