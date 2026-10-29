/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqtsreq and nqtsput: the RFC 3161 request over a seal's signature, and
 * the TSA's reply checked and stored as the seal's "timestamp". The
 * library makes no network request: the caller (the CLI) sends the
 * request and hands back the reply. */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "der/tsp.h"

/* the seal in dir, canonical and with only noqtis-seal-1 fields */
typedef struct {
  nqjs *v;
  uint8_t *sig;
  size_t sign;
  size_t cap;
} rseal;

static void rsfree(rseal *s) {
  nqjfree(s->v);
  nqfree(s->sig, s->cap);
  memset(s, 0, sizeof *s);
}

static const char *const fld[] = {"alg",        "context",
                                  "format",     "manifest_sha256",
                                  "public_key", "signature",
                                  "timestamp"};

static int rdseal(const char *dir, rseal *s, const char **why) {
  char *b = NULL;
  size_t n = 0, i, j;
  nqcbuf c;
  nqsalg alg;
  nqssz sz;
  const nqjs *sg, *a;
  int rc;
  memset(s, 0, sizeof *s);
  *why = "cannot read noqtis.sig";
  rc = nqcread(dir, NQCSIG, NQCSIGMAX, &b, &n);
  if (rc != NQOK) return rc;
  *why = "noqtis.sig is not a canonical noqtis-seal-1 seal";
  rc = nqjparse(b, n, &s->v, NULL);
  if (rc == NQOK && s->v->type != NQJOBJ) rc = NQEDEC;
  if (rc == NQOK) {
    memset(&c, 0, sizeof c);
    rc = nqcjval(&c, s->v);
    if (rc == NQOK && (c.n != n || memcmp(c.p, b, n) != 0)) rc = NQEDEC;
    nqcbfree(&c);
  }
  nqfree(b, n + 1);
  if (rc != NQOK) return rc;
  for (i = 0; i < s->v->n; i++) {
    for (j = 0; j < 7; j++) {
      if (s->v->klen[i] == strlen(fld[j]) &&
          memcmp(s->v->keys[i], fld[j], s->v->klen[i]) == 0) {
        break;
      }
    }
    if (j == 7 || s->v->kids[i]->type != NQJSTR ||
        memchr(s->v->kids[i]->str, 0, s->v->kids[i]->len) != NULL) {
      return NQEDEC;
    }
  }
  for (j = 0; j < 6; j++) {
    if (nqjget(s->v, fld[j]) == NULL) return NQEDEC;
  }
  a = nqjget(s->v, "alg");
  sg = nqjget(s->v, "signature");
  if (nqsfind(a->str, &alg) != NQOK || nqssize(alg, &sz) != NQOK) {
    return NQEDEC;
  }
  s->cap = sz.sig;
  s->sig = (uint8_t *)nqmal(s->cap);
  if (s->sig == NULL) return NQEMEM;
  if (nqb64d(sg->str, sg->len, s->sig, s->cap, &s->sign) != NQOK ||
      s->sign != sz.sig) {
    return NQEDEC;
  }
  *why = NULL;
  return NQOK;
}

/* the DER of a length, at p (room for 3 bytes); its size */
static size_t dlen(uint8_t *p, size_t n) {
  if (n < 0x80) {
    p[0] = (uint8_t)n;
    return 1;
  }
  p[0] = 0x81;
  p[1] = (uint8_t)n;
  return 2;
}

/* SHA-256, with NULL parameters as RFC 5754 says senders should */
static const uint8_t sha256id[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                   0x01, 0x05, 0x00};

int nqtsreq(const char *dir, const uint8_t *nonce, size_t noncelen,
            uint8_t *req, size_t reqlen, size_t *outlen) {
  uint8_t d[32], b[128];
  size_t n = 0, body, i = 0;
  const char *why;
  rseal s;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (dir == NULL || req == NULL || outlen == NULL ||
      (nonce == NULL && noncelen != 0) || noncelen > 32) {
    return NQEARG;
  }
  /* a nonce is an INTEGER: no redundant leading zero, and positive */
  while (noncelen > 1 && nonce[0] == 0) {
    nonce++;
    noncelen--;
  }
  rc = rdseal(dir, &s, &why);
  if (rc == NQOK) rc = nqhash(NQS256, s.sig, s.sign, d, 32);
  rsfree(&s);
  if (rc != NQOK) return rc;
  /* TimeStampReq ::= SEQUENCE { version 1, messageImprint, nonce,
   * certReq TRUE } */
  body = 3 + 2 + sizeof sha256id + 2 + 32 + 3;
  if (nonce != NULL) body += 2 + noncelen + (nonce[0] & 0x80 ? 1 : 0);
  b[n++] = 0x30;
  n += dlen(b + n, body);
  b[n++] = 0x02;
  b[n++] = 0x01;
  b[n++] = 0x01;
  b[n++] = 0x30;
  b[n++] = (uint8_t)(sizeof sha256id + 2 + 32);
  memcpy(b + n, sha256id, sizeof sha256id);
  n += sizeof sha256id;
  b[n++] = 0x04;
  b[n++] = 32;
  memcpy(b + n, d, 32);
  n += 32;
  if (nonce != NULL) {
    b[n++] = 0x02;
    b[n++] = (uint8_t)(noncelen + (nonce[0] & 0x80 ? 1 : 0));
    if (nonce[0] & 0x80) b[n++] = 0;
    for (i = 0; i < noncelen; i++) b[n++] = nonce[i];
  }
  b[n++] = 0x01;
  b[n++] = 0x01;
  b[n++] = 0xff;
  if (n > reqlen) return NQEBUF;
  memcpy(req, b, n);
  *outlen = n;
  return NQOK;
}

/* strips leading zero octets of an INTEGER's contents */
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

/* noqtis.sig again, its fields in order, with "timestamp" set to tok */
static int wrseal(const char *dir, const rseal *s, const uint8_t *tok,
                  size_t tn) {
  size_t bn = nqb64n(tn) + 1, j;
  char *b = (char *)nqmal(bn);
  nqcbuf o;
  int rc;
  if (b == NULL) return NQEMEM;
  nqb64e(tok, tn, b);
  memset(&o, 0, sizeof o);
  nqcput(&o, "{", 1);
  for (j = 0; j < 6; j++) {
    const nqjs *v = nqjget(s->v, fld[j]);
    if (j > 0) nqcput(&o, ",", 1);
    nqcjstr(&o, fld[j], strlen(fld[j]));
    nqcput(&o, ":", 1);
    nqcjstr(&o, v->str, v->len);
  }
  nqcputs(&o, ",\"timestamp\":");
  nqcjstr(&o, b, strlen(b));
  nqcput(&o, "}", 1);
  nqfree(b, bn);
  rc = o.err;
  if (rc == NQOK && o.n > NQCSIGMAX) rc = NQELIM;
  if (rc == NQOK) rc = nqcwrite(dir, NQCSIG, o.p, o.n);
  nqcbfree(&o);
  return rc;
}

/* whether a refused reply names SHA-1 (sha1, ecdsa-with-SHA1 or
 * sha1WithRSAEncryption), only to say why it was refused */
static int sha1(const uint8_t *b, size_t n) {
  static const uint8_t o[][12] = {
      {7, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A},
      {9, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01},
      {11, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
       0x05}};
  size_t k, i;
  for (k = 0; k < sizeof o / sizeof o[0]; k++) {
    size_t m = o[k][0];
    for (i = 0; i + m <= n; i++) {
      if (memcmp(b + i, o[k] + 1, m) == 0) return 1;
    }
  }
  return 0;
}

int nqtsput(const char *dir, const uint8_t *rsp, size_t rsplen,
            const uint8_t *nonce, size_t noncelen,
            const uint8_t *const *anc, const size_t *anclen, size_t nanc,
            int64_t *gt, const char **why) {
  const char *w = NULL;
  nqcert *c = NULL;
  nqts *ts = NULL;
  uint8_t d[64];
  size_t dl = 0, i;
  nqtsarg ta;
  rseal s;
  int rc;
  if (why == NULL) why = &w;
  *why = NULL;
  if (gt != NULL) *gt = 0;
  memset(&s, 0, sizeof s);
  if (dir == NULL || rsp == NULL || rsplen == 0 ||
      (nonce == NULL && noncelen != 0) ||
      (nanc != 0 && (anc == NULL || anclen == NULL))) {
    return NQEARG;
  }
  if (nanc > NQCANC) return NQELIM;
  for (i = 0; i < nanc; i++) {
    if (anc[i] == NULL || anclen[i] == 0) return NQEARG;
  }
  ts = (nqts *)nqmal(sizeof(nqts));
  if (nanc != 0) c = (nqcert *)nqmal(nanc * sizeof(nqcert));
  if (ts == NULL || (nanc != 0 && c == NULL)) {
    rc = NQEMEM;
    goto out;
  }
  rc = rdseal(dir, &s, why);
  if (rc != NQOK) goto out;
  rc = nqtsprs(rsp, rsplen, ts);
  if (rc == NQEVRFY && ts->status > 1) {
    *why = "the TSA did not grant the request (PKIStatus not 0 or 1)";
    goto out;
  }
  if (rc != NQOK) {
    *why = sha1(rsp, rsplen)
               ? "the reply is signed with SHA-1, which noqtis does not "
                 "accept: use a TSA that signs with SHA-256 or stronger"
               : "the reply is not an RFC 3161 TimeStampResp or token in "
                 "the form noqtis reads";
    rc = rc == NQEMEM ? rc : NQEVRFY;
    goto out;
  }
  dl = nqhlen(ts->ialg);
  if (dl == 0 || dl > sizeof d || dl != ts->imp.n ||
      (ts->ialg != NQS256 && ts->ialg != NQS384 && ts->ialg != NQS512) ||
      nqhash(ts->ialg, s.sig, s.sign, d, dl) != NQOK ||
      memcmp(d, ts->imp.p, dl) != 0) {
    *why = "the token's imprint is not the hash of this seal's signature";
    rc = NQEVRFY;
    goto out;
  }
  if (nonce != NULL &&
      (!ts->hasnonce ||
       !sameint(nonce, noncelen, ts->nonce.p, ts->nonce.n))) {
    *why = "the token's nonce is not the request's";
    rc = NQEVRFY;
    goto out;
  }
  for (i = 0; i < nanc; i++) {
    if (nqcprs(anc[i], anclen[i], &c[i]) != NQOK) {
      *why = "a TSA anchor is not a DER X.509 certificate";
      rc = NQEARG;
      goto out;
    }
  }
  memset(&ta, 0, sizeof ta);
  ta.halg = ts->ialg;
  ta.dig = d;
  ta.diglen = dl;
  ta.ops = nqcxops();
  ta.self = 1;
  rc = nqtsvrf(rsp, rsplen, &ta, ts);
  if (rc != NQOK) {
    *why = "the token's signature or TSA certificate does not verify";
    rc = rc == NQEMEM ? rc : NQEVRFY;
    goto out;
  }
  if (nanc != 0) {
    ta.self = 0;
    ta.anc = c;
    ta.nanc = nanc;
    rc = nqtsvrf(rsp, rsplen, &ta, ts);
    if (rc != NQOK) {
      *why = "the TSA certificate has no valid path to a given anchor";
      rc = rc == NQEMEM ? rc : NQEVRFY;
      goto out;
    }
  }
  rc = wrseal(dir, &s, ts->tok.p, ts->tok.n);
  if (rc != NQOK) {
    *why = "cannot write noqtis.sig";
    goto out;
  }
  if (gt != NULL) *gt = ts->gt;
out:
  rsfree(&s);
  nqfree(ts, sizeof(nqts));
  nqfree(c, nanc * sizeof(nqcert));
  return rc;
}
