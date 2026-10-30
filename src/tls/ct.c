/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Certificate Transparency (RFC 6962) for the TLS 1.3 client, opt-in: a
 * log list goes stale, so nothing is checked until the caller gives one
 * (nqtlct, in the form of Chrome's log_list.json v3). Then the client
 * offers signed_certificate_timestamp and needs the server's leaf to
 * carry SCTs, embedded (the SCT list extension: precert entries over its
 * TBSCertificate without that extension, with the SHA-256 of the
 * issuer's key) or in the TLS extension (x509 entries over the leaf).
 *
 * An SCT counts when its log is in the list and was qualified, usable or
 * read-only, or retired after the SCT; the leaf's notAfter is in the
 * log's temporal interval, if it has one; the SCT is not from the future;
 * and its signature (ECDSA P-256 or RSA PKCS #1 v1.5, both SHA-256)
 * verifies. The leaf needs SCTs that count from logs of at least two
 * operators: the operator rule of Chrome's policy, without its rule on
 * the number of SCTs by lifetime. SCTs in an OCSP response are not
 * read. */
#include <stdio.h>
#include <string.h>

#include "cap/cap.h"
#include "cls/cls.h"
#include "core/int.h"
#include "core/json.h"
#include "tls/tls.h"

#define NLGMAX 4096 /* logs in a list */
#define NSCT 64     /* SCTs looked at, both places together */

/* ---- the log list ---- */

static int dig2(const char *s, int *v) {
  if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') return 0;
  *v = (s[0] - '0') * 10 + (s[1] - '0');
  return 1;
}

/* "YYYY-MM-DDTHH:MM:SS[.fff]Z" to seconds since the epoch */
static int when(const nqjs *v, int64_t *out) {
  const char *s = nqjstr(v);
  int y1, y2, mo, d, h, mi, se;
  int64_t y, era, yoe, doy, doe;
  size_t n, i = 19;
  if (s == NULL || (n = strlen(s)) < 20) return 0;
  if (!dig2(s, &y1) || !dig2(s + 2, &y2) || s[4] != '-' ||
      !dig2(s + 5, &mo) || s[7] != '-' || !dig2(s + 8, &d) ||
      (s[10] != 'T' && s[10] != 't') || !dig2(s + 11, &h) || s[13] != ':' ||
      !dig2(s + 14, &mi) || s[16] != ':' || !dig2(s + 17, &se)) {
    return 0;
  }
  if (s[i] == '.') {
    for (i++; i < n && s[i] >= '0' && s[i] <= '9'; i++) {
    }
  }
  if (i + 1 != n || (s[i] != 'Z' && s[i] != 'z')) return 0;
  y = y1 * 100 + y2;
  if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 ||
      mi > 59 || se > 60) {
    return 0;
  }
  /* days from the civil date (H. Hinnant's algorithm) */
  y -= mo <= 2;
  era = y / 400;
  yoe = y - era * 400;
  doy = (153 * (mo > 2 ? mo - 3 : mo + 9) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  *out = ((era * 146097 + doe - 719468) * 24 + h) * 3600 + mi * 60 + se;
  return 1;
}

/* the logs of operator o: its "logs" and "tiled_logs" */
static const nqjs *logs(const nqjs *o, int k) {
  const nqjs *l = nqjget(o, k == 0 ? "logs" : "tiled_logs");
  return l != NULL && l->type == NQJARR ? l : NULL;
}

/* one log into g, its key into t->lk at *used */
static int onelog(nqtls *t, const nqjs *l, size_t op, nqtlog *g,
                  size_t *used) {
  static const char *const sts[] = {"pending", "qualified", "usable",
                                    "readonly", "retired", "rejected"};
  const nqjs *id = nqjget(l, "log_id"), *key = nqjget(l, "key"),
             *st = nqjget(l, "state"), *ti = nqjget(l, "temporal_interval");
  const char *s;
  uint8_t h[32];
  size_t n = 0, i;
  if (l->type != NQJOBJ || nqjstr(id) == NULL || nqjstr(key) == NULL) {
    return NQEDEC;
  }
  memset(g, 0, sizeof *g);
  g->op = op;
  s = nqjstr(id);
  if (nqb64d(s, strlen(s), g->id, sizeof g->id, &n) != NQOK || n != 32) {
    return NQEDEC;
  }
  s = nqjstr(key);
  if (nqb64d(s, strlen(s), t->lk + *used, t->lkn - *used, &n) != NQOK ||
      n == 0) {
    return NQEDEC;
  }
  /* the log_id is the key's hash (RFC 6962 3.2) */
  if (nqhash(NQS256, t->lk + *used, n, h, 32) != NQOK ||
      memcmp(h, g->id, 32) != 0) {
    return NQEDEC;
  }
  g->key = *used;
  g->keyn = n;
  *used += n;
  /* the one state it is in, and since when; none known: not usable */
  if (st != NULL && st->type == NQJOBJ && st->n == 1) {
    for (i = 0; i < sizeof sts / sizeof sts[0]; i++) {
      if (st->klen[0] == strlen(sts[i]) &&
          memcmp(st->keys[0], sts[i], st->klen[0]) == 0) {
        if (!when(nqjget(st->kids[0], "timestamp"), &g->stt)) return NQEDEC;
        g->st = (int)i + 1;
      }
    }
  }
  if (ti != NULL) {
    if (!when(nqjget(ti, "start_inclusive"), &g->tis) ||
        !when(nqjget(ti, "end_exclusive"), &g->tie)) {
      return NQEDEC;
    }
    g->ti = 1;
  }
  return NQOK;
}

static void drop(nqtls *t) {
  if (t->lg != NULL) nqfree(t->lg, t->nlg * sizeof *t->lg);
  if (t->lk != NULL) nqfree(t->lk, t->lkn);
  t->lg = NULL;
  t->lk = NULL;
  t->nlg = 0;
  t->lkn = 0;
}

int nqtlctl(nqtls *t, const uint8_t *js, size_t n) {
  nqjs *root = NULL;
  const nqjs *ops, *o, *l;
  size_t i, j, cnt = 0, used = 0;
  int k, rc = NQOK;
  if (t == NULL || js == NULL || n == 0) return NQEARG;
  if (t->chn != 0) return NQESTATE;
  drop(t);
  if ((rc = nqjparse((const char *)js, n, &root, NULL)) != NQOK) return rc;
  ops = nqjget(root, "operators");
  if (ops == NULL || ops->type != NQJARR) {
    nqjfree(root);
    return NQEDEC;
  }
  for (i = 0; (o = nqjat(ops, i)) != NULL; i++) {
    for (k = 0; k < 2; k++) {
      if ((l = logs(o, k)) != NULL) cnt += l->n;
    }
  }
  if (cnt == 0 || cnt > NLGMAX) {
    nqjfree(root);
    return cnt == 0 ? NQEDEC : NQELIM;
  }
  /* the keys decode to fewer bytes than the text holds */
  t->lg = (nqtlog *)nqmal(cnt * sizeof *t->lg);
  t->lk = (uint8_t *)nqmal(n);
  if (t->lg == NULL || t->lk == NULL) {
    if (t->lg != NULL) nqfree(t->lg, cnt * sizeof *t->lg);
    if (t->lk != NULL) nqfree(t->lk, n);
    t->lg = NULL;
    t->lk = NULL;
    nqjfree(root);
    return NQEMEM;
  }
  t->nlg = cnt;
  t->lkn = n;
  cnt = 0;
  for (i = 0; rc == NQOK && (o = nqjat(ops, i)) != NULL; i++) {
    if (o->type != NQJOBJ) rc = NQEDEC;
    for (k = 0; rc == NQOK && k < 2; k++) {
      l = logs(o, k);
      for (j = 0; rc == NQOK && l != NULL && j < l->n; j++) {
        rc = onelog(t, l->kids[j], i, &t->lg[cnt++], &used);
      }
    }
  }
  nqjfree(root);
  if (rc != NQOK) drop(t);
  return rc;
}

/* ---- the SCTs ---- */

/* what one SCT came to */
enum { SOK, SUNK, SBAD, SOLD };

static uint64_t ld64(const uint8_t *p) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static void put24(nqfctx *c, size_t n) {
  uint8_t b[3];
  b[0] = (uint8_t)(n >> 16);
  b[1] = (uint8_t)(n >> 8);
  b[2] = (uint8_t)n;
  nqfupd(c, b, 3);
}

/* a DER header for tag and length n into b; its size */
static size_t hdr(uint8_t tag, size_t n, uint8_t *b) {
  size_t k = 0, i;
  b[0] = tag;
  if (n < 128) {
    b[1] = (uint8_t)n;
    return 2;
  }
  for (i = n; i > 0; i >>= 8) k++;
  b[1] = (uint8_t)(0x80 | k);
  for (i = 0; i < k; i++) b[2 + i] = (uint8_t)(n >> (8 * (k - 1 - i)));
  return 2 + k;
}

/* the precertificate's TBSCertificate (RFC 6962 3.2): the leaf's, its
 * SCT list extension taken out and the lengths made again, fed to c
 * after its 3-byte length; NQEDEC when its form is not the expected */
static int pretbs(const nqcert *leaf, nqfctx *c) {
  static const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x04, 0x01,
                                0xd6, 0x79, 0x02, 0x04, 0x02};
  nqdtlv tbs, x, seq, e, id;
  nqdcur tc, ec, f;
  const uint8_t *x3 = NULL;
  nqspan se, sct = {NULL, 0};
  uint8_t h0[12], h1[12], h2[12];
  size_t n0, n1 = 0, n2 = 0, pre, en;
  if (nqdone(leaf->tbs.p, leaf->tbs.n, &tbs) != NQOK ||
      nqddown(&tbs, &tc) != NQOK) {
    return NQEDEC;
  }
  /* [3] extensions is the last field */
  memset(&x, 0, sizeof x);
  while (!nqdend(&tc)) {
    if (nqdnext(&tc, &x) != NQOK) return NQEDEC;
  }
  if (x.cls != NQDCTX || x.tag != 3 || nqddown(&x, &ec) != NQOK ||
      nqdnext(&ec, &seq) != NQOK || nqddown(&seq, &f) != NQOK) {
    return NQEDEC;
  }
  x3 = x.raw.p;
  while (!nqdend(&f)) {
    nqdcur g;
    if (nqdnext(&f, &e) != NQOK || nqddown(&e, &g) != NQOK ||
        nqdnext(&g, &id) != NQOK) {
      return NQEDEC;
    }
    if (nqdoideq(&id, oid, sizeof oid)) sct = e.raw;
  }
  if (sct.p == NULL) return NQEDEC;
  se = seq.v;
  en = se.n - sct.n;
  pre = (size_t)(x3 - tbs.v.p);
  /* SEQUENCE of what is left, in [3]; none left: no [3] */
  if (en > 0) {
    n2 = hdr(0x30, en, h2);
    n1 = hdr(0xa3, n2 + en, h1);
  }
  n0 = hdr(0x30, pre + (en > 0 ? n1 + n2 + en : 0), h0);
  put24(c, n0 + pre + (en > 0 ? n1 + n2 + en : 0));
  nqfupd(c, h0, n0);
  nqfupd(c, tbs.v.p, pre);
  if (en > 0) {
    nqfupd(c, h1, n1);
    nqfupd(c, h2, n2);
    nqfupd(c, se.p, (size_t)(sct.p - se.p));
    nqfupd(c, sct.p + sct.n, (size_t)(se.p + se.n - (sct.p + sct.n)));
  }
  return NQOK;
}

/* one SCT (p, n) about leaf: SOK and the log's index in *li, or why
 * not; pre for an embedded one (issuer iss) */
static int one(const nqtls *t, const uint8_t *p, size_t n, int pre,
               const nqcert *leaf, const nqcert *iss, int64_t now,
               size_t *li) {
  static const uint8_t z[2] = {0, 0};
  const uint8_t *id, *ext, *sig;
  size_t en, sn, i;
  uint64_t ts;
  int64_t s;
  const nqtlog *g = NULL;
  uint8_t d[32], ty[2];
  nqfctx c;
  nqck k;
  int rc;
  /* version (v1 only), log id, timestamp, extensions, the signature */
  if (n < 47 || p[0] != 0) return SUNK;
  id = p + 1;
  ts = ld64(p + 33);
  en = ((size_t)p[41] << 8) | p[42];
  if (n < 47 + en) return SBAD;
  ext = p + 43;
  sig = ext + en;
  sn = ((size_t)sig[2] << 8) | sig[3];
  if (n != 47 + en + sn) return SBAD;
  for (i = 0; i < t->nlg && g == NULL; i++) {
    if (memcmp(t->lg[i].id, id, 32) == 0) g = &t->lg[i];
  }
  if (g == NULL) return SUNK;
  *li = (size_t)(g - t->lg);
  /* the time: not ahead of the clock, when the log took entries */
  if (ts / 1000 > (uint64_t)(now + NQXSKEW)) return SOLD;
  s = (int64_t)(ts / 1000);
  if (g->st != NQTLCTQ && g->st != NQTLCTU && g->st != NQTLCTR &&
      !(g->st == NQTLCTX && s < g->stt)) {
    return SOLD;
  }
  if (g->ti && (leaf->na < g->tis || leaf->na >= g->tie)) return SOLD;
  /* the signed struct (3.2): version, certificate_timestamp, the time,
   * the entry, the extensions */
  if (nqfini(&c, NQS256) != NQOK) return SBAD;
  nqfupd(&c, z, 2);
  nqfupd(&c, p + 33, 8);
  ty[0] = 0;
  ty[1] = (uint8_t)pre;
  nqfupd(&c, ty, 2);
  if (pre) {
    if (nqhash(NQS256, iss->key.spki.p, iss->key.spki.n, d, 32) != NQOK) {
      return SBAD;
    }
    nqfupd(&c, d, 32);
    if (pretbs(leaf, &c) != NQOK) return SBAD;
  } else {
    put24(&c, leaf->raw.n);
    nqfupd(&c, leaf->raw.p, leaf->raw.n);
  }
  nqfupd(&c, ext - 2, en + 2);
  nqffin(&c, d);
  if (nqckey(&k, t->lk + g->key, g->keyn) != NQOK || sig[0] != 4) {
    return SBAD;
  }
  if (sig[1] == 3 && k.kind == NQKEC && k.crv == NQP256) {
    rc = nqecvh(&k, d, 32, sig + 4, sn, 0);
  } else if (sig[1] == 1 && k.kind == NQKRSA && k.pss == 0) {
    rc = nqrsavh(&k, NQS256, d, 32, sig + 4, sn);
  } else {
    return SBAD;
  }
  return rc == NQOK ? SOK : SBAD;
}

int nqtlctv(nqtls *t, const nqcert *leaf, const nqcert *iss, int64_t now) {
  size_t got[NSCT], ng = 0, nsct = 0, cnt[4] = {0, 0, 0, 0}, i, j, nop = 0;
  char why[NQTLWHY];
  int w;
  for (w = 0; w < 2; w++) {
    nqspan l = w == 0 ? leaf->sct : t->sctl;
    const uint8_t *p = l.p;
    size_t n = l.n, m = 0;
    if (n == 0) continue;
    /* SignedCertificateTimestampList: SerializedSCT<1..2^16-1>, in a
     * vector of 1 to 2^16-1 */
    if (n < 2 || (((size_t)p[0] << 8) | p[1]) != n - 2 || n == 2) {
      return nqtlfail(t, NQEVRFY, 42, "the server's SCT list is "
                      "malformed");
    }
    p += 2;
    n -= 2;
    while (n > 0) {
      size_t li = 0;
      int r;
      if (n < 2 || (m = ((size_t)p[0] << 8) | p[1]) == 0 || m > n - 2) {
        return nqtlfail(t, NQEVRFY, 42, "the server's SCT list is "
                        "malformed");
      }
      if (nsct++ < NSCT) {
        r = one(t, p + 2, m, w == 0, leaf, iss, now, &li);
        cnt[r]++;
        if (r == SOK) {
          for (i = 0; i < ng && got[i] != li; i++) {
          }
          if (i == ng) got[ng++] = li;
        }
      }
      p += 2 + m;
      n -= 2 + m;
    }
  }
  /* distinct operators among the logs that count */
  for (i = 0; i < ng; i++) {
    for (j = 0; j < i && t->lg[got[j]].op != t->lg[got[i]].op; j++) {
    }
    if (j == i) nop++;
  }
  if (nop >= 2) return NQOK;
  if (nsct == 0) {
    return nqtlfail(t, NQEVRFY, 42, "the server's certificate has no SCTs "
                    "(Certificate Transparency)");
  }
  snprintf(why, sizeof why, "Certificate Transparency: the server's SCTs "
           "come from %lu log operator%s, 2 are needed (%lu valid, %lu "
           "from logs not listed, %lu bad, %lu from logs not usable then)",
           (unsigned long)nop, nop == 1 ? "" : "s", (unsigned long)cnt[SOK],
           (unsigned long)cnt[SUNK], (unsigned long)cnt[SBAD],
           (unsigned long)cnt[SOLD]);
  return nqtlfail(t, NQEVRFY, 42, why);
}
