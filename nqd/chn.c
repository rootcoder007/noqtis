/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Chains: an append-only log of capsules, each sealed in format 2 with
 * the one before as its only input (`noqtis seal --input`), so the seal
 * of each link signs the id of the last. nqdchain checks a chain in
 * order: every link checks, each names exactly the link before it, and
 * all are sealed by one key; its head is the last link's id. A lineage
 * check (nqchkx's lin) follows inputs as a tree to 64 levels; a chain is
 * checked one link at a time, at any length. */
#include "int.h"

#include <string.h>

/* the ids of the inputs of the capsule in dir, read from its manifest
 * and bound to its seal: the bytes the seal signs (the manifest, or in
 * format 2 its head) must hash to the capsule's id */
static int inputs(const char *dir, const uint8_t id[32], uint8_t *ids,
                  size_t max, size_t *n, char *why, size_t cap) {
  static const char ff[] = ",\"files\":[";
  /* the first after the files: a file entry's strings hold no bare
   * quote, and meta comes after the format */
  static const char fe[] = "],\"format\":\"noqtis-capsule-";
  char p[4200], *m = NULL, *s, *e;
  size_t ml = 0, i;
  dbuf h;
  djs *v = NULL;
  const djs *a;
  uint8_t d[32];
  int rc;
  *n = 0;
  memset(&h, 0, sizeof h);
  if (qdjoin(dir, "noqtis.json", p, sizeof p) != NQOK ||
      qdread(p, (size_t)512 << 20, &m, &ml) != NQOK) {
    qdwhy(why, cap, "its manifest cannot be read");
    return NQEIO;
  }
  s = strstr(m, ff);
  e = s != NULL ? strstr(s, fe) : NULL;
  if (e != NULL && e[sizeof fe - 1] != '2')
    e = NULL;
  if (e == NULL) {
    /* format 1: the manifest is what the seal signs, and has no inputs */
    rc = nqhash(NQS256, (const uint8_t *)m, ml, d, 32);
  } else {
    qdbput(&h, m, (size_t)(s - m) + 1);
    qdbput(&h, e + 2, ml - (size_t)(e + 2 - m));
    rc = h.err ? h.err : nqhash(NQS256, (const uint8_t *)h.b, h.n, d, 32);
  }
  if (rc == NQOK && !nqcteq(d, id, 32)) {
    qdwhy(why, cap, "its manifest is not the one its seal signs");
    rc = NQEVRFY;
  }
  if (rc == NQOK && e != NULL &&
      (rc = qdjparse(h.b, h.n, &v, why, cap)) == NQOK &&
      (a = qdjget(v, "inputs")) != NULL) {
    for (i = 0; i < a->n && i < max; i++) {
      const djs *c = qdjget(a->k[i], "capsule");
      size_t j;
      for (j = 0; c != NULL && c->t == DJSTR && c->sl == 64 && j < 32; j++) {
        unsigned hi = (unsigned)c->s[2 * j], lo = (unsigned)c->s[2 * j + 1];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        ids[32 * i + j] = (uint8_t)(hi << 4 | lo);
      }
    }
    *n = a->n;
  }
  qdjfree(v);
  qdbfree(&h);
  qdfree(m);
  return rc;
}

/* the seal's key fingerprint (info.key of nqinsp), "" when unread */
static void keyfp(const char *dir, char out[65]) {
  nqrep *r = NULL;
  size_t i;
  out[0] = '\0';
  if (nqinsp(dir, &r) == NQOK) {
    for (i = 0; i < nqrepn(r); i++) {
      const char *c = NULL, *d = NULL;
      nqrepi(r, i, &c, NULL, &d);
      if (c != NULL && d != NULL && strcmp(c, "info.key") == 0 &&
          strlen(d) == 64)
        memcpy(out, d, 65);
    }
  }
  nqrepfree(r);
}

/* the first failed row of a capsule check, as "check: detail" */
static void firstbad(const nqrep *r, char *out, size_t cap) {
  size_t i;
  out[0] = '\0';
  for (i = 0; i < nqrepn(r); i++) {
    const char *c = NULL, *d = NULL;
    int ok = 1;
    nqrepi(r, i, &c, &ok, &d);
    if (!ok) {
      qdwhy(out, cap, "%s: %s", c != NULL ? c : "?", d != NULL ? d : "");
      return;
    }
  }
}

int nqdchain(const char *const *dirs, size_t n, const nqcopt *o,
             uint8_t head[32], nqdrep **out) {
  nqdrep *rep;
  nqcopt co;
  uint8_t prev[32], id[32], in[64];
  char hx[65], why[600], k0[65], k[65];
  size_t i, nin, bad = 0;
  int rc, have = 0;
  if (dirs == NULL || n == 0 || head == NULL || out == NULL)
    return NQEARG;
  *out = NULL;
  memset(head, 0, 32);
  memset(prev, 0, sizeof prev);
  memset(id, 0, sizeof id);
  memset(in, 0, sizeof in);
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  memset(&co, 0, sizeof co);
  if (o != NULL) {
    co.trust = o->trust;
    co.trustlen = o->trustlen;
    co.anc = o->anc;
    co.anclen = o->anclen;
    co.nanc = o->nanc;
    co.stmt = o->stmt;
    co.stmtlen = o->stmtlen;
    co.nstmt = o->nstmt;
  }
  k0[0] = '\0';
  for (i = 0; i < n; i++) {
    nqrep *r = NULL;
    int ok;
    rc = nqchkx(dirs[i], &co, &r);
    if (rc == NQEMEM) {
      nqrepfree(r);
      nqdrepfree(rep);
      return rc;
    }
    ok = rc == NQOK;
    if (!ok) {
      firstbad(r, why, sizeof why);
      qdrepadd(rep, "link", 0, "%lu, %s: does not check (%s)",
               (unsigned long)i + 1, dirs[i], why[0] ? why : nqerr(rc));
    }
    nqrepfree(r);
    if (nqcapid(dirs[i], id) != NQOK) {
      if (ok)
        qdrepadd(rep, "link", 0, "%lu, %s: its seal does not read",
                 (unsigned long)i + 1, dirs[i]);
      bad++;
      have = 0;
      continue;
    }
    qdhex(id, 32, hx);
    why[0] = '\0';
    rc = inputs(dirs[i], id, in, 2, &nin, why, sizeof why);
    if (rc == NQEMEM) {
      nqdrepfree(rep);
      return rc;
    }
    if (rc != NQOK) {
      ok = 0;
      qdrepadd(rep, "link", 0, "%lu, %s: %s", (unsigned long)i + 1, dirs[i],
               why);
    } else if (i == 0) {
      if (ok)
        qdrepadd(rep, "link", 1, "1, %s: checks; %s", dirs[i],
                 nin == 0 ? "the start of the chain"
                          : "its inputs are not part of what is checked");
    } else if (nin != 1) {
      ok = 0;
      qdrepadd(rep, "link", 0, "%lu, %s: %lu inputs, where a link has the "
               "one before it", (unsigned long)i + 1, dirs[i],
               (unsigned long)nin);
    } else if (!have || !nqcteq(in, prev, 32)) {
      ok = 0;
      qdhex(in, 32, why);
      qdrepadd(rep, "link", 0, "%lu, %s: follows %.16s..., not %s (a fork, "
               "or links out of order)", (unsigned long)i + 1, dirs[i], why,
               dirs[i - 1]);
    } else if (ok) {
      qdrepadd(rep, "link", 1, "%lu, %s: checks, and follows %s",
               (unsigned long)i + 1, dirs[i], dirs[i - 1]);
    }
    bad += !ok;
    keyfp(dirs[i], k);
    if (i == 0) {
      memcpy(k0, k, sizeof k);
    } else if (k[0] == '\0' || strcmp(k, k0) != 0) {
      bad++;
      qdrepadd(rep, "key", 0, "%lu, %s: sealed by another key than the "
               "first link's", (unsigned long)i + 1, dirs[i]);
    }
    memcpy(prev, id, 32);
    have = 1;
  }
  if (bad == 0) {
    qdrepadd(rep, "key", 1, "every link sealed by the key %.16s...", k0);
    memcpy(head, prev, 32);
    qdhex(head, 32, hx);
    qdrepadd(rep, "head", 1, "%s (%s)", hx, dirs[n - 1]);
  }
  *out = rep;
  return bad ? NQEVRFY : NQOK;
}
