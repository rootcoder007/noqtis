/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Certification paths (RFC 5280 section 6, the parts a short chain to a
 * caller-chosen anchor needs): build by name and signature, then check
 * every link. No recursion: the path grows one certificate at a time and
 * never backtracks; a candidate is taken only once its signature over
 * the certificate below has verified. Anchors are matched by subject and
 * key (nqxalias): an intermediate with an anchor's subject Name and
 * byte-identical SubjectPublicKeyInfo is replaced by the anchor, whose
 * own validity and constraints then apply, and its issuer is not
 * followed. The leaf is never an anchor. */
#include <string.h>

#include "der/x509.h"

/* 1 when c signed sub (names chain and the signature verifies). */
static int issued(const nqcert *c, const nqcert *sub, const nqxops *ops) {
  if (!nqxneq(sub->issuer, c->subject)) {
    return 0;
  }
  if (sub->salg.kind == 0) {
    return 0;
  }
  return nqxvrfy(ops, &c->key, &sub->salg, sub->tbs, sub->sig) == NQOK;
}

static int inpath(const nqcert *const *path, size_t np, const nqcert *c) {
  size_t i;
  for (i = 0; i < np; i++) {
    if (path[i] == c || nqdseq(path[i]->raw, c->raw)) {
      return 1;
    }
  }
  return 0;
}

int nqxalias(const nqcert *c, const nqcert *anc) {
  if (c == NULL || anc == NULL) {
    return 0;
  }
  /* the SKI only as a quick filter; the key bytes decide */
  if (c->ski.n > 0 && anc->ski.n > 0 && !nqdseq(c->ski, anc->ski)) {
    return 0;
  }
  return nqdseq(c->key.spki, anc->key.spki) &&
         nqxneq(c->subject, anc->subject);
}

static int valid(const nqcert *c, int64_t t) {
  return t >= c->nb && t <= c->na;
}

static int selfiss(const nqcert *c) {
  return nqxneq(c->issuer, c->subject);
}

/* An issuer's own checks; anchor 1 for the trust anchor, which may be a
 * version 1 certificate without extensions. */
static int caok(const nqcert *c, int anchor, uint32_t eku) {
  if ((c->ext & NQXHASBC) != 0 || !anchor) {
    if ((c->ext & NQXHASBC) == 0 || !c->ca) {
      return 0;
    }
  }
  if ((c->ext & NQXHASKU) != 0) {
    if ((c->ku & NQXKUCERT) == 0) {
      return 0;
    }
  } else if (!anchor) {
    return 0; /* RFC 5280 4.2.1.3: CAs MUST include key usage */
  }
  if (eku != 0 && (c->ext & NQXHASEKU) != 0 &&
      (c->eku & (eku | NQXEKUANY)) == 0) {
    return 0;
  }
  return 1;
}

int nqchain(const nqcert *leaf, const nqxchk *k, const nqcert **path,
            size_t cap, size_t *np) {
  const nqcert *cur = leaf;
  size_t n = 1, i, j;
  int anch = 0;
  if (leaf == NULL || k == NULL || path == NULL || np == NULL || cap == 0 ||
      k->nanc == 0 || k->anc == NULL || k->ops == NULL) {
    return NQEARG;
  }
  *np = 0;
  path[0] = leaf;
  /* a certificate is never its own anchor: a path has at least one link,
   * so trusting a leaf does not make it its own issuer */
  while (!anch) {
    const nqcert *nx = NULL;
    if (n >= cap || n >= NQXMAXPATH) {
      return NQELIM;
    }
    for (i = 0; i < k->nanc && nx == NULL; i++) {
      if (!inpath(path, n, &k->anc[i]) && issued(&k->anc[i], cur, k->ops)) {
        nx = &k->anc[i];
        anch = 1;
      }
    }
    for (i = 0; i < k->npool && nx == NULL; i++) {
      if (!inpath(path, n, &k->pool[i]) && issued(&k->pool[i], cur, k->ops)) {
        nx = &k->pool[i];
      }
    }
    if (nx == NULL) {
      return NQEVRFY;
    }
    /* an intermediate that is an alias of an anchor (same subject, same
     * key: a cross-certificate) ends the path at that anchor; nothing
     * else in the alias is used */
    for (i = 0; i < k->nanc && !anch; i++) {
      if (nqxalias(nx, &k->anc[i])) {
        nx = &k->anc[i];
        anch = 1;
      }
    }
    path[n++] = nx;
    cur = nx;
  }
  /* every certificate */
  for (i = 0; i < n; i++) {
    const nqcert *c = path[i];
    if (c->bad || !valid(c, k->t)) {
      return NQEVRFY;
    }
    if (i > 0 && !caok(c, i == n - 1, k->eku)) {
      return NQEVRFY;
    }
    if (i > 0 && i < n - 1 && c->ver != 3) {
      return NQEVRFY;
    }
    /* the key identifiers agree where both are stated */
    if (i + 1 < n && path[i]->aki.n > 0 && path[i + 1]->ski.n > 0 &&
        !nqdseq(path[i]->aki, path[i + 1]->ski)) {
      return NQEVRFY;
    }
    /* path length: non-self-issued intermediates below an issuer */
    if (i > 0 && c->plen >= 0) {
      size_t below = 0;
      for (j = 1; j < i; j++) {
        if (!selfiss(path[j])) {
          below++;
        }
      }
      if (below > (size_t)c->plen) {
        return NQEVRFY;
      }
    }
  }
  /* the purpose */
  if (k->eku != 0 &&
      ((leaf->ext & NQXHASEKU) == 0 || (leaf->eku & k->eku) == 0)) {
    return NQEVRFY;
  }
  *np = n;
  return NQOK;
}
