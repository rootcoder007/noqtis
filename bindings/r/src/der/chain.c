/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Certification paths (RFC 5280 section 6, the parts a short chain to a
 * caller-chosen anchor needs): build by name and signature, then check
 * every link. No recursion: the path grows one certificate at a time and
 * never backtracks; a candidate is taken only once its signature over
 * the certificate below has verified. Anchors are matched by subject and
 * key (nqxalias): an intermediate with an anchor's subject Name and
 * byte-identical SubjectPublicKeyInfo is replaced by the anchor, whose
 * own validity and constraints then apply, and its issuer is not
 * followed. The leaf is never an anchor. Name constraints (RFC 5280
 * 4.2.1.10 and 6.1.3 (b), (c)) are checked once the path is built. */
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

/* ---- name constraints ---- */

/* GeneralName forms (the context tags) */
#define GMAIL 1
#define GDNS 2
#define GDIR 4
#define GIP 7

static int lc(uint8_t c) {
  return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/* b (bn bytes) ends with c (cn bytes), ASCII case-insensitively */
static int tail(const uint8_t *b, size_t bn, const uint8_t *c, size_t cn) {
  size_t i;
  if (cn > bn) {
    return 0;
  }
  for (i = 0; i < cn; i++) {
    if (lc(b[bn - cn + i]) != lc(c[i])) {
      return 0;
    }
  }
  return 1;
}

/* a DNS name within constraint c: c itself or c with labels added on
 * the left; with a leading dot, the added labels only */
static int dnsin(nqspan n, nqspan c) {
  if (c.n == 0) {
    return 1;
  }
  if (c.p[0] == '.') {
    return n.n > c.n && tail(n.p, n.n, c.p, c.n);
  }
  return tail(n.p, n.n, c.p, c.n) &&
         (n.n == c.n || n.p[n.n - c.n - 1] == '.');
}

/* an excluded DNS subtree c hit by n: n within c, or n a wildcard
 * "*.D" whose one label could be c (one label, a dot, D) */
static int dnsex(nqspan n, nqspan c) {
  nqspan d, k = c;
  size_t i;
  if (dnsin(n, c)) {
    return 1;
  }
  if (n.n < 3 || n.p[0] != '*' || n.p[1] != '.') {
    return 0;
  }
  if (k.n > 0 && k.p[0] == '.') {
    k.p++;
    k.n--;
  }
  d.p = n.p + 1; /* ".D" */
  d.n = n.n - 1;
  if (k.n <= d.n || !tail(k.p, k.n, d.p, d.n)) {
    return 0;
  }
  for (i = 0; i < k.n - d.n; i++) {
    if (k.p[i] == '.') {
      return 0;
    }
  }
  return k.n > d.n;
}

/* where the last '@' of a mailbox is, or n.n */
static size_t at(nqspan n) {
  size_t i, a = n.n;
  for (i = 0; i < n.n; i++) {
    if (n.p[i] == '@') {
      a = i;
    }
  }
  return a;
}

/* a mailbox within constraint c: that mailbox (local part exact, host
 * case-insensitive), every mailbox on host c, or with a leading dot on
 * any host below c */
static int mailin(nqspan n, nqspan c) {
  size_t a = at(n), b = at(c);
  nqspan h;
  h.p = n.p + a + 1;
  h.n = n.n - a - 1;
  if (b < c.n) {
    return a == b && memcmp(n.p, c.p, a) == 0 && h.n == c.n - b - 1 &&
           tail(h.p, h.n, c.p + b + 1, c.n - b - 1);
  }
  if (c.n == 0) {
    return 1;
  }
  if (c.p[0] == '.') {
    return h.n > c.n && tail(h.p, h.n, c.p, c.n);
  }
  return h.n == c.n && tail(h.p, h.n, c.p, c.n);
}

/* an address within c: address then mask, of the same family */
static int ipin(nqspan n, nqspan c) {
  size_t i;
  if (c.n != 2 * n.n) {
    return 0;
  }
  for (i = 0; i < n.n; i++) {
    uint8_t m = c.p[n.n + i];
    if ((n.p[i] & m) != (c.p[i] & m)) {
      return 0;
    }
  }
  return 1;
}

/* a name of form ty well formed enough to compare */
static int wf(uint32_t ty, nqspan n) {
  switch (ty) {
  case GMAIL: return at(n) > 0 && at(n) + 1 < n.n;
  case GDNS: return n.n > 0;
  case GIP: return n.n == 4 || n.n == 16;
  case GDIR: return 1; /* nqxnpre refuses what does not parse */
  default: return 0;
  }
}

/* the name n of form ty within the subtree base b (of the same form);
 * ex 1 for an excluded subtree */
static int gnin(uint32_t ty, nqspan n, const nqdtlv *b, int ex) {
  switch (ty) {
  case GMAIL: return mailin(n, b->v);
  case GDNS: return ex ? dnsex(n, b->v) : dnsin(n, b->v);
  case GIP: return ipin(n, b->v);
  case GDIR: return nqxnpre(b->v, n);
  default: return 0;
  }
}

/* in the GeneralSubtrees contents l: *any gets whether a base is of
 * form ty, and the return whether n is within one */
static int scan(nqspan l, uint32_t ty, nqspan n, int ex, int *any) {
  nqdcur e, f;
  nqdtlv s, b;
  int hit = 0;
  *any = 0;
  nqdinit(&e, l.p, l.n);
  while (!nqdend(&e)) {
    /* nqcprs checked the form */
    nqdnext(&e, &s);
    nqddown(&s, &f);
    nqdnext(&f, &b);
    if (b.tag == ty) {
      *any = 1;
      if (wf(ty, n) && gnin(ty, n, &b, ex)) {
        hit = 1;
      }
    }
  }
  return hit;
}

/* 1 when ca's constraints allow the name n of form ty */
static int ncok(const nqcert *ca, uint32_t ty, nqspan n) {
  int anyp = 0, anye = 0, inp = 0, ine = 0;
  if (ca->ncp.n > 0) {
    inp = scan(ca->ncp, ty, n, 0, &anyp);
  }
  if (ca->nce.n > 0) {
    ine = scan(ca->nce, ty, n, 1, &anye);
  }
  if (!anyp && !anye) {
    return 1; /* no constraint on this form */
  }
  /* a form not compared here, or a name that cannot be compared, fails
   * closed */
  if (!wf(ty, n)) {
    return 0;
  }
  return (!anyp || inp) && !ine;
}

/* 1 when every name of c is allowed by ca */
static int ncchk(const nqcert *ca, const nqcert *c) {
  static const uint8_t mail[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                 0x0d, 0x01, 0x09, 0x01};
  nqdtlv t, e;
  nqdcur g, r, a;
  int empty = 1;
  if (nqdhdr(c->subject.p, c->subject.n, &t) != NQOK ||
      nqxname(&t, &empty) != NQOK) {
    return 0;
  }
  if (!empty && !ncok(ca, GDIR, c->subject)) {
    return 0;
  }
  if ((c->ext & NQXHASSAN) != 0) {
    nqdinit(&g, c->san.p, c->san.n);
    while (!nqdend(&g)) {
      if (nqdnext(&g, &e) != NQOK || e.cls != NQDCTX || e.tag > 8 ||
          !ncok(ca, e.tag, e.v)) {
        return 0;
      }
    }
    return 1;
  }
  /* no subjectAltName: the subject's emailAddress attributes */
  nqddown(&t, &g);
  while (!nqdend(&g)) {
    nqdnext(&g, &e);
    nqddown(&e, &r);
    while (!nqdend(&r)) {
      nqdtlv o, v;
      nqdnext(&r, &e);
      nqddown(&e, &a);
      nqdnext(&a, &o);
      nqdnext(&a, &v);
      if (nqdoideq(&o, mail, sizeof mail) && !ncok(ca, GMAIL, v.v)) {
        return 0;
      }
    }
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
  /* name constraints: an issuer's bind every certificate below it,
   * except a self-issued intermediate (the leaf always) */
  for (j = 1; j < n; j++) {
    if ((path[j]->ext & NQXHASNC) == 0) {
      continue;
    }
    for (i = 0; i < j; i++) {
      if (i > 0 && selfiss(path[i])) {
        continue;
      }
      if (!ncchk(path[j], path[i])) {
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
