/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqdchk: the record in a folder against the files beside it. */
#include "int.h"

#include <string.h>

/* " [synthetic]" when the source of path is marked synthetic */
static const char *synth(const djs *root, const char *path) {
  const djs *s = qdjget(root, "sources");
  size_t i;
  if (s == NULL)
    return "";
  for (i = 0; i < s->n; i++) {
    const djs *p = qdjget(s->k[i], "path"), *y = qdjget(s->k[i], "synthetic");
    if (p != NULL && strcmp(p->s, path) == 0)
      return y != NULL && y->t == DJTRUE ? " [synthetic]" : "";
  }
  return "";
}

static int srcrow(nqdrep *rep, const char *dir, const djs *e) {
  const char *path = qdjget(e, "path")->s;
  const char *want = qdjget(e, "sha256")->s;
  const djs *y = qdjget(e, "synthetic");
  const char *sy = y != NULL && y->t == DJTRUE ? " [synthetic]" : "";
  int64_t size = 0;
  char p[4200], hx[65];
  uint8_t h[32], w[32];
  uint64_t got;
  size_t i;
  int rc;
  qdjint(qdjget(e, "size"), &size);
  if (qdjoin(dir, path, p, sizeof p) != NQOK)
    return qdrepadd(rep, "source", 0, "%s%s: not a path in the folder", path,
                   sy);
  rc = qdsha(p, h, &got);
  if (rc != NQOK)
    return qdrepadd(rep, "source", 0, "%s%s: missing or unreadable", path, sy);
  for (i = 0; i < 32; i++) {
    unsigned hi = (unsigned)(want[2 * i] <= '9' ? want[2 * i] - '0'
                                                : want[2 * i] - 'a' + 10);
    unsigned lo = (unsigned)(want[2 * i + 1] <= '9'
                                 ? want[2 * i + 1] - '0'
                                 : want[2 * i + 1] - 'a' + 10);
    w[i] = (uint8_t)(hi << 4 | lo);
  }
  qdhex(h, 32, hx);
  if (!nqcteq(h, w, 32))
    return qdrepadd(rep, "source", 0,
                   "%s%s: SHA-256 is %.16s..., the record says %.16s...",
                   path, sy, hx, want);
  if ((uint64_t)size != got)
    return qdrepadd(rep, "source", 0, "%s%s: %llu bytes, the record says %lld",
                   path, sy, (unsigned long long)got, (long long)size);
  return qdrepadd(rep, "source", 1, "%s%s: SHA-256 and size match", path, sy);
}

int nqdchk(const char *dir, nqdrep **out) {
  nqdrep *rep;
  nqdrec *r = NULL;
  const djs *root, *a;
  char why[600];
  size_t i, n, bad = 0;
  int rc;
  if (dir == NULL || out == NULL)
    return NQEARG;
  *out = NULL;
  if ((rep = qdrepnew()) == NULL)
    return NQEMEM;
  rc = nqdload(dir, &r, why, sizeof why);
  if (rc == NQEMEM) {
    nqdrepfree(rep);
    return rc;
  }
  if (rc != NQOK) {
    qdrepadd(rep, "record", 0, "%s", why);
    *out = rep;
    return NQEVRFY;
  }
  root = qdrectree(r);
  qdrepadd(rep, "record", 1, NQDFMT ", canonical: %lu sources, %lu schemas",
          (unsigned long)nqdlen(r, "sources"),
          (unsigned long)nqdlen(r, "schemas"));
  if ((a = qdjget(root, "sources")) != NULL)
    for (i = 0; i < a->n; i++)
      srcrow(rep, dir, a->k[i]);
  if ((a = qdjget(root, "schemas")) != NULL)
    for (i = 0; i < a->n; i++)
      qdschk(rep, dir, a->k[i], synth(root, qdjget(a->k[i], "path")->s));
  if ((a = qdjget(root, "checks")) != NULL) {
    for (i = 0; i < a->n; i++) {
      const char *st = qdjget(a->k[i], "status")->s;
      qdrepadd(rep, "recorded", strcmp(st, "fail") != 0, "%s: %s",
              qdjget(a->k[i], "name")->s, st);
    }
  }
  nqdrfree(r);
  n = nqdrepn(rep);
  for (i = 0; i < n; i++) {
    int ok = 0;
    nqdrepi(rep, i, NULL, &ok, NULL);
    bad += !ok;
  }
  *out = rep;
  return bad ? NQEVRFY : NQOK;
}
