/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Commitments (a randomisation list, a pre-registration sealed before
 * the data are seen) and citations of a data record. */
#include "int.h"

#include <string.h>

#define QDCTAG "noqtis-commit-1"

int nqdcommit(const uint8_t *salt, size_t sl, const uint8_t *m, size_t n,
              char hex[65]) {
  nqhctx h;
  uint8_t d[32], len[8];
  int i, rc;
  if (salt == NULL || hex == NULL || (m == NULL && n) || sl < 16 ||
      sl > 1024)
    return NQEARG;
  for (i = 0; i < 8; i++)
    len[i] = (uint8_t)((uint64_t)sl >> (56 - 8 * i));
  if ((rc = nqhini(&h, NQS3256)) != NQOK)
    return rc;
  /* SHA3-256(tag || 0x00 || salt length, 8 bytes big-endian || salt ||
   * content): the tag keeps the digest from passing as any other
   * noqtis digest, the length fixes where the salt ends */
  nqhupd(&h, (const uint8_t *)QDCTAG, sizeof QDCTAG);
  nqhupd(&h, len, 8);
  nqhupd(&h, salt, sl);
  if (n)
    nqhupd(&h, m, n);
  if ((rc = nqhfin(&h, d, 32)) != NQOK)
    return rc;
  qdhex(d, 32, hex);
  nqwipe(d, sizeof d);
  return NQOK;
}

static int unhex(const char *s, uint8_t out[32]) {
  int i;
  for (i = 0; i < 64; i++) {
    char c = s[i];
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                                  : -1;
    if (v < 0)
      return 0;
    out[i / 2] = (uint8_t)(i % 2 ? out[i / 2] | v : v << 4);
  }
  return 1;
}

int nqdreveal(const nqdrec *r, const uint8_t *salt, size_t sl,
              const uint8_t *m, size_t n, size_t *idx) {
  const djs *a;
  char hex[65];
  uint8_t d[32], w[32];
  size_t i, hit = (size_t)-1;
  int rc;
  if (r == NULL)
    return NQEARG;
  if ((rc = nqdcommit(salt, sl, m, n, hex)) != NQOK)
    return rc;
  unhex(hex, d);
  a = qdjget(qdrectree(r), "commits");
  /* every commitment is compared, in constant time, whatever matched */
  for (i = 0; a != NULL && i < a->n; i++) {
    const djs *g = qdjget(a->k[i], "digest");
    if (unhex(g->s, w) && nqcteq(d, w, 32) && hit == (size_t)-1)
      hit = i;
  }
  nqwipe(d, sizeof d);
  if (hit == (size_t)-1)
    return NQEVRFY;
  if (idx != NULL)
    *idx = hit;
  return NQOK;
}

/* s escaped for a quoted YAML scalar ("...") or a BibTeX braced value */
static void esc(dbuf *b, const char *s, int bib) {
  for (; *s; s++) {
    if (!bib && (*s == '"' || *s == '\\'))
      qdbch(b, '\\');
    if (bib && (*s == '{' || *s == '}' || *s == '\\')) {
      qdbch(b, '\\');
    }
    qdbch(b, *s);
  }
}

static const char *str(const djs *o, const char *k) {
  const djs *v = qdjget(o, k);
  return v != NULL && v->t == DJSTR ? v->s : NULL;
}

int nqdcite(const nqdrec *r, int fmt, char *out, size_t cap,
            size_t *outlen) {
  const djs *c, *au;
  dbuf b;
  size_t i;
  int64_t year = 0;
  int rc;
  static const char *const keys[] = {"version", "doi", "url", "licence"};
  if (r == NULL || (fmt != NQDCFF && fmt != NQDBIB))
    return NQEARG;
  c = qdjget(qdrectree(r), "cite");
  if (c == NULL)
    return NQEIO;
  au = qdjget(c, "authors");
  qdjint(qdjget(c, "year"), &year);
  memset(&b, 0, sizeof b);
  if (fmt == NQDCFF) {
    /* CITATION.cff 1.2.0; an author is written as a name */
    qdbstr(&b, "cff-version: 1.2.0\nmessage: \"Cite this data as below.\"\n"
               "type: dataset\ntitle: \"");
    esc(&b, str(c, "title"), 0);
    qdbstr(&b, "\"\n");
    if (au != NULL) {
      qdbstr(&b, "authors:\n");
      for (i = 0; i < au->n; i++) {
        qdbstr(&b, "  - name: \"");
        esc(&b, au->k[i]->s, 0);
        qdbstr(&b, "\"\n");
      }
    }
    for (i = 0; i < 4; i++) {
      const char *v = str(c, keys[i]);
      if (v == NULL)
        continue;
      qdbstr(&b, i == 3 ? "license" : keys[i]);
      qdbstr(&b, ": \"");
      esc(&b, v, 0);
      qdbstr(&b, "\"\n");
    }
    if (year > 0) {
      char y[64];
      snprintf(y, sizeof y, "date-released: \"%04lld-01-01\"\n",
               (long long)year);
      qdbstr(&b, y);
    }
  } else {
    qdbstr(&b, "@misc{data,\n  title = {");
    esc(&b, str(c, "title"), 1);
    qdbstr(&b, "}");
    if (au != NULL && au->n) {
      qdbstr(&b, ",\n  author = {");
      for (i = 0; i < au->n; i++) {
        if (i)
          qdbstr(&b, " and ");
        qdbch(&b, '{');
        esc(&b, au->k[i]->s, 1);
        qdbch(&b, '}');
      }
      qdbstr(&b, "}");
    }
    if (year > 0) {
      char y[64];
      snprintf(y, sizeof y, ",\n  year = {%lld}", (long long)year);
      qdbstr(&b, y);
    }
    for (i = 0; i < 4; i++) {
      const char *v = str(c, keys[i]);
      if (v == NULL)
        continue;
      qdbstr(&b, ",\n  ");
      qdbstr(&b, i == 3 ? "note = {Licence: " : keys[i]);
      if (i != 3)
        qdbstr(&b, " = {");
      esc(&b, v, 1);
      qdbch(&b, '}');
    }
    qdbstr(&b, "\n}\n");
  }
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}
