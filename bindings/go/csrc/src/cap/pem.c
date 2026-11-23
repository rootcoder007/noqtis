/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* ASCII armor: bytes as text between a BEGIN and an END line, as RFC 7468
 * writes them (base64 of RFC 4648 section 4 in lines of 64 characters, no
 * headers). The label is the caller's. The base64 here is not constant
 * time: armor is for what is public (signatures, sealed streams), never
 * for a secret key. */
#include <string.h>

#include "cap/cap.h"
#include "noqtis.h"

static const char beg[] = "-----BEGIN ";
static const char end[] = "-----END ";
static const char dash[] = "-----";
#define NBEG (sizeof beg - 1)
#define NEND (sizeof end - 1)
#define NDASH (sizeof dash - 1)

/* a label: capitals, digits and single spaces between them */
static int labok(const char *l, size_t n) {
  size_t i;
  if (n < 1 || n >= NQARMLAB || l[0] == ' ' || l[n - 1] == ' ') return 0;
  for (i = 0; i < n; i++) {
    char c = l[i];
    if (c == ' ') {
      if (l[i - 1] == ' ') return 0;
    } else if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
      return 0;
    }
  }
  return 1;
}

static int ws(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

int nqarmlen(const char *label, size_t n, size_t *len) {
  size_t l, ch;
  if (label == NULL || len == NULL) return NQEARG;
  l = strlen(label);
  if (!labok(label, l)) return NQEARG;
  if (n > (size_t)-1 / 2 - 4 * NQARMLAB) return NQELIM;
  ch = nqb64n(n);
  *len = NBEG + l + NDASH + 1 + ch + (ch + 63) / 64 + NEND + l + NDASH + 1;
  return NQOK;
}

int nqarmenc(const char *label, const uint8_t *in, size_t n, char *out,
             size_t cap, size_t *outlen) {
  char line[65];
  size_t need, l, o = 0, i;
  int rc;
  if (out == NULL || outlen == NULL || (in == NULL && n != 0)) return NQEARG;
  rc = nqarmlen(label, n, &need);
  if (rc != NQOK) return rc;
  if (need > cap) return NQEBUF;
  l = strlen(label);
  memcpy(out + o, beg, NBEG);
  o += NBEG;
  memcpy(out + o, label, l);
  o += l;
  memcpy(out + o, dash, NDASH);
  o += NDASH;
  out[o++] = '\n';
  for (i = 0; i < n; i += 48) {
    size_t k = n - i < 48 ? n - i : 48;
    nqb64e(in + i, k, line);
    memcpy(out + o, line, nqb64n(k));
    o += nqb64n(k);
    out[o++] = '\n';
  }
  memcpy(out + o, end, NEND);
  o += NEND;
  memcpy(out + o, label, l);
  o += l;
  memcpy(out + o, dash, NDASH);
  o += NDASH;
  out[o++] = '\n';
  *outlen = o;
  return NQOK;
}

/* the label of a BEGIN or END line whose first characters (pre, np) are
 * at in[*at]: its place and length, *at after the five dashes */
static int labat(const char *in, size_t n, size_t *at, const char *pre,
                 size_t np, const char **lab, size_t *ll) {
  size_t i = *at, s;
  if (n - i < np || memcmp(in + i, pre, np) != 0) return NQEDEC;
  s = i += np;
  while (i < n && in[i] != '-') i++;
  if (!labok(in + s, i - s)) return NQEDEC;
  if (n - i < NDASH || memcmp(in + i, dash, NDASH) != 0) return NQEDEC;
  *lab = in + s;
  *ll = i - s;
  *at = i + NDASH;
  return NQOK;
}

int nqarmdec(const char *in, size_t n, char *label, size_t lcap,
             uint8_t *out, size_t cap, size_t *outlen) {
  const char *lb, *le;
  size_t i = 0, ll, el, o = 0, k, q = 0;
  char quad[4];
  int rc, last = 0;
  if (in == NULL || outlen == NULL || (out == NULL && cap != 0) ||
      (label == NULL && lcap != 0)) {
    return NQEARG;
  }
  while (i < n && ws(in[i])) i++;
  rc = labat(in, n, &i, beg, NBEG, &lb, &ll);
  if (rc != NQOK) return rc;
  /* the rest of the BEGIN line */
  while (i < n && (in[i] == ' ' || in[i] == '\t' || in[i] == '\r')) i++;
  if (i == n || in[i] != '\n') return NQEDEC;
  for (i++; i < n && in[i] != '-'; i++) {
    if (ws(in[i])) continue;
    /* nothing follows a group that ends in padding */
    if (last) return NQEDEC;
    quad[q++] = in[i];
    if (q < 4) continue;
    q = 0;
    last = quad[3] == '=';
    rc = nqb64d(quad, 4, out == NULL ? NULL : out + o, cap - o, &k);
    if (rc != NQOK) return rc;
    o += k;
  }
  /* the END line starts a line, after whole groups */
  if (q != 0 || in[i - 1] != '\n') return NQEDEC;
  rc = labat(in, n, &i, end, NEND, &le, &el);
  if (rc != NQOK) return rc;
  if (el != ll || memcmp(lb, le, ll) != 0) return NQEDEC;
  for (; i < n; i++) {
    if (!ws(in[i])) return NQEDEC;
  }
  if (lcap != 0) {
    if (ll + 1 > lcap) return NQEBUF;
    memcpy(label, lb, ll);
    label[ll] = '\0';
  }
  *outlen = o;
  return NQOK;
}
