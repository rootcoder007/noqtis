/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Sources of a data record (noqtis-data(5), "sources"): the addresses a
 * file can be fetched from, in the order to try them; the check of
 * fetched bytes against the recorded SHA-256 and size; and the portal
 * resolvers, as pure functions: the request to send (CKAN, Socrata,
 * ArcGIS, the Wayback Machine) and the reading of the reply. Nothing
 * here touches the network: the caller moves the bytes. */
#include "int.h"

#include <string.h>

/* the longest address built or accepted, and the largest reply read */
#define QDURL 4096
#define QDRSPMAX ((size_t)16 << 20)

static int lc(int c) {
  return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/* 1 when s[0..n) equals t, ignoring ASCII case */
static int caseq(const char *s, size_t n, const char *t) {
  size_t i;
  if (strlen(t) != n)
    return 0;
  for (i = 0; i < n; i++) {
    if (lc((unsigned char)s[i]) != lc((unsigned char)t[i]))
      return 0;
  }
  return 1;
}

static int ishttps(const char *s) {
  size_t i;
  for (i = 0; i < 8; i++) {
    if (s[i] == '\0' || lc((unsigned char)s[i]) != "https://"[i])
      return 0;
  }
  return 1;
}

static int ishttp(const char *s) {
  size_t i;
  if (ishttps(s))
    return 1;
  for (i = 0; i < 7; i++) {
    if (s[i] == '\0' || lc((unsigned char)s[i]) != "http://"[i])
      return 0;
  }
  return 1;
}

/* an http:// or https:// address with a host, of at most QDURL bytes,
 * no space, control character or fragment; with noq 1 no query either */
static int urlok(const char *s, size_t n, int noq) {
  size_t i, h;
  if (n == 0 || n > QDURL || memchr(s, 0, n) != NULL || !ishttp(s))
    return 0;
  h = ishttps(s) ? 8 : 7;
  if (h >= n || s[h] == '/' || s[h] == '?' || s[h] == ':')
    return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == 0x7f || c == '#' || c == '\\' ||
        (noq && c == '?'))
      return 0;
  }
  return 1;
}

/* 1 when the host of the address u (n bytes, checked by urlok) may be
 * named by a reply: not localhost, no IPv6 literal, and no IPv4 one
 * but a plain dotted quad outside the loopback, private, link-local,
 * shared, multicast and reserved ranges. A reply must not steer the
 * fetch at this machine or its network; a name is not resolved here. */
static int pubhost(const char *u, size_t n) {
  size_t h = ishttps(u) ? 8 : 7, e = h, i, k = 0, dots = 0;
  unsigned o[4] = {0, 0, 0, 0};
  int num = 1, dig = 0;
  if (h < n && u[h] == '[')
    return 0;
  while (e < n && u[e] != ':' && u[e] != '/' && u[e] != '?')
    e++;
  while (e > h && u[e - 1] == '.')
    e--; /* "localhost." is localhost */
  if (e - h == 9 && caseq(u + h, 9, "localhost"))
    return 0;
  if (e - h > 10 && caseq(u + e - 10, 10, ".localhost"))
    return 0;
  for (i = h; i < e; i++) {
    char c = (char)lc((unsigned char)u[i]);
    if (!((c >= '0' && c <= '9') || c == '.' || c == 'x' ||
          (c >= 'a' && c <= 'f')))
      num = 0;
  }
  if (!num)
    return 1;
  /* something a resolver may read as a number: only a plain dotted quad
   * of public octets passes */
  for (i = h; i < e; i++) {
    if (u[i] == '.') {
      if (!dig || ++dots > 3)
        return 0;
      k++;
      dig = 0;
    } else if (u[i] >= '0' && u[i] <= '9') {
      if (dig && o[k] == 0)
        return 0; /* a leading zero: octal to some resolvers */
      o[k] = o[k] * 10 + (unsigned)(u[i] - '0');
      if (o[k] > 255)
        return 0;
      dig = 1;
    } else {
      return 0;
    }
  }
  if (dots != 3 || !dig)
    return 0;
  if (o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224 ||
      (o[0] == 100 && o[1] >= 64 && o[1] < 128) ||
      (o[0] == 169 && o[1] == 254) || (o[0] == 172 && o[1] >= 16 &&
                                       o[1] < 32) ||
      (o[0] == 192 && o[1] == 168) || (o[0] == 192 && o[1] == 0 &&
                                       o[2] == 0) ||
      (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
    return 0;
  return 1;
}

/* s percent-encoded but for RFC 3986 unreserved bytes */
static void pct(dbuf *b, const char *s, size_t n) {
  static const char hx[] = "0123456789ABCDEF";
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
        c == '~') {
      qdbch(b, (char)c);
    } else {
      qdbch(b, '%');
      qdbch(b, hx[c >> 4]);
      qdbch(b, hx[c & 15]);
    }
  }
}

/* the string member k of o, or NULL; *n its length */
static const char *sget(const djs *o, const char *k, size_t *n) {
  const djs *v = qdjget(o, k);
  if (v == NULL || v->t != DJSTR)
    return NULL;
  *n = v->sl;
  return v->s;
}

/* base without its trailing '/'s, checked: *n its length */
static const char *baseof(const djs *rs, size_t *n, char *why, size_t cap) {
  const char *b = sget(rs, "base", n);
  if (b == NULL) {
    qdwhy(why, cap, "the resolver has no base (the portal's address)");
    return NULL;
  }
  while (*n > 0 && b[*n - 1] == '/')
    (*n)--;
  if (!urlok(b, *n, 1)) {
    qdwhy(why, cap, "the resolver's base is not an http:// or https:// "
          "address without a query (at most %d bytes)", QDURL);
    return NULL;
  }
  return b;
}

/* the address of a whole layer's features: <svc>/<layer>/query?... */
static void arcq(dbuf *b, const char *svc, size_t sn, int64_t layer,
                 const char *fmt) {
  char num[32];
  qdbput(b, svc, sn);
  qdwhy(num, sizeof num, "/%lld", (long long)layer);
  qdbstr(b, num);
  qdbstr(b, "/query?where=1%3D1&outFields=*&f=");
  qdbstr(b, fmt);
}

static int fmtof(const djs *rs, const char *const *ok, const char **fmt,
                 char *why, size_t cap) {
  size_t n = 0, i;
  const char *f = sget(rs, "format", &n);
  if (f == NULL) {
    *fmt = ok[0];
    return NQOK;
  }
  for (i = 0; ok[i] != NULL; i++) {
    if (caseq(f, n, ok[i])) {
      *fmt = ok[i];
      return NQOK;
    }
  }
  qdwhy(why, cap, "the resolver's format %.40s is not one this portal "
        "exports here (%s%s%s)", f, ok[0], ok[1] ? ", " : "",
        ok[1] ? ok[1] : "");
  return NQEARG;
}

static int layerof(const djs *rs, int64_t *l) {
  const djs *v = qdjget(rs, "layer");
  *l = 0;
  return v == NULL || (qdjint(v, l) && *l >= 0);
}

/* 1 when the Socrata id is four-by-four: [a-z0-9]{4}-[a-z0-9]{4} */
static int fbf(const char *s, size_t n) {
  size_t i;
  if (n != 9 || s[4] != '-')
    return 0;
  for (i = 0; i < 9; i++) {
    char c = s[i];
    if (i != 4 && !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
      return 0;
  }
  return 1;
}

/* 1 when an ArcGIS item id: 32 hex digits */
static int item(const char *s, size_t n) {
  size_t i;
  if (n != 32)
    return 0;
  for (i = 0; i < n; i++) {
    char c = (char)lc((unsigned char)s[i]);
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
  }
  return 1;
}

/* 1 when a Wayback time: 0 to 14 digits */
static int wbts(const char *s, size_t n) {
  size_t i;
  if (n > 14)
    return 0;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return 0;
  }
  return 1;
}

static const char *const fsoc[] = {"csv", "json", NULL};
static const char *const farc[] = {"geojson", "json", NULL};

static int rslv(const djs *rs, dbuf *b, char *why, size_t cap) {
  size_t kn = 0, bn = 0, n = 0;
  const char *k = sget(rs, "kind", &kn), *base, *id, *res, *fmt;
  int64_t layer;
  int rc;
  if (k == NULL) {
    qdwhy(why, cap, "the resolver has no kind");
    return NQEDEC;
  }
  if (strcmp(k, "direct") == 0) {
    qdwhy(why, cap, "a direct source is fetched from its url: there is "
          "no portal to ask");
    return NQEARG;
  }
  if (strcmp(k, "wayback") == 0) {
    /* base: the archived address; id: the time asked for */
    base = sget(rs, "base", &bn);
    if (base == NULL || !urlok(base, bn, 0)) {
      qdwhy(why, cap, "a wayback resolver needs base, the archived "
            "http:// or https:// address");
      return NQEARG;
    }
    id = sget(rs, "id", &n);
    if (id != NULL && !wbts(id, n)) {
      qdwhy(why, cap, "a wayback resolver's id is a time of 1 to 14 "
            "digits, YYYYMMDDhhmmss or a prefix of it");
      return NQEARG;
    }
    qdbstr(b, "https://archive.org/wayback/available?url=");
    pct(b, base, bn);
    if (id != NULL && n > 0) {
      qdbstr(b, "&timestamp=");
      qdbput(b, id, n);
    }
    return NQOK;
  }
  if ((base = baseof(rs, &bn, why, cap)) == NULL)
    return NQEARG;
  id = sget(rs, "id", &n);
  if (strcmp(k, "ckan") == 0) {
    size_t rn = 0;
    res = sget(rs, "resource", &rn);
    qdbput(b, base, bn);
    if (id != NULL && n > 0) {
      qdbstr(b, "/api/3/action/package_show?id=");
      pct(b, id, n);
    } else if (res != NULL && rn > 0) {
      qdbstr(b, "/api/3/action/resource_show?id=");
      pct(b, res, rn);
    } else {
      qdwhy(why, cap, "a ckan resolver needs id (the dataset) or "
            "resource (a resource's id)");
      return NQEARG;
    }
    return NQOK;
  }
  if (strcmp(k, "socrata") == 0) {
    if (id == NULL || !fbf(id, n)) {
      qdwhy(why, cap, "a socrata resolver needs id, the dataset's "
            "four-by-four id (such as abcd-1234)");
      return NQEARG;
    }
    if ((rc = fmtof(rs, fsoc, &fmt, why, cap)) != NQOK)
      return rc;
    qdbput(b, base, bn);
    qdbstr(b, "/api/views/");
    qdbput(b, id, n);
    qdbstr(b, ".json");
    return NQOK;
  }
  /* arcgis: an item of a portal (id), or a layer of a FeatureServer or
   * MapServer (base, layer) */
  if (!layerof(rs, &layer)) {
    qdwhy(why, cap, "the resolver's layer is not a count");
    return NQEARG;
  }
  if ((rc = fmtof(rs, farc, &fmt, why, cap)) != NQOK)
    return rc;
  qdbput(b, base, bn);
  if (id != NULL) {
    if (!item(id, n)) {
      qdwhy(why, cap, "an arcgis resolver's id is an item id, 32 hex "
            "digits");
      return NQEARG;
    }
    qdbstr(b, "/sharing/rest/content/items/");
    qdbput(b, id, n);
    qdbstr(b, "?f=json");
    return NQOK;
  }
  {
    char num[32];
    qdwhy(num, sizeof num, "/%lld?f=json", (long long)layer);
    qdbstr(b, num);
  }
  return NQOK;
}

int nqdrslv(const char *rslvj, size_t n, char *out, size_t cap,
            size_t *outlen, char *why, size_t wcap) {
  djs *rs = NULL;
  dbuf b;
  int rc;
  if (why != NULL && wcap)
    why[0] = '\0';
  if (rslvj == NULL)
    return NQEARG;
  if ((rc = qdjparse(rslvj, n, &rs, why, wcap)) != NQOK)
    return rc;
  if ((rc = qdrslvok(rs, why, wcap)) != NQOK) {
    qdjfree(rs);
    return rc;
  }
  memset(&b, 0, sizeof b);
  b.max = QDURL + 1;
  rc = rslv(rs, &b, why, wcap);
  qdjfree(rs);
  if (rc == NQOK && b.err == NQELIM) {
    qdwhy(why, wcap, "the request's address would be over %d bytes", QDURL);
    rc = NQELIM;
  }
  if (rc == NQOK)
    rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}

/* an address a portal answered with: an http:// or https:// one, and
 * https:// when the portal is */
static int answer(const char *u, size_t n, int tls, dbuf *b, char *why,
                  size_t cap) {
  if (!urlok(u, n, 0)) {
    qdwhy(why, cap, "the reply's address is not an http:// or https:// "
          "address of at most %d bytes", QDURL);
    return NQEDEC;
  }
  if (tls && !ishttps(u)) {
    qdwhy(why, cap, "the portal is https:// but its reply names an "
          "http:// address: refused");
    return NQEDEC;
  }
  if (!pubhost(u, n)) {
    qdwhy(why, cap, "the reply names an address on this machine or a "
          "local network (localhost, a private, loopback or link-local "
          "address, or an address in another form): refused");
    return NQEDEC;
  }
  qdbput(b, u, n);
  return NQOK;
}

static int ckan(const djs *rs, const djs *rp, int tls, dbuf *b, char *why,
                size_t cap) {
  const djs *ok = qdjget(rp, "success"), *res = qdjget(rp, "result"), *a;
  size_t rn = 0, fn = 0, i, un = 0;
  const char *want = sget(rs, "resource", &rn), *fmt = sget(rs, "format",
                                                             &fn), *u;
  if (ok == NULL || ok->t != DJTRUE || res == NULL || res->t != DJOBJ) {
    qdwhy(why, cap, "the CKAN reply is not a success with a result");
    return NQEDEC;
  }
  a = qdjget(res, "resources");
  if (a == NULL) {
    /* resource_show: the result is the resource */
    size_t idn = 0;
    const char *id = sget(res, "id", &idn);
    if (want != NULL && (id == NULL || idn != rn || memcmp(id, want, rn))) {
      qdwhy(why, cap, "the CKAN reply is of another resource");
      return NQEDEC;
    }
    if ((u = sget(res, "url", &un)) == NULL) {
      qdwhy(why, cap, "the CKAN resource has no url");
      return NQEDEC;
    }
    return answer(u, un, tls, b, why, cap);
  }
  if (a->t != DJARR) {
    qdwhy(why, cap, "the CKAN dataset's resources are not an array");
    return NQEDEC;
  }
  if (fmt == NULL) {
    fmt = "CSV";
    fn = 3;
  }
  /* the resource with that id, else that name; with no resource named,
   * the first one in that format */
  for (i = 0; i < a->n; i++) {
    const djs *e = a->k[i];
    size_t idn = 0, en = 0;
    const char *id = sget(e, "id", &idn), *ef = sget(e, "format", &en);
    int hit;
    if (e->t != DJOBJ)
      continue;
    if (want != NULL)
      hit = id != NULL && idn == rn && memcmp(id, want, rn) == 0;
    else
      hit = ef != NULL && en == fn && caseq(ef, en, fmt);
    if (hit && (u = sget(e, "url", &un)) != NULL)
      return answer(u, un, tls, b, why, cap);
  }
  if (want != NULL) {
    for (i = 0; i < a->n; i++) {
      const djs *e = a->k[i];
      size_t nn = 0;
      const char *nm = sget(e, "name", &nn);
      if (e->t == DJOBJ && nm != NULL && nn == rn &&
          memcmp(nm, want, rn) == 0 && (u = sget(e, "url", &un)) != NULL)
        return answer(u, un, tls, b, why, cap);
    }
    qdwhy(why, cap, "the CKAN dataset has no resource with the id or name "
          "%.80s", want);
    return NQEDEC;
  }
  qdwhy(why, cap, "the CKAN dataset has no resource in the format %.20s",
        fmt);
  return NQEDEC;
}

static int socrata(const djs *rs, const djs *rp, dbuf *b, char *why,
                   size_t cap) {
  size_t bn = 0, n = 0, rn = 0;
  const char *base = baseof(rs, &bn, why, cap), *id = sget(rs, "id", &n),
             *got = sget(rp, "id", &rn), *fmt;
  if (base == NULL || id == NULL || fmtof(rs, fsoc, &fmt, why, cap) != NQOK)
    return NQEARG;
  if (got == NULL || rn != n || memcmp(got, id, n) != 0) {
    qdwhy(why, cap, "the Socrata reply is not the metadata of %.20s", id);
    return NQEDEC;
  }
  qdbput(b, base, bn);
  qdbstr(b, "/api/views/");
  qdbput(b, id, n);
  qdbstr(b, strcmp(fmt, "csv") == 0 ? "/rows.csv?accessType=DOWNLOAD"
                                    : "/rows.json?accessType=DOWNLOAD");
  return NQOK;
}

static int arcgis(const djs *rs, const djs *rp, int tls, dbuf *b,
                  char *why, size_t cap) {
  size_t bn = 0, n = 0, tn = 0, un = 0, rn = 0;
  const char *base = baseof(rs, &bn, why, cap), *id = sget(rs, "id", &n),
             *fmt, *t, *u, *got;
  int64_t layer;
  if (base == NULL || !layerof(rs, &layer) ||
      fmtof(rs, farc, &fmt, why, cap) != NQOK)
    return NQEARG;
  if (qdjget(rp, "error") != NULL) {
    qdwhy(why, cap, "the ArcGIS reply is an error");
    return NQEDEC;
  }
  if (id == NULL) {
    if (sget(rp, "name", &tn) == NULL) {
      qdwhy(why, cap, "the ArcGIS reply is not a layer's metadata (no "
            "name)");
      return NQEDEC;
    }
    arcq(b, base, bn, layer, fmt);
    return NQOK;
  }
  got = sget(rp, "id", &rn);
  if (got == NULL || rn != n || !caseq(got, rn, id)) {
    qdwhy(why, cap, "the ArcGIS reply is not the item %.40s", id);
    return NQEDEC;
  }
  t = sget(rp, "type", &tn);
  if (t == NULL) {
    qdwhy(why, cap, "the ArcGIS item has no type");
    return NQEDEC;
  }
  if (caseq(t, tn, "Feature Service") || caseq(t, tn, "Map Service")) {
    if ((u = sget(rp, "url", &un)) == NULL) {
      qdwhy(why, cap, "the ArcGIS service item has no url");
      return NQEDEC;
    }
    while (un > 0 && u[un - 1] == '/')
      un--;
    if (!urlok(u, un, 1) || (tls && !ishttps(u)) || !pubhost(u, un)) {
      qdwhy(why, cap, "the ArcGIS item's url is not an %s address without "
            "a query on a public host", tls ? "https://" : "http:// or "
            "https://");
      return NQEDEC;
    }
    arcq(b, u, un, layer, fmt);
    return NQOK;
  }
  /* a file item (CSV, a spreadsheet, ...): its data */
  qdbput(b, base, bn);
  qdbstr(b, "/sharing/rest/content/items/");
  qdbput(b, id, n);
  qdbstr(b, "/data");
  return NQOK;
}

/* "YYYYMMDDhhmmss" to "YYYY-MM-DDTHH:MM:SSZ"; 0 when not a valid time */
static int wbtime(const char *s, size_t n, char tm[21]) {
  char d[11];
  int h, mi, se;
  if (n != 14 || !wbts(s, n))
    return 0;
  memcpy(d, s, 4);
  d[4] = '-';
  memcpy(d + 5, s + 4, 2);
  d[7] = '-';
  memcpy(d + 8, s + 6, 2);
  d[10] = '\0';
  h = (s[8] - '0') * 10 + (s[9] - '0');
  mi = (s[10] - '0') * 10 + (s[11] - '0');
  se = (s[12] - '0') * 10 + (s[13] - '0');
  if (!qddate(d, 10) || h > 23 || mi > 59 || se > 59)
    return 0;
  memcpy(tm, d, 10);
  tm[10] = 'T';
  memcpy(tm + 11, s + 8, 2);
  tm[13] = ':';
  memcpy(tm + 14, s + 10, 2);
  tm[16] = ':';
  memcpy(tm + 17, s + 12, 2);
  tm[19] = 'Z';
  tm[20] = '\0';
  return 1;
}

static int wayback(const djs *rs, const djs *rp, dbuf *b, char tm[21],
                   char *why, size_t cap) {
  const djs *c = qdjget(qdjget(rp, "archived_snapshots"), "closest"), *av;
  size_t bn = 0, tn = 0, sn = 0;
  const char *base = sget(rs, "base", &bn), *ts, *st;
  char t[21];
  if (base == NULL || !urlok(base, bn, 0)) {
    qdwhy(why, cap, "a wayback resolver needs base, the archived address");
    return NQEARG;
  }
  if (qdjget(rp, "archived_snapshots") == NULL) {
    qdwhy(why, cap, "the reply is not the Wayback Machine's availability "
          "answer");
    return NQEDEC;
  }
  if (c == NULL) {
    qdwhy(why, cap, "the Wayback Machine has no copy of %.200s", base);
    return NQEDEC;
  }
  av = qdjget(c, "available");
  st = sget(c, "status", &sn);
  ts = sget(c, "timestamp", &tn);
  if (c->t != DJOBJ || av == NULL || av->t != DJTRUE) {
    qdwhy(why, cap, "the Wayback Machine has no copy of %.200s", base);
    return NQEDEC;
  }
  if (st != NULL && !(sn == 3 && memcmp(st, "200", 3) == 0)) {
    qdwhy(why, cap, "the Wayback Machine's closest copy is of an HTTP "
          "%.3s answer, not of the file", st);
    return NQEDEC;
  }
  if (ts == NULL || !wbtime(ts, tn, t)) {
    qdwhy(why, cap, "the Wayback Machine's answer has no valid timestamp");
    return NQEDEC;
  }
  /* the raw bytes of that copy, of the address asked for: the reply's
   * own url is not followed */
  qdbstr(b, "https://web.archive.org/web/");
  qdbput(b, ts, tn);
  qdbstr(b, "id_/");
  qdbput(b, base, bn);
  if (tm != NULL)
    memcpy(tm, t, 21);
  return NQOK;
}

int nqdrsp(const char *rslvj, size_t n, const char *reply, size_t rn,
           char *out, size_t cap, size_t *outlen, char tm[21], char *why,
           size_t wcap) {
  djs *rs = NULL, *rp = NULL;
  size_t kn = 0, bn = 0;
  const char *k, *base;
  dbuf b;
  int rc;
  if (why != NULL && wcap)
    why[0] = '\0';
  if (tm != NULL)
    tm[0] = '\0';
  if (rslvj == NULL || (reply == NULL && rn))
    return NQEARG;
  if (rn > QDRSPMAX) {
    qdwhy(why, wcap, "the reply is over 16 MiB");
    return NQELIM;
  }
  if ((rc = qdjparse(rslvj, n, &rs, why, wcap)) != NQOK)
    return rc;
  if ((rc = qdrslvok(rs, why, wcap)) != NQOK) {
    qdjfree(rs);
    return rc;
  }
  /* the request must be one nqdrslv builds */
  memset(&b, 0, sizeof b);
  b.max = QDURL + 1;
  rc = rslv(rs, &b, why, wcap);
  qdbfree(&b);
  if (rc != NQOK) {
    qdjfree(rs);
    return rc;
  }
  if ((rc = qdjparse(reply, rn, &rp, why, wcap)) != NQOK) {
    qdjfree(rs);
    return rc;
  }
  memset(&b, 0, sizeof b);
  b.max = QDURL + 64;
  k = sget(rs, "kind", &kn);
  base = sget(rs, "base", &bn);
  if (rp->t != DJOBJ) {
    qdwhy(why, wcap, "the reply is not a JSON object");
    rc = NQEDEC;
  } else if (strcmp(k, "ckan") == 0) {
    rc = ckan(rs, rp, ishttps(base), &b, why, wcap);
  } else if (strcmp(k, "socrata") == 0) {
    rc = socrata(rs, rp, &b, why, wcap);
  } else if (strcmp(k, "arcgis") == 0) {
    rc = arcgis(rs, rp, ishttps(base), &b, why, wcap);
  } else {
    rc = wayback(rs, rp, &b, tm, why, wcap);
  }
  qdjfree(rs);
  qdjfree(rp);
  if (rc == NQOK && b.err == NQELIM) {
    qdwhy(why, wcap, "the address would be over %d bytes", QDURL);
    rc = NQEDEC;
  }
  if (rc == NQOK)
    rc = qdbout(&b, out, cap, outlen);
  if (rc != NQOK && tm != NULL)
    tm[0] = '\0';
  qdbfree(&b);
  return rc;
}

/* the raw form of a Wayback Machine snapshot address into b */
static void wbraw(dbuf *b, const char *u, size_t n) {
  size_t h = ishttps(u) ? 8 : ishttp(u) ? 7 : 0, i, k;
  static const char wb[] = "web.archive.org/web/";
  if (h == 0 || n < h + sizeof wb - 1 ||
      !caseq(u + h, sizeof wb - 1, wb)) {
    qdbput(b, u, n);
    return;
  }
  i = h + sizeof wb - 1;
  for (k = i; k < n && u[k] >= '0' && u[k] <= '9'; k++) {
  }
  if (k == i || k - i > 14) {
    qdbput(b, u, n);
    return;
  }
  qdbstr(b, "https://web.archive.org/web/");
  qdbput(b, u + i, k - i);
  /* a modifier such as im_ or if_ is replaced by id_ */
  while (k < n && ((u[k] >= 'a' && u[k] <= 'z') || u[k] == '_'))
    k++;
  if (k >= n || u[k] != '/') {
    b->err = b->err ? b->err : NQEDEC;
    return;
  }
  qdbstr(b, "id_");
  qdbput(b, u + k, n - k);
}

int nqdwb(const char *url, char *out, size_t cap, size_t *outlen) {
  dbuf b;
  int rc;
  size_t n;
  if (url == NULL)
    return NQEARG;
  n = strlen(url);
  if (!urlok(url, n, 0))
    return NQEARG;
  memset(&b, 0, sizeof b);
  b.max = QDURL + 64;
  wbraw(&b, url, n);
  rc = b.err == NQEDEC ? NQEARG : qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}

/* the "sources" element of path, or NULL */
static const djs *srcof(const nqdrec *r, const char *path) {
  const djs *a = qdjget(qdrectree(r), "sources");
  size_t i;
  if (a == NULL || path == NULL)
    return NULL;
  for (i = 0; i < a->n; i++) {
    size_t n = 0;
    const char *p = sget(a->k[i], "path", &n);
    if (p != NULL && strcmp(p, path) == 0)
      return a->k[i];
  }
  return NULL;
}

int nqdaddr(const nqdrec *r, const char *path, size_t i, int *kind,
            char *out, size_t cap, size_t *outlen) {
  const djs *e, *v, *rs, *m;
  size_t n = 0, k = 0;
  dbuf b;
  int rc;
  if (kind != NULL)
    *kind = 0;
  if (r == NULL || path == NULL)
    return NQEARG;
  if ((e = srcof(r, path)) == NULL)
    return NQEIO;
  v = qdjget(e, "synthetic");
  if (v != NULL && v->t == DJTRUE)
    return NQEARG;
  memset(&b, 0, sizeof b);
  /* the recorded url, the portal, each mirror, the archived copy */
  if (sget(e, "url", &n) != NULL && k++ == i) {
    if (kind != NULL)
      *kind = NQDAURL;
    qdbstr(&b, sget(e, "url", &n));
    goto done;
  }
  rs = qdjget(e, "resolver");
  if (rs != NULL) {
    size_t kn = 0;
    const char *kd = sget(rs, "kind", &kn);
    if (kd != NULL && strcmp(kd, "direct") == 0) {
      size_t bn = 0;
      const char *bs = sget(rs, "base", &bn), *u = sget(e, "url", &n);
      if (bs != NULL && (u == NULL || strcmp(u, bs) != 0) && k++ == i) {
        if (kind != NULL)
          *kind = NQDAURL;
        qdbstr(&b, bs);
        goto done;
      }
    } else if (k++ == i) {
      char why[200];
      if (kind != NULL)
        *kind = NQDAPORT;
      if ((rc = rslv(rs, &b, why, sizeof why)) != NQOK) {
        qdbfree(&b);
        return rc;
      }
      goto done;
    }
  }
  m = qdjget(e, "mirrors");
  if (m != NULL && i >= k && i - k < m->n) {
    if (kind != NULL)
      *kind = NQDAMIR;
    qdbput(&b, m->k[i - k]->s, m->k[i - k]->sl);
    goto done;
  }
  k += m != NULL ? m->n : 0;
  v = qdjget(qdjget(e, "archived"), "url");
  if (v != NULL && v->t == DJSTR && k == i) {
    if (kind != NULL)
      *kind = NQDAARC;
    if (urlok(v->s, v->sl, 0))
      wbraw(&b, v->s, v->sl);
    else
      qdbput(&b, v->s, v->sl);
    goto done;
  }
  return NQEIO;
done:
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}

int nqdvrfy(const nqdrec *r, const char *path, const uint8_t *b, size_t n) {
  const djs *e, *h;
  uint8_t d[32];
  char hx[65];
  int64_t sz = 0;
  int rc;
  if (r == NULL || path == NULL || (b == NULL && n))
    return NQEARG;
  if ((e = srcof(r, path)) == NULL)
    return NQEIO;
  h = qdjget(e, "sha256");
  if (h == NULL || h->t != DJSTR || h->sl != 64 ||
      !qdjint(qdjget(e, "size"), &sz))
    return NQEIO;
  if ((uint64_t)sz != (uint64_t)n)
    return NQEVRFY;
  if ((rc = nqhash(NQS256, n ? b : (const uint8_t *)"", n, d, 32)) != NQOK)
    return rc;
  qdhex(d, 32, hx);
  return nqcteq(hx, h->s, 64) == 1 ? NQOK : NQEVRFY;
}

int nqdfld(const nqdrec *r, const char *member, size_t i, const char *field,
           char *out, size_t cap, size_t *outlen) {
  const djs *a, *e, *v;
  dbuf b;
  int rc;
  if (r == NULL || member == NULL || field == NULL)
    return NQEARG;
  a = qdjget(qdrectree(r), member);
  if (a == NULL)
    return NQEIO;
  if (a->t == DJARR) {
    if (i >= a->n)
      return NQEIO;
    e = a->k[i];
  } else {
    if (i != 0)
      return NQEIO;
    e = a;
  }
  if ((v = qdjget(e, field)) == NULL)
    return NQEIO;
  memset(&b, 0, sizeof b);
  if (v->t == DJSTR)
    qdbput(&b, v->s, v->sl);
  else
    qdjwrite(v, &b);
  rc = qdbout(&b, out, cap, outlen);
  qdbfree(&b);
  return rc;
}
