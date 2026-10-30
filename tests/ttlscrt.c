/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The TLS client's certificate checks, offline, on the test PKI of
 * vectors/tls/pki (gen.sh): PEM bundles, the path and its refusals
 * (expired, not yet valid, untrusted root with the same name, missing
 * intermediate, no serverAuth, no digitalSignature), host names and
 * addresses (wildcards, case, no common-name fallback, a critical
 * subjectAltName), CertificateVerify signatures of every scheme with
 * one-bit changes and wrong schemes, host names nqtlmk refuses, and
 * stapled OCSP responses (good, revoked, stale, from a responder with no
 * authority, about another certificate; must-staple), and Certificate
 * Transparency: SCTs embedded and in the TLS extension from the test
 * logs, changed ones, unknown logs, one operator, log states and
 * intervals, SCTs from the future, log lists refused, and a public
 * certificate (www.google.com) with an excerpt of Chrome's log list. */
#include "tls/tls.h"
#include "nqt.h"
#include "tvec.h"

#define PKI "vectors/tls/pki/"

static int nullwr(void *u, const uint8_t *b, size_t n) {
  (void)u;
  (void)b;
  (void)n;
  return NQOK;
}

static int nullrd(void *u, uint8_t *b, size_t cap, size_t *got) {
  (void)u;
  (void)b;
  (void)cap;
  *got = 0;
  return NQOK;
}

static const nqtlio io = {nullwr, nullrd, NULL};

/* the concatenation of up to four files */
static char *cat(const char *a, const char *b, const char *c, size_t *n) {
  const char *f[3];
  char *out = NULL;
  size_t i, on = 0;
  f[0] = a;
  f[1] = b;
  f[2] = c;
  for (i = 0; i < 3 && f[i] != NULL; i++) {
    char path[128], *buf = NULL, *nb;
    size_t bn = 0;
    snprintf(path, sizeof path, PKI "%s", f[i]);
    if (nqreadf(path, 1u << 20, &buf, &bn) != NQOK) {
      fprintf(stderr, "cannot read %s\n", path);
      free(out);
      return NULL;
    }
    nb = (char *)realloc(out, on + bn + 1);
    if (nb == NULL) {
      nqfree(buf, bn + 1);
      free(out);
      return NULL;
    }
    out = nb;
    memcpy(out + on, buf, bn);
    on += bn;
    nqfree(buf, bn + 1);
  }
  *n = on;
  return out;
}

/* a client trusting anchors, with the server's chain (leaf first) as
 * its received certificates; kept alive in *srv */
static nqtls *setup(const char *host, const char *anc, const char *leaf,
                    const char *inter, const char *extra, nqtls **srv) {
  nqtls *t = NULL, *s = NULL;
  size_t an = 0, cn = 0, i;
  char *a = cat(anc, NULL, NULL, &an), *c = cat(leaf, inter, extra, &cn);
  *srv = NULL;
  if (a == NULL || c == NULL) {
    NQTCHK(0);
    free(a);
    free(c);
    return NULL;
  }
  NQTEQI(nqtlmk(&t, host, (const uint8_t *)a, an, &io), NQOK);
  /* a second context parses the server's chain in the same order */
  NQTEQI(nqtlmk(&s, "x", (const uint8_t *)c, cn, &io), NQOK);
  free(a);
  free(c);
  if (t == NULL || s == NULL) {
    nqtlfree(t);
    nqtlfree(s);
    return NULL;
  }
  for (i = 0; i < s->nanc && i < NQTLCMAX; i++) t->crt[i] = s->anc[i];
  t->ncrt = i;
  *srv = s;
  return t;
}

/* 2030-01-01T00:00:00Z */
#define NOW ((int64_t)1893456000)

static void path(const char *name, const char *host, const char *anc,
                 const char *leaf, const char *inter, const char *extra,
                 int64_t now, int want, const char *why) {
  nqtls *s, *t = setup(host, anc, leaf, inter, extra, &s);
  int rc;
  if (t == NULL) return;
  rc = nqtlpath(t, now);
  if (rc != want || (why != NULL && strstr(t->why, why) == NULL)) {
    fprintf(stderr, "%s: %s (%s)\n", name, nqerr(rc), t->why);
  }
  NQTEQI(rc, want);
  if (why != NULL) NQTCHK(strstr(t->why, why) != NULL);
  nqtlfree(t);
  nqtlfree(s);
}

static void paths(void) {
  path("RSA leaf", "localhost", "root.pem", "rsa.pem", "inter.pem", NULL,
       NOW, NQOK, NULL);
  path("EC leaf, IPv4", "127.0.0.1", "root.pem", "ec.pem", "inter.pem",
       NULL, NOW, NQOK, NULL);
  path("EC leaf, IPv6", "::1", "root.pem", "ec.pem", "inter.pem", NULL, NOW,
       NQOK, NULL);
  path("P-384 under the root", "localhost", "root.pem", "ec384.pem", NULL,
       NULL, NOW, NQOK, NULL);
  /* the chain out of order, with a stranger in it */
  path("shuffled chain", "localhost", "root.pem", "rsa.pem", "other.pem",
       "inter.pem", NOW, NQOK, NULL);
  path("wrong host", "example.com", "root.pem", "rsa.pem", "inter.pem", NULL,
       NOW, NQEVRFY, "not for this host");
  path("wrong address", "127.0.0.2", "root.pem", "rsa.pem", "inter.pem",
       NULL, NOW, NQEVRFY, "not for this host");
  path("expired", "localhost", "root.pem", "old.pem", "inter.pem", NULL, NOW,
       NQEVRFY, "expired");
  path("not yet valid", "localhost", "root.pem", "rsa.pem", "inter.pem",
       NULL, (int64_t)1735689600, NQEVRFY, "expired or is not yet");
  path("after the root", "localhost", "root.pem", "rsa.pem", "inter.pem",
       NULL, (int64_t)2398464000, NQEVRFY, NULL);
  path("same-name root", "localhost", "root.pem", "evil.pem", "other.pem",
       NULL, NOW, NQEVRFY, "no valid path");
  path("missing intermediate", "localhost", "root.pem", "rsa.pem", NULL,
       NULL, NOW, NQEVRFY, "no valid path");
  path("other anchors", "localhost", "other.pem", "rsa.pem", "inter.pem",
       NULL, NOW, NQEVRFY, "no valid path");
  path("clientAuth", "localhost", "root.pem", "cli.pem", "inter.pem", NULL,
       NOW, NQEVRFY, "serverAuth");
  path("keyEncipherment only", "localhost", "root.pem", "noku.pem",
       "inter.pem", NULL, NOW, NQEVRFY, "digitalSignature");
  path("common name only", "localhost", "root.pem", "cn.pem", "inter.pem",
       NULL, NOW, NQEVRFY, "not for this host");
  path("critical SAN", "localhost", "root.pem", "crit.pem", "inter.pem",
       NULL, NOW, NQOK, NULL);
  /* an intermediate as the anchor is enough */
  path("intermediate anchor", "localhost", "inter.pem", "rsa.pem", NULL,
       NULL, NOW, NQOK, NULL);
  /* the leaf is never its own anchor */
  path("leaf as anchor", "localhost", "rsa.pem", "rsa.pem", NULL, NULL, NOW,
       NQEVRFY, NULL);
}

static void names(void) {
  static const struct {
    const char *h;
    int ok;
  } v[] = {{"a.w.example", 1},     {"A.W.Example", 1},
           {"w.example", 0},       {"a.b.w.example", 0},
           {".w.example", 0},      {"foo.bad.example", 0},
           {"f.bad.example", 0},   {"x.com", 0},
           {"exact.example", 1},   {"EXACT.EXAMPLE", 1},
           {"upper.example", 1},   {"a.b.x.example", 0},
           {"b.x.example", 0},     {"exact.example.", 0},
           {"xexact.example", 0},  {"localhost", 0}};
  nqtls *s, *t = setup("a.w.example", "root.pem", "wild.pem", NULL, NULL,
                       &s);
  uint8_t ip[16];
  size_t i;
  if (t == NULL) return;
  for (i = 0; i < sizeof v / sizeof v[0]; i++) {
    int got = nqtlname(&t->crt[0], v[i].h, 0, NULL);
    if (got != v[i].ok) fprintf(stderr, "name %s: %d\n", v[i].h, got);
    NQTEQI(got, v[i].ok);
  }
  NQTEQI(nqtlip("192.0.2.7", ip), 4);
  NQTEQI(nqtlname(&t->crt[0], "192.0.2.7", 4, ip), 1);
  /* an address never matches a DNS name, nor a name an address */
  NQTEQI(nqtlname(&t->crt[0], "192.0.2.7", 0, NULL), 0);
  NQTEQI(nqtlip("192.0.2.8", ip), 4);
  NQTEQI(nqtlname(&t->crt[0], "192.0.2.8", 4, ip), 0);
  NQTEQI(nqtlip("2001:db8::7", ip), 16);
  NQTEQI(nqtlname(&t->crt[0], "2001:db8::7", 16, ip), 1);
  NQTEQI(nqtlip("2001:db8::8", ip), 16);
  NQTEQI(nqtlname(&t->crt[0], "2001:db8::8", 16, ip), 0);
  /* the whole path still checks */
  NQTEQI(nqtlpath(t, NOW), NQEVRFY); /* no intermediate given */
  nqtlfree(t);
  nqtlfree(s);
}

/* ---- CertificateVerify ---- */

static void cv1(const char *leaf, const char *sigf, uint16_t sch,
                size_t hl, const uint16_t *bad, size_t nbad) {
  nqtls *s, *t = setup("localhost", "root.pem", leaf, NULL, NULL, &s);
  char path[128], *sig = NULL;
  uint8_t th[48];
  size_t sn = 0, i, fl = 0;
  if (t == NULL) return;
  snprintf(path, sizeof path, PKI "%s", sigf);
  NQTEQI(nqreadf(path, 4096, &sig, &sn), NQOK);
  if (sig == NULL) return;
  for (i = 0; i < hl; i++) th[i] = (uint8_t)i;
  t->hl = hl;
  NQTEQI(nqtlcv(t, sch, th, (const uint8_t *)sig, sn), NQOK);
  /* every bit of the first eight bytes, then every 29th bit (valgrind
   * runs this test too) */
  for (i = 0; i < 8 * sn; i += i < 64 ? 1 : 29) {
    t->err = 0;
    sig[i / 8] ^= (char)(1u << (i % 8));
    if (nqtlcv(t, sch, th, (const uint8_t *)sig, sn) == NQOK) fl++;
    sig[i / 8] ^= (char)(1u << (i % 8));
  }
  NQTEQI(fl, 0);
  /* the transcript hash changed */
  t->err = 0;
  th[0] ^= 1;
  NQTEQI(nqtlcv(t, sch, th, (const uint8_t *)sig, sn), NQEVRFY);
  th[0] ^= 1;
  for (i = 0; i < nbad; i++) {
    t->err = 0;
    NQTEQI(nqtlcv(t, bad[i], th, (const uint8_t *)sig, sn), NQEVRFY);
  }
  nqfree(sig, sn + 1);
  nqtlfree(t);
  nqtlfree(s);
}

static void cvs(void) {
  static const uint16_t nrsa[] = {0x0403, 0x0503, 0x0805, 0x0401, 0x0201};
  static const uint16_t nrsa384[] = {0x0804, 0x0806};
  static const uint16_t nec[] = {0x0503, 0x0804, 0x0401};
  static const uint16_t nec384[] = {0x0403, 0x0805};
  cv1("rsa.pem", "cv-rsa.sig", 0x0804, 32, nrsa, 5);
  cv1("rsa.pem", "cv-rsa384.sig", 0x0805, 48, nrsa384, 2);
  cv1("ec.pem", "cv-ec.sig", 0x0403, 32, nec, 3);
  cv1("ec384.pem", "cv-ec384.sig", 0x0503, 48, nec384, 2);
}

/* ---- bundles and host names ---- */

static void bundles(void) {
  static const char junk[] = "-----BEGIN CERTIFICATE-----\n!!!!\n"
                             "-----END CERTIFICATE-----\n";
  static const char tr[] = "-----BEGIN TRUSTED CERTIFICATE-----\nMA==\n"
                           "-----END TRUSTED CERTIFICATE-----\n";
  nqtls *t = NULL;
  size_t n = 0, i, k = 0;
  char *a = cat("root.pem", "other.pem", "inter.pem", &n), *c;
  NQTCHK(a != NULL);
  if (a == NULL) return;
  NQTEQI(nqtlmk(&t, "localhost", (const uint8_t *)a, n, &io), NQOK);
  NQTEQI(t->nanc, 3);
  nqtlfree(t);
  /* CRLF line ends, junk around and between, a TRUSTED block */
  c = (char *)malloc(2 * n + 400);
  NQTCHK(c != NULL);
  if (c == NULL) {
    free(a);
    return;
  }
  memcpy(c, tr, sizeof tr - 1);
  k = sizeof tr - 1;
  memcpy(c + k, junk, sizeof junk - 1);
  k += sizeof junk - 1;
  for (i = 0; i < n; i++) {
    if (a[i] == '\n') c[k++] = '\r';
    c[k++] = a[i];
  }
  NQTEQI(nqtlmk(&t, "localhost", (const uint8_t *)c, k, &io), NQOK);
  NQTEQI(t->nanc, 3);
  nqtlfree(t);
  NQTEQI(nqtlmk(&t, "localhost", (const uint8_t *)junk, sizeof junk - 1,
                &io),
         NQEDEC);
  NQTEQI(nqtlmk(&t, "localhost", (const uint8_t *)"hello", 5, &io), NQEDEC);
  NQTCHK(t == NULL);
  /* host names: refused, and lower-cased */
  {
    static const char *const bad[] = {
        "", "a b", "-a.com", "a-.com", "a..b", ".", "a.com..", "a_b.com",
        "\xc3\xa9.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"};
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      NQTEQI(nqtlmk(&t, bad[i], (const uint8_t *)a, n, &io), NQEARG);
    }
    NQTEQI(nqtlmk(&t, "WWW.Example.COM.", (const uint8_t *)a, n, &io), NQOK);
    if (t != NULL) NQTCHK(strcmp(t->host, "www.example.com") == 0);
    nqtlfree(t);
  }
  /* the public functions without NQTLS */
#ifndef NQTLSON
  NQTEQI(nqtlnew(&t, "localhost", (const uint8_t *)a, n, &io), NQENOSUP);
  NQTCHK(t == NULL);
#else
  NQTEQI(nqtlnew(&t, "localhost", NULL, 0, &io), NQEARG);
  NQTEQI(nqtlnew(&t, "localhost", (const uint8_t *)a, n, &io), NQOK);
  NQTEQI(nqtlwr(t, (const uint8_t *)"x", 1), NQESTATE);
  nqtlfree(t);
#endif
  free(a);
  free(c);
}

/* ---- stapled OCSP responses ---- */

/* the path of leaf (under inter.pem) with the staple in file resp, or
 * the bytes junk, or none */
static void stap1(const char *name, const char *leaf, const char *resp,
                  const char *junk, int want, const char *why) {
  nqtls *s, *t = setup("localhost", "root.pem", leaf, "inter.pem", NULL, &s);
  char path[128], *r = NULL;
  size_t rn = 0;
  int rc;
  if (t == NULL) return;
  if (resp != NULL) {
    snprintf(path, sizeof path, PKI "%s", resp);
    NQTEQI(nqreadf(path, 1u << 16, &r, &rn), NQOK);
    if (r == NULL) return;
    t->ocsp.p = (const uint8_t *)r;
    t->ocsp.n = rn;
  } else if (junk != NULL) {
    t->ocsp.p = (const uint8_t *)junk;
    t->ocsp.n = strlen(junk);
  }
  rc = nqtlpath(t, NOW);
  if (rc != want || (why != NULL && strstr(t->why, why) == NULL)) {
    fprintf(stderr, "%s: %s (%s)\n", name, nqerr(rc), t->why);
  }
  NQTEQI(rc, want);
  if (why != NULL) NQTCHK(strstr(t->why, why) != NULL);
  if (r != NULL) nqfree(r, rn + 1);
  nqtlfree(t);
  nqtlfree(s);
}

static void staples(void) {
  stap1("good", "rsa.pem", "ocsp-good.der", NULL, NQOK, NULL);
  stap1("revoked", "rsa.pem", "ocsp-rev.der", NULL, NQEVRFY, "is revoked");
  stap1("stale", "rsa.pem", "ocsp-old.der", NULL, NQEVRFY,
        "does not check");
  stap1("no authority", "rsa.pem", "ocsp-oth.der", NULL, NQEVRFY,
        "does not check");
  stap1("another certificate", "ec.pem", "ocsp-good.der", NULL, NQEVRFY,
        "does not check");
  stap1("not DER", "rsa.pem", NULL, "\x30\x03\x0a\x01", NQEVRFY,
        "does not check");
  stap1("none", "rsa.pem", NULL, NULL, NQOK, NULL);
  stap1("must-staple, none", "ms.pem", NULL, NULL, NQEVRFY, "must-staple");
  stap1("must-staple, good", "ms.pem", "ocsp-ms.der", NULL, NQOK, NULL);
  stap1("must-staple, another's", "ms.pem", "ocsp-rev.der", NULL, NQEVRFY,
        "does not check");
}

/* ---- Certificate Transparency ---- */

/* a file of vectors/tls/, whole; free with nqfree(b, *n + 1) */
static char *rd(const char *f, size_t *n) {
  char path[128], *b = NULL;
  snprintf(path, sizeof path, "vectors/tls/%s", f);
  *n = 0;
  if (nqreadf(path, 1u << 20, &b, n) != NQOK) {
    fprintf(stderr, "cannot read %s\n", path);
    NQTCHK(0);
    return NULL;
  }
  return b;
}

/* js with the last "from" replaced by "to" (malloc'd) */
static char *sub(const char *js, const char *from, const char *to,
                 size_t *n) {
  const char *at = NULL, *p;
  char *o;
  size_t fl = strlen(from), tl = strlen(to), jl = strlen(js);
  for (p = strstr(js, from); p != NULL; p = strstr(p + 1, from)) at = p;
  NQTCHK(at != NULL);
  if (at == NULL || (o = (char *)malloc(jl - fl + tl + 1)) == NULL) {
    return NULL;
  }
  memcpy(o, js, (size_t)(at - js));
  memcpy(o + (at - js), to, tl);
  memcpy(o + (at - js) + tl, at + fl, jl - (size_t)(at - js) - fl + 1);
  *n = jl - fl + tl;
  return o;
}

/* the path of leaf under inter for host at now, with the log list js (jn
 * bytes) and the TLS extension's SCT list in file tls (or none); flip
 * changes the last byte of the TLS list (1) or of the embedded one (2) */
static void ct1(const char *name, const char *host, const char *anc,
                const char *leaf, const char *inter, const char *js,
                size_t jn, const char *tls, int flip, int64_t now, int want,
                const char *why) {
  nqtls *s, *t = setup(host, anc, leaf, inter, NULL, &s);
  char *x = NULL;
  size_t xn = 0;
  int rc;
  if (t == NULL) return;
  NQTEQI(nqtlctl(t, (const uint8_t *)js, jn), NQOK);
  if (tls != NULL && (x = rd(tls, &xn)) != NULL) {
    if (flip == 1) x[xn - 1] ^= 1;
    t->sctl.p = (const uint8_t *)x;
    t->sctl.n = xn;
  }
  /* a changed leaf fails the path: then only the SCTs are checked */
  if (flip == 2 && t->crt[0].sct.n > 0) {
    /* the bytes are s's copy of the bundle */
    s->ab[(size_t)(t->crt[0].sct.p - s->ab) + t->crt[0].sct.n - 1] ^= 1;
    rc = nqtlctv(t, &t->crt[0], &t->crt[1], now);
  } else {
    rc = nqtlpath(t, now);
  }
  if (rc != want || (why != NULL && strstr(t->why, why) == NULL)) {
    fprintf(stderr, "%s: %s (%s)\n", name, nqerr(rc), t->why);
  }
  NQTEQI(rc, want);
  if (why != NULL) NQTCHK(strstr(t->why, why) != NULL);
  if (x != NULL) nqfree(x, xn + 1);
  nqtlfree(t);
  nqtlfree(s);
}

/* the state of the test logs' list, and that of ct2 changed */
#define USE "{\"usable\": {\"timestamp\": \"2025-06-01T00:00:00Z\"}}"

static void ctst(const char *js, const char *to, int want,
                 const char *why) {
  size_t n = 0;
  char *v = sub(js, USE, to, &n);
  if (v == NULL) return;
  ct1(to, "localhost", "root.pem", "sct.pem", "inter.pem", v, n, NULL, 0,
      NOW, want, why);
  free(v);
}

/* SCT time 2026-01-02 */
#define SCTT ((int64_t)1767312000)

static void cts(void) {
  size_t ln = 0, on = 0, gn = 0, n;
  char *l = rd("pki/ct-logs.json", &ln), *one = rd("pki/ct-one.json", &on),
       *g = rd("ct/logs.json", &gn);
  nqtls *t = NULL, *s = NULL;
  nqtloff o;
  if (l == NULL || one == NULL || g == NULL) goto out;
  /* SCTs embedded, from ct1 (A) and ct2 (B) */
  ct1("embedded", "localhost", "root.pem", "sct.pem", "inter.pem", l, ln,
      NULL, 0, NOW, NQOK, NULL);
  ct1("embedded, list without B", "localhost", "root.pem", "sct.pem",
      "inter.pem", one, on, NULL, 0, NOW, NQEVRFY,
      "1 log operator, 2 are needed (1 valid, 1 from logs not listed");
  ct1("embedded, changed", "localhost", "root.pem", "sct.pem", "inter.pem",
      l, ln, NULL, 2, NOW, NQEVRFY, "(1 valid, 0 from logs not listed, 1 bad");
  /* in the TLS extension, over rsa.pem */
  ct1("TLS extension", "localhost", "root.pem", "rsa.pem", "inter.pem", l,
      ln, "pki/sct-x.bin", 0, NOW, NQOK, NULL);
  ct1("TLS extension, one operator", "localhost", "root.pem", "rsa.pem",
      "inter.pem", l, ln, "pki/sct-a.bin", 0, NOW, NQEVRFY,
      "1 log operator, 2 are needed (2 valid");
  ct1("TLS extension, changed", "localhost", "root.pem", "rsa.pem",
      "inter.pem", l, ln, "pki/sct-x.bin", 1, NOW, NQEVRFY, "1 bad");
  ct1("TLS extension, another certificate", "localhost", "root.pem",
      "ec.pem", "inter.pem", l, ln, "pki/sct-x.bin", 0, NOW, NQEVRFY,
      "from 0 log operators");
  /* both places together; a log counted once */
  ct1("embedded and TLS, ct2 twice", "localhost", "root.pem", "sct.pem",
      "inter.pem", l, ln, "pki/sct-b.bin", 0, NOW, NQOK, NULL);
  ct1("embedded and TLS, B not listed", "localhost", "root.pem", "sct.pem",
      "inter.pem", one, on, "pki/sct-b.bin", 0, NOW, NQEVRFY,
      "(1 valid, 2 from logs not listed");
  ct1("none", "localhost", "root.pem", "rsa.pem", "inter.pem", l, ln, NULL,
      0, NOW, NQEVRFY, "has no SCTs");
  /* the SCTs are from after the time of the check */
  ct1("from the future", "localhost", "root.pem", "sct.pem", "inter.pem", l,
      ln, NULL, 0, SCTT - 3600, NQEVRFY, "2 from logs not usable then");
  ct1("a minute ahead", "localhost", "root.pem", "sct.pem", "inter.pem", l,
      ln, NULL, 0, SCTT - 60, NQOK, NULL);
  /* the state of ct2 */
  ctst(l, "{\"qualified\": {\"timestamp\": \"2025-06-01T00:00:00Z\"}}", NQOK,
       NULL);
  ctst(l, "{\"readonly\": {\"timestamp\": \"2025-06-01T00:00:00Z\"}}", NQOK,
       NULL);
  ctst(l, "{\"retired\": {\"timestamp\": \"2026-02-01T00:00:00Z\"}}", NQOK,
       NULL);
  ctst(l, "{\"retired\": {\"timestamp\": \"2025-12-01T00:00:00Z\"}}",
       NQEVRFY, "1 from logs not usable then");
  ctst(l, "{\"pending\": {\"timestamp\": \"2025-06-01T00:00:00Z\"}}",
       NQEVRFY, "1 from logs not usable then");
  ctst(l, "{\"rejected\": {\"timestamp\": \"2025-06-01T00:00:00Z\"}}",
       NQEVRFY, "1 from logs not usable then");
  ctst(l, "{}", NQEVRFY, "1 from logs not usable then");
  /* the leaf's notAfter, 2046-01-01, in the interval or not */
  ctst(l, USE ", \"temporal_interval\": {\"start_inclusive\": "
       "\"2045-07-01T00:00:00Z\", \"end_exclusive\": \"2046-01-01T00:00:01Z\"}",
       NQOK, NULL);
  ctst(l, USE ", \"temporal_interval\": {\"start_inclusive\": "
       "\"2045-07-01T00:00:00Z\", \"end_exclusive\": \"2046-01-01T00:00:00Z\"}",
       NQEVRFY, "1 from logs not usable then");
  /* a public certificate, www.google.com as served on 2026-10-30 (vectors
   * SOURCES.md), with an excerpt of Chrome's log list of that day */
  ct1("www.google.com", "www.google.com", "../ct/r4.pem", "../ct/www.pem",
      "../ct/we2.pem", g, gn, NULL, 0, (int64_t)1793318400, NQOK, NULL);
  ct1("www.google.com, test logs", "www.google.com", "../ct/r4.pem",
      "../ct/www.pem", "../ct/we2.pem", l, ln, NULL, 0, (int64_t)1793318400,
      NQEVRFY, "2 from logs not listed");
  /* lists that are refused */
  NQTEQI(nqtlmk(&t, "localhost", NULL, 0, &io), NQOK);
  if (t == NULL) goto out;
  NQTEQI(nqtlctl(t, (const uint8_t *)"{}", 2), NQEDEC);
  NQTEQI(nqtlctl(t, (const uint8_t *)"[", 1), NQEDEC);
  {
    static const char e[] = "{\"operators\": [{\"logs\": []}]}";
    NQTEQI(nqtlctl(t, (const uint8_t *)e, strlen(e)), NQEDEC);
  }
  {
    /* the last log's key swapped for the first's: its log_id is then
     * not its key's hash */
    const char *k = "\"key\": \"", *a = strstr(l, k), *b = a, *p;
    char *from = NULL, *to = NULL, *v = NULL;
    for (p = a; p != NULL; p = strstr(p + 1, k)) b = p;
    if (a != NULL && b != a) {
      a += strlen(k);
      b += strlen(k);
      from = (char *)malloc((size_t)(strchr(b, '"') - b) + 1);
      to = (char *)malloc((size_t)(strchr(a, '"') - a) + 1);
    }
    NQTCHK(from != NULL && to != NULL);
    if (from != NULL && to != NULL) {
      memcpy(from, b, (size_t)(strchr(b, '"') - b));
      from[strchr(b, '"') - b] = 0;
      memcpy(to, a, (size_t)(strchr(a, '"') - a));
      to[strchr(a, '"') - a] = 0;
      v = sub(l, from, to, &n);
      if (v != NULL) NQTEQI(nqtlctl(t, (const uint8_t *)v, n), NQEDEC);
      NQTEQI(t->nlg, 0);
    }
    free(from);
    free(to);
    free(v);
  }
  NQTEQI(nqtlctl(t, (const uint8_t *)l, ln), NQOK);
  NQTEQI(t->nlg, 3);
  NQTEQI(nqtlctl(t, (const uint8_t *)g, gn), NQOK);
  NQTEQI(t->nlg, 15);
  /* the ClientHello offers signed_certificate_timestamp only with logs;
   * nqtlhand fails at the end of the null stream, the hello sent */
  (void)nqtlhand(t);
  NQTEQI(nqtlscan(t->ch, t->chn, &o), NQOK);
  {
    size_t i;
    int sr = 0, sc = 0;
    for (i = 0; i < o.next; i++) {
      sr += o.ext[i] == 5;
      sc += o.ext[i] == 18;
    }
    NQTEQI(sr, 1);
    NQTEQI(sc, 1);
  }
  NQTEQI(nqtlctl(t, (const uint8_t *)l, ln), NQESTATE);
  NQTEQI(nqtlmk(&s, "localhost", NULL, 0, &io), NQOK);
  if (s != NULL) {
    size_t i;
    int sr = 0, sc = 0;
    (void)nqtlhand(s);
    NQTEQI(nqtlscan(s->ch, s->chn, &o), NQOK);
    for (i = 0; i < o.next; i++) {
      sr += o.ext[i] == 5;
      sc += o.ext[i] == 18;
    }
    NQTEQI(sr, 1);
    NQTEQI(sc, 0);
  }
out:
  nqtlfree(t);
  nqtlfree(s);
  if (l != NULL) nqfree(l, ln + 1);
  if (one != NULL) nqfree(one, on + 1);
  if (g != NULL) nqfree(g, gn + 1);
}

int main(void) {
  paths();
  names();
  cvs();
  bundles();
  staples();
  cts();
  return nqtdone("ttlscrt");
}
