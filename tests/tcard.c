/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Identity cards (noqtis-idcard-1): a card round trips with every
 * algorithm kind; each field's limits and shapes, at and past the edge;
 * ORCID iDs and their check digit, the URL form and a lower-case x made
 * bare; every changed byte, a removed or added field, another key and
 * cards signed for other fields refused; the card's context kept apart
 * from the seal's and the key statements' in both directions; and
 * malformed, truncated, deep and huge input refused without a crash. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "cap/cap.h"
#include "core/int.h"
#include "nqt.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#define NQTFS 1
#endif

#define T0 1767225600 /* 2026-01-01T00:00:00Z */

#if defined(__wasm32__)
/* bindings/npm/lib/index.js reads nqcardf at these offsets */
_Static_assert(offsetof(nqcardf, pk) == 4, "nqcardf.pk");
_Static_assert(offsetof(nqcardf, pklen) == 2628, "nqcardf.pklen");
_Static_assert(offsetof(nqcardf, fp) == 2632, "nqcardf.fp");
_Static_assert(offsetof(nqcardf, utc) == 2672, "nqcardf.utc");
_Static_assert(offsetof(nqcardf, name) == 2693, "nqcardf.name");
_Static_assert(offsetof(nqcardf, orcid) == 2949, "nqcardf.orcid");
_Static_assert(offsetof(nqcardf, email) == 2969, "nqcardf.email");
_Static_assert(offsetof(nqcardf, url) == 3224, "nqcardf.url");
_Static_assert(offsetof(nqcardf, affil) == 4249, "nqcardf.affil");
_Static_assert(sizeof(nqcardf) == 4512, "nqcardf");
#endif

static uint8_t pk[1312], sk[2560], pk2[1312], sk2[2560];

/* a card of the ML-DSA-44 key (pk, sk) into a new buffer, or NULL with
 * *rc the code */
static char *mk(const char *name, const char *orc, const char *email,
                const char *url, const char *affil, size_t *n, int *rc) {
  char *b;
  *n = 0;
  *rc = nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, name, orc, email,
               url, affil, T0, NULL, 0, n);
  if (*rc != NQEBUF) return NULL;
  b = (char *)malloc(*n + 1);
  if (b == NULL) return NULL;
  *rc = nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, name, orc, email,
               url, affil, T0, b, *n, n);
  if (*rc != NQOK) {
    free(b);
    return NULL;
  }
  b[*n] = 0;
  return b;
}

/* nqcard's code for these fields */
static int code(const char *name, const char *orc, const char *email,
                const char *url, const char *affil) {
  size_t n = 0;
  int rc;
  char *b = mk(name, orc, email, url, affil, &n, &rc);
  free(b);
  return rc;
}

/* the verify code of b (n bytes), its fields to *f */
static int vr(const char *b, size_t n, nqcardf *f) {
  return nqcardvrfy(b, n, NULL, 0, f);
}

static int zero(const void *p, size_t n) {
  const unsigned char *b = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) {
    if (b[i] != 0) return 0;
  }
  return 1;
}

/* s of n bytes with the string value of member key replaced by val (or,
 * val NULL, the member removed), into a new buffer */
static char *setf(const char *s, const char *key, const char *val,
                  size_t *n) {
  char pat[64], *at, *e, *o;
  size_t a, b, vl = val != NULL ? strlen(val) : 0;
  snprintf(pat, sizeof pat, "\"%s\":\"", key);
  at = strstr(s, pat);
  if (at == NULL) return NULL;
  e = strchr(at + strlen(pat), '"');
  if (e == NULL) return NULL;
  a = (size_t)(at - s);
  b = (size_t)(e + 1 - s);
  o = (char *)malloc(strlen(s) + vl + 8);
  if (o == NULL) return NULL;
  /* only measured copies, each with its NUL */
  if (val != NULL) {
    memcpy(o, s, a + strlen(pat));
    memcpy(o + a + strlen(pat), val, vl);
    memcpy(o + a + strlen(pat) + vl, s + b - 1, strlen(s + b - 1) + 1);
  } else {
    /* the comma before the member, or the one after when it is first */
    if (s[a - 1] == ',') {
      memcpy(o, s, a - 1);
      memcpy(o + a - 1, s + b, strlen(s + b) + 1);
    } else {
      memcpy(o, s, a);
      memcpy(o + a, s + b + 1, strlen(s + b + 1) + 1);
    }
  }
  *n = strlen(o);
  return o;
}

/* a card signed by (p, s) over the body of these fields, under ctx:
 * how a forger with the key, or a signature of another kind, would make
 * one. Fields are written as given, unchecked. */
static char *forge(const uint8_t *p, const uint8_t *s, const char *ctx,
                   const char *at, const char *name, const char *orc,
                   const char *email, const char *url, const char *affil,
                   size_t *n) {
  nqcbuf b, o;
  char pkb[1760], sgb[3300];
  uint8_t sg[2420];
  size_t sn = 0;
  char *r = NULL;
  memset(&b, 0, sizeof b);
  memset(&o, 0, sizeof o);
  nqb64e(p, 1312, pkb);
  NQTEQI(nqcdbody(&b, "ML-DSA-44", at, pkb, name, orc, email, url, affil,
                  NULL),
         NQOK);
  NQTEQI(nqsign(NQMLDSA44, s, 2560, (const uint8_t *)b.p, b.n,
                (const uint8_t *)ctx, strlen(ctx), 0, sg, sizeof sg, &sn),
         NQOK);
  nqb64e(sg, sn, sgb);
  NQTEQI(nqcdbody(&o, "ML-DSA-44", at, pkb, name, orc, email, url, affil,
                  sgb),
         NQOK);
  r = (char *)malloc(o.n + 1);
  if (r != NULL) {
    memcpy(r, o.p, o.n);
    r[o.n] = 0;
    *n = o.n;
  }
  nqcbfree(&b);
  nqcbfree(&o);
  return r;
}

/* ---- a card made and read back ---- */

static void tround(void) {
  nqcardf f;
  size_t n = 0, m = 0;
  int rc;
  uint8_t h[32];
  char *b = mk("Ada Lovelace", "https://orcid.org/0000-0002-1825-0097",
               "ada@example.org", "https://example.org/ada",
               "Analytical Engine Society", &n, &rc);
  NQTEQI(rc, NQOK);
  NQTCHK(b != NULL);
  if (b == NULL) return;
  /* the layout: canonical, the members in RFC 8785 order */
  {
    static const char want[] =
        "{\"affil\":\"Analytical Engine Society\",\"alg\":\"ML-DSA-44\","
        "\"created\":\"2026-01-01T00:00:00Z\",\"email\":\"ada@example.org\","
        "\"format\":\"noqtis-idcard-1\",\"key\":\"";
    NQTCHK(strncmp(b, want, sizeof want - 1) == 0);
    NQTCHK(strstr(b, "\",\"name\":\"Ada Lovelace\",\"orcid\":"
                     "\"0000-0002-1825-0097\",\"signature\":\"") != NULL);
    NQTCHK(strstr(b, "\",\"url\":\"https://example.org/ada\"}") ==
           b + n - strlen("\",\"url\":\"https://example.org/ada\"}"));
  }
  NQTEQI(vr(b, n, &f), NQOK);
  NQTEQI(f.alg, NQMLDSA44);
  NQTEQI(f.pklen, sizeof pk);
  NQTEQM(f.pk, pk, sizeof pk);
  nqhash(NQS256, pk, sizeof pk, h, 32);
  NQTEQM(f.fp, h, 32);
  NQTEQI(f.created, T0);
  NQTCHK(strcmp(f.utc, "2026-01-01T00:00:00Z") == 0);
  NQTCHK(strcmp(f.name, "Ada Lovelace") == 0);
  NQTCHK(strcmp(f.orcid, "0000-0002-1825-0097") == 0);
  NQTCHK(strcmp(f.email, "ada@example.org") == 0);
  NQTCHK(strcmp(f.url, "https://example.org/ada") == 0);
  NQTCHK(strcmp(f.affil, "Analytical Engine Society") == 0);
  /* pinned to its own key, and to another */
  NQTEQI(nqcardvrfy(b, n, pk, sizeof pk, &f), NQOK);
  NQTEQI(nqcardvrfy(b, n, pk2, sizeof pk2, &f), NQEVRFY);
  NQTCHK(zero(&f, sizeof f));
  NQTEQI(nqcardvrfy(b, n, pk, sizeof pk - 1, &f), NQEVRFY);
  /* the size: asked for, and a buffer one byte short */
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, T0, NULL, 0, &m),
         NQEBUF);
  {
    char *s = (char *)malloc(m + 1);
    size_t k = 0;
    NQTCHK(s != NULL);
    if (s != NULL) {
      s[m] = 0; /* the card is not NUL-terminated: strstr below */
      NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL,
                    NULL, NULL, NULL, T0, s, m - 1, &k),
             NQEBUF);
      NQTEQI(k, m);
      NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL,
                    NULL, NULL, NULL, T0, s, m, &k),
             NQOK);
      NQTEQI(vr(s, k, &f), NQOK);
      NQTCHK(strcmp(f.name, "A") == 0 && f.orcid[0] == 0 &&
             f.email[0] == 0 && f.url[0] == 0 && f.affil[0] == 0);
      /* only the members given */
      NQTCHK(strncmp(s, "{\"alg\":", 7) == 0);
      NQTCHK(strstr(s, "\"orcid\"") == NULL &&
             strstr(s, "\"email\"") == NULL &&
             strstr(s, "\"url\"") == NULL &&
             strstr(s, "\"affil\"") == NULL);
      free(s);
    }
  }
  free(b);
  /* text outside ASCII is kept as UTF-8, and quotes escaped */
  b = mk("Ad\xc3\xa9le \"Q\" \xe6\x9d\x8e", NULL, NULL, NULL,
         "Universit\xc3\xa9 de Montr\xc3\xa9" "al", &n, &rc);
  NQTEQI(rc, NQOK);
  if (b != NULL) {
    NQTCHK(strstr(b, "\"name\":\"Ad\xc3\xa9le \\\"Q\\\" \xe6\x9d\x8e\"") !=
           NULL);
    NQTEQI(vr(b, n, &f), NQOK);
    NQTCHK(strcmp(f.name, "Ad\xc3\xa9le \"Q\" \xe6\x9d\x8e") == 0);
    free(b);
  }
  /* the key pair must be one, and Ed25519 alone is not a card key */
  NQTEQI(nqcard(NQMLDSA44, sk2, sizeof sk2, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, T0, NULL, 0, &m),
         NQEARG);
  {
    uint8_t ep[32], es[64];
    NQTEQI(nqskg(NQED25519, ep, sizeof ep, es, sizeof es), NQOK);
    NQTEQI(nqcard(NQED25519, es, sizeof es, ep, sizeof ep, "A", NULL, NULL,
                  NULL, NULL, T0, NULL, 0, &m),
           NQENOSUP);
    NQTEQI(nqcard((nqsalg)99, es, sizeof es, ep, sizeof ep, "A", NULL, NULL,
                  NULL, NULL, T0, NULL, 0, &m),
           NQENOSUP);
  }
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk - 1, pk, sizeof pk, "A", NULL,
                NULL, NULL, NULL, T0, NULL, 0, &m),
         NQEARG);
  NQTEQI(nqcard(NQMLDSA44, NULL, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, T0, NULL, 0, &m),
         NQEARG);
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, T0, NULL, 0, NULL),
         NQEARG);
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, T0, NULL, 5, &m),
         NQEARG);
}

/* one card per kind of key: SLH-DSA, a hybrid, the largest ML-DSA */
static void talgs(void) {
  static const nqsalg as[] = {NQSLH128F, NQSLHK128F, NQMDED44, NQMDED87,
                              NQMLDSA87};
  size_t i, big = 0;
  int a;
  for (a = 1; a <= 64; a++) {
    nqssz z;
    if (nqssize((nqsalg)a, &z) != NQOK) break;
    NQTCHK(z.pk <= NQCARDPK);
    if (z.pk > big) big = z.pk;
  }
  NQTEQI(big, NQCARDPK);
  for (i = 0; i < sizeof as / sizeof as[0]; i++) {
    nqssz z;
    uint8_t *p, *s;
    char *b;
    size_t n = 0;
    nqcardf f;
    NQTEQI(nqssize(as[i], &z), NQOK);
    p = (uint8_t *)malloc(z.pk);
    s = (uint8_t *)malloc(z.sk);
    if (p == NULL || s == NULL) {
      free(p);
      free(s);
      continue;
    }
    NQTEQI(nqskg(as[i], p, z.pk, s, z.sk), NQOK);
    NQTEQI(nqcard(as[i], s, z.sk, p, z.pk, "B", NULL, NULL, NULL, NULL, T0,
                  NULL, 0, &n),
           NQEBUF);
    b = (char *)malloc(n + 1);
    if (b != NULL) {
      NQTEQI(nqcard(as[i], s, z.sk, p, z.pk, "B", NULL, NULL, NULL, NULL,
                    T0, b, n, &n),
             NQOK);
      b[n] = 0;
      NQTEQI(nqcardvrfy(b, n, p, z.pk, &f), NQOK);
      NQTEQI(f.alg, as[i]);
      NQTEQI(f.pklen, z.pk);
      NQTCHK(strstr(b, nqsname(as[i])) != NULL);
      /* a card's signature is of its own algorithm: renaming it fails */
      {
        size_t k = 0;
        char *c = setf(b, "alg", "ML-DSA-44", &k);
        NQTCHK(c != NULL);
        if (c != NULL) NQTCHK(vr(c, k, &f) != NQOK);
        free(c);
      }
      free(b);
    }
    free(p);
    free(s);
  }
}

/* ---- the fields ---- */

static void fill(char *b, size_t n, char c) {
  memset(b, c, n);
  b[n] = 0;
}

static void tlimits(void) {
  char big[1200], e[400];
  size_t m = 0;
  /* name and affil: 1 to 255 bytes of text, no space at either end */
  fill(big, 255, 'n');
  NQTEQI(code(big, NULL, NULL, NULL, NULL), NQOK);
  NQTEQI(code("A", NULL, NULL, NULL, big), NQOK);
  fill(big, 256, 'n');
  NQTEQI(code(big, NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A", NULL, NULL, NULL, big), NQEARG);
  NQTEQI(code(NULL, NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code(" Ada", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("Ada ", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code(" ", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\nB", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\tB", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\x7f", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\xff", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\xc0\xaf", NULL, NULL, NULL, NULL), NQEARG); /* overlong */
  NQTEQI(code("A\xed\xa0\x80", NULL, NULL, NULL, NULL), NQEARG); /* surrogate */
  /* C1 controls (U+0085 NEL, U+009B CSI) are refused like C0 ones, in
   * every text field; U+00A0 (0xc2 0xa0) is not one */
  NQTEQI(code("A\xc2\x85" "B", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A\xc2\x9b" "B", NULL, NULL, NULL, NULL), NQEARG);
  NQTEQI(code("A", NULL, NULL, NULL, "U\xc2\x9b"), NQEARG);
  NQTEQI(code("A", NULL, "a\xc2\x9b@b.c", NULL, NULL), NQEARG);
  NQTEQI(code("A", NULL, NULL, "https://a/\xc2\x80", NULL), NQEARG);
  NQTEQI(code("A\xc2\xa0" "B", NULL, NULL, NULL, NULL), NQOK);
  NQTEQI(code("A", NULL, NULL, NULL, ""), NQEARG);
  NQTEQI(code("A", NULL, NULL, NULL, " U"), NQEARG);
  NQTEQI(code("A", NULL, NULL, NULL, "U\r"), NQEARG);
  NQTEQI(code("A B", NULL, NULL, NULL, "U of T"), NQOK);
  /* a name of 255 bytes ending in a multibyte character */
  fill(big, 253, 'n');
  memcpy(big + 253, "\xc3\xa9", 3);
  NQTEQI(code(big, NULL, NULL, NULL, NULL), NQOK);
  /* e-mail: local@domain.tld, at most 254 bytes */
  NQTEQI(code("A", NULL, "a@b.c", NULL, NULL), NQOK);
  NQTEQI(code("A", NULL, "first.last+tag@sub.example.org", NULL, NULL),
         NQOK);
  NQTEQI(code("A", NULL, "\xc3\xa9@\xc3\xa9x.org", NULL, NULL), NQOK);
  fill(e, 254 - 6, 'x');
  memcpy(e, "a@", 2);
  memcpy(e + 248, ".org", 5);
  NQTEQI(strlen(e), 252);
  e[252] = 'g';
  e[253] = 'g';
  e[254] = 0;
  NQTEQI(code("A", NULL, e, NULL, NULL), NQOK); /* 254 bytes */
  e[254] = 'g';
  e[255] = 0;
  NQTEQI(code("A", NULL, e, NULL, NULL), NQEARG); /* 255 */
  {
    static const char *const bad[] = {
        "", "a", "ab.c", "a@b", "@b.c", "a@.c", "a@b.", "a@@b.c",
        "a@b@c.d", "a b@c.d", "a@b .c", "a@b.c ", " a@b.c", "a\n@b.c",
        "a@b.\x7f", "a@\xff.c", "a@b..", "a@.b."};
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      int rc = code("A", NULL, bad[i], NULL, NULL);
      NQTEQI(rc, NQEARG);
      if (rc != NQEARG) fprintf(stderr, "  e-mail %s\n", bad[i]);
    }
  }
  /* web page: https:// and a host, at most 1024 bytes */
  NQTEQI(code("A", NULL, NULL, "https://a", NULL), NQOK);
  NQTEQI(code("A", NULL, NULL, "https://example.org/~ada/?q=1#x", NULL),
         NQOK);
  memcpy(big, "https://", 8);
  fill(big + 8, 1024 - 8, 'u');
  NQTEQI(code("A", NULL, NULL, big, NULL), NQOK);
  fill(big + 8, 1025 - 8, 'u');
  NQTEQI(code("A", NULL, NULL, big, NULL), NQEARG);
  {
    static const char *const bad[] = {
        "", "https://", "https:///x", "http://example.org", "HTTPS://x",
        "ftp://x", "https://a b", "https://a\n", "https://a\x01",
        "example.org", " https://a", "https://\xff"};
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      int rc = code("A", NULL, NULL, bad[i], NULL);
      NQTEQI(rc, NQEARG);
      if (rc != NQEARG) fprintf(stderr, "  url %s\n", bad[i]);
    }
  }
  /* the time: 1970 to 9999 */
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, -1, NULL, 0, &m),
         NQEARG);
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, 253402300800LL, NULL, 0, &m),
         NQEARG);
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, 253402300799LL, NULL, 0, &m),
         NQEBUF);
  NQTEQI(nqcard(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "A", NULL, NULL,
                NULL, NULL, 0, NULL, 0, &m),
         NQEBUF);
}

/* the check digit of the 15 digits d (no dashes), as ISO 7064 MOD 11-2
 * defines it: sum of d_i * 2^(15 - i), check (12 - sum mod 11) mod 11 */
static char ref(const char *d) {
  unsigned long s = 0, w = 1;
  int i;
  for (i = 14; i >= 0; i--) {
    w *= 2;
    s += (unsigned long)(d[i] - '0') * w;
  }
  s = (12 - s % 11) % 11;
  return s == 10 ? 'X' : (char)('0' + s);
}

static void torcid(void) {
  nqcardf f;
  char id[20], dd[16], *b;
  size_t n = 0, i;
  int rc, x = 0, c;
  uint8_t r[8];
  /* published examples (ORCID's own documentation) */
  NQTCHK(nqcorcid("0000-0002-1825-0097", 19));
  NQTCHK(nqcorcid("0000-0001-5109-3700", 19));
  NQTCHK(nqcorcid("0000-0002-1694-233X", 19));
  NQTCHK(!nqcorcid("0000-0002-1694-2330", 19));
  NQTCHK(!nqcorcid("0000-0002-1694-233x", 19)); /* stored upper case */
  NQTCHK(!nqcorcid("0000-0002-1825-0098", 19));
  NQTCHK(!nqcorcid("0000-0002-1825-009", 18));
  NQTCHK(!nqcorcid("0000-0002-1825-00977", 20));
  NQTCHK(!nqcorcid("0000000218250097", 16));
  NQTCHK(!nqcorcid("0000-0002-1825_0097", 19));
  NQTCHK(!nqcorcid("000X-0002-1825-0097", 19));
  NQTCHK(!nqcorcid(NULL, 19));
  /* random bases: exactly one of the eleven check characters fits, the
   * one the reference computes */
  for (i = 0; i < 2000; i++) {
    int k, ok = 0;
    static const char ck[] = "0123456789X";
    NQTEQI(nqrand(r, sizeof r), NQOK);
    for (k = 0; k < 15; k++)
      dd[k] = (char)('0' + ((r[k % 8] >> (k / 8 * 4)) & 0xf) % 10);
    if (i == 0) memset(dd, '9', 15);
    snprintf(id, sizeof id, "%.4s-%.4s-%.4s-%.3s0", dd, dd + 4, dd + 8,
             dd + 12);
    for (c = 0; c < 11; c++) {
      id[18] = ck[c];
      if (nqcorcid(id, 19)) {
        ok++;
        NQTEQI(ck[c], ref(dd));
      }
    }
    NQTEQI(ok, 1);
    if (ref(dd) == 'X') x++;
  }
  NQTCHK(x > 0); /* some had an X */
  /* through nqcard: bare, the URL forms, a lower-case x; all made bare */
  {
    static const char *const in[] = {
        "0000-0002-1694-233X", "0000-0002-1694-233x",
        "https://orcid.org/0000-0002-1694-233X",
        "http://orcid.org/0000-0002-1694-233X",
        "https://www.orcid.org/0000-0002-1694-233x"};
    for (i = 0; i < sizeof in / sizeof in[0]; i++) {
      b = mk("A", in[i], NULL, NULL, NULL, &n, &rc);
      NQTEQI(rc, NQOK);
      if (b == NULL) continue;
      NQTCHK(strstr(b, "\"orcid\":\"0000-0002-1694-233X\"") != NULL);
      NQTCHK(strstr(b, "orcid.org") == NULL);
      NQTEQI(vr(b, n, &f), NQOK);
      NQTCHK(strcmp(f.orcid, "0000-0002-1694-233X") == 0);
      free(b);
    }
  }
  {
    static const char *const bad[] = {
        "0000-0002-1825-0098", "0000-0002-1694-2330", "0000-0002-1825",
        "0000-0002-1825-0097 ", " 0000-0002-1825-0097", "",
        "https://orcid.org/", "https://orcid.org/0000-0002-1825-0098",
        "https://example.org/0000-0002-1825-0097",
        "orcid.org/0000-0002-1825-0097", "0000-0002-1825-009X",
        "000a-0002-1825-0097", "0000-0002-1825-0097/"};
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      rc = code("A", bad[i], NULL, NULL, NULL);
      NQTEQI(rc, NQEARG);
      if (rc != NQEARG) fprintf(stderr, "  orcid %s\n", bad[i]);
    }
  }
}

/* ---- refusals ---- */

/* signed by the card's own key, but with a field nqcard refuses: the
 * verifier refuses it too (NQEDEC), whatever the signature says */
static void tsigned(void) {
  char big[300];
  static const char at[] = "2026-01-01T00:00:00Z";
  struct {
    const char *at, *name, *orc, *email, *url, *affil;
  } c[] = {
      {at, "A", "0000-0002-1825-0098", NULL, NULL, NULL},
      {at, "A", "https://orcid.org/0000-0002-1825-0097", NULL, NULL, NULL},
      {at, "A", "0000-0002-1694-233x", NULL, NULL, NULL},
      {at, "A", NULL, "not-an-address", NULL, NULL},
      {at, "A", NULL, NULL, "http://example.org", NULL},
      {at, "A", NULL, NULL, NULL, " U"},
      {at, " A", NULL, NULL, NULL, NULL},
      {at, "A\nB", NULL, NULL, NULL, NULL},
      {at, "A\xc2\x9b" "B", NULL, NULL, NULL, NULL},
      {at, "A\xc0\xaf", NULL, NULL, NULL, NULL},
      {at, "A", NULL, NULL, "https://a/\xc2\x85", NULL},
      {at, big, NULL, NULL, NULL, NULL},
      {"2026-01-01T00:00:00.5Z", "A", NULL, NULL, NULL, NULL},
      {"2026-01-01 00:00:00Z", "A", NULL, NULL, NULL, NULL},
      {"1969-12-31T23:59:59Z", "A", NULL, NULL, NULL, NULL},
      {"2026-02-30T00:00:00Z", "A", NULL, NULL, NULL, NULL}};
  size_t i, n = 0;
  nqcardf f;
  fill(big, 256, 'n');
  for (i = 0; i < sizeof c / sizeof c[0]; i++) {
    char *b = forge(pk, sk, NQCDFMT, c[i].at, c[i].name, c[i].orc,
                    c[i].email, c[i].url, c[i].affil, &n);
    NQTCHK(b != NULL);
    if (b == NULL) continue;
    NQTEQI(vr(b, n, &f), NQEDEC);
    NQTCHK(zero(&f, sizeof f));
    free(b);
  }
  /* and the same forger with good fields is a card */
  {
    char *b = forge(pk, sk, NQCDFMT, at, "A", "0000-0002-1825-0097",
                    "a@b.c", "https://a", "U", &n);
    if (b != NULL) {
      NQTEQI(vr(b, n, &f), NQOK);
      free(b);
    }
  }
}

static void ttamper(void) {
  nqcardf f;
  size_t n = 0, k = 0, i, bad = 0;
  int rc;
  char *b = mk("Ada Lovelace", "0000-0002-1825-0097", "ada@example.org",
               "https://example.org/ada", "AES", &n, &rc), *c;
  NQTEQI(rc, NQOK);
  if (b == NULL) return;
  /* every byte changed, one at a time (every 7th with NQFAST=1, the
   * valgrind job): never a card that verifies */
  c = (char *)malloc(n);
  NQTCHK(c != NULL);
  if (c != NULL) {
    size_t step = getenv("NQFAST") != NULL ? 7 : 1;
    for (i = 0; i < n; i += step) {
      memcpy(c, b, n);
      c[i] = (char)(c[i] ^ (i % 3 == 0 ? 0x01 : i % 3 == 1 ? 0x20 : 0x04));
      if (nqcardvrfy(c, n, NULL, 0, &f) == NQOK) {
        bad++;
        fprintf(stderr, "  byte %lu changed still verifies\n",
                (unsigned long)i);
      }
    }
    free(c);
  }
  NQTEQI(bad, 0);
  /* each field swapped for another value of the right shape */
  {
    static const char *const sw[][2] = {
        {"name", "Ada Byron"},
        {"orcid", "0000-0002-1694-233X"},
        {"email", "eve@example.org"},
        {"url", "https://example.org/eve"},
        {"affil", "AES2"},
        {"created", "2026-01-01T00:00:01Z"},
        {"alg", "ML-DSA-65"},
        {"format", "noqtis-keys-1"}};
    for (i = 0; i < sizeof sw / sizeof sw[0]; i++) {
      c = setf(b, sw[i][0], sw[i][1], &k);
      NQTCHK(c != NULL);
      if (c == NULL) continue;
      rc = vr(c, k, &f);
      NQTCHK(rc == NQEVRFY || rc == NQEDEC);
      if (strcmp(sw[i][0], "format") != 0 && strcmp(sw[i][0], "alg") != 0)
        NQTEQI(rc, NQEVRFY);
      free(c);
    }
  }
  /* a field removed (a card that claimed less) or one added */
  {
    static const char *const rm[] = {"orcid", "email", "url", "affil",
                                     "name", "signature", "key", "created",
                                     "format", "alg"};
    for (i = 0; i < sizeof rm / sizeof rm[0]; i++) {
      c = setf(b, rm[i], NULL, &k);
      NQTCHK(c != NULL);
      if (c == NULL) continue;
      rc = vr(c, k, &f);
      NQTEQI(rc, i < 4 ? NQEVRFY : NQEDEC);
      free(c);
    }
  }
  {
    char *d = (char *)malloc(n + 32);
    if (d != NULL) {
      memcpy(d, b, n - 1);
      memcpy(d + n - 1, ",\"zz\":\"x\"}", 11);
      NQTEQI(vr(d, n + 9, &f), NQEDEC);
      /* the card's members inside another object, or in an array */
      d[0] = '[';
      memcpy(d + 1, b, n);
      d[n + 1] = ']';
      NQTEQI(vr(d, n + 2, &f), NQEDEC);
      free(d);
    }
  }
  /* another key in the card, with the first key's signature */
  {
    char k2[1760];
    nqb64e(pk2, sizeof pk2, k2);
    c = setf(b, "key", k2, &k);
    if (c != NULL) {
      NQTEQI(vr(c, k, &f), NQEVRFY);
      NQTEQI(nqcardvrfy(c, k, pk2, sizeof pk2, &f), NQEVRFY);
      free(c);
    }
  }
  /* the same fields signed by another key: a card, but not pk's */
  {
    char *o = forge(pk2, sk2, NQCDFMT, "2026-01-01T00:00:00Z",
                    "Ada Lovelace", "0000-0002-1825-0097", "ada@example.org",
                    "https://example.org/ada", "AES", &k);
    if (o != NULL) {
      uint8_t h[32];
      NQTEQI(vr(o, k, &f), NQOK);
      nqhash(NQS256, pk2, sizeof pk2, h, 32);
      NQTEQM(f.fp, h, 32);
      NQTEQI(nqcardvrfy(o, k, pk, sizeof pk, &f), NQEVRFY);
      /* its signature in pk's card, and pk's in its */
      {
        char sg[3300];
        const char *s = strstr(o, "\"signature\":\"");
        char *e;
        size_t l, kk = 0;
        if (s != NULL) {
          s += 13;
          l = (size_t)(strchr(s, '"') - s);
          memcpy(sg, s, l);
          sg[l] = 0;
          e = setf(b, "signature", sg, &kk);
          if (e != NULL) {
            NQTEQI(vr(e, kk, &f), NQEVRFY);
            free(e);
          }
        }
      }
      free(o);
    }
  }
  free(b);
}

/* the card's context against the seal's and the key statements' */
static void tdomain(void) {
  static const char *const ctx[] = {NQCKFMT, NQCCTX, NQCCTX2, ""};
  static const char at[] = "2026-01-01T00:00:00Z";
  nqcardf f;
  size_t n = 0, i, k = 0;
  int rc;
  char *b = mk("Ada Lovelace", NULL, NULL, NULL, NULL, &n, &rc);
  if (b == NULL) return;
  /* a card's own signature verifies only under the card context */
  {
    nqcbuf body;
    uint8_t sg[2420];
    size_t sn = 0;
    const char *s = strstr(b, "\"signature\":\""), *e;
    char kb[1760];
    memset(&body, 0, sizeof body);
    nqb64e(pk, sizeof pk, kb);
    NQTEQI(nqcdbody(&body, "ML-DSA-44", at, kb, "Ada Lovelace", NULL, NULL,
                    NULL, NULL, NULL),
           NQOK);
    NQTCHK(s != NULL);
    if (s != NULL) {
      s += 13;
      e = strchr(s, '"');
      NQTEQI(nqb64d(s, (size_t)(e - s), sg, sizeof sg, &sn), NQOK);
      NQTEQI(nqvrfy(NQMLDSA44, pk, sizeof pk, (const uint8_t *)body.p,
                    body.n, (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg,
                    sn),
             NQOK);
      for (i = 0; i < sizeof ctx / sizeof ctx[0]; i++) {
        NQTEQI(nqvrfy(NQMLDSA44, pk, sizeof pk, (const uint8_t *)body.p,
                      body.n, (const uint8_t *)ctx[i], strlen(ctx[i]), 0,
                      sg, sn),
               NQEVRFY);
      }
    }
    nqcbfree(&body);
  }
  /* a card signed under any other context (a statement's, a seal's,
   * none) is refused, by the right key and over the right bytes */
  for (i = 0; i < sizeof ctx / sizeof ctx[0]; i++) {
    char *o = forge(pk, sk, ctx[i], at, "Ada Lovelace", NULL, NULL, NULL,
                    NULL, &k);
    if (o == NULL) continue;
    NQTEQI(vr(o, k, &f), NQEVRFY);
    free(o);
  }
  /* a key statement is not a card */
  {
    char *s;
    NQTEQI(nqkstmt(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NQMLDSA44, NULL,
                   0, NULL, 0, T0, NULL, NULL, 0, &k),
           NQEBUF);
    s = (char *)malloc(k);
    if (s != NULL) {
      NQTEQI(nqkstmt(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NQMLDSA44,
                     NULL, 0, NULL, 0, T0, NULL, s, k, &k),
             NQOK);
      NQTEQI(vr(s, k, &f), NQEDEC);
      free(s);
    }
  }
  free(b);
}

#ifdef NQTFS
static char root[300];

static char *slurp(const char *p, size_t *n) {
  char *b = NULL;
  if (nqreadf(p, (size_t)1 << 24, &b, n) != NQOK) return NULL;
  return b;
}

/* the other way round: a capsule's seal and a key statement whose
 * signatures were made under the card context fail their checks */
static void tdomain2(void) {
  char d[400], p[500], *m = NULL, *s = NULL, *o, sgb[3300];
  size_t mn = 0, sn = 0, k = 0;
  uint8_t sg[2420];
  nqrep *r = NULL;
  nqcopt co;
  nqcardf f;
  FILE *fp;
  snprintf(d, sizeof d, "%s/cap", root);
  NQTEQI(mkdir(d, 0700), 0);
  snprintf(p, sizeof p, "%s/a.txt", d);
  fp = fopen(p, "wb");
  NQTCHK(fp != NULL);
  if (fp == NULL) return;
  fputs("alpha\n", fp);
  fclose(fp);
  NQTEQI(nqseal(d, NQMLDSA44, sk, sizeof sk, pk, sizeof pk, NULL, NULL),
         NQOK);
  NQTEQI(nqchk(d, pk, sizeof pk, &r), NQOK);
  nqrepfree(r);
  snprintf(p, sizeof p, "%s/noqtis.json", d);
  m = slurp(p, &mn);
  snprintf(p, sizeof p, "%s/noqtis.sig", d);
  s = slurp(p, &sn);
  NQTCHK(m != NULL && s != NULL);
  if (m != NULL && s != NULL) {
    /* the seal is not a card */
    NQTEQI(vr(s, sn, &f), NQEDEC);
    NQTEQI(nqsign(NQMLDSA44, sk, sizeof sk, (const uint8_t *)m, mn,
                  (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg,
                  sizeof sg, &k),
           NQOK);
    nqb64e(sg, k, sgb);
    o = setf(s, "signature", sgb, &k);
    NQTCHK(o != NULL);
    if (o != NULL) {
      NQTEQI(nqcwrite(d, "noqtis.sig", o, k), NQOK);
      NQTEQI(nqchk(d, pk, sizeof pk, &r), NQEVRFY);
      {
        size_t i;
        int seen = 0;
        for (i = 0; i < nqrepn(r); i++) {
          const char *c;
          int ok;
          nqrepi(r, i, &c, &ok, NULL);
          if (strcmp(c, "signature") == 0) {
            seen = 1;
            NQTEQI(ok, 0);
          }
        }
        NQTEQI(seen, 1);
      }
      nqrepfree(r);
      free(o);
    }
    NQTEQI(nqcwrite(d, "noqtis.sig", s, sn), NQOK);
  }
  /* a revocation signed under the card context: its row fails */
  {
    nqcbuf body;
    char kb[1760], *st;
    const char *sl[1];
    size_t ln[1];
    memset(&body, 0, sizeof body);
    nqb64e(pk, sizeof pk, kb);
    NQTEQI(nqckbody(&body, "ML-DSA-44", "2026-01-01T00:00:00Z", kb, 0, NULL,
                    NULL, "", NULL, NULL),
           NQOK);
    NQTEQI(nqsign(NQMLDSA44, sk, sizeof sk, (const uint8_t *)body.p,
                  body.n, (const uint8_t *)NQCDFMT, strlen(NQCDFMT), 0, sg,
                  sizeof sg, &k),
           NQOK);
    nqb64e(sg, k, sgb);
    nqcbfree(&body);
    memset(&body, 0, sizeof body);
    NQTEQI(nqckbody(&body, "ML-DSA-44", "2026-01-01T00:00:00Z", kb, 0, NULL,
                    NULL, "", NULL, sgb),
           NQOK);
    st = (char *)malloc(body.n + 1);
    if (st != NULL) {
      memcpy(st, body.p, body.n);
      sl[0] = st;
      ln[0] = body.n;
      memset(&co, 0, sizeof co);
      co.trust = pk;
      co.trustlen = sizeof pk;
      co.stmt = sl;
      co.stmtlen = ln;
      co.nstmt = 1;
      NQTEQI(nqchkx(d, &co, &r), NQEVRFY);
      {
        size_t i;
        int seen = 0;
        for (i = 0; i < nqrepn(r); i++) {
          const char *c, *dt;
          int ok;
          nqrepi(r, i, &c, &ok, &dt);
          if (strcmp(c, "keys") == 0) {
            seen = 1;
            NQTEQI(ok, 0);
            NQTCHK(strstr(dt, "does not verify") != NULL);
          }
        }
        NQTEQI(seen, 1);
      }
      nqrepfree(r);
      /* and as a card it is refused too */
      NQTEQI(vr(st, body.n, &f), NQEDEC);
      free(st);
    }
    nqcbfree(&body);
  }
  if (m != NULL) nqfree(m, mn + 1);
  if (s != NULL) nqfree(s, sn + 1);
  snprintf(p, sizeof p, "%s/a.txt", d);
  remove(p);
  snprintf(p, sizeof p, "%s/noqtis.json", d);
  remove(p);
  snprintf(p, sizeof p, "%s/noqtis.sig", d);
  remove(p);
  rmdir(d);
}
#endif

/* ---- input that is not a card ---- */

static void tmalformed(void) {
  nqcardf f;
  size_t n = 0, i, k = 0;
  int rc;
  char *b = mk("Ada Lovelace", "0000-0002-1825-0097", NULL, NULL, NULL, &n,
               &rc), *c;
  if (b == NULL) return;
  NQTEQI(nqcardvrfy(NULL, 0, NULL, 0, &f), NQEARG);
  NQTEQI(nqcardvrfy(b, n, NULL, 0, NULL), NQEARG);
  NQTEQI(nqcardvrfy(b, n, NULL, 5, &f), NQEARG);
  /* every prefix: no crash, never a card */
  for (i = 0; i < n; i++) {
    rc = vr(b, i, &f);
    if (rc == NQOK) NQTCHK(rc != NQOK);
  }
  /* not canonical: a space, an escaped letter, keys out of order */
  c = (char *)malloc(n + 64);
  if (c != NULL) {
    c[0] = ' ';
    memcpy(c + 1, b, n);
    NQTEQI(vr(c, n + 1, &f), NQEDEC);
    memcpy(c, b, n);
    c[n] = '\n';
    NQTEQI(vr(c, n + 1, &f), NQEDEC);
    free(c);
  }
  c = setf(b, "name", "Ada \\u004covelace", &k);
  if (c != NULL) {
    NQTEQI(vr(c, k, &f), NQEDEC);
    free(c);
  }
  c = setf(b, "orcid", "0000-0002-1825-0097\\u0000", &k);
  if (c != NULL) {
    NQTEQI(vr(c, k, &f), NQEDEC);
    free(c);
  }
  {
    /* the name moved to the front */
    const char *nm = strstr(b, ",\"name\":\"Ada Lovelace\"");
    char *d = (char *)malloc(n + 1);
    if (nm != NULL && d != NULL) {
      size_t l = strlen(",\"name\":\"Ada Lovelace\""), a = (size_t)(nm - b);
      d[0] = '{';
      memcpy(d + 1, nm + 1, l - 1);
      d[l] = ',';
      memcpy(d + l + 1, b + 1, a - 1);
      memcpy(d + l + a, nm + l, n - a - l);
      NQTEQI(vr(d, n, &f), NQEDEC);
    }
    free(d);
  }
  /* members of the wrong type */
  {
    static const char *const ty[] = {"name", "orcid", "created", "key",
                                     "signature"};
    for (i = 0; i < sizeof ty / sizeof ty[0]; i++) {
      char pat[32], *at, *e, *d;
      snprintf(pat, sizeof pat, "\"%s\":\"", ty[i]);
      at = strstr(b, pat);
      if (at == NULL) continue;
      e = strchr(at + strlen(pat), '"');
      d = (char *)malloc(n + 8);
      if (d == NULL) continue;
      k = (size_t)(at - b) + strlen(pat) - 1;
      memcpy(d, b, k);
      memcpy(d + k, "null", 4);
      memcpy(d + k + 4, e + 1, n - (size_t)(e + 1 - b));
      k = k + 4 + n - (size_t)(e + 1 - b);
      NQTEQI(vr(d, k, &f), NQEDEC);
      free(d);
    }
  }
  free(b);
  /* not JSON, other JSON, deep, huge */
  {
    static const char *const t[] = {"", "{", "{}", "[]", "null", "\"x\"",
                                    "1", "{\"name\":\"A\"}", "\xff\xfe",
                                    "{\"format\":\"noqtis-idcard-1\"}"};
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
      NQTEQI(vr(t[i], strlen(t[i]), &f), NQEDEC);
  }
  {
    size_t big = NQCARDMAX + 1;
    char *h = (char *)malloc(big);
    if (h != NULL) {
      memset(h, '[', big / 2);
      memset(h + big / 2, ']', big - big / 2);
      NQTEQI(vr(h, big, &f), NQELIM);
      NQTCHK(vr(h, 200000, &f) != NQOK); /* deep, under the limit */
      /* one string near the limit, in a name */
      memcpy(h, "{\"name\":\"", 9);
      memset(h + 9, 'n', NQCARDMAX - 11);
      memcpy(h + NQCARDMAX - 2, "\"}", 2);
      NQTEQI(vr(h, NQCARDMAX, &f), NQEDEC);
      free(h);
    }
  }
  /* random bytes, and random bytes in a card's shape */
  for (i = 0; i < 2000; i++) {
    uint8_t r[64];
    NQTEQI(nqrand(r, sizeof r), NQOK);
    NQTCHK(vr((const char *)r, sizeof r, &f) != NQOK);
  }
}

int main(void) {
  uint8_t seed[32];
  size_t i;
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)i;
  NQTEQI(nqskgd(NQMLDSA44, seed, sizeof seed, pk, sizeof pk, sk, sizeof sk),
         NQOK);
  seed[0] = 0xff;
  NQTEQI(nqskgd(NQMLDSA44, seed, sizeof seed, pk2, sizeof pk2, sk2,
                sizeof sk2),
         NQOK);
  tround();
  talgs();
  tlimits();
  torcid();
  tsigned();
  ttamper();
  tdomain();
  tmalformed();
#ifdef NQTFS
  {
    const char *t = getenv("TMPDIR");
    uint8_t b[4];
    if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
    NQTEQI(nqrand(b, sizeof b), NQOK);
    snprintf(root, sizeof root, "%s/tcard%02x%02x%02x%02x", t, b[0], b[1],
             b[2], b[3]);
    NQTEQI(mkdir(root, 0700), 0);
    tdomain2();
    rmdir(root);
  }
#endif
  return nqtdone("tcard");
}
