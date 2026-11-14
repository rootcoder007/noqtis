/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Sources (nqdaddr, nqdvrfy, nqdfld) and the portal resolvers (nqdrslv,
 * nqdrsp, nqdwb): the request of each portal, the reading of replies
 * shaped as each portal documents them (tests/vectors/nqd/src), and
 * every refusal: replies that are not one, name no file or name an
 * address not to follow, cut and oversized replies. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

static char out[8192], why[600];
static size_t n;

/* nqdrslv of rs: its result, the address in out */
static int req(const char *rs) {
  why[0] = '\0';
  return nqdrslv(rs, strlen(rs), out, sizeof out, &n, why, sizeof why);
}

static int reqis(const char *rs, const char *want) {
  return req(rs) == NQOK && strcmp(out, want) == 0 && n == strlen(want);
}

/* nqdrsp of rs on the fixture file f */
static int rsp(const char *rs, const char *f, char tm[21]) {
  char p[200], *b = NULL;
  size_t bl = 0;
  int rc;
  qdwhy(p, sizeof p, "vectors/nqd/src/%s", f);
  if (qdread(p, (size_t)1 << 20, &b, &bl) != NQOK) {
    fprintf(stderr, "tdsrc: no fixture %s\n", p);
    return -99;
  }
  why[0] = '\0';
  rc = nqdrsp(rs, strlen(rs), b, bl, out, sizeof out, &n, tm, why,
              sizeof why);
  qdfree(b);
  return rc;
}

static int rspis(const char *rs, const char *f, const char *want) {
  int rc = rsp(rs, f, NULL);
  if (rc != NQOK || strcmp(out, want) != 0)
    fprintf(stderr, "tdsrc: %s: %d %s (%s)\n", f, rc, out, why);
  return rc == NQOK && strcmp(out, want) == 0;
}

#define CK "{\"base\":\"https://data.example.org/\",\"id\":\"library " \
           "statistics\",\"kind\":\"ckan\"}"
#define SOC "{\"base\":\"https://data.example.org\",\"id\":\"abcd-1234\"," \
            "\"kind\":\"socrata\"}"
#define ARL "{\"base\":\"https://services.example.com/AbC123/arcgis/rest/" \
            "services/Assault_Open_Data/FeatureServer\",\"kind\":\"arcgis\"," \
            "\"layer\":0}"
#define ARI "{\"base\":\"https://www.arcgis.com\",\"id\":\"0123456789abcdef" \
            "0123456789abcdef\",\"kind\":\"arcgis\"}"
#define WB "{\"base\":\"https://example.org/a.csv\",\"id\":\"2024\"," \
           "\"kind\":\"wayback\"}"

static void requests(void) {
  NQTCHK(reqis(CK, "https://data.example.org/api/3/action/package_show?"
                   "id=library%20statistics"));
  NQTCHK(reqis("{\"base\":\"https://data.example.org\",\"kind\":\"ckan\","
               "\"resource\":\"0a6e/7f3c\"}",
               "https://data.example.org/api/3/action/resource_show?"
               "id=0a6e%2F7f3c"));
  NQTCHK(reqis(SOC, "https://data.example.org/api/views/abcd-1234.json"));
  NQTCHK(reqis(ARL, "https://services.example.com/AbC123/arcgis/rest/"
                    "services/Assault_Open_Data/FeatureServer/0?f=json"));
  NQTCHK(reqis(ARI, "https://www.arcgis.com/sharing/rest/content/items/"
                    "0123456789abcdef0123456789abcdef?f=json"));
  NQTCHK(reqis(WB, "https://archive.org/wayback/available?url=https%3A%2F%2F"
                   "example.org%2Fa.csv&timestamp=2024"));
  NQTCHK(reqis("{\"base\":\"http://example.org/a?b=c&d\",\"kind\":"
               "\"wayback\"}",
               "https://archive.org/wayback/available?url=http%3A%2F%2F"
               "example.org%2Fa%3Fb%3Dc%26d"));
  /* sizing */
  NQTEQI(nqdrslv(SOC, strlen(SOC), NULL, 0, &n, why, sizeof why), NQEBUF);
  NQTEQI(n, strlen("https://data.example.org/api/views/abcd-1234.json"));
  /* refusals */
  {
    static const char *const bad[] = {
        "{\"base\":\"https://x.org/a.csv\",\"kind\":\"direct\"}",
        "{\"kind\":\"ckan\",\"id\":\"x\"}",
        "{\"base\":\"https://x.org\",\"kind\":\"ckan\"}",
        "{\"base\":\"ftp://x.org\",\"id\":\"x\",\"kind\":\"ckan\"}",
        "{\"base\":\"https://x.org?q=1\",\"id\":\"x\",\"kind\":\"ckan\"}",
        "{\"base\":\"https://\",\"id\":\"x\",\"kind\":\"ckan\"}",
        "{\"base\":\"https://x.org/a b\",\"id\":\"x\",\"kind\":\"ckan\"}",
        "{\"base\":\"https://x.org\",\"id\":\"ABCD-1234\",\"kind\":"
        "\"socrata\"}",
        "{\"base\":\"https://x.org\",\"id\":\"abcd1234\",\"kind\":"
        "\"socrata\"}",
        "{\"base\":\"https://x.org\",\"format\":\"xlsx\",\"id\":"
        "\"abcd-1234\",\"kind\":\"socrata\"}",
        "{\"base\":\"https://x.org\",\"id\":\"0123\",\"kind\":\"arcgis\"}",
        "{\"base\":\"https://example.org/a.csv\",\"id\":\"2024x\","
        "\"kind\":\"wayback\"}",
        "{\"base\":\"https://example.org/a.csv\",\"id\":"
        "\"202401020304050\",\"kind\":\"wayback\"}",
        "{\"kind\":\"wayback\"}",
    };
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      int rc = req(bad[i]);
      NQTCHK(rc == NQEARG);
      NQTCHK(why[0] != '\0');
      if (rc != NQEARG)
        fprintf(stderr, "tdsrc: accepted %s\n", bad[i]);
    }
  }
  /* not a resolver at all */
  NQTEQI(req("{\"kind\":\"ftp\"}"), NQEDEC);
  NQTEQI(req("{\"base\":\"https://x.org\",\"kind\":\"ckan\",\"x\":1}"),
         NQEDEC);
  NQTEQI(req("[]"), NQEDEC);
  NQTEQI(req("{\"kind\":"), NQEDEC);
  NQTEQI(req("{\"base\":\"https://x.org\",\"kind\":\"arcgis\","
             "\"layer\":-1}"), NQEDEC);
  {
    /* an address over 4096 bytes */
    char *big = (char *)malloc(5100);
    NQTCHK(big != NULL);
    if (big != NULL) {
      memset(big, 'a', 5100);
      memcpy(big, "{\"base\":\"https://x.org/", 23);
      strcpy(big + 4980, "\",\"id\":\"x\",\"kind\":\"ckan\"}");
      NQTEQI(nqdrslv(big, strlen(big), out, sizeof out, &n, why,
                     sizeof why), NQEARG);
      free(big);
    }
  }
}

static void replies(void) {
  char tm[21];
  /* CKAN: the first CSV, a resource by id, by name, resource_show */
  NQTCHK(rspis(CK, "ckan-pkg.json", "https://files.example.org/lib/2023.csv"));
  NQTCHK(rspis("{\"base\":\"https://data.example.org\",\"format\":\"json\","
               "\"id\":\"x\",\"kind\":\"ckan\"}", "ckan-pkg.json",
               "https://data.example.org/dataset/x/resource/1/download/"
               "dict.json"));
  NQTCHK(rspis("{\"base\":\"https://data.example.org\",\"id\":\"x\","
               "\"kind\":\"ckan\",\"resource\":\"0a6e7f3c-1111-4c2a-9f00-"
               "aa0000000003\"}", "ckan-pkg.json",
               "https://files.example.org/lib/2024.csv"));
  NQTCHK(rspis("{\"base\":\"https://data.example.org\",\"id\":\"x\","
               "\"kind\":\"ckan\",\"resource\":\"2024 statistics\"}",
               "ckan-pkg.json", "https://files.example.org/lib/2024.csv"));
  NQTCHK(rspis("{\"base\":\"https://data.example.org\",\"kind\":\"ckan\","
               "\"resource\":\"0a6e7f3c-1111-4c2a-9f00-aa0000000003\"}",
               "ckan-res.json", "https://files.example.org/lib/2024.csv"));
  NQTEQI(rsp("{\"base\":\"https://data.example.org\",\"kind\":\"ckan\","
             "\"resource\":\"other\"}", "ckan-res.json", NULL), NQEDEC);
  NQTEQI(rsp("{\"base\":\"https://data.example.org\",\"id\":\"x\","
             "\"kind\":\"ckan\",\"resource\":\"2025 statistics\"}",
             "ckan-pkg.json", NULL), NQEDEC);
  NQTEQI(rsp("{\"base\":\"https://data.example.org\",\"format\":\"xlsx\","
             "\"id\":\"x\",\"kind\":\"ckan\"}", "ckan-pkg.json", NULL),
         NQEDEC);
  NQTEQI(rsp(CK, "ckan-fail.json", NULL), NQEDEC);
  NQTCHK(strstr(why, "success") != NULL);
  /* an https portal naming an http file: refused; an http one may */
  NQTEQI(rsp(CK, "ckan-http.json", NULL), NQEDEC);
  NQTCHK(strstr(why, "http://") != NULL);
  NQTCHK(rspis("{\"base\":\"http://data.example.org\",\"id\":\"p\","
               "\"kind\":\"ckan\"}", "ckan-http.json",
               "http://files.example.org/lib/2024.csv"));
  /* Socrata */
  NQTCHK(rspis(SOC, "soc.json", "https://data.example.org/api/views/"
                                "abcd-1234/rows.csv?accessType=DOWNLOAD"));
  NQTCHK(rspis("{\"base\":\"https://data.example.org\",\"format\":\"JSON\","
               "\"id\":\"abcd-1234\",\"kind\":\"socrata\"}", "soc.json",
               "https://data.example.org/api/views/abcd-1234/rows.json?"
               "accessType=DOWNLOAD"));
  NQTEQI(rsp("{\"base\":\"https://data.example.org\",\"id\":\"wxyz-9876\","
             "\"kind\":\"socrata\"}", "soc.json", NULL), NQEDEC);
  NQTEQI(rsp(SOC, "arc-err.json", NULL), NQEDEC);
  /* ArcGIS: a layer, an error, a service item, a file item */
  NQTCHK(rspis(ARL, "arc-layer.json",
               "https://services.example.com/AbC123/arcgis/rest/services/"
               "Assault_Open_Data/FeatureServer/0/query?where=1%3D1&"
               "outFields=*&f=geojson"));
  NQTEQI(rsp(ARL, "arc-err.json", NULL), NQEDEC);
  NQTEQI(rsp(ARL, "soc.json", NULL), NQOK); /* it has a name */
  NQTEQI(rsp(ARL, "ckan-res.json", NULL), NQEDEC);
  NQTCHK(rspis("{\"base\":\"https://www.arcgis.com\",\"format\":\"json\","
               "\"id\":\"0123456789abcdef0123456789abcdef\",\"kind\":"
               "\"arcgis\",\"layer\":2}", "arc-item-fs.json",
               "https://services.example.com/AbC123/arcgis/rest/services/"
               "Assault_Open_Data/FeatureServer/2/query?where=1%3D1&"
               "outFields=*&f=json"));
  NQTCHK(rspis("{\"base\":\"https://www.arcgis.com\",\"id\":\"fedcba9876"
               "543210fedcba9876543210\",\"kind\":\"arcgis\"}",
               "arc-item-csv.json",
               "https://www.arcgis.com/sharing/rest/content/items/"
               "fedcba9876543210fedcba9876543210/data"));
  NQTEQI(rsp(ARI, "arc-item-csv.json", NULL), NQEDEC); /* another item */
  /* the Wayback Machine: the raw copy of the address asked for */
  memset(tm, 'x', sizeof tm);
  NQTEQI(rsp(WB, "wb.json", tm), NQOK);
  NQTCHK(strcmp(out, "https://web.archive.org/web/20240102030405id_/"
                     "https://example.org/a.csv") == 0);
  NQTCHK(strcmp(tm, "2024-01-02T03:04:05Z") == 0);
  NQTEQI(rsp(WB, "wb-none.json", tm), NQEDEC);
  NQTCHK(tm[0] == '\0');
  NQTEQI(rsp(WB, "wb-404.json", tm), NQEDEC);
  NQTEQI(rsp(WB, "ckan-pkg.json", tm), NQEDEC);
  /* other kinds leave tm empty */
  memset(tm, 'x', sizeof tm);
  NQTEQI(rsp(SOC, "soc.json", tm), NQOK);
  NQTCHK(tm[0] == '\0');
  /* a direct resolver has no reply to read */
  NQTEQI(rsp("{\"base\":\"https://x.org/a\",\"kind\":\"direct\"}",
             "soc.json", NULL), NQEARG);
  /* replies that are not JSON objects, cut, oversized */
  {
    static const char *const cut[] = {"", "[]", "\"x\"", "{\"success\":tr",
                                      "{\"success\":true,\"result\":{",
                                      "{\"id\":\"abcd-1234\"} x", "null"};
    size_t i;
    for (i = 0; i < sizeof cut / sizeof cut[0]; i++) {
      NQTEQI(nqdrsp(SOC, strlen(SOC), cut[i], strlen(cut[i]), out,
                    sizeof out, &n, NULL, why, sizeof why), NQEDEC);
    }
    NQTEQI(nqdrsp(SOC, strlen(SOC), "{}", ((size_t)16 << 20) + 1, out,
                  sizeof out, &n, NULL, why, sizeof why), NQELIM);
  }
  /* a reply naming a long, a spaced or a non-http address */
  {
    static const char *const bad[] = {
        "{\"success\":true,\"result\":{\"id\":\"r\",\"url\":\"ftp://x.org/"
        "a\"}}",
        "{\"success\":true,\"result\":{\"id\":\"r\",\"url\":\"https://x."
        "org/a b\"}}",
        "{\"success\":true,\"result\":{\"id\":\"r\",\"url\":\"https://x."
        "org/a#b\"}}",
        "{\"success\":true,\"result\":{\"id\":\"r\",\"url\":\"javascript:"
        "x\"}}",
        "{\"success\":true,\"result\":{\"id\":\"r\"}}",
        "{\"success\":true,\"result\":{\"resources\":{}}}",
        "{\"success\":\"true\",\"result\":{\"id\":\"r\",\"url\":\"https:"
        "//x.org/a\"}}",
    };
    const char *rs = "{\"base\":\"https://x.org\",\"kind\":\"ckan\","
                     "\"resource\":\"r\"}";
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
      NQTEQI(nqdrsp(rs, strlen(rs), bad[i], strlen(bad[i]), out, sizeof out,
                    &n, NULL, why, sizeof why), NQEDEC);
    }
  }
}

/* a reply may not name this machine or a local network */
static void hosts(void) {
  static const char *const bad[] = {
      "localhost", "LocalHost.", "a.localhost", "127.0.0.1", "127.1",
      "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
      "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
      "255.255.255.255", "2130706433", "0x7f000001", "0177.0.0.1",
      "[::1]", "[fe80::1]", "[::ffff:127.0.0.1]", "198.18.0.1",
      "192.0.0.8", "1.2.3", "1.2.3.4.5"};
  static const char *const good[] = {"8.8.8.8", "172.32.0.1",
                                     "files.example.org", "100.128.0.1",
                                     "deadbeef.example.com"};
  const char *rs = "{\"base\":\"https://x.org\",\"kind\":\"ckan\","
                   "\"resource\":\"r\"}";
  char rp[300];
  size_t i;
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    qdwhy(rp, sizeof rp, "{\"success\":true,\"result\":{\"id\":\"r\","
          "\"url\":\"https://%s:8443/a.csv\"}}", bad[i]);
    NQTEQI(nqdrsp(rs, strlen(rs), rp, strlen(rp), out, sizeof out, &n, NULL,
                  why, sizeof why), NQEDEC);
  }
  NQTCHK(strstr(why, "local network") != NULL);
  for (i = 0; i < sizeof good / sizeof good[0]; i++) {
    qdwhy(rp, sizeof rp, "{\"success\":true,\"result\":{\"id\":\"r\","
          "\"url\":\"https://%s/a.csv\"}}", good[i]);
    NQTEQI(nqdrsp(rs, strlen(rs), rp, strlen(rp), out, sizeof out, &n, NULL,
                  why, sizeof why), NQOK);
  }
}

static void wb(void) {
  NQTEQI(nqdwb("http://web.archive.org/web/20240102030405/https://"
               "example.org/a.csv", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "https://web.archive.org/web/20240102030405id_/"
                     "https://example.org/a.csv") == 0);
  NQTEQI(nqdwb("https://web.archive.org/web/2024im_/https://example.org/"
               "a.csv", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "https://web.archive.org/web/2024id_/https://"
                     "example.org/a.csv") == 0);
  NQTEQI(nqdwb("https://mirror.example.net/a.csv", out, sizeof out, &n),
         NQOK);
  NQTCHK(strcmp(out, "https://mirror.example.net/a.csv") == 0);
  NQTEQI(nqdwb("https://web.archive.org/web/x/a", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "https://web.archive.org/web/x/a") == 0);
  NQTEQI(nqdwb("https://web.archive.org/web/2024id_", out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqdwb("ftp://web.archive.org/web/2024/x", out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqdwb(NULL, out, sizeof out, &n), NQEARG);
  NQTEQI(nqdwb("https://x.org/a", out, 4, &n), NQEBUF);
  NQTEQI(n, 15);
}

/* the addresses of a source, in order, joined by spaces */
static void addrs(const nqdrec *r, const char *path, char *s, size_t cap) {
  size_t i;
  int k;
  s[0] = '\0';
  for (i = 0; nqdaddr(r, path, i, &k, out, sizeof out, &n) == NQOK; i++) {
    char t[20];
    qdwhy(t, sizeof t, "%s%d:", i ? " " : "", k);
    strncat(s, t, cap - strlen(s) - 1);
    strncat(s, out, cap - strlen(s) - 1);
  }
}

static void sources(void) {
  nqdrec *r = NULL;
  char s[2000];
  uint8_t h[32];
  char hx[65], e[1000];
  const uint8_t *data = (const uint8_t *)"a,b\n1,2\n";
  int k;
  NQTEQI(nqhash(NQS256, data, 8, h, 32), NQOK);
  qdhex(h, 32, hx);
  NQTEQI(nqdnew(&r), NQOK);
  qdwhy(e, sizeof e,
        "{\"archived\":{\"time\":\"2024-01-02T03:04:05Z\",\"url\":\"http://"
        "web.archive.org/web/20240102030405/https://example.org/a.csv\"},"
        "\"mirrors\":[\"https://m1.example.net/a.csv\",\"https://m2.example."
        "net/a.csv\"],\"path\":\"a.csv\",\"resolver\":{\"base\":\"https://"
        "data.example.org\",\"id\":\"abcd-1234\",\"kind\":\"socrata\"},"
        "\"sha256\":\"%s\",\"size\":8,\"url\":\"https://example.org/a.csv\"}",
        hx);
  NQTEQI(nqdput(r, "sources", e, strlen(e), why, sizeof why), NQOK);
  addrs(r, "a.csv", s, sizeof s);
  NQTCHK(strcmp(s, "1:https://example.org/a.csv 2:https://data.example.org/"
                   "api/views/abcd-1234.json 3:https://m1.example.net/a.csv "
                   "3:https://m2.example.net/a.csv 4:https://web.archive.org"
                   "/web/20240102030405id_/https://example.org/a.csv") == 0);
  if (strcmp(s, "") == 0 || strstr(s, "4:") == NULL)
    fprintf(stderr, "tdsrc: %s\n", s);
  /* a source with only a direct resolver; with nothing; synthetic */
  qdwhy(e, sizeof e, "{\"path\":\"b.csv\",\"resolver\":{\"base\":\"https://"
        "x.org/b.csv\",\"kind\":\"direct\"},\"sha256\":\"%s\",\"size\":8}",
        hx);
  NQTEQI(nqdput(r, "sources", e, strlen(e), why, sizeof why), NQOK);
  addrs(r, "b.csv", s, sizeof s);
  NQTCHK(strcmp(s, "1:https://x.org/b.csv") == 0);
  qdwhy(e, sizeof e, "{\"path\":\"c.csv\",\"sha256\":\"%s\",\"size\":8}", hx);
  NQTEQI(nqdput(r, "sources", e, strlen(e), why, sizeof why), NQOK);
  NQTEQI(nqdaddr(r, "c.csv", 0, &k, out, sizeof out, &n), NQEIO);
  NQTEQI(nqdset(r, "sources", "c.csv", "synthetic", "true", 4, why,
                sizeof why), NQOK);
  NQTEQI(nqdset(r, "sources", "c.csv", "url", "\"https://x.org/c\"", 17,
                why, sizeof why), NQOK);
  NQTEQI(nqdaddr(r, "c.csv", 0, &k, out, sizeof out, &n), NQEARG);
  NQTEQI(nqdaddr(r, "none.csv", 0, &k, out, sizeof out, &n), NQEIO);
  NQTEQI(nqdaddr(r, "a.csv", 0, &k, out, 3, &n), NQEBUF);
  NQTEQI(n, strlen("https://example.org/a.csv"));
  /* the bytes: the same, one changed, one more, none */
  NQTEQI(nqdvrfy(r, "a.csv", data, 8), NQOK);
  NQTEQI(nqdvrfy(r, "a.csv", (const uint8_t *)"a,b\n1,3\n", 8), NQEVRFY);
  NQTEQI(nqdvrfy(r, "a.csv", (const uint8_t *)"a,b\n1,2\n\n", 9), NQEVRFY);
  NQTEQI(nqdvrfy(r, "a.csv", NULL, 0), NQEVRFY);
  NQTEQI(nqdvrfy(r, "none.csv", data, 8), NQEIO);
  NQTEQI(nqdvrfy(NULL, "a.csv", data, 8), NQEARG);
  /* fields */
  NQTEQI(nqdfld(r, "sources", 0, "url", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "https://example.org/a.csv") == 0);
  NQTEQI(nqdfld(r, "sources", 0, "size", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "8") == 0);
  NQTEQI(nqdfld(r, "sources", 0, "mirrors", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "[\"https://m1.example.net/a.csv\",\"https://m2."
                     "example.net/a.csv\"]") == 0);
  NQTEQI(nqdfld(r, "sources", 2, "synthetic", out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "true") == 0);
  NQTEQI(nqdfld(r, "sources", 1, "url", out, sizeof out, &n), NQEIO);
  NQTEQI(nqdfld(r, "sources", 3, "path", out, sizeof out, &n), NQEIO);
  NQTEQI(nqdfld(r, "cite", 0, "title", out, sizeof out, &n), NQEIO);
  NQTEQI(nqdfld(r, "sources", 0, "path", out, 2, &n), NQEBUF);
  NQTEQI(n, 5);
  nqdrfree(r);
}

int main(void) {
  requests();
  replies();
  hosts();
  wb();
  sources();
  return nqtdone("tdsrc");
}
