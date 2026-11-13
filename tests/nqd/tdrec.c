/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The data record: canonical numbers (RFC 8785 appendix B), strings and
 * key order, the strict reader's refusals, the record API, and nqdchk on
 * a folder. Run from tests/ (the fixtures are in vectors/nqd). */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

static double bits(uint64_t u) {
  double d;
  memcpy(&d, &u, 8);
  return d;
}

static void nums(void) {
  static const struct {
    uint64_t u;
    const char *s;
  } v[] = {{0x0000000000000000u, "0"},
           {0x8000000000000000u, "0"},
           {0x0000000000000001u, "5e-324"},
           {0x8000000000000001u, "-5e-324"},
           {0x7fefffffffffffffu, "1.7976931348623157e+308"},
           {0xffefffffffffffffu, "-1.7976931348623157e+308"},
           {0x4340000000000000u, "9007199254740992"},
           {0xc340000000000000u, "-9007199254740992"},
           {0x4430000000000000u, "295147905179352830000"},
           {0x44b52d02c7e14af5u, "9.999999999999997e+22"},
           {0x44b52d02c7e14af6u, "1e+23"},
           {0x44b52d02c7e14af7u, "1.0000000000000001e+23"},
           {0x444b1ae4d6e2ef4eu, "999999999999999700000"},
           {0x444b1ae4d6e2ef4fu, "999999999999999900000"},
           {0x444b1ae4d6e2ef50u, "1e+21"},
           {0x3eb0c6f7a0b5ed8cu, "9.999999999999997e-7"},
           {0x3eb0c6f7a0b5ed8du, "0.000001"},
           {0x41b3de4355555553u, "333333333.3333332"},
           {0x41b3de4355555554u, "333333333.33333325"},
           {0x41b3de4355555555u, "333333333.3333333"},
           {0x41b3de4355555556u, "333333333.3333334"},
           {0x41b3de4355555557u, "333333333.33333343"},
           {0xbecbf647612f3696u, "-0.0000033333333333333333"},
           {0x43143ff3c1cb0959u, "1424953923781206.2"}};
  size_t i;
  char b[40];
  double d;
  for (i = 0; i < sizeof v / sizeof v[0]; i++) {
    NQTEQI(qdnumfmt(bits(v[i].u), b), NQOK);
    if (strcmp(b, v[i].s) != 0)
      fprintf(stderr, "number %lu: %s, expected %s\n", (unsigned long)i, b,
              v[i].s);
    NQTCHK(strcmp(b, v[i].s) == 0);
    /* and back */
    NQTEQI(qdnumrd(b, strlen(b), 1, &d), NQOK);
    NQTCHK(d == bits(v[i].u) || (d == 0 && bits(v[i].u) == 0));
  }
  NQTEQI(qdnumfmt(bits(0x7ff0000000000000u), b), NQEARG);
  /* JSON grammar */
  NQTEQI(qdnumrd("01", 2, 1, &d), NQEDEC);
  NQTEQI(qdnumrd("1.", 2, 1, &d), NQEDEC);
  NQTEQI(qdnumrd(".5", 2, 1, &d), NQEDEC);
  NQTEQI(qdnumrd("+1", 2, 1, &d), NQEDEC);
  NQTEQI(qdnumrd("1e", 2, 1, &d), NQEDEC);
  NQTEQI(qdnumrd("1e999", 5, 1, &d), NQEDEC);
  NQTEQI(qdnumrd("-0", 2, 1, &d), NQOK);
  NQTCHK(d == 0);
  NQTEQI(qdnumrd(".5", 2, 0, &d), NQOK);
  NQTCHK(d == 0.5);
  NQTEQI(qdnumrd("+5.", 3, 0, &d), NQOK);
  NQTCHK(d == 5);
}

static int canon(const char *in, const char *want) {
  djs *v = NULL;
  dbuf b;
  char why[200];
  int ok;
  memset(&b, 0, sizeof b);
  if (qdjparse(in, strlen(in), &v, why, sizeof why) != NQOK) {
    fprintf(stderr, "parse %s: %s\n", in, why);
    return 0;
  }
  qdjwrite(v, &b);
  ok = b.err == 0 && strcmp(b.b, want) == 0;
  if (!ok)
    fprintf(stderr, "canon %s: %s, expected %s\n", in, b.b, want);
  qdbfree(&b);
  qdjfree(v);
  return ok;
}

static void json(void) {
  static const char *const bad[] = {
      "", "{", "{\"a\":1,}", "[1,]", "{\"a\":1,\"a\":2}", "\"\\u0000\"",
      "\"\\ud800\"", "\"\\udc00x\"", "\"a\x01\"", "\"\xc0\x80\"",
      "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\"", "nul", "1 2", "{\"a\" 1}",
      "[1e400]", "\"\\x\"", "{1:2}", "[01]"};
  char deep[80];
  size_t i;
  djs *v;
  char why[200];
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    int rc = qdjparse(bad[i], strlen(bad[i]), &v, why, sizeof why);
    if (rc == NQOK)
      fprintf(stderr, "accepted: %s\n", bad[i]);
    NQTCHK(rc != NQOK);
  }
  memset(deep, '[', 33);
  memset(deep + 33, ']', 33);
  NQTEQI(qdjparse(deep, 66, &v, why, sizeof why), NQELIM);
  memset(deep, '[', 32);
  memset(deep + 32, ']', 32);
  NQTEQI(qdjparse(deep, 64, &v, why, sizeof why), NQOK);
  qdjfree(v);
  /* key order (UTF-16), escapes, numbers */
  NQTCHK(canon("{\"b\":1,\"a\":[true,false,null],\"c\":\"x\"}",
               "{\"a\":[true,false,null],\"b\":1,\"c\":\"x\"}"));
  NQTCHK(canon("{\"\xef\xbd\xa1\":1,\"\xf0\x9f\x98\x80\":2}",
               "{\"\xf0\x9f\x98\x80\":2,\"\xef\xbd\xa1\":1}"));
  NQTCHK(canon("\"\\u00e9\\n\\/\\u001f\\\"\"", "\"\xc3\xa9\\n/\\u001f\\\"\""));
  NQTCHK(canon("[1.0,-0,1E2,0.1e-6,100e19]", "[1,0,100,1e-7,1e+21]"));
  NQTCHK(qdkcmp("a", 1, "b", 1) < 0 && qdkcmp("ab", 2, "a", 1) > 0);
}

static const char *const rbad[] = {
    "[]",
    "{}",
    "{\"format\":\"noqtis-data-2\"}",
    "{\"format\":\"noqtis-data-1\",\"extra\":1}",
    "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"a\"}]}",
    "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"../a\","
    "\"sha256\":\"0000000000000000000000000000000000000000000000000000000000"
    "000000\",\"size\":1}]}",
    "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"a\","
    "\"sha256\":\"0000000000000000000000000000000000000000000000000000000000"
    "00000A\",\"size\":1}]}",
    "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"a\","
    "\"sha256\":\"0000000000000000000000000000000000000000000000000000000000"
    "000000\",\"size\":-1}]}",
    "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"a\","
    "\"sha256\":\"0000000000000000000000000000000000000000000000000000000000"
    "000000\",\"size\":1,\"retrieved\":\"2026-02-30T00:00:00Z\"}]}",
    "{\"format\":\"noqtis-data-1\",\"schemas\":[{\"path\":\"a\","
    "\"kind\":\"csv\",\"columns\":[{\"name\":\"x\",\"type\":\"int\"},"
    "{\"name\":\"x\",\"type\":\"int\"}]}]}",
    "{\"format\":\"noqtis-data-1\",\"schemas\":[{\"path\":\"a\","
    "\"kind\":\"csv\",\"columns\":[{\"name\":\"x\",\"type\":\"float\"}]}]}",
    "{\"format\":\"noqtis-data-1\",\"schemas\":[{\"path\":\"a\","
    "\"kind\":\"csv\",\"rules\":[{\"kind\":\"range\",\"col\":\"x\"}]}]}",
    "{\"format\":\"noqtis-data-1\",\"schemas\":[{\"path\":\"a\","
    "\"kind\":\"csv\",\"delim\":\"\\\"\"}]}",
    "{\"format\":\"noqtis-data-1\",\"stats\":[{\"path\":\"a\",\"rows\":1,"
    "\"columns\":[{\"name\":\"x\",\"n\":1,\"edges\":[1,1],"
    "\"counts\":[1,0,0]}]}]}",
    "{\"format\":\"noqtis-data-1\",\"checks\":[{\"name\":\"a\","
    "\"status\":\"ok\"}]}",
    "{\"format\":\"noqtis-data-1\",\"commits\":[{\"kind\":\"other\","
    "\"created\":\"2026-01-01T00:00:00Z\",\"alg\":\"sha256\","
    "\"digest\":\"0000000000000000000000000000000000000000000000000000000000"
    "000000\"}]}",
    "{\"format\":\"noqtis-data-1\",\"cite\":{\"authors\":[\"A\"]}}",
    "{\"format\":\"noqtis-data-1\",\"schemas\":[]}"};

#define P(m, s) nqdput(r, m, s, strlen(s), why, sizeof why)
#define S(m, k, f, s) nqdset(r, m, k, f, s, strlen(s), why, sizeof why)

static void rec(void) {
  nqdrec *r = NULL;
  char why[600], out[4096];
  size_t i, n;
  static const char *in =
      "{\"sources\":[{\"size\":3,\"path\":\"b.csv\",\"sha256\":"
      "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},"
      "{\"path\":\"a.csv\",\"size\":1,\"sha256\":"
      "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
      "\"synthetic\":true}],\"format\":\"noqtis-data-1\"}";
  static const char *want =
      "{\"format\":\"noqtis-data-1\",\"sources\":[{\"path\":\"a.csv\","
      "\"sha256\":"
      "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
      "\"size\":1,\"synthetic\":true},{\"path\":\"b.csv\",\"sha256\":"
      "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"size\":3}]}";
  for (i = 0; i < sizeof rbad / sizeof rbad[0]; i++) {
    int rc = nqdparse(rbad[i], strlen(rbad[i]), &r, why, sizeof why);
    if (rc == NQOK)
      fprintf(stderr, "record accepted: %s\n", rbad[i]);
    NQTCHK(rc == NQEDEC && r == NULL && why[0] != '\0');
  }
  /* a why names the member */
  nqdparse(rbad[3], strlen(rbad[3]), &r, why, sizeof why);
  NQTCHK(strstr(why, "extra") != NULL);
  nqdparse(rbad[6], strlen(rbad[6]), &r, why, sizeof why);
  NQTCHK(strstr(why, "sources[0].sha256") != NULL);
  /* sorted on reading, canonical out */
  NQTEQI(nqdparse(in, strlen(in), &r, why, sizeof why), NQOK);
  NQTEQI(nqdjson(r, out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, want) == 0 && n == strlen(want));
  NQTEQI(nqdjson(r, out, 10, &n), NQEBUF);
  NQTCHK(n == strlen(want));
  NQTEQI(nqdlen(r, "sources"), 2);
  NQTEQI(nqdlen(r, "nope"), 0);
  NQTEQI(nqdat(r, "sources", 1, out, sizeof out, &n), NQOK);
  NQTCHK(strncmp(out, "{\"path\":\"b.csv\"", 15) == 0);
  NQTEQI(nqdat(r, "sources", 2, out, sizeof out, &n), NQEIO);
  /* put: replace by key, insert in order, refuse invalid */
  NQTEQI(P("sources", "{\"path\":\"a.csv\",\"size\":2,\"sha256\":"
                "\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                "cccccc\"}"),
         NQOK);
  NQTEQI(nqdlen(r, "sources"), 2);
  NQTEQI(P("sources", "{\"path\":\"0.csv\",\"size\":2,\"sha256\":"
                "\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                "cccccc\"}"),
         NQOK);
  NQTEQI(nqdat(r, "sources", 0, out, sizeof out, &n), NQOK);
  NQTCHK(strncmp(out, "{\"path\":\"0.csv\"", 15) == 0);
  NQTEQI(P("sources", "{\"path\":\"x\"}"),
         NQEDEC);
  NQTEQI(P("nope", "{}"), NQEARG);
  NQTEQI(P("cite", "{\"title\":\"T\",\"year\":2026}"),
         NQOK);
  NQTEQI(nqdlen(r, "cite"), 1);
  NQTEQI(P("steps", "{\"kind\":\"filter\",\"note\":\"x\"}"),
         NQOK);
  NQTEQI(P("steps", "{\"kind\":\"recode\"}"),
         NQOK);
  NQTEQI(nqdat(r, "steps", 1, out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "{\"kind\":\"recode\"}") == 0);
  /* set and remove a field */
  NQTEQI(S("sources", "a.csv", "url", "\"https://x.org/a\""),
         NQOK);
  NQTEQI(S("sources", "a.csv", "url", "1"),
         NQEDEC);
  NQTEQI(S("sources", "a.csv", "path", "\"z\""),
         NQEARG);
  NQTEQI(S("sources", "q.csv", "url", "\"u\""),
         NQEIO);
  NQTEQI(nqdset(r, "cite", NULL, "year", NULL, 0, why, sizeof why), NQOK);
  NQTEQI(nqdset(r, "cite", NULL, "title", NULL, 0, why, sizeof why), NQEDEC);
  NQTEQI(nqddel(r, "sources", "0.csv"), NQOK);
  NQTEQI(nqddel(r, "sources", "0.csv"), NQEIO);
  NQTEQI(nqddel(r, "steps", "x"), NQEARG);
  NQTEQI(nqddel(r, "steps", NULL), NQOK);
  NQTEQI(nqdlen(r, "steps"), 0);
  nqdrfree(r);
  NQTEQI(nqdnew(&r), NQOK);
  NQTEQI(nqdjson(r, out, sizeof out, &n), NQOK);
  NQTCHK(strcmp(out, "{\"format\":\"noqtis-data-1\"}") == 0);
  nqdrfree(r);
}

/* nqdchk on vectors/nqd/cap: the record there was written by this
 * library over the files beside it */
static void chk(void) {
  nqdrep *rep = NULL;
  nqdrec *r = NULL;
  char why[600];
  size_t i;
  const char *c, *d;
  int ok, all = 1;
  NQTEQI(nqdchk("vectors/nqd/cap", &rep), NQOK);
  for (i = 0; i < nqdrepn(rep); i++) {
    nqdrepi(rep, i, &c, &ok, &d);
    if (!ok)
      fprintf(stderr, "%s: %s\n", c, d);
    all &= ok;
  }
  NQTCHK(all && nqdrepn(rep) >= 3);
  nqdrepfree(rep);
  NQTEQI(nqdload("vectors/nqd/cap", &r, why, sizeof why), NQOK);
  nqdrfree(r);
  NQTEQI(nqdload("vectors/nqd", &r, why, sizeof why), NQEIO);
  NQTEQI(nqdnew(&r), NQOK);
  NQTEQI(nqdsrc(r, "vectors/nqd/cap", "../x", why, sizeof why), NQEARG);
  NQTEQI(nqdsrc(r, "vectors/nqd/cap", "nope.csv", why, sizeof why), NQEIO);
  NQTEQI(nqdsrc(r, "vectors/nqd/cap", "data/a.csv", why, sizeof why), NQOK);
  NQTEQI(nqdlen(r, "sources"), 1);
  nqdrfree(r);
}

/* a record with every member (vectors/nqd/full.json) reads, and its
 * canonical form reads back to the same bytes */
static void full(void) {
  char *b, why[600], *o1, *o2;
  size_t n, n1, n2;
  nqdrec *r = NULL, *r2 = NULL;
  NQTEQI(qdread("vectors/nqd/full.json", NQDMAX, &b, &n), NQOK);
  NQTEQI(nqdparse(b, n, &r, why, sizeof why), NQOK);
  if (r == NULL) {
    fprintf(stderr, "full.json: %s\n", why);
    qdfree(b);
    return;
  }
  NQTEQI(nqdjson(r, NULL, 0, &n1), NQEBUF);
  o1 = (char *)malloc(n1 + 1);
  NQTEQI(nqdjson(r, o1, n1 + 1, &n1), NQOK);
  NQTEQI(nqdparse(o1, n1, &r2, why, sizeof why), NQOK);
  o2 = (char *)malloc(n1 + 1);
  NQTEQI(nqdjson(r2, o2, n1 + 1, &n2), NQOK);
  NQTCHK(n1 == n2 && memcmp(o1, o2, n1) == 0);
  NQTEQI(nqdlen(r, "steps"), 2);
  NQTEQI(nqdlen(r, "stats"), 1);
  free(o1);
  free(o2);
  qdfree(b);
  nqdrfree(r);
  nqdrfree(r2);
}

int main(void) {
  full();
  nums();
  json();
  rec();
  chk();
  return nqtdone("tdrec");
}
