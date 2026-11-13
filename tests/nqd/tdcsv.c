/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The CSV reader (RFC 4180 and its refusals), value classes, schema
 * inference and the schema check, on vectors/nqd/cap and on bytes. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

/* reads all of s; the fields of every record joined by '|' and records
 * by '/', into out; the return code of the last call */
static int rdall(const char *s, size_t n, char delim, char *out, size_t cap,
                 char *why) {
  qdcsv c;
  int got = 1, rc;
  size_t o = 0, i;
  out[0] = '\0';
  if ((rc = qdcsvmem(&c, s, n, delim)) != NQOK)
    return rc;
  for (;;) {
    rc = qdcsvnext(&c, &got);
    if (rc != NQOK || !got)
      break;
    for (i = 0; i < c.nf; i++) {
      size_t l;
      const char *f = qdcsvf(&c, i, &l);
      if (o + l + 2 < cap) {
        if (i)
          out[o++] = '|';
        memcpy(out + o, f, l);
        o += l;
      }
    }
    out[o++] = '/';
    out[o] = '\0';
  }
  if (why != NULL)
    strcpy(why, c.why);
  qdcsvclose(&c);
  return rc;
}

#define RD(s, want)                                                         \
  do {                                                                      \
    char o_[512];                                                           \
    NQTEQI(rdall(s, sizeof(s) - 1, ',', o_, sizeof o_, NULL), NQOK);        \
    if (strcmp(o_, want) != 0)                                              \
      fprintf(stderr, "csv %s: [%s], expected [%s]\n", #s, o_, want);       \
    NQTCHK(strcmp(o_, want) == 0);                                          \
  } while (0)

#define BAD(s, part)                                                        \
  do {                                                                      \
    char o_[512], w_[200];                                                  \
    NQTEQI(rdall(s, sizeof(s) - 1, ',', o_, sizeof o_, w_), NQEDEC);        \
    if (strstr(w_, part) == NULL)                                           \
      fprintf(stderr, "csv %s: why [%s] lacks [%s]\n", #s, w_, part);       \
    NQTCHK(strstr(w_, part) != NULL);                                       \
  } while (0)

static void csv(void) {
  char o[512];
  RD("a,b\nc,d\n", "a|b/c|d/");
  RD("a,b\r\nc,d", "a|b/c|d/");
  RD("\xef\xbb\xbf" "a,b\n", "a|b/");
  RD("\"a,b\",\"c\"\"d\"\n", "a,b|c\"d/");
  RD("\"line\nbreak\",x\n", "line\nbreak|x/");
  RD("\"crlf\r\nkept\"\n", "crlf\r\nkept/");
  RD(",,\n", "||/");
  RD("\"\"\n", "/");
  RD("a\n\nb\n", "a//b/");
  RD("", "");
  RD("x", "x/");
  BAD("a\"b\n", "a quote inside an unquoted field");
  BAD("\"ab\"c\n", "text after a closing quote");
  BAD("\"open\n", "not closed");
  BAD("a\rb\n", "carriage return");
  BAD("a,\xff\n", "not UTF-8");
  BAD("a,b\n\"x\ny\"z\n", "line 3");
  /* a delimiter of the caller's */
  NQTEQI(rdall("a;b,c\n", 6, ';', o, sizeof o, NULL), NQOK);
  NQTCHK(strcmp(o, "a|b,c/") == 0);
  /* limits */
  {
    size_t n = QDCSVFIELD + 10;
    char *big = (char *)malloc(n);
    memset(big, 'x', n);
    big[n - 1] = '\n';
    NQTEQI(rdall(big, n, ',', o, sizeof o, NULL), NQELIM);
    memset(big, ',', n);
    NQTEQI(rdall(big, 20000, ',', o, sizeof o, NULL), NQELIM);
    free(big);
  }
}

static void classes(void) {
  static const struct {
    const char *s;
    unsigned m;
  } v[] = {{"0", QDTINT | QDTREAL},     {"-12", QDTINT | QDTREAL},
           {"007", 0},                  {"1.5", QDTREAL},
           {"-0.25e-3", QDTREAL},       {".5", 0},
           {"1.", 0},                   {"+1", 0},
           {"true", QDTBOOL},           {"FALSE", QDTBOOL},
           {"yes", 0},                  {"2024-02-29", QDTDATE},
           {"2023-02-29", 0},           {"NaN", 0},
           {"1e999", 0},                {"1234567890123456789", 0},
           {"123456789012345678", QDTINT | QDTREAL}};
  size_t i;
  double d;
  for (i = 0; i < sizeof v / sizeof v[0]; i++) {
    unsigned m = qdvclass(v[i].s, strlen(v[i].s), &d);
    if (m != v[i].m)
      fprintf(stderr, "class %s: %u, expected %u\n", v[i].s, m, v[i].m);
    NQTEQI(m, v[i].m);
  }
}

static int rows(nqdrep *r, int *bad) {
  size_t i;
  *bad = 0;
  for (i = 0; i < nqdrepn(r); i++) {
    const char *c, *d;
    int ok;
    nqdrepi(r, i, &c, &ok, &d);
    if (!ok) {
      (*bad)++;
      if (getenv("NQDVERB") != NULL)
        fprintf(stderr, "  %s: %s\n", c, d);
    }
  }
  return (int)nqdrepn(r);
}

/* "schemas" element over data/a.csv with fields swapped in */
static int chk(const char *schema, int *bad) {
  nqdrep *r = NULL;
  int rc = nqdschk("vectors/nqd/cap", schema, strlen(schema), &r);
  if (r == NULL)
    return -1;
  rows(r, bad);
  nqdrepfree(r);
  return rc;
}

static void infer(void) {
  char out[2048], why[300];
  size_t n;
  nqdcsvopt o;
  int bad;
  static const char *want =
      "{\"columns\":[{\"name\":\"id\",\"nulls\":false,\"type\":\"int\"},"
      "{\"name\":\"name\",\"nulls\":true,\"type\":\"text\"},"
      "{\"name\":\"score\",\"nulls\":true,\"type\":\"real\"},"
      "{\"name\":\"when\",\"nulls\":false,\"type\":\"date\"}],"
      "\"kind\":\"csv\",\"path\":\"data/a.csv\",\"rows\":{\"max\":3,"
      "\"min\":3}}";
  NQTEQI(nqdinfer("vectors/nqd/cap", "data/a.csv", NULL, out, sizeof out,
                  &n, why, sizeof why),
         NQOK);
  if (strcmp(out, want) != 0)
    fprintf(stderr, "infer: %s\n", out);
  NQTCHK(strcmp(out, want) == 0);
  NQTEQI(chk(out, &bad), NQOK);
  NQTEQI(bad, 0);
  memset(&o, 0, sizeof o);
  o.ranges = 1;
  NQTEQI(nqdinfer("vectors/nqd/cap", "data/a.csv", &o, out, sizeof out, &n,
                  why, sizeof why),
         NQOK);
  NQTCHK(strstr(out, "\"max\":4,\"min\":3.5") != NULL);
  NQTCHK(strstr(out, "\"max\":\"2024-03-01\",\"min\":\"2024-01-02\"") !=
         NULL);
  NQTEQI(chk(out, &bad), NQOK);
  o.noheader = 1;
  o.ranges = 0;
  NQTEQI(nqdinfer("vectors/nqd/cap", "data/a.csv", &o, out, sizeof out, &n,
                  why, sizeof why),
         NQOK);
  NQTCHK(strstr(out, "\"header\":false") && strstr(out, "\"name\":\"V4\""));
  NQTCHK(strstr(out, "\"max\":4,\"min\":4") != NULL);
  NQTEQI(nqdinfer("vectors/nqd/cap", "nope.csv", NULL, out, sizeof out, &n,
                  why, sizeof why),
         NQEIO);
  NQTEQI(nqdinfer("vectors/nqd/cap", "data/a.csv", NULL, out, 10, &n, why,
                  sizeof why),
         NQEBUF);
}

static void check(void) {
  int bad;
  /* the type of a column */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\",\"columns\":["
             "{\"name\":\"id\",\"type\":\"int\"},{\"name\":\"name\","
             "\"type\":\"int\"},{\"name\":\"score\",\"type\":\"real\"},"
             "{\"name\":\"when\",\"type\":\"date\"}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 2);
  /* nulls, ranges, sets */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\",\"columns\":["
             "{\"name\":\"id\",\"type\":\"int\",\"max\":2},{\"name\":\"name\","
             "\"type\":\"text\",\"nulls\":false,\"set\":[\"ann\"]},"
             "{\"name\":\"score\",\"type\":\"real\"},"
             "{\"name\":\"when\",\"type\":\"date\",\"min\":\"2024-02-01\"}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 4);
  /* the header */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\",\"columns\":["
             "{\"name\":\"id\",\"type\":\"int\"}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 1);
  /* missing-value codes of the schema's own: NA is then a value */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\",\"na\":[\"\"],"
             "\"columns\":[{\"name\":\"id\",\"type\":\"int\"},{\"name\":"
             "\"name\",\"type\":\"text\"},{\"name\":\"score\",\"type\":"
             "\"real\"},{\"name\":\"when\",\"type\":\"date\"}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 1);
  /* rows and rules */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\",\"rows\":{\"min\":4},"
             "\"rules\":[{\"kind\":\"unique\",\"col\":\"id\"},{\"kind\":"
             "\"incr\",\"col\":\"when\"},{\"kind\":\"rows\",\"max\":3},"
             "{\"kind\":\"cols\",\"min\":4,\"max\":4},{\"kind\":\"complete\","
             "\"col\":\"name\",\"share\":0.5},{\"kind\":\"distinct\",\"col\":"
             "\"name\",\"min\":2}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 1); /* rows min 4 */
  NQTEQI(chk("{\"path\":\"data/a.csv\",\"kind\":\"csv\","
             "\"rules\":[{\"kind\":\"unique\",\"cols\":[\"id\",\"name\"]},"
             "{\"kind\":\"notnull\",\"col\":\"name\"},{\"kind\":\"range\","
             "\"col\":\"score\",\"max\":3.9},{\"kind\":\"set\",\"col\":\"id\","
             "\"set\":[\"1\",\"2\"]},{\"kind\":\"complete\",\"col\":\"score\","
             "\"share\":0.9},{\"kind\":\"distinct\",\"col\":\"id\",\"max\":2},"
             "{\"kind\":\"incr\",\"col\":\"nope\"}]}",
             &bad),
         NQEVRFY);
  NQTEQI(bad, 6);
  /* b.csv: 1, 2: unique and increasing */
  NQTEQI(chk("{\"path\":\"data/b.csv\",\"kind\":\"csv\",\"rules\":[{\"kind\":"
             "\"unique\",\"col\":\"x\"},{\"kind\":\"incr\",\"col\":\"x\"}]}",
             &bad),
         NQOK);
  NQTEQI(chk("{\"path\":\"data/none.csv\",\"kind\":\"csv\"}", &bad), NQEVRFY);
  NQTEQI(chk("{\"path\":\"data/a.csv\"}", &bad), NQEVRFY);
}

int main(void) {
  csv();
  classes();
  infer();
  check();
  return nqtdone("tdcsv");
}
