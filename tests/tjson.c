/* JSON reader tests: RFC 8259 acceptance and rejection, limits, lookups,
 * hex, and a real ACVP file. */
#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "nqt.h"

static int ok(const char *s) {
  nqjs *v = NULL;
  int rc = nqjparse(s, strlen(s), &v, NULL);
  nqjfree(v);
  return rc == NQOK;
}

static void taccept(void) {
  const char *good[] = {
      "0", "-0", "1.5e10", "-12.25E-3", "true", "false", "null", "\"\"",
      "[]", "{}", " [ 1 , 2 ] ", "{\"a\":{\"b\":[null,true]}}",
      "\"\\u00e9\\ud83d\\ude00\\n\\/\"", "\"\xc3\xa9\xf0\x9f\x98\x80\"",
  };
  size_t i;
  for (i = 0; i < sizeof good / sizeof *good; i++) {
    if (!ok(good[i])) {
      fprintf(stderr, "refused good input %zu: %s\n", i, good[i]);
    }
    NQTCHK(ok(good[i]));
  }
}

static void treject(void) {
  const char *bad[] = {
      "", " ", "01", "1.", ".5", "+1", "1e", "-", "tru", "nul", "[1,]",
      "{\"a\":1,}", "{,}", "[", "]", "{\"a\"}", "{\"a\":}", "{1:2}",
      "\"abc", "\"\\x\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"",
      "\"\x01\"", "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\"",
      "\"\xff\"", "[1 2]", "1 2", "{\"a\":1,\"a\":2}", "/* c */ 1", "NaN",
      "[1]x", "\"\\u12\"",
  };
  size_t i;
  for (i = 0; i < sizeof bad / sizeof *bad; i++) {
    if (ok(bad[i])) {
      fprintf(stderr, "accepted bad input %zu: %s\n", i, bad[i]);
    }
    NQTCHK(!ok(bad[i]));
  }
}

static void tdepth(void) {
  char deep[2 * NQJDEPTH + 3];
  nqjs *v = NULL;
  size_t i;
  for (i = 0; i < NQJDEPTH; i++) deep[i] = '[';
  for (i = 0; i < NQJDEPTH; i++) deep[NQJDEPTH + i] = ']';
  deep[2 * NQJDEPTH] = 0;
  NQTEQI(nqjparse(deep, strlen(deep), &v, NULL), NQOK);
  nqjfree(v);
  /* one more level is over the limit */
  memmove(deep + 1, deep, 2 * NQJDEPTH + 1);
  deep[0] = '[';
  deep[2 * NQJDEPTH + 1] = ']';
  deep[2 * NQJDEPTH + 2] = 0;
  NQTEQI(nqjparse(deep, strlen(deep), &v, NULL), NQELIM);
  NQTCHK(v == NULL);
}

static void tlookup(void) {
  const char *s = "{\"n\":-9223372036854775808,\"big\":9223372036854775808,"
                  "\"f\":1.5,\"s\":\"x\\u0000y\",\"t\":\"hi\","
                  "\"a\":[1,2,3],\"b\":true}";
  nqjs *v = NULL;
  int64_t x;
  NQTEQI(nqjparse(s, strlen(s), &v, NULL), NQOK);
  NQTEQI(nqjint(nqjget(v, "n"), &x), NQOK);
  NQTCHK(x == INT64_MIN);
  NQTEQI(nqjint(nqjget(v, "big"), &x), NQELIM);
  NQTEQI(nqjint(nqjget(v, "f"), &x), NQEDEC);
  NQTCHK(nqjstr(nqjget(v, "s")) == NULL); /* embedded NUL */
  NQTCHK(nqjget(v, "s")->len == 3);
  NQTCHK(strcmp(nqjstr(nqjget(v, "t")), "hi") == 0);
  NQTCHK(nqjat(nqjget(v, "a"), 2) != NULL);
  NQTCHK(nqjat(nqjget(v, "a"), 3) == NULL);
  NQTEQI(nqjbool(nqjget(v, "b")), 1);
  NQTEQI(nqjbool(nqjget(v, "t")), -1);
  NQTCHK(nqjget(v, "missing") == NULL);
  nqjfree(v);
}

static void thex(void) {
  uint8_t b[4];
  char h[9];
  size_t n;
  NQTEQI(nqunhex("00ffA5", 6, b, sizeof b, &n), NQOK);
  NQTCHK(n == 3 && b[0] == 0 && b[1] == 0xff && b[2] == 0xa5);
  NQTEQI(nqunhex("0", 1, b, sizeof b, &n), NQEDEC);
  NQTEQI(nqunhex("zz", 2, b, sizeof b, &n), NQEDEC);
  NQTEQI(nqunhex("0011223344", 10, b, sizeof b, &n), NQEBUF);
  nqhex(b, 3, h);
  NQTCHK(strcmp(h, "00ffa5") == 0);
}

static void tacvp(void) {
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  const nqjs *groups;
  int rc = nqreadf("vectors/acvp/SHA3-256-2.0/prompt.json", 1u << 26, &buf,
                   &len);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) return;
  NQTEQI(nqjparse(buf, len, &v, NULL), NQOK);
  /* the ACVP-Server files are one object {"vsId":..., "testGroups":[...]};
   * a live ACVP session wraps it as [ {"acvVersion":...}, {...} ] */
  groups = nqjget(v->type == NQJARR ? nqjat(v, 1) : v, "testGroups");
  NQTCHK(groups != NULL && groups->n > 0);
  nqjfree(v);
  nqfree(buf, len + 1);
  NQTEQI(nqreadf("vectors/does-not-exist.json", 100, &buf, &len), NQEIO);
}

int main(void) {
  taccept();
  treject();
  tdepth();
  tlookup();
  thex();
  tacvp();
  return nqtdone("tjson");
}
