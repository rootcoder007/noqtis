/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The regular expressions of the regex rule (nqd/rx.c): what each
 * pattern matches, every pattern refused and why, time linear in the
 * value on patterns that make a backtracking matcher exponential; and
 * the regex and mad rules of a schema on vectors/nqd/rules. */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

static int rx(const char *p, const char *v, size_t vn) {
  qdrx *x = NULL;
  char why[300];
  int m;
  if (qdrxcomp(p, strlen(p), &x, why, sizeof why) != NQOK) {
    fprintf(stderr, "pattern %s refused: %s\n", p, why);
    return -1;
  }
  m = qdrxrun(x, v, vn);
  qdrxfree(x);
  return m;
}

/* the results are Python's re.search(pattern, value, re.ASCII |
 * re.DOTALL), which has the same meaning on this subset */
static void match(void) {
  static const struct {
    const char *p, *v;
    int m;
  } t[] = {
      {"abc", "abc", 1},
      {"abc", "xabcx", 1},
      {"abc", "ab", 0},
      {"^abc$", "abc", 1},
      {"^abc$", "abcd", 0},
      {"^abc", "zabc", 0},
      {"a.c", "abc", 1},
      {"a.c", "ac", 0},
      {"a*", "", 1},
      {"^a*$", "aaaa", 1},
      {"^a*$", "aab", 0},
      {"^a+$", "", 0},
      {"^a+$", "aaa", 1},
      {"^colou?r$", "color", 1},
      {"^colou?r$", "colour", 1},
      {"^colou?r$", "colouur", 0},
      {"^(cat|dog)s?$", "dogs", 1},
      {"^(cat|dog)s?$", "cats", 1},
      {"^(cat|dog)s?$", "cow", 0},
      {"^(ab)+$", "ababab", 1},
      {"^(ab)+$", "ababa", 0},
      {"^[a-c]+$", "abcabc", 1},
      {"^[a-c]+$", "abd", 0},
      {"^[^0-9]+$", "abc", 1},
      {"^[^0-9]+$", "ab1", 0},
      {"^[-a]+$", "-a-", 1},
      {"^[a-]+$", "a-", 1},
      {"^\\d$", "5", 1},
      {"^\\d+$", "2024", 1},
      {"^\\d+$", "20x4", 0},
      {"^\\w+$", "a_Z9", 1},
      {"^\\w+$", "a-b", 0},
      {"^\\s*$", " \t", 1},
      {"^[\\d.]+$", "3.14", 1},
      {"^\\.$", ".", 1},
      {"^\\.$", "x", 0},
      {"^a\\|b$", "a|b", 1},
      {"^\\(x\\)$", "(x)", 1},
      {"^[\\]]$", "]", 1},
      {"^[\\^a]+$", "^a", 1},
      {"^$", "", 1},
      {"^$", "x", 0},
      {"x|^$", "", 1},
      {"(a|b)*c", "ababc", 1},
      {"(a|b)*c", "abab", 0},
      {"^\\d\\d\\d\\d-\\d\\d-\\d\\d$", "2024-02-29", 1},
      {"^\\d\\d\\d\\d-\\d\\d-\\d\\d$", "2024-2-29", 0},
      {"^((a*)*)*b$", "aaaab", 1},
      {"^((a*)*)*b$", "aaaa", 0},
      {"^(a|ab)(c|bcd)(d*)$", "abcd", 1},
      {"b$", "ab", 1},
      {"b$", "ba", 0},
      {"^a|b$", "xb", 1},
      {"^a|b$", "xa", 0},
      {"^[A-Z][a-z]+, [A-Z][A-Z]$", "Toronto, ON", 1},
      {"^\303\251t\303\251$", "\303\251t\303\251", 1},
      {"^..$", "\303\251t", 1},
      {"^.$", "\303\251", 1},
      {"^[\303\240-\303\277]$", "\303\251", 1},
  };
  size_t i;
  for (i = 0; i < sizeof t / sizeof t[0]; i++) {
    int m = rx(t[i].p, t[i].v, strlen(t[i].v));
    if (m != t[i].m)
      fprintf(stderr, "regex %s on \"%s\": %d, expected %d\n", t[i].p,
              t[i].v, m, t[i].m);
    NQTEQI(m, t[i].m);
  }
  /* a byte that is not UTF-8 is one character, matched by . and by a
   * negated class only */
  NQTEQI(rx("^a.b$", "a\377b", 3), 1);
  NQTEQI(rx("^a[^x]b$", "a\377b", 3), 1);
  NQTEQI(rx("^a[\303\200-\303\277]b$", "a\303b", 3), 0);
  NQTEQI(rx("^a..b$", "a\303b", 3), 0);
  /* a NUL inside the value is a character too */
  NQTEQI(rx("^a.b$", "a\0b", 3), 1);
  /* . matches a line break; $ only at the very end */
  NQTEQI(rx("^a.b$", "a\nb", 3), 1);
  NQTEQI(rx("a$", "a\n", 2), 0);
}

static void refuse(void) {
  static const struct {
    const char *p, *why;
  } t[] = {
      {"", "empty pattern"},
      {"a|", "empty alternative"},
      {"|a", "nothing before |"},
      {"a||b", "nothing before |"},
      {"()", "empty group"},
      {"(a|)", "empty group"},
      {"(a", "( without its )"},
      {"a)", ") without its ("},
      {"*a", "nothing before *"},
      {"(+a)", "nothing before +"},
      {"a|?", "nothing before ?"},
      {"a{2}", "counted repetition"},
      {"a}", "counted repetition"},
      {"a]", "] without its ["},
      {"[]a]", "empty class"},
      {"[^]a]", "empty class"},
      {"[abc", "not closed"},
      {"[a[]", "[ inside a class"},
      {"[z-a]", "out of order"},
      {"[a-\\d]", "ends at one character"},
      {"[\\q]", "escape a class does not have"},
      {"\\q", "escape the syntax does not have"},
      {"\\b", "escape the syntax does not have"},
      {"\\1", "escape the syntax does not have"},
      {"a\\", "backslash at the end"},
      {"[a\\", "backslash at the end"},
      {"\377", "not UTF-8"},
  };
  size_t i;
  qdrx *x;
  char why[300], big[1100];
  for (i = 0; i < sizeof t / sizeof t[0]; i++) {
    x = NULL;
    why[0] = '\0';
    NQTEQI(qdrxcomp(t[i].p, strlen(t[i].p), &x, why, sizeof why), NQEDEC);
    NQTCHK(x == NULL);
    if (strstr(why, t[i].why) == NULL)
      fprintf(stderr, "pattern %s: why [%s] lacks [%s]\n", t[i].p, why,
              t[i].why);
    NQTCHK(strstr(why, t[i].why) != NULL);
  }
  /* a NUL in the pattern */
  NQTEQI(qdrxcomp("a\0b", 3, &x, why, sizeof why), NQEDEC);
  /* 64 groups deep, not 65; 1,024 bytes, not 1,025 */
  memset(big, '(', 65);
  big[65] = 'a';
  memset(big + 66, ')', 65);
  NQTEQI(qdrxcomp(big + 1, 129, &x, why, sizeof why), NQOK);
  qdrxfree(x);
  NQTEQI(qdrxcomp(big, 131, &x, why, sizeof why), NQEDEC);
  NQTCHK(strstr(why, "deeper than 64") != NULL);
  memset(big, 'a', 1025);
  NQTEQI(qdrxcomp(big, 1024, &x, why, sizeof why), NQOK);
  NQTEQI(qdrxrun(x, big, 1024), 1);
  NQTEQI(qdrxrun(x, big, 1023), 0);
  qdrxfree(x);
  NQTEQI(qdrxcomp(big, 1025, &x, why, sizeof why), NQEDEC);
  NQTEQI(qdrxcomp(NULL, 1, &x, why, sizeof why), NQEARG);
}

/* patterns that take a backtracking matcher time exponential in the
 * value's length end here at once: 200,000 characters each */
static void linear(void) {
  static const char *const p[] = {"^(a*)*b$", "^(a|a)*b$", "^(a|aa)+$c",
                                  "^((a*)*)*$b", "(x+x+)+y"};
  size_t n = 200000, i;
  char *v = (char *)malloc(n + 1);
  NQTCHK(v != NULL);
  if (v == NULL)
    return;
  memset(v, 'a', n);
  for (i = 0; i < 4; i++)
    NQTEQI(rx(p[i], v, n), 0);
  memset(v, 'x', n);
  NQTEQI(rx(p[4], v, n), 0);
  v[n - 1] = 'y';
  NQTEQI(rx(p[4], v, n), 1);
  free(v);
}

static int chk(const char *schema, const char *want) {
  nqdrep *r = NULL;
  int rc = nqdschk("vectors/nqd/rules", schema, strlen(schema), &r), hit = 0;
  size_t i;
  if (r == NULL)
    return -1;
  for (i = 0; i < nqdrepn(r); i++) {
    const char *c, *d;
    int ok;
    nqdrepi(r, i, &c, &ok, &d);
    if (getenv("NQDVERB") != NULL)
      fprintf(stderr, "  %s %s: %s\n", ok ? "ok" : "FAIL", c, d);
    hit |= strstr(d, want) != NULL;
  }
  if (!hit)
    fprintf(stderr, "no row says [%s]\n", want);
  NQTCHK(hit);
  nqdrepfree(r);
  return rc;
}

#define S(r) "{\"path\":\"m.csv\",\"kind\":\"csv\",\"rules\":[" r "]}"

static void rules(void) {
  char why[300];
  nqdrec *rec = NULL;
  /* m.csv's code: ab-03 (line 4) and AB-5 (line 6) fail; the missing
   * value on line 11 is not checked */
  NQTEQI(chk(S("{\"kind\":\"regex\",\"col\":\"code\",\"pattern\":"
               "\"^[A-Z][A-Z]-\\\\d\\\\d$\"}"),
             "m.csv: regex(code): 2 rows fail, the first at line 4"),
         NQEVRFY);
  NQTEQI(chk(S("{\"kind\":\"regex\",\"col\":\"code\",\"pattern\":"
               "\"^[A-Za-z]+-\\\\d+$\"}"),
             "m.csv: regex(code): holds"),
         NQOK);
  /* m.csv's x; median 11.75 and mad 1.11195 from R (median(x), mad(x));
   * which(abs(x - 11.75) > 3.5 * mad(x)) is 7 9 (lines 8 and 10), with
   * 1 instead of 3.5 it is 1 4 7 9, with 40 none */
  NQTEQI(chk(S("{\"kind\":\"mad\",\"col\":\"x\",\"max\":3.5}"),
             "m.csv: mad(x): 2 rows fail, the first at line 8 (median "
             "11.75, scaled MAD 1.11195)"),
         NQEVRFY);
  NQTEQI(chk(S("{\"kind\":\"mad\",\"col\":\"x\",\"max\":1}"),
             "4 rows fail, the first at line 2"),
         NQEVRFY);
  NQTEQI(chk(S("{\"kind\":\"mad\",\"col\":\"x\",\"max\":40}"),
             "m.csv: mad(x): holds (median 11.75, scaled MAD 1.11195)"),
         NQOK);
  /* id 1..10: median 5.5, mad(1:10) 3.7065 (1.4826 * 2.5, which is
   * 3.7064999999999997 in binary64); which(abs(x - 5.5) > mad(x)) is
   * 1 10 in R; with 40 nothing fails */
  NQTEQI(chk(S("{\"kind\":\"mad\",\"col\":\"id\",\"max\":1}"),
             "2 rows fail, the first at line 2 (median 5.5, scaled MAD "
             "3.7064999999999997)"),
         NQEVRFY);
  /* text is not a number: each value fails */
  NQTEQI(chk(S("{\"kind\":\"mad\",\"col\":\"code\",\"max\":3}"),
             "9 rows fail, the first at line 2"),
         NQEVRFY);
  /* refusals of the rules themselves */
  {
    static const struct {
      const char *rule, *why;
    } t[] = {
        {"{\"kind\":\"regex\",\"col\":\"code\"}", "pattern belongs"},
        {"{\"kind\":\"set\",\"col\":\"code\",\"set\":[\"a\"],\"pattern\":"
         "\"a\"}",
         "pattern belongs"},
        {"{\"kind\":\"regex\",\"col\":\"code\",\"pattern\":\"a{2}\"}",
         "rules[0].pattern: byte 1: counted repetition"},
        {"{\"kind\":\"regex\",\"cols\":[\"code\"],\"pattern\":\"a\"}",
         "takes col"},
        {"{\"kind\":\"regex\",\"col\":\"code\",\"pattern\":3}",
         "must be a string"},
        {"{\"kind\":\"mad\",\"col\":\"x\"}", "needs max"},
        {"{\"kind\":\"mad\",\"col\":\"x\",\"max\":0}", "needs max"},
        {"{\"kind\":\"mad\",\"col\":\"x\",\"max\":-1}", "needs max"},
        {"{\"kind\":\"mad\",\"col\":\"x\",\"min\":1,\"max\":3}",
         "and no min"},
    };
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
      char e[400];
      size_t n = (size_t)snprintf(e, sizeof e,
                                  "{\"path\":\"m.csv\",\"kind\":\"csv\","
                                  "\"rules\":[%s]}",
                                  t[i].rule);
      NQTEQI(nqdnew(&rec), NQOK);
      why[0] = '\0';
      NQTEQI(nqdput(rec, "schemas", e, n, why, sizeof why), NQEDEC);
      if (strstr(why, t[i].why) == NULL)
        fprintf(stderr, "rule %s: why [%s] lacks [%s]\n", t[i].rule, why,
                t[i].why);
      NQTCHK(strstr(why, t[i].why) != NULL);
      nqdrfree(rec);
    }
  }
  /* a column the schema does not have */
  NQTEQI(chk(S("{\"kind\":\"regex\",\"col\":\"nope\",\"pattern\":\"a\"}"),
             "names a column the schema does not have"),
         NQEVRFY);
}

int main(void) {
  match();
  refuse();
  linear();
  rules();
  return nqtdone("tdrx");
}
