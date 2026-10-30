/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Capsules: the canonical JSON writer, base64, paths and times; seal and
 * check round trips (ML-DSA, SLH-DSA); every tamper the format defines;
 * path containment; allocation failures; and the golden capsule under
 * vectors/cap/sample (run "tcap gen" to rewrite it).
 *
 * The folder tests need POSIX (mkdir, symlink, mkfifo); on Windows only
 * the unit tests run. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
/* NetBSD hides POSIX 2008 calls (symlink, dirfd) under that alone */
#if defined(__NetBSD__)
#define _NETBSD_SOURCE 1
#endif
#endif

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "noqtis.h"
#include "cap/cap.h"
#include "core/int.h"
#include "core/json.h"
#include "nqt.h"

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define NQTFS 1
#if defined(__wasi__)
/* WASI has no FIFOs: this makes a plain file, which the FIFO checks
 * notice (lstat) and skip */
static int mkfifo(const char *p, mode_t m) {
  FILE *f = fopen(p, "wb");
  (void)m;
  if (f == NULL) return -1;
  fclose(f);
  return 0;
}
#endif
#endif

/* ---- unit tests ---- */

static void tnum(const char *in, const char *want) {
  nqcbuf b;
  int rc;
  memset(&b, 0, sizeof b);
  rc = nqcjnum(&b, in, strlen(in));
  NQTEQI(rc, NQOK);
  nqcput(&b, "", 1);
  NQTCHK(b.p != NULL && b.n == strlen(want) + 1);
  if (b.p != NULL && strcmp(b.p, want) != 0) {
    fprintf(stderr, "number %s: got %s, want %s\n", in, b.p, want);
    NQTCHK(0);
  }
  nqcbfree(&b);
}

static void tcanon(const char *in, const char *want, int wrc) {
  nqjs *v = NULL;
  nqcbuf b;
  int rc = nqjparse(in, strlen(in), &v, NULL);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) return;
  memset(&b, 0, sizeof b);
  rc = nqcjval(&b, v);
  NQTEQI(rc, wrc);
  if (wrc == NQOK) {
    NQTCHK(b.n == strlen(want) && memcmp(b.p, want, b.n) == 0);
    if (!(b.n == strlen(want) && memcmp(b.p, want, b.n) == 0)) {
      fprintf(stderr, "canon: got %.*s\n", (int)b.n, b.p);
    }
  }
  nqcbfree(&b);
  nqjfree(v);
}

/* duplicate keys are refused wherever they are, and an object of many
 * keys parses in O(n log n): 200000 keys took minutes with a scan per
 * key (review of a4eec67, F4) */
static void tdups(void) {
  static const char *const dup[] = {
      "{\"a\":1,\"a\":2}", "{\"a\":1,\"b\":2,\"c\":3,\"a\":4}",
      "{\"x\":{\"k\":1,\"j\":2,\"k\":3}}", "[{\"\":1,\"\":2}]",
      "{\"ab\":1,\"a\":2,\"ab\":3}"};
  size_t i, n = 200000, cap = n * 16 + 16, o = 0;
  char *b = (char *)malloc(cap);
  nqjs *v = NULL;
  clock_t t0;
  for (i = 0; i < sizeof dup / sizeof *dup; i++) {
    NQTEQI(nqjparse(dup[i], strlen(dup[i]), &v, NULL), NQEDEC);
  }
  NQTEQI(nqjparse("{\"a\":1,\"ab\":2,\"b\":3}", 20, &v, NULL), NQOK);
  nqjfree(v);
  v = NULL;
  NQTCHK(b != NULL);
  if (b == NULL) return;
  b[o++] = '{';
  for (i = 0; i < n; i++) {
    o += (size_t)snprintf(b + o, cap - o, "%s\"k%lu\":0", i ? "," : "",
                          (unsigned long)i);
  }
  b[o++] = '}';
  t0 = clock();
  NQTEQI(nqjparse(b, o, &v, NULL), NQOK);
  nqjfree(v);
  v = NULL;
  NQTCHK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
  /* the same object with its last key repeating its first */
  o--;
  o += (size_t)snprintf(b + o, cap - o, ",\"k0\":1}");
  NQTEQI(nqjparse(b, o, &v, NULL), NQEDEC);
  free(b);
}

static void tjson(void) {
  /* RFC 8785 appendix B and ECMAScript Number::toString edge cases */
  tnum("0", "0");
  tnum("-0", "0");
  tnum("1.0", "1");
  tnum("4.50", "4.5");
  tnum("2e-3", "0.002");
  tnum("1e21", "1e+21");
  tnum("1e20", "100000000000000000000");
  tnum("1E-7", "1e-7");
  tnum("0.000001", "0.000001");
  tnum("-1.5e-9", "-1.5e-9");
  tnum("123456789012345678901234", "1.2345678901234569e+23");
  tnum("333333333.33333329", "333333333.3333333");
  tnum("4.9406564584124654e-324", "5e-324");
  tnum("1.7976931348623157e308", "1.7976931348623157e+308");
  tnum("9007199254740992", "9007199254740992");
  tnum("295147905179352830000", "295147905179352830000");
  tnum("0.1", "0.1");
  tnum("100", "100");
  {
    nqcbuf b;
    memset(&b, 0, sizeof b);
    NQTEQI(nqcjnum(&b, "1e400", 5), NQEDEC);
    NQTEQI(nqcjnum(&b, "abc", 3), NQEDEC);
    NQTEQI(nqcjnum(&b, "", 0), NQEDEC);
    nqcbfree(&b);
  }
  /* keys by UTF-16 code units: U+20AC < U+1F600 (D83D) < U+FB33 */
  tcanon("{ \"b\": [1, 2.0, {\"z\": null, \"a\": true}], \"a\": "
         "\"\\u0001\\u00e9\\\"\\/\\n\\u007f\", \"\\ufb33\": 3, "
         "\"\\ud83d\\ude00\": 2, \"\\u20ac\": 1, \"\": false }",
         "{\"\":false,\"a\":\"\\u0001\xc3\xa9\\\"/\\n\x7f\","
         "\"b\":[1,2,{\"a\":true,\"z\":null}],"
         "\"\xe2\x82\xac\":1,\"\xf0\x9f\x98\x80\":2,\"\xef\xac\xb3\":3}",
         NQOK);
  tcanon("[]", "[]", NQOK);
  tcanon("{}", "{}", NQOK);
  tcanon("\"a\\u0000b\"", "\"a\\u0000b\"", NQOK);
  tcanon("[[[[[[[[[[1]]]]]]]]]]", "[[[[[[[[[[1]]]]]]]]]]", NQOK);
  NQTCHK(nqcjcmp("a", 1, "b", 1) < 0);
  NQTCHK(nqcjcmp("ab", 2, "a", 1) > 0);
  NQTCHK(nqcjcmp("\xf0\x9f\x98\x80", 4, "\xef\xac\xb3", 3) < 0);
  NQTCHK(nqcjcmp("\xe2\x82\xac", 3, "\xf0\x9f\x98\x80", 4) < 0);
  tdups();
}

static void tb64(void) {
  static const char *const enc[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==",
                                    "Zm9vYmE=", "Zm9vYmFy"};
  char out[16];
  uint8_t d[16];
  size_t i, n = 0;
  for (i = 0; i < 7; i++) {
    nqb64e((const uint8_t *)"foobar", i, out);
    NQTCHK(strcmp(out, enc[i]) == 0);
    NQTEQI(nqb64d(enc[i], strlen(enc[i]), d, sizeof d, &n), NQOK);
    NQTEQI(n, i);
    NQTEQM(d, "foobar", i);
  }
  NQTEQI(nqb64d("Zh==", 4, d, sizeof d, &n), NQEDEC); /* stray bits */
  NQTEQI(nqb64d("Zm9=", 4, d, sizeof d, &n), NQEDEC);
  NQTEQI(nqb64d("Zm9", 3, d, sizeof d, &n), NQEDEC);
  NQTEQI(nqb64d("Zm 9", 4, d, sizeof d, &n), NQEDEC);
  NQTEQI(nqb64d("Z===", 4, d, sizeof d, &n), NQEDEC);
  NQTEQI(nqb64d("Zg==Zg==", 8, d, sizeof d, &n), NQEDEC);
  NQTEQI(nqb64d("Zm9vYmFy", 8, d, 5, &n), NQEBUF);
}

static void tnorm1(const char *in, int wrc, const char *want) {
  char out[64];
  size_t n = 0;
  int rc = nqcnorm(in, strlen(in), out, sizeof out, &n);
  NQTEQI(rc, wrc);
  if (wrc == NQOK && rc == NQOK) NQTCHK(strcmp(out, want) == 0);
}

static void tpath(void) {
  char out[8];
  size_t n;
  tnorm1("a.txt", NQOK, "a.txt");
  tnorm1("./a.txt", NQOK, "a.txt");
  tnorm1("a//b/./c", NQOK, "a/b/c");
  tnorm1("a/b/", NQOK, "a/b");
  tnorm1("d\xc3\xa9.txt", NQOK, "d\xc3\xa9.txt");
  tnorm1("../x", NQEDEC, NULL);
  tnorm1("a/../b", NQEDEC, NULL);
  tnorm1("a/..", NQEDEC, NULL);
  tnorm1("/etc/passwd", NQEDEC, NULL);
  tnorm1("a\\b", NQEDEC, NULL);
  tnorm1("C:x", NQEDEC, NULL);
  tnorm1("a\nb", NQEDEC, NULL);
  tnorm1("\xc0\xaf", NQEDEC, NULL);       /* overlong '/' */
  tnorm1("\xed\xa0\x80", NQEDEC, NULL);   /* a surrogate */
  tnorm1(".", NQEDEC, NULL);
  tnorm1("", NQEDEC, NULL);
  NQTEQI(nqcnorm("a\0b", 3, out, sizeof out, &n), NQEDEC);
  NQTEQI(nqcnorm("abcdefghij", 10, out, sizeof out, &n), NQELIM);
  NQTEQI(nqcfold("Data/A.TXT", 10, "data/a.txt", 10), 0);
  NQTCHK(nqcfold("a", 1, "b", 1) != 0);
}

static void ttime(void) {
  char t[21];
  NQTEQI(nqctime(0, t), NQOK);
  NQTCHK(strcmp(t, "1970-01-01T00:00:00Z") == 0);
  NQTEQI(nqctime(951782400, t), NQOK);
  NQTCHK(strcmp(t, "2000-02-29T00:00:00Z") == 0);
  NQTEQI(nqctime(1793210645, t), NQOK);
  NQTCHK(strcmp(t, "2026-10-28T18:04:05Z") == 0);
  NQTEQI(nqctime(253402300799LL, t), NQOK);
  NQTCHK(strcmp(t, "9999-12-31T23:59:59Z") == 0);
  NQTEQI(nqctime(-1, t), NQEARG);
  NQTCHK(nqctchk("2026-10-28T18:04:05Z", 20));
  NQTCHK(nqctchk("2026-10-28T18:04:05.123Z", 24));
  NQTCHK(nqctchk("2024-02-29T00:00:00Z", 20));
  NQTCHK(!nqctchk("2023-02-29T00:00:00Z", 20));
  NQTCHK(!nqctchk("2026-13-01T00:00:00Z", 20));
  NQTCHK(!nqctchk("2026-10-28T18:04:05+01:00", 25));
  NQTCHK(!nqctchk("2026-10-28 18:04:05Z", 20));
  NQTCHK(!nqctchk("2026-10-28T18:04:05.Z", 21));
  NQTCHK(!nqctchk("2026-10-28T24:00:00Z", 20));
}

#ifdef NQTFS

/* ---- folders ---- */

static char root[256];
static char made[256][600]; /* everything created, removed in reverse */
static int nmade = 0;

static void track(const char *p) {
  if (nmade < 256 && strlen(p) < sizeof made[0]) {
    memcpy(made[nmade], p, strlen(p) + 1);
    nmade++;
  }
}

static void path(char *o, size_t cap, const char *d, const char *rel) {
  size_t dl = strlen(d), rl = strlen(rel);
  o[0] = 0;
  if (dl + rl + 2 > cap) return;
  memcpy(o, d, dl);
  o[dl] = '/';
  memcpy(o + dl + 1, rel, rl + 1);
}

static void mkd(const char *d, const char *rel) {
  char p[600];
  path(p, sizeof p, d, rel);
  if (mkdir(p, 0755) == 0) track(p);
}

static void wr(const char *d, const char *rel, const void *b, size_t n) {
  char p[600];
  FILE *f;
  struct stat st;
  path(p, sizeof p, d, rel);
  if (lstat(p, &st) != 0) track(p);
  f = fopen(p, "wb");
#if defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
  /* the iOS simulator refuses a name that differs only in case from one
   * it has (EEXIST), where macOS opens that file: the case tests then
   * see one file, as on macOS */
  if (f == NULL && errno == EEXIST) return;
#endif
  NQTCHK(f != NULL);
  if (f == NULL) return;
  if (n) NQTCHK(fwrite(b, 1, n, f) == n);
  fclose(f);
}

/* 1 when the system refused a FIFO or a hard link to this program:
 * Android's SELinux policy does to programs run from adb's shell
 * (EACCES); the checks that need one are then skipped */
static int denied(void) {
#if defined(__ANDROID__)
  return errno == EACCES;
#else
  return 0;
#endif
}

static void ws(const char *d, const char *rel, const char *s) {
  wr(d, rel, s, strlen(s));
}

static void rm(const char *d, const char *rel) {
  char p[600];
  path(p, sizeof p, d, rel);
  remove(p);
}

static int rd(const char *d, const char *rel, char **b, size_t *n) {
  return nqcread(d, rel, (size_t)1 << 24, b, n);
}

static void cleanup(void) {
  while (nmade > 0) {
    nmade--;
    remove(made[nmade]);
  }
}

/* a fresh folder under root with the sample files */
static int ndir = 0;
static void fresh(char *d, size_t cap) {
  static uint8_t bin[300];
  size_t i;
  snprintf(d, cap, "%s/c%d", root, ndir++);
  if (mkdir(d, 0755) == 0) track(d);
  for (i = 0; i < sizeof bin; i++) bin[i] = (uint8_t)i;
  ws(d, "a.txt", "hello\n");
  ws(d, "empty", "");
  mkd(d, "data");
  ws(d, "data/b.csv", "x,y\n1,2\n");
  mkd(d, "data/deep");
  wr(d, "data/deep/c.bin", bin, sizeof bin);
}

/* the first row named chk whose detail holds sub: its ok, or -1 */
static int row(const nqrep *r, const char *chk, const char *sub) {
  size_t i;
  for (i = 0; i < nqrepn(r); i++) {
    const char *c, *d;
    int ok;
    nqrepi(r, i, &c, &ok, &d);
    if (strcmp(c, chk) == 0 && (sub == NULL || strstr(d, sub) != NULL)) {
      return ok;
    }
  }
  return -1;
}

static int nbad(const nqrep *r) {
  size_t i;
  int k = 0;
  for (i = 0; i < nqrepn(r); i++) {
    int ok;
    nqrepi(r, i, NULL, &ok, NULL);
    k += !ok;
  }
  return k;
}

static void dump(const nqrep *r) {
  size_t i;
  for (i = 0; i < nqrepn(r); i++) {
    const char *c, *d;
    int ok;
    nqrepi(r, i, &c, &ok, &d);
    fprintf(stderr, "  %s %s: %s\n", ok ? "ok  " : "FAIL", c, d);
  }
}

typedef struct {
  nqsalg alg;
  nqssz sz;
  uint8_t *pkb;
  uint8_t *skb;
} key;

static uint8_t pkbuf[3][2592], skbuf[3][4896];

static void mkkey(key *k, nqsalg alg, int slot, uint8_t s0) {
  uint8_t seed[96];
  size_t i, sl;
  k->alg = alg;
  NQTEQI(nqssize(alg, &k->sz), NQOK);
  k->pkb = pkbuf[slot];
  k->skb = skbuf[slot];
  sl = alg <= NQMLDSA87 ? 32 : k->sz.pk / 2 * 3;
  for (i = 0; i < sl; i++) seed[i] = (uint8_t)(s0 + i);
  NQTEQI(nqskgd(alg, seed, sl, k->pkb, k->sz.pk, k->skb, k->sz.sk), NQOK);
}

static const uint8_t zero32[32] = {0};
#define GDIRX "vectors/cap/sample"
#define TSEAL 1793210645 /* 2026-10-28T18:04:05Z */

static int lastwhy = 0; /* the limit the last sealk ran into */

static int sealk(const char *d, const key *k, const char *meta) {
  char p[600];
  int rc = nqcseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, meta,
                   NULL, TSEAL, zero32,
                   k->alg <= NQMLDSA87 ? 32 : k->sz.pk / 2, &lastwhy);
  if (rc == NQOK && strcmp(d, GDIRX) != 0) {
    path(p, sizeof p, d, NQCMAN);
    track(p);
    path(p, sizeof p, d, NQCSIG);
    track(p);
  }
  return rc;
}

static int chk(const char *d, const key *k, nqrep **r) {
  return nqchk(d, k == NULL ? NULL : k->pkb, k == NULL ? 0 : k->sz.pk, r);
}

/* writes noqtis.json as given and a fresh seal over it, signed and
 * labelled with context cx */
static void resignc(const char *d, const key *k, const char *man,
                    const char *extra, const char *cx) {
  uint8_t *sig = (uint8_t *)malloc(k->sz.sig);
  uint8_t mh[32];
  char hx[65];
  char *b = (char *)malloc(nqb64n(k->sz.sig) + 1);
  size_t sl = 0;
  nqcbuf s;
  NQTCHK(sig != NULL && b != NULL);
  if (sig == NULL || b == NULL) return;
  ws(d, NQCMAN, man);
  NQTEQI(nqsignd(k->alg, k->skb, k->sz.sk, (const uint8_t *)man,
                 strlen(man), (const uint8_t *)cx, strlen(cx), 0, zero32,
                 k->alg <= NQMLDSA87 ? 32 : k->sz.pk / 2, sig, k->sz.sig,
                 &sl),
         NQOK);
  nqhash(NQS256, (const uint8_t *)man, strlen(man), mh, 32);
  nqhex(mh, 32, hx);
  memset(&s, 0, sizeof s);
  nqcputs(&s, "{\"alg\":\"");
  nqcputs(&s, nqsname(k->alg));
  nqcputs(&s, "\",\"context\":\"");
  nqcputs(&s, cx);
  nqcputs(&s, "\",\"format\":\"" NQCSFMT "\",\"manifest_sha256\":\"");
  nqcputs(&s, hx);
  nqb64e(k->pkb, k->sz.pk, b);
  nqcputs(&s, "\",\"public_key\":\"");
  nqcputs(&s, b);
  nqb64e(sig, sl, b);
  nqcputs(&s, "\",\"signature\":\"");
  nqcputs(&s, b);
  nqcputs(&s, "\"");
  if (extra != NULL) nqcputs(&s, extra);
  nqcputs(&s, "}");
  wr(d, NQCSIG, s.p, s.n);
  nqcbfree(&s);
  free(sig);
  free(b);
}

/* a valid seal: context noqtis-capsule-1 */
static void resign(const char *d, const key *k, const char *man,
                   const char *extra) {
  resignc(d, k, man, extra, NQCCTX);
}

/* review of a4eec67: F1 a signature under another context is no seal;
 * F2 a FIFO under a capsule's names neither blocks a check nor a seal;
 * F3 a seal replaces a hard-linked noqtis.sig, never writes through it */
static void treview(const key *k) {
  static const char *const cx[] = {"", "noqtis-capsule-2", "other"};
  char d[600], p[600], q[600], *man = NULL, *b = NULL;
  size_t n = 0, i;
  nqrep *r = NULL;
  struct stat st;
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(rd(d, NQCMAN, &man, &n), NQOK);
  for (i = 0; man != NULL && i < sizeof cx / sizeof *cx; i++) {
    resignc(d, k, man, NULL, cx[i]);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "seal.context", NULL), 0);
    NQTEQI(row(r, "signature", NULL), -1);
    nqrepfree(r);
    r = NULL;
  }
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  r = NULL;
  free(man);

  /* F2: FIFOs (opened without O_NONBLOCK these blocked forever); under
   * emscripten's NODERAWFS mkfifo makes a plain file, so the checks run
   * only where a real FIFO was made */
  fresh(d, sizeof d);
  path(p, sizeof p, d, NQCSIG);
  if (mkfifo(p, 0600) == 0) {
    track(p);
  } else {
    NQTCHK(denied());
  }
  if (lstat(p, &st) == 0 && S_ISFIFO(st.st_mode)) {
    NQTCHK(chk(d, k, &r) != NQOK);
    nqrepfree(r);
    r = NULL;
    path(q, sizeof q, d, NQCMAN);
    NQTEQI(mkfifo(q, 0600), 0);
    track(q);
    NQTCHK(sealk(d, k, NULL) != NQOK);
    NQTEQI(lstat(p, &st), 0);
    NQTCHK(S_ISFIFO(st.st_mode));
  } else {
    fprintf(stderr, "tcap: no FIFOs here; the FIFO checks are skipped\n");
  }

  /* F3: a hard link to a file outside the folder */
  fresh(d, sizeof d);
  path(q, sizeof q, root, "outside.txt");
  ws(root, "outside.txt", "keep me\n");
  path(p, sizeof p, d, NQCSIG);
  if (link(q, p) == 0) {
    track(p);
  } else {
    NQTCHK(denied());
  }
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(rd(root, "outside.txt", &b, &n), NQOK);
  NQTCHK(b != NULL && n == 8 && memcmp(b, "keep me\n", 8) == 0);
  free(b);
  NQTEQI(stat(p, &st), 0);
  NQTCHK(st.st_nlink == 1);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
}


/* review of a4eec67 (capsule, CLI): a folder on the way that is a link
 * is refused, not followed (the race of a folder swapped mid-seal); a
 * listed file swapped for a huge sparse one fails without being read; a
 * secret key in the folder is not sealed */
static void treview2(const key *k) {
  char d[600], p[600], q[600];
  nqrep *r = NULL;
  uint64_t sz = 0;
  uint8_t s2[32], s3[32];
  int why = 0, fd;
  clock_t t0;
  /* nqcdig never follows a link on the way: sub2 -> sub */
  fresh(d, sizeof d);
  path(p, sizeof p, d, "sub2");
  NQTEQI(symlink("data", p), 0);
  track(p);
  NQTEQI(nqcdig(d, "data/b.csv", &sz, s2, s3), NQOK);
  NQTEQI(nqcdig(d, "sub2/b.csv", &sz, s2, s3), NQEIO);
  NQTEQI(nqcdig(d, "data/../a.txt", &sz, s2, s3), NQEIO);
  /* a listed file swapped for a 1 GiB sparse one: fails at once */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  path(p, sizeof p, d, "a.txt");
  fd = open(p, O_WRONLY);
  NQTCHK(fd >= 0);
  if (fd >= 0) {
    NQTEQI(ftruncate(fd, (off_t)1 << 30), 0);
    close(fd);
  }
  t0 = clock();
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "file", "a.txt: size differs"), 0);
  NQTCHK((double)(clock() - t0) / CLOCKS_PER_SEC < 5.0);
  nqrepfree(r);
  r = NULL;
  /* and one the size of the listed file but swapped after the listing
   * is read at most one byte past it */
  NQTEQI(nqcdigx(d, "a.txt", 6, &sz, s2, s3, NULL), NQOK);
  NQTCHK(sz > 6 && sz <= 6 + 16384);
  /* a secret key file in the folder */
  fresh(d, sizeof d);
  ws(d, "me", "noqtis-key-1 ML-DSA-44 sec\nAAAA\n");
  NQTEQI(nqcseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, NULL, NULL,
                 TSEAL, zero32, k->alg <= NQMLDSA87 ? 32 : k->sz.pk / 2,
                 &why), NQEARG);
  NQTEQI(why, NQCLSEC);
  path(q, sizeof q, d, NQCSIG);
  NQTCHK(access(q, F_OK) != 0);
  /* a public key is fine */
  rm(d, "me");
  ws(d, "me.pub", "noqtis-key-1 ML-DSA-44 pub\nAAAA\n");
  NQTEQI(sealk(d, k, NULL), NQOK);
}

/* seals d with k, then checks that chk(d) passes */
static void roundtrip(const key *k, const char *meta) {
  char d[600];
  nqrep *r = NULL;
  int rc;
  fresh(d, sizeof d);
  ws(d, "d\xc3\xa9j\xc3\xa0 vu.txt", "utf-8 name\n");
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, meta, NULL),
         NQOK);
  {
    char p[600];
    path(p, sizeof p, d, NQCMAN);
    track(p);
    path(p, sizeof p, d, NQCSIG);
    track(p);
  }
  rc = chk(d, k, &r);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) dump(r);
  NQTEQI(row(r, "signature", "valid"), 1);
  NQTEQI(row(r, "key", "trusted"), 1);
  NQTEQI(row(r, "file", "a.txt"), 1);
  NQTEQI(row(r, "file", "data/deep/c.bin"), 1);
  NQTEQI(row(r, "file", "d\xc3\xa9j\xc3\xa0 vu.txt"), 1);
  NQTEQI(row(r, "file", "empty"), 1);
  NQTEQI(nbad(r), 0);
  nqrepfree(r);
  r = NULL;
  rc = chk(d, NULL, &r);
  NQTEQI(rc, NQOK);
  NQTEQI(row(r, "key", "not pinned"), 1);
  nqrepfree(r);
}

/* a sealed folder, then one change, then the rows expected to fail */
static void tamper(const key *k, const key *other) {
  char d[600], *b = NULL;
  size_t n = 0;
  nqrep *r = NULL;

  /* a byte of a file */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  ws(d, "a.txt", "hellO\n");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "file", "a.txt: sha256 differs"), 0);
  NQTEQI(row(r, "signature", NULL), 1);
  NQTEQI(nbad(r), 1);
  nqrepfree(r);
  /* a byte more */
  ws(d, "a.txt", "hello\n\n");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "file", "a.txt: size differs"), 0);
  nqrepfree(r);

  /* a file added */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  ws(d, "data/new.txt", "new");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "extra", "data/new.txt: not in the manifest"), 0);
  NQTEQI(nbad(r), 1);
  nqrepfree(r);

  /* a file removed */
  rm(d, "data/new.txt");
  rm(d, "data/b.csv");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "file", "data/b.csv: missing"), 0);
  NQTEQI(nbad(r), 1);
  nqrepfree(r);
  ws(d, "data/b.csv", "x,y\n1,2\n");

  /* a file renamed */
  {
    char p[600], q[600];
    path(p, sizeof p, d, "a.txt");
    path(q, sizeof q, d, "a2.txt");
    NQTEQI(rename(p, q), 0);
    track(q);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "file", "a.txt: missing"), 0);
    NQTEQI(row(r, "extra", "a2.txt"), 0);
    NQTEQI(nbad(r), 2);
    nqrepfree(r);
    NQTEQI(rename(q, p), 0);
  }

  /* a file swapped for a link to an identical copy outside */
  {
    char p[600], q[600];
    ws(root, "outside.txt", "hello\n");
    path(p, sizeof p, d, "a.txt");
    path(q, sizeof q, root, "outside.txt");
    remove(p);
#if defined(__wasi__)
    /* WASI makes no link to an absolute target: the same file, relative */
    (void)q;
    NQTEQI(symlink("../outside.txt", p), 0);
#else
    NQTEQI(symlink(q, p), 0);
#endif
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "file", "a.txt: a symbolic link"), 0);
    nqrepfree(r);
    remove(p);
    ws(d, "a.txt", "hello\n");
  }

  /* links escaping the folder: to a file and to a folder */
  {
    char p[600];
    path(p, sizeof p, d, "esc");
    NQTEQI(symlink("../outside.txt", p), 0);
    track(p);
    path(p, sizeof p, d, "data/up");
    NQTEQI(symlink("..", p), 0);
    track(p);
    path(p, sizeof p, d, "etc");
#if defined(__wasi__)
    NQTEQI(symlink("../..", p), 0); /* no absolute targets in WASI */
#else
    NQTEQI(symlink("/etc", p), 0);
#endif
    track(p);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "unsafe", "esc: a symbolic link"), 0);
    NQTEQI(row(r, "unsafe", "data/up: a symbolic link"), 0);
    NQTEQI(row(r, "unsafe", "etc: a symbolic link"), 0);
    NQTEQI(row(r, "file", "a.txt"), 1);
    NQTEQI(nbad(r), 3);
    nqrepfree(r);
    /* nqseal refuses a folder with a link, and nqsealwhy names the first */
    NQTEQI(sealk(d, k, NULL), NQEARG);
    {
      char wp[64];
      int w = -1;
      NQTEQI(nqsealwhy(d, &w, wp, sizeof wp), NQOK);
      NQTEQI(w, NQSWLINK);
      NQTCHK(strcmp(wp, "data/up") == 0);
      /* a short buffer gets a cut, terminated path */
      NQTEQI(nqsealwhy(d, &w, wp, 3), NQOK);
      NQTCHK(strcmp(wp, "da") == 0);
      NQTEQI(nqsealwhy(d, &w, NULL, 0), NQOK);
      NQTEQI(w, NQSWLINK);
      NQTEQI(nqsealwhy(d, NULL, wp, sizeof wp), NQEARG);
      NQTEQI(nqsealwhy(NULL, &w, wp, sizeof wp), NQEARG);
      NQTEQI(nqsealwhy(d, &w, NULL, 8), NQEARG);
    }
    remove(made[--nmade]);
    remove(made[--nmade]);
    remove(made[--nmade]);
  }

#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
  /* a special file (emscripten and WASI have no fifos) */
  {
    char p[600];
    path(p, sizeof p, d, "fifo");
    if (mkfifo(p, 0600) != 0) {
      NQTCHK(denied());
    } else {
      track(p);
      NQTEQI(chk(d, k, &r), NQEVRFY);
      NQTEQI(row(r, "unsafe", "fifo: not a regular file"), 0);
      nqrepfree(r);
      NQTEQI(sealk(d, k, NULL), NQEARG);
      {
        char wp[64];
        int w = -1;
        NQTEQI(nqsealwhy(d, &w, wp, sizeof wp), NQOK);
        NQTEQI(w, NQSWODD);
        NQTCHK(strcmp(wp, "fifo") == 0);
      }
      remove(made[--nmade]);
    }
  }
#endif

  /* a name noqtis refuses */
  ws(d, "back\\slash", "x");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "unsafe", "back\\slash: a name noqtis refuses"), 0);
  nqrepfree(r);
  NQTEQI(sealk(d, k, NULL), NQEARG);
  {
    char wp[64];
    int w = -1;
    NQTEQI(nqsealwhy(d, &w, wp, sizeof wp), NQOK);
    NQTEQI(w, NQSWNAME);
    NQTCHK(strcmp(wp, "back\\slash") == 0);
  }
  remove(made[--nmade]);

  /* a field of the manifest (created), and the format */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(rd(d, NQCMAN, &b, &n), NQOK);
  {
    char *p = strstr(b, "2026-10-28");
    NQTCHK(p != NULL);
    if (p != NULL) p[3] = '5';
    wr(d, NQCMAN, b, n);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "manifest.digest", NULL), 0);
    NQTEQI(row(r, "signature", NULL), 0);
    NQTEQI(row(r, "manifest.created", "2025-10-28"), 1);
    nqrepfree(r);
    if (p != NULL) p[3] = '6';
    p = strstr(b, "capsule-1");
    if (p != NULL) p[8] = '2';
    wr(d, NQCMAN, b, n);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "manifest.format", "noqtis-capsule-2"), 0);
    NQTEQI(row(r, "signature", NULL), 0);
    nqrepfree(r);
    /* the same change, signed: only the format row fails */
    resign(d, k, b, NULL);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "manifest.format", NULL), 0);
    NQTEQI(row(r, "signature", NULL), 1);
    NQTEQI(nbad(r), 1);
    nqrepfree(r);
  }
  nqfree(b, n + 1);

  /* a byte of the signature; then the wrong trusted key */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(rd(d, NQCSIG, &b, &n), NQOK);
  {
    char *p = strstr(b, "\"signature\":\"");
    char save;
    NQTCHK(p != NULL);
    if (p != NULL) {
      p += 13 + 40;
      save = *p;
      *p = *p == 'A' ? 'B' : 'A';
      wr(d, NQCSIG, b, n);
      NQTEQI(chk(d, k, &r), NQEVRFY);
      NQTEQI(row(r, "seal.canonical", NULL), 1);
      NQTEQI(row(r, "signature", "does not verify"), 0);
      NQTEQI(nbad(r), 1);
      nqrepfree(r);
      *p = save;
      wr(d, NQCSIG, b, n);
    }
  }
  nqfree(b, n + 1);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  NQTEQI(chk(d, other, &r), NQEVRFY);
  NQTEQI(row(r, "key", "not the trusted key"), 0);
  NQTEQI(row(r, "signature", NULL), 0);
  nqrepfree(r);

  /* the seal: missing, an unknown field, a timestamp that is not one */
  rm(d, NQCSIG);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "seal.read", NULL), 0);
  NQTEQI(row(r, "file", "a.txt"), 1);
  nqrepfree(r);
  NQTEQI(rd(d, NQCMAN, &b, &n), NQOK);
  resign(d, k, b, ",\"zzz\":\"1\"");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "seal.fields", NULL), 0);
  nqrepfree(r);
  resign(d, k, b, ",\"timestamp\":\"MAA=\"");
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "signature", NULL), 1);
  NQTEQI(row(r, "timestamp", "not an RFC 3161 token"), 0);
  nqrepfree(r);
  resign(d, k, b, NULL);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  nqfree(b, n + 1);
}

/* a manifest entry for one of the fresh files */
#define EA "{\"path\":\"%s\",\"sha256\":\"%s\",\"sha3_256\":\"%s\",\"size\":6}"

/* signed manifests that list bad paths: each gets its own failing row */
static void tpaths(const key *k) {
  static const char *const bad[] = {
      "../outside.txt", "/etc/passwd", "data/../a.txt", "data\\\\b.csv",
      "C:a.txt",        "a.txt/..",    "..",            "a\\u0000.txt"};
  static const char *const why[] = {
      "../outside.txt: refused", "/etc/passwd: refused",
      "data/../a.txt: refused",  "data\\b.csv: refused",
      "C:a.txt: refused",        "a.txt/..: refused",
      "..: refused",             "a: refused"};
  char d[600], man[2048], h2[65], h3[65], e1[400], e2[400];
  uint8_t s2[32], s3[32];
  uint64_t sz;
  nqrep *r = NULL;
  size_t i;
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(nqcdig(d, "a.txt", &sz, s2, s3), NQOK);
  nqhex(s2, 32, h2);
  nqhex(s3, 32, h3);
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    snprintf(e1, sizeof e1, EA, bad[i], h2, h3);
    snprintf(man, sizeof man,
             "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s],"
             "\"format\":\"" NQCFMT "\"}", e1);
    resign(d, k, man, NULL);
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "signature", NULL), 1);
    NQTEQI(row(r, "path", why[i]), 0);
    if (row(r, "path", why[i]) != 0) dump(r);
    /* the escaping path is never opened: outside.txt matches a.txt */
    NQTEQI(row(r, "file", "outside"), -1);
    nqrepfree(r);
  }
  /* two names for one file, and a path not in normal form */
  snprintf(e1, sizeof e1, EA, "./a.txt", h2, h3);
  snprintf(e2, sizeof e2, EA, "a.txt", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s,%s],"
           "\"format\":\"" NQCFMT "\"}", e1, e2);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "path", "./a.txt: not in normal form"), 0);
  NQTEQI(row(r, "path", "a.txt: listed twice"), 0);
  nqrepfree(r);
  snprintf(e1, sizeof e1, EA, "data//b.csv", h2, h3);
  snprintf(e2, sizeof e2, EA, "data/b.csv", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s,%s],"
           "\"format\":\"" NQCFMT "\"}", e1, e2);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "path", "data/b.csv: listed twice"), 0);
  NQTEQI(row(r, "manifest.order", NULL), 1);
  nqrepfree(r);
  /* the same path twice, and out of order */
  snprintf(e1, sizeof e1, EA, "a.txt", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s,%s],"
           "\"format\":\"" NQCFMT "\"}", e1, e1);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "path", "a.txt: listed twice"), 0);
  NQTEQI(row(r, "manifest.order", NULL), 0);
  nqrepfree(r);
  /* paths equal but for case (where the file system keeps both) */
  ws(d, "A.txt", "hello\n");
  snprintf(e1, sizeof e1, EA, "A.txt", h2, h3);
  snprintf(e2, sizeof e2, EA, "a.txt", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s,%s],"
           "\"format\":\"" NQCFMT "\"}", e1, e2);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  if (row(r, "file", "A.txt") == 1) {
    NQTEQI(row(r, "path", "A.txt and a.txt"), 0);
  }
  nqrepfree(r);
  rm(d, "A.txt");
  /* not canonical (whitespace), unknown field, bad digest text */
  snprintf(e1, sizeof e1, EA, "a.txt", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\": \"2026-10-28T18:04:05Z\",\"files\":[%s],"
           "\"format\":\"" NQCFMT "\"}", e1);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.canonical", NULL), 0);
  NQTEQI(row(r, "signature", NULL), 1);
  nqrepfree(r);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s],"
           "\"format\":\"" NQCFMT "\",\"x\":1}", e1);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.fields", NULL), 0);
  nqrepfree(r);
  h2[0] = 'A';
  snprintf(e1, sizeof e1, EA, "a.txt", h2, h3);
  snprintf(man, sizeof man,
           "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s],"
           "\"format\":\"" NQCFMT "\"}", e1);
  resign(d, k, man, NULL);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.fields", "lower-case hex"), 0);
  nqrepfree(r);
}

/* nqseal's own refusals */
static void tsealargs(const key *k, const key *other) {
  char d[600];
  fresh(d, sizeof d);
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk, other->pkb, other->sz.pk,
                NULL, NULL),
         NQEARG); /* not one key pair */
  {
    /* nothing in the folder stops it: nqsealwhy says 0, so the keys */
    char wp[8] = "x";
    int w = -1;
    NQTEQI(nqsealwhy(d, &w, wp, sizeof wp), NQOK);
    NQTEQI(w, 0);
    NQTEQI(wp[0], 0);
  }
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, NULL,
                "http://tsa.example"),
         NQENOSUP);
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk - 1, k->pkb, k->sz.pk, NULL,
                NULL),
         NQEARG);
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, "[1]",
                NULL),
         NQEDEC);
  NQTEQI(nqseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, "{\"a\":",
                NULL),
         NQEDEC);
  NQTEQI(nqseal(NULL, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, NULL,
                NULL),
         NQEARG);
  NQTEQI(nqseal(d, (nqsalg)99, k->skb, k->sz.sk, k->pkb, k->sz.pk, NULL,
                NULL),
         NQEARG);
  {
    char p[600];
    struct stat st;
    path(p, sizeof p, d, NQCMAN);
    NQTCHK(lstat(p, &st) != 0); /* nothing written */
  }
  /* case collision (only where the file system keeps both) */
  ws(d, "A.TXT", "x");
  {
    nqclist l;
    if (nqcwalk(d, &l) == NQOK) {
      if (l.n == 5) {
        char wp[64];
        int w = -1;
        NQTEQI(sealk(d, k, NULL), NQEARG);
        NQTEQI(nqsealwhy(d, &w, wp, sizeof wp), NQOK);
        NQTEQI(w, NQSWCASE);
      }
      nqclfree(&l);
    }
  }
  rm(d, "A.TXT");
  {
    nqrep *r = NULL;
    NQTEQI(nqchk(NULL, NULL, 0, &r), NQEARG);
    NQTEQI(nqchk(d, NULL, 5, &r), NQEARG);
    NQTEQI(nqchk(d, NULL, 0, NULL), NQEARG);
    NQTCHK(nqrepn(NULL) == 0);
    NQTEQI(nqrepi(NULL, 0, NULL, NULL, NULL), NQEARG);
    nqrepfree(NULL);
    /* a folder that is not there */
    NQTEQI(nqchk("/nonexistent/noqtis", NULL, 0, &r), NQEVRFY);
    NQTEQI(row(r, "seal.read", NULL), 0);
    NQTEQI(row(r, "manifest.read", NULL), 0);
    NQTEQI(nqrepi(r, nqrepn(r), NULL, NULL, NULL), NQEARG);
    nqrepfree(r);
  }
}

/* ---- allocation failures: every one fails cleanly ---- */

static long alfail = -1, alcount = 0, allive = 0;

static void *tmal(size_t n, void *u) {
  (void)u;
  if (alfail >= 0 && alcount++ == alfail) return NULL;
  allive++;
  return malloc(n);
}

static void tfree(void *p, size_t n, void *u) {
  (void)u;
  (void)n;
  allive--;
  free(p);
}

/* NQTSTEP=k fails every k-th allocation only (for valgrind runs) */
static void talloc(const key *k) {
  char d[600];
  const char *st = getenv("NQTSTEP");
  long i, step = st != NULL ? atol(st) : 1;
  int rc = NQEMEM, n = 0;
  if (step < 1) step = 1;
  fresh(d, sizeof d);
  NQTEQI(nqsetal(tmal, tfree, NULL), NQOK);
  for (i = 0; i < 2000 && rc == NQEMEM; i += step) {
    alfail = i;
    alcount = 0;
    allive = 0;
    rc = sealk(d, k, "{\"k\":[1,{\"z\":2,\"a\":3}]}");
    NQTEQI(allive, 0);
    n++;
  }
  NQTEQI(rc, NQOK);
  rc = NQEMEM;
  for (i = 0; i < 4000 && rc == NQEMEM; i += step) {
    nqrep *r = NULL;
    alfail = i;
    alcount = 0;
    allive = 0;
    rc = chk(d, k, &r);
    if (rc == NQEMEM) {
      NQTCHK(r == NULL);
      NQTEQI(allive, 0);
    }
    nqrepfree(r);
    NQTEQI(allive, 0);
  }
  NQTEQI(rc, NQOK);
  alfail = -1;
  NQTEQI(nqsetal(NULL, NULL, NULL), NQOK);
  {
    char p[600];
    path(p, sizeof p, d, NQCMAN);
    track(p);
    path(p, sizeof p, d, NQCSIG);
    track(p);
  }
  (void)n;
}

/* ---- the golden capsule ---- */

#define GDIR "vectors/cap/sample"
#define GMETA "{\"project\":\"golden\",\"n\":1.50,\"tags\":[\"a\",\"b\"]}"

static void tgolden(const key *k, int gen) {
  char d[600], *g = NULL, *m = NULL;
  size_t gn = 0, mn = 0;
  nqrep *r = NULL;
  int rc;
  if (gen) {
    NQTEQI(sealk(GDIR, k, GMETA), NQOK);
    printf("tcap: wrote " GDIR "/" NQCMAN " and " NQCSIG "\n");
  }
  /* the committed capsule checks */
  rc = chk(GDIR, k, &r);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) dump(r);
  NQTEQI(row(r, "file", "data/deep/c.bin"), 1);
  nqrepfree(r);
  /* and sealing the same files again gives the same bytes */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, GMETA), NQOK);
  {
    char p[600];
    path(p, sizeof p, d, NQCMAN);
    track(p);
    path(p, sizeof p, d, NQCSIG);
    track(p);
  }
  NQTEQI(rd(GDIR, NQCMAN, &g, &gn), NQOK);
  NQTEQI(rd(d, NQCMAN, &m, &mn), NQOK);
  NQTCHK(g != NULL && m != NULL && gn == mn && memcmp(g, m, gn) == 0);
  nqfree(g, gn + 1);
  nqfree(m, mn + 1);
  NQTEQI(rd(GDIR, NQCSIG, &g, &gn), NQOK);
  NQTEQI(rd(d, NQCSIG, &m, &mn), NQOK);
  NQTCHK(g != NULL && m != NULL && gn == mn && memcmp(g, m, gn) == 0);
  nqfree(g, gn + 1);
  nqfree(m, mn + 1);
}


/* ---- timestamps (vectors/cap/tsa, made by tsa.sh) ---- */

/* writes d's seal again with "timestamp" (base64 of tok) added */
static void stamp(const char *d, const uint8_t *tok, size_t tn) {
  char *s = NULL, *b = (char *)malloc(nqb64n(tn) + 1);
  size_t n = 0;
  nqcbuf o;
  NQTCHK(b != NULL);
  if (b == NULL) return;
  NQTEQI(rd(d, NQCSIG, &s, &n), NQOK);
  if (s == NULL || n < 2) {
    free(b);
    return;
  }
  nqb64e(tok, tn, b);
  memset(&o, 0, sizeof o);
  nqcput(&o, s, n - 1);
  nqcputs(&o, ",\"timestamp\":\"");
  nqcputs(&o, b);
  nqcputs(&o, "\"}");
  wr(d, NQCSIG, o.p, o.n);
  nqcbfree(&o);
  nqfree(s, n + 1);
  free(b);
}

static int chka(const char *d, const key *k, const char *anc, size_t an,
                nqrep **r) {
  const uint8_t *p[1];
  size_t l[1];
  p[0] = (const uint8_t *)anc;
  l[0] = an;
  return nqchkt(d, k->pkb, k->sz.pk, p, l, 1, r);
}

/* nqtsreq and nqtsput: the request over the seal's signature, and the
 * reply checked before it is stored */
static void tput(const key *k, const uint8_t *tok, size_t tn,
                 const char *ra, size_t rn, const char *oth, size_t on) {
  static const uint8_t nonce[3] = {0x00, 0x81, 0x02};
  char d[600], *s0 = NULL, *s1 = NULL;
  uint8_t q[128], h[32], *bad;
  size_t qn = 0, n0 = 0, n1 = 0, i;
  const uint8_t *p[1];
  size_t l[1];
  const char *why = NULL;
  int64_t gt = 0;
  nqrep *r = NULL;
  int rc;
  p[0] = (const uint8_t *)ra;
  l[0] = rn;
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, GMETA), NQOK);
  /* the request: version 1, SHA-256 of the signature, nonce, certReq */
  NQTEQI(nqtsreq(d, nonce, sizeof nonce, q, sizeof q, &qn), NQOK);
  NQTCHK(qn > 60 && q[0] == 0x30 && q[1] == qn - 2);
  NQTCHK(q[2] == 0x02 && q[3] == 0x01 && q[4] == 0x01);
  NQTCHK(qn >= 3 && q[qn - 3] == 0x01 && q[qn - 1] == 0xff);
  /* the nonce lost its leading zero and gained the sign byte */
  NQTCHK(memcmp(q + qn - 3 - 5, "\x02\x03\x00\x81\x02", 5) == 0);
  NQTEQI(rd(d, NQCSIG, &s0, &n0), NQOK);
  if (s0 != NULL) {
    const char *b = strstr(s0, "\"signature\":\"");
    uint8_t *sg = (uint8_t *)malloc(n0);
    size_t sn = 0;
    if (b != NULL && sg != NULL) {
      b += 13;
      NQTEQI(nqb64d(b, strcspn(b, "\""), sg, n0, &sn), NQOK);
      NQTEQI(nqhash(NQS256, sg, sn, h, 32), NQOK);
      NQTCHK(memcmp(q + 4 + 1 + 2 + 15 + 2, h, 32) == 0);
    } else {
      NQTCHK(0);
    }
    free(sg);
  }
  NQTEQI(nqtsreq(d, NULL, 0, q, sizeof q, &qn), NQOK);
  NQTEQI(qn, 2 + 3 + 2 + 15 + 2 + 32 + 3);
  NQTEQI(nqtsreq(d, NULL, 0, q, 10, &qn), NQEBUF);
  NQTEQI(nqtsreq(d, nonce, 33, q, sizeof q, &qn), NQEARG);
  NQTEQI(nqtsreq(NULL, NULL, 0, q, sizeof q, &qn), NQEARG);
  /* the golden token has no nonce: asking for one refuses it */
  NQTEQI(nqtsput(d, tok, tn, nonce, sizeof nonce, NULL, NULL, 0, &gt, &why),
         NQEVRFY);
  NQTCHK(why != NULL && strstr(why, "nonce") != NULL);
  NQTEQI(rd(d, NQCSIG, &s1, &n1), NQOK);
  NQTCHK(s0 != NULL && s1 != NULL && n0 == n1 && memcmp(s0, s1, n0) == 0);
  nqfree(s1, n1 + 1);
  s1 = NULL;
  /* the wrong anchor: refused, and nothing written */
  {
    const uint8_t *po[1];
    size_t lo[1];
    po[0] = (const uint8_t *)oth;
    lo[0] = on;
    NQTEQI(nqtsput(d, tok, tn, NULL, 0, po, lo, 1, &gt, &why), NQEVRFY);
    NQTCHK(why != NULL && strstr(why, "anchor") != NULL);
    po[0] = (const uint8_t *)"\x30\x03\x02\x01\x01";
    lo[0] = 5;
    NQTEQI(nqtsput(d, tok, tn, NULL, 0, po, lo, 1, &gt, &why), NQEARG);
    NQTCHK(why != NULL && strstr(why, "not a DER X.509") != NULL);
  }
  /* without anchors: the token's own signature is checked, and stored */
  NQTEQI(nqtsput(d, tok, tn, NULL, 0, NULL, NULL, 0, &gt, &why), NQOK);
  NQTCHK(why == NULL && gt > 1700000000);
  rc = chka(d, k, ra, rn, &r);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) dump(r);
  NQTEQI(row(r, "seal.canonical", NULL), 1);
  nqrepfree(r);
  NQTEQI(rd(d, NQCSIG, &s1, &n1), NQOK);
  /* again, with the anchor: replaces the timestamp, same bytes */
  NQTEQI(nqtsput(d, tok, tn, NULL, 0, p, l, 1, NULL, NULL), NQOK);
  {
    char *s2 = NULL;
    size_t n2 = 0;
    NQTEQI(rd(d, NQCSIG, &s2, &n2), NQOK);
    NQTCHK(s1 != NULL && s2 != NULL && n1 == n2 &&
           memcmp(s1, s2, n1) == 0);
    nqfree(s2, n2 + 1);
  }
  /* every 37th byte of the token flipped: never stored */
  bad = (uint8_t *)malloc(tn);
  NQTCHK(bad != NULL);
  for (i = 0; bad != NULL && i < tn; i += 37) {
    memcpy(bad, tok, tn);
    bad[i] ^= 0x01;
    rc = nqtsput(d, bad, tn, NULL, 0, p, l, 1, NULL, &why);
    NQTCHK(rc != NQOK);
    NQTCHK(why != NULL);
  }
  free(bad);
  /* a TimeStampResp that refused: status 2, no token */
  NQTEQI(nqtsput(d, (const uint8_t *)"\x30\x05\x30\x03\x02\x01\x02", 7,
                 NULL, 0, NULL, NULL, 0, NULL, &why),
         NQEVRFY);
  NQTCHK(why != NULL && strstr(why, "did not grant") != NULL);
  /* another seal's signature */
  ws(d, "a.txt", "other\n");
  NQTEQI(sealk(d, k, GMETA), NQOK);
  NQTEQI(nqtsput(d, tok, tn, NULL, 0, NULL, NULL, 0, NULL, &why), NQEVRFY);
  NQTCHK(why != NULL && strstr(why, "imprint") != NULL);
  /* a seal that is not canonical */
  ws(d, NQCSIG, "{ }");
  NQTEQI(nqtsput(d, tok, tn, NULL, 0, NULL, NULL, 0, NULL, &why), NQEDEC);
  NQTEQI(nqtsreq(d, NULL, 0, q, sizeof q, &qn), NQEDEC);
  NQTEQI(nqtsput(NULL, tok, tn, NULL, 0, NULL, NULL, 0, NULL, NULL),
         NQEARG);
  NQTEQI(nqtsput(d, tok, tn, NULL, 0, p, l, 33, NULL, NULL), NQELIM);
  nqfree(s0, n0 + 1);
  nqfree(s1, n1 + 1);
}

static void tstamp(const key *k) {
  char d[600], *tok = NULL, *ra = NULL, *oth = NULL;
  size_t tn = 0, rn = 0, on = 0, i;
  nqrep *r = NULL;
  int rc, bad = 0, tried = 0;
  NQTEQI(rd("vectors/cap/tsa", "sample.tok", &tok, &tn), NQOK);
  NQTEQI(rd("vectors/cap/tsa", "root.der", &ra, &rn), NQOK);
  NQTEQI(rd("vectors/cap/tsa", "other.der", &oth, &on), NQOK);
  if (tok == NULL || ra == NULL || oth == NULL) return;
  /* the golden files sealed again: the same signature, which the token
   * stamps */
  fresh(d, sizeof d);
  NQTEQI(sealk(d, k, GMETA), NQOK);
  /* anchors given, no timestamp */
  NQTEQI(chka(d, k, ra, rn, &r), NQEVRFY);
  NQTEQI(row(r, "timestamp", "no timestamp in the seal"), 0);
  NQTEQI(nbad(r), 1);
  nqrepfree(r);
  stamp(d, (const uint8_t *)tok, tn);
  rc = chka(d, k, ra, rn, &r);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) dump(r);
  NQTEQI(row(r, "timestamp", "verifies under a TSA anchor; genTime 20"), 1);
  NQTEQI(row(r, "seal.canonical", NULL), 1);
  nqrepfree(r);
  /* no anchors: fail closed */
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "timestamp", "not checked: no TSA trust anchors"), 0);
  NQTEQI(nbad(r), 1);
  nqrepfree(r);
  /* the wrong anchor (same subject, another key); not a certificate */
  NQTEQI(chka(d, k, oth, on, &r), NQEVRFY);
  NQTEQI(row(r, "timestamp", "does not verify under the TSA anchors"), 0);
  nqrepfree(r);
  NQTEQI(chka(d, k, "\x30\x03\x02\x01\x01", 5, &r), NQEVRFY);
  NQTEQI(row(r, "timestamp", "not a certificate"), 0);
  nqrepfree(r);
  /* both anchors: one is enough */
  {
    const uint8_t *p[2];
    size_t l[2];
    p[0] = (const uint8_t *)oth;
    l[0] = on;
    p[1] = (const uint8_t *)ra;
    l[1] = rn;
    NQTEQI(nqchkt(d, k->pkb, k->sz.pk, p, l, 2, &r), NQOK);
    nqrepfree(r);
    NQTEQI(nqchkt(d, k->pkb, k->sz.pk, NULL, l, 2, &r), NQEARG);
    NQTEQI(nqchkt(d, k->pkb, k->sz.pk, p, l, 33, &r), NQELIM);
    l[0] = 0;
    NQTEQI(nqchkt(d, k->pkb, k->sz.pk, p, l, 2, &r), NQEARG);
  }
  /* every 23rd byte of the token flipped: never accepted */
  for (i = 0; i < tn; i += 23) {
    tok[i] = (char)(tok[i] ^ 0x01);
    NQTEQI(sealk(d, k, GMETA), NQOK); /* the seal again, unstamped */
    stamp(d, (const uint8_t *)tok, tn);
    rc = chka(d, k, ra, rn, &r);
    tried++;
    if (rc == NQOK || row(r, "timestamp", NULL) != 0) bad++;
    NQTEQI(nbad(r), 1);
    nqrepfree(r);
    tok[i] = (char)(tok[i] ^ 0x01);
  }
  NQTEQI(bad, 0);
  NQTCHK(tried > 10);
  /* the token over another capsule's signature */
  fresh(d, sizeof d);
  ws(d, "a.txt", "other\n");
  NQTEQI(sealk(d, k, GMETA), NQOK);
  stamp(d, (const uint8_t *)tok, tn);
  NQTEQI(chka(d, k, ra, rn, &r), NQEVRFY);
  NQTEQI(row(r, "timestamp", "imprint is not the signature's"), 0);
  nqrepfree(r);
  tput(k, (const uint8_t *)tok, tn, ra, rn, oth, on);
  nqfree(tok, tn + 1);
  nqfree(ra, rn + 1);
  nqfree(oth, on + 1);
}

/* ---- limits: each one just under and just over, with lowered limits ---- */

static void deflim(void) {
  nqclim.man = NQCMANMAX;
  nqclim.files = NQCFILES;
  nqclim.path = NQCPATHMAX;
  nqclim.depth = NQCDEPTH;
}

static void tlims(const key *k) {
  char d[600], *b = NULL, *meta;
  size_t n = 0, ml = ((size_t)1 << 20) + 16, i;
  nqrep *r = NULL;
  fresh(d, sizeof d); /* 4 files, longest path data/deep/c.bin (15) */
  /* files */
  nqclim.files = 4;
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  nqclim.files = 3;
  NQTEQI(sealk(d, k, NULL), NQELIM);
  NQTEQI(lastwhy, NQCLFILES);
  NQTCHK(strcmp(nqclwhy(lastwhy), "too many files") == 0);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "folder", "too many files"), 0);
  nqrepfree(r);
  deflim();
  /* path */
  nqclim.path = 15;
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  nqclim.path = 14;
  NQTEQI(sealk(d, k, NULL), NQELIM);
  NQTEQI(lastwhy, NQCLPATH);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "folder", "path too long"), 0);
  nqrepfree(r);
  deflim();
  /* depth: data/deep is two levels */
  nqclim.depth = 2;
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  nqclim.depth = 1;
  NQTEQI(sealk(d, k, NULL), NQELIM);
  NQTEQI(lastwhy, NQCLDEPTH);
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "folder", "folder too deep"), 0);
  nqrepfree(r);
  deflim();
  /* the manifest: refused by its size before it is read */
  NQTEQI(sealk(d, k, NULL), NQOK);
  NQTEQI(rd(d, NQCMAN, &b, &n), NQOK);
  nqfree(b, n + 1);
  nqclim.man = n;
  NQTEQI(chk(d, k, &r), NQOK);
  nqrepfree(r);
  NQTEQI(sealk(d, k, NULL), NQOK);
  nqclim.man = n - 1;
  NQTEQI(chk(d, k, &r), NQEVRFY);
  NQTEQI(row(r, "manifest.read", "manifest too large"), 0);
  nqrepfree(r);
  NQTEQI(sealk(d, k, NULL), NQELIM);
  NQTEQI(lastwhy, NQCLMAN);
  deflim();
  /* a listed path over the limit, and more entries than the limit, in a
   * folder that is itself within both */
  {
    char e[3][400], man[2048], h2[65], h3[65];
    uint8_t s2[32], s3[32];
    uint64_t sz;
    NQTEQI(sealk(d, k, NULL), NQOK);
    NQTEQI(nqcdig(d, "a.txt", &sz, s2, s3), NQOK);
    nqhex(s2, 32, h2);
    nqhex(s3, 32, h3);
    snprintf(e[0], sizeof e[0], EA, "a.txt", h2, h3);
    snprintf(e[1], sizeof e[1], EA, "data/b.csv", h2, h3);
    snprintf(e[2], sizeof e[2], EA, "data/deep/c.bin", h2, h3);
    snprintf(man, sizeof man,
             "{\"created\":\"2026-10-28T18:04:05Z\",\"files\":[%s,%s,%s],"
             "\"format\":\"" NQCFMT "\"}", e[0], e[1], e[2]);
    resign(d, k, man, NULL);
    rm(d, "data/deep/c.bin");
    rm(d, "empty");
    nqclim.path = 14;
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "folder", "listed"), 1);
    NQTEQI(row(r, "path", "path too long"), 0);
    nqrepfree(r);
    deflim();
    nqclim.files = 2;
    NQTEQI(chk(d, k, &r), NQEVRFY);
    NQTEQI(row(r, "folder", "listed"), 1);
    NQTEQI(row(r, "manifest.fields", "too many files"), 0);
    nqrepfree(r);
    deflim();
  }
  /* meta: 1 MiB */
  meta = (char *)malloc(ml + 1);
  NQTCHK(meta != NULL);
  if (meta != NULL) {
    memcpy(meta, "{\"a\":\"", 6);
    for (i = 6; i < ml - 2; i++) meta[i] = 'x';
    meta[ml - 2] = '"';
    meta[ml - 1] = '}';
    meta[ml] = 0;
    NQTEQI(sealk(d, k, meta), NQELIM);
    NQTEQI(lastwhy, NQCLMETA);
    free(meta);
  }
}

/* ---- NQCAPBIG=1: a 1,000,000-file capsule (time and peak memory) ---- */

#if defined(__linux__)
static long hwm(void) {
  FILE *f = fopen("/proc/self/status", "r");
  char ln[256];
  long kb = -1;
  if (f == NULL) return -1;
  while (fgets(ln, sizeof ln, f) != NULL) {
    if (strncmp(ln, "VmHWM:", 6) == 0) kb = atol(ln + 6);
  }
  fclose(f);
  return kb;
}

static void hwmreset(void) {
  FILE *f = fopen("/proc/self/clear_refs", "w");
  if (f != NULL) {
    fputs("5", f);
    fclose(f);
  }
}
#else
static long hwm(void) { return -1; }
static void hwmreset(void) {}
#endif

static void tbig(const key *k) {
  char d[600], p[600], nm[64];
  long i, j, nd = 1000, nf = 1000;
  nqrep *r = NULL;
  time_t t0;
  int rc;
  snprintf(d, sizeof d, "%s/big", root);
  NQTEQI(mkdir(d, 0755), 0);
  t0 = time(NULL);
  for (i = 0; i < nd; i++) {
    snprintf(nm, sizeof nm, "d%03ld", i);
    path(p, sizeof p, d, nm);
    mkdir(p, 0755);
    for (j = 0; j < nf; j++) {
      char f[700];
      FILE *o;
      snprintf(f, sizeof f, "%s/f%03ld", p, j);
      o = fopen(f, "wb");
      if (o == NULL) break;
      fprintf(o, "%ld\n", i * nf + j);
      fclose(o);
    }
  }
  printf("tcap big: made %ld files in %ld s\n", nd * nf,
         (long)(time(NULL) - t0));
  hwmreset();
  t0 = time(NULL);
  rc = nqseal(d, k->alg, k->skb, k->sz.sk, k->pkb, k->sz.pk, NULL, NULL);
  NQTEQI(rc, NQOK);
  printf("tcap big: nqseal %ld s, peak RSS %ld KiB\n",
         (long)(time(NULL) - t0), hwm());
  hwmreset();
  t0 = time(NULL);
  rc = chk(d, k, &r);
  NQTEQI(rc, NQOK);
  printf("tcap big: nqchk %ld s, peak RSS %ld KiB, %lu rows\n",
         (long)(time(NULL) - t0), hwm(), (unsigned long)nqrepn(r));
  nqrepfree(r);
  path(p, sizeof p, d, NQCMAN);
  {
    struct stat st;
    if (stat(p, &st) == 0) {
      printf("tcap big: noqtis.json %ld bytes\n", (long)st.st_size);
    }
  }
  remove(p);
  path(p, sizeof p, d, NQCSIG);
  remove(p);
  for (i = 0; i < nd; i++) {
    snprintf(nm, sizeof nm, "d%03ld", i);
    path(p, sizeof p, d, nm);
    for (j = 0; j < nf; j++) {
      char f[700];
      snprintf(f, sizeof f, "%s/f%03ld", p, j);
      remove(f);
    }
    remove(p);
  }
  remove(d);
}

static void tfs(int gen) {
  key m44, m65, slh, other;
  const char *t = getenv("TMPDIR");
  if (t == NULL || t[0] == 0 || strlen(t) > 200) t = "/tmp";
#if defined(__wasi__)
  {
    /* WASI has no process ids */
    uint8_t b[4] = {0, 0, 0, 0};
    (void)nqrand(b, sizeof b);
    snprintf(root, sizeof root, "%s/tcap%02x%02x%02x%02x", t, b[0], b[1],
             b[2], b[3]);
  }
#else
  snprintf(root, sizeof root, "%s/tcap%ld", t, (long)getpid());
#endif
  if (mkdir(root, 0700) != 0) {
    NQTCHK(0);
    return;
  }
  track(root);
  {
    char p[600];
    path(p, sizeof p, root, "outside.txt");
    track(p);
  }
  mkkey(&m44, NQMLDSA44, 0, 0);
  mkkey(&m65, NQMLDSA65, 1, 0x40);
  mkkey(&slh, NQSLHK128F, 2, 0x80);
  other = m44;
  {
    static uint8_t opk[1312], osk[2560];
    uint8_t seed[32];
    memset(seed, 7, sizeof seed);
    other.pkb = opk;
    other.skb = osk;
    NQTEQI(nqskgd(NQMLDSA44, seed, 32, opk, sizeof opk, osk, sizeof osk),
           NQOK);
  }
  tgolden(&m44, gen);
  tstamp(&m44);
  roundtrip(&m44, NULL);
  roundtrip(&m65, GMETA);
  roundtrip(&slh, "{}");
  tamper(&m44, &other);
  tpaths(&m44);
  tsealargs(&m44, &other);
  treview(&m44);
  treview2(&m44);
  tlims(&m44);
  if (getenv("NQCAPBIG") != NULL) tbig(&m44);
  talloc(&m44);
  cleanup();
}

#endif /* NQTFS */

int main(int argc, char **argv) {
  tjson();
  tb64();
  tpath();
  ttime();
#ifdef NQTFS
  tfs(argc > 1 && strcmp(argv[1], "gen") == 0);
#else
  (void)argc;
  (void)argv;
#endif
  return nqtdone("tcap");
}
