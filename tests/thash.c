/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Hash tests: every NIST ACVP SHA-2, SHA-3, SHAKE and HMAC vector set in
 * vectors/acvp, known answers, incremental use, and the API's errors.
 * The large-message tests (LDT, gigabytes each) run only with NQLDT=1. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "hash/h.h"
#include "nqt.h"

/* ---- vector sets ---- */

enum { KS2 = 1, KS3, KSHK, KHM };

typedef struct {
  const char *dir;
  nqhalg alg;
  int kind;
} vset;

static const vset sets[] = {
    {"SHA2-224-1.0", NQS224, KS2},
    {"SHA2-256-1.0", NQS256, KS2},
    {"SHA2-384-1.0", NQS384, KS2},
    {"SHA2-512-1.0", NQS512, KS2},
    {"SHA2-512-224-1.0", NQS512T224, KS2},
    {"SHA2-512-256-1.0", NQS512T256, KS2},
    {"SHA3-224-2.0", NQS3224, KS3},
    {"SHA3-256-2.0", NQS3256, KS3},
    {"SHA3-384-2.0", NQS3384, KS3},
    {"SHA3-512-2.0", NQS3512, KS3},
    {"SHAKE-128-FIPS202", NQSHK128, KSHK},
    {"SHAKE-256-FIPS202", NQSHK256, KSHK},
    {"HMAC-SHA2-224-2.0", NQS224, KHM},
    {"HMAC-SHA2-256-2.0", NQS256, KHM},
    {"HMAC-SHA2-384-2.0", NQS384, KHM},
    {"HMAC-SHA2-512-2.0", NQS512, KHM},
    {"HMAC-SHA2-512-224-2.0", NQS512T224, KHM},
    {"HMAC-SHA2-512-256-2.0", NQS512T256, KHM},
    {"HMAC-SHA3-224-2.0", NQS3224, KHM},
    {"HMAC-SHA3-256-2.0", NQS3256, KHM},
    {"HMAC-SHA3-384-2.0", NQS3384, KHM},
    {"HMAC-SHA3-512-2.0", NQS3512, KHM},
};

/* test types, for the counts */
enum { TAFT, TMCT, TLDT, TVOT, TN };
static const char *tname[TN] = {"AFT", "MCT", "LDT", "VOT"};

typedef struct {
  long run[TN], pass[TN], skip[TN];
} cnt;

static int ldt = 0;   /* NQLDT=1 */
static int nmiss = 0; /* failures printed so far */

/* ---- JSON helpers ---- */

static nqjs *ldjs(const char *dir, const char *name) {
  char path[256];
  char *buf = NULL;
  size_t len = 0;
  nqjs *v = NULL;
  int rc;
  snprintf(path, sizeof path, "vectors/acvp/%s/%s", dir, name);
  rc = nqreadf(path, (size_t)1 << 28, &buf, &len);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot read (%s)\n", path, nqerr(rc));
    return NULL;
  }
  rc = nqjparse(buf, len, &v, NULL);
  nqfree(buf, len + 1);
  if (rc != NQOK) {
    fprintf(stderr, "%s: cannot parse (%s)\n", path, nqerr(rc));
    return NULL;
  }
  return v;
}

/* the ACVP-Server files are one object; a live session wraps it as
 * [ {"acvVersion":...}, {...} ] */
static const nqjs *groups(const nqjs *v) {
  return nqjget(v->type == NQJARR ? nqjat(v, 1) : v, "testGroups");
}

/* An unsigned integer given as a JSON number or as a decimal string. */
static int getu(const nqjs *v, uint64_t *out) {
  int64_t x;
  const char *s;
  uint64_t r = 0;
  if (v == NULL) return 0;
  if (v->type == NQJNUM) {
    if (nqjint(v, &x) != NQOK || x < 0) return 0;
    *out = (uint64_t)x;
    return 1;
  }
  s = nqjstr(v);
  if (s == NULL || *s == 0) return 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9' || r > UINT64_MAX / 10 - 1) return 0;
    r = r * 10 + (uint64_t)(*s - '0');
  }
  *out = r;
  return 1;
}

static int getf(const nqjs *o, const char *key, uint64_t *out) {
  return getu(nqjget(o, key), out);
}

/* The expected-results test with this tgId and tcId. */
static const nqjs *findexp(const nqjs *eg, uint64_t tg, uint64_t tc) {
  size_t i, j;
  uint64_t x;
  for (i = 0; eg != NULL && i < eg->n; i++) {
    const nqjs *g = nqjat(eg, i), *ts;
    if (!getf(g, "tgId", &x) || x != tg) continue;
    ts = nqjget(g, "tests");
    for (j = 0; ts != NULL && j < ts->n; j++) {
      if (getf(nqjat(ts, j), "tcId", &x) && x == tc) {
        return nqjat(ts, j);
      }
    }
  }
  return NULL;
}

/* Decodes a hex field into a fresh buffer of at least need bytes; NULL
 * when it is missing, malformed or shorter. */
static uint8_t *unhexa(const nqjs *v, size_t need, size_t *n) {
  const char *s = nqjstr(v);
  size_t len, cap;
  uint8_t *b;
  if (s == NULL) return NULL;
  len = strlen(s);
  cap = len / 2 > need ? len / 2 : need;
  b = (uint8_t *)calloc(cap + 1, 1);
  if (b == NULL) return NULL;
  if (nqunhex(s, len, b, cap + 1, n) != NQOK || *n < need) {
    free(b);
    return NULL;
  }
  return b;
}

/* 1 when the hex field v holds exactly the n bytes at got. */
static int eqhex(const nqjs *v, const uint8_t *got, size_t n) {
  size_t m = 0;
  uint8_t *b = unhexa(v, 0, &m);
  int ok = b != NULL && m == n && memcmp(b, got, n) == 0;
  free(b);
  return ok;
}

static void miss(const char *dir, const char *what, uint64_t tg,
                 uint64_t tc) {
  if (nmiss++ < 20) {
    fprintf(stderr, "%s: %s failed (tgId %llu, tcId %llu)\n", dir, what,
            (unsigned long long)tg, (unsigned long long)tc);
  }
}

/* ---- hashing a message of any bit length ---- */

/* ACVP gives the bits of a message most significant first, so a partial
 * last byte holds its nb bits at the top. FIPS 202 reads bits least
 * significant first; SHA-2 most significant first. */
static uint8_t k3last(uint8_t b, unsigned nb) {
  return nb == 0 ? 0 : (uint8_t)(b >> (8 - nb));
}

/* Fixed-size hash (outlen ignored) or SHAKE (outlen bytes). */
static void hbits(nqhalg alg, const uint8_t *m, uint64_t bits, uint8_t *out,
                  size_t outlen) {
  size_t full = (size_t)(bits / 8);
  unsigned nb = (unsigned)(bits % 8);
  uint8_t last = nb ? m[full] : 0;
  if (alg == NQSHK128 || alg == NQSHK256) {
    nqkctx c;
    nqshkini(&c, alg == NQSHK128 ? 128 : 256);
    nqkabs(&c, m, full);
    nqkpad(&c, k3last(last, nb), nb);
    nqksqz(&c, out, outlen);
    nqwipe(&c, sizeof c);
  } else {
    nqfctx c;
    nqfini(&c, alg);
    nqfupd(&c, m, full);
    if (alg >= NQS3224) last = k3last(last, nb);
    nqfbit(&c, last, nb, out);
  }
}

/* ---- AFT (and SHAKE VOT) ---- */

static int aft(const vset *s, const nqjs *t, const nqjs *e, uint64_t tg,
               uint64_t tc) {
  uint64_t bits, outbits = 0;
  size_t n, outlen;
  uint8_t *m, *out;
  int ok;
  if (!getf(t, "len", &bits)) return 0;
  if (s->kind == KSHK) {
    if (!getf(t, "outLen", &outbits)) return 0;
    outlen = (size_t)((outbits + 7) / 8);
  } else {
    outlen = nqhlen(s->alg);
  }
  m = unhexa(nqjget(t, "msg"), (size_t)((bits + 7) / 8), &n);
  out = (uint8_t *)malloc(outlen + 1);
  if (m == NULL || out == NULL) {
    free(m);
    free(out);
    return 0;
  }
  hbits(s->alg, m, bits, out, outlen);
  if (outbits % 8) {
    /* a partial last output byte: its FIPS 202 bits 0.. come first, so
     * ACVP shows them at the top */
    unsigned nb = (unsigned)(outbits % 8);
    out[outlen - 1] =
        (uint8_t)((out[outlen - 1] & ((1u << nb) - 1)) << (8 - nb));
  }
  ok = eqhex(nqjget(e, "md"), out, outlen);
  if (!ok) miss(s->dir, "AFT", tg, tc);
  free(m);
  free(out);
  return ok;
}

static int hmac(const vset *s, const nqjs *t, const nqjs *e, uint64_t tg,
                uint64_t tc) {
  uint64_t kb, mb, tb;
  size_t kn, mn;
  uint8_t *k, *m, tag[NQHMAX];
  int ok = 0;
  if (!getf(t, "keyLen", &kb) || !getf(t, "msgLen", &mb) ||
      !getf(t, "macLen", &tb) || kb % 8 || mb % 8 || tb % 8 ||
      tb / 8 > NQHMAX) {
    return 0;
  }
  k = unhexa(nqjget(t, "key"), (size_t)(kb / 8), &kn);
  m = unhexa(nqjget(t, "msg"), (size_t)(mb / 8), &mn);
  if (k != NULL && m != NULL &&
      nqhmac(s->alg, k, (size_t)(kb / 8), m, (size_t)(mb / 8), tag,
             (size_t)(tb / 8)) == NQOK) {
    ok = eqhex(nqjget(e, "mac"), tag, (size_t)(tb / 8));
  }
  if (!ok) miss(s->dir, "HMAC AFT", tg, tc);
  nqwipe(tag, sizeof tag);
  free(k);
  free(m);
  return ok;
}

/* ---- Monte Carlo tests ---- */

#define MCTB 512 /* the longest seed, in bytes */

/* SHA-2, ACVP 1.0: MD[i] = H(MD[i-3] || MD[i-2] || MD[i-1]), 1000 times
 * per output, 100 outputs, from MD[0] = MD[1] = MD[2] = seed. The
 * "alternate" version cuts or zero-pads each message to the seed's
 * length. */
static int s2mct(const vset *s, const nqjs *t, const nqjs *e, int alt) {
  static uint8_t md[3][MCTB], msg[3 * MCTB];
  size_t ml[3], d = nqhlen(s->alg), sl, n, i, j, tot, k;
  uint64_t bits;
  const nqjs *res = nqjget(e, "resultsArray");
  uint8_t *seed;
  int ok = 1;
  if (!getf(t, "len", &bits) || bits % 8 || bits / 8 > MCTB || res == NULL ||
      res->n != 100) {
    return 0;
  }
  sl = (size_t)(bits / 8);
  seed = unhexa(nqjget(t, "msg"), sl, &n);
  if (seed == NULL) return 0;
  for (k = 0; k < 3; k++) {
    memcpy(md[k], seed, sl);
    ml[k] = sl;
  }
  free(seed);
  for (j = 0; j < 100 && ok; j++) {
    for (i = 0; i < 1000; i++) {
      uint8_t *a = md[i % 3], *b = md[(i + 1) % 3], *c = md[(i + 2) % 3];
      size_t la = ml[i % 3], lb = ml[(i + 1) % 3], lc = ml[(i + 2) % 3];
      memcpy(msg, a, la);
      memcpy(msg + la, b, lb);
      memcpy(msg + la + lb, c, lc);
      tot = la + lb + lc;
      if (alt) {
        if (tot < sl) memset(msg + tot, 0, sl - tot);
        tot = sl;
      }
      /* the oldest digest is replaced by the new one */
      nqhash(s->alg, msg, tot, a, d);
      ml[i % 3] = d;
    }
    /* the last step (i = 999) wrote md[999 % 3] = md[0] */
    ok = eqhex(nqjget(nqjat(res, j), "md"), md[0], d);
    memcpy(md[1], md[0], d);
    memcpy(md[2], md[0], d);
    ml[0] = ml[1] = ml[2] = d;
  }
  return ok;
}

/* SHA-3, ACVP 2.0 standard: MD[i] = H(MD[i-1]). */
static int s3mct(const vset *s, const nqjs *t, const nqjs *e) {
  uint8_t cur[MCTB], nxt[NQHMAX];
  size_t d = nqhlen(s->alg), cl, n, i, j;
  uint64_t bits;
  const nqjs *res = nqjget(e, "resultsArray");
  uint8_t *seed;
  int ok = 1;
  if (!getf(t, "len", &bits) || bits % 8 || bits / 8 > MCTB || res == NULL ||
      res->n != 100) {
    return 0;
  }
  cl = (size_t)(bits / 8);
  seed = unhexa(nqjget(t, "msg"), cl, &n);
  if (seed == NULL) return 0;
  memcpy(cur, seed, cl);
  free(seed);
  for (j = 0; j < 100 && ok; j++) {
    for (i = 0; i < 1000; i++) {
      nqhash(s->alg, cur, cl, nxt, d);
      memcpy(cur, nxt, d);
      cl = d;
    }
    ok = eqhex(nqjget(nqjat(res, j), "md"), cur, d);
  }
  return ok;
}

/* SHAKE, FIPS 202 / ACVP: Msg = the leftmost 128 bits of the previous
 * output (zero-padded), output length from its rightmost 16 bits. */
static int shkmct(const vset *s, const nqjs *g, const nqjs *t,
                  const nqjs *e) {
  static uint8_t out[65536 / 8 + 2];
  uint8_t m[16];
  uint64_t bits, minb, maxb, ob, rv;
  size_t lo, hi, range, ol, prev, n, i, j;
  const nqjs *res = nqjget(e, "resultsArray");
  uint8_t *seed;
  int ok = 1;
  if (!getf(t, "len", &bits) || bits % 8 || !getf(g, "minOutLen", &minb) ||
      !getf(g, "maxOutLen", &maxb) || minb % 8 || maxb % 8 ||
      minb < 16 || maxb < minb || maxb / 8 > sizeof out || res == NULL ||
      res->n != 100) {
    return 0;
  }
  lo = (size_t)(minb / 8);
  hi = (size_t)(maxb / 8);
  range = hi - lo + 1;
  seed = unhexa(nqjget(t, "msg"), (size_t)(bits / 8), &n);
  if (seed == NULL) return 0;
  memset(out, 0, sizeof out);
  ol = (size_t)(bits / 8) < sizeof out ? (size_t)(bits / 8) : sizeof out;
  memcpy(out, seed, ol);
  free(seed);
  prev = ol;
  ol = hi;
  for (j = 0; j < 100 && ok; j++) {
    for (i = 0; i < 1000; i++) {
      memset(m, 0, sizeof m);
      memcpy(m, out, prev < 16 ? prev : 16);
      nqhash(s->alg, m, sizeof m, out, ol);
      rv = ((uint64_t)out[ol - 2] << 8) | out[ol - 1];
      prev = ol;
      ol = lo + (size_t)(rv % range);
    }
    ok = eqhex(nqjget(nqjat(res, j), "md"), out, prev) &&
         getf(nqjat(res, j), "outLen", &ob) && ob == (uint64_t)prev * 8;
  }
  return ok;
}

/* ---- large-message tests ---- */

static int ldtrun(const vset *s, const nqjs *t, const nqjs *e) {
  const nqjs *lm = nqjget(t, "largeMsg");
  const char *tech = nqjstr(nqjget(lm, "expansionTechnique"));
  uint64_t cbits, fbits, left;
  size_t cl, n, cs, i;
  uint8_t *c, *chunk, out[NQHMAX];
  nqfctx h;
  int ok;
  if (lm == NULL || tech == NULL || strcmp(tech, "repeating") != 0 ||
      !getf(lm, "contentLength", &cbits) ||
      !getf(lm, "fullLength", &fbits) || cbits == 0 || cbits % 8 ||
      fbits % 8) {
    return 0;
  }
  cl = (size_t)(cbits / 8);
  c = unhexa(nqjget(lm, "content"), cl, &n);
  if (c == NULL) return 0;
  /* a 16 MiB run of whole copies of the content */
  cs = ((size_t)1 << 24) / cl * cl;
  if (cs == 0) cs = cl;
  chunk = (uint8_t *)malloc(cs);
  if (chunk == NULL) {
    free(c);
    return 0;
  }
  for (i = 0; i < cs; i++) chunk[i] = c[i % cl];
  free(c);
  nqfini(&h, s->alg);
  for (left = fbits / 8; left > 0;) {
    size_t k = left > cs ? cs : (size_t)left;
    nqfupd(&h, chunk, k);
    left -= k;
  }
  nqffin(&h, out);
  free(chunk);
  ok = eqhex(nqjget(e, "md"), out, nqhlen(s->alg));
  return ok;
}

/* ---- one vector set ---- */

static void runset(const vset *s) {
  nqjs *p = ldjs(s->dir, "prompt.json");
  nqjs *x = ldjs(s->dir, "expectedResults.json");
  const nqjs *pg, *eg;
  cnt k;
  size_t i, j;
  int ty, any = 0;
  memset(&k, 0, sizeof k);
  NQTCHK(p != NULL && x != NULL);
  if (p == NULL || x == NULL) goto done;
  pg = groups(p);
  eg = groups(x);
  NQTCHK(pg != NULL && eg != NULL && pg->n > 0);
  for (i = 0; pg != NULL && eg != NULL && i < pg->n; i++) {
    const nqjs *g = nqjat(pg, i), *ts = nqjget(g, "tests");
    const char *tt = nqjstr(nqjget(g, "testType"));
    const char *mv = nqjstr(nqjget(g, "mctVersion"));
    uint64_t tg = 0;
    NQTCHK(getf(g, "tgId", &tg) && tt != NULL && ts != NULL);
    if (tt == NULL || ts == NULL) continue;
    for (ty = 0; ty < TN && strcmp(tt, tname[ty]) != 0; ty++) {
    }
    NQTCHK(ty < TN);
    if (ty == TN) continue;
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j), *e;
      uint64_t tc = 0;
      int r = 0;
      NQTCHK(getf(t, "tcId", &tc));
      e = findexp(eg, tg, tc);
      NQTCHK(e != NULL);
      if (e == NULL) continue;
      if (ty == TLDT && !ldt) {
        k.skip[ty]++;
        continue;
      }
      k.run[ty]++;
      if (s->kind == KHM) {
        r = ty == TAFT ? hmac(s, t, e, tg, tc) : 0;
      } else if (ty == TAFT || ty == TVOT) {
        r = s->kind == KSHK || ty == TAFT ? aft(s, t, e, tg, tc) : 0;
      } else if (ty == TMCT) {
        int alt = mv != NULL && strcmp(mv, "alternate") == 0;
        if (s->kind == KS2) {
          r = s2mct(s, t, e, alt);
        } else if (s->kind == KS3 && !alt) {
          r = s3mct(s, t, e);
        } else if (s->kind == KSHK) {
          r = shkmct(s, g, t, e);
        }
        if (r != 1) miss(s->dir, "MCT", tg, tc);
      } else if (ty == TLDT) {
        r = ldtrun(s, t, e);
        if (r != 1) miss(s->dir, "LDT", tg, tc);
      }
      NQTCHK(r == 1);
      if (r == 1) k.pass[ty]++;
    }
  }
done:
  printf("%-22s", s->dir);
  for (ty = 0; ty < TN; ty++) {
    if (k.run[ty] + k.skip[ty] == 0) continue;
    any = 1;
    printf(" %s %ld/%ld", tname[ty], k.pass[ty], k.run[ty]);
    if (k.skip[ty]) printf(" (%ld skipped)", k.skip[ty]);
  }
  printf("%s\n", any ? "" : " no tests");
  nqjfree(p);
  nqjfree(x);
}

/* ---- known answers ---- */

typedef struct {
  nqhalg alg;
  const char *empty, *abc;
} kat;

static const kat kats[] = {
    {NQS224, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {NQS256,
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {NQS384,
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
     "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
     "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
    {NQS512,
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {NQS512T224, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
     "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
    {NQS512T256,
     "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
    {NQS3224, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
     "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
    {NQS3256,
     "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
     "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
    {NQS3384,
     "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61"
     "995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
     "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c25"
     "96da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
    {NQS3512,
     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
     "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
     "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
    {NQSHK128,
     "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
     "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"},
    {NQSHK256,
     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
     "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
     "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"},
};

#define NALG 12
static const nqhalg algs[NALG] = {
    NQS224, NQS256, NQS384, NQS512, NQS512T224, NQS512T256,
    NQS3224, NQS3256, NQS3384, NQS3512, NQSHK128, NQSHK256};

static void tkat(void) {
  uint8_t out[NQHMAX];
  char hex[2 * NQHMAX + 1];
  size_t i, d;
  for (i = 0; i < sizeof kats / sizeof *kats; i++) {
    d = nqhlen(kats[i].alg);
    NQTEQI(nqhash(kats[i].alg, NULL, 0, out, d), NQOK);
    nqhex(out, d, hex);
    NQTCHK(strcmp(hex, kats[i].empty) == 0);
    NQTEQI(nqhash(kats[i].alg, (const uint8_t *)"abc", 3, out, d), NQOK);
    nqhex(out, d, hex);
    NQTCHK(strcmp(hex, kats[i].abc) == 0);
  }
  /* the one-shot helpers other modules use */
  nqs256((const uint8_t *)"abc", 3, out);
  nqhex(out, 32, hex);
  NQTCHK(strcmp(hex, kats[1].abc) == 0);
  nqs512((const uint8_t *)"abc", 3, out);
  nqhex(out, 64, hex);
  NQTCHK(strcmp(hex, kats[3].abc) == 0);
  nqs3(256, (const uint8_t *)"abc", 3, out);
  nqhex(out, 32, hex);
  NQTCHK(strcmp(hex, kats[7].abc) == 0);
  nqshk(256, (const uint8_t *)"abc", 3, out, 64);
  nqhex(out, 64, hex);
  NQTCHK(strcmp(hex, kats[11].abc) == 0);
}

/* ---- incremental use ---- */

#define ML 200

static void tsplit(void) {
  uint8_t m[ML], ref[NQHMAX], got[NQHMAX], big[300], part[300];
  nqhctx c;
  size_t a, k, d, i, bad;
  for (i = 0; i < ML; i++) m[i] = (uint8_t)(i * 7 + 3);
  for (a = 0; a < NALG; a++) {
    d = nqhlen(algs[a]);
    NQTEQI(nqhash(algs[a], m, ML, ref, d), NQOK);
    bad = 0;
    for (k = 0; k <= ML; k++) {
      int r1 = nqhini(&c, algs[a]);
      int r2 = nqhupd(&c, m, k);
      int r3 = nqhupd(&c, m + k, ML - k);
      int r4 = nqhfin(&c, got, d);
      if (r1 || r2 || r3 || r4 || memcmp(got, ref, d) != 0) bad++;
    }
    NQTEQI(bad, 0);
    /* byte at a time */
    NQTEQI(nqhini(&c, algs[a]), NQOK);
    for (k = 0; k < ML; k++) NQTEQI(nqhupd(&c, m + k, 1), NQOK);
    NQTEQI(nqhupd(&c, NULL, 0), NQOK);
    NQTEQI(nqhfin(&c, got, d), NQOK);
    NQTEQM(got, ref, d);
  }
  /* SHAKE: squeezing in pieces gives the same stream */
  for (a = NALG - 2; a < NALG; a++) {
    NQTEQI(nqhash(algs[a], m, ML, big, sizeof big), NQOK);
    NQTEQI(nqhini(&c, algs[a]), NQOK);
    NQTEQI(nqhupd(&c, m, ML), NQOK);
    for (i = 0, k = 0; i < sizeof part; k++) {
      size_t n = k + 1 < sizeof part - i ? k + 1 : sizeof part - i;
      NQTEQI(nqhfin(&c, part + i, n), NQOK);
      i += n;
    }
    NQTEQI(nqhfin(&c, NULL, 0), NQOK);
    NQTEQM(part, big, sizeof big);
  }
}

/* HMAC: the incremental form matches the one-shot, and a long key is
 * hashed first. */
static void thmac(void) {
  uint8_t key[200], m[ML], t1[NQHMAX], t2[NQHMAX];
  nqmctx c;
  size_t a, i, k, d;
  for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)(255 - i);
  for (i = 0; i < ML; i++) m[i] = (uint8_t)i;
  for (a = 0; a < NALG - 2; a++) {
    d = nqhlen(algs[a]);
    for (k = 0; k <= sizeof key; k += 25) {
      NQTEQI(nqhmac(algs[a], key, k, m, ML, t1, d), NQOK);
      NQTEQI(nqmini(&c, algs[a], key, k), NQOK);
      nqmupd(&c, m, 77);
      nqmupd(&c, m + 77, ML - 77);
      nqmfin(&c, t2);
      NQTEQM(t1, t2, d);
    }
    /* a key longer than the block is replaced by its hash */
    NQTEQI(nqhmac(algs[a], key, sizeof key, m, 10, t1, d), NQOK);
    NQTEQI(nqhash(algs[a], key, sizeof key, t2, d), NQOK);
    NQTEQI(nqhmac(algs[a], t2, d, m, 10, t2, d), NQOK);
    NQTEQM(t1, t2, d);
    /* truncation keeps the leading bytes */
    NQTEQI(nqhmac(algs[a], key, 16, m, ML, t1, d), NQOK);
    memset(t2, 0, sizeof t2);
    NQTEQI(nqhmac(algs[a], key, 16, m, ML, t2, 1), NQOK);
    NQTCHK(t2[0] == t1[0] && t2[1] == 0);
  }
  /* RFC 4231 test case 2 */
  NQTEQI(nqhmac(NQS256, (const uint8_t *)"Jefe", 4,
                (const uint8_t *)"what do ya want for nothing?", 28, t1,
                32), NQOK);
  {
    char hex[65];
    nqhex(t1, 32, hex);
    NQTCHK(strcmp(hex, "5bdcc146bf60754e6a042426089575c7"
                       "5a003f089d2739839dec58b964ec3843") == 0);
  }
}

/* ---- API errors ---- */

static void terr(void) {
  uint8_t out[NQHMAX + 1], m[4] = {1, 2, 3, 4};
  nqhctx c;
  size_t a, d;
  NQTEQI(nqhlen((nqhalg)0), 0);
  NQTEQI(nqhlen((nqhalg)99), 0);
  NQTEQI(nqhlen(NQSHK128), 32);
  NQTEQI(nqhlen(NQSHK256), 64);
  NQTEQI(nqhash((nqhalg)0, m, 4, out, 32), NQEARG);
  NQTEQI(nqhini(&c, (nqhalg)0), NQEARG);
  NQTEQI(nqhupd(&c, m, 4), NQESTATE);
  NQTEQI(nqhini(NULL, NQS256), NQEARG);
  NQTEQI(nqhupd(NULL, m, 4), NQEARG);
  NQTEQI(nqhfin(NULL, out, 32), NQEARG);
  memset(&c, 0, sizeof c);
  NQTEQI(nqhupd(&c, m, 4), NQESTATE);
  NQTEQI(nqhfin(&c, out, 32), NQESTATE);
  for (a = 0; a < NALG; a++) {
    nqhalg g = algs[a];
    int shk = a >= NALG - 2;
    d = nqhlen(g);
    NQTEQI(nqhash(g, NULL, 1, out, d), NQEARG);
    NQTEQI(nqhash(g, m, 4, NULL, d), NQEARG);
    NQTEQI(nqhini(&c, g), NQOK);
    NQTEQI(nqhupd(&c, NULL, 1), NQEARG);
    NQTEQI(nqhupd(&c, m, 4), NQOK);
    if (shk) {
      /* any length; squeezing ends absorbing */
      NQTEQI(nqhash(g, m, 4, out, d + 1), NQOK);
      NQTEQI(nqhash(g, m, 4, NULL, 0), NQOK);
      NQTEQI(nqhfin(&c, NULL, 5), NQEARG);
      NQTEQI(nqhfin(&c, out, 5), NQOK);
      NQTEQI(nqhfin(&c, out, 5), NQOK);
      NQTEQI(nqhupd(&c, m, 4), NQESTATE);
      NQTEQI(nqhupd(&c, m, 0), NQESTATE);
      NQTEQI(nqhmac(g, m, 4, m, 4, out, d), NQENOSUP);
      continue;
    }
    NQTEQI(nqhash(g, m, 4, out, d - 1), NQEBUF);
    NQTEQI(nqhash(g, m, 4, out, d + 1), NQEARG);
    NQTEQI(nqhash(g, m, 4, out, 0), NQEBUF);
    NQTEQI(nqhfin(&c, out, d - 1), NQEBUF);
    NQTEQI(nqhfin(&c, out, d + 1), NQEARG);
    NQTEQI(nqhfin(&c, NULL, d), NQEARG);
    /* the failed calls left the context usable */
    NQTEQI(nqhfin(&c, out, d), NQOK);
    NQTEQI(nqhfin(&c, out, d), NQESTATE);
    NQTEQI(nqhupd(&c, m, 4), NQESTATE);
    NQTEQI(nqhupd(&c, NULL, 0), NQESTATE);
    /* HMAC */
    NQTEQI(nqhmac(g, NULL, 0, m, 4, out, d), NQOK);
    NQTEQI(nqhmac(g, NULL, 1, m, 4, out, d), NQEARG);
    NQTEQI(nqhmac(g, m, 4, NULL, 1, out, d), NQEARG);
    NQTEQI(nqhmac(g, m, 4, NULL, 0, out, d), NQOK);
    NQTEQI(nqhmac(g, m, 4, m, 4, NULL, d), NQEARG);
    NQTEQI(nqhmac(g, m, 4, m, 4, out, 0), NQEARG);
    NQTEQI(nqhmac(g, m, 4, m, 4, out, d + 1), NQEARG);
    NQTEQI(nqhmac(g, m, 4, m, 4, out, 1), NQOK);
  }
  NQTEQI(nqhmac((nqhalg)0, m, 4, m, 4, out, 32), NQEARG);
  NQTEQI(nqhmac((nqhalg)99, m, 4, m, 4, out, 32), NQEARG);
}

int main(void) {
  const char *env = getenv("NQLDT");
  size_t i;
  ldt = env != NULL && strcmp(env, "1") == 0;
  tkat();
  tsplit();
  thmac();
  terr();
  for (i = 0; i < sizeof sets / sizeof *sets; i++) {
    runset(&sets[i]);
  }
  if (!ldt) printf("LDT skipped: set NQLDT=1 to run them\n");
  return nqtdone("thash");
}
