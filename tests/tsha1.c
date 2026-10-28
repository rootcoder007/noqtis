/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SHA-1 (verify-only, hash/h.h): every NIST CAVP SHA1ShortMsg,
 * SHA1LongMsg and SHA1Monte vector in vectors/cavp/sha1, incremental
 * use, and the nqxops.sha1 hook as src/der calls it. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "der/x509.h"
#include "hash/h.h"
#include "nqt.h"

#define MSGMAX 16384

/* The value after "<key> = " on the line at p, or NULL. */
static const char *val(const char *p, const char *key, size_t *vlen) {
  size_t k = strlen(key), n = 0;
  if (strncmp(p, key, k) != 0 || strncmp(p + k, " = ", 3) != 0) {
    return NULL;
  }
  p += k + 3;
  while (p[n] != '\0' && p[n] != '\r' && p[n] != '\n') {
    n++;
  }
  *vlen = n;
  return p;
}

static const char *nextl(const char *p) {
  while (*p != '\0' && *p != '\n') {
    p++;
  }
  return *p == '\n' ? p + 1 : p;
}

/* ShortMsg / LongMsg: Len, Msg, MD triples. Returns vectors run. */
static long msgs(const char *path, long *pass) {
  char *buf = NULL;
  size_t len = 0, vl, ml = 0;
  const char *p, *v;
  long bits = -1, run = 0;
  static uint8_t msg[MSGMAX];
  uint8_t md[NQS1LEN], want[NQS1LEN];
  size_t wl;
  int rc = nqreadf(path, (size_t)1 << 24, &buf, &len);
  NQTEQI(rc, NQOK);
  if (rc != NQOK) {
    return 0;
  }
  for (p = buf; *p != '\0'; p = nextl(p)) {
    if ((v = val(p, "Len", &vl)) != NULL) {
      bits = strtol(v, NULL, 10);
    } else if ((v = val(p, "Msg", &vl)) != NULL) {
      rc = nqunhex(v, vl, msg, sizeof msg, &ml);
      NQTEQI(rc, NQOK);
    } else if ((v = val(p, "MD", &vl)) != NULL) {
      rc = nqunhex(v, vl, want, sizeof want, &wl);
      NQTCHK(rc == NQOK && wl == NQS1LEN && bits >= 0 && bits % 8 == 0);
      if (bits == 0) {
        ml = 0;
      }
      NQTEQI(ml, (size_t)bits / 8);
      nqs1(msg, ml, md);
      run++;
      if (memcmp(md, want, NQS1LEN) == 0) {
        (*pass)++;
      } else {
        fprintf(stderr, "%s: Len %ld differs\n", path, bits);
      }
      bits = -1;
    }
  }
  nqfree(buf, len + 1);
  return run;
}

/* Monte Carlo (SHAVS 6.4): 100 checkpoints of 1000 chained hashes. */
static long monte(const char *path, long *pass) {
  char *buf = NULL;
  size_t len = 0, vl, wl;
  const char *p, *v;
  uint8_t md[3][NQS1LEN], m[3 * NQS1LEN], seed[NQS1LEN],
      want[NQS1LEN];
  long run = 0, cnt = -1;
  int rc = nqreadf(path, (size_t)1 << 20, &buf, &len), have = 0;
  unsigned i;
  NQTEQI(rc, NQOK);
  if (rc != NQOK) {
    return 0;
  }
  for (p = buf; *p != '\0'; p = nextl(p)) {
    if ((v = val(p, "Seed", &vl)) != NULL) {
      rc = nqunhex(v, vl, seed, sizeof seed, &wl);
      NQTCHK(rc == NQOK && wl == NQS1LEN);
      have = 1;
    } else if ((v = val(p, "COUNT", &vl)) != NULL) {
      cnt = strtol(v, NULL, 10);
    } else if ((v = val(p, "MD", &vl)) != NULL) {
      NQTCHK(have && cnt == run);
      rc = nqunhex(v, vl, want, sizeof want, &wl);
      NQTCHK(rc == NQOK && wl == NQS1LEN);
      memcpy(md[0], seed, NQS1LEN);
      memcpy(md[1], seed, NQS1LEN);
      memcpy(md[2], seed, NQS1LEN);
      for (i = 3; i < 1003; i++) {
        memcpy(m, md[0], NQS1LEN);
        memcpy(m + NQS1LEN, md[1], NQS1LEN);
        memcpy(m + 2 * NQS1LEN, md[2], NQS1LEN);
        memcpy(md[0], md[1], NQS1LEN);
        memcpy(md[1], md[2], NQS1LEN);
        nqs1(m, sizeof m, md[2]);
      }
      memcpy(seed, md[2], NQS1LEN);
      run++;
      if (memcmp(md[2], want, NQS1LEN) == 0) {
        (*pass)++;
      } else {
        fprintf(stderr, "%s: COUNT %ld differs\n", path, cnt);
      }
    }
  }
  nqfree(buf, len + 1);
  return run;
}

/* Every split of a 200-byte message into two updates, and byte by byte,
 * gives the one-shot digest. */
static void incr(void) {
  uint8_t msg[200], one[NQS1LEN], two[NQS1LEN];
  nqs1ctx c;
  size_t i, bad = 0;
  for (i = 0; i < sizeof msg; i++) {
    msg[i] = (uint8_t)(i * 7 + 3);
  }
  nqs1(msg, sizeof msg, one);
  for (i = 0; i <= sizeof msg; i++) {
    nqs1ini(&c);
    nqs1upd(&c, msg, i);
    nqs1upd(&c, NULL, 0);
    nqs1upd(&c, msg + i, sizeof msg - i);
    nqs1fin(&c, two);
    bad += memcmp(one, two, NQS1LEN) != 0;
  }
  NQTEQI(bad, 0);
  nqs1ini(&c);
  for (i = 0; i < sizeof msg; i++) {
    nqs1upd(&c, msg + i, 1);
  }
  nqs1fin(&c, two);
  NQTEQM(one, two, NQS1LEN);
}

/* FIPS 180-4 examples ("abc", the 448-bit message) and a million 'a'. */
static void kat(void) {
  static const uint8_t abc[NQS1LEN] = {
      0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
      0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  static const uint8_t two[NQS1LEN] = {
      0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
      0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1};
  static const uint8_t mil[NQS1LEN] = {
      0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e,
      0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f};
  const char *s2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t a[1000], md[NQS1LEN];
  nqs1ctx c;
  unsigned i;
  nqs1((const uint8_t *)"abc", 3, md);
  NQTEQM(md, abc, NQS1LEN);
  nqs1((const uint8_t *)s2, strlen(s2), md);
  NQTEQM(md, two, NQS1LEN);
  memset(a, 'a', sizeof a);
  nqs1ini(&c);
  for (i = 0; i < 1000; i++) {
    nqs1upd(&c, a, sizeof a);
  }
  nqs1fin(&c, md);
  NQTEQM(md, mil, NQS1LEN);
}

/* The hook as src/der uses it: nqxdig with h 0 is SHA-1 through ops. */
static void hook(void) {
  nqxops ops;
  uint8_t md[NQS1LEN], want[NQS1LEN];
  memset(&ops, 0, sizeof ops);
  NQTEQI(nqs1hk(NULL, NULL, 1, md), NQEARG);
  NQTEQI(nqs1hk(NULL, (const uint8_t *)"abc", 3, NULL), NQEARG);
  NQTEQI(nqs1hk(NULL, NULL, 0, md), NQOK);
  nqs1(NULL, 0, want);
  NQTEQM(md, want, NQS1LEN);
  NQTCHK(nqxdig(&ops, (nqhalg)0, (const uint8_t *)"abc", 3, md) != NQOK);
  ops.sha1 = nqs1hk;
  NQTEQI(nqxdig(&ops, (nqhalg)0, (const uint8_t *)"abc", 3, md), NQOK);
  nqs1((const uint8_t *)"abc", 3, want);
  NQTEQM(md, want, NQS1LEN);
  NQTEQI(nqxhlen((nqhalg)0), NQS1LEN);
}

int main(void) {
  static const char *const f[2] = {"vectors/cavp/sha1/SHA1ShortMsg.rsp",
                                   "vectors/cavp/sha1/SHA1LongMsg.rsp"};
  long run, pass;
  unsigned i;
  for (i = 0; i < 2; i++) {
    pass = 0;
    run = msgs(f[i], &pass);
    printf("%s: %ld run, %ld passed\n", f[i] + 18, run, pass);
    NQTCHK(run > 0);
    NQTEQI(pass, run);
  }
  pass = 0;
  run = monte("vectors/cavp/sha1/SHA1Monte.rsp", &pass);
  printf("SHA1Monte.rsp: %ld run, %ld passed\n", run, pass);
  NQTEQI(run, 100);
  NQTEQI(pass, run);
  incr();
  kat();
  hook();
  return nqtdone("tsha1");
}
