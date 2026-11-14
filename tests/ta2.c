/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Argon2 tests: the test vectors of RFC 9106 for Argon2d, Argon2i and
 * Argon2id, and Argon2id answers from OpenSSL 3.5 with more memory and
 * lanes, uneven memory (m not a multiple of 4p), segments past one block
 * of addresses and outputs over 64 bytes (vectors/argon2/), through
 * nqa2id too; the limits nqa2id refuses, a failing allocator, and that
 * the memory it takes is given back wiped. */
#include <stdint.h>
#include <stdlib.h>

#include "noqtis.h"
#include "core/int.h"
#include "hash/h.h"
#include "nqt.h"
#include "tkv.h"

static tkv kv;

static void trun(const char *file, int need) {
  static uint8_t pw[64], salt[64], key[64], ad[64], want[256], got[256];
  int seen = 0;
  NQTCHK(tkvopen(&kv, file));
  if (kv.f == NULL) return;
  while (tkvnext(&kv)) {
    int y = (int)tkvu(&kv, "y");
    size_t pl = tkvh(&kv, "pw", pw, sizeof pw);
    size_t sl = tkvh(&kv, "salt", salt, sizeof salt);
    size_t kl = tkvh(&kv, "key", key, sizeof key);
    size_t al = tkvh(&kv, "ad", ad, sizeof ad);
    size_t tl = tkvh(&kv, "tag", want, sizeof want);
    uint32_t m = (uint32_t)tkvu(&kv, "m"), t = (uint32_t)tkvu(&kv, "t"),
             p = (uint32_t)tkvu(&kv, "p");
    NQTCHK(pl != (size_t)-1 && sl != (size_t)-1 && kl != (size_t)-1 &&
           al != (size_t)-1 && tl != (size_t)-1);
    memset(got, 0, sizeof got);
    NQTEQI(nqa2(y, pw, pl, salt, sl, key, kl, ad, al, t, m, p, got, tl),
           NQOK);
    NQTEQM(got, want, tl);
    if (y == 2) {
      memset(got, 0, sizeof got);
      NQTEQI(nqa2id(pw, pl, salt, sl, key, kl, ad, al, t, m, p, got, tl),
             NQOK);
      NQTEQM(got, want, tl);
    }
    seen++;
  }
  tkvclose(&kv);
  printf("%s: %d vectors\n", file, seen);
  NQTEQI(seen, need);
}

/* an allocator that fails, and one that checks the memory comes back
 * wiped */
static int nal, wiped;
static void *bad(size_t n, void *u) {
  (void)n;
  (void)u;
  return NULL;
}
static void *mal(size_t n, void *u) {
  (void)u;
  nal++;
  return malloc(n);
}
static void fre(void *p, size_t n, void *u) {
  size_t i;
  int z = 1;
  (void)u;
  for (i = 0; i < n; i++) z &= ((uint8_t *)p)[i] == 0;
  wiped += z;
  free(p);
}

static void tlim(void) {
  uint8_t pw[8] = {1}, salt[16] = {2}, out[1025], a[64], b[64];
  /* every limit, each side */
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 3),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 1025),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 0, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, NQA2TMAX + 1, 8, 1, out,
                32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 0, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8 * 256, 256, out,
                32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 15, 2, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, NQA2MMAX + 1, 1, out,
                32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 7, NULL, 0, NULL, 0, 1, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, NULL, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(NULL, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 1, NULL, 0, 1, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 1, 1, 8, 1, out, 32),
         NQEARG);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, NULL, 32),
         NQEARG);
  /* the edges that are allowed: an empty password, 4 and 1024 bytes */
  NQTEQI(nqa2id(NULL, 0, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 4),
         NQOK);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 1024),
         NQOK);
  /* H' cut to 64 and to 65 bytes: the first 32 of 65 come from the
   * 64-byte chain, so the two differ */
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, a, 64), NQOK);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 65), NQOK);
  NQTCHK(memcmp(a, out, 32) != 0);
  /* m rounds down to 4p blocks: 35 KiB in 2 lanes is 32 KiB's memory but
   * not its output (m is in H0) */
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 35, 2, a, 32), NQOK);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 32, 2, b, 32), NQOK);
  NQTCHK(memcmp(a, b, 32) != 0);
  /* a failing allocator */
  NQTEQI(nqsetal(bad, fre, NULL), NQOK);
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 1, 8, 1, out, 32),
         NQEMEM);
  /* one allocation, given back wiped */
  NQTEQI(nqsetal(mal, fre, NULL), NQOK);
  nal = wiped = 0;
  NQTEQI(nqa2id(pw, 8, salt, 16, NULL, 0, NULL, 0, 2, 64, 1, out, 32),
         NQOK);
  NQTEQI(nal, 1);
  NQTEQI(wiped, 1);
  NQTEQI(nqsetal(NULL, NULL, NULL), NQOK);
}

int main(void) {
  trun("argon2/rfc9106.txt", 3);
  trun("argon2/ossl.txt", 6);
  tlim();
  return nqtdone("ta2");
}
