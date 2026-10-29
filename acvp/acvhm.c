/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for HMAC (FIPS 198-1) over SHA-2 and SHA-3: the
 * algorithms HMAC-SHA2-224 ... HMAC-SHA2-512/256 and HMAC-SHA3-224 ...
 * HMAC-SHA3-512, revision 2.0, AFT tests (keys, messages and tags in
 * whole bytes; a tag may be truncated).
 *
 *   acvhm <request.json> <response.json> [<expected.json>] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "hash/h.h"

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *gs = acvgrps(pr);
  const char *an = acvs(acvset(pr), "algorithm");
  int a = an != NULL && strncmp(an, "HMAC-", 5) == 0 ? acvhalg(an + 5) : -1;
  size_t i, j;
  (void)omit;
  if (a < 0 || a >= NQSHK128) {
    fprintf(stderr, "acvhm: algorithm %s is not an HMAC noqtis provides\n",
            an != NULL ? an : "(none)");
    return NQENOSUP;
  }
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    uint64_t tg = 0;
    if (!acvu(g, "tgId", &tg) || ts == NULL || !acvis(g, "testType", "AFT")) {
      fprintf(stderr, "acvhm: group %lu: not an AFT group with tests\n",
              (unsigned long)i);
      return NQEDEC;
    }
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0, kb = 0, mb = 0, tb = 0;
      size_t kn = 0, mn = 0;
      uint8_t *k = NULL, *m = NULL, tag[NQHMAX];
      int ok = 0;
      if (acvu(t, "tcId", &tc) && acvu(t, "keyLen", &kb) &&
          acvu(t, "msgLen", &mb) && acvu(t, "macLen", &tb) &&
          kb % 8 == 0 && mb % 8 == 0 && tb % 8 == 0 && tb > 0 &&
          tb / 8 <= nqhlen((nqhalg)a)) {
        k = acvhex(nqjget(t, "key"), &kn);
        m = acvhex(nqjget(t, "msg"), &mn);
        ok = k != NULL && m != NULL && kn == kb / 8 && mn == mb / 8 &&
             nqhmac((nqhalg)a, k, kn, m, mn, tag, (size_t)(tb / 8)) == NQOK;
      }
      free(k);
      free(m);
      if (!ok) {
        fprintf(stderr, "acvhm: tgId %llu tcId %llu: cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc);
        return NQEDEC;
      }
      acvtbeg(w, tc);
      acvkhex(w, "mac", tag, (size_t)(tb / 8));
      acvtend(w);
      nqwipe(tag, sizeof tag);
    }
    acvgend(w);
  }
  return NQOK;
}

int main(int argc, char **argv) {
  return acvmain(argc, argv, "acvhm", run);
}
