/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for HMAC_DRBG (SP 800-90A Rev. 1; ACVP algorithm
 * hmacDRBG, revision 1.0) with SHA2-256 and SHA2-512, the two hashes
 * noqtis's DRBG provides: AFT tests, with and without prediction
 * resistance and reseeding. Groups of any other mode are left out with
 * a message (a lab registers only the modes the module claims).
 *
 *   acvdr <request.json> <response.json> [<expected.json>] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "drbg/drbg.h"

/* one test: instantiate, then the otherInput steps; out gets the bits
 * of the last generate */
static int one(nqhalg alg, int pr, size_t ol, const nqjs *t, uint8_t *out) {
  uint8_t *ent, *non, *ps;
  size_t el = 0, nl = 0, pl = 0, i;
  const nqjs *oi = nqjget(t, "otherInput");
  nqdrbg d;
  int ok = 0, rc;
  memset(&d, 0, sizeof d);
  ent = acvhex(nqjget(t, "entropyInput"), &el);
  non = acvhex(nqjget(t, "nonce"), &nl);
  ps = acvhex(nqjget(t, "persoString"), &pl);
  if (ent == NULL || non == NULL || ps == NULL || oi == NULL ||
      oi->type != NQJARR) {
    goto done;
  }
  rc = nqdini(&d, alg, ent, el, non, nl, pl ? ps : NULL, pl, pr);
  if (rc != NQOK) goto done;
  for (i = 0; i < oi->n; i++) {
    const nqjs *o = nqjat(oi, i);
    const char *use = acvs(o, "intendedUse");
    size_t al = 0, il = 0;
    uint8_t *add = acvhex(nqjget(o, "additionalInput"), &al);
    uint8_t *ei = acvhex(nqjget(o, "entropyInput"), &il);
    const uint8_t *ap = al ? add : NULL;
    rc = NQEDEC;
    if (use != NULL && add != NULL && ei != NULL) {
      if (strcmp(use, "reSeed") == 0) {
        rc = nqdres(&d, ei, il, ap, al);
      } else if (strcmp(use, "generate") == 0 && pr) {
        rc = nqdgenp(&d, out, ol, ap, al, ei, il);
      } else if (strcmp(use, "generate") == 0 && il == 0) {
        rc = nqdgen(&d, out, ol, ap, al);
      }
    }
    free(add);
    free(ei);
    if (rc != NQOK) goto done;
  }
  ok = 1;
done:
  nqdfree(&d);
  free(ent);
  free(non);
  free(ps);
  return ok;
}

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *gs = acvgrps(pr);
  size_t i, j;
  if (!acvis(acvset(pr), "algorithm", "hmacDRBG")) {
    fprintf(stderr, "acvdr: not an hmacDRBG request\n");
    return NQENOSUP;
  }
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *mode = acvs(g, "mode");
    int prs = nqjbool(nqjget(g, "predResistance"));
    int df = nqjbool(nqjget(g, "derFunc"));
    uint64_t tg = 0, bits = 0;
    nqhalg alg;
    uint8_t *out;
    if (mode == NULL || ts == NULL || prs < 0 || !acvu(g, "tgId", &tg) ||
        !acvu(g, "returnedBitsLen", &bits) || bits % 8 || bits == 0 ||
        bits / 8 > NQDMAXB || !acvis(g, "testType", "AFT")) {
      fprintf(stderr, "acvdr: group %lu: malformed\n", (unsigned long)i);
      return NQEDEC;
    }
    if (strcmp(mode, "SHA2-256") == 0) {
      alg = NQS256;
    } else if (strcmp(mode, "SHA2-512") == 0) {
      alg = NQS512;
    } else {
      fprintf(stderr, "acvdr: tgId %llu (%s) left out: hash not provided\n",
              (unsigned long long)tg, mode);
      *omit += (long)ts->n;
      continue;
    }
    if (df == 1) {
      fprintf(stderr, "acvdr: tgId %llu: derFunc is for CTR_DRBG\n",
              (unsigned long long)tg);
      return NQEDEC;
    }
    out = (uint8_t *)malloc((size_t)(bits / 8));
    if (out == NULL) return NQEMEM;
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      if (!acvu(t, "tcId", &tc) || !one(alg, prs, (size_t)(bits / 8), t, out)) {
        fprintf(stderr, "acvdr: tgId %llu tcId %llu: cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc);
        free(out);
        return NQEDEC;
      }
      acvtbeg(w, tc);
      acvkhex(w, "returnedBits", out, (size_t)(bits / 8));
      acvtend(w);
    }
    acvgend(w);
    nqwipe(out, (size_t)(bits / 8));
    free(out);
  }
  return NQOK;
}

int main(int argc, char **argv) {
  return acvmain(argc, argv, "acvdr", run);
}
