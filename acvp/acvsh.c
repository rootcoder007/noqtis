/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* ACVP harness for SHA-2 (FIPS 180-4: SHA2-224 ... SHA2-512/256, ACVP
 * revision 1.0), SHA-3 (FIPS 202: SHA3-224 ... SHA3-512, revision 2.0)
 * and SHAKE (SHAKE-128, SHAKE-256, revision FIPS202): AFT, MCT
 * (standard, and the alternate SHA-2 form), LDT and VOT tests.
 *
 *   acvsh <request.json> <response.json> [<expected.json>]
 *
 * The large-data tests hash gigabytes; NQFAST=1 leaves them out (the
 * response is then incomplete; ctest sets it). SHA-3 with the alternate
 * Monte Carlo form is not implemented and is left out with a message. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acv.h"
#include "core/int.h"
#include "hash/h.h"

enum { KS2 = 1, KS3, KSHK };

static int fast = 0;

/* ACVP gives a message's bits most significant first, so a partial last
 * byte holds its nb bits at the top. FIPS 202 reads bits least
 * significant first; SHA-2 most significant first. */
static uint8_t k3last(uint8_t b, unsigned nb) {
  return (uint8_t)(nb == 0 ? 0u : (unsigned)b >> (8u - nb));
}

/* a fixed-size hash (outlen ignored) or SHAKE (outlen bytes) of a
 * message of any bit length */
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

/* AFT, and SHAKE's VOT: "md" */
static int aft(acvw *w, nqhalg alg, int kind, const nqjs *t) {
  uint64_t bits, ob = 0;
  size_t n, outlen;
  uint8_t *m, *out;
  if (!acvu(t, "len", &bits)) return 0;
  if (kind == KSHK) {
    if (!acvu(t, "outLen", &ob) || ob == 0 || ob > ((uint64_t)1 << 20)) {
      return 0;
    }
    outlen = (size_t)((ob + 7) / 8);
  } else {
    outlen = nqhlen(alg);
  }
  m = acvhex(nqjget(t, "msg"), &n);
  if (m == NULL || n < (bits + 7) / 8) {
    free(m);
    return 0;
  }
  out = (uint8_t *)malloc(outlen + 1);
  if (out == NULL) {
    free(m);
    return 0;
  }
  hbits(alg, m, bits, out, outlen);
  if (ob % 8) {
    /* a partial last output byte: its FIPS 202 bits 0.. come first, so
     * ACVP shows them at the top */
    unsigned nb = (unsigned)(ob % 8);
    out[outlen - 1] =
        (uint8_t)((out[outlen - 1] & ((1u << nb) - 1)) << (8 - nb));
  }
  acvkhex(w, "md", out, outlen);
  free(m);
  free(out);
  return 1;
}

#define MCTB 512 /* the longest seed, in bytes */

/* SHA-2: MD[i] = H(MD[i-3] || MD[i-2] || MD[i-1]), 1000 times per
 * output, 100 outputs, from MD[0] = MD[1] = MD[2] = seed. The alternate
 * form cuts or zero-pads each message to the seed's length. */
static int s2mct(acvw *w, nqhalg alg, const nqjs *t, int alt) {
  static uint8_t md[3][MCTB], msg[3 * MCTB];
  size_t ml[3], d = nqhlen(alg), sl, n, i, j, tot, k;
  uint64_t bits;
  uint8_t *seed;
  if (!acvu(t, "len", &bits) || bits % 8 || bits / 8 > MCTB) return 0;
  sl = (size_t)(bits / 8);
  seed = acvhex(nqjget(t, "msg"), &n);
  if (seed == NULL || n < sl) {
    free(seed);
    return 0;
  }
  for (k = 0; k < 3; k++) {
    memcpy(md[k], seed, sl);
    ml[k] = sl;
  }
  free(seed);
  acvarr(w, "resultsArray");
  for (j = 0; j < 100; j++) {
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
      nqhash(alg, msg, tot, a, d);
      ml[i % 3] = d;
    }
    /* the last step (i = 999) wrote md[999 % 3] = md[0] */
    acvobj(w, NULL);
    acvkhex(w, "md", md[0], d);
    acvclose(w, '}');
    memcpy(md[1], md[0], d);
    memcpy(md[2], md[0], d);
    ml[0] = ml[1] = ml[2] = d;
  }
  acvclose(w, ']');
  return 1;
}

/* SHA-3, standard: MD[i] = H(MD[i-1]). */
static int s3mct(acvw *w, nqhalg alg, const nqjs *t) {
  uint8_t cur[MCTB], nxt[NQHMAX];
  size_t d = nqhlen(alg), cl, n, i, j;
  uint64_t bits;
  uint8_t *seed;
  if (!acvu(t, "len", &bits) || bits % 8 || bits / 8 > MCTB) return 0;
  cl = (size_t)(bits / 8);
  seed = acvhex(nqjget(t, "msg"), &n);
  if (seed == NULL || n < cl) {
    free(seed);
    return 0;
  }
  memcpy(cur, seed, cl);
  free(seed);
  acvarr(w, "resultsArray");
  for (j = 0; j < 100; j++) {
    for (i = 0; i < 1000; i++) {
      nqhash(alg, cur, cl, nxt, d);
      memcpy(cur, nxt, d);
      cl = d;
    }
    acvobj(w, NULL);
    acvkhex(w, "md", cur, d);
    acvclose(w, '}');
  }
  acvclose(w, ']');
  return 1;
}

/* SHAKE: Msg = the leftmost 128 bits of the previous output
 * (zero-padded), the next output length from its rightmost 16 bits. */
static int shkmct(acvw *w, nqhalg alg, const nqjs *g, const nqjs *t) {
  static uint8_t out[65536 / 8 + 2];
  uint8_t m[16];
  uint64_t bits, minb, maxb, rv;
  size_t lo, hi, range, ol, prev, n, i, j;
  uint8_t *seed;
  if (!acvu(t, "len", &bits) || bits % 8 || !acvu(g, "minOutLen", &minb) ||
      !acvu(g, "maxOutLen", &maxb) || minb % 8 || maxb % 8 || minb < 16 ||
      maxb < minb || maxb / 8 > sizeof out) {
    return 0;
  }
  lo = (size_t)(minb / 8);
  hi = (size_t)(maxb / 8);
  range = hi - lo + 1;
  seed = acvhex(nqjget(t, "msg"), &n);
  if (seed == NULL || n < bits / 8) {
    free(seed);
    return 0;
  }
  memset(out, 0, sizeof out);
  ol = (size_t)(bits / 8) < sizeof out ? (size_t)(bits / 8) : sizeof out;
  memcpy(out, seed, ol);
  free(seed);
  prev = ol;
  ol = hi;
  acvarr(w, "resultsArray");
  for (j = 0; j < 100; j++) {
    for (i = 0; i < 1000; i++) {
      memset(m, 0, sizeof m);
      memcpy(m, out, prev < 16 ? prev : 16);
      nqhash(alg, m, sizeof m, out, ol);
      rv = ((uint64_t)out[ol - 2] << 8) | out[ol - 1];
      prev = ol;
      ol = lo + (size_t)(rv % range);
    }
    acvobj(w, NULL);
    acvkhex(w, "md", out, prev);
    acvkint(w, "outLen", (uint64_t)prev * 8);
    acvclose(w, '}');
  }
  acvclose(w, ']');
  return 1;
}

/* LDT: the content repeated to fullLength bits */
static int ldt(acvw *w, nqhalg alg, const nqjs *t) {
  const nqjs *lm = nqjget(t, "largeMsg");
  const char *tech = acvs(lm, "expansionTechnique");
  uint64_t cbits, fbits, left;
  size_t cl, n, cs, i;
  uint8_t *c, *chunk, out[NQHMAX];
  nqfctx h;
  if (lm == NULL || tech == NULL || strcmp(tech, "repeating") != 0 ||
      !acvu(lm, "contentLength", &cbits) || !acvu(lm, "fullLength", &fbits) ||
      cbits == 0 || cbits % 8 || fbits % 8) {
    return 0;
  }
  cl = (size_t)(cbits / 8);
  c = acvhex(nqjget(lm, "content"), &n);
  if (c == NULL || n < cl) {
    free(c);
    return 0;
  }
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
  nqfini(&h, alg);
  for (left = fbits / 8; left > 0;) {
    size_t k = left > cs ? cs : (size_t)left;
    nqfupd(&h, chunk, k);
    left -= k;
  }
  nqffin(&h, out);
  free(chunk);
  acvkhex(w, "md", out, nqhlen(alg));
  return 1;
}

static int run(const nqjs *pr, acvw *w, long *omit) {
  const nqjs *gs = acvgrps(pr);
  const char *an = acvs(acvset(pr), "algorithm");
  int a = acvhalg(an), kind;
  size_t i, j;
  if (a < 0) {
    fprintf(stderr, "acvsh: algorithm %s is not a hash noqtis provides\n",
            an != NULL ? an : "(none)");
    return NQENOSUP;
  }
  kind = a >= NQSHK128 ? KSHK : a >= NQS3224 ? KS3 : KS2;
  for (i = 0; i < gs->n; i++) {
    const nqjs *g = nqjat(gs, i), *ts = nqjget(g, "tests");
    const char *tt = acvs(g, "testType");
    const char *mv = acvs(g, "mctVersion");
    int alt = mv != NULL && strcmp(mv, "alternate") == 0;
    uint64_t tg = 0;
    if (!acvu(g, "tgId", &tg) || tt == NULL || ts == NULL) {
      fprintf(stderr, "acvsh: group %lu: no tgId, testType or tests\n",
              (unsigned long)i);
      return NQEDEC;
    }
    if ((strcmp(tt, "LDT") == 0 && fast) ||
        (strcmp(tt, "MCT") == 0 && kind == KS3 && alt)) {
      fprintf(stderr, "acvsh: tgId %llu (%s%s) left out: %s\n",
              (unsigned long long)tg, tt, alt ? ", alternate" : "",
              alt ? "not implemented" : "NQFAST=1");
      *omit += (long)ts->n;
      continue;
    }
    acvgbeg(w, tg);
    for (j = 0; j < ts->n; j++) {
      const nqjs *t = nqjat(ts, j);
      uint64_t tc = 0;
      int ok = 0;
      if (!acvu(t, "tcId", &tc)) return NQEDEC;
      acvtbeg(w, tc);
      if (strcmp(tt, "AFT") == 0 || (strcmp(tt, "VOT") == 0 && kind == KSHK)) {
        ok = aft(w, (nqhalg)a, kind, t);
      } else if (strcmp(tt, "MCT") == 0) {
        ok = kind == KS2   ? s2mct(w, (nqhalg)a, t, alt)
             : kind == KS3 ? s3mct(w, (nqhalg)a, t)
                           : shkmct(w, (nqhalg)a, g, t);
      } else if (strcmp(tt, "LDT") == 0 && kind != KSHK) {
        ok = ldt(w, (nqhalg)a, t);
      }
      if (!ok) {
        fprintf(stderr, "acvsh: tgId %llu tcId %llu (%s): cannot answer\n",
                (unsigned long long)tg, (unsigned long long)tc, tt);
        return NQEDEC;
      }
      acvtend(w);
    }
    acvgend(w);
  }
  return NQOK;
}

int main(int argc, char **argv) {
  const char *f = getenv("NQFAST");
  fast = f != NULL && f[0] == '1';
  return acvmain(argc, argv, "acvsh", run);
}
