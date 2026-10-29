/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Simulated TVLA: first-order leakage assessment of the masked ML-KEM
 * decapsulation and ML-DSA signing, on traces made by the code itself.
 *
 * The library is built with -DNQTVLA, which compiles the hooks of
 * core/lk.h: every share word the masked gadgets pass through their
 * opaque copies, every 64-bit lane of the masked Keccak, the share
 * polynomials after each linear step, the stored key as it is loaded and
 * split, and the unmasked output. A trace is one call; its samples are
 * those values in program order, each turned into two leakage models:
 *
 *   value      the Hamming weight of the value (HW)
 *   transition the Hamming distance from the value recorded before it
 *              (HD), the model of a register or bus that switches
 *
 * The test is TVLA (Goodwill et al. 2011; ISO/IEC 17825), fixed against
 * random: class 0 one secret key, class 1 a fresh random key for every
 * trace, the class drawn at random per trace. Welch's t at every sample,
 * in two independent sets of traces; a sample leaks when |t| > 4.5 in both
 * sets with the same sign. Public inputs are the same for both classes,
 * or random in both, so that only the key differs:
 *
 *   ML-KEM  one ciphertext, valid for the fixed key and so rejected
 *           (implicitly) under every random key
 *   ML-DSA  one mu; every input signs in one attempt (the number of
 *           attempts is public, and more would misalign the traces).
 *           Two tests: the key one (a fresh rnd in both classes, so y
 *           is random in both and only the key differs), and a nonce
 *           one, mldsa44y: one key, class 0 one rnd and so one y,
 *           class 1 a fresh rnd, which asks whether y, w and z leak.
 *           There w1 differs by class; it is public (the code reveals
 *           it), and the share words ANDed with constants made from it
 *           leak only those constants, so they are reported in a row of
 *           their own and not judged.
 *
 * A control runs each operation with every mask forced to zero (the
 * shares then hold the secret and its complement), which must be flagged;
 * if it is not, the harness cannot see a leak.
 *
 * This is a model, not a measurement: it sees the values the C code
 * hands to the hooks, not what a CPU does with them (registers the
 * compiler reuses, buses, glitches, the transitions inside a gadget).
 *
 *   nqtv [-n traces] [-s seed] [-o out.json] [-t name,...|all|list]
 *
 * Exit status: 0 no masked sample leaks in the value model and every
 * control is flagged, 1 otherwise, 2 usage. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/lk.h"
#include "mldsa/md.h"
#include "mldsa/mldsa.h"
#include "mlkem/mlkem.h"
#include "st.h"
#include "md1.h"

#define NSTEP 11 /* steps 0..10 of core/lk.h users */
#define NWHAT 7  /* NQLKOP .. NQLKPB, and 0 */

/* ---- the recorder ---- */

typedef struct {
  uint8_t *hw, *hd; /* this trace */
  uint8_t *tag;     /* step * 8 + what of each sample, from the traces */
  size_t n, cap, ntag;
  uint64_t prev;
  unsigned long mis; /* samples whose tag differs from earlier traces */
  int on;
} recst;

static recst R;

static void rec(uint64_t v, unsigned what, unsigned step) {
  uint8_t tg;
  if (!R.on || nqlkatt != 0) return;
  if (R.n == R.cap) {
    size_t c = R.cap ? 2 * R.cap : (size_t)1 << 16;
    uint8_t *a = (uint8_t *)realloc(R.hw, c), *b = (uint8_t *)realloc(R.hd, c);
    uint8_t *t = (uint8_t *)realloc(R.tag, c);
    if (a) R.hw = a;
    if (b) R.hd = b;
    if (t) R.tag = t;
    if (!a || !b || !t) {
      fprintf(stderr, "nqtv: out of memory\n");
      exit(2);
    }
    R.cap = c;
  }
  tg = (uint8_t)((step < NSTEP ? step : 0) * 8 + (what < NWHAT ? what : 0));
  R.hw[R.n] = (uint8_t)pop64(v);
  R.hd[R.n] = (uint8_t)pop64(v ^ R.prev);
  R.prev = v;
  if (R.n < R.ntag) {
    if (R.tag[R.n] != tg) R.mis++;
  } else {
    R.tag[R.n] = tg;
    R.ntag = R.n + 1;
  }
  R.n++;
}

/* ---- the moments, per sample, set (2), class (2) and model (2) ---- */

typedef struct {
  uint32_t *c[2][2];        /* traces with this sample */
  uint32_t *s[2][2][2];     /* [model][set][class] sum */
  uint32_t *q[2][2][2];     /* sum of squares */
  size_t cap;
} mom;

static void *grow(void *p, size_t old, size_t n) {
  uint8_t *q = (uint8_t *)realloc(p, n * sizeof(uint32_t));
  if (q == NULL) {
    fprintf(stderr, "nqtv: out of memory\n");
    exit(2);
  }
  memset(q + old * sizeof(uint32_t), 0, (n - old) * sizeof(uint32_t));
  return q;
}

static void madd(mom *m, int set, int cls) {
  size_t i;
  int md;
  if (R.n > m->cap) {
    size_t c = m->cap ? m->cap : 1;
    int a, b;
    while (c < R.n) c *= 2;
    for (a = 0; a < 2; a++) {
      for (b = 0; b < 2; b++) {
        m->c[a][b] = (uint32_t *)grow(m->c[a][b], m->cap, c);
        for (md = 0; md < 2; md++) {
          m->s[md][a][b] = (uint32_t *)grow(m->s[md][a][b], m->cap, c);
          m->q[md][a][b] = (uint32_t *)grow(m->q[md][a][b], m->cap, c);
        }
      }
    }
    m->cap = c;
  }
  for (i = 0; i < R.n; i++) m->c[set][cls][i]++;
  for (md = 0; md < 2; md++) {
    const uint8_t *x = md ? R.hd : R.hw;
    uint32_t *s = m->s[md][set][cls], *q = m->q[md][set][cls];
    for (i = 0; i < R.n; i++) {
      s[i] += x[i];
      q[i] += (uint32_t)x[i] * x[i];
    }
  }
}

static void mfree(mom *m) {
  int a, b, md;
  for (a = 0; a < 2; a++) {
    for (b = 0; b < 2; b++) {
      free(m->c[a][b]);
      for (md = 0; md < 2; md++) {
        free(m->s[md][a][b]);
        free(m->q[md][a][b]);
      }
    }
  }
  memset(m, 0, sizeof *m);
}

static double tat(const mom *m, int md, int set, size_t i) {
  return welts(m->c[set][0][i], m->s[md][set][0][i], m->q[md][set][0][i],
               m->c[set][1][i], m->s[md][set][1][i], m->q[md][set][1][i]);
}

/* ---- the operations ---- */

static xr G;
static uint8_t fk[8192], ft[4096], fm[64], fr[64], kb[8192], ob[8192];

typedef struct tv {
  const char *name, *what;
  int a;    /* k, or an nqsalg */
  int zm;   /* the control: masks forced to zero */
  int y;    /* ML-DSA: the nonce test, not the key test */
  unsigned div;
  void (*prep)(const struct tv *t);
  void (*run)(const struct tv *t, int cls);
} tv;

/* ML-KEM: a fixed key and a valid ciphertext for it */
static void pkem(const tv *t) {
  uint8_t s[NQMKSEED], m[NQMKMSG], ss[NQMKSS];
  xrfill(&G, s, sizeof s);
  xrfill(&G, m, sizeof m);
  nqmkkgd(t->a, s, sizeof s, kb, NQMKEK(t->a), fk, NQMKDK(t->a));
  nqmkencd(t->a, kb, NQMKEK(t->a), m, sizeof m, ft, NQMKCT(t->a), ss,
           sizeof ss);
}

static void rkem(const tv *t, int cls) {
  const uint8_t *dk = fk;
  if (cls) {
    uint8_t s[NQMKSEED];
    xrfill(&G, s, sizeof s);
    nqmkkgd(t->a, s, sizeof s, ob, NQMKEK(t->a), kb, NQMKDK(t->a));
    dk = kb;
  }
  nqlkzm = t->zm;
  nqlkatt = 0;
  R.on = 1;
  nqmkdec(t->a, dk, NQMKDK(t->a), ft, NQMKCT(t->a), ob, 32);
  R.on = 0;
  nqlkzm = 0;
}

/* an rnd for sk under which mu signs in one attempt */
static void onernd(const nqmdp *p, const uint8_t *sk, uint8_t *rnd) {
  do {
    xrfill(&G, rnd, NQMDRND);
  } while (!first(p, sk, fm, rnd));
}

/* ML-DSA: a fixed key, mu, and (for the nonce test) rnd */
static void pdsa(const tv *t) {
  const nqmdp *p = nqmdpar(t->a);
  uint8_t xi[NQMDSEED];
  xrfill(&G, xi, sizeof xi);
  xrfill(&G, fm, sizeof fm);
  nqmdkgd(t->a, xi, sizeof xi, ob, p->pk, fk, p->sk);
  onernd(p, fk, fr + 32);
}

static void rdsa(const tv *t, int cls) {
  const nqmdp *p = nqmdpar(t->a);
  const uint8_t *sk = fk;
  size_t ol;
  if (cls && !t->y) {
    uint8_t xi[NQMDSEED];
    xrfill(&G, xi, sizeof xi);
    nqmdkgd(t->a, xi, sizeof xi, ob, p->pk, kb, p->sk);
    sk = kb;
  }
  if (t->y && !cls) {
    memcpy(fr, fr + 32, NQMDRND);
  } else {
    onernd(p, sk, fr);
  }
  nqlkzm = t->zm;
  R.on = 1;
  nqmdsmu(t->a, sk, p->sk, fm, fr, NQMDRND, NQMDMASK, ob, p->sig, &ol);
  R.on = 0;
  nqlkzm = 0;
}

static const tv tvs[] = {
    {"mlkem512", "ML-KEM-512 masked decaps, one key vs random keys", 2, 0,
     0, 1, pkem, rkem},
    {"mlkem768", "ML-KEM-768 masked decaps, one key vs random keys", 3, 0,
     0, 1, pkem, rkem},
    {"mlkem1024", "ML-KEM-1024 masked decaps, one key vs random keys", 4,
     0, 0, 1, pkem, rkem},
    {"mldsa44", "ML-DSA-44 masked signing, one key vs random keys",
     NQMLDSA44, 0, 0, 4, pdsa, rdsa},
    {"mldsa65", "ML-DSA-65 masked signing, one key vs random keys",
     NQMLDSA65, 0, 0, 8, pdsa, rdsa},
    {"mldsa87", "ML-DSA-87 masked signing, one key vs random keys",
     NQMLDSA87, 0, 0, 8, pdsa, rdsa},
    {"mldsa44y", "ML-DSA-44 masked signing, one key: one rnd vs random rnd",
     NQMLDSA44, 0, 1, 4, pdsa, rdsa},
    {"mlkem768z", "control: ML-KEM-768 decaps, masks zero", 3, 1, 0, 4,
     pkem, rkem},
    {"mldsa44z", "control: ML-DSA-44 signing, key test, masks zero",
     NQMLDSA44, 1, 0, 8, pdsa, rdsa},
    {"mldsa44yz", "control: ML-DSA-44 signing, nonce test, masks zero",
     NQMLDSA44, 1, 1, 8, pdsa, rdsa},
};

/* ---- the analysis ---- */

/* the regions a result is given for: the key as it is loaded and split
 * (step 1, and any unmasked key value), the masked computation after
 * that (the judged part), share words ANDed with a public constant, and
 * the unmasked output (step 10 of ML-DSA unmasks z) */
#define RKEY 0
#define RMSK 1
#define RPUB 2
#define ROUT 3
#define NREG 4

static int region(unsigned step, unsigned what) {
  if (what == NQLKOUT || step == 10) return ROUT; /* ML-DSA: z unmasked */
  if (what == NQLKUN || step == 1) return RKEY;
  if (what == NQLKPB) return RPUB;
  return RMSK;
}

static const char *rnames[NREG] = {"key load and split",
                                   "masked (judged)", "share AND public",
                                   "output"};

static const char *wnames[NWHAT] = {"-", "share word", "Keccak lane",
                                    "share coefficient", "key (unmasked)",
                                    "output (unmasked)", "share AND public"};

/* per step and kind: samples, max |t| in either set, leaking points and
 * the largest |t| a leaking point has in both */
typedef struct {
  unsigned long n, skip, pts[2];
  double tx[2], tb[2];
} cell;

typedef struct {
  long traces;
  size_t samples;
  unsigned long mis, skip;
  cell r[NREG];
  cell c[NSTEP][NWHAT];
} out;

static void cadd(cell *c, int md, double a, double b) {
  const double mx = fabs(a) > fabs(b) ? fabs(a) : fabs(b);
  if (mx > c->tx[md]) c->tx[md] = mx;
  if (fabs(a) > NQTHR && fabs(b) > NQTHR && (a > 0) == (b > 0)) {
    const double mn = fabs(a) < fabs(b) ? fabs(a) : fabs(b);
    c->pts[md]++;
    if (mn > c->tb[md]) c->tb[md] = mn;
  }
}

/* a sample is assessed only when each class of each set has this many
 * traces, so that Welch's t is near normal; rarer samples (late in an
 * attempt few traces reach) are counted as skipped */
#define MINN 30

static void anal(const mom *m, out *o) {
  size_t i;
  int md;
  memset(o->c, 0, sizeof o->c);
  memset(o->r, 0, sizeof o->r);
  o->skip = 0;
  for (i = 0; i < R.ntag && i < m->cap; i++) {
    const unsigned st = R.tag[i] / 8u, wh = R.tag[i] % 8u;
    cell *c = &o->c[st][wh], *r = &o->r[region(st, wh)];
    if (m->c[0][0][i] < MINN || m->c[0][1][i] < MINN ||
        m->c[1][0][i] < MINN || m->c[1][1][i] < MINN) {
      c->skip++;
      r->skip++;
      o->skip++;
      continue;
    }
    c->n++;
    r->n++;
    for (md = 0; md < 2; md++) {
      const double a = tat(m, md, 0, i), b = tat(m, md, 1, i);
      cadd(c, md, a, b);
      cadd(r, md, a, b);
    }
  }
  o->samples = R.ntag;
  o->mis = R.mis;
}

static void ptab(const tv *t, const out *o) {
  int s, w;
  printf("\n%s: %s, %ld traces, %lu samples (first attempt)%s\n", t->name,
         t->what, o->traces, (unsigned long)o->samples,
         o->mis ? ", MISALIGNED" : "");
  printf("  %-4s %-18s %9s %7s %9s %7s %9s %7s\n", "step", "values",
         "samples", "skipped", "HW max|t|", "HW pts", "HD max|t|", "HD pts");
  for (s = 0; s < NSTEP; s++) {
    for (w = 0; w < NWHAT; w++) {
      const cell *c = &o->c[s][w];
      if (c->n + c->skip == 0) continue;
      printf("  %-4d %-18s %9lu %7lu %9.2f %7lu %9.2f %7lu\n", s, wnames[w],
             c->n, c->skip, c->tx[0], c->pts[0], c->tx[1], c->pts[1]);
    }
  }
  for (s = 0; s < NREG; s++) {
    const cell *c = &o->r[s];
    printf("  %-23s %9lu %7lu %9.2f %7lu %9.2f %7lu\n", rnames[s], c->n,
           c->skip, c->tx[0], c->pts[0], c->tx[1], c->pts[1]);
  }
  fflush(stdout);
}

static void jcell(FILE *f, const cell *c) {
  fprintf(f, "\"samples\": %lu, \"skipped\": %lu, \"hw\": {\"maxt\": "
             "%.3f, \"points\": %lu, \"pointt\": %.3f}, \"hd\": "
             "{\"maxt\": %.3f, \"points\": %lu, \"pointt\": %.3f}",
          c->n, c->skip, c->tx[0], c->pts[0], c->tb[0], c->tx[1], c->pts[1],
          c->tb[1]);
}

static void jtab(FILE *f, const tv *t, const out *o, int pass, int last) {
  static const char *rk[NREG] = {"key", "masked", "public", "output"};
  int s, w, first = 1;
  fprintf(f, "    {\"name\": \"%s\", \"what\": \"%s\", \"control\": "
             "%s, \"traces\": %ld, \"samples\": %lu, \"misaligned\": "
             "%lu, \"pass\": %s,\n",
          t->name, t->what, t->zm ? "true" : "false", o->traces,
          (unsigned long)o->samples, o->mis, pass ? "true" : "false");
  for (s = 0; s < NREG; s++) {
    fprintf(f, "     \"%s\": {", rk[s]);
    jcell(f, &o->r[s]);
    fprintf(f, "},\n");
  }
  fprintf(f, "     \"steps\": [");
  for (s = 0; s < NSTEP; s++) {
    for (w = 0; w < NWHAT; w++) {
      const cell *c = &o->c[s][w];
      if (c->n + c->skip == 0) continue;
      fprintf(f, "%s\n      {\"step\": %d, \"values\": \"%s\", ",
              first ? "" : ",", s, wnames[w]);
      jcell(f, c);
      fprintf(f, "}");
      first = 0;
    }
  }
  fprintf(f, "]}%s\n", last ? "" : ",");
}

static int pick(const char *sel, const char *name) {
  const char *p = sel;
  while (*p) {
    size_t n = strcspn(p, ",");
    if ((n == 3 && strncmp(p, "all", 3) == 0) ||
        (strlen(name) == n && strncmp(p, name, n) == 0)) {
      return 1;
    }
    p += n;
    if (*p == ',') p++;
  }
  return 0;
}

int main(int argc, char **argv) {
  const size_t nt = sizeof tvs / sizeof tvs[0];
  const char *sel = "all", *outf = NULL;
  unsigned long long seed = 1;
  long n = 4000, k;
  static out os[sizeof tvs / sizeof tvs[0]];
  int i, ran[sizeof tvs / sizeof tvs[0]], ok[sizeof tvs / sizeof tvs[0]];
  int bad = 0;
  size_t j, last = 0;
  FILE *f;
  for (i = 1; i < argc; i++) {
    if (i + 1 < argc && strcmp(argv[i], "-n") == 0) {
      n = atol(argv[++i]);
    } else if (i + 1 < argc && strcmp(argv[i], "-s") == 0) {
      seed = strtoull(argv[++i], NULL, 0);
    } else if (i + 1 < argc && strcmp(argv[i], "-o") == 0) {
      outf = argv[++i];
    } else if (i + 1 < argc && strcmp(argv[i], "-t") == 0) {
      sel = argv[++i];
    } else {
      fprintf(stderr, "usage: nqtv [-n traces] [-s seed] [-o out.json] "
                      "[-t name,...|all|list]\n");
      return 2;
    }
  }
  if (strcmp(sel, "list") == 0) {
    for (j = 0; j < nt; j++) {
      printf("%-10s N/%-2u %s\n", tvs[j].name, tvs[j].div, tvs[j].what);
    }
    return 0;
  }
  if (n < 100) n = 100;
  if (n > (1L << 19)) n = 1L << 19; /* the 32-bit sums of squares */
  printf("noqtis %s simulated TVLA: %ld traces (N/div per target), seed "
         "%llu, a point leaks at |t| > %.1f in both sets, same sign\n",
         nqver(), n, seed, NQTHR);
  nqlkfn = rec;
  for (j = 0; j < nt; j++) {
    const tv *t = &tvs[j];
    const long m = n / (long)t->div < 100 ? 100 : n / (long)t->div;
    mom mm;
    ran[j] = pick(sel, t->name);
    if (!ran[j]) continue;
    last = j;
    memset(&mm, 0, sizeof mm);
    memset(&R, 0, sizeof R);
    xrs(&G, seed + j);
    t->prep(t);
    for (k = 0; k < m; k++) {
      const uint64_t r = xr64(&G);
      R.n = 0;
      R.prev = 0;
      t->run(t, (int)(r & 1u));
      madd(&mm, (int)((r >> 1) & 1u), (int)(r & 1u));
    }
    os[j].traces = m;
    anal(&mm, &os[j]);
    ptab(t, &os[j]);
    /* a leak in the masked part (value model) fails; a control must
     * leak there */
    ok[j] = t->zm ? os[j].r[RMSK].pts[0] > 0
                  : os[j].r[RMSK].pts[0] == 0 && os[j].mis == 0;
    printf("  %s\n", ok[j] ? (t->zm ? "control flagged" : "pass")
                           : (t->zm ? "CONTROL NOT FLAGGED" : "FAIL"));
    bad |= !ok[j];
    mfree(&mm);
    free(R.hw);
    free(R.hd);
    free(R.tag);
    memset(&R, 0, sizeof R);
  }
  nqlkfn = NULL;
  if (outf != NULL) {
    f = strcmp(outf, "-") == 0 ? stdout : fopen(outf, "w");
    if (f == NULL) return 2;
    fprintf(f, "{\n  \"tool\": \"tvla\", \"noqtis\": \"%s\", \"traces\": "
               "%ld, \"seed\": %llu, \"threshold\": %.1f,\n  \"models\": "
               "[\"hw\", \"hd\"],\n  \"results\": [\n",
            nqver(), n, seed, NQTHR);
    for (j = 0; j < nt; j++) {
      if (ran[j]) jtab(f, &tvs[j], &os[j], ok[j], j == last);
    }
    fprintf(f, "  ]\n}\n");
    if (f != stdout) fclose(f);
  }
  return bad;
}
