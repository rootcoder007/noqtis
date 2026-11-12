/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* dv: the noqtis side of the differential test against rmoriebricklayer
 * (tests/diff/run.sh; dv.R is the other side). Through the public API
 * only. One line per operation, its inputs then its outputs:
 *
 *   kk <kem> seed                  -> pk sk   key generation from a seed
 *   ke <kem> pk sk m               -> ct ss   encapsulation with the
 *                                             randomness m (HQC: m || salt)
 *   kd <kem> sk ct                 -> ss      decapsulation
 *   sk <sig> seed                  -> pk sk   key generation from a seed
 *   ss <sig> pk sk msg ctx ph rnd  -> sig     signing with the randomness rnd
 *   sv <sig> pk msg ctx ph sig     -> 01|00   verification (00 also for a
 *                                             refusal)
 *   h  <hash> msg                  -> md      digest (SHAKE: as many bytes as
 *                                             the line gives)
 *   hm <hash> key msg              -> mac     HMAC
 *
 * <kem>, <sig>: the names nqkname and nqsname give; <hash>: sha224,
 * sha256, sha384, sha512, sha512_224, sha512_256, sha3_224 ... sha3_512,
 * shake128, shake256. Every field is lowercase hex, "-" for an empty
 * input, and "-" for every output of an operation that was refused; ph
 * is "-" (pure) or a <hash> name. sk in ke and pk in ss are not used by
 * the operation: they let the other side cross-check a disagreement (the
 * other implementation's ciphertext decapsulated, its signature verified).
 *
 *   dv gen <alg>|hash <n> [<seed> [<first>]]
 *       cases first..n-1 (first 0) of one algorithm, with noqtis' outputs,
 *       on stdout. Each case is its own deterministic stream from the seed
 *       (default 20261112), the case number and the algorithm; cases 0-3
 *       use fixed seeds (all 00, all ff, 00 01 02 ..., ff fe fd ...).
 *   dv chk <file>
 *       recomputes every line with noqtis and compares its outputs; prints
 *       each difference, then "dv chk: <n> lines, <d> differ"; exit 1 on
 *       any difference or unreadable line. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"

typedef struct {
  uint8_t *p;
  size_t n;
  int no; /* an output: the operation was refused */
} fld;

static const struct {
  const char *name;
  nqhalg alg;
} hs[12] = {{"sha224", NQS224},         {"sha256", NQS256},
            {"sha384", NQS384},         {"sha512", NQS512},
            {"sha512_224", NQS512T224}, {"sha512_256", NQS512T256},
            {"sha3_224", NQS3224},      {"sha3_256", NQS3256},
            {"sha3_384", NQS3384},      {"sha3_512", NQS3512},
            {"shake128", NQSHK128},     {"shake256", NQSHK256}};

/* the hash of a name, 0 for "-" (pure), -1 for an unknown name */
static int hfind(const char *s) {
  int i;
  if (strcmp(s, "-") == 0) return 0;
  for (i = 0; i < 12; i++) {
    if (strcmp(s, hs[i].name) == 0) return (int)hs[i].alg;
  }
  return -1;
}

static void *xal(size_t n) {
  void *p = malloc(n + 1);
  if (p == NULL) {
    fprintf(stderr, "dv: out of memory\n");
    exit(2);
  }
  return p;
}

/* ---- the deterministic stream (splitmix64) ---- */

static uint64_t rs;

static uint64_t r64(void) {
  uint64_t z = (rs += 0x9E3779B97F4A7C15u);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9u;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBu;
  return z ^ (z >> 31);
}

static size_t ru(size_t n) { return n == 0 ? 0 : (size_t)(r64() % n); }

static void rb(uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) p[i] = (uint8_t)(r64() >> 56);
}

/* case i's bytes: a fixed pattern for i < 4, the stream after */
static void fill(uint8_t *p, size_t n, unsigned long i) {
  size_t j;
  for (j = 0; j < n; j++) {
    switch (i) {
    case 0: p[j] = 0; break;
    case 1: p[j] = 0xff; break;
    case 2: p[j] = (uint8_t)j; break;
    case 3: p[j] = (uint8_t)(0xff - j); break;
    default: p[j] = (uint8_t)(r64() >> 56); break;
    }
  }
}

static void setcase(uint64_t seed, const char *alg, unsigned long i) {
  uint64_t h = 1469598103934665603u;
  for (; *alg != '\0'; alg++) h = (h ^ (uint8_t)*alg) * 1099511628211u;
  rs = seed ^ h ^ ((uint64_t)i * 0xD1B54A32D192ED03u);
  (void)r64();
}

/* ---- one operation ---- */

static fld out[2];

static void oset(int k, size_t n) {
  free(out[k].p);
  out[k].p = xal(n);
  out[k].n = n;
  out[k].no = 0;
}

static void orej(int k) {
  free(out[k].p);
  out[k].p = NULL;
  out[k].n = 0;
  out[k].no = 1;
}

/* Runs op on alg with inputs in (ph: the pre-hash name of ss and sv; shk:
 * the SHAKE output length of h). Returns the number of outputs (in out),
 * or -1 for an unknown op or alg. */
static int run(const char *op, const char *alg, const fld *in,
               const char *ph, size_t shk) {
  int rc, hp;
  if (op[0] == 'k') {
    nqkalg ka;
    nqksz sz;
    if (nqkfind(alg, &ka) != NQOK || nqksize(ka, &sz) != NQOK) return -1;
    if (strcmp(op, "kk") == 0) {
      oset(0, sz.pk);
      oset(1, sz.sk);
      rc = nqkkgd(ka, in[0].p, in[0].n, out[0].p, sz.pk, out[1].p, sz.sk);
    } else if (strcmp(op, "ke") == 0) {
      oset(0, sz.ct);
      oset(1, sz.ss);
      rc = nqencd(ka, in[0].p, in[0].n, in[2].p, in[2].n, out[0].p, sz.ct,
                  out[1].p, sz.ss);
    } else if (strcmp(op, "kd") == 0) {
      oset(0, sz.ss);
      rc = nqdec(ka, in[0].p, in[0].n, in[1].p, in[1].n, out[0].p, sz.ss);
      if (rc != NQOK) orej(0);
      return 1;
    } else {
      return -1;
    }
    if (rc != NQOK) {
      orej(0);
      orej(1);
    }
    return 2;
  }
  if (op[0] == 's') {
    nqsalg sa;
    nqssz sz;
    size_t n = 0;
    if (nqsfind(alg, &sa) != NQOK || nqssize(sa, &sz) != NQOK) return -1;
    if (strcmp(op, "sk") == 0) {
      oset(0, sz.pk);
      oset(1, sz.sk);
      rc = nqskgd(sa, in[0].p, in[0].n, out[0].p, sz.pk, out[1].p, sz.sk);
      if (rc != NQOK) {
        orej(0);
        orej(1);
      }
      return 2;
    }
    hp = hfind(ph);
    if (strcmp(op, "ss") == 0) {
      oset(0, sz.sig);
      rc = hp < 0 ? NQEARG
                  : nqsignd(sa, in[1].p, in[1].n, in[2].p, in[2].n,
                            in[3].p, in[3].n, hp, in[4].p, in[4].n,
                            out[0].p, sz.sig, &n);
      if (rc != NQOK) {
        orej(0);
      } else {
        out[0].n = n;
      }
      return 1;
    }
    if (strcmp(op, "sv") == 0) {
      oset(0, 1);
      rc = hp < 0 ? NQEARG
                  : nqvrfy(sa, in[0].p, in[0].n, in[1].p, in[1].n,
                           in[2].p, in[2].n, hp, in[3].p, in[3].n);
      out[0].p[0] = rc == NQOK ? 1 : 0;
      return 1;
    }
    return -1;
  }
  hp = hfind(alg);
  if (hp <= 0) return -1;
  if (strcmp(op, "h") == 0) {
    size_t n = hp == NQSHK128 || hp == NQSHK256 ? shk : nqhlen((nqhalg)hp);
    oset(0, n);
    rc = nqhash((nqhalg)hp, in[0].p, in[0].n, out[0].p, n);
  } else if (strcmp(op, "hm") == 0) {
    size_t n = nqhlen((nqhalg)hp);
    oset(0, n);
    rc = nqhmac((nqhalg)hp, in[0].p, in[0].n, in[1].p, in[1].n, out[0].p,
                n);
  } else {
    return -1;
  }
  if (rc != NQOK) orej(0);
  return 1;
}

/* the number of inputs of op (ph not counted), -1 if unknown */
static int nins(const char *op) {
  static const struct {
    const char *op;
    int n;
  } t[8] = {{"kk", 1}, {"ke", 3}, {"kd", 2}, {"sk", 1},
            {"ss", 5}, {"sv", 4}, {"h", 1},  {"hm", 2}};
  int i;
  for (i = 0; i < 8; i++) {
    if (strcmp(op, t[i].op) == 0) return t[i].n;
  }
  return -1;
}

/* ---- gen ---- */

static void phex(const uint8_t *p, size_t n) {
  size_t i;
  putchar(' ');
  if (n == 0) {
    putchar('-');
    return;
  }
  for (i = 0; i < n; i++) printf("%02x", p[i]);
}

/* Runs op and prints its line. in: the inputs in the order of the line
 * (ss and sv: ph separately, after ctx). */
static void emit(const char *op, const char *alg, const fld *in, int nin,
                 const char *ph, size_t shk) {
  int i, no = run(op, alg, in, ph, shk);
  if (no < 0) {
    fprintf(stderr, "dv: %s %s: unknown\n", op, alg);
    exit(2);
  }
  printf("%s %s", op, alg);
  for (i = 0; i < nin; i++) {
    phex(in[i].p, in[i].n);
    if (ph != NULL && i == nin - 2) printf(" %s", ph);
  }
  for (i = 0; i < no; i++) {
    if (out[i].no) {
      printf(" -");
    } else {
      phex(out[i].p, out[i].n);
    }
  }
  putchar('\n');
}

static fld mk(size_t n) {
  fld f;
  f.p = xal(n);
  f.n = n;
  f.no = 0;
  return f;
}

static fld cp(const uint8_t *p, size_t n) {
  fld f = mk(n);
  if (n > 0) memcpy(f.p, p, n);
  return f;
}

static void fr(fld *f) {
  free(f->p);
  f->p = NULL;
  f->n = 0;
}

static void flip(fld *f) {
  if (f->n > 0) f->p[ru(f->n)] ^= (uint8_t)(1u << ru(8));
}

/* KEM case i: key generation, encapsulation, decapsulation of the
 * ciphertext, of tampered ones, and malformed keys and lengths */
static void gkem(const char *alg, unsigned long i) {
  nqkalg ka;
  nqksz sz;
  int hq;
  size_t sl, ml;
  fld in[3], pk, sk, ct, t;
  (void)nqkfind(alg, &ka);
  (void)nqksize(ka, &sz);
  hq = ka == NQHQC128 || ka == NQHQC192 || ka == NQHQC256;
  sl = hq ? 32 : 64;
  ml = hq ? (ka == NQHQC128 ? 16u : ka == NQHQC192 ? 24u : 32u) + 16u : 32;
  in[0] = mk(sl);
  fill(in[0].p, sl, i);
  emit("kk", alg, in, 1, NULL, 0);
  fr(&in[0]);
  if (out[0].no) return;
  pk = cp(out[0].p, out[0].n);
  sk = cp(out[1].p, out[1].n);
  in[0] = pk;
  in[1] = sk;
  in[2] = mk(ml);
  fill(in[2].p, ml, i);
  emit("ke", alg, in, 3, NULL, 0);
  ct = cp(out[0].p, out[0].n);
  in[0] = sk;
  in[1] = ct;
  emit("kd", alg, in, 2, NULL, 0);
  /* implicit rejection: one bit, the tail (HQC: the salt), all random */
  t = cp(ct.p, ct.n);
  flip(&t);
  in[1] = t;
  emit("kd", alg, in, 2, NULL, 0);
  t.p[t.n - 1 - ru(16)] ^= (uint8_t)(1u + ru(255));
  emit("kd", alg, in, 2, NULL, 0);
  rb(t.p, t.n);
  emit("kd", alg, in, 2, NULL, 0);
  fr(&t);
  /* wrong lengths */
  in[1] = ct;
  in[1].n = ct.n - 1;
  emit("kd", alg, in, 2, NULL, 0);
  in[0].n = sk.n - 1;
  in[1].n = ct.n;
  emit("kd", alg, in, 2, NULL, 0);
  in[0] = pk;
  in[0].n = pk.n - 1;
  in[1] = sk;
  emit("ke", alg, in, 3, NULL, 0);
  in[0].n = pk.n;
  /* a malformed public key: ML-KEM a coefficient >= q (FIPS 203 7.2);
   * HQC a bit set past the code length */
  t = cp(pk.p, pk.n);
  if (hq) {
    t.p[t.n - 1] |= 0x80;
  } else {
    size_t c = ru((pk.n - 32) / 3) * 3;
    unsigned v = 3329u + (unsigned)ru(4096 - 3329);
    if (ru(2) == 0) {
      t.p[c] = (uint8_t)v;
      t.p[c + 1] = (uint8_t)((t.p[c + 1] & 0xf0u) | (v >> 8));
    } else {
      t.p[c + 1] = (uint8_t)((t.p[c + 1] & 0x0fu) | ((v & 0xfu) << 4));
      t.p[c + 2] = (uint8_t)(v >> 4);
    }
  }
  in[0] = t;
  emit("ke", alg, in, 3, NULL, 0);
  fr(&t);
  /* tampered secret keys, each part in turn */
  in[1] = ct;
  if (hq) {
    /* pk || seed_dk || sigma || seed_kem */
    size_t off[4];
    int j;
    off[0] = ru(pk.n);
    off[1] = pk.n + ru(32);
    off[2] = pk.n + 32 + ru(ml - 16);
    off[3] = sk.n - 1 - ru(32);
    for (j = 0; j < 4; j++) {
      t = cp(sk.p, sk.n);
      t.p[off[j]] ^= (uint8_t)(1u << ru(8));
      in[0] = t;
      emit("kd", alg, in, 2, NULL, 0);
      fr(&t);
    }
  } else {
    /* dk_pke || ek || H(ek) || z: a coefficient of s >= q (FIPS 203
     * checks only the hash), ek, H(ek), z */
    size_t kp = (sk.n - 96) / 2, off[3];
    int j;
    t = cp(sk.p, sk.n);
    t.p[0] = 0xff;
    t.p[1] |= 0x0f;
    in[0] = t;
    emit("kd", alg, in, 2, NULL, 0);
    fr(&t);
    off[0] = kp + ru(kp + 32);
    off[1] = 2 * kp + 32 + ru(32);
    off[2] = sk.n - 1 - ru(32);
    for (j = 0; j < 3; j++) {
      t = cp(sk.p, sk.n);
      t.p[off[j]] ^= (uint8_t)(1u << ru(8));
      in[0] = t;
      emit("kd", alg, in, 2, NULL, 0);
      fr(&t);
    }
  }
  fr(&in[2]);
  fr(&pk);
  fr(&sk);
  fr(&ct);
}

/* ML-DSA layout: c~ bytes, l, k, omega, bytes per z polynomial, eta */
static int mdp(const char *alg, size_t *ctl, size_t *l, size_t *k,
               size_t *om, size_t *zb, unsigned *eta) {
  if (strcmp(alg, "ML-DSA-44") == 0) {
    *ctl = 32, *l = 4, *k = 4, *om = 80, *zb = 576, *eta = 2;
  } else if (strcmp(alg, "ML-DSA-65") == 0) {
    *ctl = 48, *l = 5, *k = 6, *om = 55, *zb = 640, *eta = 4;
  } else if (strcmp(alg, "ML-DSA-87") == 0) {
    *ctl = 64, *l = 7, *k = 8, *om = 75, *zb = 640, *eta = 2;
  } else {
    return 0;
  }
  return 1;
}

/* in: pk msg ctx sig, verified under ph */
static void ver(const char *alg, fld *in, const char *ph) {
  emit("sv", alg, in, 4, ph, 0);
}

/* signature case i */
static void gsig(const char *alg, unsigned long i) {
  nqsalg sa;
  nqssz sz;
  size_t sl, rl, ctl = 0, l = 0, k = 0, om = 0, zb = 0, j;
  unsigned eta = 0;
  int md;
  const char *ph = "-", *oph;
  fld in[5], pk, sk, msg, ctx, sig, t, v[4];
  (void)nqsfind(alg, &sa);
  (void)nqssize(sa, &sz);
  md = mdp(alg, &ctl, &l, &k, &om, &zb, &eta);
  sl = md ? 32 : sz.pk / 2 * 3;
  rl = md ? 32 : sz.pk / 2;
  in[0] = mk(sl);
  fill(in[0].p, sl, i);
  emit("sk", alg, in, 1, NULL, 0);
  fr(&in[0]);
  if (out[0].no) return;
  pk = cp(out[0].p, out[0].n);
  sk = cp(out[1].p, out[1].n);
  msg = mk(i % 7 == 6 ? 1000 + ru(4000) : i % 5 == 4 ? 0 : ru(256));
  rb(msg.p, msg.n);
  ctx = mk(i % 3 == 0 ? 0 : ru(256));
  rb(ctx.p, ctx.n);
  if (i % 4 == 3) ph = hs[ru(12)].name;
  /* deterministic (ML-DSA: rnd all zero; SLH-DSA: PK.seed), then hedged
   * (SLH-DSA: odd cases only) */
  in[0] = pk;
  in[1] = sk;
  in[2] = msg;
  in[3] = ctx;
  in[4] = mk(rl);
  if (md) {
    memset(in[4].p, 0, rl);
  } else {
    memcpy(in[4].p, pk.p, rl);
  }
  if (md || i % 2 == 0) {
    emit("ss", alg, in, 5, ph, 0);
    sig = cp(out[0].p, out[0].n);
  } else {
    sig = mk(0);
  }
  if (md || i % 2 == 1) {
    rb(in[4].p, rl);
    emit("ss", alg, in, 5, ph, 0);
    if (sig.n == 0 && !out[0].no) {
      fr(&sig);
      sig = cp(out[0].p, out[0].n);
    }
  }
  if (sig.n == 0) goto done;
  v[0] = pk;
  v[1] = msg;
  v[2] = ctx;
  v[3] = sig;
  ver(alg, v, ph);
  /* each input tampered, the lengths, the other variant */
  t = cp(sig.p, sig.n);
  flip(&t);
  v[3] = t;
  ver(alg, v, ph);
  t.n = sig.n - 1;
  memcpy(t.p, sig.p, t.n);
  v[3] = t;
  ver(alg, v, ph);
  fr(&t);
  t = mk(sig.n + 1);
  memcpy(t.p, sig.p, sig.n);
  t.p[sig.n] = 0;
  v[3] = t;
  ver(alg, v, ph);
  fr(&t);
  v[3] = sig;
  v[3].n = 0;
  ver(alg, v, ph);
  v[3] = sig;
  t = mk(msg.n + (msg.n == 0));
  memcpy(t.p, msg.p, msg.n);
  if (msg.n == 0) t.p[0] = 0;
  flip(&t);
  v[1] = t;
  ver(alg, v, ph);
  fr(&t);
  v[1] = msg;
  t = mk(ctx.n == 255 ? 254 : ctx.n + 1);
  memcpy(t.p, ctx.p, ctx.n < t.n ? ctx.n : t.n);
  if (t.n > ctx.n) t.p[ctx.n] = (uint8_t)ru(256);
  v[2] = t;
  ver(alg, v, ph);
  fr(&t);
  v[2] = ctx;
  t = cp(pk.p, pk.n);
  flip(&t);
  v[0] = t;
  ver(alg, v, ph);
  fr(&t);
  v[0] = pk;
  oph = strcmp(ph, "-") == 0 ? "sha256" : "-";
  ver(alg, v, oph);
  t = mk(256);
  rb(t.p, 256);
  v[2] = t;
  ver(alg, v, ph);
  v[2] = ctx;
  fr(&t);
  if (md) {
    /* the hint h: om indices, then k running counts (FIPS 204 alg. 21) */
    size_t hb = ctl + l * zb, tot = sig.p[hb + om + k - 1], c0 = 0, p;
    if (tot < om) { /* a nonzero byte after the last index */
      t = cp(sig.p, sig.n);
      t.p[hb + tot] = (uint8_t)(1u + ru(255));
      v[3] = t;
      ver(alg, v, ph);
      fr(&t);
    }
    for (p = 0; p < k; p++) { /* two indices of one polynomial swapped */
      size_t c1 = sig.p[hb + om + p];
      if (c1 >= c0 + 2 && c1 <= om) {
        uint8_t x;
        t = cp(sig.p, sig.n);
        x = t.p[hb + c0];
        t.p[hb + c0] = t.p[hb + c0 + 1];
        t.p[hb + c0 + 1] = x;
        v[3] = t;
        ver(alg, v, ph);
        fr(&t);
        break;
      }
      c0 = c1;
    }
    t = cp(sig.p, sig.n); /* a running count past omega */
    t.p[hb + om + ru(k)] = (uint8_t)(om + 1);
    v[3] = t;
    ver(alg, v, ph);
    fr(&t);
    if (k > 1 && sig.p[hb + om] > 0) { /* counts not monotone */
      t = cp(sig.p, sig.n);
      t.p[hb + om + 1] = (uint8_t)(t.p[hb + om] - 1);
      v[3] = t;
      ver(alg, v, ph);
      fr(&t);
    }
    /* z: the first coefficient of a random polynomial = gamma1, out of
     * range */
    t = cp(sig.p, sig.n);
    j = ctl + ru(l) * zb;
    t.p[j] = 0;
    t.p[j + 1] = 0;
    t.p[j + 2] &= zb == 576 ? 0xfc : 0xf0;
    v[3] = t;
    ver(alg, v, ph);
    fr(&t);
    v[3] = sig;
    /* signing with a malformed secret key: s1 coefficient out of
     * [-eta, eta]; tr changed */
    in[4].n = rl;
    rb(in[4].p, rl);
    t = cp(sk.p, sk.n);
    t.p[128] |= eta == 2 ? 0x07 : 0x0f;
    in[1] = t;
    emit("ss", alg, in, 5, ph, 0);
    fr(&t);
    t = cp(sk.p, sk.n);
    t.p[64 + ru(64)] ^= 1;
    in[1] = t;
    emit("ss", alg, in, 5, ph, 0);
    fr(&t);
    in[1] = sk;
  }
  if (i % 25 == 0) { /* refusals: ctx too long, rnd and sk lengths */
    fld c = mk(256);
    rb(c.p, 256);
    in[3] = c;
    emit("ss", alg, in, 5, ph, 0);
    in[3] = ctx;
    fr(&c);
    in[4].n = rl - 1;
    emit("ss", alg, in, 5, ph, 0);
    in[4].n = rl;
    in[1].n = sk.n - 1;
    emit("ss", alg, in, 5, ph, 0);
    in[1].n = sk.n;
  }
done:
  fr(&in[4]);
  fr(&pk);
  fr(&sk);
  fr(&msg);
  fr(&ctx);
  fr(&sig);
}

/* hash case i: every hash on one message (SHAKE: one output length),
 * HMAC with SHA-256 and SHA-512 on one key */
static void ghash(unsigned long i) {
  static const size_t ml[] = {0,   1,   55,  56,  63,  64,  65,  111,
                              112, 127, 128, 129, 135, 136, 137, 143,
                              144, 167, 168, 169, 1000, 4097};
  static const size_t ol[] = {1, 16, 32, 64, 136, 167, 168, 169, 500};
  static const size_t kl[] = {0, 1, 32, 64, 65, 128, 129, 200};
  const size_t nm = sizeof ml / sizeof ml[0], no = sizeof ol / sizeof ol[0],
               nk = sizeof kl / sizeof kl[0];
  fld in[2];
  int j;
  size_t sh = i < no ? ol[i] : 1 + ru(600);
  in[0] = mk(i < nm ? ml[i] : ru(700));
  rb(in[0].p, in[0].n);
  for (j = 0; j < 12; j++) emit("h", hs[j].name, in, 1, NULL, sh);
  in[1] = in[0];
  in[0] = mk(i < nk ? kl[i] : ru(300));
  rb(in[0].p, in[0].n);
  emit("hm", "sha256", in, 2, NULL, 0);
  emit("hm", "sha512", in, 2, NULL, 0);
  fr(&in[0]);
  fr(&in[1]);
}

static int gen(const char *alg, unsigned long n, uint64_t seed,
               unsigned long first) {
  nqkalg ka;
  nqsalg sa;
  unsigned long i;
  int kind = strcmp(alg, "hash") == 0             ? 'h'
             : nqkfind(alg, &ka) == NQOK           ? 'k'
             : nqsfind(alg, &sa) == NQOK           ? 's'
                                                   : 0;
  if (kind == 0) {
    fprintf(stderr, "dv: unknown algorithm %s\n", alg);
    return 2;
  }
  for (i = first; i < n; i++) {
    setcase(seed, alg, i);
    if (kind == 'h') {
      ghash(i);
    } else if (kind == 'k') {
      gkem(alg, i);
    } else {
      gsig(alg, i);
    }
  }
  return fflush(stdout) == 0 && !ferror(stdout) ? 0 : 2;
}

/* ---- chk ---- */

static int hexv(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* f: "-" or hex; returns 0 if neither */
static int unhex(const char *s, fld *f) {
  size_t n = strlen(s), j;
  f->p = NULL;
  f->no = 0;
  if (strcmp(s, "-") == 0) {
    f->p = xal(0);
    f->n = 0;
    f->no = 1;
    return 1;
  }
  if (n % 2 != 0) return 0;
  f->p = xal(n / 2);
  f->n = n / 2;
  for (j = 0; j < n / 2; j++) {
    int a = hexv(s[2 * j]), b = hexv(s[2 * j + 1]);
    if (a < 0 || b < 0) return 0;
    f->p[j] = (uint8_t)(a * 16 + b);
  }
  return 1;
}

/* the next line of f, without its line end, in *buf; NULL at the end */
static char *rdln(FILE *f, char **buf, size_t *cap) {
  size_t n = 0;
  int c;
  while ((c = getc(f)) != EOF && c != '\n') {
    if (n + 1 >= *cap) {
      char *b = realloc(*buf, *cap * 2);
      if (b == NULL) {
        fprintf(stderr, "dv: out of memory\n");
        exit(2);
      }
      *buf = b;
      *cap *= 2;
    }
    (*buf)[n++] = (char)c;
  }
  if (c == EOF && n == 0) return NULL;
  (*buf)[n] = '\0';
  return *buf;
}

static void show(const char *what, const fld *f) {
  size_t j;
  fprintf(stderr, "  %s: ", what);
  if (f->no) {
    fprintf(stderr, "refused\n");
    return;
  }
  for (j = 0; j < f->n && j < 32; j++) fprintf(stderr, "%02x", f->p[j]);
  fprintf(stderr, "%s (%lu bytes)\n", f->n > 32 ? "..." : "",
          (unsigned long)f->n);
}

static int chk(const char *path) {
  FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
  size_t cap = 1 << 16;
  char *buf = xal(cap), *ln;
  unsigned long nl = 0, nd = 0, nb = 0;
  if (f == NULL) {
    fprintf(stderr, "dv: cannot open %s\n", path);
    return 2;
  }
  while ((ln = rdln(f, &buf, &cap)) != NULL) {
    char *tok[12], *op, *alg, *ph = NULL;
    int nt = 0, ni, no, j, k, bad = 0;
    fld in[5] = {{NULL, 0, 0}}, ex[2] = {{NULL, 0, 0}};
    size_t shk = 0;
    if (ln[0] == '\0') continue;
    nl++;
    for (tok[nt] = strtok(ln, " "); tok[nt] != NULL && nt < 11;
         tok[nt] = strtok(NULL, " ")) {
      nt++;
    }
    ni = nt >= 2 ? nins(tok[0]) : -1;
    no = ni < 0 ? 0
         : strcmp(tok[0], "kk") == 0 || strcmp(tok[0], "ke") == 0 ||
                 strcmp(tok[0], "sk") == 0
             ? 2
             : 1;
    if (tok[0][0] == 's' && strcmp(tok[0], "sk") != 0) ni++; /* ph */
    if (ni < 0 || nt != 2 + ni + no) {
      fprintf(stderr, "dv: line %lu: unreadable\n", nl);
      nb++;
      continue;
    }
    op = tok[0];
    alg = tok[1];
    for (j = 0, k = 0; j < ni; j++) {
      if (tok[0][0] == 's' && strcmp(op, "sk") != 0 && j == ni - 2) {
        ph = tok[2 + j];
        continue;
      }
      if (!unhex(tok[2 + j], &in[k])) bad = 1;
      in[k].no = 0;
      k++;
    }
    for (j = 0; j < no; j++) {
      if (!unhex(tok[2 + ni + j], &ex[j])) bad = 1;
    }
    shk = ex[0].n;
    if (!bad && run(op, alg, in, ph, shk) != no) bad = 1;
    if (bad) {
      fprintf(stderr, "dv: line %lu: unreadable\n", nl);
      nb++;
    } else {
      for (j = 0; j < no; j++) {
        if (ex[j].no != out[j].no ||
            (!ex[j].no && (ex[j].n != out[j].n ||
                           memcmp(ex[j].p, out[j].p, ex[j].n) != 0))) {
          break;
        }
      }
      if (j < no) {
        nd++;
        fprintf(stderr, "DIFF line %lu: %s %s, output %d%s\n", nl, op, alg,
                j + 1,
                ex[j].no != out[j].no ? " (one side refused)" : "");
        show("rmoriebricklayer", &ex[j]);
        show("noqtis", &out[j]);
      }
    }
    for (j = 0; j < k; j++) free(in[j].p);
    for (j = 0; j < no; j++) free(ex[j].p);
  }
  if (f != stdin) fclose(f);
  free(buf);
  printf("dv chk: %lu lines, %lu differ%s\n", nl, nd,
         nb > 0 ? ", some unreadable" : "");
  return nd == 0 && nb == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc >= 4 && strcmp(argv[1], "gen") == 0) {
    return gen(argv[2], strtoul(argv[3], NULL, 10),
               argc > 4 ? (uint64_t)strtoull(argv[4], NULL, 10) : 20261112u,
               argc > 5 ? strtoul(argv[5], NULL, 10) : 0);
  }
  if (argc == 3 && strcmp(argv[1], "chk") == 0) return chk(argv[2]);
  fprintf(stderr, "usage: dv gen <alg>|hash <n> [<seed> [<first>]]\n"
                  "       dv chk <file>\n");
  return 2;
}
