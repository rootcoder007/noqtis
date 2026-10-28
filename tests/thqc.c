/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* HQC tests: the official known answers of the reference implementation
 * v5.0.0 (300 vectors, through the digests in vectors/hqc), round trips,
 * implicit rejection to the exact J value, the decoder at its capacity,
 * the polynomial product against a direct one, and the API's errors.
 *
 * NQHQKAT=n runs only the first n known answers of each set (for slow
 * runs under valgrind); the default is all of them. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"
#include "hash/h.h"
#include "hqc/hqc.h"
#include "hqc/hqci.h"
#include "nqt.h"

static const nqkalg algs[3] = {NQHQC128, NQHQC192, NQHQC256};
static const int lvls[3] = {1, 3, 5};

static uint8_t pk[NQHQPK5], sk[NQHQSK5], ct[NQHQCT5], bad[NQHQCT5];

/* ---- the KAT randomness ----
 * The reference's KAT generator seeds its randombytes per vector with the
 * 48-byte seed of the .rsp file: SHAKE256(seed || 0x00), squeezed in
 * order. Key generation draws seed_kem (32), encapsulation m (k bytes)
 * and then the salt (16). */
typedef struct {
  nqkctx k;
} kprng;

static void kpini(kprng *r, const uint8_t seed[48]) {
  const uint8_t z = 0;
  nqshkini(&r->k, 256);
  nqkabs(&r->k, seed, 48);
  nqkabs(&r->k, &z, 1);
}

static void kpget(kprng *r, uint8_t *out, size_t len) {
  nqksqz(&r->k, out, len);
}

static int alglv(long lv, nqkalg *alg) {
  switch (lv) {
  case 1: *alg = NQHQC128; return 0;
  case 3: *alg = NQHQC192; return 0;
  case 5: *alg = NQHQC256; return 0;
  default: return -1;
  }
}

/* one record; 1 when the digest and the decapsulation match */
static int katone(nqkalg alg, const uint8_t seed[48],
                  const uint8_t want[32]) {
  const nqhqp *p = nqhqpar(alg);
  kprng r;
  uint8_t ks[NQHQSEED], es[NQHQM5 + NQHQSALT], ss[32], ss2[32], dg[32];
  nqs2ctx h;
  int ok = 1;
  kpini(&r, seed);
  kpget(&r, ks, sizeof ks);
  kpget(&r, es, p->k + NQHQSALT);
  if (nqhqkgd(alg, ks, sizeof ks, pk, p->pk, sk, p->sk) != NQOK) ok = 0;
  if (nqhqencd(alg, pk, p->pk, es, p->k + NQHQSALT, ct, p->ct, ss, 32) !=
      NQOK) {
    ok = 0;
  }
  if (nqhqdec(alg, sk, p->sk, ct, p->ct, ss2, 32) != NQOK) ok = 0;
  if (memcmp(ss, ss2, 32) != 0) ok = 0;
  nqs2ini(&h, 32);
  nqs2upd(&h, pk, p->pk);
  nqs2upd(&h, sk, p->sk);
  nqs2upd(&h, ct, p->ct);
  nqs2upd(&h, ss, 32);
  nqs2fin(&h, dg);
  if (memcmp(dg, want, 32) != 0) ok = 0;
  return ok;
}

/* vectors/hqc/hqc-kat-digests.txt: '#' comments, a header line, then
 * "level count seed digest" per vector */
static void tkat(void) {
  char *buf = NULL, *line, *next;
  size_t len = 0;
  long lim = -1, run[3] = {0, 0, 0}, pass[3] = {0, 0, 0}, skip[3] = {0};
  int hdr = 0, i;
  const char *env = getenv("NQHQKAT");
  if (env != NULL && *env != '\0') lim = strtol(env, NULL, 10);
  if (nqreadf("vectors/hqc/hqc-kat-digests.txt", 1u << 20, &buf, &len) !=
      NQOK) {
    fprintf(stderr, "vectors/hqc/hqc-kat-digests.txt is missing\n");
    NQTCHK(0);
    return;
  }
  for (line = buf; line != NULL && *line != '\0'; line = next) {
    char hs[97], hd[65];
    long lv, cnt;
    uint8_t seed[48], dg[32];
    size_t n1 = 0, n2 = 0;
    nqkalg alg;
    int s;
    next = strchr(line, '\n');
    if (next != NULL) *next++ = '\0';
    /* a copy with Windows line endings still reads */
    if (*line != '\0' && line[strlen(line) - 1] == '\r') {
      line[strlen(line) - 1] = '\0';
    }
    if (line[0] == '#' || line[0] == '\0') continue;
    if (!hdr) {
      NQTCHK(strcmp(line, "level count seed digest") == 0);
      hdr = 1;
      continue;
    }
    if (sscanf(line, "%ld %ld %96s %64s", &lv, &cnt, hs, hd) != 4 ||
        alglv(lv, &alg) != 0 ||
        nqunhex(hs, strlen(hs), seed, sizeof seed, &n1) != NQOK ||
        nqunhex(hd, strlen(hd), dg, sizeof dg, &n2) != NQOK || n1 != 48 ||
        n2 != 32) {
      fprintf(stderr, "malformed KAT digest line\n");
      NQTCHK(0);
      continue;
    }
    s = lv == 1 ? 0 : lv == 3 ? 1 : 2;
    if (lim >= 0 && cnt >= lim) {
      skip[s]++;
      continue;
    }
    run[s]++;
    if (katone(alg, seed, dg)) {
      pass[s]++;
    } else {
      fprintf(stderr, "HQC-%ld KAT %ld fails\n", lv, cnt);
    }
    NQTCHK(1);
  }
  nqfree(buf, len + 1);
  for (i = 0; i < 3; i++) {
    printf("HQC-%d KAT: %ld run, %ld passed, %ld skipped\n", lvls[i],
           run[i], pass[i], skip[i]);
    NQTEQI(run[i], pass[i]);
    NQTEQI(run[i] + skip[i], 100);
  }
}

/* ---- sizes and errors ---- */

static void tsize(void) {
  static const size_t want[3][3] = {{NQHQPK1, NQHQSK1, NQHQCT1},
                                    {NQHQPK3, NQHQSK3, NQHQCT3},
                                    {NQHQPK5, NQHQSK5, NQHQCT5}};
  static const size_t ms[3] = {NQHQM1, NQHQM3, NQHQM5};
  nqksz sz;
  int i;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    NQTEQI(nqhqsz(algs[i], &sz), NQOK);
    NQTEQI(sz.pk, want[i][0]);
    NQTEQI(sz.sk, want[i][1]);
    NQTEQI(sz.ct, want[i][2]);
    NQTEQI(sz.ss, 32);
    NQTCHK(p != NULL);
    if (p == NULL) continue;
    NQTEQI(p->k, ms[i]);
    NQTEQI(p->pk, 32 + p->nb);
    NQTEQI(p->sk, p->pk + 64 + p->k);
    NQTEQI(p->ct, p->nb + p->vb + 16);
    NQTEQI(p->nw, (p->n + 63) / 64);
    NQTEQI(p->nb, (p->n + 7) / 8);
    NQTEQI(p->vw * 64, p->n1 * p->n2);
    NQTEQI(p->vb * 8, p->n1 * p->n2);
    NQTEQI(p->mu, (uint32_t)((((uint64_t)1) << 32) / p->n));
    NQTCHK(p->top == (((uint64_t)1) << (p->n % 64)) - 1);
    NQTEQI(p->n1 - p->k, 2 * p->dl);
  }
  NQTEQI(nqhqsz(NQMLKEM768, &sz), NQEARG);
  NQTEQI(nqhqsz(NQHQC128, NULL), NQEARG);
  NQTCHK(nqhqpar(NQMLKEM512) == NULL);
}

static void terr(void) {
  const nqhqp *p = nqhqpar(NQHQC128);
  uint8_t seed[32], es[40], ss[32], ss2[32];
  size_t offs[4], i;
  for (i = 0; i < 40; i++) {
    seed[i % 32] = (uint8_t)(i + 1);
    es[i] = (uint8_t)(3 * i);
  }
  NQTEQI(nqhqkgd(NQMLKEM512, seed, 32, pk, NQHQPK1, sk, NQHQSK1), NQEARG);
  NQTEQI(nqhqkgd(NQHQC128, NULL, 32, pk, NQHQPK1, sk, NQHQSK1), NQEARG);
  NQTEQI(nqhqkgd(NQHQC128, seed, 31, pk, NQHQPK1, sk, NQHQSK1), NQEARG);
  NQTEQI(nqhqkgd(NQHQC128, seed, 32, pk, NQHQPK1 - 1, sk, NQHQSK1),
         NQEBUF);
  NQTEQI(nqhqkgd(NQHQC128, seed, 32, pk, NQHQPK1, sk, NQHQSK1 - 1),
         NQEBUF);
  NQTEQI(nqhqkgd(NQHQC128, seed, 32, pk, NQHQPK1, sk, NQHQSK1), NQOK);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 31, ct, NQHQCT1, ss, 32),
         NQEARG);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 33, ct, NQHQCT1, ss, 32),
         NQEARG);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1 - 1, es, 32, ct, NQHQCT1, ss, 32),
         NQEDEC);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1 - 1, ss, 32),
         NQEBUF);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1, ss, 31),
         NQEBUF);
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1, NULL, 32),
         NQEARG);
  NQTEQI(nqhqencd(NQHQC192, pk, NQHQPK1, es, 40, ct, NQHQCT5, ss, 32),
         NQEDEC);
  NQTEQI(nqhqenc(NQMLKEM512, pk, NQHQPK1, ct, NQHQCT1, ss, 32), NQEARG);
  /* a bit set past the code length (n = 17669, 3 spare bits) */
  pk[NQHQPK1 - 1] ^= 0x80;
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1, ss, 32),
         NQEDEC);
  pk[NQHQPK1 - 1] ^= 0x80;
  pk[NQHQPK1 - 1] ^= 0x20;
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1, ss, 32),
         NQEDEC);
  pk[NQHQPK1 - 1] ^= 0x20;
  NQTEQI(nqhqencd(NQHQC128, pk, NQHQPK1, es, 32, ct, NQHQCT1, ss, 32),
         NQOK);
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1 - 1, ss2, 32), NQEDEC);
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1 + 1, ss2, 32), NQEDEC);
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1 - 1, ct, NQHQCT1, ss2, 32), NQEDEC);
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1, ss2, 31), NQEBUF);
  NQTEQI(nqhqdec(NQHQC128, NULL, NQHQSK1, ct, NQHQCT1, ss2, 32), NQEARG);
  NQTEQI(nqhqdec(NQMLKEM512, sk, NQHQSK1, ct, NQHQCT1, ss2, 32), NQEARG);
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1, ss2, 32), NQOK);
  NQTEQM(ss, ss2, 32);
  /* a secret key whose seeds were damaged: seed_ek, seed_dk, sigma and
   * seed_kem each, and a bit past n in its public half */
  offs[0] = 4;
  offs[1] = p->pk + 2;
  offs[2] = p->pk + 39;
  offs[3] = p->sk - 2;
  for (i = 0; i < 4; i++) {
    sk[offs[i]] ^= 1;
    NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1, ss2, 32), NQEDEC);
    sk[offs[i]] ^= 1;
  }
  sk[p->pk - 1] ^= 0x40;
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1, ss2, 32), NQEDEC);
  sk[p->pk - 1] ^= 0x40;
  NQTEQI(nqhqdec(NQHQC128, sk, NQHQSK1, ct, NQHQCT1, ss2, 32), NQOK);
  NQTEQM(ss, ss2, 32);
}

/* ---- round trips and implicit rejection ---- */

static void tround(void) {
  int i;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    uint8_t ss[32], ss2[32], ss3[32], pk2[NQHQPK5];
    NQTEQI(nqhqkg(algs[i], pk, p->pk, sk, p->sk), NQOK);
    NQTEQM(pk, sk, p->pk);
    NQTEQI(nqhqenc(algs[i], pk, p->pk, ct, p->ct, ss, 32), NQOK);
    NQTEQI(nqhqdec(algs[i], sk, p->sk, ct, p->ct, ss2, 32), NQOK);
    NQTEQM(ss, ss2, 32);
    NQTEQI(nqhqenc(algs[i], pk, p->pk, bad, p->ct, ss3, 32), NQOK);
    NQTCHK(memcmp(ss, ss3, 32) != 0);
    NQTCHK(memcmp(ct, bad, p->ct) != 0);
    NQTEQI(nqhqdec(algs[i], sk, p->sk, bad, p->ct, ss2, 32), NQOK);
    NQTEQM(ss3, ss2, 32);
    memcpy(pk2, pk, p->pk);
    NQTEQI(nqhqkg(algs[i], pk, p->pk, sk, p->sk), NQOK);
    NQTCHK(memcmp(pk, pk2, p->pk) != 0);
    /* larger output buffers are fine; only the sizes are written */
    NQTEQI(nqhqkg(algs[i], pk, sizeof pk, sk, sizeof sk), NQOK);
  }
}

/* a flipped bit in u, in v and in the salt gives exactly
 * J(H(ek) || sigma || c') = SHA3-256(SHA3-256(ek || 1) || sigma || c' ||
 * 3), every time */
static void treject(void) {
  int i, j;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    uint8_t seed[32], es[NQHQM5 + NQHQSALT], ss[32], ss2[32], ss3[32];
    uint8_t hek[32], kb[32], b1 = 1, b3 = 3;
    size_t pos[3];
    nqkctx k;
    for (j = 0; j < 32; j++) {
      seed[j] = (uint8_t)(j + 1);
    }
    for (j = 0; j < (int)p->k; j++) {
      es[j] = (uint8_t)(j + 1);
    }
    for (j = 0; j < 16; j++) {
      es[(int)p->k + j] = (uint8_t)(16 - j);
    }
    NQTEQI(nqhqkgd(algs[i], seed, 32, pk, p->pk, sk, p->sk), NQOK);
    NQTEQI(nqhqencd(algs[i], pk, p->pk, es, p->k + 16, ct, p->ct, ss, 32),
           NQOK);
    nqs3ini(&k, 256);
    nqkabs(&k, pk, p->pk);
    nqkabs(&k, &b1, 1);
    nqksqz(&k, hek, 32);
    pos[0] = 9;
    pos[1] = p->nb + 790;
    pos[2] = p->ct - 3;
    for (j = 0; j < 3; j++) {
      memcpy(bad, ct, p->ct);
      bad[pos[j]] ^= 4;
      nqs3ini(&k, 256);
      nqkabs(&k, hek, 32);
      nqkabs(&k, sk + p->pk + 32, p->k);
      nqkabs(&k, bad, p->ct);
      nqkabs(&k, &b3, 1);
      nqksqz(&k, kb, 32);
      NQTEQI(nqhqdec(algs[i], sk, p->sk, bad, p->ct, ss2, 32), NQOK);
      NQTEQM(ss2, kb, 32);
      NQTCHK(memcmp(ss2, ss, 32) != 0);
      NQTEQI(nqhqdec(algs[i], sk, p->sk, bad, p->ct, ss3, 32), NQOK);
      NQTEQM(ss2, ss3, 32);
    }
    /* a bit past n in u still decapsulates, to the rejection value */
    memcpy(bad, ct, p->ct);
    bad[p->nb - 1] ^= 0x80;
    NQTEQI(nqhqdec(algs[i], sk, p->sk, bad, p->ct, ss2, 32), NQOK);
    NQTCHK(memcmp(ss2, ss, 32) != 0);
    NQTEQI(nqhqdec(algs[i], sk, p->sk, ct, p->ct, ss2, 32), NQOK);
    NQTEQM(ss2, ss, 32);
  }
}

/* ---- the codes ---- */

/* a deterministic stream for the self-tests */
static uint64_t nx(nqkctx *k) {
  uint8_t b[8];
  nqksqz(k, b, 8);
  return nqld64l(b);
}

/* Reed-Solomon corrects any dl byte errors; the concatenated code
 * survives heavy damage to up to dl Reed-Muller blocks plus light noise
 * in the others (the reference's own self-test) */
static void tcode(void) {
  int i, t;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    nqkctx k;
    char lab[32];
    long badrs = 0, badcc = 0;
    snprintf(lab, sizeof lab, "hqc selftest %d", lvls[i]);
    nqshkini(&k, 256);
    nqkabs(&k, (const uint8_t *)lab, strlen(lab));
    for (t = 0; t < 60; t++) {
      uint8_t m[NQHQK], c[NQHQN1], dm[NQHQN1], out[NQHQK], ps[NQHQN1];
      uint8_t rsw[NQHQN1];
      uint64_t v[NQHQNW];
      size_t j, nerr, blk;
      for (j = 0; j < p->k; j++) {
        m[j] = (uint8_t)nx(&k);
      }
      nqhqrse(p, c, m);
      NQTEQM(c + 2 * p->dl, m, p->k);
      memcpy(dm, c, p->n1);
      for (j = 0; j < p->n1; j++) {
        ps[j] = (uint8_t)j;
      }
      /* exactly dl errors every fourth trial, otherwise up to dl */
      nerr = (t % 4 == 0) ? p->dl : (size_t)(nx(&k) % (p->dl + 1));
      for (j = 0; j < nerr; j++) {
        size_t r = j + (size_t)(nx(&k) % (p->n1 - j));
        uint8_t tmp = ps[j];
        ps[j] = ps[r];
        ps[r] = tmp;
        dm[ps[j]] ^= (uint8_t)(1 + nx(&k) % 255);
      }
      nqhqrsd(p, out, dm);
      if (memcmp(out, m, p->k) != 0) badrs++;
      nqhqrme(p, v, c);
      nqhqrmd(p, rsw, v);
      NQTEQM(rsw, c, p->n1);
      for (blk = 0; blk < p->n1; blk++) {
        int heavy = blk < p->dl && (nx(&k) & 1u);
        size_t fl = heavy ? p->n2 / 4 + (size_t)(nx(&k) % (p->n2 / 4))
                          : (size_t)(nx(&k) % 30), f;
        for (f = 0; f < fl; f++) {
          size_t bit = blk * p->n2 + (size_t)(nx(&k) % p->n2);
          v[bit / 64] ^= (uint64_t)1 << (bit % 64);
        }
      }
      nqhqrmd(p, rsw, v);
      nqhqrsd(p, out, rsw);
      if (memcmp(out, m, p->k) != 0) badcc++;
    }
    NQTEQI(badrs, 0);
    NQTEQI(badcc, 0);
  }
}

/* ---- the product ---- */

static int getb(const uint64_t *v, size_t i) {
  return (int)((v[i / 64] >> (i % 64)) & 1u);
}

/* nqhqmul against the direct cyclic product for a sparse a, and the
 * distributive law for dense operands */
static void tmul(void) {
  static uint64_t a[NQHQNW], b[NQHQNW], c[NQHQNW], o[NQHQNW], d[NQHQNW];
  static uint64_t e[NQHQNW];
  int i;
  for (i = 0; i < 3; i++) {
    const nqhqp *p = nqhqpar(algs[i]);
    size_t sup[24], j, q, n = p->n;
    nqkctx k;
    const uint8_t lab = (uint8_t)i;
    nqshkini(&k, 128);
    nqkabs(&k, &lab, 1);
    for (j = 0; j < p->nw; j++) {
      a[j] = 0;
      b[j] = nx(&k);
      c[j] = nx(&k);
      d[j] = 0;
    }
    b[p->nw - 1] &= p->top;
    c[p->nw - 1] &= p->top;
    /* positions at both ends of the vector and random ones */
    sup[0] = 0;
    sup[1] = n - 1;
    sup[2] = 63;
    sup[3] = 64;
    for (j = 4; j < 24; j++) {
      sup[j] = (size_t)(nx(&k) % n);
    }
    for (j = 0; j < 24; j++) {
      a[sup[j] / 64] ^= (uint64_t)1 << (sup[j] % 64);
    }
    /* d = sum of b rotated by each set position of a */
    for (j = 0; j < n; j++) {
      if (getb(a, j)) {
        for (q = 0; q < n; q++) {
          if (getb(b, q)) {
            size_t t = (q + j) % n;
            d[t / 64] ^= (uint64_t)1 << (t % 64);
          }
        }
      }
    }
    nqhqmul(p, o, a, b);
    NQTEQM(o, d, p->nw * 8);
    nqhqmul(p, o, b, a);
    NQTEQM(o, d, p->nw * 8);
    /* (a + c) b = a b + c b, b c = c b, and o may alias an operand */
    nqhqmul(p, e, c, b);
    for (j = 0; j < p->nw; j++) {
      d[j] ^= e[j];
      a[j] ^= c[j];
    }
    nqhqmul(p, o, a, b);
    NQTEQM(o, d, p->nw * 8);
    nqhqmul(p, o, b, c);
    NQTEQM(o, e, p->nw * 8);
    memcpy(o, b, p->nw * 8);
    nqhqmul(p, o, c, o);
    NQTEQM(o, e, p->nw * 8);
    NQTCHK((o[p->nw - 1] & ~p->top) == 0);
  }
}

int main(void) {
  tsize();
  tmul();
  tcode();
  terr();
  tround();
  treject();
  tkat();
  return nqtdone("thqc");
}
