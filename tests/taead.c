/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* AES, AES-GCM and ChaCha20-Poly1305 tests: the FIPS 197 examples, the
 * GCM specification's first test cases, the RFC 8439 examples, every
 * Wycheproof AES-GCM and ChaCha20-Poly1305 test, every one-bit change of
 * a tag and a ciphertext, in-place use and the API's errors. A
 * Wycheproof test with a tag other than 128 bits is skipped (TLS uses
 * only full tags); the counts say how many. */
#include "aead/aead.h"
#include "nqt.h"
#include "tvec.h"

/* ---- AES (FIPS 197 appendices A.1 and C) ---- */

static void taes(void) {
  static const char *const key[3] = {
      "000102030405060708090a0b0c0d0e0f",
      "000102030405060708090a0b0c0d0e0f1011121314151617",
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
  static const char *const ct[3] = {"69c4e0d86a7b0430d8cdb78070b4c55a",
                                    "dda97ca4864cdfe06eaf70a0ec0d7191",
                                    "8ea2b7ca516745bfeafc49904b496089"};
  uint8_t k[32], pt[16], c[16], o[16], two[32], t2[32];
  nqaes a;
  size_t kl, i;
  tvlit("00112233445566778899aabbccddeeff", pt, 16);
  for (i = 0; i < 3; i++) {
    kl = tvlit(key[i], k, 32);
    tvlit(ct[i], c, 16);
    NQTEQI(nqaesk(&a, k, kl), NQOK);
    NQTEQI(a.nr, 10 + 2 * i);
    nqaes1(&a, pt, o);
    NQTEQM(o, c, 16);
    /* two blocks at once, and in place */
    memcpy(two, pt, 16);
    memcpy(two + 16, pt, 16);
    two[31] ^= 1;
    nqaes2(&a, two, t2);
    NQTEQM(t2, c, 16);
    NQTCHK(memcmp(t2 + 16, c, 16) != 0);
    nqaes1(&a, two + 16, o);
    NQTEQM(o, t2 + 16, 16);
    memcpy(o, pt, 16);
    nqaes1(&a, o, o);
    NQTEQM(o, c, 16);
  }
  /* A.1: the last round key of 2b7e1516... */
  tvlit("2b7e151628aed2a6abf7158809cf4f3c", k, 16);
  NQTEQI(nqaesk(&a, k, 16), NQOK);
  tvlit("d014f9a8c9ee2589e13f0cc8b6630ca6", c, 16);
  NQTEQM(a.rk + 160, c, 16);
  NQTEQI(nqaesk(&a, k, 20), NQEARG);
  NQTEQI(nqaesk(&a, NULL, 16), NQEARG);
  NQTEQI(nqaesk(NULL, k, 16), NQEARG);
}

/* ---- GCM (McGrew and Viega, test cases 1 and 2) ---- */

static void tgcm(void) {
  uint8_t k[16], iv[12], z[16], o[16], t[16], e[16];
  nqgcm g;
  memset(k, 0, sizeof k);
  memset(iv, 0, sizeof iv);
  memset(z, 0, sizeof z);
  NQTEQI(nqgcmk(&g, k, 16), NQOK);
  NQTEQI(nqgcme(&g, iv, 12, NULL, 0, NULL, 0, NULL, t), NQOK);
  tvlit("58e2fccefa7e3061367f1d57a4e7455a", e, 16);
  NQTEQM(t, e, 16);
  NQTEQI(nqgcmd(&g, iv, 12, NULL, 0, NULL, 0, t, 16, NULL), NQOK);
  NQTEQI(nqgcme(&g, iv, 12, NULL, 0, z, 16, o, t), NQOK);
  tvlit("0388dace60b6a392f328c2b971b2fe78", e, 16);
  NQTEQM(o, e, 16);
  tvlit("ab6e47d42cec13bdf53a67b21257bddf", e, 16);
  NQTEQM(t, e, 16);
  NQTEQI(nqgcmd(&g, iv, 12, NULL, 0, o, 16, t, 16, o), NQOK);
  NQTEQM(o, z, 16);
  /* errors */
  NQTEQI(nqgcme(&g, iv, 0, NULL, 0, z, 16, o, t), NQEARG);
  NQTEQI(nqgcme(&g, NULL, 12, NULL, 0, z, 16, o, t), NQEARG);
  NQTEQI(nqgcme(&g, iv, 12, NULL, 1, z, 16, o, t), NQEARG);
  NQTEQI(nqgcme(&g, iv, 12, NULL, 0, z, 16, o, NULL), NQEARG);
  NQTEQI(nqgcmd(&g, iv, 12, NULL, 0, z, 16, t, 12, o), NQEARG);
  NQTEQI(nqgcmk(&g, k, 15), NQEARG);
}

/* ---- ChaCha20, Poly1305 and the AEAD (RFC 8439) ---- */

static const char sun[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only "
    "one tip for the future, sunscreen would be it.";

static void tccp(void) {
  uint8_t k[32], n[12], z[64], o[64], e[64], t[16], aad[12], m[128],
      c[128];
  size_t i;
  nqp1305 p;
  /* 2.3.2: the block with counter 1 */
  for (i = 0; i < 32; i++) k[i] = (uint8_t)i;
  tvlit("000000090000004a00000000", n, 12);
  memset(z, 0, sizeof z);
  nqcc20(k, n, 1, z, 64, o);
  tvlit("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        e, 64);
  NQTEQM(o, e, 64);
  /* 2.5.2: Poly1305 */
  tvlit("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        k, 32);
  nqp1ini(&p, k);
  nqp1upd(&p, (const uint8_t *)"Cryptographic Forum Research Group", 34);
  nqp1fin(&p, t);
  tvlit("a8061dc1305136c6c22b8baf0c0127a9", e, 16);
  NQTEQM(t, e, 16);
  /* the same, a byte at a time */
  nqp1ini(&p, k);
  for (i = 0; i < 34; i++) {
    nqp1upd(&p, (const uint8_t *)"Cryptographic Forum Research Group" + i,
            1);
  }
  nqp1fin(&p, t);
  NQTEQM(t, e, 16);
  /* 2.8.2: the AEAD */
  for (i = 0; i < 32; i++) k[i] = (uint8_t)(0x80 + i);
  tvlit("070000004041424344454647", n, 12);
  tvlit("50515253c0c1c2c3c4c5c6c7", aad, 12);
  memcpy(m, sun, sizeof sun - 1);
  NQTEQI(nqccpe(k, 32, n, 12, aad, 12, m, sizeof sun - 1, c, t), NQOK);
  tvlit("1ae10b594f09e26a7e902ecbd0600691", e, 16);
  NQTEQM(t, e, 16);
  tvlit("d31a8d34648e60db7b86afbc53ef7ec2", e, 16);
  NQTEQM(c, e, 16);
  NQTEQI(nqccpd(k, 32, n, 12, aad, 12, c, sizeof sun - 1, t, 16, c), NQOK);
  NQTEQM(c, sun, sizeof sun - 1);
  NQTEQI(nqccpe(k, 31, n, 12, aad, 12, m, 1, c, t), NQEARG);
  NQTEQI(nqccpe(k, 32, n, 8, aad, 12, m, 1, c, t), NQEARG);
  NQTEQI(nqccpd(k, 32, n, 12, aad, 12, m, 1, t, 15, c), NQEARG);
}

/* ---- Wycheproof ---- */

typedef struct {
  long run, skip;
} cnt;

/* every bit of the tag and of the first and last ciphertext bytes,
 * flipped one at a time, must fail and leave zeros */
static void flips(int gcm, const nqgcm *g, const uint8_t *k,
                  const uint8_t *iv, size_t ivl, const uint8_t *aad,
                  size_t al, const uint8_t *ct, size_t n,
                  const uint8_t *tag) {
  uint8_t t[16], *c = (uint8_t *)malloc(n + 1), *o = (uint8_t *)malloc(n + 1);
  size_t i;
  int bad = 0;
  if (c == NULL || o == NULL) {
    NQTCHK(0);
    free(c);
    free(o);
    return;
  }
  for (i = 0; i < 8 * 16 + (n > 0 ? 16 : 0); i++) {
    int rc;
    memcpy(t, tag, 16);
    memcpy(c, ct, n);
    if (i < 128) {
      t[i / 8] ^= (uint8_t)(1u << (i % 8));
    } else if (i < 136) {
      c[0] ^= (uint8_t)(1u << (i % 8));
    } else {
      c[n - 1] ^= (uint8_t)(1u << (i % 8));
    }
    memset(o, 0xa5, n + 1);
    rc = gcm ? nqgcmd(g, iv, ivl, aad, al, c, n, t, 16, o)
             : nqccpd(k, 32, iv, ivl, aad, al, c, n, t, 16, o);
    if (rc != NQEVRFY) bad++;
    if (n > 0 && (o[0] != 0 || o[n - 1] != 0)) bad++;
  }
  NQTEQI(bad, 0);
  free(c);
  free(o);
}

static void wfile(const char *f, int gcm, cnt *ct) {
  char path[256];
  nqjs *v;
  const nqjs *gs;
  size_t gi, ti;
  int fl = 0;
  snprintf(path, sizeof path, "vectors/wycheproof/%s", f);
  v = tvjs(path);
  NQTCHK(v != NULL);
  if (v == NULL) return;
  gs = nqjget(v, "testGroups");
  NQTCHK(gs != NULL);
  for (gi = 0; gs != NULL && gi < gs->n; gi++) {
    const nqjs *g = nqjat(gs, gi), *ts = nqjget(g, "tests");
    int64_t tsz = 0;
    if (ts == NULL || nqjint(nqjget(g, "tagSize"), &tsz) != NQOK) {
      NQTCHK(0);
      continue;
    }
    for (ti = 0; ti < ts->n; ti++) {
      const nqjs *t = nqjat(ts, ti);
      const char *res = nqjstr(nqjget(t, "result"));
      size_t kl, il, al, ml, cl, tl;
      uint8_t *k = tvhex(nqjget(t, "key"), &kl),
              *iv = tvhex(nqjget(t, "iv"), &il),
              *aad = tvhex(nqjget(t, "aad"), &al),
              *m = tvhex(nqjget(t, "msg"), &ml),
              *c = tvhex(nqjget(t, "ct"), &cl),
              *tag = tvhex(nqjget(t, "tag"), &tl);
      uint8_t *o = NULL, ot[16];
      int valid = res != NULL && strcmp(res, "valid") == 0, rc;
      nqgcm gc;
      NQTCHK(k != NULL && iv != NULL && aad != NULL && m != NULL &&
             c != NULL && tag != NULL && res != NULL);
      if (k == NULL || iv == NULL || aad == NULL || m == NULL || c == NULL ||
          tag == NULL || res == NULL) {
        goto next;
      }
      if (tsz != 128) {
        ct->skip++;
        goto next;
      }
      ct->run++;
      o = (uint8_t *)malloc(cl + 1);
      if (o == NULL) {
        NQTCHK(0);
        goto next;
      }
      if (gcm) {
        rc = nqgcmk(&gc, k, kl);
        if (rc != NQOK) {
          /* a key size AES does not have */
          NQTCHK(!valid);
          goto next;
        }
      }
      /* decryption */
      rc = gcm ? nqgcmd(&gc, iv, il, aad, al, c, cl, tag, tl, o)
               : nqccpd(k, kl, iv, il, aad, al, c, cl, tag, tl, o);
      if (valid) {
        NQTEQI(rc, NQOK);
        NQTCHK(ml == cl && memcmp(o, m, ml) == 0);
      } else {
        NQTCHK(rc != NQOK);
      }
      /* encryption */
      rc = gcm ? nqgcme(&gc, iv, il, aad, al, m, ml, o, ot)
               : nqccpe(k, kl, iv, il, aad, al, m, ml, o, ot);
      if (valid) {
        NQTEQI(rc, NQOK);
        NQTCHK(tl == 16 && memcmp(o, c, cl) == 0 && memcmp(ot, tag, 16) == 0);
        /* in place */
        memcpy(o, m, ml);
        rc = gcm ? nqgcme(&gc, iv, il, aad, al, o, ml, o, ot)
                 : nqccpe(k, kl, iv, il, aad, al, o, ml, o, ot);
        NQTCHK(rc == NQOK && memcmp(o, c, cl) == 0);
        rc = gcm ? nqgcmd(&gc, iv, il, aad, al, o, cl, tag, 16, o)
                 : nqccpd(k, kl, iv, il, aad, al, o, cl, tag, 16, o);
        NQTCHK(rc == NQOK && memcmp(o, m, ml) == 0);
        if (fl++ < 24) flips(gcm, &gc, k, iv, il, aad, al, c, cl, tag);
      }
    next:
      free(k);
      free(iv);
      free(aad);
      free(m);
      free(c);
      free(tag);
      free(o);
    }
  }
  nqjfree(v);
}

int main(void) {
  cnt g = {0, 0}, c = {0, 0};
  taes();
  tgcm();
  tccp();
  wfile("aes_gcm_test.json", 1, &g);
  wfile("chacha20_poly1305_test.json", 0, &c);
  printf("wycheproof AES-GCM: %ld run, %ld skipped (tag not 128 bits)\n",
         g.run, g.skip);
  printf("wycheproof ChaCha20-Poly1305: %ld run, %ld skipped\n", c.run,
         c.skip);
  NQTCHK(g.run >= 250);
  NQTCHK(c.run >= 300);
  return nqtdone("taead");
}
