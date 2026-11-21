/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The AES inverse cipher, AES Key Wrap (RFC 3394), AES-OCB (RFC 7253)
 * and AES-EAX: the published vectors, every length through three
 * blocks there and back, in place, a changed tag, text, nonce and
 * associated data refused with nothing given out, and the argument
 * checks. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "aead/aead.h"
#include "nqt.h"

static size_t hex(const char *s, uint8_t *o) {
  size_t n = 0;
  for (; s[0] != '\0' && s[1] != '\0'; s += 2) {
    unsigned a = (unsigned)(s[0] <= '9' ? s[0] - '0' : (s[0] | 32) - 'a' + 10);
    unsigned b = (unsigned)(s[1] <= '9' ? s[1] - '0' : (s[1] | 32) - 'a' + 10);
    o[n++] = (uint8_t)(a << 4 | b);
  }
  return n;
}

static void taes(void) {
  /* FIPS 197 appendix C */
  static const struct {
    size_t kl;
    const char *ct;
  } v[] = {{16, "69c4e0d86a7b0430d8cdb78070b4c55a"},
           {24, "dda97ca4864cdfe06eaf70a0ec0d7191"},
           {32, "8ea2b7ca516745bfeafc49904b496089"}};
  uint8_t key[32], pt[16], ct[16], x[16];
  nqaes k;
  size_t i, j;
  for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
  for (i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 0x11);
  for (i = 0; i < 3; i++) {
    NQTEQI(nqaesk(&k, key, v[i].kl), NQOK);
    hex(v[i].ct, ct);
    nqaes1(&k, pt, x);
    NQTEQM(x, ct, 16);
    nqaesd1(&k, ct, x);
    NQTEQM(x, pt, 16);
    /* in place, and many blocks there and back */
    for (j = 0; j < 64; j++) {
      memset(x, (int)(j * 37 + i), 16);
      x[j % 16] ^= (uint8_t)j;
      memcpy(ct, x, 16);
      nqaes1(&k, x, x);
      nqaesd1(&k, x, x);
      NQTEQM(x, ct, 16);
    }
  }
}

/* two blocks at once: each is the cipher of FIPS 197 appendix C. A
 * loop vectorizer once got the second block wrong (Apple clang 21 on
 * arm64), which no one-block test sees. */
static void taes2(void) {
  static const uint8_t want[3][16] = {
      {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
       0x70, 0xb4, 0xc5, 0x5a},
      {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0,
       0xec, 0x0d, 0x71, 0x91},
      {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90,
       0x4b, 0x49, 0x60, 0x89}};
  uint8_t key[32], in[32], out[32];
  nqaes k;
  size_t i, n;
  for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
  for (i = 0; i < 16; i++) in[i] = in[16 + i] = (uint8_t)(i * 0x11);
  for (n = 0; n < 3; n++) {
    NQTEQI(nqaesk(&k, key, 16 + 8 * n), NQOK);
    nqaes2(&k, in, out);
    NQTEQM(out, want[n], 16);
    NQTEQM(out + 16, want[n], 16);
    /* and in place */
    memcpy(out, in, 32);
    nqaes2(&k, out, out);
    NQTEQM(out, want[n], 16);
    NQTEQM(out + 16, want[n], 16);
  }
}

static void tkw(void) {
  /* RFC 3394 section 4 */
  static const struct {
    size_t kl, n;
    const char *ct;
  } v[] = {
      {16, 16, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
      {24, 16, "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
      {32, 16, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
      {24, 24,
       "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
      {32, 24,
       "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
      {32, 32,
       "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B"
       "FB988B9B7A02DD21"}};
  uint8_t kek[32], kd[32], w[48], want[48], back[40];
  size_t i, j;
  for (i = 0; i < 32; i++) kek[i] = (uint8_t)i;
  for (i = 0; i < 16; i++) kd[i] = (uint8_t)(i * 0x11);
  for (i = 0; i < 16; i++) kd[16 + i] = (uint8_t)i;
  for (i = 0; i < sizeof v / sizeof v[0]; i++) {
    NQTCHK(hex(v[i].ct, want) == v[i].n + 8);
    NQTEQI(nqkwrap(kek, v[i].kl, kd, v[i].n, w), NQOK);
    NQTEQM(w, want, v[i].n + 8);
    NQTEQI(nqkunwrap(kek, v[i].kl, w, v[i].n + 8, back), NQOK);
    NQTEQM(back, kd, v[i].n);
    /* any byte changed: no key */
    for (j = 0; j < v[i].n + 8; j++) {
      size_t z, nz = 0;
      w[j] ^= 0x40;
      memset(back, 0x5a, sizeof back);
      NQTEQI(nqkunwrap(kek, v[i].kl, w, v[i].n + 8, back), NQEVRFY);
      for (z = 0; z < v[i].n; z++) nz += back[z] != 0;
      NQTCHK(nz == 0);
      w[j] ^= 0x40;
    }
    /* another key-encryption key */
    kek[0] ^= 1;
    NQTEQI(nqkunwrap(kek, v[i].kl, w, v[i].n + 8, back), NQEVRFY);
    kek[0] ^= 1;
  }
  NQTEQI(nqkwrap(kek, 16, kd, 8, w), NQEARG);
  NQTEQI(nqkwrap(kek, 16, kd, 17, w), NQEARG);
  NQTEQI(nqkwrap(kek, 15, kd, 16, w), NQEARG);
  NQTEQI(nqkwrap(NULL, 16, kd, 16, w), NQEARG);
  NQTEQI(nqkwrap(kek, 16, NULL, 16, w), NQEARG);
  NQTEQI(nqkwrap(kek, 16, kd, 16, NULL), NQEARG);
  NQTEQI(nqkunwrap(kek, 16, w, 16, back), NQEARG);
  NQTEQI(nqkunwrap(kek, 16, w, 25, back), NQEARG);
  NQTEQI(nqkunwrap(kek, 15, w, 24, back), NQEARG);
  NQTEQI(nqkunwrap(NULL, 16, w, 24, back), NQEARG);
}

typedef int (*encf)(const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, size_t, const uint8_t *, size_t,
                    uint8_t *, uint8_t *);
typedef int (*decf)(const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, size_t, const uint8_t *, size_t,
                    const uint8_t *, uint8_t *);

/* one vector: ct is the ciphertext followed by the tag */
static void kat(encf e, decf d, const char *key, const char *nonce,
                const char *ad, const char *pt, const char *ct) {
  uint8_t k[32], n[16], a[64], p[64], c[80], o[64], t[16];
  size_t kl = hex(key, k), nl = hex(nonce, n), al = hex(ad, a),
         pl = hex(pt, p), cl = hex(ct, c);
  NQTCHK(cl == pl + 16);
  NQTEQI(e(k, kl, n, nl, a, al, p, pl, o, t), NQOK);
  NQTEQM(o, c, pl);
  NQTEQM(t, c + pl, 16);
  memset(o, 0, sizeof o);
  NQTEQI(d(k, kl, n, nl, a, al, c, pl, c + pl, o), NQOK);
  NQTEQM(o, p, pl);
}

/* every length to three blocks and a half, with and without
 * associated data, in place, and every way of being wrong */
static void sweep(encf e, decf d, size_t nl) {
  uint8_t k[32], n[16], a[56], p[56], c[56], o[56], t[16];
  size_t pl, al, i, kl;
  for (i = 0; i < sizeof k; i++) k[i] = (uint8_t)(0xa0 + i);
  for (i = 0; i < sizeof n; i++) n[i] = (uint8_t)(0x10 + i);
  for (i = 0; i < sizeof a; i++) a[i] = (uint8_t)(3 * i + 1);
  for (i = 0; i < sizeof p; i++) p[i] = (uint8_t)(7 * i + 5);
  for (kl = 16; kl <= 32; kl += 8) {
    for (pl = 0; pl <= sizeof p; pl += pl < 34 ? 1 : 11) {
      for (al = 0; al <= sizeof a; al += 19) {
        size_t nz = 0;
        NQTEQI(e(k, kl, n, nl, a, al, p, pl, c, t), NQOK);
        NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQOK);
        NQTEQM(o, p, pl);
        /* in place both ways */
        memcpy(o, p, pl);
        NQTEQI(e(k, kl, n, nl, a, al, o, pl, o, t), NQOK);
        NQTEQM(o, c, pl);
        NQTEQI(d(k, kl, n, nl, a, al, o, pl, t, o), NQOK);
        NQTEQM(o, p, pl);
        /* a wrong tag, text, associated data, nonce or key */
        t[5] ^= 1;
        memset(o, 0x77, sizeof o);
        NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQEVRFY);
        for (i = 0; i < pl; i++) nz += o[i] != 0 && o[i] != 0x77;
        NQTCHK(nz == 0);
        t[5] ^= 1;
        if (pl > 0) {
          c[pl - 1] ^= 0x80;
          NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQEVRFY);
          c[pl - 1] ^= 0x80;
        }
        if (al > 0) {
          a[0] ^= 2;
          NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQEVRFY);
          a[0] ^= 2;
        }
        n[nl - 1] ^= 1;
        NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQEVRFY);
        n[nl - 1] ^= 1;
        k[1] ^= 4;
        NQTEQI(d(k, kl, n, nl, a, al, c, pl, t, o), NQEVRFY);
        k[1] ^= 4;
      }
    }
  }
  NQTEQI(e(NULL, 16, n, nl, a, 0, p, 1, c, t), NQEARG);
  NQTEQI(e(k, 17, n, nl, a, 0, p, 1, c, t), NQEARG);
  NQTEQI(e(k, 16, n, nl, NULL, 1, p, 1, c, t), NQEARG);
  NQTEQI(e(k, 16, n, nl, a, 0, NULL, 1, c, t), NQEARG);
  NQTEQI(e(k, 16, n, nl, a, 0, p, 1, NULL, t), NQEARG);
  NQTEQI(e(k, 16, n, nl, a, 0, p, 1, c, NULL), NQEARG);
  NQTEQI(d(NULL, 16, n, nl, a, 0, c, 1, t, o), NQEARG);
  NQTEQI(d(k, 16, n, nl, a, 0, c, 1, NULL, o), NQEARG);
  NQTEQI(e(k, 16, n, nl, NULL, 0, NULL, 0, NULL, t), NQOK);
}

static void tocb(void) {
  /* RFC 7253 appendix A, AEAD_AES_128_OCB_TAGLEN128 */
  static const char key[] = "000102030405060708090A0B0C0D0E0F";
  uint8_t k[16], n[16], p[8], c[8], t[16];
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221100", "", "",
      "785407BFFFC8AD9EDCC5520AC9111EE6");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221101", "0001020304050607",
      "0001020304050607",
      "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221102", "0001020304050607",
      "", "81017F8203F081277152FADE694A0A00");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221103", "",
      "0001020304050607",
      "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221104",
      "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F",
      "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221105",
      "000102030405060708090A0B0C0D0E0F", "",
      "8CF761B6902EF764462AD86498CA6B97");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221106", "",
      "000102030405060708090A0B0C0D0E0F",
      "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221107",
      "000102030405060708090A0B0C0D0E0F1011121314151617",
      "000102030405060708090A0B0C0D0E0F1011121314151617",
      "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7"
      "F3C90BB0E07F");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221108",
      "000102030405060708090A0B0C0D0E0F1011121314151617", "",
      "6DC225A071FC1B9F7C69F93B0F1E10DE");
  kat(nqocbe, nqocbd, key, "BBAA99887766554433221109", "",
      "000102030405060708090A0B0C0D0E0F1011121314151617",
      "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C"
      "0B1EB38357FF");
  sweep(nqocbe, nqocbd, 12);
  sweep(nqocbe, nqocbd, 15);
  sweep(nqocbe, nqocbd, 1);
  /* a nonce of no bytes, and of a whole block */
  memset(k, 1, sizeof k);
  memset(n, 2, sizeof n);
  memset(p, 3, sizeof p);
  NQTEQI(nqocbe(k, 16, n, 0, NULL, 0, p, 8, c, t), NQEARG);
  NQTEQI(nqocbe(k, 16, n, 16, NULL, 0, p, 8, c, t), NQEARG);
  NQTEQI(nqocbe(k, 16, NULL, 12, NULL, 0, p, 8, c, t), NQEARG);
  NQTEQI(nqocbd(k, 16, n, 16, NULL, 0, c, 8, t, p), NQEARG);
}

static void teax(void) {
  /* Bellare, Rogaway, Wagner: The EAX Mode of Operation, appendix G */
  kat(nqeaxe, nqeaxd, "233952DEE4D5ED5F9B9C6D6FF80FF478",
      "62EC67F9C3A4A407FCB2A8C49031A8B3", "6BFB914FD07EAE6B", "",
      "E037830E8389F27B025A2D6527E79D01");
  kat(nqeaxe, nqeaxd, "91945D3F4DCBEE0BF45EF52255F095A4",
      "BECAF043B0A23D843194BA972C66DEBD", "FA3BFD4806EB53FA", "F7FB",
      "19DD5C4C9331049D0BDAB0277408F67967E5");
  kat(nqeaxe, nqeaxd, "01F74AD64077F2E704C0F60ADA3DD523",
      "70C3DB4F0D26368400A10ED05D2BFF5E", "234A3463C1264AC6", "1A47CB4933",
      "D851D5BAE03A59F238A23E39199DC9266626C40F80");
  sweep(nqeaxe, nqeaxd, 16);
  sweep(nqeaxe, nqeaxd, 7);
}

int main(void) {
  taes();
  taes2();
  tkw();
  tocb();
  teax();
  return nqtdone("tmode");
}
