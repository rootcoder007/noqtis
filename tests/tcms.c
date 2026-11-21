/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Certificates and CMS (nqx5self, nqx5kem, nqx5info, nqcmssign,
 * nqcmsvrfy, nqcmsenc, nqcmsdec): a certificate for each kind of key
 * and what it says; a SignedData with the content inside and detached,
 * by ML-DSA, SLH-DSA and Ed25519, verified against its anchor, another
 * anchor, another content, outside its validity, and with every part
 * changed; an AuthEnvelopedData to one and to three recipients, opened
 * by each, by a stranger, and changed; the worked example of RFC 9936
 * appendix C opened with its key; the same as S/MIME entities, with
 * the content inside and in the clear, line ends changed on the way,
 * signed and then encrypted; the refusals. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#define T0 1767225600 /* 2026-01-01T00:00:00Z */
#define YEAR 31536000

static uint8_t spk[2592], ssk[4896], opk[2592], osk[4896];
static uint8_t kpk[3][1568], ksk[3][3168];
static const nqkalg kalg[3] = {NQMLKEM512, NQMLKEM768, NQMLKEM1024};
static nqksz kz[3];
static uint8_t cert[8192], ocert[8192], kc[3][8192], big[1 << 17],
    out[1 << 17], msg[5000];
static size_t certn, ocertn, kcn[3];

static void keys(void) {
  uint8_t seed[64];
  nqssz z;
  int i;
  memset(seed, 0x41, sizeof seed);
  NQTEQI(nqskgd(NQMLDSA65, seed, 32, spk, 1952, ssk, 4032), NQOK);
  memset(seed, 0x42, sizeof seed);
  NQTEQI(nqskgd(NQMLDSA65, seed, 32, opk, 1952, osk, 4032), NQOK);
  for (i = 0; i < 3; i++) {
    memset(seed, 0x50 + i, sizeof seed);
    NQTEQI(nqksize(kalg[i], &kz[i]), NQOK);
    NQTEQI(nqkkgd(kalg[i], seed, 64, kpk[i], kz[i].pk, ksk[i], kz[i].sk),
           NQOK);
  }
  NQTEQI(nqssize(NQMLDSA65, &z), NQOK);
  NQTCHK(z.pk == 1952 && z.sk == 4032);
  for (i = 0; i < (int)sizeof msg; i++) msg[i] = (uint8_t)(i * 31 + 7);
}

static void tcert(void) {
  nqx5f f;
  size_t n = 0;
  int i;
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "Ada Example",
                  "ada@example.org", T0, T0 + YEAR, cert, 100, &n),
         NQEBUF);
  NQTCHK(n > 100 && n < sizeof cert);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "Ada Example",
                  "ada@example.org", T0, T0 + YEAR, cert, sizeof cert,
                  &certn),
         NQOK);
  NQTCHK(certn == n);
  NQTEQI(nqx5info(cert, certn, &f), NQOK);
  NQTCHK(f.kem == 0 && f.alg == (int)NQMLDSA65 && f.ca == 1);
  NQTCHK(f.nb == T0 && f.na == T0 + YEAR && f.pklen == 1952);
  NQTCHK(strcmp(f.name, "Ada Example") == 0);
  NQTCHK(strcmp(f.email, "ada@example.org") == 0);
  NQTEQM(cert + f.pkoff, spk, 1952);
  /* no address: none in the certificate */
  NQTEQI(nqx5self(NQMLDSA65, osk, 4032, opk, 1952, "Other", NULL, T0,
                  T0 + YEAR, ocert, sizeof ocert, &ocertn),
         NQOK);
  NQTEQI(nqx5info(ocert, ocertn, &f), NQOK);
  NQTCHK(strcmp(f.name, "Other") == 0 && f.email[0] == '\0');
  /* the KEM certificates, under the issuer's name and address */
  for (i = 0; i < 3; i++) {
    NQTEQI(nqx5kem(NQMLDSA65, ssk, 4032, cert, certn, kalg[i], kpk[i],
                   kz[i].pk, T0, T0 + YEAR, kc[i], sizeof kc[i], &kcn[i]),
           NQOK);
    NQTEQI(nqx5info(kc[i], kcn[i], &f), NQOK);
    NQTCHK(f.kem == 1 && f.alg == (int)kalg[i] && f.ca == 0);
    NQTCHK(f.pklen == kz[i].pk);
    NQTCHK(strcmp(f.name, "Ada Example") == 0);
    NQTCHK(strcmp(f.email, "ada@example.org") == 0);
    NQTEQM(kc[i] + f.pkoff, kpk[i], kz[i].pk);
  }
  /* the refusals */
  NQTEQI(nqx5self(NQMDED65, ssk, 4032, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQENOSUP);
  NQTEQI(nqx5self((nqsalg)999, ssk, 4032, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQENOSUP);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4031, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, osk, 4032, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "X", "nowhere", T0,
                  T0 + 1, out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "X", NULL, T0, T0, out,
                  sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, NULL, 4032, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5self(NQMLDSA65, ssk, 4032, spk, 1952, "X", NULL, T0, T0 + 1,
                  out, sizeof out, NULL),
         NQEARG);
  NQTEQI(nqx5kem(NQMLDSA65, osk, 4032, cert, certn, NQMLKEM768, kpk[1],
                 kz[1].pk, T0, T0 + 1, out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5kem(NQMLDSA65, ssk, 4032, kc[1], kcn[1], NQMLKEM768, kpk[1],
                 kz[1].pk, T0, T0 + 1, out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5kem(NQMLDSA65, ssk, 4032, cert, certn, NQHQC128, kpk[1],
                 kz[1].pk, T0, T0 + 1, out, sizeof out, &n),
         NQENOSUP);
  NQTEQI(nqx5kem(NQMLDSA65, ssk, 4032, cert, certn, NQMLKEM768, kpk[1],
                 kz[1].pk - 1, T0, T0 + 1, out, sizeof out, &n),
         NQEARG);
  NQTEQI(nqx5kem(NQMLDSA65, ssk, 4032, cert, certn - 1, NQMLKEM768, kpk[1],
                 kz[1].pk, T0, T0 + 1, out, sizeof out, &n),
         NQEDEC);
  NQTEQI(nqx5info(cert, certn - 1, &f), NQEDEC);
  NQTEQI(nqx5info(NULL, 0, &f), NQEARG);
  NQTEQI(nqx5info(cert, certn, NULL), NQEARG);
}

/* signs msg[0..n) with the algorithm alg (a key from a fixed seed, its
 * own certificate), checks it, and every way it must not check */
static void signwith(nqsalg alg, size_t n, int detached) {
  static uint8_t pk[2592], sk[4896], c[60000], other[8192];
  uint8_t seed[64];
  const uint8_t *anc[2];
  size_t ancl[2], cn = 0, sn = 0, on = 0, i, step;
  nqssz z;
  nqx5f f;
  NQTEQI(nqssize(alg, &z), NQOK);
  memset(seed, 0x60 + (int)alg, sizeof seed);
  NQTEQI(nqskgd(alg, seed, alg >= NQSLH128S && alg <= NQSLHK256F
                               ? 3 * z.pk / 2
                               : 32,
                pk, z.pk, sk, z.sk),
         NQOK);
  NQTEQI(nqx5self(alg, sk, z.sk, pk, z.pk, "Signer", "s@example.org", T0,
                  T0 + YEAR, c, sizeof c, &cn),
         NQOK);
  NQTEQI(nqcmssign(alg, sk, z.sk, c, cn, msg, n, detached, T0 + 60, big,
                   sizeof big, &sn),
         NQOK);
  anc[0] = c;
  ancl[0] = cn;
  memset(out, 0, n + 1);
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, 0, out, sizeof out, &on, &f),
         NQOK);
  NQTCHK(on == n);
  NQTEQM(out, msg, n);
  NQTCHK(f.alg == (int)alg && strcmp(f.name, "Signer") == 0);
  NQTCHK(strcmp(f.email, "s@example.org") == 0);
  /* the content given beside one that is inside: the same, or refused */
  if (!detached) {
    NQTEQI(nqcmsvrfy(big, sn, msg, n, anc, ancl, 1, 0, NULL, 0, &on, NULL),
           NQOK);
    if (n > 0) {
      msg[0] ^= 1;
      NQTEQI(nqcmsvrfy(big, sn, msg, n, anc, ancl, 1, 0, NULL, 0, &on, NULL),
             NQEVRFY);
      msg[0] ^= 1;
    }
  } else {
    NQTEQI(nqcmsvrfy(big, sn, NULL, 0, anc, ancl, 1, 0, NULL, 0, &on, NULL),
           NQEARG);
    if (n > 0) {
      msg[n - 1] ^= 1;
      NQTEQI(nqcmsvrfy(big, sn, msg, n, anc, ancl, 1, 0, NULL, 0, &on, NULL),
             NQEVRFY);
      msg[n - 1] ^= 1;
    }
  }
  /* an anchor that is not the signer's: no path */
  anc[0] = ocert;
  ancl[0] = ocertn;
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, 0, out, sizeof out, &on, &f),
         NQEVRFY);
  NQTCHK(on == 0 && f.name[0] == '\0');
  /* among several anchors */
  anc[1] = c;
  ancl[1] = cn;
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 2, 0, NULL, 0, &on, NULL),
         NQOK);
  anc[0] = c;
  ancl[0] = cn;
  /* before and after the certificate holds */
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, T0 - 86400, NULL, 0, &on, NULL),
         NQEVRFY);
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, T0 + YEAR + 86400, NULL, 0, &on, NULL),
         NQEVRFY);
  NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, T0 + 3600, NULL, 0, &on, NULL),
         NQOK);
  /* a smaller buffer than the content */
  if (n > 0) {
    NQTEQI(nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                     ancl, 1, 0, out, n - 1, &on, NULL),
           NQEBUF);
    NQTCHK(on == n);
  }
  /* bytes changed all through it: never accepted as it was */
  step = sn / 97 + 1;
  for (i = 0; i < sn; i += step) {
    int rc;
    big[i] ^= 0x20;
    rc = nqcmsvrfy(big, sn, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, 0, out, sizeof out, &on, NULL);
    NQTCHK(rc != NQOK || (on == n && memcmp(out, msg, n) == 0 && 0));
    big[i] ^= 0x20;
  }
  NQTEQI(nqcmsvrfy(big, sn - 1, detached ? msg : NULL, detached ? n : 0, anc,
                   ancl, 1, 0, NULL, 0, &on, NULL),
         NQEDEC);
  /* a key that is not the certificate's */
  memset(seed, 0x11, sizeof seed);
  if (alg == NQMLDSA65) {
    NQTEQI(nqcmssign(alg, osk, 4032, c, cn, msg, n, detached, T0, other,
                     sizeof other, &on),
           NQEARG);
  }
}

static void tsign(void) {
  const uint8_t *anc[1];
  size_t ancl[1], n = 0;
  signwith(NQMLDSA44, 0, 0);
  signwith(NQMLDSA44, 1, 1);
  signwith(NQMLDSA65, sizeof msg, 0);
  signwith(NQMLDSA65, sizeof msg, 1);
  signwith(NQMLDSA87, 300, 0);
  signwith(NQSLH128F, 300, 0);
  signwith(NQSLHK128F, 300, 1);
  signwith(NQED25519, 300, 0);
  signwith(NQED25519, 0, 1);
  anc[0] = cert;
  ancl[0] = certn;
  /* the refusals */
  NQTEQI(nqcmssign(NQMDED65, ssk, 4032, cert, certn, msg, 4, 0, T0, big,
                   sizeof big, &n),
         NQENOSUP);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, kc[1], kcn[1], msg, 4, 0, T0, big,
                   sizeof big, &n),
         NQEARG);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, cert, certn - 2, msg, 4, 0, T0, big,
                   sizeof big, &n),
         NQEDEC);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, cert, certn, msg, 4, 0, T0, big, 50,
                   &n),
         NQEBUF);
  NQTCHK(n > 50);
  NQTEQI(nqcmssign(NQMLDSA65, NULL, 4032, cert, certn, msg, 4, 0, T0, big,
                   sizeof big, &n),
         NQEARG);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, cert, certn, NULL, 4, 0, T0, big,
                   sizeof big, &n),
         NQEARG);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, cert, certn, msg, 4, 0, -1, big,
                   sizeof big, &n),
         NQEARG);
  NQTEQI(nqcmssign(NQMLDSA65, ssk, 4032, cert, certn, msg, 4, 0, T0, big,
                   sizeof big, &n),
         NQOK);
  NQTEQI(nqcmsvrfy(NULL, n, NULL, 0, anc, ancl, 1, 0, NULL, 0, &n, NULL),
         NQEARG);
  NQTEQI(nqcmsvrfy(big, n, NULL, 0, NULL, ancl, 1, 0, NULL, 0, &n, NULL),
         NQEARG);
  NQTEQI(nqcmsvrfy(big, n, NULL, 0, anc, ancl, 0, 0, NULL, 0, &n, NULL),
         NQEARG);
  NQTEQI(nqcmsvrfy(big, n, NULL, 0, anc, ancl, 1, 0, NULL, 9, &n, NULL),
         NQEARG);
  /* what is not a SignedData at all */
  NQTEQI(nqcmsvrfy(cert, certn, NULL, 0, anc, ancl, 1, 0, NULL, 0, &n, NULL),
         NQEDEC);
  NQTEQI(nqcmsvrfy((const uint8_t *)"", 0, NULL, 0, anc, ancl, 1, 0, NULL, 0,
                   &n, NULL),
         NQEDEC);
}

static void tenc(void) {
  const uint8_t *rc[3];
  size_t rl[3], n = 0, on = 0, i, step;
  int k;
  for (k = 0; k < 3; k++) {
    rc[k] = kc[k];
    rl[k] = kcn[k];
  }
  /* to each alone, and to all three */
  for (k = 0; k < 3; k++) {
    NQTEQI(nqcmsenc(rc + k, rl + k, 1, msg, 777, big, sizeof big, &n), NQOK);
    memset(out, 0, 800);
    NQTEQI(nqcmsdec(kalg[k], ksk[k], kz[k].sk, kc[k], kcn[k], big, n, out,
                    sizeof out, &on),
           NQOK);
    NQTCHK(on == 777);
    NQTEQM(out, msg, 777);
    NQTEQI(nqcmsdec(kalg[k], ksk[k], kz[k].sk, NULL, 0, big, n, out,
                    sizeof out, &on),
           NQOK);
    /* another recipient's key and certificate: not for it */
    NQTEQI(nqcmsdec(kalg[(k + 1) % 3], ksk[(k + 1) % 3], kz[(k + 1) % 3].sk,
                    kc[(k + 1) % 3], kcn[(k + 1) % 3], big, n, out,
                    sizeof out, &on),
           NQEVRFY);
    NQTCHK(on == 0);
    NQTEQI(nqcmsdec(kalg[(k + 1) % 3], ksk[(k + 1) % 3], kz[(k + 1) % 3].sk,
                    NULL, 0, big, n, out, sizeof out, &on),
           NQEVRFY);
  }
  NQTEQI(nqcmsenc(rc, rl, 3, msg, sizeof msg, big, sizeof big, &n), NQOK);
  for (k = 0; k < 3; k++) {
    memset(out, 0, sizeof msg);
    NQTEQI(nqcmsdec(kalg[k], ksk[k], kz[k].sk, kc[k], kcn[k], big, n, out,
                    sizeof out, &on),
           NQOK);
    NQTCHK(on == sizeof msg);
    NQTEQM(out, msg, sizeof msg);
  }
  /* the recipients come in the order of their encodings (a SET OF) */
  NQTEQI(nqcmsdec(kalg[1], ksk[1], kz[1].sk, kc[1], kcn[1], big, n, out, 10,
                  &on),
         NQEBUF);
  NQTCHK(on == sizeof msg);
  /* changed all through: never the plaintext */
  step = n / 131 + 1;
  for (i = 0; i < n; i += step) {
    int r;
    big[i] ^= 0x04;
    r = nqcmsdec(kalg[1], ksk[1], kz[1].sk, kc[1], kcn[1], big, n, out,
                 sizeof out, &on);
    NQTCHK(r != NQOK || (on == sizeof msg && memcmp(out, msg, on) == 0));
    big[i] ^= 0x04;
  }
  NQTEQI(nqcmsdec(kalg[1], ksk[1], kz[1].sk, kc[1], kcn[1], big, n - 1, out,
                  sizeof out, &on),
         NQEDEC);
  /* nothing to encrypt */
  NQTEQI(nqcmsenc(rc + 1, rl + 1, 1, NULL, 0, big, sizeof big, &n), NQOK);
  NQTEQI(nqcmsdec(kalg[1], ksk[1], kz[1].sk, kc[1], kcn[1], big, n, out,
                  sizeof out, &on),
         NQOK);
  NQTCHK(on == 0);
  /* the refusals */
  rc[0] = cert;
  rl[0] = certn;
  NQTEQI(nqcmsenc(rc, rl, 1, msg, 4, big, sizeof big, &n), NQEARG);
  rc[0] = kc[0];
  rl[0] = kcn[0];
  NQTEQI(nqcmsenc(rc, rl, 0, msg, 4, big, sizeof big, &n), NQEARG);
  NQTEQI(nqcmsenc(rc, rl, 33, msg, 4, big, sizeof big, &n), NQEARG);
  NQTEQI(nqcmsenc(NULL, rl, 1, msg, 4, big, sizeof big, &n), NQEARG);
  NQTEQI(nqcmsenc(rc, rl, 1, NULL, 4, big, sizeof big, &n), NQEARG);
  NQTEQI(nqcmsenc(rc, rl, 1, msg, 4, big, 20, &n), NQEBUF);
  NQTCHK(n > 20);
  NQTEQI(nqcmsenc(rc, rl, 1, msg, 4, big, sizeof big, &n), NQOK);
  NQTEQI(nqcmsdec(NQHQC128, ksk[0], kz[0].sk, NULL, 0, big, n, out,
                  sizeof out, &on),
         NQENOSUP);
  NQTEQI(nqcmsdec(kalg[0], ksk[0], kz[0].sk - 1, NULL, 0, big, n, out,
                  sizeof out, &on),
         NQEARG);
  NQTEQI(nqcmsdec(kalg[0], NULL, kz[0].sk, NULL, 0, big, n, out, sizeof out,
                  &on),
         NQEARG);
  NQTEQI(nqcmsdec(kalg[0], ksk[0], kz[0].sk, NULL, 0, NULL, n, out,
                  sizeof out, &on),
         NQEARG);
  NQTEQI(nqcmsdec(kalg[0], ksk[0], kz[0].sk, NULL, 0, cert, certn, out,
                  sizeof out, &on),
         NQEDEC);
}

/* S/MIME: the same as MIME entities */
static void tsmime(void) {
  static const char ent[] =
      "Content-Type: text/plain; charset=utf-8\n\nHello,\nsigned mail.\n";
  static const char crlf[] = "Content-Type: text/plain; charset=utf-8\r\n"
                             "\r\nHello,\r\nsigned mail.\r\n";
  static char m[1 << 16], m2[1 << 17], o[1 << 16];
  const uint8_t *anc[1], *rc[2];
  size_t ancl[1], rl[2], n = 0, on = 0, n2 = 0, i, k;
  nqx5f f;
  anc[0] = cert;
  ancl[0] = certn;
  /* the content inside */
  NQTEQI(nqsmsign(NQMLDSA65, ssk, 4032, cert, certn, ent, sizeof ent - 1, 0,
                  T0 + 60, m, sizeof m, &n),
         NQOK);
  NQTCHK(memcmp(m, "MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime;"
                   " smime-type=signed-data;", 81) == 0);
  NQTEQI(nqsmvrfy(m, n, anc, ancl, 1, 0, o, sizeof o, &on, &f), NQOK);
  /* what was signed is the entity with CRLF line ends */
  NQTCHK(on == sizeof crlf - 1);
  NQTEQM(o, crlf, on);
  NQTCHK(strcmp(f.name, "Ada Example") == 0);
  /* detached: the text is there to read */
  NQTEQI(nqsmsign(NQMLDSA65, ssk, 4032, cert, certn, ent, sizeof ent - 1, 1,
                  T0 + 60, m, sizeof m, &n),
         NQOK);
  NQTCHK(memcmp(m, "MIME-Version: 1.0\r\nContent-Type: multipart/signed;", 51)
         == 0);
  NQTCHK(strstr(m, "micalg=sha-512") != NULL);
  NQTCHK(strstr(m, "\r\nHello,\r\nsigned mail.\r\n") != NULL);
  NQTEQI(nqsmvrfy(m, n, anc, ancl, 1, 0, o, sizeof o, &on, &f), NQOK);
  NQTCHK(on == sizeof crlf - 1);
  NQTEQM(o, crlf, on);
  /* a message whose line ends became LF on the way still verifies */
  for (i = 0, k = 0; i < n; i++) {
    if (m[i] != '\r') m2[k++] = m[i];
  }
  NQTEQI(nqsmvrfy(m2, k, anc, ancl, 1, 0, o, sizeof o, &on, NULL), NQOK);
  NQTCHK(on == sizeof crlf - 1);
  /* one letter of the text changed */
  {
    char *h = strstr(m, "Hello");
    NQTCHK(h != NULL);
    if (h != NULL) {
      h[0] = 'J';
      NQTEQI(nqsmvrfy(m, n, anc, ancl, 1, 0, o, sizeof o, &on, NULL),
             NQEVRFY);
      h[0] = 'H';
    }
  }
  /* another anchor */
  anc[0] = ocert;
  ancl[0] = ocertn;
  NQTEQI(nqsmvrfy(m, n, anc, ancl, 1, 0, o, sizeof o, &on, NULL), NQEVRFY);
  anc[0] = cert;
  ancl[0] = certn;
  /* cut anywhere: never accepted */
  for (i = 0; i < n; i += n / 61 + 1) {
    NQTCHK(nqsmvrfy(m, i, anc, ancl, 1, 0, o, sizeof o, &on, NULL) != NQOK);
  }
  /* signed, then encrypted to two keys; opened and checked */
  rc[0] = kc[1];
  rl[0] = kcn[1];
  rc[1] = kc[2];
  rl[1] = kcn[2];
  NQTEQI(nqsmenc(rc, rl, 2, m, n, m2, sizeof m2, &n2), NQOK);
  NQTCHK(strstr(m2, "smime-type=authEnveloped-data") != NULL);
  NQTEQI(nqsmdec(kalg[2], ksk[2], kz[2].sk, kc[2], kcn[2], m2, n2, o,
                 sizeof o, &on),
         NQOK);
  NQTCHK(on == n);
  NQTEQM(o, m, n);
  NQTEQI(nqsmvrfy(o, on, anc, ancl, 1, 0, NULL, 0, &k, NULL), NQOK);
  NQTEQI(nqsmdec(kalg[0], ksk[0], kz[0].sk, NULL, 0, m2, n2, o, sizeof o,
                 &on),
         NQEVRFY);
  /* an encrypted entity is not a signed one, and the other way */
  NQTCHK(nqsmvrfy(m2, n2, anc, ancl, 1, 0, o, sizeof o, &on, NULL) != NQOK);
  NQTEQI(nqsmdec(kalg[2], ksk[2], kz[2].sk, NULL, 0, m, n, o, sizeof o, &on),
         NQEDEC);
  /* what is not an entity of these kinds, and the refusals */
  NQTEQI(nqsmvrfy(ent, sizeof ent - 1, anc, ancl, 1, 0, o, sizeof o, &on,
                  NULL),
         NQEDEC);
  NQTEQI(nqsmvrfy("", 0, anc, ancl, 1, 0, o, sizeof o, &on, NULL), NQEDEC);
  NQTEQI(nqsmdec(kalg[2], ksk[2], kz[2].sk, NULL, 0, ent, sizeof ent - 1, o,
                 sizeof o, &on),
         NQEDEC);
  NQTEQI(nqsmsign(NQMLDSA65, ssk, 4032, cert, certn, NULL, 4, 0, T0, m,
                  sizeof m, &n),
         NQEARG);
  NQTEQI(nqsmsign(NQMLDSA65, ssk, 4032, cert, certn, ent, sizeof ent - 1, 0,
                  T0, m, 40, &n),
         NQEBUF);
  NQTCHK(n > 40);
  NQTEQI(nqsmvrfy(NULL, 4, anc, ancl, 1, 0, o, sizeof o, &on, NULL), NQEARG);
  NQTEQI(nqsmenc(rc, rl, 2, NULL, 4, m2, sizeof m2, &n2), NQEARG);
  NQTEQI(nqsmenc(rc, rl, 2, ent, sizeof ent - 1, m2, 30, &n2), NQEBUF);
  NQTEQI(nqsmdec(kalg[2], ksk[2], kz[2].sk, NULL, 0, NULL, 4, o, sizeof o,
                 &on),
         NQEARG);
}

/* RFC 9936 appendix C: Bob's key is the seed 00 .. 3f; the message
 * decrypts to "Hello, world!" */
static void trfc(void) {
  static const char cms[] =
      "-----BEGIN CMS-----\n"
      "MIID4gYLKoZIhvcNAQkQARegggPRMIIDzQIBADGCA3ikggN0BgsqhkiG9w0BCRAN\n"
      "AzCCA2MCAQCAFFmXiMN67UAO5AXRsqM2arF9gkpRMAsGCWCGSAFlAwQEAQSCAwA+\n"
      "pA/GygkOLIr3bicnqzjgZS2VFZhv4YaCf+hOWW5CG4X9RZzHiZc3LJ3jHRkbOcHV\n"
      "o+tt21aq3t52XMOQ/bvC+IyxdWgdQgG4HM38sk/vE68vWhq8+NivOE8CoBCm6Rnx\n"
      "mHpemxwOLT8H9YqfpTnOhswUmRChaSwMpM4Ozk7u0uZpnLl2MyRS3koutcph97CB\n"
      "Mww0eY73EqJOWcM86h8fnm1PvzdDo4RnQwARM29i2HB5K4Zr780dGzZb7RlSZz06\n"
      "Wwwgs4a079HPY/03a9R8zEasTdjsZrBHxMlaz/HP0CikGbAC/aG2F8umHS6Rz+j/\n"
      "+8uP/U1fatixWMIZ423FFAXcDAsjSXmsZY5yvd8bZ3O5ayrj5NB76GBIBAwBZ0Nv\n"
      "qDnnUpsAzJq1Wi8l22PMn1V1lOaRwR5VPUo+vHYPXxnl/hRIOLTH0VkdqbXUZ0lP\n"
      "2crFLMVQQGA5nb23IpjrmkwBewB4b9x9nXqletu4thw03h4oiyq3KBcdzhQ80WlT\n"
      "+YTBrtVZ5WuqDOZY0yzOQvRAdQTNelea0O+bdxNeqjm2+To6LlmXgH8GNhyD9OZ/\n"
      "jj+c9oMWARUU9dhaGBzq1xTNSUDk66wB1mUo2jL4nOoEKOjrytz4qhiMn2LoWxlX\n"
      "ZVt/4rjXlzt6cia2bZO/eyMvPc9lPIS07PGpkg2xlJrXULVGpVUqIOVJCXGbjAwH\n"
      "BW/LfldK0qMuyVAB3ehEgb530DntW/dCYuzzmB8bANM2apwuBhxH4kGgYcYklWDS\n"
      "uERqSAw4woupidn2itxLuvKiC0fkkjEoxyNC1Zf9olneC4PCBW1rd+eZsxkySqUL\n"
      "HWWcKlYCm3RTxfO6UkPZ+nSdkXxA2dEB5FO8ixDkKnwIkyPAJveD4QC5+m5wFEJN\n"
      "pvo3kryVfughnQFrdz8o/tzJYqSFq6/+wCMoGXHimqaJg57P0mGekih80jDbJqJQ\n"
      "fMUA6xx6UpO1/pF64pvxrTUBJPijEWNSFLQR259n07hb1xUBhTfqRbQfQbTGYFEw\n"
      "DQYLKoZIhvcNAQkQAxwCARAwCwYJYIZIAWUDBAEFBBjAUOQ5L5wU3QrCIgID8xfX\n"
      "AflPndknePUwOgYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBBjARBAxcpXRouBvwO42n\n"
      "GGwCARCADZTIaJqZ0sOOGS+muggEEFzxeGxXx0ArVPyTwwpKRTM=\n"
      "-----END CMS-----\n";
  uint8_t seed[64], pk[800], sk[1632], der[1200], pt[64];
  char lab[NQARMLAB];
  size_t dn = 0, pn = 0, i;
  for (i = 0; i < 64; i++) seed[i] = (uint8_t)i;
  NQTEQI(nqkkgd(NQMLKEM512, seed, 64, pk, sizeof pk, sk, sizeof sk), NQOK);
  NQTEQI(nqarmdec(cms, sizeof cms - 1, lab, sizeof lab, der, sizeof der, &dn),
         NQOK);
  NQTCHK(dn == 998);
  NQTEQI(nqcmsdec(NQMLKEM512, sk, sizeof sk, NULL, 0, der, dn, pt, sizeof pt,
                  &pn),
         NQOK);
  NQTCHK(pn == 13);
  NQTEQM(pt, "Hello, world!", 13);
}

int main(void) {
  keys();
  tcert();
  tsign();
  tenc();
  tsmime();
  trfc();
  return nqtdone("tcms");
}
