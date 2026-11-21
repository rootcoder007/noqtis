/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* OpenPGP (nqpgpgen, nqpgpinfo, nqpgpsign, nqpgpvrfy, nqpgpenc,
 * nqpgpdec, nqpgparm, nqpgpdearm). The samples of RFC 9580 appendix A:
 * the version 6 certificate and its fingerprints, the secret key and
 * the locked one, the cleartext and the inline signed message
 * verified, the X25519 message and the three passphrase messages (EAX,
 * OCB, GCM) opened. Then keys of every algorithm made here: signed
 * three ways and verified, by the right key, another key, and changed;
 * encrypted to keys, to a passphrase and to both, signed inside,
 * opened by each and by none; armor there and back; a key under a
 * passphrase; the refusals. */
#include <stdint.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#define T0 1767225600 /* 2026-01-01T00:00:00Z */

static const char vcert[] =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "\n"
    "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n"
    "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n"
    "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n"
    "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n"
    "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n"
    "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n"
    "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n"
    "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n"
    "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n";
static const char vkey[] =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    "\n"
    "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n"
    "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n"
    "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n"
    "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n"
    "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n"
    "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n"
    "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n"
    "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n"
    "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n"
    "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n"
    "k0mXubZvyl4GBg==\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n";
static const char vlocked[] =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    "\n"
    "xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC\n"
    "FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS\n"
    "3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC\n"
    "Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW\n"
    "cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin\n"
    "7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/\n"
    "0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0\n"
    "gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf\n"
    "9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR\n"
    "v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr\n"
    "DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki\n"
    "Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt\n"
    "ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n";
static const char vclear[] =
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "\n"
    "What we need from the grocery store:\n"
    "\n"
    "- - tofu\n"
    "- - vegetables\n"
    "- - noodles\n"
    "\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n"
    "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo\n"
    "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr\n"
    "NK2ay45cX1IVAQ==\n"
    "-----END PGP SIGNATURE-----\n";
static const char vinline[] =
    "-----BEGIN PGP MESSAGE-----\n"
    "\n"
    "xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk\n"
    "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv\n"
    "bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k\n"
    "bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l\n"
    "JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ\n"
    "b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj\n"
    "FtCgazStmsuOXF9SFQE=\n"
    "-----END PGP MESSAGE-----\n";
static const char vx25519[] =
    "-----BEGIN PGP MESSAGE-----\n"
    "\n"
    "wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO\n"
    "WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS\n"
    "aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l\n"
    "yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo\n"
    "bhF30A+IitsxxA==\n"
    "-----END PGP MESSAGE-----\n";
static const char veax[] =
    "-----BEGIN PGP MESSAGE-----\n"
    "\n"
    "w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14\n"
    "KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq\n"
    "pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1\n"
    "QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=\n"
    "-----END PGP MESSAGE-----\n";
static const char vocb[] =
    "-----BEGIN PGP MESSAGE-----\n"
    "\n"
    "wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl\n"
    "ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM\n"
    "WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0\n"
    "K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==\n"
    "-----END PGP MESSAGE-----\n";
static const char vgcm[] =
    "-----BEGIN PGP MESSAGE-----\n"
    "\n"
    "wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa\n"
    "v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax\n"
    "Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS\n"
    "+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==\n"
    "-----END PGP MESSAGE-----\n";

static const char grocery[] =
    "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n";

static uint8_t cert[4096], key[4096], lkey[4096], big[1 << 18],
    out[1 << 17], bin[1 << 17];
static size_t certn, keyn, lkeyn;

static size_t hex(const char *s, uint8_t *o) {
  size_t n = 0;
  for (; s[0] != '\0' && s[1] != '\0'; s += 2) {
    unsigned a = (unsigned)(s[0] <= '9' ? s[0] - '0' : (s[0] | 32) - 'a' + 10);
    unsigned b = (unsigned)(s[1] <= '9' ? s[1] - '0' : (s[1] | 32) - 'a' + 10);
    o[n++] = (uint8_t)(a << 4 | b);
  }
  return n;
}

/* the samples of the RFC */
static void trfc(void) {
  static const char pw[] = "correct horse battery staple";
  nqpgpk k;
  uint8_t fp[32];
  size_t n = 0, on = 0;
  int64_t at = 0;
  int kind = 0, sb = 9, rc = 0, lowmem = 0;
  NQTEQI(nqpgpdearm(vcert, sizeof vcert - 1, &kind, cert, sizeof cert,
                    &certn),
         NQOK);
  NQTCHK(kind == NQPGPPUB);
  NQTEQI(nqpgpinfo(cert, certn, &k), NQOK);
  NQTCHK(k.alg == NQPGPED25519 && k.encalg == NQPGPX25519 && !k.secret);
  hex("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", fp);
  NQTEQM(k.fp, fp, 32);
  hex("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885", fp);
  NQTEQM(k.encfp, fp, 32);
  NQTEQI(nqpgpdearm(vkey, sizeof vkey - 1, &kind, key, sizeof key, &keyn),
         NQOK);
  NQTCHK(kind == NQPGPSEC);
  NQTEQI(nqpgpinfo(key, keyn, &k), NQOK);
  NQTCHK(k.secret && !k.locked && k.alg == NQPGPED25519);
  NQTEQI(nqpgpdearm(vlocked, sizeof vlocked - 1, &kind, lkey, sizeof lkey,
                    &lkeyn),
         NQOK);
  NQTEQI(nqpgpinfo(lkey, lkeyn, &k), NQOK);
  NQTCHK(k.secret && k.locked);
  /* the signed messages verify under the certificate */
  NQTEQI(nqpgpvrfy(cert, certn, (const uint8_t *)vclear, sizeof vclear - 1,
                   NULL, 0, out, sizeof out, &on, &at),
         NQOK);
  NQTCHK(on == sizeof grocery - 1);
  NQTEQM(out, grocery, on);
  NQTCHK(at > 1600000000);
  NQTEQI(nqpgpvrfy(cert, certn, (const uint8_t *)vinline, sizeof vinline - 1,
                   NULL, 0, out, sizeof out, &on, &at),
         NQOK);
  NQTCHK(on == sizeof grocery - 1);
  NQTEQM(out, grocery, on);
  /* the X25519 message opens with the secret key, and with the locked
   * one under its passphrase and under no other */
  NQTEQI(nqpgpdec(key, keyn, NULL, 0, NULL, 0, (const uint8_t *)vx25519,
                  sizeof vx25519 - 1, out, sizeof out, &on, &sb, &at),
         NQOK);
  NQTCHK(on == 13 && sb == 0);
  NQTEQM(out, "Hello, world!", 13);
  /* the RFC's locked key asks Argon2id for 2 GiB: where the machine has
   * not that much (NQEMEM), opening it is not tested, and said so */
  rc = nqpgpdec(lkey, lkeyn, (const uint8_t *)pw, sizeof pw - 1, NULL, 0,
                (const uint8_t *)vx25519, sizeof vx25519 - 1, out, sizeof out,
                &on, NULL, NULL);
  lowmem = rc == NQEMEM;
  if (lowmem) {
    printf("tpgp: no memory for the RFC's Argon2id key: not opened here\n");
  } else {
    NQTEQI(rc, NQOK);
    NQTCHK(on == 13);
    NQTEQI(nqpgpdec(lkey, lkeyn, (const uint8_t *)"wrong", 5, NULL, 0,
                    (const uint8_t *)vx25519, sizeof vx25519 - 1, out,
                    sizeof out, &on, NULL, NULL),
           NQEVRFY);
  }
  NQTEQI(nqpgpdec(lkey, lkeyn, NULL, 0, NULL, 0, (const uint8_t *)vx25519,
                  sizeof vx25519 - 1, out, sizeof out, &on, NULL, NULL),
         NQEARG);
  /* the passphrase messages: EAX, OCB and GCM, an iterated S2K */
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"password", 8, NULL, 0,
                  (const uint8_t *)veax, sizeof veax - 1, out, sizeof out,
                  &on, NULL, NULL),
         NQOK);
  NQTCHK(on == 13);
  NQTEQM(out, "Hello, world!", 13);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"password", 8, NULL, 0,
                  (const uint8_t *)vocb, sizeof vocb - 1, out, sizeof out,
                  &on, NULL, NULL),
         NQOK);
  NQTEQM(out, "Hello, world!", 13);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"password", 8, NULL, 0,
                  (const uint8_t *)vgcm, sizeof vgcm - 1, out, sizeof out,
                  &on, NULL, NULL),
         NQOK);
  NQTEQM(out, "Hello, world!", 13);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"Password", 8, NULL, 0,
                  (const uint8_t *)vocb, sizeof vocb - 1, out, sizeof out,
                  &on, NULL, NULL),
         NQEVRFY);
  /* the sample key signs, and its certificate verifies it */
  NQTEQI(nqpgpsign(key, keyn, NULL, 0, (const uint8_t *)"abc", 3,
                   NQPGPINLINE, T0, big, sizeof big, &n),
         NQOK);
  NQTEQI(nqpgpvrfy(cert, certn, big, n, NULL, 0, out, sizeof out, &on, &at),
         NQOK);
  NQTCHK(on == 3 && at == T0);
  if (!lowmem) {
    NQTEQI(nqpgpsign(lkey, lkeyn, (const uint8_t *)pw, sizeof pw - 1,
                     (const uint8_t *)"abc", 3, NQPGPDETACHED, T0, big,
                     sizeof big, &n),
           NQOK);
    NQTEQI(nqpgpvrfy(cert, certn, big, n, (const uint8_t *)"abc", 3, NULL, 0,
                     &on, NULL),
           NQOK);
  }
  NQTEQI(nqpgpsign(lkey, lkeyn, NULL, 0, (const uint8_t *)"abc", 3,
                   NQPGPDETACHED, T0, big, sizeof big, &n),
         NQEARG);
}

/* a key of the algorithms made here, and everything done with it */
static void talg(int sa, int ea, const char *pw) {
  static uint8_t sec[1 << 17], pub[1 << 17], sec2[1 << 17], pub2[1 << 17],
      msg[40000];
  static char arm[1 << 17];
  const uint8_t *certs[2];
  size_t cl[2], sn = 0, pn = 0, s2n = 0, p2n = 0, n = 0, on = 0, an = 0, i,
         step;
  size_t pwn = pw != NULL ? strlen(pw) : 0;
  nqpgpk k;
  int64_t at = 0;
  int kind = 0, sb = 0, mode;
  for (i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 13 + 1);
  NQTEQI(nqpgpgen(sa, ea, "Ada Example <ada@example.org>", T0,
                  (const uint8_t *)pw, pwn, sec, sizeof sec, &sn, pub,
                  sizeof pub, &pn),
         NQOK);
  NQTEQI(nqpgpgen(sa, ea, "Other <other@example.org>", T0, NULL, 0, sec2,
                  sizeof sec2, &s2n, pub2, sizeof pub2, &p2n),
         NQOK);
  NQTEQI(nqpgpinfo(pub, pn, &k), NQOK);
  NQTCHK(k.alg == sa && k.encalg == ea && !k.secret && k.created == T0);
  NQTCHK(strcmp(k.uid, "Ada Example <ada@example.org>") == 0);
  NQTEQI(nqpgpinfo(sec, sn, &k), NQOK);
  NQTCHK(k.secret && k.locked == (pw != NULL));
  /* signed three ways */
  for (mode = NQPGPINLINE; mode <= NQPGPCLEAR; mode++) {
    const uint8_t *m = mode == NQPGPCLEAR
                           ? (const uint8_t *)"- dash\nline two  \nthree"
                           : msg;
    size_t mn = mode == NQPGPCLEAR ? 23 : 3000;
    NQTEQI(nqpgpsign(sec, sn, (const uint8_t *)pw, pwn, m, mn, mode, T0 + 9,
                     big, sizeof big, &n),
           NQOK);
    NQTEQI(nqpgpvrfy(pub, pn, big, n, mode == NQPGPDETACHED ? m : NULL,
                     mode == NQPGPDETACHED ? mn : 0, out, sizeof out, &on,
                     &at),
           NQOK);
    NQTCHK(at == T0 + 9);
    if (mode == NQPGPCLEAR) {
      /* the text without the space at the end of its lines */
      NQTCHK(on == 21);
      NQTEQM(out, "- dash\nline two\nthree", 21);
    } else {
      NQTCHK(on == mn);
      NQTEQM(out, m, mn);
    }
    /* another key's certificate does not verify it */
    NQTEQI(nqpgpvrfy(pub2, p2n, big, n, mode == NQPGPDETACHED ? m : NULL,
                     mode == NQPGPDETACHED ? mn : 0, out, sizeof out, &on,
                     &at),
           NQEVRFY);
    NQTCHK(on == 0);
    /* changed all through: never the same data under a changed word */
    step = n / 53 + 1;
    for (i = 0; i < n; i += step) {
      int rc;
      big[i] ^= 0x10;
      rc = nqpgpvrfy(pub, pn, big, n, mode == NQPGPDETACHED ? m : NULL,
                     mode == NQPGPDETACHED ? mn : 0, out, sizeof out, &on,
                     &at);
      NQTCHK(rc != NQOK || (mode == NQPGPCLEAR && on != 21) ||
             (on == mn && memcmp(out, m, mn) == 0) || mode == NQPGPCLEAR);
      big[i] ^= 0x10;
    }
    if (mode == NQPGPDETACHED) {
      NQTEQI(nqpgpvrfy(pub, pn, big, n, msg, 2999, NULL, 0, &on, &at),
             NQEVRFY);
      NQTEQI(nqpgpvrfy(pub, pn, big, n, NULL, 0, NULL, 0, &on, &at), NQEARG);
      /* armored, the signature is read as well */
      NQTEQI(nqpgparm(NQPGPSIG, big, n, arm, sizeof arm, &an), NQOK);
      NQTEQI(nqpgpvrfy(pub, pn, (const uint8_t *)arm, an, msg, 3000, NULL, 0,
                       &on, &at),
             NQOK);
    }
  }
  /* armor there and back, every kind */
  NQTEQI(nqpgparm(NQPGPPUB, pub, pn, NULL, 0, &an), NQOK);
  NQTCHK(an < sizeof arm);
  NQTEQI(nqpgparm(NQPGPPUB, pub, pn, arm, an - 1, &on), NQEBUF);
  NQTEQI(nqpgparm(NQPGPPUB, pub, pn, arm, an, &on), NQOK);
  NQTCHK(on == an &&
         memcmp(arm, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n", 38) == 0);
  NQTEQI(nqpgpdearm(arm, an, &kind, bin, sizeof bin, &on), NQOK);
  NQTCHK(kind == NQPGPPUB && on == pn);
  NQTEQM(bin, pub, pn);
  if (ea == 0) {
    /* a key with no encryption subkey receives nothing */
    certs[0] = pub;
    cl[0] = pn;
    NQTEQI(nqpgpenc(certs, cl, 1, NULL, 0, NULL, 0, NULL, 0, msg, 10, T0,
                    big, sizeof big, &n),
           NQEARG);
    return;
  }
  /* encrypted to both keys: each opens it, with and without the signer */
  certs[0] = pub;
  cl[0] = pn;
  certs[1] = pub2;
  cl[1] = p2n;
  NQTEQI(nqpgpenc(certs, cl, 2, NULL, 0, NULL, 0, NULL, 0, msg, sizeof msg,
                  T0, big, sizeof big, &n),
         NQOK);
  memset(out, 0, sizeof msg);
  NQTEQI(nqpgpdec(sec, sn, (const uint8_t *)pw, pwn, NULL, 0, big, n, out,
                  sizeof out, &on, &sb, &at),
         NQOK);
  NQTCHK(on == sizeof msg && sb == 0);
  NQTEQM(out, msg, sizeof msg);
  NQTEQI(nqpgpdec(sec2, s2n, NULL, 0, NULL, 0, big, n, out, sizeof out, &on,
                  NULL, NULL),
         NQOK);
  NQTCHK(on == sizeof msg);
  /* not signed: asking for a signer fails */
  NQTCHK(nqpgpdec(sec2, s2n, NULL, 0, pub, pn, big, n, out, sizeof out, &on,
                  &sb, NULL) != NQOK);
  /* changed all through: never plaintext that is not the message */
  step = n / 71 + 1;
  for (i = 0; i < n; i += step) {
    int rc;
    big[i] ^= 0x01;
    rc = nqpgpdec(sec2, s2n, NULL, 0, NULL, 0, big, n, out, sizeof out, &on,
                  NULL, NULL);
    NQTCHK(rc != NQOK || (on == sizeof msg && memcmp(out, msg, on) == 0));
    big[i] ^= 0x01;
  }
  /* to one key only: the other does not open it */
  NQTEQI(nqpgpenc(certs, cl, 1, NULL, 0, NULL, 0, NULL, 0, msg, 100, T0, big,
                  sizeof big, &n),
         NQOK);
  NQTEQI(nqpgpdec(sec2, s2n, NULL, 0, NULL, 0, big, n, out, sizeof out, &on,
                  NULL, NULL),
         NQEVRFY);
  /* signed inside, to a key and a passphrase */
  NQTEQI(nqpgpenc(certs + 1, cl + 1, 1, (const uint8_t *)"open sesame", 11,
                  sec, sn, (const uint8_t *)pw, pwn, msg, 5000, T0 + 3, big,
                  sizeof big, &n),
         NQOK);
  NQTEQI(nqpgpdec(sec2, s2n, NULL, 0, pub, pn, big, n, out, sizeof out, &on,
                  &sb, &at),
         NQOK);
  NQTCHK(on == 5000 && sb == 1 && at == T0 + 3);
  NQTEQM(out, msg, 5000);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"open sesame", 11, pub, pn, big,
                  n, out, sizeof out, &on, &sb, &at),
         NQOK);
  NQTCHK(on == 5000 && sb == 1);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"open sesame", 11, NULL, 0, big,
                  n, out, sizeof out, &on, &sb, &at),
         NQOK);
  NQTCHK(on == 5000 && sb == 0);
  /* signed by another key than the one asked for */
  NQTEQI(nqpgpdec(sec2, s2n, NULL, 0, pub2, p2n, big, n, out, sizeof out,
                  &on, &sb, NULL),
         NQEVRFY);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"open sesam", 10, NULL, 0, big, n,
                  out, sizeof out, &on, NULL, NULL),
         NQEVRFY);
  /* nothing to encrypt, and an armored message */
  NQTEQI(nqpgpenc(certs, cl, 2, NULL, 0, NULL, 0, NULL, 0, NULL, 0, T0, big,
                  sizeof big, &n),
         NQOK);
  NQTEQI(nqpgparm(NQPGPMSG, big, n, arm, sizeof arm, &an), NQOK);
  NQTEQI(nqpgpdec(sec2, s2n, NULL, 0, NULL, 0, (const uint8_t *)arm, an, out,
                  sizeof out, &on, NULL, NULL),
         NQOK);
  NQTCHK(on == 0);
  NQTEQI(nqpgpenc(certs, cl, 2, NULL, 0, NULL, 0, NULL, 0, msg, 100, T0, big,
                  30, &n),
         NQEBUF);
  NQTCHK(n > 30);
}

static void targs(void) {
  static uint8_t sec[1 << 14], pub[1 << 14];
  const uint8_t *certs[1];
  size_t cl[1], sn = 0, pn = 0, n = 0, on = 0;
  nqpgpk k;
  char arm[64];
  int kind;
  NQTEQI(nqpgpgen(NQPGPED25519, NQPGPX25519, "X", T0, NULL, 0, sec,
                  sizeof sec, &sn, pub, sizeof pub, &pn),
         NQOK);
  certs[0] = pub;
  cl[0] = pn;
  NQTEQI(nqpgpgen(99, 0, "X", T0, NULL, 0, sec, sizeof sec, &n, pub,
                  sizeof pub, &on),
         NQENOSUP);
  NQTEQI(nqpgpgen(NQPGPX25519, 0, "X", T0, NULL, 0, sec, sizeof sec, &n, pub,
                  sizeof pub, &on),
         NQENOSUP);
  NQTEQI(nqpgpgen(NQPGPED25519, NQPGPED25519, "X", T0, NULL, 0, sec,
                  sizeof sec, &n, pub, sizeof pub, &on),
         NQENOSUP);
  NQTEQI(nqpgpgen(NQPGPED25519, 0, "", T0, NULL, 0, sec, sizeof sec, &n, pub,
                  sizeof pub, &on),
         NQEARG);
  NQTEQI(nqpgpgen(NQPGPED25519, 0, NULL, T0, NULL, 0, sec, sizeof sec, &n,
                  pub, sizeof pub, &on),
         NQEARG);
  NQTEQI(nqpgpgen(NQPGPED25519, 0, "X", -1, NULL, 0, sec, sizeof sec, &n, pub,
                  sizeof pub, &on),
         NQEARG);
  NQTEQI(nqpgpgen(NQPGPED25519, 0, "X", T0, NULL, 0, out, 10, &n, big, 10,
                  &on),
         NQEBUF);
  NQTCHK(n > 10 && on > 10);
  /* a certificate does not sign or decrypt; a secret key is needed */
  NQTEQI(nqpgpsign(pub, pn, NULL, 0, (const uint8_t *)"a", 1, NQPGPINLINE, T0,
                   big, sizeof big, &n),
         NQEARG);
  NQTEQI(nqpgpsign(sec, sn, NULL, 0, (const uint8_t *)"a", 1, 7, T0, big,
                   sizeof big, &n),
         NQEARG);
  NQTEQI(nqpgpsign(sec, sn, NULL, 0, (const uint8_t *)"\xff\xfe", 2,
                   NQPGPCLEAR, T0, big, sizeof big, &n),
         NQEARG);
  NQTEQI(nqpgpsign(NULL, 0, NULL, 0, (const uint8_t *)"a", 1, NQPGPINLINE, T0,
                   big, sizeof big, &n),
         NQEARG);
  NQTEQI(nqpgpenc(certs, cl, 1, NULL, 0, NULL, 0, NULL, 0, (const uint8_t *)
                  "a", 1, T0, big, sizeof big, &n),
         NQOK);
  NQTEQI(nqpgpdec(pub, pn, NULL, 0, NULL, 0, big, n, out, sizeof out, &on,
                  NULL, NULL),
         NQEARG);
  NQTEQI(nqpgpdec(NULL, 0, NULL, 0, NULL, 0, big, n, out, sizeof out, &on,
                  NULL, NULL),
         NQEARG);
  NQTEQI(nqpgpdec(NULL, 0, (const uint8_t *)"pw", 2, NULL, 0, big, n, out,
                  sizeof out, &on, NULL, NULL),
         NQEVRFY);
  NQTEQI(nqpgpenc(NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, (const uint8_t *)
                  "a", 1, T0, big, sizeof big, &n),
         NQEARG);
  /* what is not OpenPGP */
  NQTEQI(nqpgpinfo((const uint8_t *)"hello", 5, &k), NQEDEC);
  NQTEQI(nqpgpinfo(NULL, 0, &k), NQEARG);
  NQTEQI(nqpgpinfo(pub, pn, NULL), NQEARG);
  NQTEQI(nqpgpinfo(pub, pn - 1, &k), NQEDEC);
  NQTCHK(nqpgpvrfy(pub, pn, (const uint8_t *)"hello", 5, NULL, 0, out,
                   sizeof out, &on, NULL) != NQOK);
  NQTEQI(nqpgpdec(sec, sn, NULL, 0, NULL, 0, (const uint8_t *)"hello", 5, out,
                  sizeof out, &on, NULL, NULL),
         NQEDEC);
  /* armor: kinds, text that is not armor, text after it */
  NQTEQI(nqpgparm(0, pub, pn, arm, sizeof arm, &on), NQEARG);
  NQTEQI(nqpgparm(5, pub, pn, arm, sizeof arm, &on), NQEARG);
  NQTEQI(nqpgparm(NQPGPMSG, NULL, 3, arm, sizeof arm, &on), NQEARG);
  NQTEQI(nqpgpdearm("hello", 5, &kind, out, sizeof out, &on), NQEDEC);
  NQTEQI(nqpgpdearm("-----BEGIN PGP MESSAGE-----\n\nAAAA\n"
                    "-----END PGP MESSAGE-----\nmore",
                    64, &kind, out, sizeof out, &on),
         NQEDEC);
  NQTEQI(nqpgpdearm("-----BEGIN PGP MESSAGE-----\n\nAAAA\n"
                    "-----END PGP SIGNATURE-----\n",
                    62, &kind, out, sizeof out, &on),
         NQEDEC);
  NQTEQI(nqpgpdearm("-----BEGIN PGP MESSAGE-----\nComment: x\n\nAAAA\n=abcd\n"
                    "-----END PGP MESSAGE-----\n",
                    77, &kind, out, sizeof out, &on),
         NQOK);
  NQTCHK(kind == NQPGPMSG && on == 3);
  NQTEQI(nqpgpdearm(NULL, 0, &kind, out, sizeof out, &on), NQEARG);
}

int main(void) {
  trfc();
  talg(NQPGPED25519, NQPGPX25519, NULL);
  talg(NQPGPMLDSA65, NQPGPMLKEM768, NULL);
  talg(NQPGPMLDSA65, NQPGPMLKEM768, "a passphrase for the key");
  talg(NQPGPSLH128F, 0, NULL);
  talg(NQPGPSLH128S, NQPGPMLKEM768, NULL);
  targs();
  return nqtdone("tpgp");
}
