/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * noqtis pgp: OpenPGP (RFC 9580, version 6) keys, signatures and
 * encrypted messages, with the post-quantum algorithms.
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEYMAX ((size_t)1 << 18) /* a key or a certificate, in binary */

static const struct {
  int id;
  const char *name;
} algs[] = {{NQPGPMLDSA65, "mldsa65-ed25519"},
            {NQPGPED25519, "ed25519"},
            {NQPGPSLH128S, "slh-shake-128s"},
            {NQPGPSLH128F, "slh-shake-128f"},
            {NQPGPSLH256S, "slh-shake-256s"},
            {NQPGPMLKEM768, "mlkem768-x25519"},
            {NQPGPX25519, "x25519"}};

static const char *algname(int id) {
  size_t i;
  for (i = 0; i < sizeof algs / sizeof algs[0]; i++)
    if (algs[i].id == id) return algs[i].name;
  return "another kind";
}

/* an OpenPGP key or certificate file, armored or binary, as binary in
 * a new buffer of KEYMAX bytes (ncfree, sec) */
static int rdkey(const char *path, int sec, uint8_t **key, size_t *n) {
  uint8_t *b = NULL, *o;
  size_t bn = 0, i = 0;
  int kind = 0, rc;
  if (ncrdx(path, sec, NCRDSMALL, &b, &bn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", path, ncwhy());
    return NCUSE;
  }
  o = (uint8_t *)malloc(KEYMAX);
  if (o == NULL) {
    ncfree(b, bn, sec);
    return nclib("pgp", "memory", NQEMEM);
  }
  while (i < bn && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r')) i++;
  if (bn - i >= 5 && memcmp(b + i, "-----", 5) == 0) {
    rc = nqpgpdearm((const char *)b + i, bn - i, &kind, o, KEYMAX, n);
    if (rc == NQOK && kind != NQPGPPUB && kind != NQPGPSEC) rc = NQEDEC;
  } else {
    rc = bn <= KEYMAX ? NQOK : NQELIM;
    if (rc == NQOK) memcpy(o, b, bn);
    *n = bn;
  }
  ncfree(b, bn, sec);
  if (rc != NQOK) {
    ncmsg("pgp", "%s is not an OpenPGP key (%s)", path, nqerr(rc));
    ncfree(o, KEYMAX, sec);
    return NCUSE;
  }
  *key = o;
  return NCOK;
}

/* writes n bytes to out (- or NULL: stdout), armored as kind unless
 * kind is 0 */
static int wrout(const char *out, int kind, const uint8_t *b, size_t n,
                 int force, int sec) {
  char *a = NULL;
  size_t an = 0;
  int ret;
  if (kind != 0) {
    if (nqpgparm(kind, b, n, NULL, 0, &an) != NQOK) return NCUSE;
    a = (char *)malloc(an);
    if (a == NULL) return nclib("pgp", "memory", NQEMEM);
    if (nqpgparm(kind, b, n, a, an, &an) != NQOK) {
      free(a);
      return NCUSE;
    }
    b = (const uint8_t *)a;
    n = an;
  }
  if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    ret = fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  } else if (ncwr(out, b, n, force, sec) != NQOK) {
    ncwfail("pgp", out, force);
    ret = NCUSE;
  } else {
    ret = NCOK;
  }
  if (a != NULL) ncfree(a, an, sec);
  return ret;
}

static void stamp(int64_t at, char *o, size_t cap) {
  struct tm g;
  o[0] = '\0';
  if (ncgmtime(at, &g) == NCOK)
    strftime(o, cap, "%Y-%m-%dT%H:%M:%SZ", &g);
}

/* what the library said of a key that would not do */
static void keywhy(const char *path, int rc, int locked) {
  if (rc == NQEVRFY)
    ncmsg("pgp", "%s: %s", path,
          locked ? "the passphrase does not open the key"
                 : "the key does not check out: no valid self-signature, "
                   "or it is revoked or has expired");
  else if (rc == NQEARG)
    ncmsg("pgp", "%s cannot do this: it must be a secret key that signs "
          "(or, to decrypt, has an encryption subkey), with --pass-fd or "
          "--pass-env when it is under a passphrase", path);
  else if (rc == NQENOSUP)
    ncmsg("pgp", "%s is of a kind not supported here: version 6 keys of "
          "Ed25519, X25519, ML-DSA, ML-KEM and SLH-DSA are", path);
  else
    ncmsg("pgp", "%s is not an OpenPGP key (%s)", path, nqerr(rc));
}

static int pgpgen(const char *uid, const char *alg, const char *out,
                  int signonly, const ncpw *pwo, int force) {
  uint8_t *pw = NULL, *sec = NULL, *pub = NULL;
  char *pp = NULL;
  size_t pn = 0, sn = 0, bn = 0, i, l = strlen(out);
  int sa = NQPGPMLDSA65, ea, rc, ret = NCUSE;
  if (alg != NULL) {
    sa = 0;
    for (i = 0; i < 5; i++)
      if (strcmp(alg, algs[i].name) == 0) sa = algs[i].id;
    if (sa == 0) {
      ncmsg("pgp", "%s is not a signature algorithm of OpenPGP keys here: "
            "mldsa65-ed25519, ed25519, slh-shake-128s, slh-shake-128f, "
            "slh-shake-256s", alg);
      return NCUSE;
    }
  }
  ea = signonly ? 0 : sa == NQPGPED25519 ? NQPGPX25519 : NQPGPMLKEM768;
  if (ncpwget("pgp", pwo, &pw, &pn) != NCOK) return NCUSE;
  sec = (uint8_t *)malloc(KEYMAX);
  pub = (uint8_t *)malloc(KEYMAX);
  pp = (char *)malloc(l + 5);
  if (sec == NULL || pub == NULL || pp == NULL) {
    nclib("pgp", "memory", NQEMEM);
    goto done;
  }
  memcpy(pp, out, l);
  memcpy(pp + l, ".pub", 5);
  rc = nqpgpgen(sa, ea, uid, ncnow(), pw, pn, sec, KEYMAX, &sn, pub, KEYMAX,
                &bn);
  if (rc != NQOK) {
    if (rc == NQEARG)
      ncmsg("pgp", "the user ID must be 1 to 255 bytes of UTF-8 text, such "
            "as \"Ada Example <ada@example.org>\"");
    else
      nclib("pgp", "making the key", rc);
    goto done;
  }
  if (wrout(out, NQPGPSEC, sec, sn, force, 1) != NCOK ||
      wrout(pp, NQPGPPUB, pub, bn, force, 0) != NCOK)
    goto done;
  ret = NCOK;
done:
  if (pw != NULL) ncfree(pw, NQPWLEN, 1);
  if (sec != NULL) ncfree(sec, KEYMAX, 1);
  free(pub);
  free(pp);
  return ret;
}

static int pgpshow(const char *path) {
  uint8_t *k = NULL;
  size_t kn = 0;
  nqpgpk f;
  char hx[65], a[32], b[32];
  int rc;
  if (rdkey(path, 1, &k, &kn) != NCOK) return NCUSE;
  rc = nqpgpinfo(k, kn, &f);
  ncfree(k, KEYMAX, 1);
  if (rc != NQOK) {
    keywhy(path, rc, 0);
    return rc == NQEVRFY ? NCBAD : NCUSE;
  }
  stamp(f.created, a, sizeof a);
  stamp(f.expires, b, sizeof b);
  nchexe(f.fp, 32, hx);
  hx[64] = '\0';
  printf("user ID      %s\n", ncesc(f.uid));
  printf("kind         %s\n", !f.secret ? "certificate (public)"
                              : f.locked ? "secret key, under a passphrase"
                                         : "secret key");
  printf("key          %s\n", algname(f.alg));
  printf("fingerprint  %s\n", hx);
  if (f.encalg != 0) {
    nchexe(f.encfp, 32, hx);
    hx[64] = '\0';
    printf("encryption   %s\n", algname(f.encalg));
    printf("fingerprint  %s\n", hx);
  }
  printf("created      %s\n", a);
  printf("expires      %s\n", f.expires == 0 ? "never" : b);
  return NCOK;
}

static int pgpsign(const char *kp, const ncpw *pwo, const char *in,
                   const char *out, int mode, int binary, int force) {
  uint8_t *k = NULL, *pw = NULL, *b = NULL, *o = NULL;
  size_t kn = 0, pn = 0, bn = 0, on = 0, cap = 0;
  int rc, ret = NCUSE;
  if (ncpwget("pgp", pwo, &pw, &pn) != NCOK) return NCUSE;
  if (rdkey(kp, 1, &k, &kn) != NCOK) goto done;
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  /* the data, a dash before every line of it at most, the signature */
  cap = 3 * bn + ((size_t)1 << 17);
  o = (uint8_t *)malloc(cap);
  if (o == NULL) {
    nclib("pgp", "memory", NQEMEM);
    goto done;
  }
  rc = nqpgpsign(k, kn, pw, pn, b, bn, mode, ncnow(), o, cap, &on);
  if (rc != NQOK) {
    keywhy(kp, rc, pw != NULL);
    if (rc == NQEARG && mode == NQPGPCLEAR)
      ncmsg("pgp", "or %s is not UTF-8 text: --clear signs text", in);
    goto done;
  }
  ret = wrout(out, mode == NQPGPCLEAR || binary ? 0
                   : mode == NQPGPDETACHED ? NQPGPSIG : NQPGPMSG,
              o, on, force, 0);
done:
  if (pw != NULL) ncfree(pw, NQPWLEN, 1);
  if (k != NULL) ncfree(k, KEYMAX, 1);
  if (b != NULL) ncfree(b, bn, 0);
  free(o);
  return ret;
}

static int pgpverify(const char *cp, const char *content, const char *in,
                     const char *out, int force) {
  uint8_t *c = NULL, *b = NULL, *m = NULL, *o = NULL;
  size_t cn = 0, bn = 0, mn = 0, on = 0;
  nqpgpk f;
  char hx[65], at[32];
  int64_t t = 0;
  int rc, ret = NCUSE;
  if (rdkey(cp, 0, &c, &cn) != NCOK) return NCUSE;
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  if (content != NULL && ncrdx(content, 0, NCRDMAX, &m, &mn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", content, ncwhy());
    goto done;
  }
  /* the data comes back: what is inside, or the content given */
  o = (uint8_t *)malloc(bn + mn + 1);
  if (o == NULL) {
    nclib("pgp", "memory", NQEMEM);
    goto done;
  }
  rc = nqpgpvrfy(c, cn, b, bn, content != NULL ? (m != NULL ? m : o) : NULL,
                 mn, o, bn + mn + 1, &on, &t);
  if (rc == NQEVRFY) {
    ncmsg("pgp", "%s does NOT verify under %s", in, cp);
    ret = NCBAD;
    goto done;
  }
  if (rc != NQOK) {
    if (rc == NQEARG)
      ncmsg("pgp", "%s is a detached signature: give what it signs with "
            "--content", in);
    else if (rc == NQENOSUP)
      ncmsg("pgp", "%s is of a kind not supported here (version 6 "
            "signatures of the algorithms of `noqtis pgp keygen` are)", in);
    else
      ncmsg("pgp", "%s is not an OpenPGP signature or signed message, or "
            "%s not a certificate (%s)", in, cp, nqerr(rc));
    goto done;
  }
  if (out != NULL && content == NULL &&
      wrout(out, 0, o, on, force, 0) != NCOK)
    goto done;
  if (nqpgpinfo(c, cn, &f) == NQOK) {
    nchexe(f.fp, 32, hx);
    hx[64] = '\0';
    stamp(t, at, sizeof at);
    fprintf(out != NULL && strcmp(out, "-") == 0 ? stderr : stdout,
            "%s: OK, signed by %s (%s) at %s\n", in, ncesc(f.uid), hx, at);
  }
  ret = NCOK;
done:
  ncfree(c, KEYMAX, 0);
  if (b != NULL) ncfree(b, bn, 0);
  if (m != NULL) ncfree(m, mn, 0);
  free(o);
  return ret;
}

static int pgpencrypt(const char **to, int nto, int sym, const char *kp,
                      const ncpw *pwo, const char *in, const char *out,
                      int binary, int force) {
  uint8_t *certs[NCMAXV], *pw = NULL, *k = NULL, *b = NULL, *o = NULL;
  const uint8_t *cp[NCMAXV];
  size_t cl[NCMAXV], pn = 0, kn = 0, bn = 0, on = 0, cap = 0;
  int i, rc, ret = NCUSE;
  memset(certs, 0, sizeof certs);
  if (ncpwget("pgp", pwo, &pw, &pn) != NCOK) return NCUSE;
  if (sym && pw == NULL) {
    ncmsg("pgp", "--symmetric takes the passphrase of the message from "
          "--pass-fd or --pass-env");
    goto done;
  }
  for (i = 0; i < nto; i++) {
    if (rdkey(to[i], 0, &certs[i], &cl[i]) != NCOK) goto done;
    cp[i] = certs[i];
  }
  if (kp != NULL && rdkey(kp, 1, &k, &kn) != NCOK) goto done;
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  cap = bn + bn / 512 + (size_t)nto * 2048 + ((size_t)1 << 17);
  o = (uint8_t *)malloc(cap);
  if (o == NULL) {
    nclib("pgp", "memory", NQEMEM);
    goto done;
  }
  /* with --symmetric the passphrase is the message's, and the signing
   * key is taken as it is; without, the passphrase is the key's */
  rc = nqpgpenc(cp, cl, (size_t)nto, sym ? pw : NULL, sym ? pn : 0, k, kn,
                sym ? NULL : pw, sym ? 0 : pn, b, bn, ncnow(), o, cap, &on);
  if (rc != NQOK) {
    if (kp != NULL && (rc == NQEVRFY || (rc == NQEARG && nto == 0)))
      keywhy(kp, rc, !sym && pw != NULL);
    else if (rc == NQEARG || rc == NQEVRFY)
      ncmsg("pgp", "a --to certificate cannot receive: it has no "
            "encryption subkey, or does not check out%s",
            kp != NULL ? "; or the -k key cannot sign (with --symmetric "
                         "it must not be under a passphrase)" : "");
    else
      nclib("pgp", "encrypting", rc);
    goto done;
  }
  ret = wrout(out, binary ? 0 : NQPGPMSG, o, on, force, 0);
done:
  for (i = 0; i < nto; i++)
    if (certs[i] != NULL) ncfree(certs[i], KEYMAX, 0);
  if (pw != NULL) ncfree(pw, NQPWLEN, 1);
  if (k != NULL) ncfree(k, KEYMAX, 1);
  if (b != NULL) ncfree(b, bn, 1);
  free(o);
  return ret;
}

static int pgpdecrypt(const char *kp, const char *cp, const ncpw *pwo,
                      const char *in, const char *out, int force) {
  uint8_t *pw = NULL, *k = NULL, *c = NULL, *b = NULL, *o = NULL;
  size_t pn = 0, kn = 0, cn = 0, bn = 0, on = 0;
  int64_t t = 0;
  int rc, ret = NCUSE, sb = 0;
  if (ncpwget("pgp", pwo, &pw, &pn) != NCOK) return NCUSE;
  if (kp == NULL && pw == NULL) {
    ncmsg("pgp", "decrypt takes a secret key (-k), or with --symmetric the "
          "passphrase of the message from --pass-fd or --pass-env");
    goto done;
  }
  if ((kp != NULL && rdkey(kp, 1, &k, &kn) != NCOK) ||
      (cp != NULL && rdkey(cp, 0, &c, &cn) != NCOK))
    goto done;
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("pgp", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  o = (uint8_t *)malloc(bn + 1);
  if (o == NULL) {
    nclib("pgp", "memory", NQEMEM);
    goto done;
  }
  rc = nqpgpdec(k, kn, pw, pn, c, cn, b, bn, o, bn + 1, &on, &sb, &t);
  if (rc == NQEVRFY) {
    ncmsg("pgp", "%s does NOT open: it is not for this %s, it was changed, "
          "or%s", in, kp != NULL ? "key" : "passphrase",
          cp != NULL ? " it is not signed by the --cert certificate"
                     : " the passphrase is wrong");
    goto done;
  }
  if (rc != NQOK) {
    if (rc == NQEARG && kp != NULL)
      keywhy(kp, rc, pw != NULL);
    else if (rc == NQENOSUP)
      ncmsg("pgp", "%s is encrypted in a way not supported here: version 2 "
            "encrypted data to version 6 keys or passphrases is", in);
    else
      ncmsg("pgp", "%s is not an OpenPGP encrypted message (%s)", in,
            nqerr(rc));
    goto done;
  }
  ret = wrout(out, 0, o, on, force, 1);
  if (ret == NCOK && sb) fprintf(stderr, "verified: signed by --cert\n");
done:
  if (pw != NULL) ncfree(pw, NQPWLEN, 1);
  if (k != NULL) ncfree(k, KEYMAX, 1);
  if (c != NULL) ncfree(c, KEYMAX, 0);
  if (b != NULL) ncfree(b, bn, 0);
  if (o != NULL) ncfree(o, bn + 1, 1);
  return ret;
}

int ncpgp(int argc, char **argv) {
  const char *kp = NULL, *cp = NULL, *out = NULL, *content = NULL;
  const char *uid = NULL, *alg = NULL, *to[NCMAXV], *sub;
  int force = 0, help = 0, np, nto = 0, det = 0, clear = 0, binary = 0;
  int sym = 0, so = 0;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'n', "name", 1, &uid, NULL},
    {'a', "alg", 1, &alg, NULL},
    {'\0', "cert", 1, &cp, NULL},
    {'\0', "to", NCMANY, to, &nto},
    {'\0', "content", 1, &content, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "detached", 0, NULL, &det},
    {'\0', "clear", 0, NULL, &clear},
    {'\0', "binary", 0, NULL, &binary},
    {'\0', "symmetric", 0, NULL, &sym},
    {'\0', "sign-only", 0, NULL, &so},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  int plain; /* none of the options of the other forms */

  if (ncargs("pgp", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "pgp");
    return NCOK;
  }
  if (np < 1 || (det && clear)) {
    ncuse(stderr, "pgp");
    return NCUSE;
  }
  sub = argv[0];
  plain = uid == NULL && alg == NULL && !so;
  if (strcmp(sub, "keygen") == 0 && np == 1 && uid != NULL && out != NULL &&
      strcmp(out, "-") != 0 && kp == NULL && cp == NULL && nto == 0 &&
      content == NULL && !det && !clear && !binary && !sym)
    return pgpgen(uid, alg, out, so, &pwo, force);
  if (strcmp(sub, "show") == 0 && np == 2 && plain && kp == NULL &&
      cp == NULL && nto == 0 && content == NULL && out == NULL && !det &&
      !clear && !binary && !sym)
    return pgpshow(argv[1]);
  if (strcmp(sub, "sign") == 0 && np == 2 && plain && kp != NULL &&
      cp == NULL && nto == 0 && content == NULL && !sym &&
      !(clear && binary))
    return pgpsign(kp, &pwo, argv[1], out,
                   det ? NQPGPDETACHED : clear ? NQPGPCLEAR : NQPGPINLINE,
                   binary, force);
  if (strcmp(sub, "verify") == 0 && np == 2 && plain && cp != NULL &&
      kp == NULL && nto == 0 && !det && !clear && !binary && !sym)
    return pgpverify(cp, content, argv[1], out, force);
  if (strcmp(sub, "encrypt") == 0 && np == 2 && plain && (nto > 0 || sym) &&
      cp == NULL && content == NULL && !det && !clear)
    return pgpencrypt(to, nto, sym, kp, &pwo, argv[1], out, binary, force);
  if (strcmp(sub, "decrypt") == 0 && np == 2 && plain &&
      (kp != NULL) != (sym != 0) && nto == 0 && content == NULL && !det &&
      !clear && !binary)
    return pgpdecrypt(kp, cp, &pwo, argv[1], out, force);
  ncuse(stderr, "pgp");
  return NCUSE;
}
