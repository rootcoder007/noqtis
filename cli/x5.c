/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis cert and noqtis smime: X.509 certificates for noqtis keys, and
 * signed and encrypted mail (S/MIME, CMS) with them.
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LCERT "CERTIFICATE"
#define MAXC 32 /* certificates one option may be given */

/* a certificate file, PEM or DER, as DER in a new buffer (free) */
static int rdcert(const char *cmd, const char *path, uint8_t **der,
                  size_t *n) {
  uint8_t *b = NULL, *o;
  char lab[NQARMLAB];
  size_t bn = 0, i = 0, k = 0;
  if (ncrdx(path, 0, NCRDSMALL, &b, &bn) != NQOK) {
    ncmsg(cmd, "cannot read %s%s", path, ncwhy());
    return NCUSE;
  }
  while (i < bn && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r')) i++;
  if (bn - i >= 10 && memcmp(b + i, "-----BEGIN", 10) == 0) {
    o = (uint8_t *)malloc(bn);
    if (o == NULL) {
      ncfree(b, bn, 0);
      return nclib(cmd, "memory", NQEMEM);
    }
    if (nqarmdec((const char *)b, bn, lab, sizeof lab, o, bn, &k) != NQOK ||
        strcmp(lab, LCERT) != 0) {
      ncmsg(cmd, "%s is not a certificate (-----BEGIN CERTIFICATE-----, or "
            "DER)", path);
      free(o);
      ncfree(b, bn, 0);
      return NCUSE;
    }
    ncfree(b, bn, 0);
    *der = o;
    *n = k;
    return NCOK;
  }
  o = (uint8_t *)malloc(bn > 0 ? bn : 1);
  if (o == NULL) {
    ncfree(b, bn, 0);
    return nclib(cmd, "memory", NQEMEM);
  }
  memcpy(o, b, bn);
  ncfree(b, bn, 0);
  *der = o;
  *n = bn;
  return NCOK;
}

/* writes n bytes to out (- or NULL: stdout) */
static int wrout(const char *cmd, const char *out, const uint8_t *b, size_t n,
                 int force) {
  if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    return fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  }
  if (ncwr(out, b, n, force, 0) != NQOK) {
    ncwfail(cmd, out, force);
    return NCUSE;
  }
  return NCOK;
}

static void show(const nqx5f *f) {
  char hx[65], nb[32], na[32];
  struct tm t;
  const char *an = f->kem ? nqkname((nqkalg)f->alg) : nqsname((nqsalg)f->alg);
  nchexe(f->fp, 32, hx);
  hx[64] = '\0';
  nb[0] = na[0] = '\0';
  if (ncgmtime((time_t)f->nb, &t) == NCOK)
    strftime(nb, sizeof nb, "%Y-%m-%dT%H:%M:%SZ", &t);
  if (ncgmtime((time_t)f->na, &t) == NCOK)
    strftime(na, sizeof na, "%Y-%m-%dT%H:%M:%SZ", &t);
  printf("name         %s\n", ncesc(f->name));
  printf("email        %s\n", ncesc(f->email));
  printf("key          %s%s\n", an != NULL ? an : "another kind",
         f->ca ? " (a CA)" : "");
  printf("valid        %s to %s\n", nb, na);
  printf("fingerprint  %s\n", hx);
}

/* a signature key pair for cmd: kp and kp.pub */
static int sigpair(const char *cmd, const char *kp, const ncpw *pwo,
                   nckey *sk, nckey *pk) {
  uint8_t *pw = NULL;
  size_t pn = 0, l = strlen(kp);
  char *pp;
  int rc;
  if (ncpwget(cmd, pwo, &pw, &pn) != NCOK) return NCUSE;
  rc = nckrdp(cmd, kp, 1, pw, pn, sk);
  ncfree(pw, NQPWLEN, 1);
  if (rc != NCOK) return NCUSE;
  if (pk == NULL) return NCOK;
  pp = (char *)malloc(l + 5);
  if (pp == NULL) return nclib(cmd, "memory", NQEMEM);
  memcpy(pp, kp, l);
  memcpy(pp + l, ".pub", 5);
  rc = nckrd(cmd, pp, 0, pk);
  free(pp);
  return rc;
}

int nccert(int argc, char **argv) {
  const char *kp = NULL, *name = NULL, *email = NULL, *out = NULL;
  const char *days = NULL, *issuer = NULL, *kem = NULL, *sh = NULL;
  int force = 0, help = 0, np, rc, ret = NCUSE;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'n', "name", 1, &name, NULL},
    {'e', "email", 1, &email, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "days", 1, &days, NULL},
    {'\0', "issuer", 1, &issuer, NULL},
    {'\0', "kem", 1, &kem, NULL},
    {'\0', "show", 1, &sh, NULL},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey sk = {{0, 0, NULL}, 1, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  nckey kk = {{0, 0, NULL}, 0, NULL, 0};
  uint8_t *ic = NULL, *c = NULL;
  char *pem = NULL;
  size_t icn = 0, cn = 0, pn = 0;
  long d = 730;
  int64_t now = ncnow();
  nqx5f f;

  if (ncargs("cert", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "cert");
    return NCOK;
  }
  if (now < 0) {
    ncmsg("cert", "%s", NCSDEBAD);
    return NCUSE;
  }
  if (sh != NULL) {
    if (np != 0 || kp != NULL) {
      ncuse(stderr, "cert");
      return NCUSE;
    }
    if (rdcert("cert", sh, &c, &cn) != NCOK) return NCUSE;
    rc = nqx5info(c, cn, &f);
    free(c);
    if (rc != NQOK) {
      ncmsg("cert", "%s is not a certificate (%s)", sh, nqerr(rc));
      return NCUSE;
    }
    show(&f);
    return NCOK;
  }
  if (kp == NULL || out == NULL || np != 0 ||
      (kem == NULL) != (issuer == NULL) || (kem == NULL && name == NULL) ||
      (kem != NULL && (name != NULL || email != NULL))) {
    ncuse(stderr, "cert");
    return NCUSE;
  }
  if (days != NULL) {
    char *end;
    d = strtol(days, &end, 10);
    if (*days == '\0' || *end != '\0' || d < 1 || d > 36500) {
      ncmsg("cert", "--days takes 1 to 36500");
      return NCUSE;
    }
  }
  if (!force && ncexist(out)) {
    ncwfail("cert", out, force);
    return NCUSE;
  }
  cn = 65536;
  c = (uint8_t *)malloc(cn);
  if (c == NULL) return nclib("cert", "memory", NQEMEM);
  if (kem == NULL) {
    if (sigpair("cert", kp, &pwo, &sk, &pk) != NCOK) goto done;
    if (sk.a.kem) {
      ncmsg("cert", "%s is a %s key: a certificate of one's own is for a "
            "signature key; a KEM key gets one with --kem and --issuer",
            kp, sk.a.name);
      goto done;
    }
    /* valid from five minutes ago: clocks differ */
    rc = nqx5self((nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n, name, email,
                  now - 300, now + (int64_t)d * 86400, c, cn, &cn);
  } else {
    if (sigpair("cert", kp, &pwo, &sk, NULL) != NCOK ||
        nckrd("cert", kem, 0, &kk) != NCOK ||
        rdcert("cert", issuer, &ic, &icn) != NCOK)
      goto done;
    if (sk.a.kem || !kk.a.kem) {
      ncmsg("cert", "-k takes the signature key of --issuer, --kem a KEM "
            "public key");
      goto done;
    }
    rc = nqx5kem((nqsalg)sk.a.alg, sk.b, sk.n, ic, icn, (nqkalg)kk.a.alg,
                 kk.b, kk.n, now - 300, now + (int64_t)d * 86400, c, cn, &cn);
  }
  if (rc != NQOK) {
    if (rc == NQENOSUP)
      ncmsg("cert", "no certificate for this kind of key: ML-DSA, SLH-DSA "
            "and Ed25519 sign, ML-KEM receives; a hybrid key has no "
            "standard certificate");
    else if (rc == NQEARG)
      ncmsg("cert", "the key is not the pair of %s, or the name is not 1 to "
            "255 bytes of text, or the address not name@domain.tld",
            kem == NULL ? "its .pub" : "the --issuer certificate");
    else
      nclib("cert", "the certificate", rc);
    goto done;
  }
  if (nqarmlen(LCERT, cn, &pn) != NQOK || (pem = (char *)malloc(pn)) == NULL ||
      nqarmenc(LCERT, c, cn, pem, pn, &pn) != NQOK) {
    nclib("cert", "memory", NQEMEM);
    goto done;
  }
  if (ncwr(out, (const uint8_t *)pem, pn, force, 0) != NQOK) {
    ncwfail("cert", out, force);
    goto done;
  }
  if (nqx5info(c, cn, &f) == NQOK) show(&f);
  ret = NCOK;
done:
  nckfree(&sk);
  nckfree(&pk);
  nckfree(&kk);
  free(ic);
  free(c);
  free(pem);
  return ret;
}

/* ---- smime ---- */

/* the content of a file as a MIME entity: text as it is when text is
 * set (its line ends become CRLF when it is signed), else base64, which
 * gives every byte back */
static int wrap(const uint8_t *b, size_t n, int text, char **out,
                size_t *on) {
  static const char ht[] = "Content-Type: text/plain; charset=utf-8\r\n\r\n";
  static const char hb[] = "Content-Type: application/octet-stream\r\n"
                           "Content-Transfer-Encoding: base64\r\n\r\n";
  size_t cap = n / 48 * 66 + 200, o, i;
  char *m = (char *)malloc(text ? n + sizeof ht : cap);
  if (m == NULL) return NQEMEM;
  if (text) {
    memcpy(m, ht, sizeof ht - 1);
    memcpy(m + sizeof ht - 1, b, n);
    *on = sizeof ht - 1 + n;
  } else {
    memcpy(m, hb, sizeof hb - 1);
    o = sizeof hb - 1;
    for (i = 0; i < n; i += 48) {
      size_t k = n - i < 48 ? n - i : 48;
      ncb64e(b + i, k, m + o);
      o += ncb64n(k) - 1;
      m[o++] = '\r';
      m[o++] = '\n';
    }
    *on = o;
  }
  *out = m;
  return NQOK;
}

/* the body of an entity wrap wrote, in place: *n its length; an entity
 * of another kind is left whole */
static void unwrap(uint8_t *m, size_t *n) {
  size_t i, h = 0, k = 0;
  int b64 = 0;
  for (i = 0; i + 3 < *n; i++) {
    if (memcmp(m + i, "\r\n\r\n", 4) == 0) {
      h = i + 4;
      break;
    }
  }
  if (h == 0) return;
  for (i = 0; i + 33 < h; i++) {
    if (memcmp(m + i, "Content-Transfer-Encoding: base64", 33) == 0) b64 = 1;
  }
  if (!b64) {
    memmove(m, m + h, *n - h);
    *n -= h;
    return;
  }
  if (ncb64d((const char *)m + h, *n - h, m, *n, &k) == NQOK) *n = k;
}

static int smsign(const char *kp, const ncpw *pwo, const char *cp,
                  const char *in, const char *out, int detached, int der,
                  int text, int entity, int force) {
  nckey sk = {{0, 0, NULL}, 1, NULL, 0};
  uint8_t *c = NULL, *b = NULL, *o = NULL;
  char *m = NULL;
  size_t cn = 0, bn = 0, mn = 0, cap, on = 0;
  int64_t now = ncnow();
  int rc, ret = NCUSE;
  if (now < 0) {
    ncmsg("smime", "%s", NCSDEBAD);
    return NCUSE;
  }
  if (sigpair("smime", kp, pwo, &sk, NULL) != NCOK ||
      rdcert("smime", cp, &c, &cn) != NCOK)
    goto done;
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("smime", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  cap = 2 * bn + cn + 300000;
  o = (uint8_t *)malloc(cap);
  if (o == NULL) {
    nclib("smime", "memory", NQEMEM);
    goto done;
  }
  if (der) {
    rc = nqcmssign((nqsalg)sk.a.alg, sk.b, sk.n, c, cn, b, bn, detached,
                   now, o, cap, &on);
  } else {
    if (entity) {
      m = (char *)malloc(bn > 0 ? bn : 1);
      if (m != NULL) memcpy(m, b, bn);
      mn = bn;
    } else if (wrap(b, bn, text, &m, &mn) != NQOK) {
      m = NULL;
    }
    if (m == NULL) {
      nclib("smime", "memory", NQEMEM);
      goto done;
    }
    rc = nqsmsign((nqsalg)sk.a.alg, sk.b, sk.n, c, cn, m, mn, detached,
                  now, (char *)o, cap, &on);
  }
  if (rc != NQOK) {
    if (rc == NQEARG)
      ncmsg("smime", "%s is not the certificate of the key in %s", cp, kp);
    else if (rc == NQENOSUP)
      ncmsg("smime", "%s keys do not sign mail: ML-DSA, SLH-DSA and Ed25519 "
            "do", sk.a.name);
    else
      nclib("smime", "signing", rc);
    goto done;
  }
  ret = wrout("smime", out, o, on, force);
done:
  nckfree(&sk);
  free(c);
  free(m);
  free(o);
  if (b != NULL) ncfree(b, bn, 0);
  return ret;
}

static int smverify(const char **ap, int na, const char *cp, const char *in,
                    const char *out, int entity, int force) {
  const uint8_t *anc[MAXC];
  uint8_t *ab[MAXC], *b = NULL, *ct = NULL, *o = NULL;
  size_t al[MAXC], bn = 0, ctn = 0, on = 0, i = 0;
  nqx5f f;
  int rc, ret = NCUSE, k, der;
  for (k = 0; k < na; k++) ab[k] = NULL;
  for (k = 0; k < na; k++) {
    if (rdcert("smime", ap[k], &ab[k], &al[k]) != NCOK) goto done;
    anc[k] = ab[k];
  }
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("smime", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  if (cp != NULL && ncrdx(cp, 0, NCRDMAX, &ct, &ctn) != NQOK) {
    ncmsg("smime", "cannot read %s%s", cp, ncwhy());
    goto done;
  }
  o = (uint8_t *)malloc(bn + ctn + 1);
  if (o == NULL) {
    nclib("smime", "memory", NQEMEM);
    goto done;
  }
  /* DER starts with a SEQUENCE; a MIME entity with a header field */
  der = bn > 0 && b[0] == 0x30;
  if (der)
    rc = nqcmsvrfy(b, bn, ct, ctn, anc, al, (size_t)na, 0, o, bn + ctn + 1,
                   &on, &f);
  else
    rc = nqsmvrfy((const char *)b, bn, anc, al, (size_t)na, 0, (char *)o,
                  bn + ctn + 1, &on, &f);
  if (rc != NQOK) {
    if (rc == NQEVRFY) {
      printf("%s: FAILED: the signature does not verify, or its signer does "
             "not chain to an --anchor\n", in);
      ret = NCBAD;
    } else if (rc == NQEARG && der && cp == NULL) {
      ncmsg("smime", "%s is a detached signature: give what it signs with "
            "--content <file>", in);
    } else {
      ncmsg("smime", "%s is not a signed message (%s)", in, nqerr(rc));
    }
    goto done;
  }
  if (out != NULL) {
    if (!der && !entity) unwrap(o, &on);
    if (wrout("smime", out, o, on, force) != NCOK) goto done;
  }
  {
    char hx[65];
    nchexe(f.fp, 32, hx);
    hx[64] = '\0';
    fprintf(out != NULL && strcmp(out, "-") == 0 ? stderr : stdout,
            "%s: OK, signed by %s", in, ncesc(f.name));
    if (f.email[0] != '\0')
      fprintf(out != NULL && strcmp(out, "-") == 0 ? stderr : stdout,
              " <%s>", ncesc(f.email));
    fprintf(out != NULL && strcmp(out, "-") == 0 ? stderr : stdout,
            " (certificate %.16s)\n", hx);
  }
  (void)i;
  ret = NCOK;
done:
  for (k = 0; k < na; k++) free(ab[k]);
  free(o);
  if (b != NULL) ncfree(b, bn, 0);
  if (ct != NULL) ncfree(ct, ctn, 0);
  return ret;
}

static int smencrypt(const char **tp, int nt, const char *in, const char *out,
                     int der, int text, int entity, int force) {
  const uint8_t *rc[MAXC];
  uint8_t *rb[MAXC], *b = NULL, *o = NULL;
  char *m = NULL;
  size_t rl[MAXC], bn = 0, mn = 0, cap, on = 0;
  int r, ret = NCUSE, k;
  for (k = 0; k < nt; k++) rb[k] = NULL;
  for (k = 0; k < nt; k++) {
    if (rdcert("smime", tp[k], &rb[k], &rl[k]) != NCOK) goto done;
    rc[k] = rb[k];
  }
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("smime", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  cap = 4 * bn + (size_t)nt * 4096 + 4096;
  o = (uint8_t *)malloc(cap);
  if (o == NULL) {
    nclib("smime", "memory", NQEMEM);
    goto done;
  }
  if (der) {
    r = nqcmsenc(rc, rl, (size_t)nt, b, bn, o, cap, &on);
  } else {
    if (entity) {
      m = (char *)malloc(bn > 0 ? bn : 1);
      if (m != NULL) memcpy(m, b, bn);
      mn = bn;
    } else if (wrap(b, bn, text, &m, &mn) != NQOK) {
      m = NULL;
    }
    if (m == NULL) {
      nclib("smime", "memory", NQEMEM);
      goto done;
    }
    r = nqsmenc(rc, rl, (size_t)nt, m, mn, (char *)o, cap, &on);
  }
  if (r != NQOK) {
    if (r == NQEARG)
      ncmsg("smime", "--to takes certificates of ML-KEM keys (`noqtis cert "
            "--kem`)");
    else
      nclib("smime", "encrypting", r);
    goto done;
  }
  ret = wrout("smime", out, o, on, force);
done:
  for (k = 0; k < nt; k++) free(rb[k]);
  free(m);
  free(o);
  if (b != NULL) ncfree(b, bn, 1);
  return ret;
}

static int smdecrypt(const char *kp, const ncpw *pwo, const char *cp,
                     const char *in, const char *out, int entity, int force) {
  nckey sk = {{0, 0, NULL}, 1, NULL, 0};
  uint8_t *c = NULL, *b = NULL, *o = NULL;
  size_t cn = 0, bn = 0, on = 0;
  int rc, ret = NCUSE, der;
  if (sigpair("smime", kp, pwo, &sk, NULL) != NCOK ||
      (cp != NULL && rdcert("smime", cp, &c, &cn) != NCOK))
    goto done;
  if (!sk.a.kem) {
    ncmsg("smime", "decrypt takes an ML-KEM secret key; %s is a %s key", kp,
          sk.a.name);
    goto done;
  }
  if (ncrdx(in, 0, NCRDMAX, &b, &bn) != NQOK) {
    ncmsg("smime", "cannot read %s%s", in, ncwhy());
    goto done;
  }
  o = (uint8_t *)malloc(bn + 1);
  if (o == NULL) {
    nclib("smime", "memory", NQEMEM);
    goto done;
  }
  der = bn > 0 && b[0] == 0x30;
  rc = der ? nqcmsdec((nqkalg)sk.a.alg, sk.b, sk.n, c, cn, b, bn, o, bn + 1,
                      &on)
           : nqsmdec((nqkalg)sk.a.alg, sk.b, sk.n, c, cn, (const char *)b,
                     bn, (char *)o, bn + 1, &on);
  if (rc != NQOK) {
    if (rc == NQEVRFY)
      ncmsg("smime", "%s does not open with %s: it is not for this key, or "
            "it was changed", in, kp);
    else if (rc == NQENOSUP)
      ncmsg("smime", "%s keys do not open mail: ML-KEM keys do", sk.a.name);
    else
      ncmsg("smime", "%s is not an encrypted message (%s)", in, nqerr(rc));
    goto done;
  }
  if (!der && !entity) unwrap(o, &on);
  ret = wrout("smime", out, o, on, force);
done:
  nckfree(&sk);
  free(c);
  if (o != NULL) ncfree(o, bn + 1, 1);
  if (b != NULL) ncfree(b, bn, 0);
  return ret;
}

int ncsmime(int argc, char **argv) {
  const char *kp = NULL, *cp = NULL, *out = NULL, *content = NULL;
  const char *anc[NCMAXV], *to[NCMAXV], *sub;
  int force = 0, help = 0, np, nanc = 0, nto = 0, det = 0, der = 0;
  int text = 0, entity = 0;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'\0', "cert", 1, &cp, NULL},
    {'\0', "anchor", NCMANY, anc, &nanc},
    {'\0', "to", NCMANY, to, &nto},
    {'\0', "content", 1, &content, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "detached", 0, NULL, &det},
    {'\0', "der", 0, NULL, &der},
    {'\0', "text", 0, NULL, &text},
    {'\0', "entity", 0, NULL, &entity},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };

  if (ncargs("smime", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "smime");
    return NCOK;
  }
  if (np != 2 || (text && entity) || (der && (text || entity))) {
    ncuse(stderr, "smime");
    return NCUSE;
  }
  sub = argv[0];
  if (strcmp(sub, "sign") == 0 && kp != NULL && cp != NULL && nanc == 0 &&
      nto == 0 && content == NULL)
    return smsign(kp, &pwo, cp, argv[1], out, det, der, text, entity, force);
  if (strcmp(sub, "verify") == 0 && nanc > 0 && kp == NULL && cp == NULL &&
      nto == 0 && !det && !der && !text)
    return smverify(anc, nanc, content, argv[1], out, entity, force);
  if (strcmp(sub, "encrypt") == 0 && nto > 0 && kp == NULL && cp == NULL &&
      nanc == 0 && content == NULL && !det)
    return smencrypt(to, nto, argv[1], out, der, text, entity, force);
  if (strcmp(sub, "decrypt") == 0 && kp != NULL && nanc == 0 && nto == 0 &&
      content == NULL && !det && !der && !text)
    return smdecrypt(kp, &pwo, cp, argv[1], out, entity, force);
  ncuse(stderr, "smime");
  return NCUSE;
}
