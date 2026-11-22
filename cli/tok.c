/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis token: keys on a PKCS #11 token (a smart card, a hardware
 * security module, a software token). The private key stays there; the
 * token signs and decapsulates.
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

#define MAXK 64

/* what the library said, with the module's own return value */
static int p11fail(nqp11 *p, const char *what, int rc) {
  if (rc == NQEVRFY)
    ncmsg("token", "%s: the PIN is wrong, or the token has locked it", what);
  else if (rc == NQENOSUP)
    ncmsg("token", "%s: the token does not do this (CKR 0x%lx)", what,
          nqp11why(p));
  else if (rc == NQEIO)
    ncmsg("token", "%s: the token refused (CKR 0x%lx)", what, nqp11why(p));
  else
    ncmsg("token", "%s: %s", what, nqerr(rc));
  return NCUSE;
}

/* loads the module: --module, else $NOQTIS_PKCS11 */
static int modopen(const char *mod, nqp11 **p) {
  int rc;
  if (mod == NULL) mod = getenv("NOQTIS_PKCS11");
  if (mod == NULL || mod[0] == '\0') {
    ncmsg("token", "which PKCS #11 module? Give its path with --module, or "
          "in the variable NOQTIS_PKCS11");
    return NCUSE;
  }
  rc = nqp11open(mod, p);
  if (rc == NQOK) return NCOK;
  if (rc == NQEARG)
    ncmsg("token", "%s: give the module as a path (./%s for one in this "
          "folder), not a name to search for", ncesc(mod), ncesc(mod));
  else if (rc == NQEDEC)
    ncmsg("token", "%s is not a PKCS #11 module", ncesc(mod));
  else if (rc == NQENOSUP)
    ncmsg("token", "this build of noqtis loads no modules");
  else
    ncmsg("token", "cannot load %s (%s)", ncesc(mod), nqerr(rc));
  return NCUSE;
}

/* a session with the token in --slot (default: the only token), logged
 * in when a PIN was given */
static int login(nqp11 *p, const char *slot, const ncpw *pwo) {
  nqp11t t[MAXK];
  uint8_t *pin = NULL;
  size_t n = 0, pn = 0;
  unsigned long s;
  char *end = NULL;
  int rc;
  if (slot != NULL) {
    s = strtoul(slot, &end, 10);
    if (slot[0] == '\0' || slot[0] == '-' || end == NULL || *end != '\0') {
      ncmsg("token", "--slot takes a slot number (see `noqtis token list`)");
      return NCUSE;
    }
  } else {
    rc = nqp11toks(p, t, MAXK, &n);
    if (rc != NQOK && rc != NQEBUF) return p11fail(p, "listing tokens", rc);
    if (n != 1) {
      ncmsg("token", n == 0 ? "no token is present"
                            : "more than one token is present: name one "
                              "with --slot (see `noqtis token list`)");
      return NCUSE;
    }
    s = t[0].slot;
  }
  if (ncpwgetn("token", pwo, "pin", &pin, &pn) != NCOK) return NCUSE;
  rc = nqp11login(p, s, (const char *)pin, pn);
  if (pin != NULL) ncfree(pin, NQPWLEN, 1);
  return rc == NQOK ? NCOK : p11fail(p, "opening the token", rc);
}

/* the one key with the label, or with the ID in hex */
static int pick(nqp11 *p, const char *label, const char *id, nqp11k *k) {
  static nqp11k ks[MAXK];
  uint8_t want[32];
  size_t n = 0, wn = 0, i, hit = MAXK, hits = 0;
  int rc;
  if ((label == NULL) == (id == NULL)) {
    ncmsg("token", "name the key with --label or with --id (see `noqtis "
          "token keys`)");
    return NCUSE;
  }
  if (id != NULL && (nchexd(id, strlen(id), want, sizeof want, &wn) != NQOK ||
                     wn == 0)) {
    ncmsg("token", "--id takes the key's ID in hexadecimal");
    return NCUSE;
  }
  rc = nqp11keys(p, ks, MAXK, &n);
  if (rc != NQOK && rc != NQEBUF) return p11fail(p, "listing keys", rc);
  if (n > MAXK) n = MAXK;
  for (i = 0; i < n; i++) {
    if (label != NULL ? strcmp(ks[i].label, label) == 0
                      : ks[i].idlen == wn && memcmp(ks[i].id, want, wn) == 0) {
      hit = i;
      hits++;
    }
  }
  if (hits != 1) {
    ncmsg("token", hits == 0 ? "no key of that %s on the token (without the "
                               "PIN its private keys are not shown)"
                             : "more than one key of that %s: name it with "
                               "--id",
          label != NULL ? "label" : "ID");
    return NCUSE;
  }
  *k = ks[hit];
  return NCOK;
}

static const char *kname(const nqp11k *k) {
  const char *s = k->kem ? nqkname((nqkalg)k->alg) : nqsname((nqsalg)k->alg);
  return s != NULL ? s : "?";
}

int nctkopen(const char *mod, const char *slot, const ncpw *pwo,
             const char *label, const char *id, nqp11 **p, nqp11k *k) {
  *p = NULL;
  if (modopen(mod, p) != NCOK) return NCUSE;
  if (login(*p, slot, pwo) != NCOK || pick(*p, label, id, k) != NCOK) {
    nqp11close(*p);
    *p = NULL;
    return NCUSE;
  }
  return NCOK;
}

const char *nctkname(const nqp11k *k) { return kname(k); }

int nctkfail(nqp11 *p, const char *what, int rc) {
  return p11fail(p, what, rc);
}

/* the public key of k as a key file at out */
static int pubwrite(nqp11 *p, const nqp11k *k, const char *out, int force) {
  uint8_t pk[4096];
  size_t n = 0;
  ncalg a;
  FILE *f;
  int rc = nqp11pub(p, k, pk, sizeof pk, &n);
  if (rc != NQOK) return p11fail(p, "reading the public key", rc);
  if (ncfind(kname(k), &a) != NQOK) return NCUSE;
  f = ncopen(out, force, 0);
  if (f == NULL) {
    ncwfail("token", out, force);
    return NCUSE;
  }
  rc = nckwr(f, &a, 0, pk, n);
  if (ncclose(f, out, rc != NQOK) != NQOK || rc != NQOK) {
    ncmsg("token", "cannot write %s%s", out, ncwhy());
    return NCUSE;
  }
  return NCOK;
}

static int toklist(nqp11 *p) {
  nqp11t t[MAXK];
  size_t n = 0, i;
  int rc = nqp11toks(p, t, MAXK, &n);
  if (rc != NQOK && rc != NQEBUF) return p11fail(p, "listing tokens", rc);
  if (n > MAXK) n = MAXK;
  for (i = 0; i < n; i++) {
    printf("slot %lu  %s", t[i].slot, ncesc(t[i].label));
    printf("  (%s", ncesc(t[i].maker));
    printf(" %s", ncesc(t[i].model));
    printf(", serial %s)%s\n", ncesc(t[i].serial),
           t[i].login ? "  PIN needed" : "");
  }
  if (n == 0) printf("no token is present\n");
  return NCOK;
}

static int tokkeys(nqp11 *p) {
  static nqp11k ks[MAXK];
  char hx[65];
  size_t n = 0, i;
  int rc = nqp11keys(p, ks, MAXK, &n);
  if (rc != NQOK && rc != NQEBUF) return p11fail(p, "listing keys", rc);
  if (n > MAXK) n = MAXK;
  for (i = 0; i < n; i++) {
    nchexe(ks[i].id, ks[i].idlen, hx);
    hx[2 * ks[i].idlen] = '\0';
    printf("%-22s %s", kname(&ks[i]), hx);
    printf("  %s\n", ncesc(ks[i].label));
  }
  if (n == 0)
    printf("no private key noqtis can use (without the PIN they are not "
           "shown)\n");
  return NCOK;
}

static int tokgen(nqp11 *p, const char *alg, const char *label,
                  const char *out, int force) {
  ncalg a;
  nqp11k k;
  char hx[65];
  int rc;
  if (ncfind(alg, &a) != NQOK) {
    ncmsg("token", "%s is not an algorithm (see `noqtis list`)", ncesc(alg));
    return NCUSE;
  }
  rc = nqp11gen(p, a.kem, a.alg, label, &k);
  if (rc == NQENOSUP && nqp11why(p) == 0) {
    ncmsg("token", "PKCS #11 has no key type for %s: ML-DSA, SLH-DSA, "
          "Ed25519 and ML-KEM keys are made on tokens", a.name);
    return NCUSE;
  }
  if (rc == NQEARG) {
    ncmsg("token", "the label is 1 to 64 bytes");
    return NCUSE;
  }
  if (rc != NQOK) return p11fail(p, "making the key", rc);
  nchexe(k.id, k.idlen, hx);
  hx[2 * k.idlen] = '\0';
  printf("%s key %s made on the token, ID %s\n", a.name, ncesc(label), hx);
  return out != NULL ? pubwrite(p, &k, out, force) : NCOK;
}

static int toksign(nqp11 *p, const nqp11k *k, const char *ctx,
                   const char *in, const char *out, int force) {
  uint8_t *msg = NULL, *sig = NULL, pk[4096];
  size_t mn = 0, sn = 0, pn = 0, cn = ctx != NULL ? strlen(ctx) : 0;
  nqssz z;
  int rc, ret = NCUSE;
  if (k->kem || nqssize((nqsalg)k->alg, &z) != NQOK) {
    ncmsg("token", "%s is a %s key: it does not sign", ncesc(k->label),
          kname(k));
    return NCUSE;
  }
  if (cn > 255) {
    ncmsg("token", "the context is at most 255 bytes");
    return NCUSE;
  }
  if (ncrdx(in, 0, NCRDMAX, &msg, &mn) != NQOK) {
    ncmsg("token", "cannot read %s%s", in, ncwhy());
    return NCUSE;
  }
  sig = (uint8_t *)malloc(z.sig);
  if (sig == NULL) {
    nclib("token", "memory", NQEMEM);
    goto done;
  }
  rc = nqp11sign(p, k, msg, mn, (const uint8_t *)ctx, cn, sig, z.sig, &sn);
  if (rc != NQOK) {
    p11fail(p, "signing", rc);
    goto done;
  }
  /* what the token gave is written only when it verifies under the
   * token's own public key */
  rc = nqp11pub(p, k, pk, sizeof pk, &pn);
  if (rc == NQOK)
    rc = nqvrfy((nqsalg)k->alg, pk, pn, msg, mn, (const uint8_t *)ctx, cn, 0,
                sig, sn);
  if (rc != NQOK) {
    ncmsg("token", "the signature the token made does not verify under its "
          "public key: nothing is written");
    goto done;
  }
  if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    ret = fwrite(sig, 1, sn, stdout) == sn && fflush(stdout) == 0 ? NCOK
                                                                  : NCUSE;
  } else if (ncwr(out, sig, sn, force, 0) != NQOK) {
    ncwfail("token", out, force);
  } else {
    ret = NCOK;
  }
done:
  if (msg != NULL) ncfree(msg, mn, 0);
  free(sig);
  return ret;
}

static int tokdec(nqp11 *p, const nqp11k *k, const char *in, const char *out,
                  int force) {
  uint8_t *ct = NULL, ss[64];
  size_t cn = 0;
  nqksz z;
  int rc, ret = NCUSE;
  if (!k->kem || nqksize((nqkalg)k->alg, &z) != NQOK || z.ss > sizeof ss) {
    ncmsg("token", "%s is a %s key: it does not decapsulate",
          ncesc(k->label), kname(k));
    return NCUSE;
  }
  if (ncrdx(in, 0, NCRDSMALL, &ct, &cn) != NQOK) {
    ncmsg("token", "cannot read %s%s", in, ncwhy());
    return NCUSE;
  }
  if (cn != z.ct) {
    ncmsg("token", "%s is not a %s ciphertext (%lu bytes, not %lu)", in,
          kname(k), (unsigned long)cn, (unsigned long)z.ct);
    goto done;
  }
  rc = nqp11dec(p, k, ct, cn, ss, z.ss);
  if (rc != NQOK) {
    if (rc == NQENOSUP)
      ncmsg("token", "the token's module is older than PKCS #11 version "
            "3.2: it cannot decapsulate");
    else
      p11fail(p, "decapsulating", rc);
    goto done;
  }
  if (ncwr(out, ss, z.ss, force, 1) != NQOK)
    ncwfail("token", out, force);
  else
    ret = NCOK;
done:
  nqwipe(ss, sizeof ss);
  if (ct != NULL) ncfree(ct, cn, 0);
  return ret;
}

int nctoken(int argc, char **argv) {
  const char *mod = NULL, *slot = NULL, *label = NULL, *id = NULL;
  const char *alg = NULL, *out = NULL, *ctx = NULL, *sub;
  int force = 0, help = 0, np, ret = NCUSE;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'m', "module", 1, &mod, NULL},
    {'\0', "slot", 1, &slot, NULL},
    {'n', "label", 1, &label, NULL},
    {'\0', "id", 1, &id, NULL},
    {'a', "alg", 1, &alg, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "pin-fd", 1, &pwo.fd, NULL},
    {'\0', "pin-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nqp11 *p = NULL;
  nqp11k k;

  if (ncargs("token", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "token");
    return NCOK;
  }
  if (np < 1) {
    ncuse(stderr, "token");
    return NCUSE;
  }
  sub = argv[0];
  /* the shape of each form, before the module is loaded */
  if (strcmp(sub, "list") == 0) {
    if (np != 1 || slot || label || id || alg || ctx || out) goto use;
  } else if (strcmp(sub, "keys") == 0) {
    if (np != 1 || label || id || alg || ctx || out) goto use;
  } else if (strcmp(sub, "keygen") == 0) {
    if (np != 1 || alg == NULL || label == NULL || id || ctx) goto use;
  } else if (strcmp(sub, "pub") == 0) {
    if (np != 1 || alg || ctx || out == NULL) goto use;
  } else if (strcmp(sub, "sign") == 0) {
    if (np != 2 || alg) goto use;
  } else if (strcmp(sub, "dec") == 0) {
    if (np != 2 || alg || ctx || out == NULL) goto use;
  } else {
    goto use;
  }
  if (modopen(mod, &p) != NCOK) return NCUSE;
  if (strcmp(sub, "list") == 0) {
    ret = toklist(p);
  } else if (login(p, slot, &pwo) != NCOK) {
    ret = NCUSE;
  } else if (strcmp(sub, "keys") == 0) {
    ret = tokkeys(p);
  } else if (strcmp(sub, "keygen") == 0) {
    ret = tokgen(p, alg, label, out, force);
  } else if (pick(p, label, id, &k) != NCOK) {
    ret = NCUSE;
  } else if (strcmp(sub, "pub") == 0) {
    ret = pubwrite(p, &k, out, force);
  } else if (strcmp(sub, "sign") == 0) {
    ret = toksign(p, &k, ctx, argv[1], out, force);
  } else {
    ret = tokdec(p, &k, argv[1], out, force);
  }
  nqp11close(p);
  return ret;
use:
  ncuse(stderr, "token");
  return NCUSE;
}
