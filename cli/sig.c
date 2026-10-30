/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis keygen, sign and verify. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

#define NCSEEDX 256 /* longest seed accepted */
#define NCCTXX 255  /* longest context string (FIPS 204/205) */

/* whether the n bytes at b contain the string s */
static int hasstr(const uint8_t *b, size_t n, const char *s) {
  size_t m = strlen(s), i;
  if (m == 0 || n < m) return 0;
  for (i = 0; i + m <= n; i++) {
    if (b[i] == (uint8_t)s[0] && memcmp(b + i, s, m) == 0) return 1;
  }
  return 0;
}

/* The seed from --seed: a file holding the raw bytes when one exists by
 * that name, else hex digits. */
static int seedrd(const char *cmd, const char *arg, uint8_t *seed,
                  size_t *n) {
  if (ncexist(arg)) {
    uint8_t *b;
    size_t bn;
    if (ncrdx(arg, 1, 4096, &b, &bn) != NQOK) {
      ncmsg(cmd, "cannot read seed file %s", arg);
      return NCUSE;
    }
    if (bn == 0 || bn > NCSEEDX) {
      ncfree(b, bn, 1);
      ncmsg(cmd, "seed file %s must hold 1 to %d bytes", arg, NCSEEDX);
      return NCUSE;
    }
    memcpy(seed, b, bn);
    *n = bn;
    ncfree(b, bn, 1);
    return NCOK;
  }
  if (nchexd(arg, strlen(arg), seed, NCSEEDX, n) != NQOK || *n == 0) {
    ncmsg(cmd, "--seed is neither a file nor an even number of hex digits");
    return NCUSE;
  }
  ncmsg(cmd, "warning: a seed given as hex on the command line can be "
             "seen by other users (the process list, shell history); "
             "give a seed file instead");
  return NCOK;
}

int nckeygen(int argc, char **argv) {
  const char *an = NULL, *out = NULL, *sd = NULL;
  int force = 0, help = 0, np, rc;
  ncopt o[] = {
    {'a', "alg", 1, &an, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "seed", 1, &sd, NULL},
    {'f', "force", 0, NULL, &force}
  };
  ncalg a = {0, 0, NULL};
  uint8_t seed[NCSEEDX], *pk = NULL, *sk = NULL;
  size_t sn = 0, pkn, skn, pl;
  char *pp = NULL;
  FILE *fs = NULL, *fp = NULL;
  int ret = NCUSE;

  if (ncargs("keygen", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "keygen");
    return NCOK;
  }
  if (an == NULL || out == NULL || np != 0) {
    ncuse(stderr, "keygen");
    return NCUSE;
  }
  if (ncfind(an, &a) != NQOK) {
    ncmsg("keygen", "unknown algorithm %s (see `noqtis algs`)", an);
    return NCUSE;
  }
  if (ncksz(&a, &pkn, &skn) != NQOK)
    return nclib("keygen", a.name, NQENOSUP);
  if (sd != NULL && seedrd("keygen", sd, seed, &sn) != NCOK)
    return NCUSE;
  pl = strlen(out);
  pp = (char *)malloc(pl + 5);
  pk = (uint8_t *)malloc(pkn);
  sk = (uint8_t *)malloc(skn);
  if (pp == NULL || pk == NULL || sk == NULL) {
    nclib("keygen", "memory", NQEMEM);
    goto done;
  }
  memcpy(pp, out, pl);
  memcpy(pp + pl, ".pub", 5);
  if (a.kem)
    rc = sd != NULL ? nqkkgd((nqkalg)a.alg, seed, sn, pk, pkn, sk, skn)
                    : nqkkg((nqkalg)a.alg, pk, pkn, sk, skn);
  else
    rc = sd != NULL ? nqskgd((nqsalg)a.alg, seed, sn, pk, pkn, sk, skn)
                    : nqskg((nqsalg)a.alg, pk, pkn, sk, skn);
  if (rc != NQOK) {
    nclib("keygen", sd != NULL ? "key generation from the seed"
                               : "key generation", rc);
    goto done;
  }
  fs = ncopen(out, force, 1);
  if (fs == NULL) {
    ncwfail("keygen", out, force);
    goto done;
  }
  fp = ncopen(pp, force, 0);
  if (fp == NULL) {
    ncwfail("keygen", pp, force);
    (void)ncclose(fs, out, 1);
    fs = NULL;
    goto done;
  }
  rc = nckwr(fs, &a, 1, sk, skn);
  rc = ncclose(fs, out, rc != NQOK);
  fs = NULL;
  if (rc != NQOK) {
    (void)ncclose(fp, pp, 1);
    ncmsg("keygen", "cannot write %s", out);
    goto done;
  }
  rc = nckwr(fp, &a, 0, pk, pkn);
  if (ncclose(fp, pp, rc != NQOK) != NQOK) {
    ncmsg("keygen", "cannot write %s", pp);
    goto done;
  }
  printf("%s key pair: %s (secret), %s (public)\n", a.name, out, pp);
  ret = NCOK;
done:
  nqwipe(seed, sizeof seed);
  ncfree(sk, skn, 1);
  free(pk);
  free(pp);
  return ret;
}

/* Pre-hash option: 0 for none. */
static int phopt(const char *cmd, const char *ph, int *out) {
  nqhalg h = NQS256;
  *out = 0;
  if (ph == NULL)
    return NCOK;
  if (nchalg(ph, &h) != NQOK) {
    ncmsg(cmd, "unknown pre-hash %s", ph);
    return NCUSE;
  }
  *out = (int)h;
  return NCOK;
}

static int ctxopt(const char *cmd, const char *c, size_t *n) {
  *n = c != NULL ? strlen(c) : 0;
  if (*n > NCCTXX) {
    ncmsg(cmd, "the context is %lu bytes; at most %d are allowed",
          (unsigned long)*n, NCCTXX);
    return NCUSE;
  }
  return NCOK;
}

/* checks sig with the public key file beside the secret key kp, if any */
static int vas(const char *kp, const nckey *k, const uint8_t *msg,
               size_t mn, const char *ctx, size_t cn, int phv,
               const uint8_t *sig, size_t sl) {
  nckey p = {{0, 0, NULL}, 0, NULL, 0};
  size_t l = strlen(kp);
  char *pp = (char *)malloc(l + 5);
  int ret = NCUSE, rc;
  if (pp == NULL) {
    nclib("sign", "memory", NQEMEM);
    return NCUSE;
  }
  memcpy(pp, kp, l);
  memcpy(pp + l, ".pub", 5);
  if (!ncexist(pp)) {
    free(pp);
    return NCOK; /* nothing to check against */
  }
  if (nckrd("sign", pp, 0, &p) != NCOK)
    goto done;
  if (p.a.kem || p.a.alg != k->a.alg) {
    ncmsg("sign", "%s (%s) is not the public key of %s (%s): nothing was "
          "written", pp, p.a.name, kp, k->a.name);
    goto done;
  }
  rc = nqvrfy((nqsalg)k->a.alg, p.b, p.n, msg, mn, (const uint8_t *)ctx,
              cn, phv, sig, sl);
  if (rc != NQOK) {
    ncmsg("sign", "the new signature does not verify with %s, so it was "
          "not written: %s and %s are not one key pair, or signing went "
          "wrong (a hardware fault); sign again, and check the key files",
          pp, kp, pp);
    goto done;
  }
  ret = NCOK;
done:
  nckfree(&p);
  free(pp);
  return ret;
}

int ncsign(int argc, char **argv) {
  const char *kp = NULL, *out = NULL, *ctx = NULL, *ph = NULL;
  int det = 0, force = 0, help = 0, np, rc, phv, ret = NCUSE;
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &out, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'d', "det", 0, NULL, &det},
    {'\0', "ph", 1, &ph, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqssz z = {0, 0, 0};
  uint8_t *msg = NULL, *sig = NULL, rnd[64];
  size_t mn = 0, cn, sl = 0;
  char *dp = NULL;

  if (ncargs("sign", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "sign");
    return NCOK;
  }
  if (kp == NULL || np != 1) {
    ncuse(stderr, "sign");
    return NCUSE;
  }
  if (strcmp(argv[0], "-") == 0 && out == NULL) {
    ncmsg("sign", "signing stdin needs -o <sig>");
    return NCUSE;
  }
  if (phopt("sign", ph, &phv) != NCOK || ctxopt("sign", ctx, &cn) != NCOK)
    return NCUSE;
  if (nckrd("sign", kp, 1, &k) != NCOK)
    return NCUSE;
  if (k.a.kem) {
    ncmsg("sign", "%s is a %s (KEM) key, not a signature key", kp,
          k.a.name);
    goto done;
  }
  if (nqssize((nqsalg)k.a.alg, &z) != NQOK) {
    nclib("sign", k.a.name, NQENOSUP);
    goto done;
  }
  if (out == NULL) {
    size_t l = strlen(argv[0]);
    dp = (char *)malloc(l + 5);
    if (dp == NULL) {
      nclib("sign", "memory", NQEMEM);
      goto done;
    }
    memcpy(dp, argv[0], l);
    memcpy(dp + l, ".sig", 5);
    out = dp;
  }
  if (!force && ncexist(out)) {
    ncwfail("sign", out, force);
    goto done;
  }
  if (ncrd(argv[0], 0, &msg, &mn) != NQOK) {
    ncmsg("sign", "cannot read %s", argv[0]);
    goto done;
  }
  /* someone may hand over a capsule manifest as "a document to sign": a
   * plain signature never makes a seal (seals use their own context), but
   * say so */
  if (mn > 30 && mn < ((size_t)1 << 28) && msg[0] == '{' &&
      hasstr(msg, mn, "\"format\":\"noqtis-capsule-1\"")) {
    ncmsg("sign", "warning: %s is a capsule manifest (noqtis.json); this "
          "signs it as a plain file, which is not a seal: to seal a "
          "folder, use `noqtis seal`", argv[0]);
  }
  sig = (uint8_t *)malloc(z.sig);
  if (sig == NULL) {
    nclib("sign", "memory", NQEMEM);
    goto done;
  }
  if (det) {
    /* all-zero rnd: 32 bytes for ML-DSA and the hybrids, none for
     * Ed25519, n = |pk|/2 for SLH-DSA */
    size_t rl = k.a.alg <= (int)NQMLDSA87 || k.a.alg >= (int)NQMDED44
                    ? 32
                    : (k.a.alg == (int)NQED25519 ? 0 : z.pk / 2);
    memset(rnd, 0, sizeof rnd);
    rc = nqsignd((nqsalg)k.a.alg, k.b, k.n, msg, mn,
                 (const uint8_t *)ctx, cn, phv, rnd, rl, sig, z.sig, &sl);
  } else {
    rc = nqsign((nqsalg)k.a.alg, k.b, k.n, msg, mn, (const uint8_t *)ctx,
                cn, phv, sig, z.sig, &sl);
  }
  if (rc != NQOK) {
    nclib("sign", "signing", rc);
    goto done;
  }
  /* verify before writing, with <key>.pub when it is there: a signature
   * that does not verify (a wrong pair, or a fault while signing) is never
   * written */
  if (vas(kp, &k, msg, mn, ctx, cn, phv, sig, sl) != NCOK)
    goto done;
  rc = ncwr(out, sig, sl, force, 0);
  if (rc != NQOK) {
    ncwfail("sign", out, force);
    goto done;
  }
  ret = NCOK;
done:
  nckfree(&k);
  free(msg);
  free(sig);
  free(dp);
  return ret;
}

int ncvrfy(int argc, char **argv) {
  const char *kp = NULL, *sp = NULL, *ctx = NULL, *ph = NULL, *op = NULL;
  int quiet = 0, help = 0, np, rc, phv, ret = NCUSE, dsse = 0;
  ncopt o[] = {
    {'p', "pub", 1, &kp, NULL},
    {'s', "sig", 1, &sp, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'\0', "ph", 1, &ph, NULL},
    {'q', "quiet", 0, NULL, &quiet},
    {'\0', "dsse", 0, NULL, &dsse},
    {'o', "out", 1, &op, NULL}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqssz z = {0, 0, 0};
  uint8_t *msg = NULL, *sig = NULL;
  size_t mn = 0, sn = 0, cn;

  if (ncargs("verify", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "verify");
    return NCOK;
  }
  if (dsse) {
    if (kp == NULL || sp != NULL || ctx != NULL || ph != NULL || np != 1) {
      ncuse(stderr, "verify");
      return NCUSE;
    }
    return ncvdsse(kp, argv[0], op, quiet);
  }
  if (kp == NULL || sp == NULL || np != 1 || op != NULL) {
    ncuse(stderr, "verify");
    return NCUSE;
  }
  if (phopt("verify", ph, &phv) != NCOK ||
      ctxopt("verify", ctx, &cn) != NCOK)
    return NCUSE;
  if (nckrd("verify", kp, 0, &k) != NCOK)
    return NCUSE;
  if (k.a.kem) {
    ncmsg("verify", "%s is a %s (KEM) key, not a signature key", kp,
          k.a.name);
    goto done;
  }
  if (nqssize((nqsalg)k.a.alg, &z) != NQOK) {
    nclib("verify", k.a.name, NQENOSUP);
    goto done;
  }
  if (ncrdx(sp, 0, NCRDSMALL, &sig, &sn) != NQOK) {
    ncmsg("verify", "cannot read %s", sp);
    goto done;
  }
  if (ncrd(argv[0], 0, &msg, &mn) != NQOK) {
    ncmsg("verify", "cannot read %s", argv[0]);
    goto done;
  }
  if (sn != z.sig) {
    ncmsg("verify", "%s: FAILED: the signature is %lu bytes; %s "
          "signatures are %lu", argv[0], (unsigned long)sn, k.a.name,
          (unsigned long)z.sig);
    ret = NCBAD;
    goto done;
  }
  rc = nqvrfy((nqsalg)k.a.alg, k.b, k.n, msg, mn, (const uint8_t *)ctx, cn,
              phv, sig, sn);
  if (rc == NQOK) {
    if (!quiet)
      printf("%s: OK (%s)\n", ncesc(argv[0]), k.a.name);
    ret = NCOK;
  } else if (rc == NQEVRFY || rc == NQEDEC) {
    ncmsg("verify", "%s: FAILED: the signature does not verify", argv[0]);
    ret = NCBAD;
  } else {
    nclib("verify", "verification", rc);
  }
done:
  nckfree(&k);
  free(msg);
  free(sig);
  return ret;
}
