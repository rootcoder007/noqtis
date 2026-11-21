/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis keys: the key store (nqksadd and the functions beside it): other
 * people's public keys by name, the certifications of them, and the trust
 * the owner places in their holders.
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXE 4096 /* entries one listing prints */

static const char *const tname[] = {"unknown", "never", "marginal", "full",
                                    "ultimate"};
static const char *const vname[] = {"not valid", "marginal", "valid"};

static const char *algof(const nqkse *e) {
  const char *n = e->kem ? nqkname((nqkalg)e->alg) : nqsname((nqsalg)e->alg);
  return n != NULL ? n : "?";
}

static void line(const nqkse *e) {
  char hx[65];
  nchexe(e->fp, 32, hx);
  hx[64] = '\0';
  printf("%.16s  %-22s  %-9s  %-9s  %lu  ", hx, algof(e), tname[e->trust],
         vname[e->valid], (unsigned long)e->ncert);
  /* ncesc keeps one result at a time */
  fputs(ncesc(e->name), stdout);
  if (e->email[0] != '\0') printf(" <%s>", ncesc(e->email));
  fputs(e->card ? "  [card]\n" : "\n", stdout);
}

/* every folder on the way to p, then p */
static void mkpath(const char *p) {
  size_t n = strlen(p), i;
  char *t = (char *)malloc(n + 1);
  if (t == NULL) return;
  memcpy(t, p, n + 1);
  for (i = 1; i < n; i++) {
    if (t[i] == '/' || t[i] == '\\') {
      char c = t[i];
      t[i] = '\0';
      (void)ncmkdir(t);
      t[i] = c;
    }
  }
  (void)ncmkdir(t);
  free(t);
}

/* the one entry of the store that answers q; NCUSE (said why) when none
 * or several do */
static int one(const char *dir, const char *q, nqkse *e) {
  nqkse two[2];
  size_t n = 0;
  int rc = nqkslist(dir, q, two, 2, &n);
  if (rc != NQOK && rc != NQEBUF) {
    ncmsg("keys", "cannot read the key store %s (%s)", dir, nqerr(rc));
    return NCUSE;
  }
  if (n == 0) {
    ncmsg("keys", "no key in the store answers \"%s\" (`noqtis keys list` "
          "shows them)", q);
    return NCUSE;
  }
  if (n > 1) {
    ncmsg("keys", "%lu keys answer \"%s\": give more of the name, or the "
          "start of the fingerprint", (unsigned long)n, q);
    return NCUSE;
  }
  *e = two[0];
  return NCOK;
}

/* one() for a bundle, which is of a key with an identity card: when
 * several keys answer q (a holder's signature key and KEM key bear one
 * name) and one of them alone has a card, that one */
static int onecard(const char *dir, const char *q, nqkse *e) {
  nqkse *all = (nqkse *)malloc(MAXE * sizeof *all);
  size_t n = 0, i, hit = MAXE, cards = 0;
  int rc;
  if (all == NULL) return nclib("keys", "memory", NQEMEM);
  rc = nqkslist(dir, q, all, MAXE, &n);
  if ((rc == NQOK || rc == NQEBUF) && n > 1 && n <= MAXE) {
    for (i = 0; i < n; i++) {
      if (all[i].card) {
        hit = i;
        cards++;
      }
    }
    if (cards == 1) {
      *e = all[hit];
      free(all);
      return NCOK;
    }
  }
  free(all);
  return one(dir, q, e);
}

static int list(const char *dir, const char *q, int find) {
  nqkse *e = (nqkse *)malloc(MAXE * sizeof *e);
  size_t n = 0, i;
  int rc;
  if (e == NULL) return nclib("keys", "memory", NQEMEM);
  rc = nqkslist(dir, q, e, MAXE, &n);
  if (rc != NQOK && rc != NQEBUF) {
    free(e);
    /* a store nobody made yet holds no keys */
    if (rc == NQEIO && !find) return NCOK;
    ncmsg("keys", "cannot read the key store %s (%s)", dir, nqerr(rc));
    return NCUSE;
  }
  for (i = 0; i < n && i < MAXE; i++) line(&e[i]);
  if (n > MAXE)
    ncmsg("keys", "%lu more keys are not shown: give a name to list fewer",
          (unsigned long)(n - MAXE));
  free(e);
  return find && n == 0 ? NCBAD : NCOK;
}

static int add(const char *dir, const char *kp, const char *name,
               const char *email, const char *cardp) {
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  uint8_t *card = NULL, fp[32];
  size_t cn = 0;
  nqkse e;
  char hx[65];
  int rc, ret = NCUSE;
  if ((cardp != NULL) == (name != NULL) || (cardp != NULL && email != NULL)) {
    ncmsg("keys", "add takes the holder's name with -n <name> (and -e "
          "<email>), or their identity card with --card <file>");
    return NCUSE;
  }
  if (nckrd("keys", kp, 0, &k) != NCOK) return NCUSE;
  if (cardp != NULL && ncrdx(cardp, 0, NCRDSMALL, &card, &cn) != NQOK) {
    ncmsg("keys", "cannot read %s%s", cardp, ncwhy());
    goto done;
  }
  mkpath(dir);
  rc = nqksadd(dir, k.a.kem, k.a.alg, k.b, k.n, name, email,
               (const char *)card, cn, fp);
  if (rc != NQOK) {
    if (rc == NQEVRFY || rc == NQEDEC)
      ncmsg("keys", "%s is not an identity card of the key in %s (%s)",
            cardp, kp, nqerr(rc));
    else if (rc == NQEARG && cardp != NULL)
      ncmsg("keys", "an identity card is a signature key's; %s is a %s key",
            kp, k.a.name);
    else if (rc == NQEARG)
      ncmsg("keys", "the name is 1 to 255 bytes of text with no space at "
            "either end, the address name@domain.tld");
    else
      ncmsg("keys", "cannot write the key store %s (%s)", dir, nqerr(rc));
    goto done;
  }
  nchexe(fp, 32, hx);
  hx[64] = '\0';
  if (one(dir, hx, &e) == NCOK) line(&e);
  ret = NCOK;
done:
  nckfree(&k);
  if (card != NULL) ncfree(card, cn, 0);
  return ret;
}

static int certify(const char *dir, const char *kp, const ncpw *pwo,
                   const char *q, const char *out, int force) {
  nckey sk = {{0, 0, NULL}, 1, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  nqkse e;
  uint8_t *pw = NULL;
  size_t pn = 0, l, cn = 0;
  char *pp = NULL, *c = NULL;
  int64_t now;
  int rc, ret = NCUSE;
  if (one(dir, q, &e) != NCOK) return NCUSE;
  l = strlen(kp);
  pp = (char *)malloc(l + 5);
  if (pp == NULL) return nclib("keys", "memory", NQEMEM);
  memcpy(pp, kp, l);
  memcpy(pp + l, ".pub", 5);
  if (ncpwget("keys", pwo, &pw, &pn) != NCOK) goto done;
  rc = nckrdp("keys", kp, 1, pw, pn, &sk);
  ncfree(pw, NQPWLEN, 1);
  if (rc != NCOK || nckrd("keys", pp, 0, &pk) != NCOK) goto done;
  if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg) {
    ncmsg("keys", "certify takes a signature key pair; %s is a %s key", kp,
          sk.a.name);
    goto done;
  }
  now = ncnow();
  if (now < 0) {
    ncmsg("keys", "%s", NCSDEBAD);
    goto done;
  }
  cn = (size_t)64 << 10;
  c = (char *)malloc(cn);
  if (c == NULL) {
    nclib("keys", "memory", NQEMEM);
    goto done;
  }
  rc = nqkscert(dir, (nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n, e.fp, now, c,
                cn, &l);
  if (rc != NQOK) {
    if (rc == NQEARG)
      ncmsg("keys", "%s and %s are not one key pair", kp, pp);
    else if (rc == NQENOSUP)
      ncmsg("keys", "%s keys do not certify: use a post-quantum signature "
            "key", sk.a.name);
    else
      nclib("keys", "certifying", rc);
    goto done;
  }
  if (out != NULL && ncwr(out, (const uint8_t *)c, l, force, 0) != NQOK) {
    ncwfail("keys", out, force);
    goto done;
  }
  if (one(dir, q, &e) == NCOK) line(&e);
  ret = NCOK;
done:
  nckfree(&sk);
  nckfree(&pk);
  free(pp);
  free(c);
  return ret;
}

static int addcert(const char *dir, const char *path) {
  uint8_t *c = NULL;
  size_t n = 0;
  int rc;
  if (ncrdx(path, 0, NCRDSMALL, &c, &n) != NQOK) {
    ncmsg("keys", "cannot read %s%s", path, ncwhy());
    return NCUSE;
  }
  rc = nqkscput(dir, (const char *)c, n);
  ncfree(c, n, 0);
  if (rc == NQOK) return NCOK;
  if (rc == NQEIO)
    ncmsg("keys", "%s: the key it certifies and the key that made it must "
          "both be in the store first (`noqtis keys add`)", path);
  else if (rc == NQEVRFY)
    ncmsg("keys", "%s does not verify: its signature is not the issuer's, "
          "or it names the key under another name or address than the "
          "store has", path);
  else
    ncmsg("keys", "%s is not a certification (%s)", path, nqerr(rc));
  return rc == NQEVRFY ? NCBAD : NCUSE;
}

static int trust(const char *dir, const char *q, const char *lvl) {
  nqkse e;
  size_t i;
  int rc;
  for (i = 0; i < sizeof tname / sizeof tname[0]; i++) {
    if (strcmp(lvl, tname[i]) == 0) break;
  }
  if (i == sizeof tname / sizeof tname[0]) {
    ncmsg("keys", "a trust level is unknown, never, marginal, full or "
          "ultimate");
    return NCUSE;
  }
  if (one(dir, q, &e) != NCOK) return NCUSE;
  rc = nqkstrust(dir, e.fp, (int)i);
  if (rc != NQOK) return nclib("keys", "the key store", rc);
  if (one(dir, q, &e) == NCOK) line(&e);
  return NCOK;
}

static int export(const char *dir, const char *q, const char *out,
                  int force) {
  nqkse e;
  ncalg a;
  uint8_t *pk;
  size_t n = 0;
  FILE *f;
  int rc, ret = NCUSE;
  if (one(dir, q, &e) != NCOK) return NCUSE;
  pk = (uint8_t *)malloc(e.pklen);
  if (pk == NULL) return nclib("keys", "memory", NQEMEM);
  rc = nqksget(dir, e.fp, NULL, NULL, pk, e.pklen, &n);
  if (rc != NQOK || ncfind(algof(&e), &a) != NQOK) {
    nclib("keys", "the key store", rc != NQOK ? rc : NQENOSUP);
    goto done;
  }
  if (out == NULL || strcmp(out, "-") == 0) {
    ret = nckwr(stdout, &a, 0, pk, n) == NQOK ? NCOK : NCUSE;
    goto done;
  }
  f = ncopen(out, force, 0);
  if (f == NULL) {
    ncwfail("keys", out, force);
    goto done;
  }
  rc = nckwr(f, &a, 0, pk, n);
  if (ncclose(f, out, rc != NQOK) != NQOK || rc != NQOK) {
    ncmsg("keys", "cannot write %s%s", out, ncwhy());
    goto done;
  }
  ret = NCOK;
done:
  free(pk);
  return ret;
}

/* the bundle of the one key that answers q, to out or stdout */
static int bundle(const char *dir, const char *q, const char *out,
                  int force) {
  nqkse e;
  char *b;
  size_t n = 0, cap = (size_t)1 << 20;
  int rc, ret = NCUSE;
  if (onecard(dir, q, &e) != NCOK) return NCUSE;
  b = (char *)malloc(cap);
  if (b == NULL) return nclib("keys", "memory", NQEMEM);
  rc = nqksexp(dir, e.fp, b, cap, &n);
  if (rc != NQOK) {
    if (rc == NQEARG)
      ncmsg("keys", "a bundle starts with an identity card: add the key "
            "with its card first (`noqtis idcard`, then `noqtis keys add "
            "--card`)");
    else
      nclib("keys", "the key store", rc);
    goto done;
  }
  if (out == NULL || strcmp(out, "-") == 0) {
    ret = fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  } else if (ncwr(out, (const uint8_t *)b, n, force, 0) != NQOK) {
    ncwfail("keys", out, force);
  } else {
    ret = NCOK;
  }
done:
  free(b);
  return ret;
}

/* puts a bundle (n bytes, from what) into the store; email is the
 * address it was looked up for, or NULL */
static int import(const char *dir, const uint8_t *b, size_t n,
                  const char *what, const char *email) {
  uint8_t fp[32];
  char hx[65];
  size_t nk = 0;
  int rc;
  mkpath(dir);
  rc = nqksimp(dir, (const char *)b, n, email, fp, &nk);
  if (rc != NQOK) {
    if (rc == NQEVRFY && email != NULL)
      ncmsg("keys", "%s does not verify as the keys of %s: the card is "
            "for another address, or a signature in it is not the card "
            "key's%s", what, email,
            nk > 0 ? "; the keys before that were put in" : "");
    else if (rc == NQEVRFY)
      ncmsg("keys", "%s does not verify: a signature in it is not the "
            "card key's%s", what,
            nk > 0 ? "; the keys before that were put in" : "");
    else if (rc == NQEDEC || rc == NQELIM)
      ncmsg("keys", "%s is not a key bundle (%s)", what, nqerr(rc));
    else
      ncmsg("keys", "cannot write the key store %s (%s)", dir, nqerr(rc));
    return rc == NQEVRFY ? NCBAD : NCUSE;
  }
  nchexe(fp, 32, hx);
  hx[64] = '\0';
  /* the card key's line, and how many keys came with it */
  list(dir, hx, 0);
  ncmsg("keys", "%lu key%s put in; none of them is valid until you "
        "certify it (compare the fingerprint with its holder first)",
        (unsigned long)nk, nk == 1 ? "" : "s");
  return NCOK;
}

static int importf(const char *dir, const char *path) {
  uint8_t *b = NULL;
  size_t n = 0;
  int ret;
  if (ncrdx(path, 0, (size_t)1 << 20, &b, &n) != NQOK) {
    ncmsg("keys", "cannot read %s%s", path, ncwhy());
    return NCUSE;
  }
  ret = import(dir, b, n, path, NULL);
  ncfree(b, n, 0);
  return ret;
}

/* looks an address up at its domain (nqksurl) and puts in what is there */
static int fetch(const char *dir, const char *email, int show) {
  char url[512], err[256];
  uint8_t *b = NULL;
  size_t n = 0;
  int ret;
  if (nqksurl(email, url, sizeof url) != NQOK) {
    ncmsg("keys", "%s is not an e-mail address a key can be looked up "
          "for (name@domain.tld)", email);
    return NCUSE;
  }
  if (show) {
    printf("%s\n", url);
    return NCOK;
  }
  if (ncget(url, (size_t)1 << 20, &b, &n, err, sizeof err) != NCOK) {
    ncmsg("keys", "no keys for %s: %s (looked at %s)", email, err, url);
    return NCUSE;
  }
  ret = import(dir, b, n, url, email);
  free(b);
  return ret;
}

int nckeys(int argc, char **argv) {
  const char *store = NULL, *name = NULL, *email = NULL, *card = NULL;
  const char *kp = NULL, *out = NULL, *sub;
  int force = 0, help = 0, np, url = 0;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'\0', "store", 1, &store, NULL},
    {'\0', "url", 0, NULL, &url},
    {'n', "name", 1, &name, NULL},
    {'e', "email", 1, &email, NULL},
    {'\0', "card", 1, &card, NULL},
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  char dir[1024];
  nqkse e;

  if (ncargs("keys", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "keys");
    return NCOK;
  }
  if (np < 1 || ncstore(store, dir, sizeof dir) != NCOK) {
    if (np >= 1)
      ncmsg("keys", "no key store: give --store <dir>, or set NOQTIS_KEYS "
            "or HOME");
    else
      ncuse(stderr, "keys");
    return NCUSE;
  }
  sub = argv[0];
  if (strcmp(sub, "path") == 0 && np == 1) {
    printf("%s\n", dir);
    return NCOK;
  }
  if (strcmp(sub, "list") == 0 && np <= 2)
    return list(dir, np == 2 ? argv[1] : NULL, 0);
  if (strcmp(sub, "find") == 0 && np == 2) return list(dir, argv[1], 1);
  if (strcmp(sub, "add") == 0 && np == 2)
    return add(dir, argv[1], name, email, card);
  if (strcmp(sub, "certify") == 0 && np == 2 && kp != NULL)
    return certify(dir, kp, &pwo, argv[1], out, force);
  if (strcmp(sub, "addcert") == 0 && np == 2) return addcert(dir, argv[1]);
  if (strcmp(sub, "trust") == 0 && np == 3)
    return trust(dir, argv[1], argv[2]);
  if (strcmp(sub, "export") == 0 && np == 2)
    return export(dir, argv[1], out, force);
  if (strcmp(sub, "bundle") == 0 && np == 2)
    return bundle(dir, argv[1], out, force);
  if (strcmp(sub, "import") == 0 && np == 2) return importf(dir, argv[1]);
  if (strcmp(sub, "fetch") == 0 && np == 2) return fetch(dir, argv[1], url);
  if (strcmp(sub, "rm") == 0 && np == 2) {
    int rc;
    if (one(dir, argv[1], &e) != NCOK) return NCUSE;
    rc = nqksdel(dir, e.fp);
    if (rc != NQOK) return nclib("keys", "the key store", rc);
    return NCOK;
  }
  ncuse(stderr, "keys");
  return NCUSE;
}
