/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis idcard: make an identity card (noqtis-idcard-1) for a signing
 * key, or check one; and the card row of noqtis check --card. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* SOURCE_DATE_EPOCH when set, as noqtis seal reads it, else the clock;
 * -1 when it is not a plain decimal number */
static int64_t now(void) {
  const char *e = getenv("SOURCE_DATE_EPOCH");
  int64_t v = 0;
  size_t i;
  if (e != NULL && e[0] != 0) {
    for (i = 0; e[i] != 0; i++) {
      if (e[i] < '0' || e[i] > '9' || i >= 12) return -1;
      v = v * 10 + (e[i] - '0');
    }
    return v;
  }
  return (int64_t)time(NULL);
}

/* which field nqcard refused, said with its rule. nqcard checks the
 * fields before the algorithm, so each field alone with Ed25519 (never a
 * card key) gives NQEARG when the field is refused, NQENOSUP when not */
static int badfield(const char *const v[5]) {
  static const char *const opt[5] = {"--name", "--orcid", "--email",
                                     "--url", "--affil"};
  static const char *const rule[5] = {
    "1 to 255 bytes of text, no control character and no space at "
    "either end",
    "an ORCID iD such as 0000-0002-1825-0097 (or its https://orcid.org/ "
    "address) whose last character is its check digit",
    "an e-mail address local@domain.tld, at most 254 bytes, no space",
    "an https:// address with a host, at most 1024 bytes, no space",
    "1 to 255 bytes of text, no control character and no space at "
    "either end"};
  static const uint8_t z[64] = {0};
  size_t i, n = 0;
  for (i = 0; i < 5; i++) {
    const char *w[5] = {"x", NULL, NULL, NULL, NULL};
    if (v[i] == NULL) continue;
    w[i] = v[i];
    if (nqcard(NQED25519, z, 64, z, 32, w[0], w[1], w[2], w[3], w[4], 0,
               NULL, 0, &n) == NQEARG) {
      ncmsg("idcard", "%s %s: give %s", opt[i], v[i], rule[i]);
      return 1;
    }
  }
  return 0;
}

/* the hex SHA-256 of a public key, as noqtis inspect shows a seal's */
static void fphex(const uint8_t fp[32], char out[65]) {
  nchexe(fp, 32, out);
  out[64] = 0;
}

static int mkcard(const char *kp, const char *pp, const char *const v[5],
                  const char *out, int force) {
  nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  char *dp = NULL, *b = NULL;
  size_t n = 0;
  int64_t t = now();
  int rc, ret = NCUSE;
  if (t < 0) {
    ncmsg("idcard", "SOURCE_DATE_EPOCH is not a number of seconds");
    return NCUSE;
  }
  if (pp == NULL) {
    size_t l = strlen(kp);
    dp = (char *)malloc(l + 5);
    if (dp == NULL) return nclib("idcard", "memory", NQEMEM);
    memcpy(dp, kp, l);
    memcpy(dp + l, ".pub", 5);
    pp = dp;
  }
  if (out != NULL && strcmp(out, "-") != 0 && !force && ncexist(out)) {
    ret = ncwfail("idcard", out, force);
    goto done;
  }
  if (nckrd("idcard", pp, 0, &pk) != NCOK) goto done;
  if (nckrd("idcard", kp, 1, &sk) != NCOK) goto done;
  if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg) {
    ncmsg("idcard", "%s and %s are not a signature key pair", kp, pp);
    goto done;
  }
  rc = nqcard((nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n, v[0], v[1], v[2],
              v[3], v[4], t, NULL, 0, &n);
  if (rc == NQEBUF) {
    b = (char *)malloc(n);
    if (b == NULL) {
      nclib("idcard", "memory", NQEMEM);
      goto done;
    }
    rc = nqcard((nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n, v[0], v[1], v[2],
                v[3], v[4], t, b, n, &n);
  }
  if (rc == NQENOSUP) {
    ncmsg("idcard", "identity cards are for post-quantum signing keys "
          "(ML-DSA, SLH-DSA or a hybrid), not Ed25519 alone");
  } else if (rc == NQEARG) {
    if (!badfield(v))
      ncmsg("idcard", "%s and %s are not one key pair", kp, pp);
  } else if (rc != NQOK) {
    nclib("idcard", kp, rc);
  } else if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    ret = fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  } else if (ncwr(out, (const uint8_t *)b, n, force, 0) != NCOK) {
    ret = ncwfail("idcard", out, force);
  } else {
    ret = NCOK;
  }
done:
  free(b);
  free(dp);
  nckfree(&sk);
  nckfree(&pk);
  return ret;
}

int ncidrd(const char *path, nqcardf *f, char *why, size_t cap) {
  uint8_t *b = NULL;
  size_t n = 0;
  int rc;
  why[0] = 0;
  if (ncrdx(path, 0, NQCARDMAX, &b, &n) != NCOK) {
    snprintf(why, cap, "cannot read the card (or it is over 256 KiB)");
    return NCUSE;
  }
  rc = nqcardvrfy((const char *)b, n, NULL, 0, f);
  ncfree(b, n, 0);
  if (rc == NQOK) return NCOK;
  if (rc == NQEVRFY)
    snprintf(why, cap, "its signature does not verify: the card was "
             "changed after it was made");
  else if (rc == NQEDEC)
    snprintf(why, cap, "not a noqtis-idcard-1 card (or one that was "
             "edited: it is not in the canonical form noqtis writes)");
  else
    snprintf(why, cap, "%s", nqerr(rc));
  return rc == NQEVRFY || rc == NQEDEC ? NCBAD : NCUSE;
}

void ncidwho(const nqcardf *f, char *out, size_t cap) {
  const char *x[4];
  size_t i, k = 0, o;
  x[0] = f->orcid;
  x[1] = f->email;
  x[2] = f->url;
  x[3] = f->affil;
  snprintf(out, cap, "%s", f->name);
  for (i = 0; i < 4; i++) {
    if (x[i][0] == 0) continue;
    o = strlen(out);
    snprintf(out + o, cap - o, "%s%s%s", k++ == 0 ? " (" : ", ",
             i == 0 ? "ORCID " : "", x[i]);
  }
  o = strlen(out);
  if (k > 0) snprintf(out + o, cap - o, ")");
}

static int vrcard(const char *path, const char *pp) {
  nqcardf f;
  nckey pk = {{0, 0, NULL}, 0, NULL, 0};
  char why[200], hx[65];
  int rc;
  if (pp != NULL) {
    if (nckrd("idcard", pp, 0, &pk) != NCOK) return NCUSE;
    if (pk.a.kem) {
      ncmsg("idcard", "%s is a %s (KEM) key, not a signature key", pp,
            pk.a.name);
      nckfree(&pk);
      return NCUSE;
    }
  }
  rc = ncidrd(path, &f, why, sizeof why);
  if (rc != NCOK) {
    nckfree(&pk);
    if (rc == NCBAD)
      ncmsg("idcard", "%s: FAILED: %s", path, why);
    else
      ncmsg("idcard", "%s: %s", path, why);
    return rc;
  }
  fphex(f.fp, hx);
  if (pp != NULL && ((nqsalg)pk.a.alg != f.alg || pk.n != f.pklen ||
                     memcmp(pk.b, f.pk, pk.n) != 0)) {
    ncmsg("idcard", "%s: FAILED: the card is for another key (%s, "
          "SHA-256 %.16s...) than %s", path, nqsname(f.alg), hx, pp);
    nckfree(&pk);
    return NCBAD;
  }
  nckfree(&pk);
  printf("name     %s\n", ncesc(f.name));
  if (f.orcid[0] != 0) printf("orcid    %s\n", f.orcid);
  if (f.email[0] != 0) printf("email    %s\n", ncesc(f.email));
  if (f.url[0] != 0) printf("url      %s\n", ncesc(f.url));
  if (f.affil[0] != 0) printf("affil    %s\n", ncesc(f.affil));
  printf("created  %s\n", f.utc);
  printf("alg      %s\n", nqsname(f.alg));
  printf("key      %s\n", hx);
  printf("%s: OK (%s)\n", ncesc(path), pp != NULL ? "the -p key"
         : "self-signed: compare the key with the one its holder gave");
  fflush(stdout);
  return NCOK;
}

int ncidc(int argc, char **argv) {
  const char *kp = NULL, *pp = NULL, *out = NULL, *vf = NULL, *v[5] = {0};
  int help = 0, force = 0, npos;
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'p', "pub", 1, &pp, NULL},
    {'\0', "name", 1, &v[0], NULL},
    {'\0', "orcid", 1, &v[1], NULL},
    {'\0', "email", 1, &v[2], NULL},
    {'\0', "url", 1, &v[3], NULL},
    {'\0', "affil", 1, &v[4], NULL},
    {'o', "out", 1, &out, NULL},
    {'f', "force", 0, NULL, &force},
    {'\0', "verify", 1, &vf, NULL}
  };
  if (ncargs("idcard", argc, argv, o, sizeof o / sizeof o[0], &npos,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "idcard");
    return NCOK;
  }
  if (npos != 0) {
    ncuse(stderr, "idcard");
    return NCUSE;
  }
  if (vf != NULL) {
    if (kp != NULL || out != NULL || force || v[0] != NULL ||
        v[1] != NULL || v[2] != NULL || v[3] != NULL || v[4] != NULL) {
      ncmsg("idcard", "--verify checks a card: it takes only -p");
      return NCUSE;
    }
    return vrcard(vf, pp);
  }
  if (kp == NULL || v[0] == NULL) {
    ncuse(stderr, "idcard");
    return NCUSE;
  }
  return mkcard(kp, pp, v, out, force);
}
