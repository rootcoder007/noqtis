/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis rotate, revoke and expire: key statements (noqtis-keys-1) that
 * noqtis check --keys follows from a trusted key. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* YYYY-MM-DDTHH:MM:SSZ, 1970 or later, to seconds; NCUSE otherwise */
static int when(const char *s, int64_t *t) {
  static const int dim[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int64_t y, m, d, hh, mm, ss, era, yoe, doy, doe;
  int i;
  if (strlen(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
      s[13] != ':' || s[16] != ':' || s[19] != 'Z') {
    return NCUSE;
  }
  for (i = 0; i < 19; i++) {
    if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 &&
        (s[i] < '0' || s[i] > '9')) {
      return NCUSE;
    }
  }
#define D2(k) ((int64_t)(s[k] - '0') * 10 + (s[(k) + 1] - '0'))
  y = D2(0) * 100 + D2(2);
  m = D2(5);
  d = D2(8);
  hh = D2(11);
  mm = D2(14);
  ss = D2(17);
#undef D2
  if (y < 1970 || m < 1 || m > 12 || d < 1 || d > dim[m - 1] || hh > 23 ||
      mm > 59 || ss > 59 ||
      (m == 2 && d == 29 && !((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)))
    return NCUSE;
  y -= m <= 2;
  era = y / 400;
  yoe = y - era * 400;
  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  *t = (era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss;
  return NCOK;
}

/* a key pair: kp and pp, or kp.pub; NCOK or NCUSE (said why) */
static int pair(const char *cmd, const char *kp, const char *pp,
                const ncpw *pwo, const char *opt, nckey *sk, nckey *pk) {
  char *dp = NULL;
  int rc = NCUSE;
  if (pp == NULL) {
    size_t l = strlen(kp);
    dp = (char *)malloc(l + 5);
    if (dp == NULL) return nclib(cmd, "memory", NQEMEM);
    memcpy(dp, kp, l);
    memcpy(dp + l, ".pub", 5);
    pp = dp;
  }
  if (nckrd(cmd, pp, pk) == NCOK) {
    if (ncskrd(cmd, kp, pwo, opt, sk) != NCOK) {
      nckfree(pk);
    } else if (sk->a.kem || pk->a.kem || sk->a.alg != pk->a.alg) {
      ncmsg(cmd, "%s and %s are not a signature key pair", kp, pp);
      nckfree(sk);
      nckfree(pk);
    } else {
      rc = NCOK;
    }
  }
  free(dp);
  return rc;
}

/* the statement of the kind, to b (cap bytes) */
static int one(int kind, const nckey *sk, const nckey *pk, const nckey *nsk,
               const nckey *npk, int64_t t, const char *rs, char *b,
               size_t cap, size_t *n) {
  int rot = kind == 1;
  if (kind == 2)
    return nqkexp((nqsalg)sk->a.alg, sk->b, sk->n, pk->b, pk->n, t, rs, b,
                  cap, n);
  return nqkstmt((nqsalg)sk->a.alg, sk->b, sk->n, pk->b, pk->n,
                 rot ? (nqsalg)nsk->a.alg : (nqsalg)0, rot ? nsk->b : NULL,
                 rot ? nsk->n : 0, rot ? npk->b : NULL, rot ? npk->n : 0, t,
                 rs, b, cap, n);
}

/* kind: 0 revoke, 1 rotate, 2 expire */
static int stmt(const char *cmd, int argc, char **argv, int kind) {
  const char *kp = NULL, *pp = NULL, *np = NULL, *npp = NULL, *at = NULL,
             *rs = NULL, *out = NULL;
  int help = 0, force = 0, npos, rc, ret = NCUSE, rot = kind == 1;
  ncpw pwo = {NULL, NULL}, npwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'p', "pub", 1, &pp, NULL},
    {'n', "new", 1, &np, NULL},
    {'\0', "new-pub", 1, &npp, NULL},
    {'\0', "at", 1, &at, NULL},
    {'\0', "reason", 1, &rs, NULL},
    {'o', "out", 1, &out, NULL},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'\0', "new-pass-fd", 1, &npwo.fd, NULL},
    {'\0', "new-pass-env", 1, &npwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  nckey nsk = {{0, 0, NULL}, 0, NULL, 0}, npk = {{0, 0, NULL}, 0, NULL, 0};
  int64_t t = (int64_t)time(NULL);
  size_t n = 0;
  char *b = NULL;
  /* one table: -n, --new-pub and --new-pass-* are refused below for a
   * revocation */
  if (ncargs(cmd, argc, argv, o, sizeof o / sizeof o[0], &npos, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, cmd);
    return NCOK;
  }
  if (kp == NULL || npos != 0 || (rot && np == NULL) ||
      (!rot && (np != NULL || npp != NULL || npwo.fd != NULL ||
                npwo.env != NULL)) ||
      (kind == 2 && at == NULL)) {
    ncuse(stderr, cmd);
    return NCUSE;
  }
  if (at != NULL && when(at, &t) != NCOK) {
    ncmsg(cmd, "--at %s: give a UTC time as YYYY-MM-DDTHH:MM:SSZ, 1970 or "
          "later", at);
    return NCUSE;
  }
  if (rs != NULL && strlen(rs) > 255) {
    ncmsg(cmd, "--reason: at most 255 bytes");
    return NCUSE;
  }
  if (pair(cmd, kp, pp, &pwo, "pass", &sk, &pk) != NCOK) return NCUSE;
  if (rot && pair(cmd, np, npp, &npwo, "new-pass", &nsk, &npk) != NCOK)
    goto done;
  rc = one(kind, &sk, &pk, &nsk, &npk, t, rs, NULL, 0, &n);
  if (rc == NQEBUF) {
    b = (char *)malloc(n);
    if (b == NULL) {
      nclib(cmd, "memory", NQEMEM);
      goto done;
    }
    rc = one(kind, &sk, &pk, &nsk, &npk, t, rs, b, n, &n);
  }
  if (rc == NQENOSUP) {
    ncmsg(cmd, "key statements are for post-quantum seal keys (ML-DSA, "
          "SLH-DSA or a hybrid), not Ed25519 alone");
  } else if (rc == NQEARG) {
    ncmsg(cmd, "%s: the keys do not match, the new key is the old one, or "
          "the reason is not plain text", rot ? np : kp);
  } else if (rc != NQOK) {
    nclib(cmd, kp, rc);
  } else if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    ret = fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  } else if (ncwr(out, (const uint8_t *)b, n, force, 0) != NCOK) {
    ret = ncwfail(cmd, out, force);
  } else {
    ret = NCOK;
  }
done:
  free(b);
  nckfree(&sk);
  nckfree(&pk);
  nckfree(&nsk);
  nckfree(&npk);
  return ret;
}

int ncrot(int argc, char **argv) {
  return stmt("rotate", argc, argv, 1);
}

int ncrev(int argc, char **argv) {
  return stmt("revoke", argc, argv, 0);
}

int ncexpire(int argc, char **argv) {
  return stmt("expire", argc, argv, 2);
}
