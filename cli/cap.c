/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis seal and check (capsules). */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

int ncseal(int argc, char **argv) {
  const char *kp = NULL, *pp = NULL, *mp = NULL, *tsa = NULL;
  int help = 0, np, rc, ret = NCUSE;
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'p', "pub", 1, &pp, NULL},
    {'m', "meta", 1, &mp, NULL},
    {'\0', "tsa", 1, &tsa, NULL}
  };
  nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  uint8_t *meta = NULL;
  size_t mn = 0;
  char *dp = NULL;

  if (ncargs("seal", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "seal");
    return NCOK;
  }
  if (kp == NULL || np != 1) {
    ncuse(stderr, "seal");
    return NCUSE;
  }
  if (pp == NULL) {
    size_t l = strlen(kp);
    dp = (char *)malloc(l + 5);
    if (dp == NULL)
      return nclib("seal", "memory", NQEMEM);
    memcpy(dp, kp, l);
    memcpy(dp + l, ".pub", 5);
    pp = dp;
  }
  if (mp != NULL) {
    uint8_t *m;
    if (ncrd(mp, 0, &meta, &mn) != NQOK) {
      ncmsg("seal", "cannot read %s", mp);
      free(dp);
      return NCUSE;
    }
    m = (uint8_t *)realloc(meta, mn + 1);
    if (m == NULL) {
      free(meta);
      free(dp);
      return nclib("seal", "memory", NQEMEM);
    }
    meta = m;
    meta[mn] = 0;
    if (memchr(meta, 0, mn) != NULL) {
      ncmsg("seal", "%s holds a NUL byte; give a JSON object", mp);
      goto out;
    }
  }
  if (nckrd("seal", pp, 0, &pk) != NCOK)
    goto out;
  if (nckrd("seal", kp, 1, &sk) != NCOK) {
    nckfree(&pk);
    goto out;
  }
  if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg) {
    if (sk.a.kem)
      ncmsg("seal", "%s is a %s (KEM) key; seals need a signature key", kp,
            sk.a.name);
    else
      ncmsg("seal", "%s (%s) and %s (%s) are not a pair", kp, sk.a.name, pp,
            pk.a.name);
    goto done;
  }
  rc = nqseal(argv[0], (nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n,
              (const char *)meta, tsa);
  if (rc != NQOK) {
    nclib("seal", argv[0], rc);
    goto done;
  }
  printf("sealed %s with %s\n", argv[0], sk.a.name);
  ret = NCOK;
done:
  nckfree(&sk);
  nckfree(&pk);
out:
  free(meta);
  free(dp);
  return ret;
}

static void jstr(const char *s) {
  putchar('"');
  for (; s != NULL && *s != '\0'; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\')
      printf("\\%c", c);
    else if (c == '\n')
      fputs("\\n", stdout);
    else if (c == '\t')
      fputs("\\t", stdout);
    else if (c < 0x20)
      printf("\\u%04x", c);
    else
      putchar(c);
  }
  putchar('"');
}

int ncchk(int argc, char **argv) {
  const char *pp = NULL;
  int json = 0, help = 0, np, rc, ret, all = 1;
  ncopt o[] = {
    {'p', "pub", 1, &pp, NULL},
    {'j', "json", 0, NULL, &json}
  };
  nckey pk = {{0, 0, NULL}, 0, NULL, 0};
  nqrep *r = NULL;
  size_t n = 0, i, w = 5, nf = 0;

  if (ncargs("check", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "check");
    return NCOK;
  }
  if (np != 1) {
    ncuse(stderr, "check");
    return NCUSE;
  }
  if (!ncexist(argv[0])) {
    ncmsg("check", "%s: no such folder", argv[0]);
    return NCUSE;
  }
  pk.b = NULL;
  pk.n = 0;
  pk.sec = 0;
  if (pp != NULL) {
    if (nckrd("check", pp, 0, &pk) != NCOK)
      return NCUSE;
    if (pk.a.kem) {
      ncmsg("check", "%s is a %s (KEM) key, not a signature key", pp,
            pk.a.name);
      nckfree(&pk);
      return NCUSE;
    }
  }
  rc = nqchk(argv[0], pk.b, pk.n, &r);
  nckfree(&pk);
  if (r != NULL)
    n = nqrepn(r);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || c == NULL) {
      all = 0;
      continue;
    }
    if (!ok) {
      all = 0;
      nf++;
    }
    if (strlen(c) > w)
      w = strlen(c);
  }
  if (rc == NQOK && all && n > 0)
    ret = NCOK;
  else if (rc == NQOK || rc == NQEVRFY || rc == NQEDEC)
    ret = NCBAD;
  else
    ret = NCUSE;
  if (json) {
    fputs("{\"capsule\":", stdout);
    jstr(argv[0]);
    printf(",\"ok\":%s,\"result\":", ret == NCOK ? "true" : "false");
    jstr(nqerr(rc));
    fputs(",\"checks\":[", stdout);
  } else if (n > 0) {
    printf("%-4s  %-*s  %s\n", "", (int)w, "check", "detail");
  }
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || c == NULL)
      continue;
    if (json) {
      fputs(i > 0 ? ",{\"check\":" : "{\"check\":", stdout);
      jstr(c);
      printf(",\"ok\":%s,\"detail\":", ok ? "true" : "false");
      jstr(d != NULL ? d : "");
      putchar('}');
    } else {
      printf("%-4s  %-*s  %s\n", ok ? "ok" : "FAIL", (int)w, c,
             d != NULL ? d : "");
    }
  }
  if (json) {
    fputs("]}\n", stdout);
  } else if (ret == NCOK) {
    printf("%s: OK (%lu checks passed)\n", argv[0], (unsigned long)n);
  } else if (n > 0 && nf > 0) {
    printf("%s: FAILED (%lu of %lu checks failed)\n", argv[0],
           (unsigned long)nf, (unsigned long)n);
  } else {
    printf("%s: FAILED (%s)\n", argv[0], nqerr(rc));
  }
  if (pp == NULL && ret == NCOK && !json)
    ncmsg("check", "note: no -p given, so the key inside the seal was "
          "trusted; pass -p <key.pub> to check who sealed it");
  if (ret == NCUSE && !json)
    ncmsg("check", "%s: %s", argv[0], nqerr(rc));
  if (r != NULL)
    nqrepfree(r);
  fflush(stdout);
  return ret;
}
