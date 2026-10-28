/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis enc and dec (key encapsulation). The shared secret goes to an
 * owner-only file, or to stdout in hex only when --stdout asks for it. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* Writes the shared secret to path, or as hex to stdout. */
static int ssout(const char *cmd, const char *path, int force,
                 const uint8_t *ss, size_t n) {
  if (path == NULL) {
    char *h = (char *)malloc(2 * n + 1);
    int ok;
    if (h == NULL)
      return nclib(cmd, "memory", NQEMEM);
    nchexe(ss, n, h);
    h[2 * n] = '\n';
    ok = fwrite(h, 1, 2 * n + 1, stdout) == 2 * n + 1 && fflush(stdout) == 0;
    ncfree(h, 2 * n + 1, 1);
    if (!ok) {
      ncmsg(cmd, "cannot write the shared secret to stdout");
      return NCUSE;
    }
    return NCOK;
  }
  if (ncwr(path, ss, n, force, 1) != NQOK)
    return ncwfail(cmd, path, force);
  return NCOK;
}

int ncenc(int argc, char **argv) {
  const char *kp = NULL, *cp = NULL;
  int force = 0, sout = 0, help = 0, np, rc, ret = NCUSE;
  ncopt o[] = {
    {'p', "pub", 1, &kp, NULL},
    {'o', "out", 1, &cp, NULL},
    {'\0', "stdout", 0, NULL, &sout},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqksz z = {0, 0, 0, 0};
  uint8_t *ct = NULL, *ss = NULL;
  const char *sp;

  if (ncargs("enc", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "enc");
    return NCOK;
  }
  if (kp == NULL || cp == NULL || np != (sout ? 0 : 1)) {
    ncuse(stderr, "enc");
    return NCUSE;
  }
  sp = sout ? NULL : argv[0];
  if (nckrd("enc", kp, 0, &k) != NCOK)
    return NCUSE;
  if (!k.a.kem) {
    ncmsg("enc", "%s is a %s (signature) key, not a KEM key", kp,
          k.a.name);
    goto done;
  }
  if (nqksize((nqkalg)k.a.alg, &z) != NQOK) {
    nclib("enc", k.a.name, NQENOSUP);
    goto done;
  }
  if (!force && (ncexist(cp) || (sp != NULL && ncexist(sp)))) {
    ncwfail("enc", ncexist(cp) ? cp : sp, force);
    goto done;
  }
  ct = (uint8_t *)malloc(z.ct);
  ss = (uint8_t *)malloc(z.ss);
  if (ct == NULL || ss == NULL) {
    nclib("enc", "memory", NQEMEM);
    goto done;
  }
  rc = nqenc((nqkalg)k.a.alg, k.b, k.n, ct, z.ct, ss, z.ss);
  if (rc != NQOK) {
    nclib("enc", "encapsulation", rc);
    goto done;
  }
  if (ncwr(cp, ct, z.ct, force, 0) != NQOK) {
    ncwfail("enc", cp, force);
    goto done;
  }
  ret = ssout("enc", sp, force, ss, z.ss);
done:
  nckfree(&k);
  free(ct);
  ncfree(ss, z.ss, 1);
  return ret;
}

int ncdec(int argc, char **argv) {
  const char *kp = NULL, *sp = NULL;
  int force = 0, sout = 0, help = 0, np, rc, ret = NCUSE;
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &sp, NULL},
    {'\0', "stdout", 0, NULL, &sout},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqksz z = {0, 0, 0, 0};
  uint8_t *ct = NULL, *ss = NULL;
  size_t cn = 0;

  if (ncargs("dec", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "dec");
    return NCOK;
  }
  if (kp == NULL || np != 1 || (sp == NULL) == (sout == 0)) {
    if (kp != NULL && np == 1)
      ncmsg("dec", "give exactly one of -o <ss> and --stdout");
    ncuse(stderr, "dec");
    return NCUSE;
  }
  if (sp != NULL && !force && ncexist(sp))
    return ncwfail("dec", sp, force);
  if (nckrd("dec", kp, 1, &k) != NCOK)
    return NCUSE;
  if (!k.a.kem) {
    ncmsg("dec", "%s is a %s (signature) key, not a KEM key", kp,
          k.a.name);
    goto done;
  }
  if (nqksize((nqkalg)k.a.alg, &z) != NQOK) {
    nclib("dec", k.a.name, NQENOSUP);
    goto done;
  }
  if (ncrd(argv[0], 0, &ct, &cn) != NQOK) {
    ncmsg("dec", "cannot read %s", argv[0]);
    goto done;
  }
  if (cn != z.ct) {
    ncmsg("dec", "%s is %lu bytes; %s ciphertexts are %lu", argv[0],
          (unsigned long)cn, k.a.name, (unsigned long)z.ct);
    goto done;
  }
  ss = (uint8_t *)malloc(z.ss);
  if (ss == NULL) {
    nclib("dec", "memory", NQEMEM);
    goto done;
  }
  rc = nqdec((nqkalg)k.a.alg, k.b, k.n, ct, cn, ss, z.ss);
  if (rc != NQOK) {
    nclib("dec", "decapsulation", rc);
    goto done;
  }
  ret = ssout("dec", sp, force, ss, z.ss);
done:
  nckfree(&k);
  free(ct);
  if (ss != NULL)
    ncfree(ss, z.ss, 1);
  return ret;
}
