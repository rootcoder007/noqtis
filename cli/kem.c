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
  FILE *f;
  int sl[2] = {-1, -1}, nk;

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
  if (nckrd("enc", kp, &k) != NCOK)
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
  /* The ciphertext is kept under its temporary name until the shared
   * secret is out, then named last (cli/io.c): a failed enc never
   * leaves a ciphertext whose secret was lost. */
  if ((f = ncopen(cp, force, 0)) == NULL ||
      (sl[1] = nckeep(f, fwrite(ct, 1, z.ct, f) != z.ct)) < 0) {
    ncwfail("enc", cp, force);
    goto done;
  }
  if (sp == NULL) {
    if ((ret = ssout("enc", NULL, force, ss, z.ss)) != NCOK)
      ncdrop(sl[1]);
    else if (ncput(&sl[1], 1) != 1)
      ret = ncwfail("enc", cp, force);
    goto done;
  }
  if ((f = ncopen(sp, force, 1)) == NULL ||
      (sl[0] = nckeep(f, fwrite(ss, 1, z.ss, f) != z.ss)) < 0) {
    ncdrop(sl[1]);
    ncwfail("enc", sp, force);
    goto done;
  }
  nk = ncput(sl, 2);
  if (nk == 0)
    ncwfail("enc", sp, force);
  else if (nk == 1)
    ncmsg("enc", "cannot write %s, after %s was written: encapsulate "
          "again", cp, sp);
  else
    ret = NCOK;
done:
  nckfree(&k);
  free(ct);
  ncfree(ss, z.ss, 1);
  return ret;
}

int ncdec(int argc, char **argv) {
  const char *kp = NULL, *sp = NULL;
  int force = 0, sout = 0, help = 0, np, rc, ret = NCUSE;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &sp, NULL},
    {'\0', "stdout", 0, NULL, &sout},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
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
  if (pwo.fd != NULL && strcmp(pwo.fd, "0") == 0 &&
      strcmp(argv[0], "-") == 0) {
    ncmsg("dec", "--pass-fd 0 and a ciphertext on stdin cannot share it");
    return NCUSE;
  }
  if (ncskrd("dec", kp, &pwo, "pass", &k) != NCOK)
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
  if (ncrdx(argv[0], 0, NCRDSMALL, &ct, &cn) != NQOK) {
    ncmsg("dec", "cannot read %s%s", argv[0], ncwhy());
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
