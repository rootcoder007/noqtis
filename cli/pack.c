/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis pack: reproducibility bundles. A bundle is a capsule whose data
 * record holds the environment and its lock files: `pack init` starts
 * one from a template, `pack build` records the environment, seals and
 * writes the single file (noqtis-bundle-1), `pack check` checks it
 * before it is shipped, `pack unpack` opens one. Each step is a command
 * the tool already has; this file only puts them in order. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* the templates: the code folder, the lock file and how it is made */
static const struct {
  const char *name;
  const char *code;
  const char *lock;
  const char *how;
} tmpl[] = {
    {"plain", "code", "the lock file of your language",
     "the package manager's lock command"},
    {"r", "R", "renv.lock", "renv::snapshot()"},
    {"python", "src", "uv.lock (or requirements.txt)",
     "uv lock (or pip freeze > requirements.txt)"}};

#define NTMPL (sizeof tmpl / sizeof tmpl[0])

/* an argument for a command run from here: the commands take argv as
 * main gives it, and none writes its strings */
static char *arg(const char *s) {
  union {
    const char *c;
    char *m;
  } u;
  u.c = s;
  return u.m;
}

static int pinit(int argc, char **argv) {
  const char *tn = "plain";
  const char *sub[3];
  char p[4200], rd[2048];
  int np, help, rc, n;
  size_t t, i;
  nqdrec *r;
  ncopt o[] = {{'t', "template", 1, &tn, NULL}};
  if (ncargs("pack init", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "pack");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("pack init", "give one folder (see `noqtis help pack`)");
    return NCUSE;
  }
  for (t = 0; t < NTMPL && strcmp(tn, tmpl[t].name) != 0; t++)
    ;
  if (t == NTMPL) {
    ncmsg("pack init", "--template %s: give plain, r or python", tn);
    return NCUSE;
  }
  snprintf(p, sizeof p, "%s/%s", argv[0], NQDFILE);
  if (ncexist(p)) {
    ncmsg("pack init", "%s already has a data record: it is started", argv[0]);
    return NCUSE;
  }
  if (!ncisdir(argv[0]) && ncmkdir(argv[0]) != NCOK) {
    ncmsg("pack init", "cannot make the folder %s", argv[0]);
    return NCUSE;
  }
  sub[0] = "data";
  sub[1] = tmpl[t].code;
  sub[2] = "output";
  for (i = 0; i < 3; i++) {
    snprintf(p, sizeof p, "%s/%s", argv[0], sub[i]);
    if (!ncisdir(p) && ncmkdir(p) != NCOK) {
      ncmsg("pack init", "cannot make the folder %s", p);
      return NCUSE;
    }
  }
  n = snprintf(
      rd, sizeof rd,
      "# Reproducibility bundle\n\n"
      "Started with `noqtis pack init --template %s`.\n\n"
      "- `data/`: the input data. Record where each file came from:\n"
      "  `noqtis data add --url <url> . data/<file>`\n"
      "- `%s/`: the code that makes the results\n"
      "- `output/`: the results\n"
      "- %s: the package versions, from %s\n\n"
      "Build the bundle (environment, seal, one file) and check it before\n"
      "it is shipped:\n\n"
      "    noqtis pack build -k <key> -o ../bundle.nqb .\n"
      "    noqtis pack check -p <key>.pub ../bundle.nqb\n",
      tmpl[t].name, tmpl[t].code, tmpl[t].lock, tmpl[t].how);
  /* a README there is the project's own: kept */
  snprintf(p, sizeof p, "%s/README.md", argv[0]);
  if (n < 0 || (size_t)n >= sizeof rd ||
      (!ncexist(p) && ncwr(p, (const uint8_t *)rd, (size_t)n, 0, 0) != NCOK))
    return ncwfail("pack init", p, 0);
  if ((rc = nqdnew(&r)) != NQOK)
    return nclib("pack init", "a new record", rc);
  rc = ncdsave("pack init", argv[0], r);
  nqdrfree(r);
  if (rc == NCOK)
    printf("%s: started from the %s template\n", ncesc(argv[0]),
           tmpl[t].name);
  return rc;
}

/* The keys of a build, read as seal will read them: NCOK when they are a
 * signature key pair, else the reason said and NCUSE. */
static int pkeys(const char *kp, const char *pp) {
  nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  char dp[4200];
  int rc = NCUSE;
  if (pp == NULL) {
    if (snprintf(dp, sizeof dp, "%s.pub", kp) >= (int)sizeof dp) {
      ncmsg("pack build", "the key's path is too long");
      return NCUSE;
    }
    pp = dp;
  }
  if (nckrd("pack build", pp, 0, &pk) != NCOK)
    return NCUSE;
  if (nckrd("pack build", kp, 1, &sk) != NCOK) {
    nckfree(&pk);
    return NCUSE;
  }
  if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg)
    ncmsg("pack build", "%s (%s) and %s (%s) are not a signature key pair",
          kp, sk.a.name, pp, pk.a.name);
  else
    rc = NCOK;
  nckfree(&sk);
  nckfree(&pk);
  return rc;
}

/* A build that a step refused: the record and the seal are put back as
 * they were, and rc is returned. */
static int pundo(ncsnap was[3], const char *dir, int rc) {
  int k, bad = 0;
  for (k = 0; k < 3; k++)
    bad |= ncsnapput(&was[k]) != NCOK;
  if (bad)
    ncmsg("pack build", "%s could not be put back as it was: check it "
          "(`noqtis check`) and build again", dir);
  else
    ncmsg("pack build", "%s is left as it was", dir);
  return rc;
}

static int pbuild(int argc, char **argv) {
  const char *kp = NULL, *pp = NULL, *fv = NULL, *out = NULL,
             *lk[NCMAXV];
  char *av[2 * NCMAXV + 8];
  static const char *const keep[3] = {NQDFILE, "noqtis.json", "noqtis.sig"};
  ncsnap was[3];
  int np, help, nl = 0, force = 0, nof = 0, rc, k, a;
  ncopt o[] = {{'k', "key", 1, &kp, NULL},
               {'p', "pub", 1, &pp, NULL},
               {'\0', "format", 1, &fv, NULL},
               {'\0', "lock", NCMANY, lk, &nl},
               {'o', "out", 1, &out, NULL},
               {'f', "force", 0, NULL, &force},
               {'\0', "no-files", 0, NULL, &nof}};
  if (ncargs("pack build", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "pack");
    return NCOK;
  }
  if (kp == NULL || np != 1) {
    ncmsg("pack build", "give the key with -k and one folder (see `noqtis "
          "help pack`)");
    return NCUSE;
  }
  if (nof && out == NULL) {
    ncmsg("pack build", "--no-files shapes the bundle file: give it with -o");
    return NCUSE;
  }
  if (!ncisdir(argv[0])) {
    ncmsg("pack build", "%s is not a folder", argv[0]);
    return NCUSE;
  }
  /* what the later steps would refuse is refused here, before the
   * record is rewritten: a refused build leaves the folder as it was */
  if (fv != NULL && strcmp(fv, "1") != 0 && strcmp(fv, "2") != 0) {
    ncmsg("pack build", "--format %s: give 1 or 2", fv);
    return NCUSE;
  }
  if (out != NULL && !force && ncexist(out))
    return ncwfail("pack build", out, force);
  if ((rc = pkeys(kp, pp)) != NCOK)
    return rc;
  /* what no check ahead can foresee (a link among the files, a bundle
   * that cannot be written) is undone: the record and the seal are kept
   * as they were and put back when a step refuses */
  for (k = 0; k < 3; k++) {
    if (ncsnapget(&was[k], argv[0], keep[k]) != NCOK) {
      ncmsg("pack build", "%s/%s cannot be read", argv[0], keep[k]);
      while (k-- > 0)
        ncsnapfree(&was[k]);
      return NCUSE;
    }
  }
  /* noqtis env [--lock <file>]... <dir> */
  a = 0;
  av[a++] = arg("env");
  for (k = 0; k < nl; k++) {
    av[a++] = arg("--lock");
    av[a++] = arg(lk[k]);
  }
  av[a++] = argv[0];
  av[a] = NULL;
  if ((rc = ncenv(a, av)) != NCOK)
    return pundo(was, argv[0], rc);
  /* noqtis seal -k <key> [-p <key.pub>] [--format <n>] <dir> */
  a = 0;
  av[a++] = arg("seal");
  av[a++] = arg("-k");
  av[a++] = arg(kp);
  if (pp != NULL) {
    av[a++] = arg("-p");
    av[a++] = arg(pp);
  }
  if (fv != NULL) {
    av[a++] = arg("--format");
    av[a++] = arg(fv);
  }
  av[a++] = argv[0];
  av[a] = NULL;
  if ((rc = ncseal(a, av)) != NCOK)
    return pundo(was, argv[0], rc);
  if (out != NULL &&
      (rc = ncbwr("pack build", argv[0], !nof, out, force)) != NCOK)
    return pundo(was, argv[0], rc);
  for (k = 0; k < 3; k++)
    ncsnapfree(&was[k]);
  if (out != NULL)
    printf("%s: bundle written (%s)\n", ncesc(out),
           nof ? "the seal, the manifest and the data record"
               : "every file");
  return NCOK;
}

static int pcheck(int argc, char **argv) {
  const char *pp = NULL;
  char *av[5], bdir[1024];
  const char *dir;
  int np, help, rc, ret, a = 0, env = 0, e, bsl = -1;
  size_t i, locks = 0;
  nqdrec *r = NULL;
  nqdrep *rep = NULL;
  ncopt o[] = {{'p', "pub", 1, &pp, NULL}};
  if (ncargs("pack check", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "pack");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("pack check", "give one bundle file or folder");
    return NCUSE;
  }
  /* the capsule: noqtis check [-p <key.pub>] <dir|file> */
  av[a++] = arg("check");
  if (pp != NULL) {
    av[a++] = arg("-p");
    av[a++] = arg(pp);
  }
  av[a++] = argv[0];
  av[a] = NULL;
  ret = ncchk(a, av);
  if (ret == NCUSE)
    return ret;
  /* the data record, and what a bundle needs of it */
  dir = argv[0];
  if (!ncisdir(dir)) {
    if ((rc = ncbget("pack check", argv[0], bdir, sizeof bdir, &bsl)) !=
        NCOK)
      return rc;
    dir = bdir;
  }
  e = nqdchk(dir, &rep);
  if (rep != NULL) {
    rc = ncdrep("pack check", argv[0], rep, e, 0);
    for (i = 0; i < nqdrepn(rep); i++) {
      const char *c = NULL;
      nqdrepi(rep, i, &c, NULL, NULL);
      locks += c != NULL && strcmp(c, "lock") == 0;
    }
    nqdrepfree(rep);
  } else {
    rc = nclib("pack check", argv[0], e);
  }
  if (rc > ret)
    ret = rc;
  if (nqdload(dir, &r, NULL, 0) == NQOK)
    env = nqdlen(r, "env") == 1;
  nqdrfree(r);
  if (dir == bdir)
    ncbdone(bsl);
  printf("%-4s  pack  %s\n", env ? "ok" : "FAIL",
         env ? "the environment is recorded" : "no environment recorded");
  printf("%-4s  pack  %lu lock files recorded\n", locks ? "ok" : "FAIL",
         (unsigned long)locks);
  /* pack build records the environment whatever the folder holds, but a
   * lock file only when the project has made one: the advice differs */
  if (!env)
    ncmsg("pack check", "no environment is recorded: run `noqtis pack "
          "build` on the folder");
  else if (!locks)
    ncmsg("pack check", "no lock file is recorded: make the project's own "
          "(renv.lock from renv::snapshot() in R; uv.lock, or pip freeze > "
          "requirements.txt, in Python) at the top of the folder, or name "
          "it with `noqtis pack build --lock <file>`, then build again");
  if ((!env || !locks) && ret == NCOK)
    ret = NCBAD;
  printf("%s: %s\n", ncesc(argv[0]),
         ret == NCOK ? "ready to ship" : "not ready to ship");
  return ret;
}

static int punpack(int argc, char **argv) {
  char why[600], t[4200];
  int np, help, rc, sl;
  if (ncargs("pack unpack", argc, argv, NULL, 0, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "pack");
    return NCOK;
  }
  if (np != 2) {
    ncmsg("pack unpack", "give the bundle file and a new folder");
    return NCUSE;
  }
  if (ncexist(argv[1])) {
    ncmsg("pack unpack", "%s: it must not exist yet", argv[1]);
    return NCUSE;
  }
  /* unpacked under a temporary name beside the folder and named only
   * when whole (cli/io.c): a failed or stopped unpack leaves nothing */
  if ((sl = nctmpd(argv[1], t, sizeof t)) < 0) {
    ncmsg("pack unpack", "cannot write %s", argv[1]);
    return NCUSE;
  }
  rc = nqdunpack(argv[0], t, 0, why, sizeof why);
  if (rc != NQOK) {
    ncdrop(sl);
    ncmsg("pack unpack", "%s: %s", argv[0], why[0] ? why : nqerr(rc));
    return rc == NQEDEC || rc == NQELIM ? NCBAD : NCUSE;
  }
  if (ncput(&sl, 1) != 1) {
    ncmsg("pack unpack", "cannot write %s", argv[1]);
    return NCUSE;
  }
  printf("%s: unpacked into %s; check it with `noqtis check %s`\n",
         ncesc(argv[0]), ncesc(argv[1]), ncesc(argv[1]));
  return NCOK;
}

int ncpack(int argc, char **argv) {
  static const struct {
    const char *v;
    int (*f)(int, char **);
  } vs[] = {{"init", pinit},
            {"build", pbuild},
            {"check", pcheck},
            {"unpack", punpack}};
  size_t i;
  if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0) {
    ncuse(argc < 2 ? stderr : stdout, "pack");
    return argc < 2 ? NCUSE : NCOK;
  }
  for (i = 0; i < sizeof vs / sizeof vs[0]; i++)
    if (strcmp(argv[1], vs[i].v) == 0)
      return vs[i].f(argc - 1, argv + 1);
  ncmsg("pack", "unknown action %s (init, build, check, unpack)", argv[1]);
  return NCUSE;
}
