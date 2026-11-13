/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis report: a capsule's check and its data record's, from one run,
 * as a report in Markdown or plain text (nqdrpt), with a JSON summary
 * and GitHub workflow annotations for CI. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* s as the value of a workflow command: '%', CR and LF as GitHub
 * decodes them; in a property (prop) ':' and ',' too */
static void ghput(const char *s, int prop) {
  for (; *s; s++) {
    if (*s == '%')
      fputs("%25", stdout);
    else if (*s == '\r')
      fputs("%0D", stdout);
    else if (*s == '\n')
      fputs("%0A", stdout);
    else if (prop && *s == ':')
      fputs("%3A", stdout);
    else if (prop && *s == ',')
      fputs("%2C", stdout);
    else
      putchar(*s);
  }
}

static void ghrow(const char *dir, const char *pre, const char *c,
                  const char *d) {
  fputs("::error title=noqtis ", stdout);
  ghput(pre, 1);
  ghput(c, 1);
  fputs("::", stdout);
  ghput(dir, 0);
  fputs(": ", stdout);
  ghput(d != NULL ? d : "", 0);
  putchar('\n');
}

static void jrow(int first, const char *pre, const char *c, int ok,
                 const char *d) {
  char *q;
  size_t n = strlen(pre) + strlen(c) + 1;
  fputs(first ? "{\"check\":" : ",{\"check\":", stdout);
  if ((q = (char *)malloc(n)) != NULL) {
    memcpy(q, pre, strlen(pre));
    memcpy(q + strlen(pre), c, strlen(c) + 1);
    ncjstr(q);
    free(q);
  } else {
    ncjstr(c);
  }
  printf(",\"ok\":%s,\"detail\":", ok ? "true" : "false");
  ncjstr(d != NULL ? d : "");
  putchar('}');
}

int ncrpt(int argc, char **argv) {
  const char *pp = NULL, *ff = NULL, *of = NULL, *dir;
  int json = 0, gh = 0, help = 0, np, fmt = NQDMD, rc, sealed, hasrec;
  ncopt o[] = {{'p', "pub", 1, &pp, NULL},
               {'f', "format", 1, &ff, NULL},
               {'o', "out", 1, &of, NULL},
               {'j', "json", 0, NULL, &json},
               {'\0', "github", 0, NULL, &gh}};
  nckey pk = {{0, 0, NULL}, 0, NULL, 0};
  nqrep *cr = NULL;
  nqdrep *dr = NULL;
  nqcopt co;
  char p[4200], *buf = NULL;
  size_t n = 0, i, tot = 0, bad = 0, ver = 0, chg = 0, nc = 0, nd = 0;
  int ret = NCUSE, first = 1;
  if (ncargs("report", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "report");
    return NCOK;
  }
  if (np != 1) {
    ncuse(stderr, "report");
    return NCUSE;
  }
  dir = argv[0];
  if (ff != NULL) {
    if (strcmp(ff, "md") == 0 || strcmp(ff, "markdown") == 0)
      fmt = NQDMD;
    else if (strcmp(ff, "txt") == 0 || strcmp(ff, "text") == 0)
      fmt = NQDTXT;
    else {
      ncmsg("report", "--format: md or txt");
      return NCUSE;
    }
  }
  if (!ncisdir(dir)) {
    ncmsg("report", "%s: not a folder", dir);
    return NCUSE;
  }
  snprintf(p, sizeof p, "%s/noqtis.sig", dir);
  sealed = ncexist(p);
  snprintf(p, sizeof p, "%s/%s", dir, NQDFILE);
  hasrec = ncexist(p);
  if (!sealed && !hasrec) {
    ncmsg("report", "%s holds neither a seal (noqtis.sig) nor a data record "
          "(%s): seal it with `noqtis seal`", dir, NQDFILE);
    return NCUSE;
  }
  if (pp != NULL) {
    if (nckrd("report", pp, 0, &pk) != NCOK)
      return NCUSE;
    if (pk.a.kem) {
      ncmsg("report", "%s is a %s (KEM) key, not a signature key", pp,
            pk.a.name);
      nckfree(&pk);
      return NCUSE;
    }
  }
  memset(&co, 0, sizeof co);
  co.trust = pk.b;
  co.trustlen = pk.n;
  if (sealed) {
    rc = nqchkx(dir, &co, &cr);
    if (cr == NULL) {
      nckfree(&pk);
      return nclib("report", dir, rc);
    }
  }
  nckfree(&pk);
  if (hasrec) {
    rc = nqdchk(dir, &dr);
    if (dr == NULL) {
      ret = nclib("report", dir, rc);
      goto out;
    }
  }
  rc = nqdrpt(dir, cr, dr, fmt, NULL, 0, &n);
  if (rc == NQEBUF && (buf = (char *)malloc(n + 1)) != NULL)
    rc = nqdrpt(dir, cr, dr, fmt, buf, n + 1, &n);
  if (rc != NQOK) {
    ret = nclib("report", dir, rc);
    goto out;
  }
  /* the counts: every row; files that match; files changed, missing or
   * added since the seal */
  nc = cr != NULL ? nqrepn(cr) : 0;
  nd = dr != NULL ? nqdrepn(dr) : 0;
  tot = nc + nd + (cr == NULL);
  bad = cr == NULL;
  for (i = 0; i < nc; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(cr, i, &c, &ok, &d) != NQOK || c == NULL)
      continue;
    bad += !ok;
    if (strcmp(c, "file") == 0 && ok)
      ver++;
    else if (strcmp(c, "file") == 0)
      chg++;
    else if (strcmp(c, "extra") == 0 && !ok)
      chg++;
  }
  for (i = 0; i < nd; i++) {
    int ok = 0;
    nqdrepi(dr, i, NULL, &ok, NULL);
    bad += !ok;
  }
  if (of != NULL) {
    FILE *f = ncfopen(of, "wb");
    if (f == NULL || fwrite(buf, 1, n, f) != n || fclose(f) != 0) {
      ncmsg("report", "%s: cannot be written", of);
      goto out;
    }
  }
  if (gh) {
    if (cr == NULL)
      ghrow(dir, "", "seal", "not sealed: no noqtis.sig");
    for (i = 0; i < nc; i++) {
      const char *c = NULL, *d = NULL;
      int ok = 1;
      if (nqrepi(cr, i, &c, &ok, &d) == NQOK && c != NULL && !ok)
        ghrow(dir, "", c, d);
    }
    for (i = 0; i < nd; i++) {
      const char *c = NULL, *d = NULL;
      int ok = 1;
      if (nqdrepi(dr, i, &c, &ok, &d) == NQOK && !ok)
        ghrow(dir, "data.", c, d);
    }
  }
  if (json) {
    fputs("{\"capsule\":", stdout);
    ncjstr(dir);
    printf(",\"ok\":%s,\"status\":\"%s\",\"sealed\":%s,\"total\":%lu,"
           "\"failed\":%lu,\"verified\":%lu,\"changed\":%lu,\"checks\":[",
           bad ? "false" : "true", bad ? "failed" : "passed",
           cr != NULL ? "true" : "false", (unsigned long)tot,
           (unsigned long)bad, (unsigned long)ver, (unsigned long)chg);
    if (cr == NULL) {
      jrow(first, "", "seal", 0, "not sealed: no noqtis.sig");
      first = 0;
    }
    for (i = 0; i < nc; i++) {
      const char *c = NULL, *d = NULL;
      int ok = 0;
      if (nqrepi(cr, i, &c, &ok, &d) != NQOK || c == NULL)
        continue;
      jrow(first, "", c, ok, d);
      first = 0;
    }
    for (i = 0; i < nd; i++) {
      const char *c = NULL, *d = NULL;
      int ok = 0;
      if (nqdrepi(dr, i, &c, &ok, &d) != NQOK)
        continue;
      jrow(first, "data.", c, ok, d);
      first = 0;
    }
    fputs("]}\n", stdout);
  } else if (of == NULL) {
    fwrite(buf, 1, n, stdout);
  }
  if (pp == NULL && sealed && !json && !gh)
    ncmsg("report", "note: no -p given, so the key inside the seal was "
          "trusted; pass -p <key.pub> to check who sealed it");
  ret = bad ? NCBAD : NCOK;
out:
  free(buf);
  if (cr != NULL)
    nqrepfree(cr);
  nqdrepfree(dr);
  fflush(stdout);
  return ret;
}
