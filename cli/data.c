/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis data: make, show and check a capsule's data record
 * (noqtis.data.json, noqtis-data(5)) through nqd.h. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* a JSON string of s to stdout */
void ncjstr(const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  putchar('"');
  for (; *p; p++) {
    if (*p == '"' || *p == '\\')
      printf("\\%c", *p);
    else if (*p < 0x20)
      printf("\\u%04x", *p);
    else
      putchar(*p);
  }
  putchar('"');
}

/* s as a JSON string into a new buffer (free it) */
char *ncjq(const char *s) {
  size_t n = strlen(s), o = 0, i;
  char *b = (char *)malloc(6 * n + 3);
  if (b == NULL)
    return NULL;
  b[o++] = '"';
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') {
      b[o++] = '\\';
      b[o++] = (char)c;
    } else if (c < 0x20) {
      o += (size_t)sprintf(b + o, "\\u%04x", c);
    } else {
      b[o++] = (char)c;
    }
  }
  b[o++] = '"';
  b[o] = '\0';
  return b;
}

/* the record of dir: loaded, or a new one when there is none and mk */
int ncdload(const char *cmd, const char *dir, int mk, nqdrec **r) {
  char why[600];
  int rc = nqdload(dir, r, why, sizeof why);
  if (rc == NQEIO && mk)
    rc = nqdnew(r);
  if (rc == NQEIO) {
    ncmsg(cmd, "%s has no %s: start one with `noqtis data init %s`", dir,
          NQDFILE, dir);
    return NCUSE;
  }
  if (rc != NQOK) {
    ncmsg(cmd, "%s/%s: %s", dir, NQDFILE, why[0] ? why : nqerr(rc));
    return NCUSE;
  }
  return NCOK;
}

int ncdsave(const char *cmd, const char *dir, nqdrec *r) {
  char p[4200];
  int rc = nqdsave(r, dir);
  if (rc != NQOK)
    return nclib(cmd, "cannot write " NQDFILE, rc);
  snprintf(p, sizeof p, "%s/noqtis.sig", dir);
  if (ncexist(p))
    ncmsg(cmd, "note: %s is sealed, and its seal does not cover the "
          "changed %s: seal it again (`noqtis seal`)", dir, NQDFILE);
  return NCOK;
}

/* a time option: YYYY-MM-DDTHH:MM:SSZ, or "now" */
static int optime(const char *v, char out[21]) {
  if (strcmp(v, "now") == 0) {
    struct tm tm;
    const char *e = getenv("SOURCE_DATE_EPOCH");
    time_t t = e != NULL && *e ? (time_t)strtoll(e, NULL, 10) : time(NULL);
    if (ncgmtime(t, &tm) != NCOK)
      return NCUSE;
    strftime(out, 21, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return NCOK;
  }
  if (strlen(v) != 20)
    return NCUSE;
  memcpy(out, v, 21);
  return NCOK;
}

static int setstr(const char *cmd, nqdrec *r, const char *m, const char *k,
                  const char *field, const char *v) {
  char why[600];
  char *q = ncjq(v);
  int rc;
  if (q == NULL)
    return nclib(cmd, "memory", NQEMEM);
  rc = nqdset(r, m, k, field, q, strlen(q), why, sizeof why);
  free(q);
  if (rc != NQOK) {
    ncmsg(cmd, "%s: %s", field, why[0] ? why : nqerr(rc));
    return NCUSE;
  }
  return NCOK;
}

static int dinit(int argc, char **argv) {
  int np, help, force = 0, rc;
  char p[4200];
  nqdrec *r;
  ncopt o[] = {{'f', "force", 0, NULL, &force}};
  if (ncargs("data init", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("data init", "give one folder (see `noqtis help data`)");
    return NCUSE;
  }
  snprintf(p, sizeof p, "%s/%s", argv[0], NQDFILE);
  if (ncexist(p) && !force) {
    ncmsg("data init", "%s already exists: --force replaces it", p);
    return NCUSE;
  }
  if ((rc = nqdnew(&r)) != NQOK)
    return nclib("data init", "a new record", rc);
  rc = ncdsave("data init", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int dadd(int argc, char **argv) {
  const char *url = NULL, *title = NULL, *pub = NULL, *lic = NULL,
             *ret = NULL, *etag = NULL, *mod = NULL, *arc = NULL;
  const char *mir[NCMAXV];
  int np, help, syn = 0, nmir = 0, i, rc = NCOK, j;
  nqdrec *r;
  char why[600], t[21];
  ncopt o[] = {{'u', "url", 1, &url, NULL},
               {0, "title", 1, &title, NULL},
               {0, "publisher", 1, &pub, NULL},
               {0, "licence", 1, &lic, NULL},
               {0, "retrieved", 1, &ret, NULL},
               {0, "etag", 1, &etag, NULL},
               {0, "modified", 1, &mod, NULL},
               {0, "archived", 1, &arc, NULL},
               {0, "mirror", NCMANY, mir, &nmir},
               {0, "synthetic", 0, NULL, &syn}};
  if (ncargs("data add", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np < 2) {
    ncmsg("data add", "give the folder and at least one file in it");
    return NCUSE;
  }
  if (np > 2 && (url != NULL || etag != NULL || mod != NULL || arc != NULL ||
                 nmir > 0)) {
    ncmsg("data add", "--url, --etag, --modified, --archived and --mirror "
          "describe one file: add the files one at a time");
    return NCUSE;
  }
  if (ret != NULL && optime(ret, t) != NCOK) {
    ncmsg("data add", "--retrieved: YYYY-MM-DDTHH:MM:SSZ (UTC) or now");
    return NCUSE;
  }
  if ((rc = ncdload("data add", argv[0], 1, &r)) != NCOK)
    return rc;
  for (i = 1; i < np && rc == NCOK; i++) {
    const char *p = argv[i];
    int e = nqdsrc(r, argv[0], p, why, sizeof why);
    if (e != NQOK) {
      ncmsg("data add", "%s", why[0] ? why : nqerr(e));
      rc = NCUSE;
      break;
    }
    if (url != NULL)
      rc |= setstr("data add", r, "sources", p, "url", url);
    if (title != NULL)
      rc |= setstr("data add", r, "sources", p, "title", title);
    if (pub != NULL)
      rc |= setstr("data add", r, "sources", p, "publisher", pub);
    if (lic != NULL)
      rc |= setstr("data add", r, "sources", p, "licence", lic);
    if (ret != NULL)
      rc |= setstr("data add", r, "sources", p, "retrieved", t);
    if (etag != NULL)
      rc |= setstr("data add", r, "sources", p, "etag", etag);
    if (mod != NULL)
      rc |= setstr("data add", r, "sources", p, "modified", mod);
    if (arc != NULL) {
      char *q = ncjq(arc), *v;
      if (q == NULL)
        return nclib("data add", "memory", NQEMEM);
      v = (char *)malloc(strlen(q) + 16);
      if (v == NULL) {
        free(q);
        return nclib("data add", "memory", NQEMEM);
      }
      sprintf(v, "{\"url\":%s}", q);
      free(q);
      e = nqdset(r, "sources", p, "archived", v, strlen(v), why, sizeof why);
      free(v);
      if (e != NQOK) {
        ncmsg("data add", "--archived: %s", why[0] ? why : nqerr(e));
        rc = NCUSE;
      }
    }
    if (nmir > 0) {
      size_t n = 3;
      char *v, **q = (char **)calloc((size_t)nmir, sizeof *q);
      if (q == NULL)
        return nclib("data add", "memory", NQEMEM);
      for (j = 0; j < nmir; j++) {
        if ((q[j] = ncjq(mir[j])) == NULL)
          return nclib("data add", "memory", NQEMEM);
        n += strlen(q[j]) + 1;
      }
      v = (char *)malloc(n);
      if (v == NULL)
        return nclib("data add", "memory", NQEMEM);
      strcpy(v, "[");
      for (j = 0; j < nmir; j++) {
        if (j)
          strcat(v, ",");
        strcat(v, q[j]);
        free(q[j]);
      }
      strcat(v, "]");
      free(q);
      e = nqdset(r, "sources", p, "mirrors", v, strlen(v), why, sizeof why);
      free(v);
      if (e != NQOK) {
        ncmsg("data add", "--mirror: %s", why[0] ? why : nqerr(e));
        rc = NCUSE;
      }
    }
    if (syn && nqdset(r, "sources", p, "synthetic", "true", 4, why,
                      sizeof why) != NQOK)
      rc = NCUSE;
  }
  if (rc == NCOK)
    rc = ncdsave("data add", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int dput(int argc, char **argv) {
  int np, help, rc, e;
  nqdrec *r;
  uint8_t *b;
  size_t n;
  char why[600];
  if (ncargs("data put", argc, argv, NULL, 0, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 3) {
    ncmsg("data put", "give the folder, a member (sources, schemas, stats, "
          "chunks, steps, checks, commits, env, cite) and a JSON file (- "
          "for stdin)");
    return NCUSE;
  }
  if (ncrdx(argv[2], 0, NQDMAX, &b, &n) != NQOK) {
    ncmsg("data put", "%s: cannot be read (or is over 64 MiB)", argv[2]);
    return NCUSE;
  }
  if ((rc = ncdload("data put", argv[0], 1, &r)) != NCOK) {
    ncfree(b, n, 0);
    return rc;
  }
  e = nqdput(r, argv[1], (const char *)b, n, why, sizeof why);
  ncfree(b, n, 0);
  if (e != NQOK) {
    ncmsg("data put", "%s: %s", argv[2], why[0] ? why : nqerr(e));
    nqdrfree(r);
    return NCUSE;
  }
  rc = ncdsave("data put", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int ddel(int argc, char **argv) {
  int np, help, rc, e;
  nqdrec *r;
  if (ncargs("data del", argc, argv, NULL, 0, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 2 && np != 3) {
    ncmsg("data del", "give the folder, a member and the path or name of "
          "the element (none: the whole member)");
    return NCUSE;
  }
  if ((rc = ncdload("data del", argv[0], 0, &r)) != NCOK)
    return rc;
  e = nqddel(r, argv[1], np == 3 ? argv[2] : NULL);
  if (e != NQOK) {
    ncmsg("data del", e == NQEIO ? "%s has no %s %s" : "%s: %s is not a "
          "member with keyed elements", argv[0], argv[1],
          np == 3 ? argv[2] : "");
    nqdrfree(r);
    return NCUSE;
  }
  rc = ncdsave("data del", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int dfmt(int argc, char **argv) {
  int np, help, rc, e;
  nqdrec *r;
  uint8_t *b;
  size_t n;
  char p[4200], why[600];
  if (ncargs("data fmt", argc, argv, NULL, 0, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("data fmt", "give one folder");
    return NCUSE;
  }
  snprintf(p, sizeof p, "%s/%s", argv[0], NQDFILE);
  if (ncrdx(p, 0, NQDMAX, &b, &n) != NQOK) {
    ncmsg("data fmt", "%s: missing, unreadable or over 64 MiB", p);
    return NCUSE;
  }
  e = nqdparse((const char *)b, n, &r, why, sizeof why);
  ncfree(b, n, 0);
  if (e != NQOK) {
    ncmsg("data fmt", "%s: %s", p, why[0] ? why : nqerr(e));
    return NCUSE;
  }
  rc = ncdsave("data fmt", argv[0], r);
  nqdrfree(r);
  return rc;
}

static void line(const nqdrec *r, const char *m, size_t i) {
  size_t n = 0;
  char *b;
  if (nqdat(r, m, i, NULL, 0, &n) != NQEBUF || (b = (char *)malloc(n + 1))
                                                    == NULL)
    return;
  if (nqdat(r, m, i, b, n + 1, &n) == NQOK)
    printf("  %s\n", ncesc(b));
  free(b);
}

static int dshow(int argc, char **argv) {
  int np, help, json = 0, rc;
  nqdrec *r;
  size_t n = 0, i;
  char *b;
  static const char *const ms[] = {"sources", "schemas", "stats", "chunks",
                                   "steps", "checks", "commits", "env",
                                   "cite"};
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  if (ncargs("data show", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("data show", "give one folder");
    return NCUSE;
  }
  if ((rc = ncdload("data show", argv[0], 0, &r)) != NCOK)
    return rc;
  if (json) {
    if (nqdjson(r, NULL, 0, &n) == NQEBUF &&
        (b = (char *)malloc(n + 1)) != NULL) {
      if (nqdjson(r, b, n + 1, &n) == NQOK)
        printf("%s\n", b);
      free(b);
    }
    nqdrfree(r);
    return NCOK;
  }
  printf("%s: %s\n", ncesc(argv[0]), NQDFMT);
  for (i = 0; i < sizeof ms / sizeof ms[0]; i++) {
    size_t k, c = nqdlen(r, ms[i]);
    if (c == 0)
      continue;
    printf("%s (%lu):\n", ms[i], (unsigned long)c);
    for (k = 0; k < c; k++)
      line(r, ms[i], k);
  }
  nqdrfree(r);
  return NCOK;
}

static const char *dfix(const char *check) {
  if (strcmp(check, "record") == 0)
    return "restore noqtis.data.json from the sealed capsule; one edited by "
           "hand is rewritten in canonical form by `noqtis data fmt`";
  if (strcmp(check, "source") == 0)
    return "the file differs from the one recorded: restore it from its "
           "source (the record's url, archived copy or mirrors), or record "
           "the new bytes with `noqtis data add` and seal again";
  if (strcmp(check, "chunk") == 0)
    return "the file, or this piece of it, differs from the chunks recorded: "
           "fetch the chunks named again, or record the new file (`noqtis "
           "chunk pin`) and seal again";
  if (strcmp(check, "lock") == 0)
    return "the lock file differs from the one `noqtis env` recorded: record "
           "it again with `noqtis env` and seal again";
  if (strcmp(check, "drift") == 0)
    return "the data drifted from its summary: look at the column, and if "
           "the change is expected pin the new data (`noqtis drift pin`) "
           "and seal again";
  if (strcmp(check, "stats") == 0)
    return "the file's summaries are not those recorded: the file changed "
           "(see `noqtis drift check`), or was pinned read another way; "
           "pin it again with `noqtis drift pin` if the change is expected, "
           "and seal again";
  if (strcmp(check, "step") == 0)
    return "the script or mapping of a step changed: restore it, or record "
           "the step again with the new SHA-256 (`noqtis hash`) and seal "
           "again";
  if (strcmp(check, "schema") == 0 || strcmp(check, "rule") == 0)
    return "the file does not match its schema: correct the data, or pin a "
           "new schema with `noqtis schema infer` and seal again";
  return "a check recorded as failed: see its entry with `noqtis data show`";
}

/* row i over the reports rs[0..nr) */
static void rowat(const nqdrep *const *rs, size_t nr, size_t i,
                  const char **c, int *ok, const char **d) {
  size_t k;
  for (k = 0; k < nr; k++) {
    if (i < nqdrepn(rs[k])) {
      nqdrepi(rs[k], i, c, ok, d);
      return;
    }
    i -= nqdrepn(rs[k]);
  }
}

int ncdreps(const char *cmd, const char *lab, const nqdrep *const *rs,
            size_t nr, int ret, int json) {
  size_t i, n = 0, w = 6, nf = 0, k;
  for (k = 0; k < nr; k++)
    n += nqdrepn(rs[k]);
  for (i = 0; i < n; i++) {
    const char *c, *d;
    int ok;
    rowat(rs, nr, i, &c, &ok, &d);
    if (strlen(c) > w)
      w = strlen(c);
    nf += !ok;
  }
  if (json) {
    fputs("{\"folder\":", stdout);
    ncjstr(lab);
    printf(",\"ok\":%s,\"checks\":[", ret == NCOK ? "true" : "false");
  } else if (n > 0) {
    printf("%-4s  %-*s  %s\n", "", (int)w, "check", "detail");
  }
  for (i = 0; i < n; i++) {
    const char *c, *d;
    int ok;
    rowat(rs, nr, i, &c, &ok, &d);
    if (json) {
      fputs(i ? ",{\"check\":" : "{\"check\":", stdout);
      ncjstr(c);
      printf(",\"ok\":%s,\"detail\":", ok ? "true" : "false");
      ncjstr(d);
      if (!ok) {
        fputs(",\"fix\":", stdout);
        ncjstr(dfix(c));
      }
      putchar('}');
    } else {
      printf("%-4s  %-*s  %s\n", ok ? "ok" : "FAIL", (int)w, ncesc(c),
             ncesc(d));
    }
  }
  if (json) {
    fputs("]}\n", stdout);
    return ret;
  }
  if (ret == NCOK)
    printf("%s: OK (%lu checks passed)\n", ncesc(lab), (unsigned long)n);
  else
    printf("%s: FAILED (%lu of %lu checks failed)\n", ncesc(lab),
           (unsigned long)nf, (unsigned long)n);
  for (i = 0; i < n; i++) {
    const char *c = "", *d = "";
    int ok = 0, seen = 0;
    size_t j;
    rowat(rs, nr, i, &c, &ok, &d);
    for (j = 0; j < i && !seen; j++) {
      const char *c2 = "", *d2 = "";
      int ok2 = 0;
      rowat(rs, nr, j, &c2, &ok2, &d2);
      seen = !ok2 && strcmp(c, c2) == 0;
    }
    if (!ok && !seen)
      ncmsg(cmd, "%s: %s", c, dfix(c));
  }
  return ret;
}

int ncdrep(const char *cmd, const char *lab, const nqdrep *rep, int rc,
           int json) {
  return ncdreps(cmd, lab, &rep, 1,
                 rc == NQOK ? NCOK : rc == NQEVRFY ? NCBAD : NCUSE, json);
}

static int dcheck(int argc, char **argv) {
  int np, help, json = 0, rc, ret;
  nqdrep *rep = NULL;
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  if (ncargs("data check", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("data check", "give one folder");
    return NCUSE;
  }
  if (!ncisdir(argv[0])) {
    ncmsg("data check", "%s is not a folder", argv[0]);
    return NCUSE;
  }
  {
    char p[4200];
    snprintf(p, sizeof p, "%s/%s", argv[0], NQDFILE);
    if (!ncexist(p)) {
      ncmsg("data check", "%s has no %s: start one with `noqtis data init "
            "%s`", argv[0], NQDFILE, argv[0]);
      return NCUSE;
    }
  }
  rc = nqdchk(argv[0], &rep);
  if (rep == NULL)
    return nclib("data check", argv[0], rc);
  ret = ncdrep("data check", argv[0], rep, rc, json);
  nqdrepfree(rep);
  return ret;
}

/* the element JSON at e holds "path":<path> as its own member */
static int haspath(const char *e, const char *path) {
  char *q = ncjq(path), *k;
  const char *f;
  int hit = 0;
  if (q == NULL)
    return 0;
  k = (char *)malloc(strlen(q) + 10);
  if (k != NULL) {
    sprintf(k, "\"path\":%s", q);
    for (f = strstr(e, k); f != NULL && !hit; f = strstr(f + 1, k)) {
      char a = f[strlen(k)];
      hit = (f > e && (f[-1] == ',' || f[-1] == '{')) && (a == ',' || a == '}');
    }
    free(k);
  }
  free(q);
  return hit;
}

static int sinfer(int argc, char **argv) {
  const char *dl = NULL;
  int np, help, noh = 0, rng = 0, put = 0, i, rc = NCOK;
  nqdcsvopt co;
  nqdrec *r = NULL;
  ncopt o[] = {{'d', "delim", 1, &dl, NULL},
               {0, "no-header", 0, NULL, &noh},
               {0, "ranges", 0, NULL, &rng},
               {0, "put", 0, NULL, &put}};
  if (ncargs("schema infer", argc, argv, o, 4, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "schema");
    return NCOK;
  }
  if (np < 2) {
    ncmsg("schema infer", "give the folder and at least one CSV file in it");
    return NCUSE;
  }
  memset(&co, 0, sizeof co);
  if (dl != NULL) {
    if (strcmp(dl, "\\t") == 0 || strcmp(dl, "tab") == 0)
      dl = "\t";
    if (strlen(dl) != 1) {
      ncmsg("schema infer", "--delim: one byte, such as , ; | or tab");
      return NCUSE;
    }
    co.delim = dl[0];
  }
  co.noheader = noh;
  co.ranges = rng;
  if (put && (rc = ncdload("schema infer", argv[0], 1, &r)) != NCOK)
    return rc;
  for (i = 1; i < np && rc == NCOK; i++) {
    char why[600], *b = NULL;
    size_t n = 0;
    int e = nqdinfer(argv[0], argv[i], &co, NULL, 0, &n, why, sizeof why);
    if (e == NQEBUF && (b = (char *)malloc(n + 1)) != NULL)
      e = nqdinfer(argv[0], argv[i], &co, b, n + 1, &n, why, sizeof why);
    if (e != NQOK) {
      ncmsg("schema infer", "%s", why[0] ? why : nqerr(e));
      rc = NCUSE;
    } else if (put) {
      if (nqdput(r, "schemas", b, n, why, sizeof why) != NQOK) {
        ncmsg("schema infer", "%s", why);
        rc = NCUSE;
      }
    } else {
      printf("%s\n", b);
    }
    free(b);
  }
  if (put && rc == NCOK)
    rc = ncdsave("schema infer", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int scheck(int argc, char **argv) {
  int np, help, json = 0, rc, ret = NCOK, i;
  nqdrec *r;
  size_t k, n, nr = 0;
  nqdrep **rs;
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  if (ncargs("schema check", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "schema");
    return NCOK;
  }
  if (np < 1) {
    ncmsg("schema check", "give the folder (and, to check only them, "
          "files in it)");
    return NCUSE;
  }
  if ((rc = ncdload("schema check", argv[0], 0, &r)) != NCOK)
    return rc;
  n = nqdlen(r, "schemas");
  rs = (nqdrep **)calloc(n + 1, sizeof *rs);
  if (rs == NULL) {
    nqdrfree(r);
    return nclib("schema check", "memory", NQEMEM);
  }
  for (k = 0; k < n && ret != NCUSE; k++) {
    size_t l = 0;
    char *e = NULL;
    int want = np == 1;
    if (nqdat(r, "schemas", k, NULL, 0, &l) != NQEBUF ||
        (e = (char *)malloc(l + 1)) == NULL ||
        nqdat(r, "schemas", k, e, l + 1, &l) != NQOK) {
      free(e);
      ret = nclib("schema check", "memory", NQEMEM);
      break;
    }
    for (i = 1; i < np && !want; i++)
      want = haspath(e, argv[i]);
    if (want) {
      rc = nqdschk(argv[0], e, l, &rs[nr]);
      if (rs[nr] == NULL)
        ret = nclib("schema check", argv[0], rc);
      else {
        if (rc != NQOK)
          ret = NCBAD;
        nr++;
      }
    }
    free(e);
  }
  for (i = 1; i < np && ret != NCUSE; i++) {
    int hit = 0;
    for (k = 0; k < n && !hit; k++) {
      size_t l = 0;
      char *e = NULL;
      if (nqdat(r, "schemas", k, NULL, 0, &l) == NQEBUF &&
          (e = (char *)malloc(l + 1)) != NULL &&
          nqdat(r, "schemas", k, e, l + 1, &l) == NQOK)
        hit = haspath(e, argv[i]);
      free(e);
    }
    if (!hit) {
      ncmsg("schema check", "%s has no schema for %s: pin one with `noqtis "
            "schema infer --put %s %s`", argv[0], argv[i], argv[0], argv[i]);
      ret = NCUSE;
    }
  }
  if (ret != NCUSE && nr == 0) {
    ncmsg("schema check", "%s has no schemas: pin one with `noqtis schema "
          "infer --put %s <file>`", argv[0], argv[0]);
    ret = NCUSE;
  }
  if (ret != NCUSE)
    ret = ncdreps("schema check", argv[0], (const nqdrep *const *)rs, nr,
                  ret, json);
  for (k = 0; k < nr; k++)
    nqdrepfree(rs[k]);
  free(rs);
  nqdrfree(r);
  return ret;
}

int ncschema(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "infer") == 0)
    return sinfer(argc - 1, argv + 1);
  if (argc >= 2 && strcmp(argv[1], "check") == 0)
    return scheck(argc - 1, argv + 1);
  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 ||
                    strcmp(argv[1], "--help") == 0)) {
    ncuse(stdout, "schema");
    return NCOK;
  }
  if (argc < 2)
    ncuse(stderr, "schema");
  else
    ncmsg("schema", "unknown action %s (infer, check)", argv[1]);
  return NCUSE;
}

/* a number option in [lo, hi] */
static int optnum(const char *cmd, const char *name, const char *v,
                  double lo, double hi, double *out) {
  char *e;
  double d;
  if (v == NULL)
    return NCOK;
  d = strtod(v, &e);
  if (*v == '\0' || *e != '\0' || !(d >= lo && d <= hi)) {
    ncmsg(cmd, "%s %s: a number from %g to %g", name, v, lo, hi);
    return NCUSE;
  }
  *out = d;
  return NCOK;
}

static int dpin(int argc, char **argv) {
  const char *dl = NULL;
  int np, help, noh = 0, i, rc;
  nqdcsvopt co;
  nqdrec *r = NULL;
  ncopt o[] = {{'d', "delim", 1, &dl, NULL},
               {0, "no-header", 0, NULL, &noh}};
  if (ncargs("drift pin", argc, argv, o, 2, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "drift");
    return NCOK;
  }
  if (np < 2) {
    ncmsg("drift pin", "give the folder and at least one CSV file in it");
    return NCUSE;
  }
  memset(&co, 0, sizeof co);
  if (dl != NULL) {
    if (strcmp(dl, "tab") == 0)
      dl = "\t";
    if (strlen(dl) != 1) {
      ncmsg("drift pin", "--delim: one byte, such as , ; | or tab");
      return NCUSE;
    }
    co.delim = dl[0];
  }
  co.noheader = noh;
  if ((rc = ncdload("drift pin", argv[0], 1, &r)) != NCOK)
    return rc;
  for (i = 1; i < np && rc == NCOK; i++) {
    char why[600], *b = NULL;
    size_t n = 0;
    int e = nqdstats(argv[0], argv[i], &co, NULL, 0, &n, why, sizeof why);
    if (e == NQEBUF && (b = (char *)malloc(n + 1)) != NULL)
      e = nqdstats(argv[0], argv[i], &co, b, n + 1, &n, why, sizeof why);
    if (e == NQOK)
      e = nqdput(r, "stats", b, n, why, sizeof why);
    if (e != NQOK) {
      ncmsg("drift pin", "%s", why[0] ? why : nqerr(e));
      rc = NCUSE;
    }
    free(b);
  }
  if (rc == NCOK)
    rc = ncdsave("drift pin", argv[0], r);
  nqdrfree(r);
  return rc;
}

#define NCWARN 3 /* drift: a warning, no failure */

static int dchk(int argc, char **argv) {
  const char *dl = NULL, *pw = NULL, *pf = NULL, *al = NULL, *mn = NULL;
  int np, help, noh = 0, json = 0, ben = 0, i, rc, ret = NCOK, warn = 0;
  nqdcsvopt co;
  nqddopt d;
  nqdrec *r;
  size_t k, n, nr = 0, nh = 0;
  nqdrep **rs;
  ncopt o[] = {{'d', "delim", 1, &dl, NULL},
               {0, "no-header", 0, NULL, &noh},
               {'j', "json", 0, NULL, &json},
               {0, "psi-warn", 1, &pw, NULL},
               {0, "psi-fail", 1, &pf, NULL},
               {0, "alpha", 1, &al, NULL},
               {0, "min-n", 1, &mn, NULL},
               {0, "benford", 0, NULL, &ben}};
  if (ncargs("drift check", argc, argv, o, 8, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "drift");
    return NCOK;
  }
  if (np < 1) {
    ncmsg("drift check", "give the folder, and optionally <path> or "
          "<path>=<current file> for each file to compare");
    return NCUSE;
  }
  memset(&co, 0, sizeof co);
  if (dl != NULL) {
    if (strcmp(dl, "tab") == 0)
      dl = "\t";
    if (strlen(dl) != 1) {
      ncmsg("drift check", "--delim: one byte, such as , ; | or tab");
      return NCUSE;
    }
    co.delim = dl[0];
  }
  co.noheader = noh;
  d.psiwarn = 0.1;
  d.psifail = 0.25;
  d.alpha = 0.001;
  d.minn = 1000;
  d.benford = ben;
  if (optnum("drift check", "--psi-warn", pw, 0, 1e9, &d.psiwarn) != NCOK ||
      optnum("drift check", "--psi-fail", pf, 0, 1e9, &d.psifail) != NCOK ||
      optnum("drift check", "--alpha", al, 0, 1, &d.alpha) != NCOK ||
      optnum("drift check", "--min-n", mn, 0, 9e15, &d.minn) != NCOK)
    return NCUSE;
  if ((rc = ncdload("drift check", argv[0], 0, &r)) != NCOK)
    return rc;
  n = nqdlen(r, "stats");
  rs = (nqdrep **)calloc(n + 1, sizeof *rs);
  if (rs == NULL) {
    nqdrfree(r);
    return nclib("drift check", "memory", NQEMEM);
  }
  for (k = 0; k < n && ret != NCUSE; k++) {
    size_t l = 0;
    char *e = NULL, cur[4200];
    const char *alt = NULL;
    int want = np == 1;
    if (nqdat(r, "stats", k, NULL, 0, &l) != NQEBUF ||
        (e = (char *)malloc(l + 1)) == NULL ||
        nqdat(r, "stats", k, e, l + 1, &l) != NQOK) {
      free(e);
      ret = nclib("drift check", "memory", NQEMEM);
      break;
    }
    for (i = 1; i < np && !want; i++) {
      char *eq = strchr(argv[i], '=');
      if (eq != NULL) {
        *eq = '\0';
        want = haspath(e, argv[i]);
        *eq = '=';
        if (want)
          alt = eq + 1;
      } else {
        want = haspath(e, argv[i]);
      }
    }
    if (want) {
      /* the stats element's path, from its JSON: "path":"..." */
      const char *pp = strstr(e, ",\"path\":\"");
      nh++;
      if (alt != NULL) {
        snprintf(cur, sizeof cur, "%s", alt);
      } else if (pp != NULL) {
        size_t m = 0;
        pp += 9;
        m = (size_t)snprintf(cur, sizeof cur, "%s/", argv[0]);
        /* paths of a record have no quote or backslash escapes but \"
         * and \\; copy until the closing quote */
        while (*pp && *pp != '"' && m + 2 < sizeof cur) {
          if (*pp == '\\' && pp[1])
            pp++;
          cur[m++] = *pp++;
        }
        cur[m] = '\0';
      }
      rc = nqddrift(e, l, cur, &co, &d, &rs[nr]);
      if (rs[nr] == NULL) {
        ret = nclib("drift check", cur, rc);
      } else {
        size_t q;
        if (rc != NQOK)
          ret = NCBAD;
        for (q = 0; q < nqdrepn(rs[nr]); q++) {
          const char *c;
          nqdrepi(rs[nr], q, &c, NULL, NULL);
          warn |= strcmp(c, "drift.warn") == 0;
        }
        nr++;
      }
    }
    free(e);
  }
  if (ret != NCUSE && np > 1 && nh < (size_t)np - 1) {
    ncmsg("drift check", "a file named has no summary in %s: pin one with "
          "`noqtis drift pin %s <file>`", argv[0], argv[0]);
    ret = NCUSE;
  }
  if (ret != NCUSE && nr == 0) {
    ncmsg("drift check", "%s has no summaries: pin one with `noqtis drift "
          "pin %s <file>`", argv[0], argv[0]);
    ret = NCUSE;
  }
  if (ret != NCUSE) {
    if (json) {
      size_t q, first = 1;
      fputs("{\"folder\":", stdout);
      ncjstr(argv[0]);
      printf(",\"level\":\"%s\",\"rows\":[",
             ret == NCBAD ? "fail" : warn ? "warn" : "ok");
      for (k = 0; k < nr; k++) {
        for (q = 0; q < nqdrepn(rs[k]); q++) {
          const char *c, *dt, *j = nqdrepj(rs[k], q);
          int ok;
          nqdrepi(rs[k], q, &c, &ok, &dt);
          fputs(first ? "{\"check\":" : ",{\"check\":", stdout);
          first = 0;
          ncjstr(c);
          printf(",\"ok\":%s,\"detail\":", ok ? "true" : "false");
          ncjstr(dt);
          if (j != NULL)
            printf(",\"stats\":%s", j);
          putchar('}');
        }
      }
      fputs("]}\n", stdout);
    } else {
      ncdreps("drift check", argv[0], (const nqdrep *const *)rs, nr, ret, 0);
    }
    if (ret == NCOK && warn)
      ret = NCWARN;
  }
  for (k = 0; k < nr; k++)
    nqdrepfree(rs[k]);
  free(rs);
  nqdrfree(r);
  return ret;
}

/* noqtis drift cal: each <path>=<file> names a file known not to have
 * drifted from the summary of path; the files of one path calibrate it
 * together */
static int dcal(int argc, char **argv) {
  const char *dl = NULL;
  int np, help, noh = 0, i, j, rc;
  nqdcsvopt co;
  nqdrec *r = NULL;
  const char **fs;
  char *done;
  ncopt o[] = {{'d', "delim", 1, &dl, NULL},
               {0, "no-header", 0, NULL, &noh}};
  if (ncargs("drift cal", argc, argv, o, 2, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "drift");
    return NCOK;
  }
  if (np < 2) {
    ncmsg("drift cal", "give the folder and at least one <file>=<file "
          "known not to have drifted>");
    return NCUSE;
  }
  for (i = 1; i < np; i++) {
    char *eq = strchr(argv[i], '=');
    if (eq == NULL || eq == argv[i] || eq[1] == '\0') {
      ncmsg("drift cal", "%s: give <file>=<file known not to have drifted "
            "from it>", argv[i]);
      return NCUSE;
    }
  }
  memset(&co, 0, sizeof co);
  if (dl != NULL) {
    if (strcmp(dl, "tab") == 0)
      dl = "\t";
    if (strlen(dl) != 1) {
      ncmsg("drift cal", "--delim: one byte, such as , ; | or tab");
      return NCUSE;
    }
    co.delim = dl[0];
  }
  co.noheader = noh;
  if ((rc = ncdload("drift cal", argv[0], 0, &r)) != NCOK)
    return rc;
  fs = (const char **)calloc((size_t)np, sizeof *fs);
  done = (char *)calloc((size_t)np, 1);
  if (fs == NULL || done == NULL) {
    free(fs);
    free(done);
    nqdrfree(r);
    return nclib("drift cal", "memory", NQEMEM);
  }
  /* <path>=<file>: the path, and the file after it */
  for (i = 1; i < np; i++)
    *strchr(argv[i], '=') = '\0';
  for (i = 1; i < np && rc == NCOK; i++) {
    char why[600], *e = NULL, *b = NULL;
    size_t l = 0, nf = 0, n = 0;
    int k;
    if (done[i])
      continue;
    /* every file given for this path, in the order given */
    for (j = i; j < np; j++) {
      if (strcmp(argv[j], argv[i]) == 0) {
        fs[nf++] = argv[j] + strlen(argv[j]) + 1;
        done[j] = 1;
      }
    }
    k = nqdkey(r, "stats", argv[i], NULL, 0, &l);
    if (k == NQEIO) {
      ncmsg("drift cal", "%s has no summary of %s: pin one with `noqtis "
            "drift pin %s %s`", argv[0], argv[i], argv[0], argv[i]);
      rc = NCUSE;
      break;
    }
    if (k != NQEBUF || (e = (char *)malloc(l + 1)) == NULL ||
        nqdkey(r, "stats", argv[i], e, l + 1, &l) != NQOK) {
      free(e);
      rc = nclib("drift cal", "memory", NQEMEM);
      break;
    }
    why[0] = '\0';
    k = nqddcal(e, l, fs, nf, &co, NULL, 0, &n, why, sizeof why);
    if (k == NQEBUF && (b = (char *)malloc(n + 1)) != NULL)
      k = nqddcal(e, l, fs, nf, &co, b, n + 1, &n, why, sizeof why);
    if (k == NQOK)
      k = nqdput(r, "stats", b, n, why, sizeof why);
    if (k != NQOK) {
      ncmsg("drift cal", "%s", why[0] ? why : nqerr(k));
      rc = NCUSE;
    } else {
      printf("%s: calibrated on %lu file%s known not to have drifted\n",
             ncesc(argv[i]), (unsigned long)nf, nf == 1 ? "" : "s");
    }
    free(e);
    free(b);
  }
  free(fs);
  free(done);
  if (rc == NCOK)
    rc = ncdsave("drift cal", argv[0], r);
  nqdrfree(r);
  return rc;
}

int ncdrift(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "pin") == 0)
    return dpin(argc - 1, argv + 1);
  if (argc >= 2 && strcmp(argv[1], "cal") == 0)
    return dcal(argc - 1, argv + 1);
  if (argc >= 2 && strcmp(argv[1], "check") == 0)
    return dchk(argc - 1, argv + 1);
  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 ||
                    strcmp(argv[1], "--help") == 0)) {
    ncuse(stdout, "drift");
    return NCOK;
  }
  if (argc < 2)
    ncuse(stderr, "drift");
  else
    ncmsg("drift", "unknown action %s (pin, check, cal)", argv[1]);
  return NCUSE;
}

/* the platform this tool was built for */
static const char *osname(void) {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#elif defined(__FreeBSD__)
  return "freebsd";
#elif defined(__OpenBSD__)
  return "openbsd";
#elif defined(__NetBSD__)
  return "netbsd";
#else
  return "other";
#endif
}

static const char *archname(void) {
#if defined(__x86_64__) || defined(_M_X64)
  return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
  return "aarch64";
#elif defined(__i386__) || defined(_M_IX86)
  return "i686";
#elif defined(__arm__)
  return "arm";
#elif defined(__s390x__)
  return "s390x";
#elif defined(__riscv)
  return "riscv";
#elif defined(__wasm__)
  return "wasm32";
#else
  return "other";
#endif
}

/* appends ,"k":<JSON string of v> to b (cap bytes) */
static int jadd(char *b, size_t cap, const char *k, const char *v) {
  char *q;
  size_t n = strlen(b);
  if (v == NULL || *v == '\0')
    return NCOK;
  if ((q = ncjq(v)) == NULL)
    return NCUSE;
  if ((size_t)snprintf(b + n, cap - n, "%s\"%s\":%s", n > 1 ? "," : "", k,
                       q) >= cap - n) {
    free(q);
    return NCUSE;
  }
  free(q);
  return NCOK;
}

static int denv(int argc, char **argv) {
  static const char *const known[] = {
      "renv.lock", "uv.lock", "poetry.lock", "Pipfile.lock",
      "requirements.txt", "Cargo.lock", "go.sum", "package-lock.json",
      "pnpm-lock.yaml", "yarn.lock", "environment.yml", "Manifest.toml"};
  const char *seed = NULL, *rng = NULL, *lk[NCMAXV];
  int np, help, nl = 0, i, rc;
  char b[16384], why[600];
  nqdrec *r;
  ncopt o[] = {{0, "seed", 1, &seed, NULL},
               {0, "rng", 1, &rng, NULL},
               {0, "lock", NCMANY, lk, &nl}};
  if (ncargs("env", argc, argv, o, 3, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "env");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("env", "give one capsule folder");
    return NCUSE;
  }
  if (seed != NULL && rng == NULL) {
    ncmsg("env", "--seed needs --rng, the generator it seeds (such as "
          "Mersenne-Twister)");
    return NCUSE;
  }
  strcpy(b, "{");
  if (jadd(b, sizeof b, "os", osname()) != NCOK ||
      jadd(b, sizeof b, "arch", archname()) != NCOK ||
      jadd(b, sizeof b, "noqtis", nqver()) != NCOK ||
      jadd(b, sizeof b, "locale",
           getenv("LC_ALL") && *getenv("LC_ALL") ? getenv("LC_ALL")
                                                  : getenv("LANG")) !=
          NCOK ||
      jadd(b, sizeof b, "tz", getenv("TZ")) != NCOK)
    return nclib("env", "memory", NQELIM);
  strcat(b, "}");
  if ((rc = ncdload("env", argv[0], 1, &r)) != NCOK)
    return rc;
  if (nqdput(r, "env", b, strlen(b), why, sizeof why) != NQOK) {
    ncmsg("env", "%s", why);
    nqdrfree(r);
    return NCUSE;
  }
  if (rng != NULL) {
    char g[1024] = "{";
    jadd(g, sizeof g, "kind", rng);
    if (seed != NULL)
      jadd(g, sizeof g, "seed", seed);
    strcat(g, "}");
    if (nqdset(r, "env", NULL, "rng", g, strlen(g), why, sizeof why) !=
        NQOK) {
      ncmsg("env", "--rng: %s", why);
      nqdrfree(r);
      return NCUSE;
    }
  }
  /* lock files: those named, else the known ones at the top of dir */
  {
    char a[16384] = "[";
    int k = 0, n = nl > 0 ? nl : (int)(sizeof known / sizeof known[0]);
    for (i = 0; i < n; i++) {
      const char *f = nl > 0 ? lk[i] : known[i];
      char p[4200], hx[65], e[4400], *q;
      uint8_t *buf, h[32];
      size_t bl, j;
      snprintf(p, sizeof p, "%s/%s", argv[0], f);
      if (!ncisreg(p)) {
        if (nl > 0) {
          ncmsg("env", "--lock %s: not a file in %s", f, argv[0]);
          nqdrfree(r);
          return NCUSE;
        }
        continue;
      }
      if (ncrdx(p, 0, NCRDMAX, &buf, &bl) != NCOK ||
          nqhash(NQS256, buf, bl, h, 32) != NQOK) {
        ncmsg("env", "%s: cannot be read", p);
        nqdrfree(r);
        return NCUSE;
      }
      ncfree(buf, bl, 0);
      for (j = 0; j < 32; j++)
        snprintf(hx + 2 * j, 3, "%02x", h[j]);
      if ((q = ncjq(f)) == NULL)
        return nclib("env", "memory", NQEMEM);
      snprintf(e, sizeof e, "%s{\"path\":%s,\"sha256\":\"%s\"}",
               k++ ? "," : "", q, hx);
      free(q);
      if (strlen(a) + strlen(e) + 2 >= sizeof a) {
        ncmsg("env", "too many lock files");
        nqdrfree(r);
        return NCUSE;
      }
      strcat(a, e);
    }
    strcat(a, "]");
    if (k > 0 &&
        nqdset(r, "env", NULL, "locks", a, strlen(a), why, sizeof why) !=
            NQOK) {
      ncmsg("env", "--lock: %s", why);
      nqdrfree(r);
      return NCUSE;
    }
  }
  rc = ncdsave("env", argv[0], r);
  nqdrfree(r);
  return rc;
}

int ncenv(int argc, char **argv) {
  return denv(argc, argv);
}

int nccommit(int argc, char **argv) {
  const char *kind = "other", *lab = NULL, *after = NULL, *out = NULL;
  int np, help, force = 0, rc;
  uint8_t *m, salt[32];
  size_t n;
  char hx[65], e[2048], t[21], why[600], sp[4200];
  nqdrec *r;
  ncopt o[] = {{0, "kind", 1, &kind, NULL},
               {0, "label", 1, &lab, NULL},
               {0, "after", 1, &after, NULL},
               {'o', "out", 1, &out, NULL},
               {'f', "force", 0, NULL, &force}};
  if (ncargs("commit", argc, argv, o, 5, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "commit");
    return NCOK;
  }
  if (np != 2) {
    ncmsg("commit", "give the capsule folder and the file to commit to");
    return NCUSE;
  }
  if (ncrdx(argv[1], 0, NCRDMAX, &m, &n) != NCOK) {
    ncmsg("commit", "%s: cannot be read (or is over 1 GiB)", argv[1]);
    return NCUSE;
  }
  if (nqrand(salt, sizeof salt) != NQOK ||
      nqdcommit(salt, sizeof salt, m, n, hx) != NQOK) {
    ncfree(m, n, 0);
    nqwipe(salt, sizeof salt);
    return nclib("commit", "the commitment", NQERNG);
  }
  ncfree(m, n, 0);
  if (optime("now", t) != NCOK) {
    nqwipe(salt, sizeof salt);
    return NCUSE;
  }
  snprintf(e, sizeof e,
           "{\"kind\":\"%s\",\"created\":\"%s\",\"alg\":\"sha3-256\","
           "\"digest\":\"%s\"",
           strchr(kind, '"') == NULL ? kind : "?", t, hx);
  if (lab != NULL) {
    char *q = ncjq(lab);
    if (q != NULL && strlen(e) + strlen(q) + 12 < sizeof e) {
      strcat(e, ",\"label\":");
      strcat(e, q);
    }
    free(q);
  }
  if (after != NULL && strlen(after) == 20 && strchr(after, '"') == NULL) {
    strcat(e, ",\"after\":\"");
    strcat(e, after);
    strcat(e, "\"");
  } else if (after != NULL) {
    ncmsg("commit", "--after: a UTC time YYYY-MM-DDTHH:MM:SSZ");
    nqwipe(salt, sizeof salt);
    return NCUSE;
  }
  strcat(e, "}");
  snprintf(sp, sizeof sp, "%s.salt", argv[1]);
  if (out == NULL)
    out = sp;
  if ((rc = ncdload("commit", argv[0], 1, &r)) != NCOK) {
    nqwipe(salt, sizeof salt);
    return rc;
  }
  if (nqdput(r, "commits", e, strlen(e), why, sizeof why) != NQOK) {
    ncmsg("commit", "%s", why);
    nqdrfree(r);
    nqwipe(salt, sizeof salt);
    return NCUSE;
  }
  /* the salt first: a record that names a commitment nobody can open
   * would be worse than none */
  if (ncwr(out, salt, sizeof salt, force, 1) != NCOK) {
    nqwipe(salt, sizeof salt);
    nqdrfree(r);
    return ncwfail("commit", out, force);
  }
  nqwipe(salt, sizeof salt);
  rc = ncdsave("commit", argv[0], r);
  nqdrfree(r);
  if (rc == NCOK)
    ncmsg("commit", "committed to %s (SHA3-256 %.16s...); the salt is in "
          "%s: keep it secret and outside the capsule until the reveal",
          argv[1], hx, out);
  return rc;
}

int ncreveal(int argc, char **argv) {
  int np, help, rc;
  uint8_t *m, *s;
  size_t n, sn, at = 0;
  nqdrec *r;
  if (ncargs("reveal", argc, argv, NULL, 0, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "reveal");
    return NCOK;
  }
  if (np != 3) {
    ncmsg("reveal", "give the capsule folder, the file and its salt file");
    return NCUSE;
  }
  if ((rc = ncdload("reveal", argv[0], 0, &r)) != NCOK)
    return rc;
  if (ncrdx(argv[1], 0, NCRDMAX, &m, &n) != NCOK ||
      ncrdx(argv[2], 1, NCRDSMALL, &s, &sn) != NCOK) {
    ncmsg("reveal", "%s or %s cannot be read", argv[1], argv[2]);
    nqdrfree(r);
    return NCUSE;
  }
  rc = nqdreveal(r, s, sn, m, n, &at);
  ncfree(m, n, 0);
  ncfree(s, sn, 1);
  nqdrfree(r);
  if (rc == NQOK) {
    printf("%s: matches commitment %lu of %s\n", ncesc(argv[1]),
           (unsigned long)at + 1, ncesc(argv[0]));
    return NCOK;
  }
  if (rc == NQEVRFY) {
    printf("%s: matches no commitment of %s\n", ncesc(argv[1]),
           ncesc(argv[0]));
    ncmsg("reveal", "the file, or the salt, is not the one committed to: "
          "this is not the list or plan recorded before");
    return NCBAD;
  }
  return nclib("reveal", "the salt", rc);
}

int nccite(int argc, char **argv) {
  const char *fmt = "cff";
  int np, help, rc, f;
  nqdrec *r;
  size_t n = 0;
  char *b;
  ncopt o[] = {{0, "format", 1, &fmt, NULL}};
  if (ncargs("cite", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "cite");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("cite", "give one capsule folder");
    return NCUSE;
  }
  f = strcmp(fmt, "cff") == 0 ? NQDCFF : strcmp(fmt, "bibtex") == 0 ? NQDBIB
                                                                  : 0;
  if (f == 0) {
    ncmsg("cite", "--format: cff or bibtex");
    return NCUSE;
  }
  if ((rc = ncdload("cite", argv[0], 0, &r)) != NCOK)
    return rc;
  rc = nqdcite(r, f, NULL, 0, &n);
  if (rc == NQEIO) {
    ncmsg("cite", "%s says nothing of how to cite it: add it with `noqtis "
          "data put %s cite <json-file>` (title, authors, year, doi, ...)",
          argv[0], argv[0]);
    nqdrfree(r);
    return NCUSE;
  }
  if (rc == NQEBUF && (b = (char *)malloc(n + 1)) != NULL) {
    if (nqdcite(r, f, b, n + 1, &n) == NQOK)
      fputs(b, stdout);
    free(b);
  }
  nqdrfree(r);
  return NCOK;
}

int ncdiff(int argc, char **argv) {
  int np, help, json = 0, rc;
  nqdrep *rep = NULL;
  size_t i, n, nd = 0, w = 8;
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  if (ncargs("diff", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "diff");
    return NCOK;
  }
  if (np != 2) {
    ncmsg("diff", "give two capsule folders (see `noqtis help diff`)");
    return NCUSE;
  }
  for (i = 0; i < 2; i++) {
    if (!ncisdir(argv[i])) {
      ncmsg("diff", "%s is not a folder", argv[i]);
      return NCUSE;
    }
  }
  rc = nqddiff(argv[0], argv[1], &rep);
  if (rep == NULL)
    return nclib("diff", "compare", rc);
  n = nqdrepn(rep);
  for (i = 0; i < n; i++) {
    const char *c;
    int ok;
    nqdrepi(rep, i, &c, &ok, NULL);
    nd += !ok;
    if (strlen(c) > w)
      w = strlen(c);
  }
  if (json) {
    fputs("{\"from\":", stdout);
    ncjstr(argv[0]);
    fputs(",\"to\":", stdout);
    ncjstr(argv[1]);
    printf(",\"same\":%s,\"rows\":[", nd ? "false" : "true");
  }
  for (i = 0; i < n; i++) {
    const char *c, *d;
    int ok;
    nqdrepi(rep, i, &c, &ok, &d);
    if (json) {
      fputs(i ? ",{\"what\":" : "{\"what\":", stdout);
      ncjstr(c);
      printf(",\"differs\":%s,\"detail\":", ok ? "false" : "true");
      ncjstr(d);
      putchar('}');
    } else {
      printf("%-4s  %-*s  %s\n", ok ? "" : "diff", (int)w, ncesc(c),
             ncesc(d));
    }
  }
  if (json)
    fputs("]}\n", stdout);
  else if (nd == 0)
    printf("%s and %s: the same\n", ncesc(argv[0]), ncesc(argv[1]));
  else
    printf("%s and %s: %lu differences\n", ncesc(argv[0]), ncesc(argv[1]),
           (unsigned long)nd);
  nqdrepfree(rep);
  return rc == NQOK ? NCOK : rc == NQEVRFY ? NCBAD : NCUSE;
}

/* a whole number option from 0 to 2^64 - 1 */
static int optu64(const char *cmd, const char *name, const char *v,
                  uint64_t *out) {
  uint64_t x = 0;
  const char *q;
  if (v == NULL)
    return NCOK;
  for (q = v; *q; q++) {
    unsigned d = (unsigned)(*q - '0');
    if (*q < '0' || *q > '9' || x > (UINT64_MAX - d) / 10) {
      ncmsg(cmd, "%s %s: a whole number from 0 to 18446744073709551615",
            name, v);
      return NCUSE;
    }
    x = x * 10 + d;
  }
  if (q == v) {
    ncmsg(cmd, "%s: a whole number", name);
    return NCUSE;
  }
  *out = x;
  return NCOK;
}

static int dsyn(int argc, char **argv) {
  const char *sd = NULL, *rw = NULL;
  int np, help, rc;
  uint64_t seed = 0, rows = 0;
  nqdrec *r = NULL;
  char why[600];
  ncopt o[] = {{0, "seed", 1, &sd, NULL}, {0, "rows", 1, &rw, NULL}};
  if (ncargs("data syn", argc, argv, o, 2, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "data");
    return NCOK;
  }
  if (np != 2) {
    ncmsg("data syn", "give the folder and the CSV file to make");
    return NCUSE;
  }
  if (sd == NULL) {
    ncmsg("data syn", "give --seed: the same seed makes the same file");
    return NCUSE;
  }
  if (optu64("data syn", "--seed", sd, &seed) != NCOK ||
      optu64("data syn", "--rows", rw, &rows) != NCOK)
    return NCUSE;
  if ((rc = ncdload("data syn", argv[0], 0, &r)) != NCOK)
    return rc;
  why[0] = '\0';
  rc = nqdsyn(r, argv[0], argv[1], seed, rows, why, sizeof why);
  if (rc != NQOK) {
    ncmsg("data syn", "%s", why[0] ? why : nqerr(rc));
    if (rc == NQEARG)
      ncmsg("data syn", "the recipe is the file's schema: pin one with "
            "`noqtis schema infer --put` or `noqtis data put %s schemas`",
            argv[0]);
    nqdrfree(r);
    return NCUSE;
  }
  rc = ncdsave("data syn", argv[0], r);
  if (rc == NCOK)
    ncmsg("data syn", "wrote %s, synthetic, and recorded it as such",
          argv[1]);
  nqdrfree(r);
  return rc;
}

static int cpin(int argc, char **argv) {
  const char *sz = NULL;
  uint64_t chunk = (uint64_t)1 << 20;
  int np, help, i, rc, e;
  nqdrec *r;
  char why[600], *b;
  size_t n;
  ncopt o[] = {{0, "size", 1, &sz, NULL}};
  if (ncargs("chunk pin", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "chunk");
    return NCOK;
  }
  if (np < 2) {
    ncmsg("chunk pin", "give the folder and at least one file in it");
    return NCUSE;
  }
  if (sz != NULL && optu64("chunk pin", "--size", sz, &chunk) != NCOK)
    return NCUSE;
  if ((rc = ncdload("chunk pin", argv[0], 1, &r)) != NCOK)
    return rc;
  for (i = 1; i < np && rc == NCOK; i++) {
    n = 0;
    e = nqdchunk(argv[0], argv[i], chunk, NULL, 0, &n, why, sizeof why);
    if (e == NQEBUF && (b = (char *)malloc(n + 1)) != NULL) {
      e = nqdchunk(argv[0], argv[i], chunk, b, n + 1, &n, why, sizeof why);
      if (e == NQOK)
        e = nqdput(r, "chunks", b, n, why, sizeof why);
      free(b);
    }
    if (e != NQOK) {
      ncmsg("chunk pin", "%s: %s", argv[i], why[0] ? why : nqerr(e));
      rc = NCUSE;
    }
  }
  if (rc == NCOK)
    rc = ncdsave("chunk pin", argv[0], r);
  nqdrfree(r);
  return rc;
}

static int ccheck(int argc, char **argv) {
  const char *atv = NULL;
  uint64_t off = 0;
  int np, help, json = 0, rc, e;
  nqdrec *r;
  nqdrep *rep = NULL;
  char p[4200], *b;
  size_t n = 0;
  ncopt o[] = {{0, "at", 1, &atv, NULL}, {'j', "json", 0, NULL, &json}};
  if (ncargs("chunk check", argc, argv, o, 2, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "chunk");
    return NCOK;
  }
  if (np != 2 && np != 3) {
    ncmsg("chunk check", "give the folder, the file and, when you have only "
          "a piece of it, the piece");
    return NCUSE;
  }
  if (atv != NULL && optu64("chunk check", "--at", atv, &off) != NCOK)
    return NCUSE;
  if (atv != NULL && np != 3) {
    ncmsg("chunk check", "--at says where a piece starts: give the piece");
    return NCUSE;
  }
  if ((rc = ncdload("chunk check", argv[0], 0, &r)) != NCOK)
    return rc;
  e = nqdkey(r, "chunks", argv[1], NULL, 0, &n);
  if (e != NQEBUF || (b = (char *)malloc(n + 1)) == NULL) {
    ncmsg("chunk check", "%s records no chunks of %s: pin them with `noqtis "
          "chunk pin %s %s`", argv[0], argv[1], argv[0], argv[1]);
    nqdrfree(r);
    return NCUSE;
  }
  e = nqdkey(r, "chunks", argv[1], b, n + 1, &n);
  nqdrfree(r);
  if (np == 3)
    snprintf(p, sizeof p, "%s", argv[2]);
  else
    snprintf(p, sizeof p, "%s/%s", argv[0], argv[1]);
  if (e == NQOK)
    e = nqdpiece(b, n, p, off, &rep);
  free(b);
  if (rep == NULL)
    return nclib("chunk check", argv[1], e);
  rc = ncdrep("chunk check", np == 3 ? argv[2] : argv[1], rep, e, json);
  nqdrepfree(rep);
  return rc;
}

int ncchunk(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0) {
    ncuse(argc < 2 ? stderr : stdout, "chunk");
    return argc < 2 ? NCUSE : NCOK;
  }
  if (strcmp(argv[1], "pin") == 0)
    return cpin(argc - 1, argv + 1);
  if (strcmp(argv[1], "check") == 0)
    return ccheck(argc - 1, argv + 1);
  ncmsg("chunk", "unknown action %s (pin, check)", argv[1]);
  return NCUSE;
}

int ncdata(int argc, char **argv) {
  static const struct {
    const char *v;
    int (*f)(int, char **);
  } vs[] = {{"init", dinit}, {"add", dadd},     {"put", dput},
            {"del", ddel},   {"fmt", dfmt},     {"show", dshow},
            {"check", dcheck}, {"syn", dsyn}};
  size_t i;
  if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0) {
    ncuse(argc < 2 ? stderr : stdout, "data");
    return argc < 2 ? NCUSE : NCOK;
  }
  for (i = 0; i < sizeof vs / sizeof vs[0]; i++)
    if (strcmp(argv[1], vs[i].v) == 0)
      return vs[i].f(argc - 1, argv + 1);
  ncmsg("data", "unknown action %s (init, add, put, del, fmt, show, check, "
        "syn)", argv[1]);
  return NCUSE;
}
