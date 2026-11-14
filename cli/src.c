/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis src: the sources of a capsule's data record, fetched. add
 * records a file by its address or its portal (and fetches it when it
 * is not there yet), resolve asks each portal where its file is now,
 * fetch restores files from the first address that gives the recorded
 * bytes (the url, the portal, the mirrors, the archived copy), refresh
 * fetches each source again and says what changed, list shows them.
 * The addresses, the resolvers and the check of the bytes are nqd's
 * (nqdaddr(3)); the HTTP is net.c's (ncfetch). */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NCSRCMAX ((uint64_t)1 << 30) /* the default largest file */
#define NCSRCSECS 600                /* the default time per file */
#define NCMETA ((size_t)16 << 20)    /* the largest portal reply */
#define NCWARN 3                     /* refresh: a source unreachable */

typedef struct {
  size_t max;
  int secs;
} ncsopt;

/* --max and --timeout */
static int sopts(const char *cmd, const char *mx, const char *to,
                 ncsopt *o) {
  char *e;
  o->max = (size_t)NCSRCMAX;
  o->secs = NCSRCSECS;
  if (mx != NULL) {
    unsigned long long v = strtoull(mx, &e, 10);
    if (*mx < '0' || *mx > '9' || *e != '\0' || v == 0 ||
        v > (unsigned long long)((size_t)-1 >> 1)) {
      ncmsg(cmd, "--max %s: a size in bytes, from 1", mx);
      return NCUSE;
    }
    o->max = (size_t)v;
  }
  if (to != NULL) {
    long v = strtol(to, &e, 10);
    if (*to < '0' || *to > '9' || *e != '\0' || v < 1 || v > 86400) {
      ncmsg(cmd, "--timeout %s: seconds, from 1 to 86400", to);
      return NCUSE;
    }
    o->secs = (int)v;
  }
  return NCOK;
}

#ifdef NQTEST
/* the test hook: NQTESTWB, an http:// server, stands in for the Wayback
 * Machine (archive.org and web.archive.org) */
static const char *hook(const char *u, char *buf, size_t cap) {
  static const char *const wb[] = {"https://archive.org/",
                                   "https://web.archive.org/"};
  const char *t = getenv("NQTESTWB");
  size_t i;
  if (t == NULL || *t == '\0') return u;
  for (i = 0; i < 2; i++) {
    size_t k = strlen(wb[i]);
    if (strncmp(u, wb[i], k) == 0) {
      snprintf(buf, cap, "%s/%s", t, u + k);
      return buf;
    }
  }
  return u;
}
#else
static const char *hook(const char *u, char *buf, size_t cap) {
  (void)buf;
  (void)cap;
  return u;
}
#endif

static int get(const char *u, size_t max, int secs, ncres *r, char *err,
               size_t cap) {
  char hb[4300];
  return ncfetch(hook(u, hb, sizeof hb), max, secs, r, err, cap);
}

/* a field of element i of "sources" in a new buffer, NULL when absent */
static char *fld(const nqdrec *r, size_t i, const char *f) {
  size_t n = 0;
  char *b;
  if (nqdfld(r, "sources", i, f, NULL, 0, &n) != NQEBUF) return NULL;
  if ((b = (char *)malloc(n + 1)) == NULL) return NULL;
  if (nqdfld(r, "sources", i, f, b, n + 1, &n) != NQOK) {
    free(b);
    return NULL;
  }
  return b;
}

/* the index in "sources" of path, or (size_t)-1 */
static size_t srcat(const nqdrec *r, const char *path) {
  size_t i, n = nqdlen(r, "sources");
  for (i = 0; i < n; i++) {
    char *p = fld(r, i, "path");
    int hit = p != NULL && strcmp(p, path) == 0;
    free(p);
    if (hit) return i;
  }
  return (size_t)-1;
}

static int issyn(const nqdrec *r, size_t i) {
  char *s = fld(r, i, "synthetic");
  int y = s != NULL && strcmp(s, "true") == 0;
  free(s);
  return y;
}

/* asks the portal of the resolver rs (JSON) for its file's address,
 * into out; tm (may be NULL) gets a Wayback copy's time */
static int portal(const char *rs, char *out, size_t cap, char tm[21],
                  char *err, size_t ecap) {
  char rq[4200], why[600];
  size_t n = 0;
  ncres re;
  int k = nqdrslv(rs, strlen(rs), rq, sizeof rq, &n, why, sizeof why);
  if (k != NQOK) {
    snprintf(err, ecap, "%s", why[0] ? why : nqerr(k));
    return NCUSE;
  }
  if (get(rq, NCMETA, 0, &re, err, ecap) != NCOK) {
    char e2[400];
    snprintf(e2, sizeof e2, "%s", err);
    snprintf(err, ecap, "%.200s: %s", rq, e2);
    return NCUSE;
  }
  k = nqdrsp(rs, strlen(rs), (const char *)re.b, re.n, out, cap, &n, tm,
             why, sizeof why);
  ncresfree(&re);
  if (k != NQOK) {
    snprintf(err, ecap, "%.200s: %.400s", rq, why[0] ? why : nqerr(k));
    return NCUSE;
  }
  return NCOK;
}

/* the time now, UTC (SOURCE_DATE_EPOCH when set) */
static void now(char out[21]) {
  struct tm tm;
  const char *e = getenv("SOURCE_DATE_EPOCH");
  time_t t = e != NULL && *e ? (time_t)strtoll(e, NULL, 10) : time(NULL);
  out[0] = '\0';
  if (ncgmtime(t, &tm) == NCOK) strftime(out, 21, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* sets field of the source path to the JSON value v (NULL removes it) */
static int setj(const char *cmd, nqdrec *r, const char *path,
                const char *field, const char *v) {
  char why[600];
  int k = nqdset(r, "sources", path, field, v, v != NULL ? strlen(v) : 0,
                 why, sizeof why);
  if (k != NQOK && !(v == NULL && k == NQEIO)) {
    ncmsg(cmd, "%s: %s", field, why[0] ? why : nqerr(k));
    return NCUSE;
  }
  return NCOK;
}

/* sets field of the source path to the string v */
static int sets(const char *cmd, nqdrec *r, const char *path,
                const char *field, const char *v) {
  char *q = ncjq(v);
  int rc;
  if (q == NULL) return nclib(cmd, "memory", NQEMEM);
  rc = setj(cmd, r, path, field, q);
  free(q);
  return rc;
}

/* the fetch's ETag, Last-Modified and time recorded for path */
static int stamp(const char *cmd, nqdrec *r, const char *path,
                 const ncres *re) {
  char t[21];
  int rc = NCOK;
  now(t);
  if (t[0]) rc |= sets(cmd, r, path, "retrieved", t);
  rc |= re->etag[0] ? sets(cmd, r, path, "etag", re->etag)
                    : setj(cmd, r, path, "etag", NULL);
  rc |= re->mod[0] ? sets(cmd, r, path, "modified", re->mod)
                   : setj(cmd, r, path, "modified", NULL);
  return rc;
}

/* "archived": the Wayback Machine's copy of url */
static int wayback(const char *cmd, nqdrec *r, const char *path,
                   const char *url) {
  char *q = ncjq(url), *rs, out[4300], tm[21], err[700], *a, *qa;
  size_t n;
  int rc;
  if (q == NULL) return nclib(cmd, "memory", NQEMEM);
  n = strlen(q) + 40;
  rs = (char *)malloc(n);
  if (rs == NULL) {
    free(q);
    return nclib(cmd, "memory", NQEMEM);
  }
  snprintf(rs, n, "{\"base\":%s,\"kind\":\"wayback\"}", q);
  free(q);
  rc = portal(rs, out, sizeof out, tm, err, sizeof err);
  free(rs);
  if (rc != NCOK) {
    ncmsg(cmd, "%s: no Wayback Machine copy: %s", ncesc(path), err);
    return NCUSE;
  }
  if ((qa = ncjq(out)) == NULL) return nclib(cmd, "memory", NQEMEM);
  n = strlen(qa) + 64;
  if ((a = (char *)malloc(n)) == NULL) {
    free(qa);
    return nclib(cmd, "memory", NQEMEM);
  }
  snprintf(a, n, "{\"time\":\"%s\",\"url\":%s}", tm, qa);
  free(qa);
  rc = setj(cmd, r, path, "archived", a);
  free(a);
  if (rc == NCOK)
    fprintf(stderr, "noqtis %s: %s: archived copy of %s\n", cmd,
            ncesc(path), tm);
  return rc;
}

/* writes n bytes to dir/path, making its folders; replacing a file
 * there only when force */
static int put(const char *cmd, const char *dir, const char *path,
               const uint8_t *b, size_t n, int force) {
  char p[4200];
  size_t i, dl = strlen(dir);
  int k = snprintf(p, sizeof p, "%s/%s", dir, path);
  if (k < 0 || (size_t)k >= sizeof p) {
    ncmsg(cmd, "%s: the path is too long", ncesc(path));
    return NCUSE;
  }
  for (i = dl + 1; p[i] != '\0'; i++) {
    if (p[i] != '/') continue;
    p[i] = '\0';
    if (!ncisdir(p) && ncmkdir(p) != NCOK) {
      ncmsg(cmd, "%s: cannot make the folder", ncesc(p));
      return NCUSE;
    }
    p[i] = '/';
  }
  if (force && ncexist(p) && ncisreg(p) && ncrmfile(p) != 0) {
    ncmsg(cmd, "%s: cannot be replaced", ncesc(p));
    return NCUSE;
  }
  if (ncwr(p, b, n, 0, 0) != NCOK) return ncwfail(cmd, p, 0);
  return NCOK;
}

/* "path" of a capsule: no '..', not absolute, not a noqtis file */
static int pathok(const char *cmd, const char *p) {
  nqdrec *r;
  char why[300];
  int k;
  if (nqdnew(&r) != NQOK) return NCUSE;
  /* the record's own check of a path, through a source of it */
  {
    char *q = ncjq(p), e[4300];
    if (q == NULL) {
      nqdrfree(r);
      return NCUSE;
    }
    snprintf(e, sizeof e, "{\"path\":%s,\"sha256\":\"%064d\",\"size\":0}",
             q, 0);
    free(q);
    k = nqdput(r, "sources", e, strlen(e), why, sizeof why);
  }
  nqdrfree(r);
  if (k != NQOK) {
    ncmsg(cmd, "%s: not a path a capsule holds (relative, '/' between "
          "folders, no '.' or '..', not a noqtis file)", ncesc(p));
    return NCUSE;
  }
  return NCOK;
}

/* noqtis src add */
static int sadd(int argc, char **argv) {
  const char *url = NULL, *kind = NULL, *base = NULL, *id = NULL,
             *res = NULL, *fmt = NULL, *lay = NULL, *arc = NULL, *mx = NULL,
             *to = NULL;
  const char *mir[NCMAXV];
  int np, help, wb = 0, nmir = 0, syn = 0, rc, k, i;
  char path[4200], why[600], rs[9000], addr[4300], err[700];
  nqdrec *r = NULL;
  ncsopt so;
  ncres re;
  int fetched = 0;
  ncopt o[] = {{'u', "url", 1, &url, NULL},
               {0, "portal", 1, &kind, NULL},
               {0, "base", 1, &base, NULL},
               {0, "id", 1, &id, NULL},
               {0, "resource", 1, &res, NULL},
               {0, "format", 1, &fmt, NULL},
               {0, "layer", 1, &lay, NULL},
               {0, "mirror", NCMANY, mir, &nmir},
               {0, "archived", 1, &arc, NULL},
               {0, "wayback", 0, NULL, &wb},
               {0, "synthetic", 0, NULL, &syn},
               {0, "max", 1, &mx, NULL},
               {0, "timeout", 1, &to, NULL}};
  memset(&re, 0, sizeof re);
  if (ncargs("src add", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "src");
    return NCOK;
  }
  if (np != 2) {
    ncmsg("src add", "give the folder and the file's path in it");
    return NCUSE;
  }
  if (sopts("src add", mx, to, &so) != NCOK ||
      pathok("src add", argv[1]) != NCOK)
    return NCUSE;
  if (syn && (url != NULL || kind != NULL || wb || nmir > 0 || arc)) {
    ncmsg("src add", "--synthetic marks a generated stand-in: it has no "
          "address (see `noqtis data syn`)");
    return NCUSE;
  }
  if (kind == NULL && (base != NULL || id != NULL || res != NULL ||
                       fmt != NULL || lay != NULL)) {
    ncmsg("src add", "--base, --id, --resource, --format and --layer "
          "describe a portal: give --portal too");
    return NCUSE;
  }
  rs[0] = '\0';
  if (kind != NULL) {
    /* the resolver, as JSON, members in order */
    static const char *const ks[] = {"ckan", "socrata", "arcgis"};
    const char *nm[] = {"base", "format", "id"};
    const char *vs[3];
    size_t j, l;
    char *q;
    for (j = 0; j < 3 && strcmp(kind, ks[j]) != 0; j++) {
    }
    if (j == 3) {
      ncmsg("src add", "--portal %s: ckan, socrata or arcgis", kind);
      return NCUSE;
    }
    vs[0] = base;
    vs[1] = fmt;
    vs[2] = id;
    l = (size_t)snprintf(rs, sizeof rs, "{");
    for (j = 0; j < 3; j++) {
      if (vs[j] == NULL) continue;
      if ((q = ncjq(vs[j])) == NULL) return nclib("src add", "memory", NQEMEM);
      l += (size_t)snprintf(rs + l, sizeof rs - l, "%s\"%s\":%s",
                            l > 1 ? "," : "", nm[j], q);
      free(q);
      if (l >= sizeof rs) break;
    }
    l += (size_t)snprintf(rs + l, l < sizeof rs ? sizeof rs - l : 0,
                          "%s\"kind\":\"%s\"", l > 1 ? "," : "", kind);
    if (lay != NULL && l < sizeof rs) {
      char *e;
      long v = strtol(lay, &e, 10);
      if (*lay < '0' || *lay > '9' || *e != '\0' || v > 1000000) {
        ncmsg("src add", "--layer %s: a layer number", lay);
        return NCUSE;
      }
      l += (size_t)snprintf(rs + l, sizeof rs - l, ",\"layer\":%ld", v);
    }
    if (res != NULL && l < sizeof rs) {
      if ((q = ncjq(res)) == NULL) return nclib("src add", "memory", NQEMEM);
      l += (size_t)snprintf(rs + l, sizeof rs - l, ",\"resource\":%s", q);
      free(q);
    }
    if (l + 2 > sizeof rs) {
      ncmsg("src add", "the portal's options are too long");
      return NCUSE;
    }
    memcpy(rs + l, "}", 2);
    k = nqdrslv(rs, strlen(rs), NULL, 0, NULL, why, sizeof why);
    if (k != NQEBUF) {
      ncmsg("src add", "--portal %s: %s", kind, why[0] ? why : nqerr(k));
      return NCUSE;
    }
  }
  if (url == NULL && kind == NULL && !syn) {
    ncmsg("src add", "give --url, or --portal with the dataset");
    return NCUSE;
  }
  if (url != NULL && ncurlok(url, err, sizeof err) != NCOK) {
    ncmsg("src add", "--url %s: %s", ncesc(url), err);
    return NCUSE;
  }
  if ((rc = ncdload("src add", argv[0], 1, &r)) != NCOK) return rc;
  snprintf(path, sizeof path, "%s/%s", argv[0], argv[1]);
  addr[0] = '\0';
  if (url != NULL) snprintf(addr, sizeof addr, "%s", url);
  if (!ncexist(path)) {
    if (syn) {
      ncmsg("src add", "%s: no such file (make it with `noqtis data syn`)",
            ncesc(path));
      nqdrfree(r);
      return NCUSE;
    }
    if (addr[0] == '\0' &&
        portal(rs, addr, sizeof addr, NULL, err, sizeof err) != NCOK) {
      ncmsg("src add", "%s: the portal does not say where the file is: %s",
            kind, err);
      nqdrfree(r);
      return NCUSE;
    }
    if (ncurlok(addr, err, sizeof err) != NCOK) {
      ncmsg("src add", "%s: %s", ncesc(addr), err);
      nqdrfree(r);
      return NCUSE;
    }
    if (get(addr, so.max, so.secs, &re, err, sizeof err) != NCOK) {
      ncmsg("src add", "%s: %s", ncesc(addr), err);
      nqdrfree(r);
      return NCUSE;
    }
    if (put("src add", argv[0], argv[1], re.b, re.n, 0) != NCOK) {
      ncresfree(&re);
      nqdrfree(r);
      return NCUSE;
    }
    fetched = 1;
    fprintf(stderr, "noqtis src add: %s: fetched %lu bytes from %s%s\n",
            ncesc(argv[1]), (unsigned long)re.n, ncesc(re.url),
            re.resumed ? " (resumed)" : "");
  } else if (url == NULL && kind != NULL) {
    /* the file is there: the portal's address is recorded too */
    if (portal(rs, addr, sizeof addr, NULL, err, sizeof err) != NCOK)
      ncmsg("src add", "note: %s: no address recorded: %s", kind, err);
  }
  k = nqdsrc(r, argv[0], argv[1], why, sizeof why);
  if (k != NQOK) {
    ncmsg("src add", "%s", why[0] ? why : nqerr(k));
    rc = NCUSE;
  }
  if (rc == NCOK && addr[0]) rc |= sets("src add", r, argv[1], "url", addr);
  if (rc == NCOK && rs[0]) rc |= setj("src add", r, argv[1], "resolver", rs);
  if (rc == NCOK && fetched) rc |= stamp("src add", r, argv[1], &re);
  if (rc == NCOK && arc != NULL) {
    char *q = ncjq(arc), *v;
    size_t n;
    if (q == NULL) return nclib("src add", "memory", NQEMEM);
    n = strlen(q) + 16;
    v = (char *)malloc(n);
    if (v == NULL) {
      free(q);
      return nclib("src add", "memory", NQEMEM);
    }
    snprintf(v, n, "{\"url\":%s}", q);
    free(q);
    rc |= setj("src add", r, argv[1], "archived", v);
    free(v);
  }
  if (rc == NCOK && nmir > 0) {
    size_t n = 3;
    char *v;
    for (i = 0; i < nmir; i++) {
      if (ncurlok(mir[i], err, sizeof err) != NCOK) {
        ncmsg("src add", "--mirror %s: %s", ncesc(mir[i]), err);
        rc = NCUSE;
      }
      n += 6 * strlen(mir[i]) + 3;
    }
    if (rc == NCOK && (v = (char *)malloc(n)) != NULL) {
      size_t l = 1;
      v[0] = '[';
      for (i = 0; i < nmir; i++) {
        char *q = ncjq(mir[i]);
        if (q == NULL) break;
        l += (size_t)snprintf(v + l, n - l, "%s%s", i ? "," : "", q);
        free(q);
      }
      snprintf(v + l, n - l, "]");
      rc |= setj("src add", r, argv[1], "mirrors", v);
      free(v);
    }
  }
  if (rc == NCOK && syn) rc |= setj("src add", r, argv[1], "synthetic", "true");
  if (rc == NCOK && wb) {
    const char *u = addr[0] ? addr : NULL;
    if (u == NULL) {
      ncmsg("src add", "--wayback: the source has no address to look up");
      rc = NCUSE;
    } else {
      rc |= wayback("src add", r, argv[1], u);
    }
  }
  ncresfree(&re);
  if (rc == NCOK) rc = ncdsave("src add", argv[0], r);
  nqdrfree(r);
  return rc;
}

/* the paths to act on: those named (each must be a source), else all */
static int pick(const char *cmd, const nqdrec *r, int np, char **argv,
                size_t **out, size_t *n) {
  size_t i, c = nqdlen(r, "sources");
  *n = 0;
  *out = (size_t *)calloc(c + 1, sizeof **out);
  if (*out == NULL) return nclib(cmd, "memory", NQEMEM);
  if (np <= 1) {
    for (i = 0; i < c; i++) (*out)[(*n)++] = i;
    return NCOK;
  }
  for (i = 1; i < (size_t)np; i++) {
    size_t at = srcat(r, argv[i]);
    if (at == (size_t)-1) {
      ncmsg(cmd, "%s is not a source of %s (add it with `noqtis src add`)",
            ncesc(argv[i]), argv[0]);
      free(*out);
      *out = NULL;
      return NCUSE;
    }
    if (*n < c) (*out)[(*n)++] = at;
  }
  return NCOK;
}

/* one line of a report: text, or a JSON object */
static void row(int json, int *first, const char *path, const char *st,
                int syn, const char *from, const char *url,
                const char *detail) {
  if (json) {
    fputs(*first ? "{\"path\":" : ",{\"path\":", stdout);
    ncjstr(path);
    fputs(",\"status\":", stdout);
    ncjstr(st);
    if (syn) fputs(",\"synthetic\":true", stdout);
    if (from != NULL) {
      fputs(",\"from\":", stdout);
      ncjstr(from);
    }
    if (url != NULL) {
      fputs(",\"url\":", stdout);
      ncjstr(url);
    }
    if (detail != NULL) {
      fputs(",\"detail\":", stdout);
      ncjstr(detail);
    }
    putchar('}');
  } else {
    printf("%-11s %s%s", st, ncesc(path), syn ? " [synthetic]" : "");
    if (from != NULL) printf(" from %s", from);
    if (url != NULL) printf(" %s", ncesc(url));
    if (detail != NULL) printf(": %s", ncesc(detail));
    putchar('\n');
  }
  *first = 0;
}

static const char *kname(int k) {
  return k == NQDAURL ? "url" : k == NQDAPORT ? "portal"
                                : k == NQDAMIR ? "mirror" : "archived";
}

/* the file dir/path is the source's recorded bytes */
static int same(const nqdrec *r, const char *dir, const char *path) {
  char p[4200];
  uint8_t *b = NULL;
  size_t n = 0;
  int ok;
  snprintf(p, sizeof p, "%s/%s", dir, path);
  if (!ncisreg(p) || ncrdx(p, 0, (size_t)-1 >> 1, &b, &n) != NQOK) return 0;
  ok = nqdvrfy(r, path, b, n) == NQOK;
  ncfree(b, n, 0);
  return ok;
}

/* noqtis src fetch */
static int sfetch(int argc, char **argv) {
  const char *mx = NULL, *to = NULL;
  int np, help, json = 0, force = 0, rc, first = 1, bad = 0;
  nqdrec *r = NULL;
  size_t *ix = NULL, n = 0, j;
  ncsopt so;
  ncopt o[] = {{'j', "json", 0, NULL, &json},
               {'f', "force", 0, NULL, &force},
               {0, "max", 1, &mx, NULL},
               {0, "timeout", 1, &to, NULL}};
  if (ncargs("src fetch", argc, argv, o, 4, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "src");
    return NCOK;
  }
  if (np < 1) {
    ncmsg("src fetch", "give the folder, and optionally the files");
    return NCUSE;
  }
  if (sopts("src fetch", mx, to, &so) != NCOK) return NCUSE;
  if ((rc = ncdload("src fetch", argv[0], 0, &r)) != NCOK) return rc;
  if ((rc = pick("src fetch", r, np, argv, &ix, &n)) != NCOK) {
    nqdrfree(r);
    return rc;
  }
  if (json) {
    fputs("{\"folder\":", stdout);
    ncjstr(argv[0]);
    fputs(",\"sources\":[", stdout);
  }
  for (j = 0; j < n; j++) {
    char *path = fld(r, ix[j], "path"), *sz = fld(r, ix[j], "size");
    char a[4300], u[4300], err[700], p[4200], last[800];
    size_t i, an = 0, want = sz != NULL ? (size_t)strtoull(sz, NULL, 10) : 0;
    int k = 0, got = 0, syn = issyn(r, ix[j]), there;
    free(sz);
    if (path == NULL) {
      bad = 1;
      continue;
    }
    snprintf(p, sizeof p, "%s/%s", argv[0], path);
    if (same(r, argv[0], path)) {
      row(json, &first, path, "present", syn, NULL, NULL, NULL);
      free(path);
      continue;
    }
    there = ncexist(p);
    if (syn) {
      row(json, &first, path, "missing", 1, NULL, NULL,
          "a synthetic file has no source: make it again with `noqtis data "
          "syn`");
      bad = 1;
      free(path);
      continue;
    }
    if (there && !force) {
      row(json, &first, path, "differs", 0, NULL, NULL,
          "the file there is not the one recorded; --force replaces it with "
          "a copy that is");
      bad = 1;
      free(path);
      continue;
    }
    last[0] = '\0';
    for (i = 0; !got && nqdaddr(r, path, i, &k, a, sizeof a, &an) == NQOK;
         i++) {
      ncres re;
      const char *at = a;
      if (k == NQDAPORT) {
        char *rs = fld(r, ix[j], "resolver");
        int e = rs == NULL ? NCUSE
                           : portal(rs, u, sizeof u, NULL, err, sizeof err);
        free(rs);
        if (e != NCOK) {
          ncmsg("src fetch", "%s: portal: %s", ncesc(path), err);
          snprintf(last, sizeof last, "portal: %s", err);
          continue;
        }
        at = u;
      }
      if (get(at, want, so.secs, &re, err, sizeof err) != NCOK) {
        ncmsg("src fetch", "%s: %s %s: %s", ncesc(path), kname(k),
              ncesc(at), err);
        snprintf(last, sizeof last, "%s: %s", kname(k), err);
        continue;
      }
      if (nqdvrfy(r, path, re.b, re.n) != NQOK) {
        ncmsg("src fetch", "%s: %s %s: not the recorded bytes (SHA-256 or "
              "size differs), refused", ncesc(path), kname(k), ncesc(at));
        snprintf(last, sizeof last, "%s: the bytes differ", kname(k));
        ncresfree(&re);
        continue;
      }
      if (put("src fetch", argv[0], path, re.b, re.n, there) == NCOK) {
        got = 1;
        row(json, &first, path, "fetched", 0, kname(k), re.url, NULL);
      } else {
        bad = 1;
        got = -1;
      }
      ncresfree(&re);
    }
    if (got == 0) {
      row(json, &first, path, "unreachable", 0, NULL, NULL,
          i == 0 ? "the source records no address" : last);
      bad = 1;
    }
    free(path);
  }
  if (json) printf("],\"ok\":%s}\n", bad ? "false" : "true");
  free(ix);
  nqdrfree(r);
  return bad ? NCBAD : NCOK;
}

/* noqtis src refresh */
static int srefresh(int argc, char **argv) {
  const char *mx = NULL, *to = NULL;
  int np, help, json = 0, wr = 0, rc, first = 1, chg = 0, dead = 0;
  int wrote = 0;
  nqdrec *r = NULL;
  size_t *ix = NULL, n = 0, j;
  ncsopt so;
  ncopt o[] = {{'j', "json", 0, NULL, &json},
               {'w', "write", 0, NULL, &wr},
               {0, "max", 1, &mx, NULL},
               {0, "timeout", 1, &to, NULL}};
  if (ncargs("src refresh", argc, argv, o, 4, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "src");
    return NCOK;
  }
  if (np < 1) {
    ncmsg("src refresh", "give the folder, and optionally the files");
    return NCUSE;
  }
  if (sopts("src refresh", mx, to, &so) != NCOK) return NCUSE;
  if ((rc = ncdload("src refresh", argv[0], 0, &r)) != NCOK) return rc;
  if ((rc = pick("src refresh", r, np, argv, &ix, &n)) != NCOK) {
    nqdrfree(r);
    return rc;
  }
  if (json) {
    fputs("{\"folder\":", stdout);
    ncjstr(argv[0]);
    fputs(",\"sources\":[", stdout);
  }
  for (j = 0; j < n && rc == NCOK; j++) {
    char *path = fld(r, ix[j], "path"), *osha = fld(r, ix[j], "sha256"),
         *osz = fld(r, ix[j], "size");
    char a[4300], u[4300], err[700], det[400];
    const char *at = NULL;
    size_t an = 0;
    int k = 0, syn = issyn(r, ix[j]);
    ncres re;
    memset(&re, 0, sizeof re);
    if (path == NULL || osha == NULL || osz == NULL) {
      free(path);
      free(osha);
      free(osz);
      rc = nclib("src refresh", "memory", NQEMEM);
      break;
    }
    if (syn) {
      row(json, &first, path, "synthetic", 1, NULL, NULL,
          "made by `noqtis data syn`, not fetched");
    } else if (nqdaddr(r, path, 0, &k, a, sizeof a, &an) != NQOK ||
               (k != NQDAURL && k != NQDAPORT)) {
      row(json, &first, path, "unreachable", 0, NULL, NULL,
          "the source records no url or portal to fetch it from");
      dead = 1;
    } else {
      at = a;
      if (k == NQDAPORT) {
        char *rs = fld(r, ix[j], "resolver");
        at = rs != NULL && portal(rs, u, sizeof u, NULL, err, sizeof err) ==
                               NCOK
                 ? u
                 : NULL;
        if (rs == NULL) snprintf(err, sizeof err, "out of memory");
        free(rs);
      }
      if (at != NULL &&
          get(at, so.max, so.secs, &re, err, sizeof err) != NCOK)
        at = NULL;
      if (at == NULL) {
        row(json, &first, path, "unreachable", 0, kname(k), NULL, err);
        dead = 1;
      } else if (nqdvrfy(r, path, re.b, re.n) == NQOK) {
        row(json, &first, path, "unchanged", 0, kname(k), re.url, NULL);
      } else {
        uint8_t h[32];
        char hx[65];
        nqhash(NQS256, re.n ? re.b : (const uint8_t *)"", re.n, h, 32);
        nchexe(h, 32, hx);
        hx[64] = '\0';
        snprintf(det, sizeof det, "was %s bytes, SHA-256 %s; now %lu "
                 "bytes, SHA-256 %s", osz, osha, (unsigned long)re.n, hx);
        if (json) {
          fputs(first ? "{\"path\":" : ",{\"path\":", stdout);
          first = 0;
          ncjstr(path);
          printf(",\"status\":\"changed\",\"from\":\"%s\",\"url\":",
                 kname(k));
          ncjstr(re.url);
          printf(",\"old\":{\"sha256\":\"%s\",\"size\":%s},\"new\":{"
                 "\"sha256\":\"%s\",\"size\":%lu}", osha, osz, hx,
                 (unsigned long)re.n);
          fputs(",\"detail\":", stdout);
          ncjstr(det);
          putchar('}');
        } else {
          row(0, &first, path, "changed", 0, kname(k), re.url, det);
        }
        chg = 1;
        if (wr) {
          char why[600];
          int e = put("src refresh", argv[0], path, re.b, re.n, 1);
          if (e == NCOK &&
              (e = nqdsrc(r, argv[0], path, why, sizeof why)) != NQOK) {
            ncmsg("src refresh", "%s", why[0] ? why : nqerr(e));
            e = NCUSE;
          }
          if (e == NCOK) e = stamp("src refresh", r, path, &re);
          if (e == NCOK && k == NQDAPORT)
            e = sets("src refresh", r, path, "url", at);
          /* copies of the old bytes are no longer copies */
          if (e == NCOK) e |= setj("src refresh", r, path, "archived", NULL);
          if (e == NCOK) e |= setj("src refresh", r, path, "mirrors", NULL);
          if (e != NCOK) {
            rc = NCUSE;
          } else {
            wrote = 1;
            ncmsg("src refresh", "%s: wrote the new bytes and recorded "
                  "them; its archived copy and mirrors were of the old "
                  "bytes and are no longer recorded", ncesc(path));
          }
        }
      }
    }
    ncresfree(&re);
    free(path);
    free(osha);
    free(osz);
  }
  if (json && rc == NCOK)
    printf("],\"changed\":%s,\"unreachable\":%s,\"written\":%s}\n",
           chg ? "true" : "false", dead ? "true" : "false",
           wrote ? "true" : "false");
  if (wrote && rc == NCOK) rc = ncdsave("src refresh", argv[0], r);
  free(ix);
  nqdrfree(r);
  if (rc != NCOK) return rc;
  if (chg && !wr && !json)
    ncmsg("src refresh", "a source changed: --write records the new bytes "
          "in the capsule (then seal it again)");
  return chg ? NCBAD : dead ? NCWARN : NCOK;
}

/* noqtis src resolve */
static int sresolve(int argc, char **argv) {
  int np, help, json = 0, wr = 0, rc, first = 1, bad = 0, chg = 0, wb = 0;
  nqdrec *r = NULL;
  size_t *ix = NULL, n = 0, j;
  ncopt o[] = {{'j', "json", 0, NULL, &json},
               {'w', "write", 0, NULL, &wr},
               {0, "wayback", 0, NULL, &wb}};
  if (ncargs("src resolve", argc, argv, o, 3, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "src");
    return NCOK;
  }
  if (np < 1) {
    ncmsg("src resolve", "give the folder, and optionally the files");
    return NCUSE;
  }
  if ((rc = ncdload("src resolve", argv[0], 0, &r)) != NCOK) return rc;
  if ((rc = pick("src resolve", r, np, argv, &ix, &n)) != NCOK) {
    nqdrfree(r);
    return rc;
  }
  if (json) {
    fputs("{\"folder\":", stdout);
    ncjstr(argv[0]);
    fputs(",\"sources\":[", stdout);
  }
  for (j = 0; j < n; j++) {
    char *path = fld(r, ix[j], "path"), *rs = fld(r, ix[j], "resolver"),
         *url = fld(r, ix[j], "url");
    char u[4300], err[700];
    if (path == NULL) {
      bad = 1;
    } else if (wb) {
      if (url == NULL) {
        row(json, &first, path, "unresolved", issyn(r, ix[j]), NULL, NULL,
            "the source has no url to look up");
        bad = 1;
      } else if (wayback("src resolve", r, path, url) != NCOK) {
        row(json, &first, path, "unresolved", 0, "wayback", NULL,
            "no copy (see above)");
        bad = 1;
      } else {
        char *a = fld(r, ix[j], "archived");
        row(json, &first, path, "archived", 0, "wayback", NULL, a);
        free(a);
        chg = 1;
      }
    } else if (rs == NULL || strstr(rs, "\"kind\":\"direct\"") != NULL) {
      row(json, &first, path, "direct", issyn(r, ix[j]), NULL, url,
          NULL);
    } else if (portal(rs, u, sizeof u, NULL, err, sizeof err) != NCOK) {
      row(json, &first, path, "unresolved", 0, "portal", NULL, err);
      bad = 1;
    } else {
      int moved = url == NULL || strcmp(url, u) != 0;
      row(json, &first, path, moved ? "moved" : "same", 0, "portal", u,
          moved && url != NULL ? url : NULL);
      if (moved && wr && sets("src resolve", r, path, "url", u) == NCOK) {
        chg = 1;
        ncmsg("src resolve", "%s: url recorded: %s", ncesc(path), ncesc(u));
      }
    }
    free(path);
    free(rs);
    free(url);
  }
  if (json) printf("],\"ok\":%s}\n", bad ? "false" : "true");
  if (chg && (wr || wb)) rc = ncdsave("src resolve", argv[0], r);
  free(ix);
  nqdrfree(r);
  if (rc != NCOK) return rc;
  return bad ? NCBAD : NCOK;
}

/* noqtis src list */
static int slist(int argc, char **argv) {
  int np, help, json = 0, rc;
  nqdrec *r = NULL;
  size_t i, c;
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  if (ncargs("src list", argc, argv, o, 1, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "src");
    return NCOK;
  }
  if (np != 1) {
    ncmsg("src list", "give one folder");
    return NCUSE;
  }
  if ((rc = ncdload("src list", argv[0], 0, &r)) != NCOK) return rc;
  c = nqdlen(r, "sources");
  if (json) {
    fputs("{\"folder\":", stdout);
    ncjstr(argv[0]);
    fputs(",\"sources\":[", stdout);
  }
  for (i = 0; i < c; i++) {
    size_t n = 0, k;
    char *e = NULL;
    if (json) {
      if (nqdat(r, "sources", i, NULL, 0, &n) == NQEBUF &&
          (e = (char *)malloc(n + 1)) != NULL &&
          nqdat(r, "sources", i, e, n + 1, &n) == NQOK)
        printf("%s%s", i ? "," : "", e);
      free(e);
      continue;
    } else {
      char *p = fld(r, i, "path"), *sz = fld(r, i, "size"),
           *sh = fld(r, i, "sha256");
      char a[4300];
      int kd;
      printf("%s  %s bytes  sha256 %.16s%s\n", p ? ncesc(p) : "?",
             sz ? sz : "?", sh ? sh : "?",
             issyn(r, i) ? "  [synthetic]" : "");
      for (k = 0; p != NULL &&
                  nqdaddr(r, p, k, &kd, a, sizeof a, &n) == NQOK;
           k++)
        printf("  %d. %-8s %s\n", (int)k + 1, kname(kd), ncesc(a));
      free(p);
      free(sz);
      free(sh);
    }
  }
  if (json) fputs("]}\n", stdout);
  nqdrfree(r);
  return NCOK;
}

int ncsrc(int argc, char **argv) {
  static const struct {
    const char *n;
    int (*f)(int, char **);
  } t[] = {{"add", sadd},         {"resolve", sresolve}, {"fetch", sfetch},
           {"refresh", srefresh}, {"list", slist}};
  size_t i;
  if (argc >= 2) {
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
      if (strcmp(argv[1], t[i].n) == 0) return t[i].f(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
      ncuse(stdout, "src");
      return NCOK;
    }
    ncmsg("src", "unknown action %s (add, resolve, fetch, refresh, list)",
          argv[1]);
    return NCUSE;
  }
  ncuse(stderr, "src");
  return NCUSE;
}
