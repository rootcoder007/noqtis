/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis export: a checked capsule in other formats. intoto, an in-toto
 * Statement v1 whose subjects are the capsule's files; dsse, that
 * statement in a DSSE envelope signed with -k; rocrate, RO-Crate 1.1
 * metadata; bagit, a BagIt 1.0 bag (RFC 8493) with a copy of the files,
 * each checked against the manifest as it is copied. And noqtis verify
 * --dsse, the check of a DSSE envelope. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- a growing text buffer ---- */

typedef struct {
  char *p;
  size_t n, cap;
  int bad;
} tbuf;

static void tput(tbuf *b, const char *s, size_t n) {
  if (b->bad) return;
  if (b->n + n + 1 > b->cap) {
    size_t nc = b->cap == 0 ? 4096 : b->cap;
    char *q;
    while (nc < b->n + n + 1) nc *= 2;
    q = (char *)realloc(b->p, nc);
    if (q == NULL) {
      b->bad = 1;
      return;
    }
    b->p = q;
    b->cap = nc;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = 0;
}

static void tstr(tbuf *b, const char *s) {
  tput(b, s, strlen(s));
}

/* s as a JSON string, quotes included */
static void tjstr(tbuf *b, const char *s) {
  static const char hx[] = "0123456789abcdef";
  tput(b, "\"", 1);
  for (; *s != '\0'; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      char e[2];
      e[0] = '\\';
      e[1] = (char)c;
      tput(b, e, 2);
    } else if (c < 0x20) {
      char e[6];
      e[0] = '\\';
      e[1] = 'u';
      e[2] = '0';
      e[3] = '0';
      e[4] = hx[c >> 4];
      e[5] = hx[c & 15];
      tput(b, e, 6);
    } else {
      tput(b, (const char *)&c, 1);
    }
  }
  tput(b, "\"", 1);
}

/* rel percent-encoded as a URI path (RO-Crate @id) */
static void turi(tbuf *b, const char *rel) {
  static const char hx[] = "0123456789ABCDEF";
  for (; *rel != '\0'; rel++) {
    unsigned char c = (unsigned char)*rel;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
        c == '~' || c == '/') {
      tput(b, (const char *)&c, 1);
    } else {
      char e[3];
      e[0] = '%';
      e[1] = hx[c >> 4];
      e[2] = hx[c & 15];
      tput(b, e, 3);
    }
  }
}

/* ---- what the capsule says ---- */

typedef struct {
  char id[65], fmt[40], alg[40], key[65], created[40];
  char *meta;     /* canonical JSON, or NULL */
  nqrep *files;   /* nqfiles' report */
  unsigned long long bytes;
  size_t nfiles;
} cinfo;

static const char *row(const nqrep *r, const char *name) {
  size_t i, n = nqrepn(r);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(r, i, &c, &ok, &d) == NQOK && strcmp(c, name) == 0)
      return d;
  }
  return NULL;
}

static void cpy(char *o, size_t cap, const char *s) {
  size_t n = s != NULL ? strlen(s) : 0;
  if (n >= cap) n = cap - 1;
  if (n > 0) memcpy(o, s, n);
  o[n] = 0;
}

/* checks dir (the key in its seal), then reads what export needs */
static int cread(const char *dir, cinfo *ci) {
  nqrep *r = NULL;
  uint8_t id[32];
  size_t i, n;
  int rc = nqchk(dir, NULL, 0, &r);
  memset(ci, 0, sizeof *ci);
  nqrepfree(r);
  if (rc != NQOK) {
    ncmsg("export", "%s does not check: run `noqtis check %s` and fix it "
          "first", ncesc(dir), ncesc(dir));
    return rc == NQEVRFY ? NCBAD : NCUSE;
  }
  if (nqcapid(dir, id) != NQOK || nqfiles(dir, &ci->files) != NQOK)
    return nclib("export", dir, NQEIO);
  nchexe(id, 32, ci->id);
  ci->id[64] = 0;
  cpy(ci->fmt, sizeof ci->fmt, row(ci->files, "info.format"));
  cpy(ci->alg, sizeof ci->alg, row(ci->files, "info.alg"));
  cpy(ci->key, sizeof ci->key, row(ci->files, "info.key"));
  cpy(ci->created, sizeof ci->created, row(ci->files, "info.created"));
  if (row(ci->files, "info.meta") != NULL) {
    const char *m = row(ci->files, "info.meta");
    ci->meta = (char *)malloc(strlen(m) + 1);
    if (ci->meta == NULL) return nclib("export", "memory", NQEMEM);
    strcpy(ci->meta, m);
  }
  n = nqrepn(ci->files);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(ci->files, i, &c, &ok, &d) == NQOK &&
        strcmp(c, "info.file") == 0) {
      ci->nfiles++;
      ci->bytes += strtoull(d, NULL, 10);
    }
  }
  return NCOK;
}

static void cdone(cinfo *ci) {
  nqrepfree(ci->files);
  free(ci->meta);
}

/* the i-th file: size, hex SHA-256, path; 0 at the end */
static int file(const cinfo *ci, size_t *at, unsigned long long *sz,
                char hx[65], const char **path) {
  size_t n = nqrepn(ci->files);
  while (*at < n) {
    const char *c = NULL, *d = NULL, *sp;
    int ok = 0;
    size_t i = (*at)++;
    if (nqrepi(ci->files, i, &c, &ok, &d) != NQOK ||
        strcmp(c, "info.file") != 0)
      continue;
    sp = strchr(d, ' ');
    if (sp == NULL || strlen(sp) < 67 || sp[65] != ' ') continue;
    *sz = strtoull(d, NULL, 10);
    memcpy(hx, sp + 1, 64);
    hx[64] = 0;
    *path = sp + 66;
    return 1;
  }
  return 0;
}

/* ---- in-toto, DSSE, RO-Crate ---- */

#define NCPT "https://rootcoder007.github.io/noqtis/spec/capsule/"

static void statement(tbuf *b, const cinfo *ci) {
  size_t at = 0;
  unsigned long long sz;
  char hx[65];
  const char *p;
  int first = 1;
  tstr(b, "{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicate\":"
        "{\"alg\":");
  tjstr(b, ci->alg);
  tstr(b, ",\"capsule\":");
  tjstr(b, ci->id);
  tstr(b, ",\"created\":");
  tjstr(b, ci->created);
  tstr(b, ",\"format\":");
  tjstr(b, ci->fmt);
  tstr(b, ",\"key\":");
  tjstr(b, ci->key);
  if (ci->meta != NULL) {
    tstr(b, ",\"meta\":");
    tstr(b, ci->meta);
  }
  tstr(b, "},\"predicateType\":\"" NCPT "\",\"subject\":[");
  while (file(ci, &at, &sz, hx, &p)) {
    tstr(b, first ? "{\"digest\":{\"sha256\":\"" : ",{\"digest\":"
          "{\"sha256\":\"");
    tstr(b, hx);
    tstr(b, "\"},\"name\":");
    tjstr(b, p);
    tstr(b, "}");
    first = 0;
  }
  tstr(b, "]}");
}

static void rocrate(tbuf *b, const cinfo *ci, const char *dir) {
  size_t at = 0;
  unsigned long long sz;
  char hx[65], num[24];
  const char *p, *nm = strrchr(dir, '/');
  int first = 1;
  nm = nm != NULL && nm[1] != '\0' ? nm + 1 : dir;
  tstr(b, "{\"@context\":[\"https://w3id.org/ro/crate/1.1/context\","
        "{\"sha256\":\"https://w3id.org/ro/terms/workflow-run#sha256\"}],"
        "\"@graph\":[{\"@id\":\"ro-crate-metadata.json\",\"@type\":"
        "\"CreativeWork\",\"about\":{\"@id\":\"./\"},\"conformsTo\":"
        "{\"@id\":\"https://w3id.org/ro/crate/1.1\"}},{\"@id\":\"./\","
        "\"@type\":\"Dataset\",\"name\":");
  tjstr(b, nm);
  tstr(b, ",\"datePublished\":");
  tjstr(b, ci->created);
  tstr(b, ",\"identifier\":\"noqtis-capsule:");
  tstr(b, ci->id);
  tstr(b, "\",\"hasPart\":[");
  while (file(ci, &at, &sz, hx, &p)) {
    tstr(b, first ? "{\"@id\":\"" : ",{\"@id\":\"");
    turi(b, p);
    tstr(b, "\"}");
    first = 0;
  }
  tstr(b, first ? "{\"@id\":\"noqtis.json\"},{\"@id\":\"noqtis.sig\"}]}"
                 : ",{\"@id\":\"noqtis.json\"},{\"@id\":\"noqtis.sig\"}]}");
  at = 0;
  while (file(ci, &at, &sz, hx, &p)) {
    tstr(b, ",{\"@id\":\"");
    turi(b, p);
    tstr(b, "\",\"@type\":\"File\",\"contentSize\":\"");
    snprintf(num, sizeof num, "%llu", sz);
    tstr(b, num);
    tstr(b, "\",\"sha256\":\"");
    tstr(b, hx);
    tstr(b, "\"}");
  }
  tstr(b, ",{\"@id\":\"noqtis.json\",\"@type\":\"File\",\"name\":"
        "\"noqtis manifest\",\"encodingFormat\":\"application/json\"},"
        "{\"@id\":\"noqtis.sig\",\"@type\":\"File\",\"name\":\"noqtis "
        "seal\",\"encodingFormat\":\"application/json\",\"description\":"
        "\"The signature over the manifest; check the folder with noqtis "
        "check\"}]}");
}

/* ---- BagIt ---- */

/* a path in a BagIt manifest: %, CR and LF percent-encoded */
static void bpath(tbuf *b, const char *p) {
  for (; *p != '\0'; p++) {
    if (*p == '%')
      tstr(b, "%25");
    else if (*p == '\r')
      tstr(b, "%0D");
    else if (*p == '\n')
      tstr(b, "%0A");
    else
      tput(b, p, 1);
  }
}

/* writes len bytes to bag/rel, making folders; NCOK or NCUSE */
static int bwrite(const char *bag, const char *rel, const char *s, size_t n) {
  tbuf p;
  size_t i, at;
  int rc;
  memset(&p, 0, sizeof p);
  tstr(&p, bag);
  tstr(&p, "/");
  at = p.n;
  tstr(&p, rel);
  if (p.bad) return NCUSE;
  for (i = at; i < p.n; i++) {
    if (p.p[i] != '/') continue;
    p.p[i] = 0;
    if (!ncisdir(p.p) && ncmkdir(p.p) != NCOK) {
      free(p.p);
      return NCUSE;
    }
    p.p[i] = '/';
  }
  rc = ncwr(p.p, (const uint8_t *)s, n, 0, 0);
  free(p.p);
  return rc;
}

/* copies dir/rel to bag/data/rel, checking its SHA-256 as it goes */
static int bcp(const char *dir, const char *bag, const char *rel,
                 const char hx[65], uint8_t *buf, size_t cap) {
  tbuf s, d;
  FILE *in = NULL, *out = NULL;
  nqhctx h;
  uint8_t md[32];
  char got[65];
  size_t k, i, at;
  int ok = 1;
  memset(&s, 0, sizeof s);
  memset(&d, 0, sizeof d);
  tstr(&s, dir);
  tstr(&s, "/");
  tstr(&s, rel);
  tstr(&d, bag);
  tstr(&d, "/data/");
  at = d.n;
  tstr(&d, rel);
  if (s.bad || d.bad) ok = 0;
  for (i = at; ok && i < d.n; i++) {
    if (d.p[i] != '/') continue;
    d.p[i] = 0;
    if (!ncisdir(d.p) && ncmkdir(d.p) != NCOK) ok = 0;
    d.p[i] = '/';
  }
  if (ok) in = ncfopen(s.p, "rb");
  if (in != NULL) out = ncopen(d.p, 0, 0);
  if (in == NULL || out == NULL || nqhini(&h, NQS256) != NQOK) ok = 0;
  while (ok && (k = fread(buf, 1, cap, in)) > 0) {
    if (nqhupd(&h, buf, k) != NQOK || fwrite(buf, 1, k, out) != k) ok = 0;
  }
  if (ok && ferror(in)) ok = 0;
  if (ok && nqhfin(&h, md, 32) != NQOK) ok = 0;
  if (ok) {
    nchexe(md, 32, got);
    got[64] = 0;
    if (strcmp(got, hx) != 0) {
      ncmsg("export", "%s changed while it was copied: export again",
            ncesc(rel));
      ok = 0;
    }
  }
  if (in != NULL) fclose(in);
  if (out != NULL && ncclose(out, d.p, !ok) != 0) ok = 0;
  if (!ok && out == NULL && d.p != NULL)
    ncmsg("export", "%s: cannot be copied into the bag", ncesc(rel));
  free(s.p);
  free(d.p);
  return ok ? NCOK : NCUSE;
}

static int bagit(const char *dir, const char *bag, const cinfo *ci) {
  static const char bt[] = "BagIt-Version: 1.0\n"
                           "Tag-File-Character-Encoding: UTF-8\n";
  tbuf man, info, tag;
  uint8_t *buf;
  size_t at = 0, i;
  unsigned long long sz;
  char hx[65], line[160], day[40];
  const char *p, *tags[5] = {"bagit.txt", "bag-info.txt",
                             "manifest-sha256.txt", "noqtis.json",
                             "noqtis.sig"};
  time_t now = time(NULL);
  struct tm *g = gmtime(&now);
  int rc = NCUSE;
  if (ncexist(bag)) {
    ncmsg("export", "%s exists: a bag goes into a new folder", ncesc(bag));
    return NCUSE;
  }
  if (ncmkdir(bag) != NCOK) {
    ncmsg("export", "%s: cannot make the folder", ncesc(bag));
    return NCUSE;
  }
  {
    tbuf d;
    int ok;
    memset(&d, 0, sizeof d);
    tstr(&d, bag);
    tstr(&d, "/data");
    ok = !d.bad && ncmkdir(d.p) == NCOK;
    free(d.p);
    if (!ok) {
      ncmsg("export", "%s: cannot make its data folder", ncesc(bag));
      return NCUSE;
    }
  }
  memset(&man, 0, sizeof man);
  memset(&info, 0, sizeof info);
  memset(&tag, 0, sizeof tag);
  buf = (uint8_t *)malloc(1 << 16);
  if (buf == NULL) return nclib("export", "memory", NQEMEM);
  while (file(ci, &at, &sz, hx, &p)) {
    if (bcp(dir, bag, p, hx, buf, 1 << 16) != NCOK) goto out;
    tstr(&man, hx);
    tstr(&man, "  data/");
    bpath(&man, p);
    tstr(&man, "\n");
  }
  if (g != NULL)
    snprintf(day, sizeof day, "%04d-%02d-%02d", g->tm_year + 1900,
             g->tm_mon + 1, g->tm_mday);
  else
    memcpy(day, "1970-01-01", 11);
  snprintf(line, sizeof line, "Bagging-Date: %s\nPayload-Oxum: %llu.%lu\n",
           day, ci->bytes, (unsigned long)ci->nfiles);
  tstr(&info, line);
  tstr(&info, "External-Identifier: noqtis-capsule:");
  tstr(&info, ci->id);
  tstr(&info, "\nExternal-Description: a noqtis capsule; noqtis.json and "
        "noqtis.sig are its manifest and seal\n");
  if (man.bad || info.bad) goto out;
  if (bwrite(bag, "bagit.txt", bt, sizeof bt - 1) != NCOK ||
      bwrite(bag, "bag-info.txt", info.p, info.n) != NCOK ||
      bwrite(bag, "manifest-sha256.txt", man.p != NULL ? man.p : "",
             man.n) != NCOK) {
    goto out;
  }
  /* the seal and the manifest as tag files, so the bag still checks */
  for (i = 3; i < 5; i++) {
    tbuf s;
    uint8_t *b = NULL;
    size_t n = 0;
    memset(&s, 0, sizeof s);
    tstr(&s, dir);
    tstr(&s, "/");
    tstr(&s, tags[i]);
    if (s.bad || ncrdx(s.p, 0, (size_t)512 << 20, &b, &n) != NCOK ||
        bwrite(bag, tags[i], (const char *)b, n) != NCOK) {
      free(s.p);
      ncfree(b, n, 0);
      goto out;
    }
    free(s.p);
    ncfree(b, n, 0);
  }
  for (i = 0; i < 5; i++) {
    tbuf s;
    uint8_t *b = NULL, md[32];
    size_t n = 0;
    memset(&s, 0, sizeof s);
    tstr(&s, bag);
    tstr(&s, "/");
    tstr(&s, tags[i]);
    if (s.bad || ncrdx(s.p, 0, (size_t)512 << 20, &b, &n) != NCOK ||
        nqhash(NQS256, b, n, md, 32) != NQOK) {
      free(s.p);
      ncfree(b, n, 0);
      goto out;
    }
    nchexe(md, 32, hx);
    hx[64] = 0;
    tstr(&tag, hx);
    tstr(&tag, "  ");
    tstr(&tag, tags[i]);
    tstr(&tag, "\n");
    free(s.p);
    ncfree(b, n, 0);
  }
  if (tag.bad ||
      bwrite(bag, "tagmanifest-sha256.txt", tag.p, tag.n) != NCOK) {
    goto out;
  }
  printf("bagged %s into %s: %lu files, %llu bytes\n", ncesc(dir), ncesc(bag),
         (unsigned long)ci->nfiles, ci->bytes);
  rc = NCOK;
out:
  if (rc != NCOK)
    ncmsg("export", "%s: the bag is incomplete; remove it and export again",
          ncesc(bag));
  free(buf);
  free(man.p);
  free(info.p);
  free(tag.p);
  return rc;
}

/* ---- the commands ---- */

static int emit(const char *out, int force, const char *b, size_t n) {
  if (out == NULL || strcmp(out, "-") == 0) {
    ncbin();
    return fwrite(b, 1, n, stdout) == n && fflush(stdout) == 0 ? NCOK : NCUSE;
  }
  if (ncwr(out, (const uint8_t *)b, n, force, 0) != NCOK)
    return ncwfail("export", out, force);
  return NCOK;
}

int ncexp(int argc, char **argv) {
  const char *as = NULL, *kp = NULL, *pp = NULL, *out = NULL;
  int help = 0, force = 0, np, rc;
  ncopt o[] = {
    {'\0', "as", 1, &as, NULL},
    {'k', "key", 1, &kp, NULL},
    {'p', "pub", 1, &pp, NULL},
    {'o', "out", 1, &out, NULL},
    {'f', "force", 0, NULL, &force}
  };
  cinfo ci;
  tbuf b;
  if (ncargs("export", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "export");
    return NCOK;
  }
  if (as == NULL || np != 1) {
    ncuse(stderr, "export");
    return NCUSE;
  }
  if (strcmp(as, "intoto") != 0 && strcmp(as, "dsse") != 0 &&
      strcmp(as, "rocrate") != 0 && strcmp(as, "bagit") != 0) {
    ncmsg("export", "--as %s: give intoto, dsse, rocrate or bagit", as);
    return NCUSE;
  }
  if ((strcmp(as, "dsse") == 0) != (kp != NULL)) {
    ncmsg("export", kp == NULL ? "--as dsse signs: give the key with -k"
                               : "-k signs a DSSE envelope: give --as dsse");
    return NCUSE;
  }
  if (strcmp(as, "bagit") == 0 && out == NULL) {
    ncmsg("export", "--as bagit: give the new bag folder with -o");
    return NCUSE;
  }
  if (!ncisdir(argv[0])) {
    ncmsg("export", "%s: not a folder (give the folder that holds "
          "noqtis.json and noqtis.sig)", argv[0]);
    return NCUSE;
  }
  rc = cread(argv[0], &ci);
  if (rc != NCOK) {
    cdone(&ci);
    return rc;
  }
  if (strcmp(as, "bagit") == 0) {
    rc = bagit(argv[0], out, &ci);
    cdone(&ci);
    return rc;
  }
  memset(&b, 0, sizeof b);
  if (strcmp(as, "rocrate") == 0)
    rocrate(&b, &ci, argv[0]);
  else
    statement(&b, &ci);
  cdone(&ci);
  if (b.bad) {
    free(b.p);
    return nclib("export", "memory", NQEMEM);
  }
  if (strcmp(as, "dsse") == 0) {
    nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
    char *dp = NULL, *e = NULL;
    size_t en = 0;
    rc = NCUSE;
    if (pp == NULL) {
      dp = (char *)malloc(strlen(kp) + 5);
      if (dp != NULL) {
        strcpy(dp, kp);
        strcat(dp, ".pub");
      }
      pp = dp;
    }
    if (pp != NULL && nckrd("export", pp, 0, &pk) == NCOK &&
        nckrd("export", kp, 1, &sk) == NCOK) {
      if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg) {
        ncmsg("export", "%s and %s are not a signature key pair", kp, pp);
      } else {
        int r2 = nqdsse((nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n,
                        "application/vnd.in-toto+json",
                        (const uint8_t *)b.p, b.n, NULL, 0, &en);
        if (r2 == NQEBUF && (e = (char *)malloc(en)) != NULL)
          r2 = nqdsse((nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n,
                      "application/vnd.in-toto+json", (const uint8_t *)b.p,
                      b.n, e, en, &en);
        if (r2 == NQOK)
          rc = emit(out, force, e, en);
        else
          nclib("export", kp, r2 == NQEARG ? NQEDEC : r2);
      }
    }
    nckfree(&sk);
    nckfree(&pk);
    free(dp);
    free(e);
    free(b.p);
    return rc;
  }
  rc = emit(out, force, b.p, b.n);
  free(b.p);
  return rc;
}

/* noqtis verify --dsse: the envelope env under the key file kp */
int ncvdsse(const char *kp, const char *env, const char *out, int quiet) {
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  uint8_t *e = NULL, *pl = NULL;
  size_t en = 0, pn = 0;
  char ty[256];
  int rc, ret = NCUSE;
  if (nckrd("verify", kp, 0, &k) != NCOK) return NCUSE;
  if (k.a.kem) {
    ncmsg("verify", "%s is a %s (KEM) key, not a signature key", kp,
          k.a.name);
    nckfree(&k);
    return NCUSE;
  }
  if (ncrdx(env, 0, NCRDMAX, &e, &en) != NCOK) {
    ncmsg("verify", "cannot read %s", env);
    nckfree(&k);
    return NCUSE;
  }
  rc = nqdssevrfy((nqsalg)k.a.alg, k.b, k.n, (const char *)e, en, NULL, 0,
                  &pn, ty);
  if (rc == NQEBUF) {
    pl = (uint8_t *)malloc(pn + 1);
    if (pl != NULL)
      rc = nqdssevrfy((nqsalg)k.a.alg, k.b, k.n, (const char *)e, en, pl,
                      pn + 1, &pn, ty);
  }
  if (rc == NQOK) {
    ret = NCOK;
    if (!quiet)
      printf("%s: OK (%s), payloadType %s\n", ncesc(env), k.a.name,
             ncesc(ty));
    if (out != NULL && ncwr(out, pl, pn, 0, 0) != NCOK)
      ret = ncwfail("verify", out, 0);
  } else if (rc == NQEVRFY) {
    ret = NCBAD;
    if (!quiet)
      printf("%s: FAILED (no signature verifies under %s)\n", ncesc(env),
             ncesc(kp));
  } else if (rc == NQEDEC) {
    ret = NCBAD;
    if (!quiet) printf("%s: FAILED (not a DSSE envelope)\n", ncesc(env));
  } else {
    nclib("verify", env, rc);
  }
  free(pl);
  ncfree(e, en, 0);
  nckfree(&k);
  return ret;
}
