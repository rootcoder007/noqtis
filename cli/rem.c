/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: `check <url>`, a capsule served over HTTP or HTTPS. The seal
 * and the manifest are fetched into a new temporary folder and checked
 * first; only when the seal, its signature and the manifest check are the
 * listed files fetched (each at most its listed size), and the folder is
 * then checked like any other. Everything written there is removed after,
 * file by file: nothing else is ever deleted. */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* most files fetched, and the largest one */
#define NCREMFILES 10000
#define NCREMBIG ((size_t)1 << 30)

struct ncrem {
  char base[2048]; /* the URL, ending in '/' */
  char dir[1024];  /* the temporary folder */
  char **made;     /* everything written, in order */
  unsigned char *isd;
  size_t n, cap;
};

int ncisurl(const char *s) {
  return s != NULL &&
         (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0);
}

static int keep(ncrem *m, const char *path, int isdir) {
  char *c;
  if (m->n == m->cap) {
    size_t nc = m->cap == 0 ? 64 : m->cap * 2;
    char **a = (char **)realloc(m->made, nc * sizeof *a);
    unsigned char *d;
    if (a == NULL) return NCUSE;
    m->made = a;
    d = (unsigned char *)realloc(m->isd, nc);
    if (d == NULL) return NCUSE;
    m->isd = d;
    m->cap = nc;
  }
  c = (char *)malloc(strlen(path) + 1);
  if (c == NULL) return NCUSE;
  strcpy(c, path);
  m->made[m->n] = c;
  m->isd[m->n] = (unsigned char)isdir;
  m->n++;
  return NCOK;
}

void ncremfree(ncrem *m) {
  size_t i;
  if (m == NULL) return;
  for (i = m->n; i > 0; i--) {
    if (m->isd[i - 1])
      ncrmdir(m->made[i - 1]);
    else
      ncrmfile(m->made[i - 1]);
    free(m->made[i - 1]);
  }
  free(m->made);
  free(m->isd);
  free(m);
}

const char *ncremdir(const ncrem *m) {
  return m->dir;
}

/* rel, percent-encoded but for unreserved bytes and '/', after base */
static int urlof(const ncrem *m, const char *rel, char *out, size_t cap) {
  static const char hx[] = "0123456789ABCDEF";
  size_t k = strlen(m->base), i;
  if (k >= cap) return NCUSE;
  memcpy(out, m->base, k);
  for (i = 0; rel[i] != '\0'; i++) {
    unsigned char c = (unsigned char)rel[i];
    int plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                c == '_' || c == '~' || c == '/';
    if (k + 4 > cap) return NCUSE;
    if (plain) {
      out[k++] = (char)c;
    } else {
      out[k++] = '%';
      out[k++] = hx[c >> 4];
      out[k++] = hx[c & 15];
    }
  }
  out[k] = '\0';
  return NCOK;
}

/* dir/rel, making the folders on the way (recorded) */
static int place(ncrem *m, const char *rel, char *path, size_t cap) {
  size_t dl = strlen(m->dir), rl = strlen(rel), i;
  if (dl + 1 + rl >= cap) return NCUSE;
  memcpy(path, m->dir, dl);
  path[dl] = '/';
  memcpy(path + dl + 1, rel, rl + 1);
  for (i = dl + 1; path[i] != '\0'; i++) {
    if (path[i] != '/') continue;
    path[i] = '\0';
    if (!ncisdir(path)) {
      if (ncmkdir(path) != NCOK || keep(m, path, 1) != NCOK) {
        path[i] = '/';
        return NCUSE;
      }
    }
    path[i] = '/';
  }
  return NCOK;
}

/* fetches rel (at most max bytes) into the folder; 1 when written */
static int pull(ncrem *m, const char *rel, size_t max) {
  char u[4200], p[2200], err[300];
  uint8_t *b = NULL;
  size_t n = 0;
  int ok = 0;
  if (urlof(m, rel, u, sizeof u) != NCOK ||
      place(m, rel, p, sizeof p) != NCOK) {
    ncmsg("check", "%s: the path is too long to fetch", ncesc(rel));
    return 0;
  }
  if (ncget(u, max, &b, &n, err, sizeof err) != NCOK) {
    ncmsg("check", "%s: %s", ncesc(u), err);
  } else if (ncwr(p, b, n, 0, 0) != NCOK || keep(m, p, 0) != NCOK) {
    ncmsg("check", "%s: cannot be written to %s", ncesc(u), ncesc(p));
  } else {
    ok = 1;
  }
  free(b);
  return ok;
}

static int listed(const char *const *only, size_t nonly, const char *p) {
  size_t i;
  if (nonly == 0) return 1;
  for (i = 0; i < nonly; i++) {
    if (strcmp(only[i], p) == 0) return 1;
  }
  return 0;
}

int ncremget(const char *url, const nqcopt *co, ncrem **out) {
  ncrem *m;
  const char *t;
  uint8_t rb[8];
  char hx[17], err[300];
  size_t ul = strlen(url), i, nf = 0;
  nqrep *r = NULL;
  nqcopt pre;
  int ok, n;
  *out = NULL;
  if (strchr(url, '?') != NULL || strchr(url, '#') != NULL) {
    ncmsg("check", "%s: give the URL of the capsule's folder, without a "
          "query or fragment", ncesc(url));
    return NCUSE;
  }
  if (ncurlok(url, err, sizeof err) != NCOK) {
    ncmsg("check", "%s: %s", ncesc(url), err);
    return NCUSE;
  }
  m = (ncrem *)calloc(1, sizeof *m);
  if (m == NULL) return NCUSE;
  if (ul + 2 > sizeof m->base) {
    ncmsg("check", "the URL is too long");
    free(m);
    return NCUSE;
  }
  memcpy(m->base, url, ul + 1);
  if (ul == 0 || url[ul - 1] != '/') strcat(m->base, "/");
  t = getenv("TMPDIR");
  if (t == NULL || *t == '\0') t = getenv("TEMP");
  if (t == NULL || *t == '\0') t = getenv("TMP");
#ifdef _WIN32
  if (t == NULL || *t == '\0') t = ".";
#else
  if (t == NULL || *t == '\0') t = "/tmp";
#endif
  if (nqrand(rb, sizeof rb) != NQOK) {
    free(m);
    return NCUSE;
  }
  nchexe(rb, sizeof rb, hx);
  hx[16] = '\0';
  n = snprintf(m->dir, sizeof m->dir, "%s/noqtis-%s", t, hx);
  if (n < 0 || (size_t)n >= sizeof m->dir) {
    ncmsg("check", "the temporary folder's path is too long");
    free(m);
    return NCUSE;
  }
  if (ncmkdir(m->dir) != NCOK || keep(m, m->dir, 1) != NCOK) {
    ncmsg("check", "%s: cannot make a temporary folder", ncesc(m->dir));
    ncremfree(m);
    return NCUSE;
  }
  *out = m;
  if (!pull(m, "noqtis.sig", (size_t)1 << 20) ||
      !pull(m, "noqtis.json", (size_t)512 << 20)) {
    return NCOK; /* the check says what is missing */
  }
  /* the seal, its signature and the manifest first: nothing more is
   * fetched for a capsule they do not vouch for */
  pre = *co;
  pre.only = NULL;
  pre.nonly = 0;
  pre.lin = NULL;
  pre.nlin = 0;
  ok = nqchkx(m->dir, &pre, &r) == NQOK || r != NULL;
  for (i = 0; ok && i < nqrepn(r); i++) {
    const char *c = NULL, *d = NULL;
    int g = 0;
    if (nqrepi(r, i, &c, &g, &d) != NQOK) ok = 0;
    else if (!g && strcmp(c, "file") != 0) ok = 0;
  }
  nqrepfree(r);
  r = NULL;
  if (!ok) {
    ncmsg("check", "%s: the seal or the manifest does not check, so no "
          "file was fetched", ncesc(url));
    return NCOK;
  }
  if (nqfiles(m->dir, &r) != NQOK) {
    nqrepfree(r);
    return NCOK;
  }
  for (i = 0; i < nqrepn(r); i++) {
    const char *c = NULL, *d = NULL, *sp;
    int g = 0;
    unsigned long long sz;
    if (nqrepi(r, i, &c, &g, &d) != NQOK || strcmp(c, "info.file") != 0)
      continue;
    /* "<size> <sha256> <path>" */
    sp = strchr(d, ' ');
    if (sp == NULL || strlen(sp) < 67 || sp[65] != ' ') continue;
    sz = strtoull(d, NULL, 10);
    sp += 65;
    if (!listed(co->only, co->nonly, sp + 1)) continue;
    if (++nf > NCREMFILES) {
      ncmsg("check", "%s: more than %d files; the rest are not fetched",
            ncesc(url), NCREMFILES);
      break;
    }
    if (sz > NCREMBIG) {
      ncmsg("check", "%s: over 1 GiB, not fetched", ncesc(sp + 1));
      continue;
    }
    pull(m, sp + 1, (size_t)sz);
  }
  nqrepfree(r);
  return NCOK;
}
