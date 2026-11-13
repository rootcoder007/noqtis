/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Single-file bundles (noqtis-bundle-1, noqtis-capsule(5) and the
 * capsule specification's section 14): a capsule's seal, manifest and
 * files in one file, to mail or attach. nqdpack writes one from a
 * capsule folder; nqdunpack reads one into a new folder, or removes what
 * it wrote; qdbread is the strict reader under both and the fuzz
 * target. Nothing here checks a signature: a bundle is unpacked, then
 * checked as the folder it holds. */
#include "int.h"

#include <stdlib.h>
#include <string.h>

#define QDBMAGIC "noqtis-bundle-1\n"
#define QDBPATH 4096
#define QDBDEPTH 64
#define QDBMAXN ((uint64_t)2000003)
#define QDBBIG ((((uint64_t)1) << 53) - 1)
#define QDBCHUNK ((size_t)65536)

/* n bytes from the input, all of them: NQOK, NQEDEC when it ends first */
static int need(const qdbio *io, uint8_t *b, size_t n) {
  size_t got = 0, k;
  int rc;
  while (got < n) {
    k = 0;
    if ((rc = io->rd(io->u, b + got, n - got, &k)) != NQOK)
      return rc;
    if (k == 0)
      return NQEDEC;
    got += k;
  }
  return NQOK;
}

/* a path a capsule holds (noqtis-capsule(5)), at most 64 folders deep */
static int bpath(const char *p, size_t n) {
  char t[QDBPATH + 8];
  size_t i, d = 0;
  if (n == 0 || n > QDBPATH || strlen(p) != n ||
      qdjoin(".", p, t, sizeof t) != NQOK)
    return 0;
  for (i = 0; i < n; i++)
    d += p[i] == '/';
  return d <= QDBDEPTH;
}

/* byte order, a proper prefix first */
static int bcmp2(const char *a, size_t al, const char *b, size_t bl) {
  int c = memcmp(a, b, al < bl ? al : bl);
  return c != 0 ? c : al < bl ? -1 : al > bl ? 1 : 0;
}

int qdbread(const qdbio *io, char *why, size_t cap) {
  uint8_t h[16], lb[2], sb[8];
  char *pa, *pb, *t;
  uint8_t *buf;
  size_t pl = 0, len, k;
  uint64_t cnt = 0, size;
  int rc = NQOK, seen = 0;
  if (why != NULL && cap)
    why[0] = '\0';
  if (need(io, h, 16) != NQOK || memcmp(h, QDBMAGIC, 16) != 0) {
    qdwhy(why, cap, "not a bundle: it does not start with noqtis-bundle-1");
    return NQEDEC;
  }
  pa = (char *)qdmal(QDBPATH + 1);
  pb = (char *)qdmal(QDBPATH + 1);
  buf = (uint8_t *)qdmal(QDBCHUNK);
  if (pa == NULL || pb == NULL || buf == NULL) {
    rc = NQEMEM;
    goto out;
  }
  for (;;) {
    if ((rc = need(io, lb, 2)) != NQOK) {
      if (rc == NQEDEC)
        qdwhy(why, cap, "the bundle ends before its end mark (cut short?)");
      goto out;
    }
    len = (size_t)lb[0] << 8 | lb[1];
    if (len == 0)
      break;
    if (len > QDBPATH) {
      qdwhy(why, cap, "entry %llu: a path of %lu bytes, over 4096",
            (unsigned long long)cnt + 1, (unsigned long)len);
      rc = NQELIM;
      goto out;
    }
    if ((rc = need(io, (uint8_t *)pb, len)) != NQOK) {
      if (rc == NQEDEC)
        qdwhy(why, cap, "entry %llu: the bundle ends inside its path",
              (unsigned long long)cnt + 1);
      goto out;
    }
    pb[len] = '\0';
    if (!bpath(pb, len)) {
      qdwhy(why, cap, "entry %llu: not a path a capsule holds (relative, "
            "'/' between folders, no '.' or '..', no backslash, colon or "
            "control character, valid UTF-8, at most 64 folders deep)",
            (unsigned long long)cnt + 1);
      rc = NQEDEC;
      goto out;
    }
    if (cnt > 0 && bcmp2(pa, pl, pb, len) >= 0) {
      qdwhy(why, cap, "%s: not after %s (entries are in byte order, each "
            "once)", pb, pa);
      rc = NQEDEC;
      goto out;
    }
    if (++cnt > QDBMAXN) {
      qdwhy(why, cap, "more than 2,000,003 entries");
      rc = NQELIM;
      goto out;
    }
    if ((rc = need(io, sb, 8)) != NQOK) {
      if (rc == NQEDEC)
        qdwhy(why, cap, "%s: the bundle ends inside its size", pb);
      goto out;
    }
    size = qdld64(sb);
    if (size > QDBBIG ||
        (strcmp(pb, "noqtis.sig") == 0 && size > ((uint64_t)1 << 20)) ||
        (strcmp(pb, "noqtis.json") == 0 && size > ((uint64_t)512 << 20))) {
      qdwhy(why, cap, "%s: %llu bytes, over its limit", pb,
            (unsigned long long)size);
      rc = NQELIM;
      goto out;
    }
    seen |= strcmp(pb, "noqtis.json") == 0 ? 1
            : strcmp(pb, "noqtis.sig") == 0 ? 2
                                             : 0;
    if ((rc = io->put(io->s, QDBBEG, pb, size, NULL, 0)) != NQOK)
      goto out;
    while (size > 0) {
      k = size < QDBCHUNK ? (size_t)size : QDBCHUNK;
      if ((rc = need(io, buf, k)) != NQOK) {
        if (rc == NQEDEC)
          qdwhy(why, cap, "%s: the bundle ends inside it", pb);
        goto out;
      }
      if ((rc = io->put(io->s, QDBDAT, NULL, 0, buf, k)) != NQOK)
        goto out;
      size -= k;
    }
    if ((rc = io->put(io->s, QDBEND, NULL, 0, NULL, 0)) != NQOK)
      goto out;
    t = pa;
    pa = pb;
    pb = t;
    pl = len;
  }
  k = 0;
  if ((rc = io->rd(io->u, h, 1, &k)) != NQOK)
    goto out;
  if (k != 0) {
    qdwhy(why, cap, "bytes after the end mark");
    rc = NQEDEC;
  } else if (seen != 3) {
    qdwhy(why, cap, "no noqtis.json or no noqtis.sig: not a capsule's "
          "bundle");
    rc = NQEDEC;
  }
out:
  qdfree(pa);
  qdfree(pb);
  qdfree(buf);
  return rc;
}

/* ---- unpacking ---- */

typedef struct {
  const char *dir;
  int rm;      /* 1: remove what an unpack wrote */
  FILE *f;     /* the file being written */
  dbuf made;   /* what was written: 'f' or 'd', the path, a NUL */
  char *why;
  size_t cap;
} usink;

static int frd(void *u, uint8_t *b, size_t n, size_t *got) {
  FILE *f = (FILE *)u;
  *got = fread(b, 1, n, f);
  return *got < n && ferror(f) ? NQEIO : NQOK;
}

static void keep(usink *s, char kind, const char *p) {
  qdbch(&s->made, kind);
  qdbput(&s->made, p, strlen(p) + 1);
}

#ifdef _WIN32
/* a segment Windows takes for a device (CON, NUL, COM1, LPT1, ...: with
 * any extension, in any case), or one it would change (a trailing dot
 * or space) */
static int devname(const char *p) {
  static const char *const dv[] = {"con", "prn", "aux", "nul"};
  const char *s = p;
  for (;;) {
    size_t n = strcspn(s, "/"), b = strcspn(s, "./"), i;
    char l[5];
    if (n > 0 && (s[n - 1] == '.' || s[n - 1] == ' '))
      return 1;
    if (b == 3 || b == 4) {
      for (i = 0; i < b; i++)
        l[i] = (char)(s[i] >= 'A' && s[i] <= 'Z' ? s[i] + 32 : s[i]);
      l[b] = '\0';
      for (i = 0; i < 4 && b == 3; i++)
        if (strcmp(l, dv[i]) == 0)
          return 1;
      if (b == 4 && (memcmp(l, "com", 3) == 0 || memcmp(l, "lpt", 3) == 0) &&
          l[3] >= '1' && l[3] <= '9')
        return 1;
    }
    if (s[n] == '\0')
      return 0;
    s += n + 1;
  }
}
#endif

static int uput(void *v, int op, const char *path, uint64_t size,
                const uint8_t *b, size_t n) {
  usink *s = (usink *)v;
  char p[QDBPATH + 1100];
  size_t i, dl;
  (void)size;
  if (op == QDBDAT)
    return s->f == NULL || fwrite(b, 1, n, s->f) == n ? NQOK : NQEIO;
  if (op == QDBEND) {
    int bad = s->f != NULL && fclose(s->f) != 0;
    s->f = NULL;
    if (bad)
      qdwhy(s->why, s->cap, "a file of the bundle cannot be written");
    return bad ? NQEIO : NQOK;
  }
#ifdef _WIN32
  if (devname(path)) {
    qdwhy(s->why, s->cap, "%s: a name Windows takes for a device or "
          "changes (CON, NUL, COM1, a trailing dot or space)", path);
    return NQEDEC;
  }
#endif
  if (qdjoin(s->dir, path, p, sizeof p) != NQOK) {
    qdwhy(s->why, s->cap, "%s: the path is too long here", path);
    return NQELIM;
  }
  dl = strlen(s->dir) + 1;
  if (s->rm) {
    qdrm(p, 0);
    /* each folder above it, once it is empty */
    for (i = strlen(p); i > dl; i--) {
      if (p[i - 1] == '/') {
        p[i - 1] = '\0';
        if (qdrm(p, 1) != NQOK)
          break;
      }
    }
    return NQOK;
  }
  /* the folders on the way: made here, or already made by an entry
   * before (the folder was new and empty) */
  for (i = dl; p[i] != '\0'; i++) {
    if (p[i] != '/')
      continue;
    p[i] = '\0';
    if (qdmkdir(p) == NQOK)
      keep(s, 'd', p);
    p[i] = '/';
  }
  if ((s->f = qdfnew(p)) == NULL) {
    qdwhy(s->why, s->cap, "%s: cannot be created (two paths that differ "
          "only in case, or a path through a file?)", path);
    return NQEIO;
  }
  keep(s, 'f', p);
  return s->made.err ? s->made.err : NQOK;
}

/* removes what s made, last first */
static void undo(usink *s) {
  size_t e = s->made.n, b;
  while (e > 0) {
    b = e - 1;
    while (b > 0 && s->made.b[b - 1] != '\0')
      b--;
    qdrm(s->made.b + b + 1, s->made.b[b] == 'd');
    e = b;
  }
}

int nqdunpack(const char *file, const char *dir, int rm, char *why,
              size_t cap) {
  FILE *in;
  usink s;
  qdbio io;
  int rc;
  if (why != NULL && cap)
    why[0] = '\0';
  if (file == NULL || dir == NULL || *dir == '\0' || (rm != 0 && rm != 1))
    return NQEARG;
  if ((in = qdfopen(file, "rb")) == NULL) {
    qdwhy(why, cap, "%s: cannot be read", file);
    return NQEIO;
  }
  if (!rm && qdmkdir(dir) != NQOK) {
    fclose(in);
    qdwhy(why, cap, "%s: cannot be made (it must not exist yet)", dir);
    return NQEIO;
  }
  memset(&s, 0, sizeof s);
  s.dir = dir;
  s.rm = rm;
  s.why = why;
  s.cap = cap;
  io.rd = frd;
  io.u = in;
  io.put = uput;
  io.s = &s;
  rc = qdbread(&io, why, cap);
  fclose(in);
  if (s.f != NULL)
    fclose(s.f);
  if (rc != NQOK && !rm)
    undo(&s);
  if (rc != NQOK || rm)
    qdrm(dir, 1);
  qdbfree(&s.made);
  return rc;
}

/* ---- packing ---- */

static int bycmp(const void *a, const void *b) {
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void be(uint8_t *o, uint64_t v, int n) {
  int i;
  for (i = n - 1; i >= 0; i--) {
    o[i] = (uint8_t)(v & 0xff);
    v >>= 8;
  }
}

/* entry path of dir into out */
static int bent(FILE *out, const char *dir, const char *path) {
  char p[QDBPATH + 1100];
  uint8_t h[32], hd[8], *b;
  uint64_t size, got = 0;
  size_t n = strlen(path), k;
  FILE *f;
  int rc = NQOK;
  if (qdjoin(dir, path, p, sizeof p) != NQOK)
    return NQELIM;
  if ((rc = qdsha(p, h, &size)) != NQOK)
    return rc;
  be(hd, n, 2);
  if (fwrite(hd, 1, 2, out) != 2 || fwrite(path, 1, n, out) != n)
    return NQEIO;
  be(hd, size, 8);
  if (fwrite(hd, 1, 8, out) != 8 || (f = qdfopen(p, "rb")) == NULL)
    return NQEIO;
  if ((b = (uint8_t *)qdmal(QDBCHUNK)) == NULL) {
    fclose(f);
    return NQEMEM;
  }
  while (rc == NQOK && (k = fread(b, 1, QDBCHUNK, f)) > 0) {
    got += k;
    if (got > size || fwrite(b, 1, k, out) != k)
      rc = NQEIO;
  }
  if (rc == NQOK && (ferror(f) || got != size))
    rc = NQEIO; /* changed while it was read */
  fclose(f);
  qdfree(b);
  return rc;
}

int nqdpack(const char *dir, int files, const char *file) {
  static const char *const top[] = {"noqtis.ers", "noqtis.json",
                                    "noqtis.sig"};
  char **pv = NULL, p[QDBPATH + 1100];
  size_t np = 0, nr, i;
  nqrep *rep = NULL;
  FILE *out = NULL;
  int rc, rec = 0;
  if (dir == NULL || file == NULL || (files != 0 && files != 1))
    return NQEARG;
  if ((rc = nqfiles(dir, &rep)) != NQOK) {
    nqrepfree(rep);
    return rc;
  }
  nr = nqrepn(rep);
  if ((pv = (char **)qdmal((nr + 3) * sizeof *pv)) == NULL) {
    rc = NQEMEM;
    goto out;
  }
  for (i = 0; i < 3; i++) {
    FILE *f;
    if (qdjoin(dir, top[i], p, sizeof p) != NQOK ||
        (f = qdfopen(p, "rb")) == NULL)
      continue;
    fclose(f);
    if ((pv[np] = qddup(top[i], strlen(top[i]))) == NULL) {
      rc = NQEMEM;
      goto out;
    }
    np++;
  }
  for (i = 0; i < nr; i++) {
    const char *c = NULL, *d = NULL, *s;
    nqrepi(rep, i, &c, NULL, &d);
    /* "<size> <sha256> <path>" */
    if (c == NULL || d == NULL || strcmp(c, "info.file") != 0 ||
        (s = strchr(d, ' ')) == NULL || strlen(s) < 67 || s[65] != ' ')
      continue;
    s += 66;
    if (strcmp(s, NQDFILE) == 0)
      rec = 1;
    else if (!files)
      continue;
    if ((pv[np] = qddup(s, strlen(s))) == NULL) {
      rc = NQEMEM;
      goto out;
    }
    np++;
  }
  if (!files && !rec) {
    rc = NQEARG; /* without the files, the record is what it carries */
    goto out;
  }
  qsort(pv, np, sizeof *pv, bycmp);
  if ((out = qdfnew(file)) == NULL) {
    rc = NQEIO;
    goto out;
  }
  if (fwrite(QDBMAGIC, 1, 16, out) != 16)
    rc = NQEIO;
  for (i = 0; rc == NQOK && i < np; i++)
    if (i == 0 || strcmp(pv[i], pv[i - 1]) != 0)
      rc = bent(out, dir, pv[i]);
  if (rc == NQOK && fwrite("\0\0", 1, 2, out) != 2)
    rc = NQEIO;
  if (fclose(out) != 0 && rc == NQOK)
    rc = NQEIO;
  if (rc != NQOK)
    qdrm(file, 0);
out:
  for (i = 0; pv != NULL && i < np; i++)
    qdfree(pv[i]);
  qdfree(pv);
  nqrepfree(rep);
  return rc;
}
