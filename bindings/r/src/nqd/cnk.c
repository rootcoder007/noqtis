/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Chunk digests of one large file ("chunks", noqtis-data(5)): the
 * SHA-256 of each run of chunk bytes, so that a piece of the file (a
 * range fetched alone, the part that survived) can be checked without
 * the rest. The file is never split: nqdchunk reads it once, nqdpiece
 * reads only the piece. A capsule's seal covers the digests through the
 * record (check it with `noqtis check --only noqtis.data.json`). */
#include "int.h"

#include <stdlib.h>
#include <string.h>

#define QDCNKMIN ((uint64_t)1024)
#define QDCNKMAX ((uint64_t)1 << 30)

int nqdchunk(const char *dir, const char *path, uint64_t chunk, char *out,
             size_t cap, size_t *outlen, char *why, size_t wcap) {
  char p[4200], hx[65];
  uint8_t *b = NULL, h[32];
  uint64_t size = 0, in = 0;
  size_t k;
  FILE *f = NULL;
  djs *e = NULL, *dg = NULL;
  nqhctx c;
  dbuf o;
  int rc;
  if (why != NULL && wcap)
    why[0] = '\0';
  memset(&c, 0, sizeof c);
  if (path == NULL || outlen == NULL || chunk < QDCNKMIN ||
      chunk > QDCNKMAX) {
    qdwhy(why, wcap, "a chunk is 1024 bytes to 1 GiB");
    return NQEARG;
  }
  if ((rc = qdjoin(dir, path, p, sizeof p)) != NQOK) {
    qdwhy(why, wcap, "%s: not a path a capsule holds", path);
    return rc;
  }
  if ((f = qdfopen(p, "rb")) == NULL) {
    qdwhy(why, wcap, "%s: cannot be read", p);
    return NQEIO;
  }
  e = qdjnew(DJOBJ);
  dg = qdjnew(DJARR);
  b = (uint8_t *)qdmal(65536);
  if (e == NULL || dg == NULL || b == NULL ||
      (rc = nqhini(&c, NQS256)) != NQOK) {
    rc = NQEMEM;
    goto out;
  }
  for (;;) {
    size_t want = (size_t)(chunk - in < 65536 ? chunk - in : 65536);
    k = fread(b, 1, want, f);
    if (k > 0) {
      nqhupd(&c, b, k);
      in += k;
      size += k;
    }
    if (in == chunk || (k < want && in > 0)) {
      if ((rc = nqhfin(&c, h, 32)) != NQOK)
        goto out;
      qdhex(h, 32, hx);
      if ((rc = qdjadd(dg, qdjstr(hx))) != NQOK)
        goto out;
      in = 0;
      if ((rc = nqhini(&c, NQS256)) != NQOK)
        goto out;
    }
    if (k < want)
      break;
  }
  if (ferror(f)) {
    qdwhy(why, wcap, "%s: cannot be read", p);
    rc = NQEIO;
    goto out;
  }
  if (qdjset(e, "chunk", qdjnum((double)chunk)) != NQOK ||
      qdjset(e, "path", qdjstr(path)) != NQOK ||
      qdjset(e, "size", qdjnum((double)size)) != NQOK) {
    rc = NQEMEM;
    goto out;
  }
  if ((rc = qdjset(e, "digests", dg)) != NQOK) {
    dg = NULL;
    goto out;
  }
  dg = NULL;
  if ((rc = qdelemok("chunks", e, why, wcap)) != NQOK)
    goto out;
  memset(&o, 0, sizeof o);
  o.max = NQDMAX;
  qdjwrite(e, &o);
  rc = o.err ? o.err : qdbout(&o, out, cap, outlen);
  if (rc == NQELIM)
    qdwhy(why, wcap, "%s: more digests than a record holds: take larger "
          "chunks", path);
  qdbfree(&o);
out:
  if (f != NULL)
    fclose(f);
  qdfree(b);
  qdjfree(dg);
  qdjfree(e);
  return rc;
}

/* the rows of a piece (the file piece, from byte off of the file) against
 * the chunks element e; whole: the piece is the whole file */
int qdpiece(nqdrep *rep, const djs *e, const char *piece, uint64_t off,
            int whole) {
  const djs *dg = qdjget(e, "digests");
  const char *path = qdjget(e, "path")->s;
  int64_t ci = 0, si = 0;
  uint64_t chunk, size, at, in = 0, first, ok = 0, bad = 0;
  uint8_t *b, h[32];
  char hx[65];
  size_t k;
  FILE *f;
  nqhctx c;
  int rc = NQOK;
  memset(&c, 0, sizeof c);
  qdjint(qdjget(e, "chunk"), &ci);
  qdjint(qdjget(e, "size"), &si);
  chunk = (uint64_t)ci;
  size = (uint64_t)si;
  if (off % chunk != 0 || off > size)
    return qdrepadd(rep, "chunk", 0, "%s: byte %llu is not where a chunk "
                    "starts (every %llu bytes, up to %llu)", path,
                    (unsigned long long)off, (unsigned long long)chunk,
                    (unsigned long long)size);
  if ((f = qdfopen(piece, "rb")) == NULL)
    return qdrepadd(rep, "chunk", 0, "%s: missing or unreadable", piece);
  if ((b = (uint8_t *)qdmal(65536)) == NULL || nqhini(&c, NQS256) != NQOK) {
    fclose(f);
    qdfree(b);
    return NQEMEM;
  }
  first = off / chunk;
  at = off;
  for (;;) {
    size_t want = (size_t)(chunk - in < 65536 ? chunk - in : 65536);
    k = fread(b, 1, want, f);
    nqhupd(&c, b, k);
    in += k;
    at += k;
    if (at > size) {
      rc = qdrepadd(rep, "chunk", 0, "%s: runs past the %llu bytes "
                    "recorded", path, (unsigned long long)size);
      bad++;
      break;
    }
    /* a whole chunk, or the file's last */
    if (in == chunk || (in > 0 && at == size)) {
      uint64_t i = (at - 1) / chunk;
      nqhfin(&c, h, 32);
      qdhex(h, 32, hx);
      if (i < dg->n && strcmp(hx, dg->k[i]->s) == 0) {
        ok++;
      } else {
        bad++;
        if (bad <= 20)
          rc = qdrepadd(rep, "chunk", 0, "%s: chunk %llu (bytes %llu to "
                        "%llu) differs", path, (unsigned long long)i,
                        (unsigned long long)(i * chunk),
                        (unsigned long long)(at - 1));
      }
      in = 0;
      nqhini(&c, NQS256);
    }
    if (k < want)
      break;
  }
  if (ferror(f)) {
    bad++;
    rc = qdrepadd(rep, "chunk", 0, "%s: cannot be read", piece);
  } else if (whole && at < size) {
    bad++;
    rc = qdrepadd(rep, "chunk", 0, "%s: %llu bytes, the record says %llu",
                  path, (unsigned long long)at, (unsigned long long)size);
  } else if (in > 0 && at < size) {
    rc = qdrepadd(rep, "chunk", 1, "%s: the piece's last %llu bytes are "
                  "not a whole chunk, so not checked", path,
                  (unsigned long long)in);
  }
  fclose(f);
  qdfree(b);
  if (bad > 20)
    rc = qdrepadd(rep, "chunk", 0, "%s: %llu more chunks differ", path,
                  (unsigned long long)(bad - 20));
  if (rc == NQOK && ok == 0 && bad == 0)
    rc = size == 0 ? qdrepadd(rep, "chunk", 1, "%s: empty, as recorded", path)
                   : qdrepadd(rep, "chunk", 0, "%s: the piece holds no "
                              "whole chunk", path);
  else if (rc == NQOK && bad == 0)
    rc = qdrepadd(rep, "chunk", 1, "%s: chunks %llu to %llu of %lu match "
                  "(bytes %llu to %llu)", path, (unsigned long long)first,
                  (unsigned long long)(first + ok - 1),
                  (unsigned long)dg->n, (unsigned long long)off,
                  (unsigned long long)(off + ok * chunk > size
                                           ? size - 1
                                           : off + ok * chunk - 1));
  return rc;
}

int nqdpiece(const char *elem, size_t n, const char *piece, uint64_t off,
             nqdrep **rep) {
  djs *e = NULL;
  nqdrep *r;
  char why[600];
  int rc;
  size_t i, bad = 0;
  if (elem == NULL || piece == NULL || rep == NULL)
    return NQEARG;
  *rep = NULL;
  if ((r = qdrepnew()) == NULL)
    return NQEMEM;
  if ((rc = qdjparse(elem, n, &e, why, sizeof why)) != NQOK ||
      (rc = qdelemok("chunks", e, why, sizeof why)) != NQOK) {
    qdjfree(e);
    if (rc == NQEMEM) {
      nqdrepfree(r);
      return rc;
    }
    qdrepadd(r, "chunk", 0, "the chunks element: %s", why);
    *rep = r;
    return NQEVRFY;
  }
  rc = qdpiece(r, e, piece, off, 0);
  qdjfree(e);
  if (rc == NQEMEM) {
    nqdrepfree(r);
    return rc;
  }
  for (i = 0; i < nqdrepn(r); i++) {
    int ok = 0;
    nqdrepi(r, i, NULL, &ok, NULL);
    bad += !ok;
  }
  *rep = r;
  return bad ? NQEVRFY : NQOK;
}
