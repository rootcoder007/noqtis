/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A CSV reader (RFC 4180): fields separated by one delimiter byte,
 * records ended by LF or CRLF, quoted fields with "" for a quote and
 * line breaks kept inside; a UTF-8 byte order mark at the start is
 * skipped. Strict: a quote inside an unquoted field, text after a
 * closing quote, a carriage return without a line feed, invalid UTF-8,
 * a NUL, and anything over the limits are refused with the line where
 * they are. No locale, no recursion, bounded memory. */
#include "int.h"

#include <string.h>

static int fill(qdcsv *c) {
  size_t got = 0;
  int rc;
  if (c->eof)
    return NQOK;
  rc = c->rd(c->u, c->buf, sizeof c->buf, &got);
  if (rc != NQOK)
    return rc;
  c->bn = got;
  c->bi = 0;
  if (got == 0)
    c->eof = 1;
  return NQOK;
}

/* the next byte, or -1 at the end */
static int peekc(qdcsv *c, int *rc) {
  if (c->bi >= c->bn) {
    if ((*rc = fill(c)) != NQOK)
      return -2;
    if (c->bi >= c->bn)
      return -1;
  }
  return (unsigned char)c->buf[c->bi];
}

static int frd(void *u, char *b, size_t cap, size_t *got) {
  FILE *f = (FILE *)u;
  *got = fread(b, 1, cap, f);
  return ferror(f) ? NQEIO : NQOK;
}

typedef struct {
  const char *p;
  size_t n;
  size_t i;
} qdmem;

static int mrd(void *u, char *b, size_t cap, size_t *got) {
  qdmem *m = (qdmem *)u;
  size_t k = m->n - m->i < cap ? m->n - m->i : cap;
  memcpy(b, m->p + m->i, k);
  m->i += k;
  *got = k;
  return NQOK;
}

static void init(qdcsv *c, char delim) {
  memset(c, 0, sizeof *c);
  c->delim = delim ? delim : ',';
  c->line = 1;
  c->maxfield = QDCSVFIELD;
  c->maxfields = QDCSVNF;
  c->maxrec = QDCSVREC;
}

int qdcsvfile(qdcsv *c, const char *path, char delim) {
  FILE *f;
  init(c, delim);
  f = qdfopen(path, "rb");
  if (f == NULL)
    return NQEIO;
  c->rd = frd;
  c->u = f;
  c->own = 1;
  return NQOK;
}

int qdcsvmem(qdcsv *c, const char *p, size_t n, char delim) {
  qdmem *m;
  init(c, delim);
  m = (qdmem *)qdmal(sizeof *m);
  if (m == NULL)
    return NQEMEM;
  m->p = p;
  m->n = n;
  m->i = 0;
  c->rd = mrd;
  c->u = m;
  c->own = 2;
  return NQOK;
}

void qdcsvclose(qdcsv *c) {
  if (c->own == 1 && c->u != NULL)
    fclose((FILE *)c->u);
  else if (c->own == 2)
    qdfree(c->u);
  qdfree(c->rec);
  qdfree(c->off);
  c->u = NULL;
  c->rec = NULL;
  c->off = NULL;
}

static int putb(qdcsv *c, char b) {
  if (c->reclen + 1 >= c->maxrec)
    return NQELIM;
  if (c->reclen + 2 > c->reccap) {
    size_t nc = c->reccap ? c->reccap * 2 : 1024;
    char *n;
    if (nc > c->maxrec + 1)
      nc = c->maxrec + 1;
    n = (char *)qdmal(nc);
    if (n == NULL)
      return NQEMEM;
    if (c->reclen)
      memcpy(n, c->rec, c->reclen);
    qdfree(c->rec);
    c->rec = n;
    c->reccap = nc;
  }
  c->rec[c->reclen++] = b;
  return NQOK;
}

/* ends the current field: a NUL after it, its offset kept */
static int endf(qdcsv *c, size_t start) {
  int rc;
  if (c->reclen - start > c->maxfield)
    return NQELIM;
  if (c->reclen > start && !qdutf8(c->rec + start, c->reclen - start)) {
    qdwhy(c->why, sizeof c->why, "line %llu, field %lu: not UTF-8, or a NUL",
          (unsigned long long)c->line, (unsigned long)c->nf + 1);
    return NQEDEC;
  }
  if ((rc = putb(c, '\0')) != NQOK)
    return rc;
  if (c->nf >= c->maxfields)
    return NQELIM;
  if (c->nf == c->offcap) {
    size_t nc = c->offcap ? c->offcap * 2 : 32, i;
    size_t *n = (size_t *)qdmal(nc * sizeof *n);
    if (n == NULL)
      return NQEMEM;
    for (i = 0; i < c->nf; i++)
      n[i] = c->off[i];
    qdfree(c->off);
    c->off = n;
    c->offcap = nc;
  }
  c->off[c->nf++] = start;
  return NQOK;
}

int qdcsvnext(qdcsv *c, int *got) {
  int rc = NQOK, ch, q = 0;
  size_t start = 0;
  uint64_t lines = 0;
  *got = 0;
  c->reclen = 0;
  c->nf = 0;
  c->why[0] = '\0';
  if (c->rd == NULL)
    return NQEARG;
  if (!c->bom) {
    /* a byte order mark: EF BB BF */
    c->bom = 1;
    if ((rc = fill(c)) != NQOK)
      return rc;
    if (c->bn >= 3 && memcmp(c->buf, "\xef\xbb\xbf", 3) == 0)
      c->bi = 3;
  }
  ch = peekc(c, &rc);
  if (ch == -2)
    return rc;
  if (ch == -1)
    return NQOK;
  c->recline = c->line;
  for (;;) {
    ch = peekc(c, &rc);
    if (ch == -2)
      return rc;
    if (q == 1) {
      /* inside quotes */
      if (ch == -1) {
        qdwhy(c->why, sizeof c->why,
              "line %llu: a quoted field is not closed before the end",
              (unsigned long long)c->recline);
        return NQEDEC;
      }
      c->bi++;
      if (ch == '"') {
        q = 2;
        continue;
      }
      if (ch == '\n')
        lines++;
      rc = putb(c, (char)ch);
    } else if (q == 2) {
      /* after a quote inside quotes: "" or the end of the field */
      if (ch == '"') {
        c->bi++;
        q = 1;
        rc = putb(c, '"');
      } else if (ch == -1 || ch == (unsigned char)c->delim || ch == '\n' ||
                 ch == '\r') {
        q = 3;
        continue;
      } else {
        qdwhy(c->why, sizeof c->why,
              "line %llu, field %lu: text after a closing quote (a quote "
              "inside a quoted field is written \"\")",
              (unsigned long long)(c->line + lines),
              (unsigned long)c->nf + 1);
        return NQEDEC;
      }
    } else {
      /* unquoted, or after a quoted field (q 3) */
      if (ch == '"' && q == 0 && c->reclen == start) {
        c->bi++;
        q = 1;
        continue;
      }
      if (ch == '"') {
        qdwhy(c->why, sizeof c->why,
              "line %llu, field %lu: a quote inside an unquoted field "
              "(quote the field, and write a quote in it as \"\")",
              (unsigned long long)(c->line + lines),
              (unsigned long)c->nf + 1);
        return NQEDEC;
      }
      if (ch == (unsigned char)c->delim) {
        c->bi++;
        if ((rc = endf(c, start)) != NQOK)
          break;
        start = c->reclen;
        q = 0;
        continue;
      }
      if (ch == '\r') {
        int n2;
        c->bi++;
        n2 = peekc(c, &rc);
        if (n2 == -2)
          return rc;
        if (n2 != '\n') {
          qdwhy(c->why, sizeof c->why,
                "line %llu: a carriage return without a line feed",
                (unsigned long long)(c->line + lines));
          return NQEDEC;
        }
        continue;
      }
      if (ch == '\n' || ch == -1) {
        if (ch == '\n')
          c->bi++;
        rc = endf(c, start);
        lines++;
        break;
      }
      if (q == 3) {
        qdwhy(c->why, sizeof c->why,
              "line %llu, field %lu: text after a closing quote",
              (unsigned long long)(c->line + lines),
              (unsigned long)c->nf + 1);
        return NQEDEC;
      }
      c->bi++;
      rc = putb(c, (char)ch);
    }
    if (rc != NQOK)
      break;
  }
  if (rc == NQELIM)
    qdwhy(c->why, sizeof c->why,
          "line %llu: over a limit (a field over %lu bytes, a record over "
          "%lu bytes or %lu fields)",
          (unsigned long long)c->recline, (unsigned long)c->maxfield,
          (unsigned long)c->maxrec, (unsigned long)c->maxfields);
  if (rc != NQOK)
    return rc;
  c->line += lines;
  c->nrec++;
  *got = 1;
  return NQOK;
}

const char *qdcsvf(const qdcsv *c, size_t i, size_t *len) {
  size_t e;
  if (i >= c->nf)
    return NULL;
  e = i + 1 < c->nf ? c->off[i + 1] - 1 : c->reclen - 1;
  if (len != NULL)
    *len = e - c->off[i];
  return c->rec + c->off[i];
}
