/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The regular expressions of the regex rule: a small subset (literals,
 * classes, '.', anchors, '*', '+', '?', alternation, groups), compiled
 * without recursion by Thompson's construction and run as a set of
 * states over the value's code points, so that a match takes time
 * proportional to the value's length times the pattern's, whatever
 * the pattern: there is no backtracking to blow up. */
#include "int.h"

#include <string.h>

#define RXMAX 1024  /* bytes in a pattern */
#define RXDEPTH 64  /* groups inside groups */
#define NOS ((size_t)-1)

/* states */
enum { XCHR = 1, XCLS, XANY, XBOL, XEOL, XSPLIT, XMATCH };
/* the postfix form's operators, beside the states' kinds */
enum { PCAT = 16, PALT, PSTAR, PPLUS, PQUES };

typedef struct {
  int t;
  uint32_t c; /* XCHR: the code point */
  size_t k;   /* XCLS: the class */
} rxtok;

typedef struct {
  uint32_t lo, hi;
} rxrng;

typedef struct {
  size_t at, n;
  int neg;
} rxcls;

typedef struct {
  int op;
  uint32_t c;
  size_t k;
  size_t x, y; /* the next states (y: the second way of a split) */
} rxst;

struct qdrx {
  rxst *s;
  size_t ns;
  rxrng *r;
  size_t nr;
  rxcls *cl;
  size_t nc;
  size_t start;
  /* for the run: two lists of states, a stack, and marks */
  size_t *cur, *nxt, *stk, *mark, gen;
};

/* the code point at s[*i], *i moved past it; a byte that does not start
 * valid UTF-8 is 0x110000 plus the byte, which only '.' and a negated
 * class match */
static uint32_t dec(const char *s, size_t n, size_t *i) {
  const uint8_t *p = (const uint8_t *)s + *i;
  size_t left = n - *i, k, len;
  uint32_t c = p[0], min;
  if (c < 0x80) {
    *i += 1;
    return c;
  }
  if (c >= 0xc2 && c <= 0xdf) {
    len = 2;
    c &= 0x1f;
    min = 0x80;
  } else if (c >= 0xe0 && c <= 0xef) {
    len = 3;
    c &= 0x0f;
    min = 0x800;
  } else if (c >= 0xf0 && c <= 0xf4) {
    len = 4;
    c &= 0x07;
    min = 0x10000;
  } else {
    *i += 1;
    return 0x110000u + p[0];
  }
  if (left < len) {
    *i += 1;
    return 0x110000u + p[0];
  }
  for (k = 1; k < len; k++) {
    if ((p[k] & 0xc0) != 0x80) {
      *i += 1;
      return 0x110000u + p[0];
    }
    c = (c << 6) | (p[k] & 0x3fu);
  }
  if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) {
    *i += 1;
    return 0x110000u + p[0];
  }
  *i += len;
  return c;
}

/* ---- the parse, to postfix (Thompson's, with counts per group) ---- */

typedef struct {
  rxtok *t;
  size_t n;
} rxpost;

static void emit(rxpost *p, int t, uint32_t c, size_t k) {
  p->t[p->n].t = t;
  p->t[p->n].c = c;
  p->t[p->n].k = k;
  p->n++;
}

static void rng(qdrx *x, uint32_t lo, uint32_t hi) {
  x->r[x->nr].lo = lo;
  x->r[x->nr].hi = hi;
  x->nr++;
}

/* the ranges of \d, \w or \s; 0 for another letter */
static int shorthand(qdrx *x, uint32_t e) {
  if (e == 'd') {
    rng(x, '0', '9');
  } else if (e == 'w') {
    rng(x, '0', '9');
    rng(x, 'A', 'Z');
    rng(x, 'a', 'z');
    rng(x, '_', '_');
  } else if (e == 's') {
    rng(x, '\t', '\r'); /* tab, line feed, vertical tab, form feed, CR */
    rng(x, ' ', ' ');
  } else {
    return 0;
  }
  return 1;
}

/* the characters a backslash makes literal, outside a class and in one */
static const char outesc[] = "\\.[]()|*+?^${}-/";
static const char inesc[] = "\\]-[^";

static int isin(const char *set, uint32_t c) {
  return c != 0 && c < 0x80 && strchr(set, (int)c) != NULL;
}

/* a class from just after its '[' to just after its ']' */
static int cls(qdrx *x, const char *p, size_t n, size_t *i, char *why,
               size_t cap) {
  rxcls *c = &x->cl[x->nc];
  size_t open = *i - 1;
  c->at = x->nr;
  c->neg = 0;
  if (*i < n && p[*i] == '^') {
    c->neg = 1;
    (*i)++;
  }
  if (*i < n && p[*i] == ']') {
    qdwhy(why, cap, "byte %lu: an empty class; write \\] for a ] in one",
          (unsigned long)*i);
    return NQEDEC;
  }
  for (;;) {
    uint32_t lo, hi;
    size_t at = *i;
    if (*i >= n) {
      qdwhy(why, cap, "byte %lu: the class is not closed with ]",
            (unsigned long)open);
      return NQEDEC;
    }
    lo = dec(p, n, i);
    if (lo == ']')
      break;
    if (lo == '[') {
      qdwhy(why, cap, "byte %lu: [ inside a class; write \\[",
            (unsigned long)at);
      return NQEDEC;
    }
    if (lo == '\\') {
      if (*i >= n) {
        qdwhy(why, cap, "byte %lu: a backslash at the end",
              (unsigned long)at);
        return NQEDEC;
      }
      lo = dec(p, n, i);
      if (shorthand(x, lo))
        continue;
      if (!isin(inesc, lo)) {
        qdwhy(why, cap, "byte %lu: an escape a class does not have (\\\\, "
              "\\], \\-, \\[, \\^, \\d, \\w, \\s)", (unsigned long)at);
        return NQEDEC;
      }
    }
    hi = lo;
    if (*i + 1 < n && p[*i] == '-' && p[*i + 1] != ']') {
      (*i)++;
      at = *i;
      hi = dec(p, n, i);
      if (hi == '\\') {
        if (*i >= n) {
          qdwhy(why, cap, "byte %lu: a backslash at the end",
                (unsigned long)at);
          return NQEDEC;
        }
        hi = dec(p, n, i);
        if (!isin(inesc, hi)) {
          qdwhy(why, cap, "byte %lu: a range ends at one character",
                (unsigned long)at);
          return NQEDEC;
        }
      } else if (hi == '[') {
        qdwhy(why, cap, "byte %lu: [ inside a class; write \\[",
              (unsigned long)at);
        return NQEDEC;
      }
      if (hi < lo) {
        qdwhy(why, cap, "byte %lu: the range is out of order",
              (unsigned long)at);
        return NQEDEC;
      }
    }
    rng(x, lo, hi);
  }
  c->n = x->nr - c->at;
  x->nc++;
  return NQOK;
}

static int topost(qdrx *x, const char *p, size_t n, rxpost *o, char *why,
                  size_t cap) {
  size_t i = 0, nalt = 0, natom = 0, depth = 0;
  size_t salt[RXDEPTH], satom[RXDEPTH], sat[RXDEPTH];
  while (i < n) {
    size_t at = i;
    uint32_t c = dec(p, n, &i);
    int t = XCHR;
    size_t k = 0;
    switch (c) {
    case '(':
      if (natom > 1) {
        natom--;
        emit(o, PCAT, 0, 0);
      }
      if (depth == RXDEPTH) {
        qdwhy(why, cap, "byte %lu: groups nest deeper than %d",
              (unsigned long)at, RXDEPTH);
        return NQEDEC;
      }
      salt[depth] = nalt;
      satom[depth] = natom;
      sat[depth] = at;
      depth++;
      nalt = natom = 0;
      continue;
    case '|':
      if (natom == 0) {
        qdwhy(why, cap, "byte %lu: nothing before |", (unsigned long)at);
        return NQEDEC;
      }
      while (--natom > 0)
        emit(o, PCAT, 0, 0);
      nalt++;
      continue;
    case ')':
      if (depth == 0) {
        qdwhy(why, cap, "byte %lu: ) without its (", (unsigned long)at);
        return NQEDEC;
      }
      if (natom == 0) {
        qdwhy(why, cap, "byte %lu: an empty group or alternative",
              (unsigned long)at);
        return NQEDEC;
      }
      while (--natom > 0)
        emit(o, PCAT, 0, 0);
      for (; nalt > 0; nalt--)
        emit(o, PALT, 0, 0);
      depth--;
      nalt = salt[depth];
      natom = satom[depth] + 1;
      continue;
    case '*':
    case '+':
    case '?':
      if (natom == 0) {
        qdwhy(why, cap, "byte %lu: nothing before %c to repeat",
              (unsigned long)at, (char)c);
        return NQEDEC;
      }
      emit(o, c == '*' ? PSTAR : c == '+' ? PPLUS : PQUES, 0, 0);
      continue;
    case '{':
    case '}':
      qdwhy(why, cap, "byte %lu: counted repetition {m,n} is not part of "
            "the syntax; write \\%c for the character", (unsigned long)at,
            (char)c);
      return NQEDEC;
    case ']':
      qdwhy(why, cap, "byte %lu: ] without its [; write \\]",
            (unsigned long)at);
      return NQEDEC;
    case '[':
      if (cls(x, p, n, &i, why, cap) != NQOK)
        return NQEDEC;
      t = XCLS;
      k = x->nc - 1;
      break;
    case '.':
      t = XANY;
      break;
    case '^':
      t = XBOL;
      break;
    case '$':
      t = XEOL;
      break;
    case '\\':
      if (i >= n) {
        qdwhy(why, cap, "byte %lu: a backslash at the end",
              (unsigned long)at);
        return NQEDEC;
      }
      c = dec(p, n, &i);
      if (c == 'd' || c == 'w' || c == 's') {
        x->cl[x->nc].at = x->nr;
        x->cl[x->nc].neg = 0;
        shorthand(x, c);
        x->cl[x->nc].n = x->nr - x->cl[x->nc].at;
        t = XCLS;
        k = x->nc++;
      } else if (!isin(outesc, c)) {
        qdwhy(why, cap, "byte %lu: an escape the syntax does not have "
              "(a backslash makes one of \\.[](){}|*+?^$-/ literal, and "
              "\\d, \\w, \\s are classes)", (unsigned long)at);
        return NQEDEC;
      }
      break;
    default:
      break;
    }
    if (natom > 1) {
      natom--;
      emit(o, PCAT, 0, 0);
    }
    emit(o, t, c, k);
    natom++;
  }
  if (depth > 0) {
    qdwhy(why, cap, "byte %lu: ( without its )",
          (unsigned long)sat[depth - 1]);
    return NQEDEC;
  }
  if (natom == 0) {
    qdwhy(why, cap, n ? "byte %lu: an empty alternative at the end"
                      : "an empty pattern (byte %lu)",
          (unsigned long)n);
    return NQEDEC;
  }
  while (--natom > 0)
    emit(o, PCAT, 0, 0);
  for (; nalt > 0; nalt--)
    emit(o, PALT, 0, 0);
  return NQOK;
}

/* ---- Thompson's construction ---- */

/* a dangling exit of a fragment: state * 2, plus 1 for its y */
static size_t *slot(qdrx *x, size_t sl) {
  return sl & 1 ? &x->s[sl >> 1].y : &x->s[sl >> 1].x;
}

static size_t one(qdrx *x, size_t st, size_t which) {
  size_t sl = st * 2 + which;
  *slot(x, sl) = NOS;
  return sl;
}

static void patch(qdrx *x, size_t l, size_t to) {
  while (l != NOS) {
    size_t *f = slot(x, l), nx = *f;
    *f = to;
    l = nx;
  }
}

static size_t join(qdrx *x, size_t a, size_t b) {
  size_t l = a;
  if (a == NOS)
    return b;
  while (*slot(x, l) != NOS)
    l = *slot(x, l);
  *slot(x, l) = b;
  return a;
}

static size_t state(qdrx *x, int op, uint32_t c, size_t k) {
  rxst *s = &x->s[x->ns];
  s->op = op;
  s->c = c;
  s->k = k;
  s->x = s->y = NOS;
  return x->ns++;
}

typedef struct {
  size_t start, out;
} rxfrag;

static void build(qdrx *x, const rxpost *o, rxfrag *fs) {
  size_t i, sp = 0, st;
  rxfrag a, b;
  for (i = 0; i < o->n; i++) {
    const rxtok *t = &o->t[i];
    switch (t->t) {
    case PCAT:
      b = fs[--sp];
      a = fs[--sp];
      patch(x, a.out, b.start);
      fs[sp].start = a.start;
      fs[sp++].out = b.out;
      break;
    case PALT:
      b = fs[--sp];
      a = fs[--sp];
      st = state(x, XSPLIT, 0, 0);
      x->s[st].x = a.start;
      x->s[st].y = b.start;
      fs[sp].start = st;
      fs[sp++].out = join(x, a.out, b.out);
      break;
    case PQUES:
      a = fs[--sp];
      st = state(x, XSPLIT, 0, 0);
      x->s[st].x = a.start;
      fs[sp].start = st;
      fs[sp++].out = join(x, a.out, one(x, st, 1));
      break;
    case PSTAR:
    case PPLUS:
      a = fs[--sp];
      st = state(x, XSPLIT, 0, 0);
      x->s[st].x = a.start;
      patch(x, a.out, st);
      fs[sp].start = t->t == PSTAR ? st : a.start;
      fs[sp++].out = one(x, st, 1);
      break;
    default:
      st = state(x, t->t, t->c, t->k);
      fs[sp].start = st;
      fs[sp++].out = one(x, st, 0);
      break;
    }
  }
  a = fs[--sp];
  st = state(x, XMATCH, 0, 0);
  patch(x, a.out, st);
  x->start = a.start;
}

void qdrxfree(qdrx *x) {
  if (x == NULL)
    return;
  qdfree(x->s);
  qdfree(x->r);
  qdfree(x->cl);
  qdfree(x->cur);
  qdfree(x->nxt);
  qdfree(x->stk);
  qdfree(x->mark);
  qdfree(x);
}

int qdrxcomp(const char *p, size_t n, qdrx **out, char *why, size_t cap) {
  qdrx *x;
  rxpost o;
  rxfrag *fs = NULL;
  size_t nt = 2 * n + 4, i;
  int rc;
  if (out == NULL || (p == NULL && n))
    return NQEARG;
  *out = NULL;
  if (n > RXMAX) {
    qdwhy(why, cap, "a pattern is at most %d bytes", RXMAX);
    return NQEDEC;
  }
  if (!qdutf8(p, n)) {
    qdwhy(why, cap, "not UTF-8 without NUL");
    return NQEDEC;
  }
  if ((x = (qdrx *)qdmal(sizeof *x)) == NULL)
    return NQEMEM;
  memset(x, 0, sizeof *x);
  /* every pattern byte gives at most one token and one concatenation,
   * a class at most four ranges per byte, a token at most one state */
  o.t = (rxtok *)qdmal(nt * sizeof *o.t);
  o.n = 0;
  x->r = (rxrng *)qdmal((4 * n + 4) * sizeof *x->r);
  x->cl = (rxcls *)qdmal((n + 1) * sizeof *x->cl);
  x->s = (rxst *)qdmal((nt + 1) * sizeof *x->s);
  fs = (rxfrag *)qdmal(nt * sizeof *fs);
  if (o.t == NULL || x->r == NULL || x->cl == NULL || x->s == NULL ||
      fs == NULL) {
    rc = NQEMEM;
    goto out;
  }
  if ((rc = topost(x, p, n, &o, why, cap)) != NQOK)
    goto out;
  build(x, &o, fs);
  x->cur = (size_t *)qdmal(x->ns * sizeof *x->cur);
  x->nxt = (size_t *)qdmal(x->ns * sizeof *x->nxt);
  x->stk = (size_t *)qdmal((2 * x->ns + 1) * sizeof *x->stk);
  x->mark = (size_t *)qdmal(x->ns * sizeof *x->mark);
  if (x->cur == NULL || x->nxt == NULL || x->stk == NULL || x->mark == NULL) {
    rc = NQEMEM;
    goto out;
  }
  for (i = 0; i < x->ns; i++)
    x->mark[i] = 0;
  x->gen = 0;
out:
  qdfree(o.t);
  qdfree(fs);
  if (rc != NQOK)
    qdrxfree(x);
  else
    *out = x;
  return rc;
}

/* ---- the run ---- */

/* adds state st and every state reachable from it without reading a
 * character to the list l (each once per position: the marks); 1 when
 * the match state is among them */
static int add(qdrx *x, size_t *l, size_t *nl, size_t st, int bol, int eol) {
  size_t sp = 0;
  x->stk[sp++] = st;
  while (sp > 0) {
    size_t k = x->stk[--sp];
    const rxst *e = &x->s[k];
    if (x->mark[k] == x->gen)
      continue;
    x->mark[k] = x->gen;
    switch (e->op) {
    case XMATCH:
      return 1;
    case XSPLIT:
      x->stk[sp++] = e->y;
      x->stk[sp++] = e->x;
      break;
    case XBOL:
      if (bol)
        x->stk[sp++] = e->x;
      break;
    case XEOL:
      if (eol)
        x->stk[sp++] = e->x;
      break;
    default:
      l[(*nl)++] = k;
      break;
    }
  }
  return 0;
}

static int step(const qdrx *x, const rxst *e, uint32_t c) {
  size_t i;
  int hit = 0;
  if (e->op == XANY)
    return 1;
  if (e->op == XCHR)
    return e->c == c;
  for (i = 0; i < x->cl[e->k].n && !hit; i++) {
    const rxrng *r = &x->r[x->cl[e->k].at + i];
    hit = c >= r->lo && c <= r->hi;
  }
  return hit != x->cl[e->k].neg;
}

int qdrxrun(qdrx *x, const char *s, size_t n) {
  size_t i = 0, nc = 0, nn, k, *t;
  x->gen++;
  for (;;) {
    uint32_t c;
    /* a match may start at any position */
    if (add(x, x->cur, &nc, x->start, i == 0, i == n))
      return 1;
    if (i == n)
      return 0;
    c = dec(s, n, &i);
    x->gen++;
    nn = 0;
    for (k = 0; k < nc; k++) {
      const rxst *e = &x->s[x->cur[k]];
      if (step(x, e, c) && add(x, x->nxt, &nn, e->x, 0, i == n))
        return 1;
    }
    t = x->cur;
    x->cur = x->nxt;
    x->nxt = t;
    nc = nn;
  }
}
