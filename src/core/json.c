/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Strict JSON reader (RFC 8259) without recursion: containers being filled
 * sit on an explicit stack of at most NQJDEPTH entries. */
#include "noqtis.h"
#include "core/int.h"
#include "core/json.h"

#include <stdio.h>
#include <string.h>

/* ---- nodes ---- */

static nqjs *mknode(nqjtype t) {
  nqjs *v = (nqjs *)nqmal(sizeof *v);
  if (v != NULL) {
    memset(v, 0, sizeof *v);
    v->type = t;
  }
  return v;
}

void nqjfree(nqjs *v) {
  size_t i;
  if (v == NULL) {
    return;
  }
  /* depth is bounded by NQJDEPTH, so this recursion is too */
  for (i = 0; i < v->n; i++) {
    nqjfree(v->kids[i]);
    if (v->keys != NULL) {
      nqfree(v->keys[i], v->klen[i] + 1);
    }
  }
  nqfree(v->kids, v->cap * sizeof *v->kids);
  nqfree(v->keys, v->cap * sizeof *v->keys);
  nqfree(v->klen, v->cap * sizeof *v->klen);
  nqfree(v->str, v->len + 1);
  nqfree(v, sizeof *v);
}

/* Grows a container's arrays (no realloc: the hook has none). */
static int grow(nqjs *c) {
  size_t ncap = c->cap ? c->cap * 2 : 8;
  nqjs **k;
  char **ks = NULL;
  size_t *kl = NULL;
  if (ncap > ((size_t)-1) / sizeof(void *) / 2) {
    return NQELIM;
  }
  k = (nqjs **)nqmal(ncap * sizeof *k);
  if (k == NULL) {
    return NQEMEM;
  }
  if (c->type == NQJOBJ) {
    ks = (char **)nqmal(ncap * sizeof *ks);
    kl = (size_t *)nqmal(ncap * sizeof *kl);
    if (ks == NULL || kl == NULL) {
      nqfree(k, ncap * sizeof *k);
      nqfree(ks, ncap * sizeof *ks);
      nqfree(kl, ncap * sizeof *kl);
      return NQEMEM;
    }
  }
  if (c->n) {
    memcpy(k, c->kids, c->n * sizeof *k);
    if (ks != NULL) {
      memcpy(ks, c->keys, c->n * sizeof *ks);
      memcpy(kl, c->klen, c->n * sizeof *kl);
    }
  }
  nqfree(c->kids, c->cap * sizeof *c->kids);
  nqfree(c->keys, c->cap * sizeof *c->keys);
  nqfree(c->klen, c->cap * sizeof *c->klen);
  c->kids = k;
  c->keys = ks;
  c->klen = kl;
  c->cap = ncap;
  return NQOK;
}

/* Adds v to container c (with key for an object); on error frees v and
 * key. Duplicate keys are refused. */
static int addkid(nqjs *c, nqjs *v, char *key, size_t klen) {
  size_t i;
  int rc;
  if (c->type == NQJOBJ) {
    for (i = 0; i < c->n; i++) {
      if (c->klen[i] == klen && memcmp(c->keys[i], key, klen) == 0) {
        nqjfree(v);
        nqfree(key, klen + 1);
        return NQEDEC;
      }
    }
  }
  if (c->n == c->cap && (rc = grow(c)) != NQOK) {
    nqjfree(v);
    nqfree(key, klen + 1);
    return rc;
  }
  c->kids[c->n] = v;
  if (c->type == NQJOBJ) {
    c->keys[c->n] = key;
    c->klen[c->n] = klen;
  }
  c->n++;
  return NQOK;
}

/* ---- lexing ---- */

typedef struct {
  const unsigned char *s;
  size_t len;
  size_t pos;
} lexer;

static void skipws(lexer *lx) {
  while (lx->pos < lx->len) {
    unsigned char c = lx->s[lx->pos];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
      break;
    }
    lx->pos++;
  }
}

static int hexval(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int rd4hex(lexer *lx, uint32_t *u) {
  int i, h;
  uint32_t v = 0;
  if (lx->len - lx->pos < 4) {
    return NQEDEC;
  }
  for (i = 0; i < 4; i++) {
    h = hexval(lx->s[lx->pos + (size_t)i]);
    if (h < 0) {
      return NQEDEC;
    }
    v = (v << 4) | (uint32_t)h;
  }
  lx->pos += 4;
  *u = v;
  return NQOK;
}

static size_t pututf8(unsigned char *o, uint32_t u) {
  if (u < 0x80) {
    o[0] = (unsigned char)u;
    return 1;
  }
  if (u < 0x800) {
    o[0] = (unsigned char)(0xc0 | (u >> 6));
    o[1] = (unsigned char)(0x80 | (u & 0x3f));
    return 2;
  }
  if (u < 0x10000) {
    o[0] = (unsigned char)(0xe0 | (u >> 12));
    o[1] = (unsigned char)(0x80 | ((u >> 6) & 0x3f));
    o[2] = (unsigned char)(0x80 | (u & 0x3f));
    return 3;
  }
  o[0] = (unsigned char)(0xf0 | (u >> 18));
  o[1] = (unsigned char)(0x80 | ((u >> 12) & 0x3f));
  o[2] = (unsigned char)(0x80 | ((u >> 6) & 0x3f));
  o[3] = (unsigned char)(0x80 | (u & 0x3f));
  return 4;
}

/* Length of the well-formed UTF-8 sequence at s (RFC 3629: no overlongs,
 * no surrogates, at most U+10FFFF), or 0. */
static size_t utf8len(const unsigned char *s, size_t n) {
  unsigned char c = s[0];
  if (c < 0x80) return 1;
  if (c >= 0xc2 && c <= 0xdf) {
    return (n >= 2 && (s[1] & 0xc0) == 0x80) ? 2 : 0;
  }
  if (c >= 0xe0 && c <= 0xef) {
    if (n < 3 || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80) return 0;
    if (c == 0xe0 && s[1] < 0xa0) return 0; /* overlong */
    if (c == 0xed && s[1] > 0x9f) return 0; /* surrogate */
    return 3;
  }
  if (c >= 0xf0 && c <= 0xf4) {
    if (n < 4 || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 ||
        (s[3] & 0xc0) != 0x80) return 0;
    if (c == 0xf0 && s[1] < 0x90) return 0; /* overlong */
    if (c == 0xf4 && s[1] > 0x8f) return 0; /* above U+10FFFF */
    return 4;
  }
  return 0;
}

/* Reads a string (lx->pos at its opening quote) into a fresh buffer. */
static int rdstr(lexer *lx, char **out, size_t *outlen) {
  size_t start = ++lx->pos, cap, k = 0;
  unsigned char *o;
  /* the decoded text is never longer than the raw text */
  while (lx->pos < lx->len && lx->s[lx->pos] != '"') {
    lx->pos += (lx->s[lx->pos] == '\\') ? 2 : 1;
  }
  if (lx->pos >= lx->len) {
    /* unterminated; a final backslash stepped one past the end */
    lx->pos = lx->len;
    return NQEDEC;
  }
  cap = lx->pos - start + 1;
  o = (unsigned char *)nqmal(cap);
  if (o == NULL) {
    return NQEMEM;
  }
  lx->pos = start;
  for (;;) {
    unsigned char c = lx->s[lx->pos];
    if (c == '"') {
      lx->pos++;
      break;
    }
    if (c < 0x20) {
      goto bad;
    }
    if (c == '\\') {
      unsigned char e = lx->s[lx->pos + 1];
      lx->pos += 2;
      switch (e) {
      case '"': o[k++] = '"'; break;
      case '\\': o[k++] = '\\'; break;
      case '/': o[k++] = '/'; break;
      case 'b': o[k++] = '\b'; break;
      case 'f': o[k++] = '\f'; break;
      case 'n': o[k++] = '\n'; break;
      case 'r': o[k++] = '\r'; break;
      case 't': o[k++] = '\t'; break;
      case 'u': {
        uint32_t u, lo;
        if (rd4hex(lx, &u) != NQOK) goto bad;
        if (u >= 0xdc00 && u <= 0xdfff) goto bad; /* lone low surrogate */
        if (u >= 0xd800 && u <= 0xdbff) {
          if (lx->len - lx->pos < 6 || lx->s[lx->pos] != '\\' ||
              lx->s[lx->pos + 1] != 'u') goto bad;
          lx->pos += 2;
          if (rd4hex(lx, &lo) != NQOK || lo < 0xdc00 || lo > 0xdfff) goto bad;
          u = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
        }
        k += pututf8(o + k, u);
        break;
      }
      default:
        goto bad;
      }
      continue;
    }
    {
      size_t m = utf8len(lx->s + lx->pos, lx->len - lx->pos);
      if (m == 0) goto bad;
      memcpy(o + k, lx->s + lx->pos, m);
      k += m;
      lx->pos += m;
    }
  }
  o[k] = 0;
  /* shrink to the decoded size so free sizes stay exact */
  {
    char *t = (char *)nqmal(k + 1);
    if (t == NULL) {
      nqfree(o, cap);
      return NQEMEM;
    }
    memcpy(t, o, k + 1);
    nqfree(o, cap);
    *out = t;
  }
  *outlen = k;
  return NQOK;
bad:
  nqfree(o, cap);
  return NQEDEC;
}

static int isdig(unsigned char c) { return c >= '0' && c <= '9'; }

/* Reads a number by the RFC 8259 grammar; keeps its text. */
static int rdnum(lexer *lx, nqjs **out) {
  size_t st = lx->pos, n;
  nqjs *v;
  if (lx->pos < lx->len && lx->s[lx->pos] == '-') lx->pos++;
  if (lx->pos >= lx->len) return NQEDEC;
  if (lx->s[lx->pos] == '0') {
    lx->pos++;
  } else if (lx->s[lx->pos] >= '1' && lx->s[lx->pos] <= '9') {
    while (lx->pos < lx->len && isdig(lx->s[lx->pos])) lx->pos++;
  } else {
    return NQEDEC;
  }
  if (lx->pos < lx->len && lx->s[lx->pos] == '.') {
    lx->pos++;
    if (lx->pos >= lx->len || !isdig(lx->s[lx->pos])) return NQEDEC;
    while (lx->pos < lx->len && isdig(lx->s[lx->pos])) lx->pos++;
  }
  if (lx->pos < lx->len && (lx->s[lx->pos] == 'e' || lx->s[lx->pos] == 'E')) {
    lx->pos++;
    if (lx->pos < lx->len && (lx->s[lx->pos] == '+' || lx->s[lx->pos] == '-'))
      lx->pos++;
    if (lx->pos >= lx->len || !isdig(lx->s[lx->pos])) return NQEDEC;
    while (lx->pos < lx->len && isdig(lx->s[lx->pos])) lx->pos++;
  }
  n = lx->pos - st;
  v = mknode(NQJNUM);
  if (v == NULL) return NQEMEM;
  v->str = (char *)nqmal(n + 1);
  if (v->str == NULL) {
    nqjfree(v);
    return NQEMEM;
  }
  memcpy(v->str, lx->s + st, n);
  v->str[n] = 0;
  v->len = n;
  *out = v;
  return NQOK;
}

static int rdword(lexer *lx, const char *w, nqjtype t, nqjs **out) {
  size_t n = strlen(w);
  if (lx->len - lx->pos < n || memcmp(lx->s + lx->pos, w, n) != 0) {
    return NQEDEC;
  }
  lx->pos += n;
  *out = mknode(t);
  return *out ? NQOK : NQEMEM;
}

/* ---- the parser: an explicit stack of open containers ---- */

int nqjparse(const char *buf, size_t len, nqjs **out, size_t *erroff) {
  lexer lx;
  nqjs *stk[NQJDEPTH];
  char *key = NULL; /* the key read for the next object member */
  size_t klen = 0;
  int depth = 0, rc = NQOK;
  nqjs *root = NULL, *v = NULL;

  if (buf == NULL || out == NULL) {
    return NQEARG;
  }
  *out = NULL;
  lx.s = (const unsigned char *)buf;
  lx.len = len;
  lx.pos = 0;

  for (;;) {
    unsigned char c;
    /* --- read one value, or open a container --- */
    skipws(&lx);
    if (lx.pos >= lx.len) { rc = NQEDEC; goto fail; }
    c = lx.s[lx.pos];
    v = NULL;
    if (c == '{' || c == '[') {
      if (depth == NQJDEPTH) { rc = NQELIM; goto fail; }
      lx.pos++;
      v = mknode(c == '{' ? NQJOBJ : NQJARR);
      if (v == NULL) { rc = NQEMEM; goto fail; }
      if (depth > 0) {
        rc = addkid(stk[depth - 1], v, key, klen);
        key = NULL;
        if (rc != NQOK) goto fail;
      } else {
        root = v;
      }
      stk[depth++] = v;
      skipws(&lx);
      /* empty container */
      if (lx.pos < lx.len && lx.s[lx.pos] == (c == '{' ? '}' : ']')) {
        lx.pos++;
        depth--;
        goto after;
      }
      if (c == '{') goto rdkey;
      continue; /* first element of an array */
    }
    if (c == '"') {
      char *s;
      size_t sl;
      if ((rc = rdstr(&lx, &s, &sl)) != NQOK) goto fail;
      v = mknode(NQJSTR);
      if (v == NULL) { nqfree(s, sl + 1); rc = NQEMEM; goto fail; }
      v->str = s;
      v->len = sl;
    } else if (c == '-' || isdig(c)) {
      if ((rc = rdnum(&lx, &v)) != NQOK) goto fail;
    } else if (c == 't') {
      if ((rc = rdword(&lx, "true", NQJTRUE, &v)) != NQOK) goto fail;
    } else if (c == 'f') {
      if ((rc = rdword(&lx, "false", NQJFALSE, &v)) != NQOK) goto fail;
    } else if (c == 'n') {
      if ((rc = rdword(&lx, "null", NQJNULL, &v)) != NQOK) goto fail;
    } else {
      rc = NQEDEC;
      goto fail;
    }
    if (depth > 0) {
      rc = addkid(stk[depth - 1], v, key, klen);
      key = NULL;
      if (rc != NQOK) goto fail;
    } else {
      root = v;
    }

  after:
    /* --- after a value: close containers or move to the next member --- */
    for (;;) {
      nqjs *top;
      if (depth == 0) {
        skipws(&lx);
        if (lx.pos != lx.len) { rc = NQEDEC; goto fail; }
        *out = root;
        return NQOK;
      }
      top = stk[depth - 1];
      skipws(&lx);
      if (lx.pos >= lx.len) { rc = NQEDEC; goto fail; }
      c = lx.s[lx.pos++];
      if (c == (top->type == NQJOBJ ? '}' : ']')) {
        depth--;
        continue;
      }
      if (c != ',') { rc = NQEDEC; goto fail; }
      if (top->type == NQJARR) break; /* next element */
      goto rdkey;
    }
    continue;

  rdkey:
    /* an object member: "key" ':' value */
    skipws(&lx);
    if (lx.pos >= lx.len || lx.s[lx.pos] != '"') { rc = NQEDEC; goto fail; }
    if ((rc = rdstr(&lx, &key, &klen)) != NQOK) { key = NULL; goto fail; }
    skipws(&lx);
    if (lx.pos >= lx.len || lx.s[lx.pos] != ':') { rc = NQEDEC; goto fail; }
    lx.pos++;
  }

fail:
  /* every node is attached (to root or a container) as soon as it is made,
   * so freeing root frees them all */
  if (key != NULL) nqfree(key, klen + 1);
  nqjfree(root);
  if (erroff != NULL) *erroff = lx.pos;
  return rc;
}

/* ---- lookups ---- */

const nqjs *nqjget(const nqjs *obj, const char *key) {
  size_t i, kl;
  if (obj == NULL || obj->type != NQJOBJ || key == NULL) return NULL;
  kl = strlen(key);
  for (i = 0; i < obj->n; i++) {
    if (obj->klen[i] == kl && memcmp(obj->keys[i], key, kl) == 0) {
      return obj->kids[i];
    }
  }
  return NULL;
}

const nqjs *nqjat(const nqjs *arr, size_t i) {
  if (arr == NULL || arr->type != NQJARR || i >= arr->n) return NULL;
  return arr->kids[i];
}

const char *nqjstr(const nqjs *v) {
  if (v == NULL || v->type != NQJSTR || strlen(v->str) != v->len) return NULL;
  return v->str;
}

int nqjint(const nqjs *v, int64_t *out) {
  size_t i = 0;
  int neg = 0;
  uint64_t acc = 0, lim;
  if (v == NULL || v->type != NQJNUM || out == NULL) return NQEARG;
  if (v->str[0] == '-') {
    neg = 1;
    i = 1;
  }
  lim = neg ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
  for (; i < v->len; i++) {
    unsigned d;
    if (!isdig((unsigned char)v->str[i])) return NQEDEC; /* '.', 'e' */
    d = (unsigned)(v->str[i] - '0');
    if (acc > (lim - d) / 10) return NQELIM;
    acc = acc * 10 + d;
  }
  if (neg) {
    *out = acc == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)acc;
  } else {
    *out = (int64_t)acc;
  }
  return NQOK;
}

int nqjbool(const nqjs *v) {
  if (v == NULL) return -1;
  if (v->type == NQJTRUE) return 1;
  if (v->type == NQJFALSE) return 0;
  return -1;
}

/* ---- files and hex ---- */

int nqreadf(const char *path, size_t maxlen, char **buf, size_t *len) {
  FILE *f;
  long sz;
  char *b;
  if (path == NULL || buf == NULL || len == NULL) return NQEARG;
  f = fopen(path, "rb");
  if (f == NULL) return NQEIO;
  if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
      fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NQEIO;
  }
  if ((unsigned long)sz > maxlen) {
    fclose(f);
    return NQELIM;
  }
  b = (char *)nqmal((size_t)sz + 1);
  if (b == NULL) {
    fclose(f);
    return NQEMEM;
  }
  if (fread(b, 1, (size_t)sz, f) != (size_t)sz) {
    nqfree(b, (size_t)sz + 1);
    fclose(f);
    return NQEIO;
  }
  fclose(f);
  b[sz] = 0;
  *buf = b;
  *len = (size_t)sz;
  return NQOK;
}

int nqunhex(const char *hex, size_t hexlen, uint8_t *out, size_t cap,
            size_t *outlen) {
  size_t i;
  if (hex == NULL || (out == NULL && hexlen != 0)) return NQEARG;
  if (hexlen % 2 != 0) return NQEDEC;
  if (hexlen / 2 > cap) return NQEBUF;
  for (i = 0; i < hexlen / 2; i++) {
    int hi = hexval((unsigned char)hex[2 * i]);
    int lo = hexval((unsigned char)hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return NQEDEC;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  if (outlen != NULL) *outlen = hexlen / 2;
  return NQOK;
}

void nqhex(const uint8_t *in, size_t len, char *out) {
  static const char dg[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    out[2 * i] = dg[in[i] >> 4];
    out[2 * i + 1] = dg[in[i] & 15];
  }
  out[2 * len] = 0;
}
