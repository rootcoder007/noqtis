/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The TLS 1.3 client's public functions (noqtis.h, nqtl*). They exist in
 * every build; without the CMake option NQTLS they return NQENOSUP and
 * the client is reachable only from the tests, through nqtlmk. */
#include <string.h>

#include "core/int.h"
#include "tls/tls.h"
#include "xdh/xdh.h"

/* a host name noqtis will put in SNI and match: ASCII letters, digits
 * and hyphens in labels of 1 to 63, at most 253 in all; lower-cased */
static int hostok(const char *h, char *out) {
  size_t n = strlen(h), i, lab = 0;
  if (n > 0 && h[n - 1] == '.') n--; /* one trailing dot */
  if (n == 0 || n > 253) return 0;
  for (i = 0; i < n; i++) {
    char c = h[i];
    if (c == '.') {
      if (lab == 0 || h[i - 1] == '-') return 0;
      lab = 0;
    } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '-' || (c >= 'A' && c <= 'Z')) {
      if (lab == 0 && c == '-') return 0;
      if (++lab > 63) return 0;
    } else {
      return 0;
    }
    out[i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
  }
  if (lab == 0 || h[n - 1] == '-') return 0;
  out[n] = '\0';
  return 1;
}

int nqtlmk(nqtls **out, const char *host, const uint8_t *ca, size_t calen,
           const nqtlio *io) {
  nqtls *t;
  int rc;
  if (out == NULL) return NQEARG;
  *out = NULL;
  if (host == NULL || io == NULL || io->wr == NULL || io->rd == NULL ||
      (ca == NULL && calen > 0)) {
    return NQEARG;
  }
  if (strlen(host) >= sizeof t->host) return NQEARG;
  t = (nqtls *)nqmal(sizeof *t);
  if (t == NULL) return NQEMEM;
  memset(t, 0, sizeof *t);
  t->io = *io;
  t->ip = nqtlip(host, t->ipb);
  if (t->ip != 0) {
    memcpy(t->host, host, strlen(host) + 1);
  } else if (!hostok(host, t->host)) {
    nqtlfree(t);
    return NQEARG;
  }
  t->hmcap = 8192;
  t->hm = (uint8_t *)nqmal(t->hmcap);
  if (t->hm == NULL) {
    nqtlfree(t);
    return NQEMEM;
  }
  if (calen > 0 && (rc = nqtlca(t, ca, calen)) != NQOK) {
    nqtlfree(t);
    return rc;
  }
  *out = t;
  return NQOK;
}

#ifdef NQTEST
void nqtlhook(nqtls *t, const nqtlhk *hk) {
  t->hk = *hk;
}
#else
const nqtlhk nqtlhk0 = {0}; /* MSVC C4132: a const object is initialised */
#endif

int nqtlw(nqtls *t, const uint8_t *b, size_t n) {
  if (t == NULL || (b == NULL && n > 0)) return NQEARG;
  if (t->err != 0) return t->err;
  if (t->st != NQTLUP || t->sent) return NQESTATE;
  if (n == 0) return NQOK;
  return nqtlsend(t, NQTLAPP, b, n);
}

int nqtlr(nqtls *t, uint8_t *b, size_t cap, size_t *got) {
  const uint8_t *m;
  size_t n;
  int rc, have;
  if (got != NULL) *got = 0;
  if (t == NULL || b == NULL || cap == 0 || got == NULL) return NQEARG;
  if (t->err != 0) return t->err;
  if (t->st != NQTLUP) return NQESTATE;
  for (;;) {
    if (t->eof) return NQOK;
    if (t->pt == NQTLAPP && t->pn > 0) {
      size_t c = t->pn < cap ? t->pn : cap;
      memcpy(b, t->rb + 5 + t->pp, c);
      t->pp += c;
      t->pn -= c;
      *got = c;
      return NQOK;
    }
    if ((rc = nqtlrec(t)) != NQOK) return rc;
    if (t->eof) return NQOK;
    /* post-handshake messages, as whole messages arrive */
    if (t->pt == NQTLHS) {
      if ((rc = nqtlpush(t)) != NQOK) return rc;
      for (;;) {
        if ((rc = nqtlpop(t, &m, &n, &have)) != NQOK) return rc;
        if (!have) break;
        if ((rc = nqtlpost(t, m, n)) != NQOK) return rc;
      }
    }
  }
}

int nqtle(nqtls *t) {
  static const uint8_t cn[2] = {1, 0};
  int rc;
  if (t == NULL) return NQEARG;
  if (t->err != 0) return t->err;
  if (t->sent) return NQOK;
  if (t->st != NQTLUP) return NQESTATE;
  rc = nqtlsend(t, NQTLALERT, cn, 2);
  t->sent = 1;
  return rc;
}

#ifdef NQTLSON
#define ON 1
#else
#define ON 0
#endif

int nqtlnew(nqtls **t, const char *host, const uint8_t *ca, size_t calen,
            const nqtlio *io) {
  if (t != NULL) *t = NULL;
  if (!ON) return NQENOSUP;
  if (ca == NULL || calen == 0) return NQEARG;
  return nqtlmk(t, host, ca, calen, io);
}

int nqtlhs(nqtls *t) {
  if (!ON) return NQENOSUP;
  if (t == NULL) return NQEARG;
  return nqtlhand(t);
}

int nqtlwr(nqtls *t, const uint8_t *b, size_t n) {
  /* used whether or not ON is 0 (MSVC's C4100) */
  (void)t;
  (void)b;
  (void)n;
  return ON ? nqtlw(t, b, n) : NQENOSUP;
}

int nqtlrd(nqtls *t, uint8_t *b, size_t cap, size_t *got) {
  if (!ON) {
    if (got != NULL) *got = 0;
    return NQENOSUP;
  }
  return nqtlr(t, b, cap, got);
}

int nqtlend(nqtls *t) {
  (void)t;
  return ON ? nqtle(t) : NQENOSUP;
}

const char *nqtlwhy(const nqtls *t) {
  if (!ON) return "noqtis was built without NQTLS";
  if (t == NULL) return "";
  return t->why;
}

void nqtlfree(nqtls *t) {
  if (t == NULL) return;
  if (t->ab != NULL) nqfree(t->ab, t->abn);
  if (t->anc != NULL) nqfree(t->anc, t->ancap * sizeof *t->anc);
  if (t->kdk != NULL) nqfree(t->kdk, NQHYBSK);
  if (t->hm != NULL) nqfree(t->hm, t->hmcap);
  if (t->cm != NULL) nqfree(t->cm, t->cmn);
  nqfree(t, sizeof *t);
}
