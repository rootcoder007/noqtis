/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqseal: lists the folder, writes noqtis.json (canonical JSON), signs its
 * exact bytes with the FIPS 204/205 context "noqtis-capsule-1" and writes
 * noqtis.sig. The folder must hold only regular files and folders with
 * portable names; anything else (a link, a device, a refused name, two
 * paths equal but for ASCII case) makes it NQEARG and nothing is
 * written. */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cap/cap.h"
#include "core/int.h"

/* SOURCE_DATE_EPOCH (reproducible builds) when set, else the clock;
 * -1 when SOURCE_DATE_EPOCH is not a plain decimal number. */
static int64_t now(void) {
  const char *e = getenv("SOURCE_DATE_EPOCH");
  int64_t v = 0;
  size_t i;
  if (e != NULL && e[0] != 0) {
    for (i = 0; e[i] != 0; i++) {
      if (e[i] < '0' || e[i] > '9' || i >= 12) return -1;
      v = v * 10 + (e[i] - '0');
    }
    return v;
  }
  return (int64_t)time(NULL);
}

static int foldcmp(const void *ctx, size_t a, size_t b) {
  const nqclist *l = (const nqclist *)ctx;
  return nqcfold(l->e[a].path, l->e[a].len, l->e[b].path, l->e[b].len);
}

/* every entry a regular file, no two equal but for ASCII case */
static int sealable(const nqclist *l) {
  size_t *idx, i;
  int rc;
  for (i = 0; i < l->n; i++) {
    if (l->e[i].kind != NQCREG) return NQEARG;
    if (l->e[i].size > NQCMAXINT) return NQELIM;
  }
  if (l->n < 2) return NQOK;
  idx = (size_t *)nqmal(l->n * sizeof(size_t));
  if (idx == NULL) return NQEMEM;
  for (i = 0; i < l->n; i++) idx[i] = i;
  rc = nqcsort(idx, l->n, foldcmp, l);
  for (i = 1; rc == NQOK && i < l->n; i++) {
    if (foldcmp(l, idx[i - 1], idx[i]) == 0) rc = NQEARG;
  }
  nqfree(idx, l->n * sizeof(size_t));
  return rc;
}

static int manifest(const char *dir, const nqclist *l, const char *ts,
                    const nqjs *meta, nqcbuf *m, int *sec) {
  size_t i;
  int rc = NQOK;
  nqcputs(m, "{\"created\":");
  nqcjstr(m, ts, strlen(ts));
  nqcputs(m, ",\"files\":[");
  for (i = 0; i < l->n; i++) {
    uint8_t s2[32], s3[32];
    char hx[65];
    uint64_t size = 0;
    rc = nqcdigx(dir, l->e[i].path, (uint64_t)-1, &size, s2, s3, sec);
    if (rc != NQOK) return rc;
    /* a secret key in the folder would ship with the capsule */
    if (*sec) return NQEARG;
    if (size > NQCMAXINT) return NQELIM;
    if (m->n > nqclim.man) return NQELIM; /* stop early */
    if (i > 0) nqcput(m, ",", 1);
    nqcputs(m, "{\"path\":");
    nqcjstr(m, l->e[i].path, l->e[i].len);
    nqhex(s2, 32, hx);
    nqcputs(m, ",\"sha256\":\"");
    nqcputs(m, hx);
    nqhex(s3, 32, hx);
    nqcputs(m, "\",\"sha3_256\":\"");
    nqcputs(m, hx);
    nqcputs(m, "\",\"size\":");
    nqcjint(m, size);
    nqcput(m, "}", 1);
  }
  nqcputs(m, "],\"format\":\"" NQCFMT "\"");
  if (meta != NULL) {
    nqcputs(m, ",\"meta\":");
    rc = nqcjval(m, meta);
    if (rc != NQOK) return rc;
  }
  nqcput(m, "}", 1);
  return m->err;
}

static int sealjson(nqcbuf *s, const char *an, const uint8_t *mh,
                    const uint8_t *pk, size_t pklen, const uint8_t *sig,
                    size_t siglen) {
  char hx[65];
  size_t bn = nqb64n(pklen > siglen ? pklen : siglen) + 1;
  char *b = (char *)nqmal(bn);
  if (b == NULL) return NQEMEM;
  nqcputs(s, "{\"alg\":");
  nqcjstr(s, an, strlen(an));
  nqcputs(s, ",\"context\":\"" NQCCTX "\",\"format\":\"" NQCSFMT "\"");
  nqhex(mh, 32, hx);
  nqcputs(s, ",\"manifest_sha256\":\"");
  nqcputs(s, hx);
  nqb64e(pk, pklen, b);
  nqcputs(s, "\",\"public_key\":\"");
  nqcputs(s, b);
  nqb64e(sig, siglen, b);
  nqcputs(s, "\",\"signature\":\"");
  nqcputs(s, b);
  nqcputs(s, "\"}");
  nqfree(b, bn);
  return s->err;
}

int nqcseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
            const uint8_t *pk, size_t pklen, const char *meta,
            const char *tsa, int64_t created, const uint8_t *rnd,
            size_t rndlen, int *why) {
  static const uint8_t ctx[] = NQCCTX;
  nqssz sz;
  const char *an;
  nqclist l;
  nqcbuf m, s;
  nqjs *mj = NULL;
  uint8_t *sig = NULL;
  uint8_t mh[32];
  size_t siglen = 0;
  char ts[21];
  int rc, sec = 0;
  if (why != NULL) *why = 0;
  if (dir == NULL || sk == NULL || pk == NULL) return NQEARG;
  /* a timestamp needs a request to a TSA over the network, which the
   * library does not make; the CLI is to add it (DESIGN.md, M10) */
  if (tsa != NULL) return NQENOSUP;
  if (nqssize(alg, &sz) != NQOK) return NQEARG;
  /* Ed25519 alone is not post-quantum: never a seal */
  if (alg == NQED25519) return NQENOSUP;
  an = nqsname(alg);
  if (an == NULL) return NQENOSUP;
  if (sklen != sz.sk || pklen != sz.pk) return NQEARG;
  if (nqctime(created, ts) != NQOK) return NQEARG;
  if (meta != NULL) {
    size_t ml = strlen(meta);
    if (ml > NQCMETAMAX) {
      if (why != NULL) *why = NQCLMETA;
      return NQELIM;
    }
    rc = nqjparse(meta, ml, &mj, NULL);
    if (rc != NQOK) return rc;
    if (mj->type != NQJOBJ) {
      nqjfree(mj);
      return NQEDEC;
    }
  }
  memset(&m, 0, sizeof m);
  memset(&s, 0, sizeof s);
  rc = nqcwalk(dir, &l);
  if (rc != NQOK) {
    if (rc == NQELIM && why != NULL) *why = l.lim;
    nqjfree(mj);
    return rc;
  }
  rc = sealable(&l);
  if (rc == NQOK) rc = manifest(dir, &l, ts, mj, &m, &sec);
  if (rc == NQEARG && sec && why != NULL) *why = NQCLSEC;
  if (rc == NQOK && m.n > nqclim.man) rc = NQELIM;
  if (rc == NQELIM && m.n > nqclim.man && why != NULL) *why = NQCLMAN;
  if (rc == NQOK) rc = nqhash(NQS256, (const uint8_t *)m.p, m.n, mh, 32);
  if (rc == NQOK) {
    sig = (uint8_t *)nqmal(sz.sig);
    if (sig == NULL) rc = NQEMEM;
  }
  if (rc == NQOK) {
    if (rnd != NULL) {
      rc = nqsignd(alg, sk, sklen, (const uint8_t *)m.p, m.n, ctx,
                   sizeof ctx - 1, 0, rnd, rndlen, sig, sz.sig, &siglen);
    } else {
      rc = nqsign(alg, sk, sklen, (const uint8_t *)m.p, m.n, ctx,
                  sizeof ctx - 1, 0, sig, sz.sig, &siglen);
    }
  }
  /* sk and pk must be one key pair: a seal that cannot verify is never
   * written */
  if (rc == NQOK && nqvrfy(alg, pk, pklen, (const uint8_t *)m.p, m.n, ctx,
                           sizeof ctx - 1, 0, sig, siglen) != NQOK) {
    rc = NQEARG;
  }
  if (rc == NQOK) rc = sealjson(&s, an, mh, pk, pklen, sig, siglen);
  if (rc == NQOK) rc = nqcwrite(dir, NQCMAN, m.p, m.n);
  if (rc == NQOK) rc = nqcwrite(dir, NQCSIG, s.p, s.n);
  nqfree(sig, sz.sig);
  nqcbfree(&m);
  nqcbfree(&s);
  nqclfree(&l);
  nqjfree(mj);
  return rc;
}

int nqseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
           const uint8_t *pk, size_t pklen, const char *meta,
           const char *tsa) {
  int64_t t = now();
  if (t < 0) return NQEARG;
  return nqcseal(dir, alg, sk, sklen, pk, pklen, meta, tsa, t, NULL, 0,
                 NULL);
}
