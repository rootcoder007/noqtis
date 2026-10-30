/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * Key statements (noqtis-keys-1): the holder of a signing key says that
 * it was replaced by another (a rotation, signed by both keys) or must no
 * longer be trusted (a revocation), from a given time. nqchkx follows
 * them from the trusted key (see chk.c, kchain).
 */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"

/* 0 when s (n bytes) is not YYYY-MM-DDTHH:MM:SSZ, else the time in *t */
int nqctparse(const char *s, size_t n, int64_t *t) {
  int64_t y, m, d, era, yoe, doy, doe, days;
  int i;
  if (n != 20 || !nqctchk(s, n)) return 0;
  for (i = 0; i < 19; i++) {
    if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 &&
        (s[i] < '0' || s[i] > '9')) {
      return 0;
    }
  }
#define D2(k) ((int64_t)(s[k] - '0') * 10 + (s[(k) + 1] - '0'))
  y = D2(0) * 100 + D2(2);
  m = D2(5);
  d = D2(8);
  if (D2(17) > 59) return 0; /* no leap second in a statement */
  /* days from 1970-01-01, the inverse of nqctime */
  y -= m <= 2;
  era = y / 400;
  yoe = y - era * 400;
  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  days = era * 146097 + doe - 719468;
  *t = days * 86400 + D2(11) * 3600 + D2(14) * 60 + D2(17);
#undef D2
  return *t >= 0; /* 1970 and after, as nqctime writes */
}

/* a statement in canonical order: with sig NULL its signed part (every
 * field but the signatures), else the whole of it */
int nqckbody(nqcbuf *b, const char *an, const char *at, const char *pkb,
             int rotate, const char *nan, const char *npkb,
             const char *reason, const char *nsig, const char *sig) {
  nqcputs(b, "{\"alg\":");
  nqcjstr(b, an, strlen(an));
  nqcputs(b, ",\"at\":\"");
  nqcputs(b, at);
  nqcputs(b, "\",\"format\":\"" NQCKFMT "\",\"key\":\"");
  nqcputs(b, pkb);
  nqcputs(b, rotate ? "\",\"kind\":\"rotate\"" : "\",\"kind\":\"revoke\"");
  if (rotate) {
    nqcputs(b, ",\"new_alg\":");
    nqcjstr(b, nan, strlen(nan));
    nqcputs(b, ",\"new_key\":\"");
    nqcputs(b, npkb);
    nqcputs(b, "\"");
    if (sig != NULL) {
      nqcputs(b, ",\"new_signature\":\"");
      nqcputs(b, nsig);
      nqcputs(b, "\"");
    }
  }
  nqcputs(b, ",\"reason\":");
  nqcjstr(b, reason, strlen(reason));
  if (sig != NULL) {
    nqcputs(b, ",\"signature\":\"");
    nqcputs(b, sig);
    nqcputs(b, "\"}");
  }
  return b->err;
}

/* sign the body with one key, check it, base64 into a new buffer */
static int sig64(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, const nqcbuf *body,
                 char **out) {
  nqssz sz;
  uint8_t *sg;
  size_t n = 0;
  int rc = nqssize(alg, &sz);
  *out = NULL;
  if (rc != NQOK) return rc;
  sg = (uint8_t *)nqmal(sz.sig);
  if (sg == NULL) return NQEMEM;
  rc = nqsign(alg, sk, sklen, (const uint8_t *)body->p, body->n,
              (const uint8_t *)NQCKFMT, strlen(NQCKFMT), 0, sg, sz.sig, &n);
  /* a statement is checked before it is given out, as a seal is */
  if (rc == NQOK)
    rc = nqvrfy(alg, pk, pklen, (const uint8_t *)body->p, body->n,
                (const uint8_t *)NQCKFMT, strlen(NQCKFMT), 0, sg, n);
  if (rc == NQEVRFY) rc = NQEARG; /* the key pair does not match */
  if (rc == NQOK) {
    *out = (char *)nqmal(nqb64n(n) + 1);
    if (*out == NULL)
      rc = NQEMEM;
    else
      nqb64e(sg, n, *out);
  }
  nqfree(sg, sz.sig);
  return rc;
}

static int pq(nqsalg alg) {
  nqssz sz;
  return alg != NQED25519 && nqssize(alg, &sz) == NQOK;
}

int nqkstmt(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *pk,
            size_t pklen, nqsalg nalg, const uint8_t *nsk, size_t nsklen,
            const uint8_t *npk, size_t npklen, int64_t at,
            const char *reason, char *out, size_t cap, size_t *outlen) {
  nqcbuf b, o;
  nqssz sz, nsz;
  char ts[21], *pkb = NULL, *npkb = NULL, *s1 = NULL, *s2 = NULL;
  const char *rs = reason != NULL ? reason : "";
  int rot = npk != NULL, rc;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || pk == NULL || outlen == NULL ||
      (out == NULL && cap != 0) || (rot && nsk == NULL) ||
      (!rot && nsk != NULL)) {
    return NQEARG;
  }
  /* statements are about post-quantum seal keys (Ed25519 alone is not) */
  if (!pq(alg) || (rot && !pq(nalg))) return NQENOSUP;
  if (nqssize(alg, &sz) != NQOK || pklen != sz.pk || sklen != sz.sk)
    return NQEARG;
  if (rot && (nqssize(nalg, &nsz) != NQOK || npklen != nsz.pk ||
              nsklen != nsz.sk ||
              (nalg == alg && npklen == pklen &&
               memcmp(npk, pk, pklen) == 0))) {
    return NQEARG;
  }
  if (strlen(rs) > 255 || (rs[0] != '\0' && !nqcinok(rs, strlen(rs))))
    return NQEARG;
  if (nqctime(at, ts) != NQOK) return NQEARG;
  memset(&b, 0, sizeof b);
  memset(&o, 0, sizeof o);
  pkb = (char *)nqmal(nqb64n(pklen) + 1);
  if (rot) npkb = (char *)nqmal(nqb64n(npklen) + 1);
  if (pkb == NULL || (rot && npkb == NULL)) {
    rc = NQEMEM;
    goto out;
  }
  nqb64e(pk, pklen, pkb);
  if (rot) nqb64e(npk, npklen, npkb);
  rc = nqckbody(&b, nqsname(alg), ts, pkb, rot, rot ? nqsname(nalg) : NULL,
                npkb, rs, NULL, NULL);
  if (rc != NQOK) goto out;
  rc = sig64(alg, sk, sklen, pk, pklen, &b, &s1);
  if (rc == NQOK && rot) rc = sig64(nalg, nsk, nsklen, npk, npklen, &b, &s2);
  if (rc != NQOK) goto out;
  /* the whole statement: the signatures in their canonical places */
  rc = nqckbody(&o, nqsname(alg), ts, pkb, rot, rot ? nqsname(nalg) : NULL,
                npkb, rs, s2, s1);
  if (rc != NQOK) goto out;
  *outlen = o.n;
  if (cap < o.n) {
    rc = NQEBUF;
    goto out;
  }
  memcpy(out, o.p, o.n);
out:
  nqcbfree(&b);
  nqcbfree(&o);
  if (pkb != NULL) nqfree(pkb, nqb64n(pklen) + 1);
  if (npkb != NULL) nqfree(npkb, nqb64n(npklen) + 1);
  if (s1 != NULL) nqfree(s1, strlen(s1) + 1);
  if (s2 != NULL) nqfree(s2, strlen(s2) + 1);
  return rc;
}
