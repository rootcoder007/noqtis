/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * DSSE envelopes (Dead Simple Signing Envelope, the in-toto and SLSA
 * wrapper): the signature is over PAE(payloadType, payload) =
 *   "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
 * with the lengths in ASCII decimal, and the envelope is
 *   {"payload":b64,"payloadType":type,"signatures":[{"keyid":k,"sig":b64}]}
 * written canonically. keyid is the hex SHA-256 of the public key.
 */
#include <string.h>

#include "cap/cap.h"
#include "core/int.h"
#include "core/json.h"

static void dec(nqcbuf *b, size_t v) {
  char d[24];
  size_t i = sizeof d;
  do {
    d[--i] = (char)('0' + v % 10);
    v /= 10;
  } while (v != 0);
  nqcput(b, d + i, sizeof d - i);
}

/* PAE(type, payload) into b */
static int pae(nqcbuf *b, const char *type, const uint8_t *p, size_t n) {
  size_t tl = strlen(type);
  nqcputs(b, "DSSEv1 ");
  dec(b, tl);
  nqcputs(b, " ");
  nqcput(b, type, tl);
  nqcputs(b, " ");
  dec(b, n);
  nqcputs(b, " ");
  nqcput(b, (const char *)p, n);
  return b->err;
}

static int typeok(const char *t, size_t n) {
  size_t i;
  if (n == 0 || n > 255) return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)t[i];
    if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return 0;
  }
  return 1;
}

int nqdsse(nqsalg alg, const uint8_t *sk, size_t sklen, const uint8_t *pk,
           size_t pklen, const char *type, const uint8_t *payload, size_t n,
           char *out, size_t cap, size_t *outlen) {
  nqcbuf m, o;
  nqssz sz;
  uint8_t *sg = NULL, h[32];
  char *b = NULL, kid[65];
  size_t sn = 0, bn = 0;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (sk == NULL || pk == NULL || type == NULL || outlen == NULL ||
      (payload == NULL && n != 0) || (out == NULL && cap != 0) ||
      !typeok(type, strlen(type))) {
    return NQEARG;
  }
  rc = nqssize(alg, &sz);
  if (rc != NQOK) return rc;
  if (sklen != sz.sk || pklen != sz.pk) return NQEARG;
  memset(&m, 0, sizeof m);
  memset(&o, 0, sizeof o);
  rc = pae(&m, type, payload, n);
  if (rc != NQOK) goto out;
  sg = (uint8_t *)nqmal(sz.sig);
  bn = nqb64n(n > sz.sig ? n : sz.sig) + 1;
  b = (char *)nqmal(bn);
  if (sg == NULL || b == NULL) {
    rc = NQEMEM;
    goto out;
  }
  rc = nqsign(alg, sk, sklen, (const uint8_t *)m.p, m.n, NULL, 0, 0, sg,
              sz.sig, &sn);
  if (rc == NQOK)
    rc = nqvrfy(alg, pk, pklen, (const uint8_t *)m.p, m.n, NULL, 0, 0, sg,
                sn);
  if (rc == NQEVRFY) rc = NQEARG; /* the key pair does not match */
  if (rc != NQOK) goto out;
  nqhash(NQS256, pk, pklen, h, 32);
  nqhex(h, 32, kid);
  nqb64e(payload, n, b);
  nqcputs(&o, "{\"payload\":\"");
  nqcputs(&o, b);
  nqcputs(&o, "\",\"payloadType\":\"");
  nqcputs(&o, type);
  nqcputs(&o, "\",\"signatures\":[{\"keyid\":\"");
  nqcputs(&o, kid);
  nqcputs(&o, "\",\"sig\":\"");
  nqb64e(sg, sn, b);
  nqcputs(&o, b);
  nqcputs(&o, "\"}]}");
  rc = o.err;
  if (rc != NQOK) goto out;
  *outlen = o.n;
  if (cap < o.n) {
    rc = NQEBUF;
    goto out;
  }
  memcpy(out, o.p, o.n);
out:
  if (sg != NULL) nqfree(sg, sz.sig);
  if (b != NULL) nqfree(b, bn);
  nqcbfree(&m);
  nqcbfree(&o);
  return rc;
}

int nqdssevrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
               const char *env, size_t n, uint8_t *payload, size_t cap,
               size_t *outlen, char type[256]) {
  nqjs *v = NULL;
  const nqjs *pl, *pt, *ss;
  nqcbuf m;
  nqssz sz;
  uint8_t *p = NULL, *sg = NULL;
  size_t pn = 0, pcap = 0, i;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (type != NULL) type[0] = 0;
  if (pk == NULL || env == NULL || outlen == NULL ||
      (payload == NULL && cap != 0)) {
    return NQEARG;
  }
  rc = nqssize(alg, &sz);
  if (rc != NQOK) return rc;
  if (pklen != sz.pk) return NQEARG;
  memset(&m, 0, sizeof m);
  rc = nqjparse(env, n, &v, NULL);
  if (rc != NQOK) return rc == NQEMEM ? rc : NQEDEC;
  pl = nqjget(v, "payload");
  pt = nqjget(v, "payloadType");
  ss = nqjget(v, "signatures");
  if (v->type != NQJOBJ || pl == NULL || pl->type != NQJSTR || pt == NULL ||
      pt->type != NQJSTR || !typeok(pt->str, pt->len) || ss == NULL ||
      ss->type != NQJARR || ss->n == 0 || ss->n > 16) {
    rc = NQEDEC;
    goto out;
  }
  pcap = pl->len / 4 * 3 + 3;
  p = (uint8_t *)nqmal(pcap);
  sg = (uint8_t *)nqmal(sz.sig);
  if (p == NULL || sg == NULL) {
    rc = NQEMEM;
    goto out;
  }
  if (nqb64d(pl->str, pl->len, p, pcap, &pn) != NQOK) {
    rc = NQEDEC;
    goto out;
  }
  rc = pae(&m, pt->str, p, pn);
  if (rc != NQOK) goto out;
  /* any one signature of the envelope under pk is enough */
  rc = NQEVRFY;
  for (i = 0; i < ss->n && rc == NQEVRFY; i++) {
    const nqjs *e = nqjat(ss, i), *sv;
    size_t gn = 0;
    if (e == NULL || e->type != NQJOBJ) continue;
    sv = nqjget(e, "sig");
    if (sv == NULL || sv->type != NQJSTR ||
        nqb64d(sv->str, sv->len, sg, sz.sig, &gn) != NQOK) {
      continue;
    }
    if (nqvrfy(alg, pk, pklen, (const uint8_t *)m.p, m.n, NULL, 0, 0, sg,
               gn) == NQOK) {
      rc = NQOK;
    }
  }
  if (rc != NQOK) goto out;
  if (type != NULL) {
    memcpy(type, pt->str, pt->len);
    type[pt->len] = 0;
  }
  *outlen = pn;
  if (cap < pn) {
    rc = NQEBUF;
    goto out;
  }
  if (pn > 0) memcpy(payload, p, pn);
out:
  if (p != NULL) nqfree(p, pcap);
  if (sg != NULL) nqfree(sg, sz.sig);
  nqcbfree(&m);
  nqjfree(v);
  return rc;
}
