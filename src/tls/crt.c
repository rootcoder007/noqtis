/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The server's certificate for the TLS 1.3 client: trust anchors from a
 * PEM bundle, the path (src/der, nqchain: names, signatures, validity,
 * basicConstraints, keyUsage, serverAuth), the host name (RFC 6125
 * section 6: DNS names in subjectAltName only, never the subject's
 * common name; a wildcard only as the whole leftmost label, matching
 * one label, and never over fewer than two more), and the
 * CertificateVerify signature (RFC 8446 section 4.4.3) through src/cls.
 *
 * Not checked: revocation (no OCSP stapling, no CRL fetch), name
 * constraints and certificate policies (a certificate carrying either as
 * a critical extension is refused by nqcprs, so a path through one
 * fails), Certificate Transparency. */
#include <string.h>

#include "cap/cap.h"
#include "cls/cls.h"
#include "core/int.h"
#include "tls/tls.h"

#define CAMAX ((size_t)16 << 20) /* the largest bundle read */
#define NCAMAX 4096              /* certificates in it */

static const char beg[] = "-----BEGIN CERTIFICATE-----";
static const char end[] = "-----END CERTIFICATE-----";

/* the next occurrence of s (length sl) in b[i..n), or n */
static size_t find(const uint8_t *b, size_t n, size_t i, const char *s,
                   size_t sl) {
  for (; i + sl <= n; i++) {
    if (memcmp(b + i, s, sl) == 0) return i;
  }
  return n;
}

int nqtlca(nqtls *t, const uint8_t *b, size_t n) {
  size_t i = 0, k = 0, cap = 0, used = 0, bl = sizeof beg - 1,
         el = sizeof end - 1;
  char *txt = NULL;
  int rc = NQOK;
  if (b == NULL || n == 0) return NQEARG;
  if (n > CAMAX) return NQELIM;
  /* one DER certificate */
  if (b[0] == 0x30) {
    t->ab = (uint8_t *)nqmal(n);
    t->anc = (nqcert *)nqmal(sizeof *t->anc);
    t->ancap = 1;
    if (t->ab == NULL || t->anc == NULL) return NQEMEM;
    memcpy(t->ab, b, n);
    t->abn = n;
    if ((rc = nqcprs(t->ab, n, &t->anc[0])) != NQOK) return rc;
    t->nanc = 1;
    return NQOK;
  }
  /* PEM: count the blocks first */
  for (i = find(b, n, 0, beg, bl); i < n; i = find(b, n, i + bl, beg, bl)) {
    k++;
  }
  if (k == 0) return NQEDEC;
  if (k > NCAMAX) return NQELIM;
  /* the decoded bytes are fewer than the text */
  t->ab = (uint8_t *)nqmal(n);
  t->anc = (nqcert *)nqmal(k * sizeof *t->anc);
  t->ancap = k;
  txt = (char *)nqmal(n);
  if (t->ab == NULL || t->anc == NULL || txt == NULL) {
    if (txt != NULL) nqfree(txt, n);
    return NQEMEM;
  }
  t->abn = n;
  cap = k;
  for (i = find(b, n, 0, beg, bl); i < n && t->nanc < cap;
       i = find(b, n, i, beg, bl)) {
    size_t s = i + bl, e = find(b, n, s, end, el), j, tn = 0, dn = 0;
    if (e == n) break;
    for (j = s; j < e; j++) {
      uint8_t c = b[j];
      if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
      txt[tn++] = (char)c;
    }
    i = e + el;
    if (nqb64d(txt, tn, t->ab + used, n - used, &dn) != NQOK || dn == 0) {
      continue; /* not base64: not a certificate */
    }
    /* a certificate this module cannot read cannot be an anchor */
    if (nqcprs(t->ab + used, dn, &t->anc[t->nanc]) == NQOK) {
      t->nanc++;
      used += dn;
    }
  }
  nqfree(txt, n);
  return t->nanc > 0 ? NQOK : NQEDEC;
}

/* ---- names ---- */

static int lc(int c) {
  return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/* case-insensitive equality of two ASCII strings of given lengths */
static int eqi(const char *a, size_t an, const uint8_t *b, size_t bn) {
  size_t i;
  if (an != bn) return 0;
  for (i = 0; i < an; i++) {
    if (lc((unsigned char)a[i]) != lc(b[i])) return 0;
  }
  return 1;
}

/* a DNS name of the certificate (p, n) against the host */
static int dnsok(const char *host, const uint8_t *p, size_t n) {
  size_t hn = strlen(host), i, dots = 0;
  const char *rest;
  if (n == 0) return 0;
  for (i = 0; i < n; i++) {
    uint8_t c = p[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '*')) {
      return 0;
    }
    if (c == '*' && i != 0) return 0;
    if (c == '.') dots++;
  }
  if (p[0] != '*') return eqi(host, hn, p, n);
  /* "*." and at least two more labels: *.example.com, never *.com */
  if (n < 3 || p[1] != '.' || dots < 2 || p[n - 1] == '.') return 0;
  rest = strchr(host, '.');
  if (rest == NULL || rest == host) return 0;
  return eqi(rest, hn - (size_t)(rest - host), p + 1, n - 1);
}

int nqtlname(const nqcert *c, const char *host, int ip,
             const uint8_t *ipb) {
  nqdcur g;
  nqdtlv e;
  if ((c->ext & NQXHASSAN) == 0) return 0;
  nqdinit(&g, c->san.p, c->san.n);
  while (!nqdend(&g)) {
    if (nqdnext(&g, &e) != NQOK) return 0;
    if (e.cls != NQDCTX || e.con) continue;
    /* [2] dNSName, [7] iPAddress */
    if (!ip && e.tag == 2 && dnsok(host, e.v.p, e.v.n)) return 1;
    if (ip && e.tag == 7 && e.v.n == (size_t)ip &&
        memcmp(e.v.p, ipb, (size_t)ip) == 0) {
      return 1;
    }
  }
  return 0;
}

/* an IPv4 dotted quad or an IPv6 address (RFC 4291 2.2, forms 1 and 2) */
int nqtlip(const char *s, uint8_t *out) {
  size_t n = strlen(s), i;
  int k, dc;
  if (n == 0 || n > 45) return 0;
  if (strchr(s, ':') == NULL) {
    unsigned v = 0;
    k = 0;
    dc = 0;
    for (i = 0; i <= n; i++) {
      if (i < n && s[i] >= '0' && s[i] <= '9') {
        if (dc > 0 && v == 0) return 0; /* no leading zero */
        v = v * 10 + (unsigned)(s[i] - '0');
        if (v > 255 || ++dc > 3) return 0;
      } else if (i == n || s[i] == '.') {
        if (dc == 0 || k == 4) return 0;
        out[k++] = (uint8_t)v;
        v = 0;
        dc = 0;
      } else {
        return 0;
      }
    }
    return k == 4 ? 4 : 0;
  }
  {
    uint16_t w[8];
    int nw = 0, gap = -1;
    unsigned v = 0;
    i = 0;
    if (s[0] == ':') {
      if (s[1] != ':') return 0;
      gap = 0;
      i = 2;
      if (i == n) goto done;
    }
    for (;;) {
      dc = 0;
      v = 0;
      while (i < n && dc < 5) {
        int c = lc((unsigned char)s[i]);
        if (c >= '0' && c <= '9') {
          v = v * 16 + (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
          v = v * 16 + (unsigned)(c - 'a' + 10);
        } else {
          break;
        }
        i++;
        dc++;
      }
      if (dc == 0 || dc > 4 || nw == 8) return 0;
      w[nw++] = (uint16_t)v;
      if (i == n) break;
      if (s[i] != ':') return 0;
      i++;
      if (i < n && s[i] == ':') {
        if (gap >= 0) return 0;
        gap = nw;
        i++;
        if (i == n) break;
      } else if (i == n) {
        return 0;
      }
    }
  done:
    if (gap < 0 && nw != 8) return 0;
    if (gap >= 0 && nw > 7) return 0;
    memset(out, 0, 16);
    for (k = 0; k < nw; k++) {
      int at = gap >= 0 && k >= gap ? k + 8 - nw : k;
      out[2 * at] = (uint8_t)(w[k] >> 8);
      out[2 * at + 1] = (uint8_t)w[k];
    }
    return 16;
  }
}

/* ---- the path ---- */

int nqtlpath(nqtls *t, int64_t now) {
  const nqcert *path[NQXMAXPATH], *leaf = &t->crt[0];
  nqxchk k;
  size_t np = 0;
  int rc;
  if (t->nanc == 0) {
    return nqtlfail(t, NQEVRFY, 48, "no trust anchors to check the server "
                    "against");
  }
  k.anc = t->anc;
  k.nanc = t->nanc;
  k.pool = t->crt + 1;
  k.npool = t->ncrt - 1;
  k.t = now;
  k.eku = NQXEKUSRV;
  k.ops = nqcxops();
  rc = nqchain(leaf, &k, path, NQXMAXPATH, &np);
  if (rc != NQOK) {
    if (now < leaf->nb || now > leaf->na) {
      return nqtlfail(t, NQEVRFY, 45, "the server's certificate has "
                      "expired or is not yet valid");
    }
    if (leaf->bad) {
      return nqtlfail(t, NQEVRFY, 43, "the server's certificate has a "
                      "critical extension noqtis does not handle");
    }
    if ((leaf->ext & NQXHASEKU) == 0 ||
        (leaf->eku & NQXEKUSRV) == 0) {
      return nqtlfail(t, NQEVRFY, 42, "the server's certificate is not "
                      "for TLS servers (no serverAuth)");
    }
    return nqtlfail(t, NQEVRFY, 48, "no valid path from the server's "
                    "certificate to a trusted root");
  }
  /* TLS 1.3 signs with the leaf key (RFC 5280 4.2.1.3) */
  if ((leaf->ext & NQXHASKU) != 0 && (leaf->ku & NQXKUSIG) == 0) {
    return nqtlfail(t, NQEVRFY, 42, "the server's certificate may not "
                    "sign (keyUsage without digitalSignature)");
  }
  if (!nqtlname(leaf, t->host, t->ip, t->ipb)) {
    return nqtlfail(t, NQEVRFY, 42, "the server's certificate is not for "
                    "this host name");
  }
  return NQOK;
}

/* ---- CertificateVerify ---- */

int nqtlcv(nqtls *t, uint16_t scheme, const uint8_t *th, const uint8_t *sig,
           size_t sn) {
  static const char ctx[] = "TLS 1.3, server CertificateVerify";
  uint8_t m[64 + sizeof ctx + NQHMAX];
  size_t mn = 64 + sizeof ctx + t->hl;
  nqck k;
  nqpss pp;
  int rc;
  const nqcert *leaf = &t->crt[0];
  memset(m, 0x20, 64);
  memcpy(m + 64, ctx, sizeof ctx); /* with its 0 byte */
  memcpy(m + 64 + sizeof ctx, th, t->hl);
  rc = nqckey(&k, leaf->key.spki.p, leaf->key.spki.n);
  if (rc != NQOK) {
    return nqtlfail(t, rc == NQENOSUP ? NQENOSUP : NQEVRFY, 43,
                    "the server's key is of a kind or size noqtis does "
                    "not verify");
  }
  switch (scheme) {
  case 0x0403:
  case 0x0503:
    if (k.kind != NQKEC || k.crv != (scheme == 0x0403 ? NQP256 : NQP384)) {
      break;
    }
    rc = nqecv(&k, scheme == 0x0403 ? NQS256 : NQS384, m, mn, sig, sn, 0);
    return rc == NQOK ? NQOK
                      : nqtlfail(t, NQEVRFY, 51, "the server's "
                                 "CertificateVerify does not verify");
  case 0x0804:
  case 0x0805:
  case 0x0806:
    /* rsa_pss_rsae: an rsaEncryption key, salt of the hash's length */
    if (k.kind != NQKRSA || k.pss != 0) break;
    pp.h = scheme == 0x0804 ? NQS256 : scheme == 0x0805 ? NQS384 : NQS512;
    pp.mgf = pp.h;
    pp.slen = nqhlen(pp.h);
    rc = nqpssv(&k, &pp, m, mn, sig, sn);
    return rc == NQOK ? NQOK
                      : nqtlfail(t, NQEVRFY, 51, "the server's "
                                 "CertificateVerify does not verify");
  default:
    break;
  }
  return nqtlfail(t, NQEVRFY, 47, "the CertificateVerify scheme does not "
                  "fit the server's key");
}
