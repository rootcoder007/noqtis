/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The TLS 1.3 record layer (RFC 8446 section 5): framing, protection
 * with the traffic keys (section 5.2, the per-record nonce of 5.3),
 * handshake message reassembly, alerts (section 6). Every limit of
 * section 5 is enforced on what is received; a record that breaks one
 * ends the connection with the alert the RFC names. */
#include <string.h>

#include "core/int.h"
#include "tls/tls.h"

/* ---- protection ---- */

static void nonce(const nqtlkey *k, uint8_t *n) {
  int i;
  memcpy(n, k->iv, 12);
  for (i = 0; i < 8; i++) n[11 - i] ^= (uint8_t)(k->seq >> (8 * i));
}

static int seal(const nqtlkey *k, const uint8_t *aad, const uint8_t *in,
                size_t n, uint8_t *out) {
  uint8_t nc[12];
  int rc;
  nonce(k, nc);
  if (k->suite == NQTLC20) {
    rc = nqccpe(k->ck, 32, nc, 12, aad, 5, in, n, out, out + n);
  } else {
    rc = nqgcme(&k->g, nc, 12, aad, 5, in, n, out, out + n);
  }
  return rc;
}

static int open1(const nqtlkey *k, const uint8_t *aad, uint8_t *in,
                 size_t n) {
  uint8_t nc[12];
  nonce(k, nc);
  if (k->suite == NQTLC20) {
    return nqccpd(k->ck, 32, nc, 12, aad, 5, in, n - 16, in + n - 16, 16,
                  in);
  }
  return nqgcmd(&k->g, nc, 12, aad, 5, in, n - 16, in + n - 16, 16, in);
}

/* ---- sending ---- */

/* one record of at most NQTLPT bytes; no change to the error state */
static int put(nqtls *t, int ty, const uint8_t *b, size_t n) {
  uint8_t *w = t->wb;
  size_t len;
  w[0] = (uint8_t)ty;
  w[1] = 3;
  /* the first ClientHello says 0x0301 for old middleboxes (5.1) */
  w[2] = t->chn > 0 && t->st == 0 && !t->hrr ? 1 : 3;
  if (!t->wk.on) {
    len = n;
    if (n > 0) memcpy(w + 5, b, n);
  } else {
    if (t->wk.seq == UINT64_MAX) return NQELIM;
    /* TLSInnerPlaintext: content, type, no padding */
    if (n > 0) memcpy(w + 5, b, n);
    w[5 + n] = (uint8_t)ty;
    len = n + 1 + 16;
    w[0] = NQTLAPP;
    w[2] = 3;
  }
  w[3] = (uint8_t)(len >> 8);
  w[4] = (uint8_t)len;
  if (t->wk.on) {
    if (seal(&t->wk, w, w + 5, n + 1, w + 5) != NQOK) return NQEARG;
    t->wk.seq++;
  }
  return t->io.wr(t->io.user, w, 5 + len) == NQOK ? NQOK : NQEIO;
}

int nqtlfail(nqtls *t, int rc, int alert, const char *why) {
  if (t->err != 0) return t->err;
  t->err = rc;
  if (why != NULL) {
    size_t n = strlen(why);
    if (n >= sizeof t->why) n = sizeof t->why - 1;
    memcpy(t->why, why, n);
    t->why[n] = '\0';
  }
  if (alert >= 0 && !t->sent) {
    uint8_t a[2];
    a[0] = 2; /* fatal */
    a[1] = (uint8_t)alert;
    t->sent = 1;
    (void)put(t, NQTLALERT, a, 2);
  }
  return rc;
}

int nqtlsend(nqtls *t, int ty, const uint8_t *b, size_t n) {
  size_t max = NQTLPT;
  int rc;
  if (t->err != 0) return t->err;
  if (t->sent) return nqtlfail(t, NQESTATE, -1, "the connection is closed");
  /* record_size_limit counts the inner content type (RFC 8449 4) */
  if (t->rsl > 0 && t->wk.on && t->rsl - 1 < max) max = t->rsl - 1;
  do {
    size_t c = n < max ? n : max;
    if ((rc = put(t, ty, b, c)) != NQOK) {
      return nqtlfail(t, rc, rc == NQELIM ? -1 : 80,
                      rc == NQEIO ? "cannot send to the server"
                                  : "cannot protect a record");
    }
    b += c;
    n -= c;
  } while (n > 0);
  return NQOK;
}

/* ---- receiving ---- */

/* exactly n bytes; *eof 1 when the stream ended before the first one */
static int rdn(nqtls *t, uint8_t *b, size_t n, int *eof) {
  size_t first = 1;
  *eof = 0;
  while (n > 0) {
    size_t got = 0;
    if (t->io.rd(t->io.user, b, n, &got) != NQOK || got > n) return NQEIO;
    if (got == 0) {
      *eof = (int)first;
      return NQEIO;
    }
    first = 0;
    b += got;
    n -= got;
  }
  return NQOK;
}

static const char *aname(int a) {
  switch (a) {
  case 0: return "close_notify";
  case 10: return "unexpected_message";
  case 20: return "bad_record_mac";
  case 22: return "record_overflow";
  case 40: return "handshake_failure";
  case 42: return "bad_certificate";
  case 43: return "unsupported_certificate";
  case 44: return "certificate_revoked";
  case 45: return "certificate_expired";
  case 46: return "certificate_unknown";
  case 47: return "illegal_parameter";
  case 48: return "unknown_ca";
  case 49: return "access_denied";
  case 50: return "decode_error";
  case 51: return "decrypt_error";
  case 70: return "protocol_version";
  case 71: return "insufficient_security";
  case 80: return "internal_error";
  case 86: return "inappropriate_fallback";
  case 90: return "user_canceled";
  case 109: return "missing_extension";
  case 110: return "unsupported_extension";
  case 112: return "unrecognized_name";
  case 113: return "bad_certificate_status_response";
  case 115: return "unknown_psk_identity";
  case 116: return "certificate_required";
  case 120: return "no_application_protocol";
  default: return "an unknown alert";
  }
}

int nqtlrec(nqtls *t) {
  uint8_t *h = t->rb, *p = t->rb + 5;
  size_t len, i;
  int eof, ty;
  for (;;) {
    if (t->err != 0) return t->err;
    if (t->eof) return nqtlfail(t, NQESTATE, -1, "read after close_notify");
    t->pt = 0;
    t->pn = 0;
    t->pp = 0;
    if (rdn(t, h, 5, &eof) != NQOK) {
      return nqtlfail(t, NQEIO, -1,
                      eof ? "the server closed the connection without "
                            "close_notify"
                          : "cannot read from the server");
    }
    ty = h[0];
    len = ((size_t)h[3] << 8) | h[4];
    if (h[1] != 3) {
      return nqtlfail(t, NQEDEC, 50, "the server's reply is not TLS");
    }
    if (len > (t->rk.on ? NQTLCT : NQTLPT)) {
      return nqtlfail(t, NQEDEC, 22, "a record over the size limit");
    }
    if (rdn(t, p, len, &eof) != NQOK) {
      return nqtlfail(t, NQEIO, -1, "the connection ended inside a record");
    }
    t->rbn = 5 + len;
    /* an unprotected change_cipher_spec of one byte 01 is dropped until
     * the server's Finished (section 5); anything else is an error */
    if (ty == NQTLCCS) {
      if (t->st >= NQTLSFIN || len != 1 || p[0] != 1) {
        return nqtlfail(t, NQEDEC, 10, "an unexpected change_cipher_spec");
      }
      continue;
    }
    if (!t->rk.on) {
      if (ty != NQTLHS && ty != NQTLALERT) {
        return nqtlfail(t, NQEDEC, 10, "an unexpected record before the "
                        "handshake keys");
      }
      t->pp = 0;
      t->pn = len;
    } else {
      uint8_t a[5];
      if (ty != NQTLAPP) {
        return nqtlfail(t, NQEDEC, 10, "an unprotected record after the "
                        "ServerHello");
      }
      if (len < 17) {
        return nqtlfail(t, NQEDEC, 50, "a protected record too short");
      }
      if (t->rk.seq == UINT64_MAX) {
        return nqtlfail(t, NQELIM, 80, "the record sequence is exhausted");
      }
      memcpy(a, h, 5);
      if (open1(&t->rk, a, p, len) != NQOK) {
        return nqtlfail(t, NQEVRFY, 20, "a record does not decrypt "
                        "(bad_record_mac)");
      }
      t->rk.seq++;
      /* the content type is the last non-zero byte (5.4) */
      i = len - 16;
      while (i > 0 && p[i - 1] == 0) i--;
      if (i == 0) {
        return nqtlfail(t, NQEDEC, 10, "a protected record of padding only");
      }
      ty = p[i - 1];
      if (i - 1 > NQTLPT) {
        return nqtlfail(t, NQEDEC, 22, "a record over the plaintext limit");
      }
      if (ty != NQTLHS && ty != NQTLALERT && ty != NQTLAPP) {
        return nqtlfail(t, NQEDEC, 10, "a protected record of an "
                        "unexpected type");
      }
      t->pp = 0;
      t->pn = i - 1;
    }
    if (ty == NQTLHS && t->pn == 0) {
      return nqtlfail(t, NQEDEC, 10, "an empty handshake record");
    }
    if (ty == NQTLALERT) {
      int lv, d;
      /* one alert, whole, per record */
      if (t->pn != 2) {
        return nqtlfail(t, NQEDEC, 50, "a malformed alert");
      }
      lv = p[0];
      d = p[1];
      if (d == 0) {
        t->eof = 1;
        t->pn = 0;
        t->pt = NQTLALERT;
        return NQOK;
      }
      if (d == 90 && lv == 1) continue; /* user_canceled: a warning */
      {
        char m[NQTLWHY];
        size_t k = 0;
        const char *s = "the server sent the alert ", *nm = aname(d);
        while (*s != '\0' && k < sizeof m - 1) m[k++] = *s++;
        while (*nm != '\0' && k < sizeof m - 1) m[k++] = *nm++;
        m[k] = '\0';
        t->sent = 1; /* never answer a fatal alert */
        /* no common version, group or suite: the server speaks nothing
         * noqtis offers; anything else ends the connection */
        return nqtlfail(t, d == 40 || d == 70 || d == 71 ? NQENOSUP : NQEIO,
                        -1, m);
      }
    }
    t->pt = ty;
    return NQOK;
  }
}

int nqtlpop(nqtls *t, const uint8_t **m, size_t *n, int *got) {
  size_t have = t->hmn - t->hmoff, len;
  const uint8_t *q = t->hm + t->hmoff;
  *got = 0;
  if (have < 4) return NQOK;
  len = ((size_t)q[1] << 16) | ((size_t)q[2] << 8) | q[3];
  if (len > NQTLHMAX) {
    return nqtlfail(t, NQELIM, 50, "a handshake message over 256 KiB");
  }
  if (have >= 4 + len) {
    *m = q;
    *n = 4 + len;
    t->hmoff += 4 + len;
    *got = 1;
  }
  return NQOK;
}

int nqtlpush(nqtls *t) {
  size_t need;
  if (t->pt != NQTLHS) return NQOK;
  /* compact first */
  if (t->hmoff > 0) {
    memmove(t->hm, t->hm + t->hmoff, t->hmn - t->hmoff);
    t->hmn -= t->hmoff;
    t->hmoff = 0;
  }
  need = t->hmn + t->pn;
  if (need > t->hmcap) {
    size_t nc = t->hmcap * 2;
    uint8_t *nb;
    /* a message of NQTLHMAX and the start of the next fit */
    if (need > NQTLHMAX + 4 + NQTLPT) {
      return nqtlfail(t, NQELIM, 50, "a handshake message over 256 KiB");
    }
    if (nc < need) nc = need;
    if (nc > NQTLHMAX + 4 + NQTLPT) nc = NQTLHMAX + 4 + NQTLPT;
    nb = (uint8_t *)nqmal(nc);
    if (nb == NULL) return nqtlfail(t, NQEMEM, 80, "out of memory");
    memcpy(nb, t->hm, t->hmn);
    nqfree(t->hm, t->hmcap);
    t->hm = nb;
    t->hmcap = nc;
  }
  memcpy(t->hm + t->hmn, t->rb + 5 + t->pp, t->pn);
  t->hmn += t->pn;
  t->pn = 0;
  t->pt = 0;
  return NQOK;
}

int nqtlmsg(nqtls *t, const uint8_t **m, size_t *n) {
  int rc, got;
  for (;;) {
    if ((rc = nqtlpop(t, m, n, &got)) != NQOK) return rc;
    if (got) return NQOK;
    if (t->pn == 0 || t->pt == 0) {
      if ((rc = nqtlrec(t)) != NQOK) return rc;
      if (t->eof) {
        return nqtlfail(t, NQEIO, -1, "the server closed the connection "
                        "during the handshake");
      }
    }
    if (t->pt != NQTLHS) {
      return nqtlfail(t, NQEDEC, 10, "application data inside a handshake "
                      "message");
    }
    if ((rc = nqtlpush(t)) != NQOK) return rc;
  }
}

int nqtlflat(nqtls *t) {
  if (t->hmn != t->hmoff || t->pn != 0) {
    return nqtlfail(t, NQEDEC, 10, "a handshake message across a key "
                    "change");
  }
  return NQOK;
}
