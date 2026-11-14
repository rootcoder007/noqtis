/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* One message sealed to an ML-KEM public key (noqtis-kseal-1, noqtis.h):
 * ML-KEM encapsulation, HKDF-SHA-256 of the shared secret bound to the
 * recipient's key, the context and the KEM ciphertext, and
 * ChaCha20-Poly1305 with the header, the KEM ciphertext and the context
 * as associated data. Nothing else: no padding, no compression, no
 * second recipient. */
#include <string.h>

#include "aead/aead.h"
#include "core/int.h"
#include "hash/h.h"

#define HDR 6
#define LAB "noqtis-kseal-1"
#define LABL (sizeof LAB - 1)
#define CTMAX 1568 /* ML-KEM-1024's ciphertext */
#define CTXMAX 255
#define KN 44

static int iskem(nqkalg alg) {
  return alg == NQMLKEM512 || alg == NQMLKEM768 || alg == NQMLKEM1024;
}

/* the checks both directions make; z gets alg's sizes */
static int args(nqkalg alg, const uint8_t *key, const uint8_t *ctx,
                size_t ctxlen, nqksz *z) {
  if (!iskem(alg)) return nqksize(alg, z) == NQOK ? NQENOSUP : NQEARG;
  if (key == NULL || (ctx == NULL && ctxlen > 0) || ctxlen > CTXMAX) {
    return NQEARG;
  }
  return nqksize(alg, z);
}

/* the AEAD's key and nonce, and its associated data (aad, *alen) */
static int derive(const uint8_t *ss, const uint8_t hek[32],
                  const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr,
                  const uint8_t *ct, size_t ctlen, uint8_t *kn,
                  uint8_t *aad, size_t *alen) {
  uint8_t info[LABL + 32 + 1 + CTXMAX + HDR + CTMAX], prk[32];
  size_t i = 0;
  int rc;
  memcpy(info, LAB, LABL);
  i += LABL;
  memcpy(info + i, hek, 32);
  i += 32;
  info[i++] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(info + i, ctx, ctxlen);
  i += ctxlen;
  memcpy(info + i, hdr, HDR);
  i += HDR;
  memcpy(info + i, ct, ctlen);
  i += ctlen;
  rc = nqhkx(NQS256, NULL, 0, ss, 32, prk);
  if (rc == NQOK) rc = nqhke(NQS256, prk, sizeof prk, info, i, kn, KN);
  nqwipe(prk, sizeof prk);
  /* header || KEM ciphertext || ctxlen || ctx */
  memcpy(aad, hdr, HDR);
  memcpy(aad + HDR, ct, ctlen);
  aad[HDR + ctlen] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(aad + HDR + ctlen + 1, ctx, ctxlen);
  *alen = HDR + ctlen + 1 + ctxlen;
  return rc;
}

int nqkseal(nqkalg alg, const uint8_t *pk, size_t pklen, const uint8_t *ctx,
            size_t ctxlen, const uint8_t *msg, size_t n, uint8_t *out,
            size_t cap, size_t *outlen) {
  nqksz z;
  uint8_t ss[32], hek[32], kn[KN], aad[HDR + CTMAX + 1 + CTXMAX];
  size_t need, al = 0;
  int rc = args(alg, pk, ctx, ctxlen, &z);
  if (outlen != NULL) *outlen = 0;
  if (rc != NQOK) return rc;
  if (out == NULL || (msg == NULL && n > 0)) return NQEARG;
  if (n > NQKSMAX) return NQELIM;
  if (pklen != z.pk) return NQEDEC;
  need = NQKSOVH + z.ct + n;
  if (outlen != NULL) *outlen = need;
  if (cap < need) return NQEBUF;
  out[0] = 'N';
  out[1] = 'Q';
  out[2] = 'K';
  out[3] = 'S';
  out[4] = 1;
  out[5] = (uint8_t)alg;
  rc = nqenc(alg, pk, pklen, out + HDR, z.ct, ss, sizeof ss);
  if (rc == NQOK) rc = nqhash(NQS3256, pk, pklen, hek, sizeof hek);
  if (rc == NQOK) {
    rc = derive(ss, hek, ctx, ctxlen, out, out + HDR, z.ct, kn, aad, &al);
  }
  if (rc == NQOK) {
    rc = nqccpe(kn, 32, kn + 32, 12, aad, al, msg, n, out + HDR + z.ct,
                out + HDR + z.ct + n);
  }
  nqwipe(ss, sizeof ss);
  nqwipe(kn, sizeof kn);
  if (rc != NQOK) {
    nqwipe(out, need);
    if (outlen != NULL) *outlen = 0;
  }
  return rc;
}

int nqkopen(nqkalg alg, const uint8_t *sk, size_t sklen, const uint8_t *ctx,
            size_t ctxlen, const uint8_t *in, size_t n, uint8_t *msg,
            size_t cap, size_t *outlen) {
  nqksz z;
  uint8_t ss[32], kn[KN], aad[HDR + CTMAX + 1 + CTXMAX];
  size_t len = 0, al = 0;
  int rc = args(alg, sk, ctx, ctxlen, &z);
  if (outlen != NULL) *outlen = 0;
  if (rc == NQOK && (in == NULL || (msg == NULL && cap > 0))) rc = NQEARG;
  if (rc == NQOK && sklen != z.sk) rc = NQEDEC;
  if (rc == NQOK &&
      (n < NQKSOVH + z.ct || in[0] != 'N' || in[1] != 'Q' || in[2] != 'K' ||
       in[3] != 'S' || in[4] != 1 || in[5] != (uint8_t)alg)) {
    rc = NQEDEC;
  }
  if (rc == NQOK) {
    len = n - NQKSOVH - z.ct;
    if (cap < len) {
      if (outlen != NULL) *outlen = len;
      rc = NQEBUF;
    }
  }
  if (rc == NQOK) rc = nqdec(alg, sk, sklen, in + HDR, z.ct, ss, sizeof ss);
  if (rc == NQOK) {
    /* H(ek), which ML-KEM's secret key holds before z (FIPS 203) */
    rc = derive(ss, sk + sklen - 64, ctx, ctxlen, in, in + HDR, z.ct, kn,
                aad, &al);
    if (rc == NQOK) {
      rc = nqccpd(kn, 32, kn + 32, 12, aad, al, in + HDR + z.ct, len,
                  in + HDR + z.ct + len, NQAEADTAG, msg);
    }
    nqwipe(ss, sizeof ss);
    nqwipe(kn, sizeof kn);
  }
  if (rc == NQOK) {
    if (outlen != NULL) *outlen = len;
  } else if (msg != NULL && cap > 0) {
    /* nothing of a message that did not open is left */
    nqwipe(msg, cap);
  }
  return rc;
}
