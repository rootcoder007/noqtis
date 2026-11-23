/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* libFuzzer target over certificates, CMS and S/MIME: nqx5info,
 * nqcmsvrfy, nqcmsdec, nqsmvrfy and nqsmdec. At start it makes a fixed
 * ML-DSA-44 key with its certificate, an ML-KEM-512 key with the
 * certificate that key issues, and of one message a SignedData, an
 * AuthEnvelopedData and the two S/MIME messages. Each input is read as
 * each of the five by itself, and as an edit of each of the four good
 * messages (one byte choosing the message, two of offset, then the
 * bytes to write there), so the mutations reach the checks past the
 * parsers. A message that verifies or opens gives the content that was
 * signed or sealed, whatever else was changed. */
#include "fz.h"

#define T0 1767225600
static const uint8_t msg[] = "Content-Type: text/plain\r\n\r\nhello, fuzz\r\n";
#define MSGN (sizeof msg - 1)

static uint8_t pk[1312], sk[2560], kpk[800], ksk[1632];
static uint8_t cert[8192], kcert[8192];
static size_t certn, kcertn;
static uint8_t *good[4];
static size_t goodn[4];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const uint8_t *cl[1];
  size_t cn[1], i;
  uint8_t seed[64];
  int rc;
  (void)argc;
  (void)argv;
  for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i + 1);
  rc = nqskgd(NQMLDSA44, seed, 32, pk, sizeof pk, sk, sizeof sk);
  if (rc == NQOK)
    rc = nqkkgd(NQMLKEM512, seed, 64, kpk, sizeof kpk, ksk, sizeof ksk);
  if (rc == NQOK)
    rc = nqx5self(NQMLDSA44, sk, sizeof sk, pk, sizeof pk, "Fuzz Signer",
                  "fuzz@example.org", T0, T0 + 86400 * 365, cert, sizeof cert,
                  &certn);
  if (rc == NQOK)
    rc = nqx5kem(NQMLDSA44, sk, sizeof sk, cert, certn, NQMLKEM512, kpk,
                 sizeof kpk, T0, T0 + 86400 * 365, kcert, sizeof kcert,
                 &kcertn);
  for (i = 0; i < 4 && rc == NQOK; i++) {
    goodn[i] = 65536;
    good[i] = (uint8_t *)malloc(goodn[i]);
    if (good[i] == NULL) rc = NQEMEM;
  }
  cl[0] = kcert;
  cn[0] = kcertn;
  if (rc == NQOK)
    rc = nqcmssign(NQMLDSA44, sk, sizeof sk, cert, certn, msg, MSGN, 0,
                   T0 + 60, good[0], goodn[0], &goodn[0]);
  if (rc == NQOK)
    rc = nqcmsenc(cl, cn, 1, msg, MSGN, good[1], goodn[1], &goodn[1]);
  if (rc == NQOK)
    rc = nqsmsign(NQMLDSA44, sk, sizeof sk, cert, certn, (const char *)msg,
                  MSGN, 1, T0 + 60, (char *)good[2], goodn[2], &goodn[2]);
  if (rc == NQOK)
    rc = nqsmenc(cl, cn, 1, (const char *)msg, MSGN, (char *)good[3],
                 goodn[3], &goodn[3]);
  if (rc != NQOK) {
    fprintf(stderr, "fcms: cannot make the fixtures: %s\n", nqerr(rc));
    return 0;
  }
  ready = 1;
  return 0;
}

/* reads b as each kind of message; kind < 0: as all of them */
static void all(const uint8_t *b, size_t n, int kind, uint8_t *out) {
  const uint8_t *an[1];
  size_t al[1], on = 0;
  nqx5f f;
  an[0] = cert;
  al[0] = certn;
  if (kind < 0 || kind == 0) {
    if (nqcmsvrfy(b, n, NULL, 0, an, al, 1, T0 + 60, out, n + 1, &on, &f) ==
        NQOK) {
      if (on != MSGN || memcmp(out, msg, MSGN) != 0) {
        /* the fixed key signed one message only */
        abort();
      }
      if (memchr(f.name, 0, sizeof f.name) == NULL) abort();
    }
    /* as a detached signature of the message */
    nqcmsvrfy(b, n, msg, MSGN, an, al, 1, T0 + 60, out, n + 1, &on, &f);
  }
  if (kind < 0 || kind == 1) {
    if (nqcmsdec(NQMLKEM512, ksk, sizeof ksk, kcert, kcertn, b, n, out, n + 1,
                 &on) == NQOK &&
        on > n)
      abort();
    nqcmsdec(NQMLKEM512, ksk, sizeof ksk, NULL, 0, b, n, out, n + 1, &on);
  }
  if (kind < 0 || kind == 2) {
    if (nqsmvrfy((const char *)b, n, an, al, 1, T0 + 60, (char *)out, n + 1,
                 &on, &f) == NQOK &&
        (on != MSGN || memcmp(out, msg, MSGN) != 0))
      abort();
  }
  if (kind < 0 || kind == 3) {
    if (nqsmdec(NQMLKEM512, ksk, sizeof ksk, kcert, kcertn, (const char *)b,
                n, (char *)out, n + 1, &on) == NQOK &&
        on > n)
      abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqx5f f;
  uint8_t *out, *e;
  size_t at, k, gn;
  int w;
  fzready(ready, "fcms");
  if (size > ((size_t)1 << 20)) return 0;
  /* a certificate: what it says stays in bounds */
  if (nqx5info(data, size, &f) == NQOK) {
    if (f.pkoff > size || f.pklen > size - f.pkoff ||
        memchr(f.name, 0, sizeof f.name) == NULL ||
        memchr(f.email, 0, sizeof f.email) == NULL)
      abort();
  }
  out = (uint8_t *)malloc(size + 65536 + 1);
  if (out == NULL) return 0;
  all(data, size, -1, out);
  /* an edit of one of the good messages */
  if (size >= 3) {
    w = data[0] & 3;
    gn = goodn[w];
    at = ((size_t)data[1] << 8 | data[2]) % gn;
    k = size - 3;
    if (k > gn - at) k = gn - at;
    e = (uint8_t *)malloc(gn);
    if (e != NULL) {
      memcpy(e, good[w], gn);
      memcpy(e + at, data + 3, k);
      if (w == 1 || w == 3) {
        /* a sealed message that opens gives the message itself */
        size_t on = 0;
        int rc = w == 1 ? nqcmsdec(NQMLKEM512, ksk, sizeof ksk, kcert, kcertn,
                                   e, gn, out, gn + 1, &on)
                        : nqsmdec(NQMLKEM512, ksk, sizeof ksk, kcert, kcertn,
                                  (const char *)e, gn, (char *)out, gn + 1,
                                  &on);
        if (rc == NQOK && (on != MSGN || memcmp(out, msg, MSGN) != 0))
          abort();
      } else {
        all(e, gn, w, out);
      }
      free(e);
    }
  }
  free(out);
  return 0;
}
