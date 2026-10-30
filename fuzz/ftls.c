/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the TLS 1.3 client's record layer and handshake
 * parsers. The client starts from the RFC 8448 section 3 ClientHello and
 * X25519 key (fuzz/t8448.h) and gets the trace's ServerHello, so it
 * derives the trace's keys; the input is then what the server says
 * next, as pieces (fzpart) each sealed by this target under the server's
 * handshake or application key, or passed raw:
 *
 *   mode, then pieces of: key (0 handshake, 1 application, 2 raw),
 *   inner content type, two-byte length, bytes
 *
 * so the fuzzer reaches EncryptedExtensions, Certificate,
 * CertificateVerify, Finished and the post-handshake messages, not just
 * the bad_record_mac check. mode bit 0 checks the certificate path
 * against the local PKI's roots (tests/vectors/der/local), bit 1 skips
 * the CertificateVerify signature (the trace's key is RSA-1024). The
 * seeds in fuzz/corpus/ftls are the trace's own flight, whole, one
 * record per message, and five bytes per record. */
#include "fz.h"
#include "t8448.h"
#include "tls/tls.h"

static uint8_t *anc = NULL;
static size_t ancn = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  anc = fzread("rsa_root.der", &ancn);
  return 0;
}

typedef struct {
  const uint8_t *b;
  size_t n, p;
} feed;

static int fwr(void *u, const uint8_t *b, size_t n) {
  (void)u;
  (void)b;
  (void)n;
  return NQOK;
}

static int frd(void *u, uint8_t *b, size_t cap, size_t *got) {
  feed *f = (feed *)u;
  size_t c = f->n - f->p;
  if (c > cap) c = cap;
  memcpy(b, f->b + f->p, c);
  f->p += c;
  *got = c;
  return NQOK;
}

/* seals b as one record of inner type ty under key k with sequence s */
static size_t seal(const nqgcm *g, const uint8_t *iv, uint64_t s, int ty,
                   const uint8_t *b, size_t n, uint8_t *out) {
  uint8_t nc[12];
  int i;
  out[0] = NQTLAPP;
  out[1] = 3;
  out[2] = 3;
  out[3] = (uint8_t)((n + 17) >> 8);
  out[4] = (uint8_t)(n + 17);
  memcpy(out + 5, b, n);
  out[5 + n] = (uint8_t)ty;
  memcpy(nc, iv, 12);
  for (i = 0; i < 8; i++) nc[11 - i] ^= (uint8_t)(s >> (8 * i));
  (void)nqgcme(g, nc, 12, out, 5, out + 5, n + 1, out + 5, out + 6 + n);
  return n + 22;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fzin in;
  feed f;
  nqgcm hk, ak;
  nqtlhk h;
  nqtlio io;
  nqtls *t = NULL;
  uint8_t *s, o[256];
  size_t cap = sizeof r8sh + 7 * size + 64, n = 0, got = 0;
  uint64_t hs = 0, as = 0;
  unsigned mode;
  int i;
  in.p = data;
  in.n = size;
  mode = fzbyte(&in);
  s = (uint8_t *)malloc(cap);
  if (s == NULL) return 0;
  memcpy(s, r8sh, sizeof r8sh);
  n = sizeof r8sh;
  nqgcmk(&hk, r8hkey, sizeof r8hkey);
  nqgcmk(&ak, r8akey, sizeof r8akey);
  while (in.n > 0) {
    unsigned key = fzbyte(&in), ty = fzbyte(&in);
    size_t pn;
    const uint8_t *p = fzpart(&in, &pn);
    if (pn > NQTLPT + 1) pn = NQTLPT + 1;
    if (key == 0) {
      n += seal(&hk, r8hiv, hs++, (int)ty, p, pn, s + n);
    } else if (key == 1) {
      n += seal(&ak, r8aiv, as++, (int)ty, p, pn, s + n);
    } else {
      memcpy(s + n, p, pn);
      n += pn;
    }
  }
  f.b = s;
  f.n = n;
  f.p = 0;
  io.wr = fwr;
  io.rd = frd;
  io.user = &f;
  if (nqtlmk(&t, "server", (mode & 1) && anc != NULL ? anc : NULL,
             (mode & 1) && anc != NULL ? ancn : 0, &io) != NQOK) {
    free(s);
    return 0;
  }
  memset(&h, 0, sizeof h);
  h.ch1 = r8ch;
  h.ch1n = sizeof r8ch;
  h.xsk = r8xsk;
  h.nopath = !(mode & 1);
  h.nocv = (mode & 2) != 0;
  h.now = (int64_t)1893456000;
  nqtlhook(t, &h);
  if (nqtlhand(t) == NQOK) {
    for (i = 0; i < 64; i++) {
      if (nqtlr(t, o, sizeof o, &got) != NQOK || got == 0) break;
    }
    (void)nqtlw(t, o, 3);
    (void)nqtle(t);
  }
  nqtlfree(t);
  free(s);
  return 0;
}
