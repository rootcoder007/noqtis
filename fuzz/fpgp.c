/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over OpenPGP: nqpgpinfo, nqpgpvrfy and nqpgpdec. At
 * start it makes an Ed25519 key with an X25519 subkey, and of one
 * message a signed message, a detached signature, a cleartext signature
 * and a message encrypted to the key and to a passphrase. Each input is
 * read as a key, as a signature of each kind and as an encrypted
 * message, and as an edit of each of the good ones (one byte choosing
 * it, two of offset, then the bytes to write there). A signature that
 * verifies and a message that opens give the message that was signed or
 * sealed, whatever else was changed.
 *
 * The passphrase method is cut to 1 MiB and one pass (nqpgps2k), so an
 * input costs one small Argon2id run at most; the limits themselves are
 * tested in tests/tpgp.c. */
#include "fz.h"
#include "pgp/pgp.h"

#define T0 1767225600
static const uint8_t msg[] = "a line\n- with a dash\nand the last\n";
#define MSGN (sizeof msg - 1)
static const uint8_t pw[] = "fuzz";

static uint8_t sec[4096], cert[4096];
static size_t secn, certn;
static uint8_t *good[4];
static size_t goodn[4];
static int ready = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const uint8_t *cl[1];
  size_t cn[1], i;
  int rc;
  (void)argc;
  (void)argv;
  nqpgps2k(1, 1, 10);
  rc = nqpgpgen(NQPGPED25519, NQPGPX25519, "Fuzz <fuzz@example.org>", T0,
                NULL, 0, sec, sizeof sec, &secn, cert, sizeof cert, &certn);
  for (i = 0; i < 4 && rc == NQOK; i++) {
    goodn[i] = 8192;
    good[i] = (uint8_t *)malloc(goodn[i]);
    if (good[i] == NULL) rc = NQEMEM;
  }
  cl[0] = cert;
  cn[0] = certn;
  if (rc == NQOK)
    rc = nqpgpsign(sec, secn, NULL, 0, msg, MSGN, NQPGPINLINE, T0 + 60,
                   good[0], goodn[0], &goodn[0]);
  if (rc == NQOK)
    rc = nqpgpsign(sec, secn, NULL, 0, msg, MSGN, NQPGPDETACHED, T0 + 60,
                   good[1], goodn[1], &goodn[1]);
  if (rc == NQOK)
    rc = nqpgpsign(sec, secn, NULL, 0, msg, MSGN, NQPGPCLEAR, T0 + 60,
                   good[2], goodn[2], &goodn[2]);
  if (rc == NQOK)
    rc = nqpgpenc(cl, cn, 1, pw, sizeof pw - 1, sec, secn, NULL, 0, msg, MSGN,
                  T0 + 60, good[3], goodn[3], &goodn[3]);
  if (rc != NQOK) {
    fprintf(stderr, "fpgp: cannot make the fixtures: %s\n", nqerr(rc));
    return 0;
  }
  ready = 1;
  return 0;
}

/* reads b every way; what verifies or opens is the message */
static void all(const uint8_t *b, size_t n, uint8_t *out) {
  size_t on = 0;
  int64_t at = 0;
  int sb = 0, rc;
  rc = nqpgpvrfy(cert, certn, b, n, NULL, 0, out, n + 1, &on, &at);
  /* an inline message carries the message; a cleartext one its text
   * without the space at line ends, which this message has none of, and
   * without its last line end */
  if (rc == NQOK &&
      !((on == MSGN && memcmp(out, msg, MSGN) == 0) ||
        (on == MSGN - 1 && memcmp(out, msg, MSGN - 1) == 0)))
    abort();
  rc = nqpgpvrfy(cert, certn, b, n, msg, MSGN, out, n + 1, &on, &at);
  if (rc == NQOK &&
      !((on == MSGN && memcmp(out, msg, MSGN) == 0) ||
        (on == MSGN - 1 && memcmp(out, msg, MSGN - 1) == 0)))
    abort();
  rc = nqpgpdec(sec, secn, NULL, 0, cert, certn, b, n, out, n + 1, &on, &sb,
                &at);
  if (rc == NQOK && (on != MSGN || memcmp(out, msg, MSGN) != 0 || sb != 1))
    abort();
  nqpgpdec(sec, secn, NULL, 0, NULL, 0, b, n, out, n + 1, &on, &sb, &at);
  rc = nqpgpdec(NULL, 0, pw, sizeof pw - 1, cert, certn, b, n, out, n + 1,
                &on, &sb, &at);
  if (rc == NQOK && (on != MSGN || memcmp(out, msg, MSGN) != 0)) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqpgpk f;
  uint8_t *out, *e;
  size_t at, k, gn;
  int w;
  fzready(ready, "fpgp");
  if (size > ((size_t)1 << 18)) return 0;
  /* a key: what it says stays in bounds */
  if (nqpgpinfo(data, size, &f) == NQOK) {
    if (memchr(f.uid, 0, sizeof f.uid) == NULL || f.created < 0) abort();
  }
  out = (uint8_t *)malloc(size + 8192 + 1);
  if (out == NULL) return 0;
  all(data, size, out);
  /* the input as a key to verify the good signature and open the good
   * message with: it is not the key that made them */
  {
    size_t on = 0;
    int64_t t = 0;
    int sb = 0;
    nqpgpvrfy(data, size, good[0], goodn[0], NULL, 0, out, goodn[0] + 1, &on,
              &t);
    nqpgpdec(data, size, NULL, 0, NULL, 0, good[3], goodn[3], out,
             goodn[3] + 1, &on, &sb, &t);
  }
  /* an edit of one of the good ones */
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
      all(e, gn, out);
      free(e);
    }
  }
  free(out);
  return 0;
}
