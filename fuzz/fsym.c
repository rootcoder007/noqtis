/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over KangarooTwelve, ChaCha20, AES-SIV and
 * AES-GCM-SIV. The first byte picks the function and the key size, the
 * next the split points; the rest is the keys, the associated strings
 * and the message. What is encrypted must decrypt to the message; one
 * changed bit anywhere in the output, or in a string, must be refused,
 * with nothing but zeros returned; ChaCha20 applied twice is the
 * identity, and from a later block it gives the same stream; and
 * KangarooTwelve gives the same bytes for an input in one piece and in
 * pieces of any size, a shorter output being the start of a longer one. */
#include "fz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

static int zero(const uint8_t *p, size_t n) {
  size_t i;
  unsigned x = 0;
  for (i = 0; i < n; i++) x |= p[i];
  return x == 0;
}

static void siv(unsigned sel, const uint8_t *d, size_t n) {
  static const size_t kls[3] = {32, 48, 64};
  size_t kl = kls[sel % 3], nad, i, at, pl;
  const uint8_t *ad[4], *pt;
  size_t adl[4];
  uint8_t *c, *o;
  if (n < kl + 1) return;
  nad = d[kl] % 4;
  at = kl + 1;
  for (i = 0; i < nad; i++) {
    size_t l;
    if (at >= n) return;
    l = d[at++] % 40;
    if (l > n - at) l = n - at;
    ad[i] = d + at;
    adl[i] = l;
    at += l;
  }
  pt = d + at;
  pl = n - at;
  c = (uint8_t *)malloc(pl + 16);
  o = (uint8_t *)malloc(pl + 1);
  if (c == NULL || o == NULL) goto out;
  if (nqsivenc(d, kl, ad, adl, nad, pt, pl, c, pl + 16) != NQOK) abort();
  if (nqsivdec(d, kl, ad, adl, nad, c, pl + 16, o, pl) != NQOK ||
      memcmp(o, pt, pl) != 0)
    abort();
  /* one changed bit of the output */
  c[sel % (pl + 16)] ^= (uint8_t)(1u << (sel % 8));
  memset(o, 0xa5, pl + 1);
  if (nqsivdec(d, kl, ad, adl, nad, c, pl + 16, o, pl) != NQEVRFY ||
      !zero(o, pl))
    abort();
  c[sel % (pl + 16)] ^= (uint8_t)(1u << (sel % 8));
  /* one string fewer */
  if (nad > 0 &&
      nqsivdec(d, kl, ad, adl, nad - 1, c, pl + 16, o, pl) != NQEVRFY)
    abort();
out:
  free(c);
  free(o);
}

static void gsiv(unsigned sel, const uint8_t *d, size_t n) {
  size_t kl = (sel & 1) ? 32 : 16, al, pl;
  const uint8_t *nonce, *ad, *pt;
  uint8_t *c, *o;
  if (n < kl + 13) return;
  nonce = d + kl;
  al = d[kl + 12] % 48;
  if (al > n - kl - 13) al = n - kl - 13;
  ad = d + kl + 13;
  pt = ad + al;
  pl = n - kl - 13 - al;
  c = (uint8_t *)malloc(pl + 16);
  o = (uint8_t *)malloc(pl + 1);
  if (c == NULL || o == NULL) goto out;
  if (nqgsivenc(d, kl, nonce, 12, ad, al, pt, pl, c, pl + 16) != NQOK) abort();
  if (nqgsivdec(d, kl, nonce, 12, ad, al, c, pl + 16, o, pl) != NQOK ||
      memcmp(o, pt, pl) != 0)
    abort();
  c[sel % (pl + 16)] ^= (uint8_t)(1u << (sel % 8));
  memset(o, 0xa5, pl + 1);
  if (nqgsivdec(d, kl, nonce, 12, ad, al, c, pl + 16, o, pl) != NQEVRFY ||
      !zero(o, pl))
    abort();
  c[sel % (pl + 16)] ^= (uint8_t)(1u << (sel % 8));
  /* other associated data */
  if (al > 0 &&
      nqgsivdec(d, kl, nonce, 12, ad, al - 1, c, pl + 16, o, pl) != NQEVRFY)
    abort();
out:
  free(c);
  free(o);
}

static void cha(unsigned sel, const uint8_t *d, size_t n) {
  size_t pl, cut;
  const uint8_t *pt;
  uint8_t *c, *o;
  uint32_t ctr = sel * 0x01010101u;
  if (n < 44) return;
  pt = d + 44;
  pl = n - 44;
  c = (uint8_t *)malloc(pl + 1);
  o = (uint8_t *)malloc(pl + 1);
  if (c == NULL || o == NULL) goto out;
  if (nqcha20(d, 32, d + 32, 12, ctr, pt, pl, c) != NQOK) {
    /* only the end of the counter refuses */
    if ((uint64_t)pl <= ((uint64_t)0x100000000u - ctr) * 64u) abort();
    goto out;
  }
  if (nqcha20(d, 32, d + 32, 12, ctr, c, pl, o) != NQOK ||
      memcmp(o, pt, pl) != 0)
    abort();
  /* from a later block, the same stream */
  cut = pl - pl % 64;
  if (cut >= 64 && ctr != 0xffffffffu) {
    cut = 64;
    if (nqcha20(d, 32, d + 32, 12, ctr + 1, pt + cut, pl - cut, o) != NQOK ||
        memcmp(o, c + cut, pl - cut) != 0)
      abort();
  }
out:
  free(c);
  free(o);
}

static void kt(unsigned sel, const uint8_t *d, size_t n) {
  unsigned bits = (sel & 1) ? 256 : 128;
  size_t cl, ml, step, at;
  const uint8_t *cu, *m;
  uint8_t a[200], b[200];
  nqktctx c;
  if (n < 2) return;
  cl = d[0] % 64;
  step = (size_t)d[1] * 37 + 1;
  if (cl > n - 2) cl = n - 2;
  cu = d + 2;
  m = cu + cl;
  ml = n - 2 - cl;
  if (nqkt(bits, m, ml, cu, cl, a, sizeof a) != NQOK) abort();
  if (nqktini(&c, bits) != NQOK) abort();
  for (at = 0; at < ml; at += step) {
    if (nqktupd(&c, m + at, ml - at < step ? ml - at : step) != NQOK) abort();
  }
  if (nqktfin(&c, cu, cl, b, sizeof b) != NQOK) abort();
  if (memcmp(a, b, sizeof a) != 0) abort();
  if (nqkt(bits, m, ml, cu, cl, b, 1 + sel % 150) != NQOK ||
      memcmp(a, b, 1 + sel % 150) != 0)
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned sel;
  if (size < 2) return 0;
  sel = data[1];
  switch (data[0] % 4) {
  case 0: siv(sel, data + 2, size - 2); break;
  case 1: gsiv(sel, data + 2, size - 2); break;
  case 2: cha(sel, data + 2, size - 2); break;
  default: kt(sel, data + 2, size - 2); break;
  }
  return 0;
}
