/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A stream sealed to an ML-KEM public key (noqtis-kstream-1, noqtis.h):
 * the STREAM construction of Hoang, Reyhanitabar, Rogaway and Vizar
 * (CRYPTO 2015) on ChaCha20-Poly1305. The header is "NQKF", the version,
 * the KEM, the chunk size, a random 7-byte nonce prefix and the ML-KEM
 * ciphertext; the key is the derivation of the sealed message (ks.c)
 * with its own label over the whole header, so a changed header gives
 * another key. Chunk i is sealed with the nonce prefix || i (32 bits,
 * big-endian) || 1 for the last chunk, 0 for the others: a chunk moved,
 * repeated or dropped, a stream cut at a chunk's end, and bytes after
 * the last chunk all fail a tag. Each call takes one chunk, so memory
 * stays one chunk whatever the stream's size. */
#include <string.h>

#include "aead/aead.h"
#include "box/box.h"
#include "core/int.h"

#define MAG 0x6e716b66u
#define LAB "noqtis-kstream-1"

_Static_assert(sizeof(nqkfst) <= sizeof(nqkfctx), "nqkfctx is too small");

static void nonce(const nqkfst *s, int last, uint8_t n[12]) {
  memcpy(n, s->pre, 7);
  nqst32b(n + 7, s->ctr);
  n[11] = (uint8_t)(last != 0);
}

static int ckchunk(uint32_t chunk) {
  return chunk >= NQKFCMIN && chunk <= NQKFCMAX;
}

int nqkfeini(nqkfctx *c, nqkalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *ctx, size_t ctxlen, uint32_t chunk, uint8_t *hdr,
             size_t cap, size_t *hlen) {
  nqkfst s;
  nqksz z;
  uint8_t ss[32], hek[32];
  int rc;
  if (hlen != NULL) *hlen = 0;
  if (c == NULL) return NQEARG;
  nqwipe(c, sizeof *c);
  if (!nqbxkem(alg)) return nqksize(alg, &z) == NQOK ? NQENOSUP : NQEARG;
  if (pk == NULL || hdr == NULL || (ctx == NULL && ctxlen > 0) ||
      ctxlen > NQBXCTX) {
    return NQEARG;
  }
  if (chunk == 0) chunk = NQKFCHUNK;
  if (!ckchunk(chunk)) return NQEARG;
  (void)nqksize(alg, &z);
  if (pklen != z.pk) return NQEDEC;
  if (hlen != NULL) *hlen = NQKFHDR + z.ct;
  if (cap < NQKFHDR + z.ct) return NQEBUF;
  memset(&s, 0, sizeof s);
  hdr[0] = 'N';
  hdr[1] = 'Q';
  hdr[2] = 'K';
  hdr[3] = 'F';
  hdr[4] = 1;
  hdr[5] = (uint8_t)alg;
  nqst32b(hdr + 6, chunk);
  rc = nqrand(hdr + 10, 7);
  if (rc == NQOK) rc = nqenc(alg, pk, pklen, hdr + NQKFHDR, z.ct, ss, 32);
  if (rc == NQOK) rc = nqhash(NQS3256, pk, pklen, hek, 32);
  if (rc == NQOK) {
    rc = nqbxkd(LAB, ss, hek, ctx, ctxlen, hdr, NQKFHDR + z.ct, NULL, 0,
                s.key, 32);
  }
  nqwipe(ss, sizeof ss);
  if (rc == NQOK) {
    s.mag = MAG;
    s.st = NQKFENC;
    s.alg = alg;
    s.chunk = chunk;
    memcpy(s.pre, hdr + 10, 7);
    memcpy(c, &s, sizeof s);
  } else {
    nqwipe(hdr, NQKFHDR + z.ct);
    if (hlen != NULL) *hlen = 0;
  }
  nqwipe(&s, sizeof s);
  return rc;
}

int nqkfdini(nqkfctx *c, nqkalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr,
             size_t hlen, uint32_t *chunk) {
  nqkfst s;
  nqksz z;
  uint8_t ss[32];
  uint32_t ch;
  int rc;
  if (chunk != NULL) *chunk = 0;
  if (c == NULL) return NQEARG;
  nqwipe(c, sizeof *c);
  if (!nqbxkem(alg)) return nqksize(alg, &z) == NQOK ? NQENOSUP : NQEARG;
  if (sk == NULL || hdr == NULL || (ctx == NULL && ctxlen > 0) ||
      ctxlen > NQBXCTX) {
    return NQEARG;
  }
  (void)nqksize(alg, &z);
  if (sklen != z.sk) return NQEDEC;
  if (hlen != NQKFHDR + z.ct || hdr[0] != 'N' || hdr[1] != 'Q' ||
      hdr[2] != 'K' || hdr[3] != 'F' || hdr[4] != 1 ||
      hdr[5] != (uint8_t)alg) {
    return NQEDEC;
  }
  /* a chunk size out of the limits is refused before anything is
   * allocated or derived */
  ch = nqld32b(hdr + 6);
  if (!ckchunk(ch)) return NQELIM;
  memset(&s, 0, sizeof s);
  rc = nqdec(alg, sk, sklen, hdr + NQKFHDR, z.ct, ss, 32);
  if (rc == NQOK) {
    /* H(ek), which ML-KEM's secret key holds before z (FIPS 203) */
    rc = nqbxkd(LAB, ss, sk + sklen - 64, ctx, ctxlen, hdr, hlen, NULL, 0,
                s.key, 32);
  }
  nqwipe(ss, sizeof ss);
  if (rc == NQOK) {
    s.mag = MAG;
    s.st = NQKFDEC;
    s.alg = alg;
    s.chunk = ch;
    memcpy(s.pre, hdr + 10, 7);
    memcpy(c, &s, sizeof s);
    if (chunk != NULL) *chunk = ch;
  }
  nqwipe(&s, sizeof s);
  return rc;
}

/* one chunk either way; last 1 ends the stream */
static int step(nqkfctx *c, int st, int last, const uint8_t *in, size_t n,
                uint8_t *out, size_t cap, size_t *outlen) {
  nqkfst s;
  uint8_t nc[12];
  size_t pl;
  int rc = NQOK;
  if (outlen != NULL) *outlen = 0;
  if (c == NULL) return NQEARG;
  memcpy(&s, c, sizeof s);
  if (s.mag != MAG || s.st != st || !ckchunk(s.chunk)) {
    nqwipe(&s, sizeof s);
    return NQESTATE;
  }
  if (in == NULL && n > 0) rc = NQEARG;
  /* plaintext bytes: a full chunk, or for the last 0 to a full chunk */
  if (st == NQKFENC) {
    pl = n;
    if (last ? n > s.chunk : n != s.chunk) rc = NQEARG;
  } else {
    pl = n >= NQAEADTAG ? n - NQAEADTAG : 0;
    if (n < NQAEADTAG || (last ? pl > s.chunk : pl != s.chunk)) {
      rc = st == NQKFDEC ? NQEDEC : NQEARG;
    }
  }
  /* the 2^32nd chunk could only reuse a nonce: refused */
  if (rc == NQOK && !last && s.ctr == 0xffffffffu) rc = NQELIM;
  if (rc == NQOK && out == NULL) rc = NQEARG;
  if (rc == NQOK && cap < (st == NQKFENC ? pl + NQAEADTAG : pl)) {
    if (outlen != NULL) *outlen = st == NQKFENC ? pl + NQAEADTAG : pl;
    nqwipe(&s, sizeof s);
    return NQEBUF;
  }
  if (rc == NQOK) {
    nonce(&s, last, nc);
    if (st == NQKFENC) {
      rc = nqccpe(s.key, 32, nc, 12, NULL, 0, in, pl, out, out + pl);
      if (rc == NQOK && outlen != NULL) *outlen = pl + NQAEADTAG;
    } else {
      rc = nqccpd(s.key, 32, nc, 12, NULL, 0, in, pl, in + pl, NQAEADTAG,
                  out);
      if (rc == NQOK && outlen != NULL) *outlen = pl;
    }
  }
  if (rc == NQOK && !last) {
    s.ctr++;
    memcpy(c, &s, sizeof s);
  } else {
    /* the end, or a failure: the stream is over; a decryption that
     * failed leaves nothing of the chunk */
    if (rc != NQOK && st == NQKFDEC && out != NULL) nqwipe(out, cap);
    nqwipe(c, sizeof *c);
  }
  nqwipe(&s, sizeof s);
  return rc;
}

int nqkfeupd(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return step(c, NQKFENC, 0, in, n, out, cap, outlen);
}

int nqkfefin(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return step(c, NQKFENC, 1, in, n, out, cap, outlen);
}

int nqkfdupd(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return step(c, NQKFDEC, 0, in, n, out, cap, outlen);
}

int nqkfdfin(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return step(c, NQKFDEC, 1, in, n, out, cap, outlen);
}
