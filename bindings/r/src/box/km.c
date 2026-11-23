/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* A stream sealed to several ML-KEM public keys, and signed by its
 * sender when asked (noqtis-kstream-2, noqtis.h). The stream is that of
 * kf.c, the STREAM construction on ChaCha20-Poly1305, under a random
 * 32-byte file key; the header carries that key once per recipient,
 * wrapped under a key from an ML-KEM encapsulation to the recipient.
 *
 * The header: "NQKM", the version 2, the flags (bit 0: signed), the
 * chunk size, a random 7-byte nonce prefix, the signature algorithm (0
 * when not signed), the number of recipients and the header's whole
 * length; then for each recipient its KEM, the first 8 bytes of the
 * SHA3-256 of its public key, the KEM ciphertext and the file key under
 * ChaCha20-Poly1305 (48 bytes). The key that wraps is HKDF-SHA-256 of
 * the shared secret with a label, the SHA3-256 of the recipient's key,
 * the context, the header's fixed part and the KEM ciphertext; the
 * stream's key is HKDF-SHA-256 of the file key with a label, the
 * context and the SHA3-256 of the whole header, so that no byte of the
 * header, another recipient's entry included, can change without every
 * chunk failing.
 *
 * Chunk i is sealed as in kf.c: nonce prefix || i || 0, or 1 for the
 * last. A signed stream ends with one more record after the last chunk,
 * under the nonce prefix || i || 2: the sender's signature, with the
 * context "noqtis-kstream-2", of the SHA3-256 of the header's hash and
 * the whole plaintext. It is inside the encryption, so only a recipient
 * learns who signed, and it covers the header, so a recipient cannot
 * pass the message on to someone else as if the sender had sealed it to
 * them. */
#include <string.h>

#include "aead/aead.h"
#include "box/box.h"
#include "core/int.h"
#include "hash/h.h"

#define MAG 0x6e716b6du
#define LABW "noqtis-kwrap-2"
#define LABS "noqtis-kstream-2"
#define WRAP 48                    /* the file key and its tag */
#define ENT(ct) (1u + 8u + (ct) + WRAP)

typedef struct {
  uint32_t mag;
  int st;          /* NQKFENC or NQKFDEC while open */
  int sig;         /* the signature algorithm, 0 when not signed */
  uint32_t chunk;
  uint32_t ctr;
  uint8_t key[32];
  uint8_t pre[7];
  nqhctx h;        /* signed: the header's hash, then the plaintext */
} kmst;

_Static_assert(sizeof(kmst) <= sizeof(nqkmctx), "nqkmctx is too small");

static int ckchunk(uint32_t chunk) {
  return chunk >= NQKFCMIN && chunk <= NQKFCMAX;
}

static void nonce(const kmst *s, int flag, uint8_t n[12]) {
  memcpy(n, s->pre, 7);
  nqst32b(n + 7, s->ctr);
  n[11] = (uint8_t)flag;
}

/* the key that wraps the file key for one recipient */
static int kek(const uint8_t *ss, const uint8_t hek[32], const uint8_t *ctx,
               size_t ctxlen, const uint8_t *fix, const uint8_t *ct,
               size_t cl, uint8_t out[32]) {
  uint8_t info[sizeof LABW - 1 + 32 + 1 + NQBXCTX + NQKMFIX + NQBXCT];
  uint8_t prk[32];
  size_t i = sizeof LABW - 1;
  int rc;
  memcpy(info, LABW, i);
  memcpy(info + i, hek, 32);
  i += 32;
  info[i++] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(info + i, ctx, ctxlen);
  i += ctxlen;
  memcpy(info + i, fix, NQKMFIX);
  i += NQKMFIX;
  memcpy(info + i, ct, cl);
  i += cl;
  rc = nqhkx(NQS256, NULL, 0, ss, 32, prk);
  if (rc == NQOK) rc = nqhke(NQS256, prk, sizeof prk, info, i, out, 32);
  nqwipe(prk, sizeof prk);
  return rc;
}

/* the stream's key from the file key, and the header's hash */
static int skey(const uint8_t fk[32], const uint8_t *ctx, size_t ctxlen,
                const uint8_t *hdr, size_t hl, uint8_t key[32],
                uint8_t hh[32]) {
  uint8_t info[sizeof LABS - 1 + 1 + NQBXCTX + 32], prk[32];
  size_t i = sizeof LABS - 1;
  int rc = nqhash(NQS3256, hdr, hl, hh, 32);
  memcpy(info, LABS, i);
  info[i++] = (uint8_t)ctxlen;
  if (ctxlen > 0) memcpy(info + i, ctx, ctxlen);
  i += ctxlen;
  memcpy(info + i, hh, 32);
  i += 32;
  if (rc == NQOK) rc = nqhkx(NQS256, NULL, 0, fk, 32, prk);
  if (rc == NQOK) rc = nqhke(NQS256, prk, sizeof prk, info, i, key, 32);
  nqwipe(prk, sizeof prk);
  return rc;
}

/* the signature algorithm sig (0: none) and its signature's size */
static int sigsz(int sig, size_t *n) {
  nqssz z;
  *n = 0;
  if (sig == 0) return NQOK;
  if (sig < 0 || sig > 255 || nqssize((nqsalg)sig, &z) != NQOK)
    return NQENOSUP;
  *n = z.sig;
  return NQOK;
}

int nqkmhlen(const nqkrcp *r, size_t n, size_t *hlen) {
  size_t i, t = NQKMFIX;
  if (hlen != NULL) *hlen = 0;
  if (r == NULL || hlen == NULL || n == 0 || n > NQKMRCP) return NQEARG;
  for (i = 0; i < n; i++) {
    nqksz z;
    if (!nqbxkem(r[i].alg))
      return nqksize(r[i].alg, &z) == NQOK ? NQENOSUP : NQEARG;
    (void)nqksize(r[i].alg, &z);
    if (r[i].pk == NULL) return NQEARG;
    if (r[i].pklen != z.pk) return NQEDEC;
    t += ENT(z.ct);
  }
  *hlen = t;
  return NQOK;
}

int nqkmpeek(const uint8_t *in, size_t n, size_t *hlen, nqsalg *sig,
             size_t *nrcp) {
  uint32_t hl;
  unsigned nr;
  size_t sl;
  if (hlen != NULL) *hlen = 0;
  if (sig != NULL) *sig = (nqsalg)0;
  if (nrcp != NULL) *nrcp = 0;
  if (in == NULL || hlen == NULL) return NQEARG;
  if (n < NQKMFIX || in[0] != 'N' || in[1] != 'Q' || in[2] != 'K' ||
      in[3] != 'M' || in[4] != 2 || (in[5] & 0xfeu) != 0) {
    return NQEDEC;
  }
  nr = ((unsigned)in[18] << 8) | in[19];
  hl = nqld32b(in + 20);
  /* a size out of the limits is refused before anything is read into
   * it: at most NQKMRCP entries of the largest KEM */
  if (nr == 0 || nr > NQKMRCP || !ckchunk(nqld32b(in + 6)) ||
      hl < NQKMFIX + nr * ENT(768u) || hl > NQKMFIX + nr * ENT(NQBXCT)) {
    return NQELIM;
  }
  if (((in[5] & 1u) != 0) != (in[17] != 0)) return NQEDEC;
  if (sigsz(in[17], &sl) != NQOK) return NQENOSUP;
  *hlen = hl;
  if (sig != NULL) *sig = (nqsalg)in[17];
  if (nrcp != NULL) *nrcp = nr;
  return NQOK;
}

int nqkmeini(nqkmctx *c, const nqkrcp *r, size_t n, nqsalg sig,
             const uint8_t *ctx, size_t ctxlen, uint32_t chunk, uint8_t *hdr,
             size_t cap, size_t *hlen) {
  kmst s;
  uint8_t fk[32], ss[32], hek[32], kk[32], hh[32], zn[12];
  size_t hl = 0, i, o, sl;
  int rc;
  if (hlen != NULL) *hlen = 0;
  if (c == NULL) return NQEARG;
  nqwipe(c, sizeof *c);
  rc = nqkmhlen(r, n, &hl);
  if (rc != NQOK) return rc;
  if (hdr == NULL || (ctx == NULL && ctxlen > 0) || ctxlen > NQBXCTX)
    return NQEARG;
  if (sigsz((int)sig, &sl) != NQOK) return NQENOSUP;
  if (chunk == 0) chunk = NQKFCHUNK;
  if (!ckchunk(chunk)) return NQEARG;
  if (hlen != NULL) *hlen = hl;
  if (cap < hl) return NQEBUF;
  memset(&s, 0, sizeof s);
  memset(zn, 0, sizeof zn);
  hdr[0] = 'N';
  hdr[1] = 'Q';
  hdr[2] = 'K';
  hdr[3] = 'M';
  hdr[4] = 2;
  hdr[5] = (uint8_t)(sig != 0);
  nqst32b(hdr + 6, chunk);
  hdr[17] = (uint8_t)sig;
  hdr[18] = (uint8_t)(n >> 8);
  hdr[19] = (uint8_t)n;
  nqst32b(hdr + 20, (uint32_t)hl);
  rc = nqrand(hdr + 10, 7);
  if (rc == NQOK) rc = nqrand(fk, sizeof fk);
  for (i = 0, o = NQKMFIX; i < n && rc == NQOK; i++) {
    nqksz z;
    (void)nqksize(r[i].alg, &z);
    hdr[o] = (uint8_t)r[i].alg;
    rc = nqhash(NQS3256, r[i].pk, r[i].pklen, hek, 32);
    memcpy(hdr + o + 1, hek, 8);
    if (rc == NQOK)
      rc = nqenc(r[i].alg, r[i].pk, r[i].pklen, hdr + o + 9, z.ct, ss, 32);
    if (rc == NQOK)
      rc = kek(ss, hek, ctx, ctxlen, hdr, hdr + o + 9, z.ct, kk);
    /* a key used once: the nonce of zeros is its only one */
    if (rc == NQOK)
      rc = nqccpe(kk, 32, zn, 12, NULL, 0, fk, 32, hdr + o + 9 + z.ct,
                  hdr + o + 9 + z.ct + 32);
    o += ENT(z.ct);
  }
  if (rc == NQOK) rc = skey(fk, ctx, ctxlen, hdr, hl, s.key, hh);
  if (rc == NQOK && sig != 0) {
    rc = nqhini(&s.h, NQS3256);
    if (rc == NQOK) rc = nqhupd(&s.h, hh, 32);
  }
  nqwipe(fk, sizeof fk);
  nqwipe(ss, sizeof ss);
  nqwipe(kk, sizeof kk);
  if (rc == NQOK) {
    s.mag = MAG;
    s.st = NQKFENC;
    s.sig = (int)sig;
    s.chunk = chunk;
    memcpy(s.pre, hdr + 10, 7);
    memcpy(c, &s, sizeof s);
  } else {
    nqwipe(hdr, hl);
    if (hlen != NULL) *hlen = 0;
  }
  nqwipe(&s, sizeof s);
  return rc;
}

int nqkmdini(nqkmctx *c, nqkalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr,
             size_t hlen, uint32_t *chunk, nqsalg *sig) {
  kmst s;
  nqksz z;
  nqsalg sg = (nqsalg)0;
  uint8_t fk[32], ss[32], kk[32], hh[32], zn[12];
  const uint8_t *hek;
  size_t hl = 0, nr = 0, i, o;
  int rc, got = 0;
  if (chunk != NULL) *chunk = 0;
  if (sig != NULL) *sig = (nqsalg)0;
  if (c == NULL) return NQEARG;
  nqwipe(c, sizeof *c);
  if (!nqbxkem(alg)) return nqksize(alg, &z) == NQOK ? NQENOSUP : NQEARG;
  if (sk == NULL || hdr == NULL || (ctx == NULL && ctxlen > 0) ||
      ctxlen > NQBXCTX) {
    return NQEARG;
  }
  (void)nqksize(alg, &z);
  if (sklen != z.sk) return NQEDEC;
  rc = nqkmpeek(hdr, hlen, &hl, &sg, &nr);
  if (rc != NQOK) return rc;
  if (hl != hlen) return NQEDEC;
  memset(&s, 0, sizeof s);
  memset(zn, 0, sizeof zn);
  /* H(ek), which ML-KEM's secret key holds before z (FIPS 203) */
  hek = sk + sklen - 64;
  rc = NQOK;
  for (i = 0, o = NQKMFIX; i < nr; i++) {
    nqksz e;
    /* every entry is of a KEM this noqtis knows and lies within the
     * header, whether it is this key's or not */
    if (o + 1 > hl || !nqbxkem((nqkalg)hdr[o]) ||
        nqksize((nqkalg)hdr[o], &e) != NQOK || o + ENT(e.ct) > hl) {
      rc = NQEDEC;
      break;
    }
    if (!got && (nqkalg)hdr[o] == alg && memcmp(hdr + o + 1, hek, 8) == 0) {
      int r2 = nqdec(alg, sk, sklen, hdr + o + 9, e.ct, ss, 32);
      if (r2 == NQOK)
        r2 = kek(ss, hek, ctx, ctxlen, hdr, hdr + o + 9, e.ct, kk);
      if (r2 == NQOK &&
          nqccpd(kk, 32, zn, 12, NULL, 0, hdr + o + 9 + e.ct, 32,
                 hdr + o + 9 + e.ct + 32, NQAEADTAG, fk) == NQOK) {
        got = 1;
      }
    }
    o += ENT(e.ct);
  }
  if (rc == NQOK && o != hl) rc = NQEDEC;
  /* no entry opens with this key: not one of the recipients, or another
   * context */
  if (rc == NQOK && !got) rc = NQEVRFY;
  if (rc == NQOK) rc = skey(fk, ctx, ctxlen, hdr, hl, s.key, hh);
  if (rc == NQOK && sg != 0) {
    rc = nqhini(&s.h, NQS3256);
    if (rc == NQOK) rc = nqhupd(&s.h, hh, 32);
  }
  nqwipe(fk, sizeof fk);
  nqwipe(ss, sizeof ss);
  nqwipe(kk, sizeof kk);
  if (rc == NQOK) {
    s.mag = MAG;
    s.st = NQKFDEC;
    s.sig = (int)sg;
    s.chunk = nqld32b(hdr + 6);
    memcpy(s.pre, hdr + 10, 7);
    memcpy(c, &s, sizeof s);
    if (chunk != NULL) *chunk = s.chunk;
    if (sig != NULL) *sig = sg;
  }
  nqwipe(&s, sizeof s);
  return rc;
}

/* one chunk either way, n bytes of it at in; last 1 ends the data. The
 * state is written back only when the stream goes on. */
static int step(kmst *s, int st, int last, const uint8_t *in, size_t n,
                uint8_t *out, size_t cap, size_t *outlen) {
  uint8_t nc[12];
  size_t pl;
  int rc = NQOK;
  if (in == NULL && n > 0) rc = NQEARG;
  if (st == NQKFENC) {
    pl = n;
    if (last ? n > s->chunk : n != s->chunk) rc = NQEARG;
  } else {
    pl = n >= NQAEADTAG ? n - NQAEADTAG : 0;
    if (n < NQAEADTAG || (last ? pl > s->chunk : pl != s->chunk)) rc = NQEDEC;
  }
  /* the 2^32nd chunk could only reuse a nonce: refused */
  if (rc == NQOK && !last && s->ctr == 0xffffffffu) rc = NQELIM;
  if (rc == NQOK && out == NULL) rc = NQEARG;
  if (rc == NQOK && cap < (st == NQKFENC ? pl + NQAEADTAG : pl)) {
    if (outlen != NULL) *outlen = st == NQKFENC ? pl + NQAEADTAG : pl;
    return NQEBUF;
  }
  if (rc != NQOK) return rc;
  nonce(s, last, nc);
  if (st == NQKFENC) {
    /* the plaintext is hashed before it is sealed: out may be in */
    if (s->sig != 0) rc = nqhupd(&s->h, in, pl);
    if (rc == NQOK)
      rc = nqccpe(s->key, 32, nc, 12, NULL, 0, in, pl, out, out + pl);
    if (rc == NQOK && outlen != NULL) *outlen = pl + NQAEADTAG;
  } else {
    rc = nqccpd(s->key, 32, nc, 12, NULL, 0, in, pl, in + pl, NQAEADTAG,
                out);
    if (rc == NQOK && s->sig != 0) rc = nqhupd(&s->h, out, pl);
    if (rc == NQOK && outlen != NULL) *outlen = pl;
  }
  if (rc == NQOK && !last) s->ctr++;
  return rc;
}

/* the state of c for a step of kind st, or NQESTATE */
static int load(const nqkmctx *c, int st, kmst *s) {
  if (c == NULL) return NQEARG;
  memcpy(s, c, sizeof *s);
  if (s->mag != MAG || s->st != st || !ckchunk(s->chunk)) {
    nqwipe(s, sizeof *s);
    return NQESTATE;
  }
  return NQOK;
}

static int upd(nqkmctx *c, int st, const uint8_t *in, size_t n, uint8_t *out,
               size_t cap, size_t *outlen) {
  kmst s;
  int rc;
  if (outlen != NULL) *outlen = 0;
  rc = load(c, st, &s);
  if (rc != NQOK) return rc;
  rc = step(&s, st, 0, in, n, out, cap, outlen);
  if (rc == NQOK) {
    memcpy(c, &s, sizeof s);
  } else if (rc != NQEBUF) {
    /* a failure ends the stream; a decryption that failed leaves
     * nothing of the chunk */
    if (st == NQKFDEC && out != NULL) nqwipe(out, cap);
    nqwipe(c, sizeof *c);
  }
  nqwipe(&s, sizeof s);
  return rc;
}

int nqkmeupd(nqkmctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return upd(c, NQKFENC, in, n, out, cap, outlen);
}

int nqkmdupd(nqkmctx *c, const uint8_t *in, size_t n, uint8_t *out,
             size_t cap, size_t *outlen) {
  return upd(c, NQKFDEC, in, n, out, cap, outlen);
}

int nqkmefin(nqkmctx *c, const uint8_t *in, size_t n, const uint8_t *sk,
             size_t sklen, uint8_t *out, size_t cap, size_t *outlen) {
  kmst s;
  uint8_t d[32], nc[12];
  size_t sl = 0, got = 0, o = 0, need;
  int rc;
  if (outlen != NULL) *outlen = 0;
  rc = load(c, NQKFENC, &s);
  if (rc != NQOK) return rc;
  (void)sigsz(s.sig, &sl);
  /* a signed stream needs its signer's key, and no other takes one */
  if ((s.sig != 0) != (sk != NULL) || n > s.chunk) {
    rc = NQEARG;
    goto end;
  }
  need = n + NQAEADTAG + (s.sig != 0 ? sl + NQAEADTAG : 0);
  if (out != NULL && cap < need) {
    if (outlen != NULL) *outlen = need;
    nqwipe(&s, sizeof s);
    return NQEBUF;
  }
  rc = step(&s, NQKFENC, 1, in, n, out, cap, &o);
  if (rc == NQOK && s.sig != 0) {
    rc = nqhfin(&s.h, d, 32);
    if (rc == NQOK)
      rc = nqsign((nqsalg)s.sig, sk, sklen, d, 32, (const uint8_t *)LABS,
                  sizeof LABS - 1, 0, out + o, sl, &got);
    if (rc == NQOK && got != sl) rc = NQEFLT;
    if (rc == NQOK) {
      nonce(&s, 2, nc);
      rc = nqccpe(s.key, 32, nc, 12, NULL, 0, out + o, sl, out + o,
                  out + o + sl);
      o += sl + NQAEADTAG;
    }
  }
  if (rc == NQOK && outlen != NULL) *outlen = o;
  if (rc != NQOK && out != NULL) nqwipe(out, cap);
end:
  nqwipe(d, sizeof d);
  nqwipe(c, sizeof *c);
  nqwipe(&s, sizeof s);
  return rc;
}

int nqkmdfin(nqkmctx *c, const uint8_t *in, size_t n, const uint8_t *pk,
             size_t pklen, uint8_t *out, size_t cap, size_t *outlen) {
  kmst s;
  uint8_t d[32], nc[12], *sg = NULL;
  size_t sl = 0, o = 0, rec;
  int rc;
  if (outlen != NULL) *outlen = 0;
  rc = load(c, NQKFDEC, &s);
  if (rc != NQOK) return rc;
  (void)sigsz(s.sig, &sl);
  rec = s.sig != 0 ? sl + NQAEADTAG : 0;
  /* a key to check a signature the stream does not carry: the caller
   * expected a signed stream, and this is not one */
  if (s.sig == 0 && pk != NULL) {
    rc = NQEVRFY;
    goto end;
  }
  if (in == NULL || n < rec + NQAEADTAG) {
    rc = in == NULL ? NQEARG : NQEDEC;
    goto end;
  }
  if (out != NULL && cap < n - rec - NQAEADTAG) {
    if (outlen != NULL) *outlen = n - rec - NQAEADTAG;
    nqwipe(&s, sizeof s);
    return NQEBUF;
  }
  rc = step(&s, NQKFDEC, 1, in, n - rec, out, cap, &o);
  if (rc == NQOK && s.sig != 0) {
    sg = (uint8_t *)nqmal(sl);
    if (sg == NULL) rc = NQEMEM;
    if (rc == NQOK) {
      nonce(&s, 2, nc);
      rc = nqccpd(s.key, 32, nc, 12, NULL, 0, in + n - rec, sl,
                  in + n - NQAEADTAG, NQAEADTAG, sg);
    }
    if (rc == NQOK) rc = nqhfin(&s.h, d, 32);
    /* without a key the record is only known to be the sender's bytes:
     * whose signature it is, the caller did not ask */
    if (rc == NQOK && pk != NULL)
      rc = nqvrfy((nqsalg)s.sig, pk, pklen, d, 32, (const uint8_t *)LABS,
                  sizeof LABS - 1, 0, sg, sl);
    if (sg != NULL) nqfree(sg, sl);
  }
  if (rc == NQOK && outlen != NULL) *outlen = o;
  if (rc != NQOK && out != NULL) nqwipe(out, cap);
end:
  nqwipe(d, sizeof d);
  nqwipe(c, sizeof *c);
  nqwipe(&s, sizeof s);
  return rc;
}
