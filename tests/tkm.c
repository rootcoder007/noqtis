/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Streams sealed to several keys, signed or not (nqkmeini ... nqkmdfin):
 * every recipient opens one, another key does not; an empty stream,
 * part of a chunk, exactly one and exactly three; a signature that
 * verifies, one under another key, a stream that is not signed read as
 * one, a signed one read without asking who sent it; every byte of the
 * header changed (another recipient's entry too), a chunk changed,
 * dropped or repeated, the signature record cut off or changed, bytes
 * after the end; another context; nqkmpeek's limits; the refusals and
 * misuse. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

#define CH 1024u
#define NR 3
#define SIGMAX 7856u /* SLH-DSA-SHA2-128s */
#define HMAX (NQKMFIX + NR * (1 + 8 + 1568 + 48))
#define MAXS (HMAX + 4 * (CH + 16) + SIGMAX + 16)

static const nqkalg kalg[NR] = {NQMLKEM512, NQMLKEM768, NQMLKEM1024};
static uint8_t kpk[NR][1568], ksk[NR][3168];
static nqksz kz[NR];
static uint8_t xpk[1568], xsk[3168]; /* a key that is not a recipient */
static uint8_t spk[2624], ssk[4960], opk[2624], osk[4960];
static nqssz sz;
static uint8_t st[MAXS], st2[MAXS], pt[4 * CH], back[4 * CH];

static void rcps(nqkrcp *r) {
  int i;
  for (i = 0; i < NR; i++) {
    r[i].alg = kalg[i];
    r[i].pk = kpk[i];
    r[i].pklen = kz[i].pk;
  }
}

/* seals pt[0..n) to the three keys in chunks of CH, signed with sig
 * when it is not 0; the stream's size, 0 on failure */
static size_t seal(nqsalg sig, const uint8_t *ctx, size_t cl, size_t n,
                   uint8_t *o) {
  nqkmctx c;
  nqkrcp r[NR];
  size_t at = 0, w = 0, k = 0;
  rcps(r);
  if (nqkmeini(&c, r, NR, sig, ctx, cl, CH, o, MAXS, &w) != NQOK) return 0;
  while (n - at > CH) {
    if (nqkmeupd(&c, pt + at, CH, o + w, MAXS - w, &k) != NQOK) return 0;
    at += CH;
    w += k;
  }
  if (nqkmefin(&c, pt + at, n - at, sig != 0 ? ssk : NULL,
               sig != 0 ? sz.sk : 0, o + w, MAXS - w, &k) != NQOK)
    return 0;
  return w + k;
}

/* opens a stream of n bytes with recipient i as a reader does: the
 * header by nqkmpeek, the last chunk the one the input ends with (and
 * the signature record after it); pk the sender's key or NULL. NQOK and
 * *got, or the first error. */
static int open1(int i, const uint8_t *sk, const uint8_t *ctx, size_t cl,
                 const uint8_t *in, size_t n, const uint8_t *pk, size_t pkl,
                 size_t *got) {
  nqkmctx c;
  nqsalg sg = (nqsalg)0;
  nqssz z;
  size_t hl = 0, nr = 0, at, w = 0, k = 0, rec = 0;
  uint32_t ch = 0;
  int rc = nqkmpeek(in, n, &hl, &sg, &nr);
  *got = 0;
  if (rc != NQOK) return rc;
  if (hl > n) return NQEDEC;
  rc = nqkmdini(&c, kalg[i], sk, kz[i].sk, ctx, cl, in, hl, &ch, &sg);
  if (rc != NQOK) return rc;
  if (sg != 0) {
    (void)nqssize(sg, &z);
    rec = z.sig + 16;
  }
  at = hl;
  while (n - at > (size_t)ch + 16 + rec) {
    rc = nqkmdupd(&c, in + at, (size_t)ch + 16, back + w, sizeof back - w,
                  &k);
    if (rc != NQOK) return rc;
    at += (size_t)ch + 16;
    w += k;
  }
  rc = nqkmdfin(&c, in + at, n - at, pk, pkl, back + w, sizeof back - w, &k);
  if (rc != NQOK) return rc;
  *got = w + k;
  return NQOK;
}

static void keys(void) {
  int i;
  for (i = 0; i < NR; i++) {
    NQTEQI(nqksize(kalg[i], &kz[i]), NQOK);
    NQTEQI(nqkkg(kalg[i], kpk[i], kz[i].pk, ksk[i], kz[i].sk), NQOK);
  }
  NQTEQI(nqkkg(NQMLKEM768, xpk, kz[1].pk, xsk, kz[1].sk), NQOK);
  NQTEQI(nqssize(NQMLDSA44, &sz), NQOK);
  NQTEQI(nqskg(NQMLDSA44, spk, sz.pk, ssk, sz.sk), NQOK);
  NQTEQI(nqskg(NQMLDSA44, opk, sz.pk, osk, sz.sk), NQOK);
  for (i = 0; i < (int)sizeof pt; i++) pt[i] = (uint8_t)(i * 7 + 1);
}

/* every recipient opens it, at every size; another key does not */
static void tround(void) {
  static const size_t ns[] = {0, 1, 700, CH, CH + 1, 3 * CH, 3 * CH + 5};
  static const uint8_t cx[] = "a context";
  size_t j, n, got;
  int i, sgn;
  for (sgn = 0; sgn < 2; sgn++) {
    for (j = 0; j < sizeof ns / sizeof ns[0]; j++) {
      size_t hl = 0, nr = 0;
      nqsalg sg = (nqsalg)9;
      n = seal(sgn ? NQMLDSA44 : (nqsalg)0, cx, 9, ns[j], st);
      NQTCHK(n > 0);
      NQTEQI(nqkmpeek(st, n, &hl, &sg, &nr), NQOK);
      NQTCHK(nr == NR && hl == NQKMFIX + 3 * 57 + 768 + 1088 + 1568);
      NQTEQI((int)sg, sgn ? (int)NQMLDSA44 : 0);
      /* the stream is the header, the chunks and the record, no more */
      NQTCHK(n == hl + ns[j] + 16 * (ns[j] == 0 ? 1 : (ns[j] + CH - 1) / CH) +
                      (sgn ? sz.sig + 16 : 0));
      for (i = 0; i < NR; i++) {
        memset(back, 0xee, sizeof back);
        NQTEQI(open1(i, ksk[i], cx, 9, st, n, sgn ? spk : NULL,
                     sgn ? sz.pk : 0, &got),
               NQOK);
        NQTCHK(got == ns[j] && memcmp(back, pt, ns[j]) == 0);
      }
      /* a key of the same KEM that is not among them */
      NQTEQI(open1(1, xsk, cx, 9, st, n, NULL, 0, &got), NQEVRFY);
      /* another context: no entry opens */
      NQTEQI(open1(0, ksk[0], (const uint8_t *)"b context", 9, st, n, NULL, 0,
                   &got),
             NQEVRFY);
      NQTEQI(open1(0, ksk[0], NULL, 0, st, n, NULL, 0, &got), NQEVRFY);
    }
  }
}

/* who signed */
static void tsig(void) {
  size_t n, got, m;
  /* another key's signature is refused, and nothing of the last chunk
   * is left */
  n = seal(NQMLDSA44, NULL, 0, 2 * CH + 9, st);
  NQTCHK(n > 0);
  memset(back, 0, sizeof back);
  NQTEQI(open1(2, ksk[2], NULL, 0, st, n, opk, sz.pk, &got), NQEVRFY);
  for (m = 2 * CH; m < 2 * CH + 9; m++) NQTCHK(back[m] == 0);
  /* a key of the wrong size */
  NQTEQI(open1(2, ksk[2], NULL, 0, st, n, opk, 5, &got), NQEDEC);
  /* not asked: the stream opens, signed or not */
  NQTEQI(open1(2, ksk[2], NULL, 0, st, n, NULL, 0, &got), NQOK);
  NQTCHK(got == 2 * CH + 9 && memcmp(back, pt, got) == 0);
  /* a stream that is not signed, read as one that should be */
  n = seal((nqsalg)0, NULL, 0, 100, st);
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  /* the plaintext is signed: a signed stream of other bytes whose
   * record is put in place of this one's fails */
  n = seal(NQMLDSA44, NULL, 0, 300, st);
  pt[5] ^= 1;
  m = seal(NQMLDSA44, NULL, 0, 300, st2);
  pt[5] ^= 1;
  NQTCHK(n == m && n > 0);
  memcpy(st + n - sz.sig - 16, st2 + n - sz.sig - 16, sz.sig + 16);
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  /* Ed25519 and a hybrid sign too */
  {
    static const nqsalg as[] = {NQED25519, NQMDED44};
    size_t a;
    for (a = 0; a < 2; a++) {
      nqssz keep = sz;
      uint8_t kp[sizeof spk], ks[sizeof ssk];
      memcpy(kp, spk, sizeof kp);
      memcpy(ks, ssk, sizeof ks);
      NQTEQI(nqssize(as[a], &sz), NQOK);
      NQTEQI(nqskg(as[a], spk, sz.pk, ssk, sz.sk), NQOK);
      n = seal(as[a], NULL, 0, 50, st);
      NQTCHK(n > 0);
      NQTEQI(open1(1, ksk[1], NULL, 0, st, n, spk, sz.pk, &got), NQOK);
      NQTCHK(got == 50);
      sz = keep;
      memcpy(spk, kp, sizeof kp);
      memcpy(ssk, ks, sizeof ks);
    }
  }
}

/* every byte of the header matters to every recipient, and so do the
 * chunks and the record */
static void ttamper(void) {
  size_t n, got, hl = 0, i;
  int rc;
  n = seal(NQMLDSA44, NULL, 0, CH + 40, st);
  NQTCHK(n > 0);
  NQTEQI(nqkmpeek(st, n, &hl, NULL, NULL), NQOK);
  /* recipient 0 reads a header changed anywhere, its own entry or not:
   * never the plaintext */
  for (i = 0; i < hl; i += (i < 60 ? 1 : 97)) {
    st[i] ^= 0x20;
    rc = open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got);
    NQTCHK(rc != NQOK);
    st[i] ^= 0x20;
  }
  /* a byte of the last recipient's entry: the first still unwraps the
   * file key, and the first chunk's tag fails */
  st[hl - 5] ^= 1;
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  st[hl - 5] ^= 1;
  /* a chunk, the last chunk, the record */
  st[hl + 3] ^= 1;
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  st[hl + 3] ^= 1;
  st[hl + CH + 16 + 2] ^= 1;
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  st[hl + CH + 16 + 2] ^= 1;
  st[n - 20] ^= 1;
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQEVRFY);
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, NULL, 0, &got), NQEVRFY);
  st[n - 20] ^= 1;
  /* the record cut off, a byte after the end, the stream cut at a
   * chunk's end, the first chunk twice */
  NQTCHK(open1(0, ksk[0], NULL, 0, st, n - sz.sig - 16, spk, sz.pk, &got) !=
         NQOK);
  memcpy(st2, st, n);
  st2[n] = 0;
  NQTCHK(open1(0, ksk[0], NULL, 0, st2, n + 1, spk, sz.pk, &got) != NQOK);
  NQTCHK(open1(0, ksk[0], NULL, 0, st, hl + CH + 16, spk, sz.pk, &got) !=
         NQOK);
  memcpy(st2, st, hl + CH + 16);
  memcpy(st2 + hl + CH + 16, st + hl, n - hl);
  NQTCHK(open1(0, ksk[0], NULL, 0, st2, n + CH + 16, spk, sz.pk, &got) !=
         NQOK);
  NQTEQI(open1(0, ksk[0], NULL, 0, st, n, spk, sz.pk, &got), NQOK);
}

/* the limits a reader refuses before it reads further */
static void tpeek(void) {
  uint8_t h[NQKMFIX];
  size_t n, hl = 9, nr = 9;
  nqsalg sg = (nqsalg)9;
  n = seal((nqsalg)0, NULL, 0, 10, st);
  NQTCHK(n > 0);
  memcpy(h, st, sizeof h);
  NQTEQI(nqkmpeek(h, sizeof h, &hl, &sg, &nr), NQOK);
  NQTCHK(hl > NQKMFIX && nr == NR && sg == 0);
  NQTEQI(nqkmpeek(h, sizeof h - 1, &hl, NULL, NULL), NQEDEC);
  NQTCHK(hl == 0);
  NQTEQI(nqkmpeek(NULL, sizeof h, &hl, NULL, NULL), NQEARG);
  NQTEQI(nqkmpeek(h, sizeof h, NULL, NULL, NULL), NQEARG);
  h[0] = 'X';
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQEDEC);
  h[0] = 'N';
  h[4] = 1;
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQEDEC);
  h[4] = 2;
  h[5] = 2; /* a flag this version does not know */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQEDEC);
  h[5] = 1; /* signed, with no algorithm */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQEDEC);
  h[5] = 0;
  h[17] = (uint8_t)NQMLDSA44; /* an algorithm, not signed */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQEDEC);
  h[5] = 1;
  h[17] = 250; /* no such algorithm */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQENOSUP);
  h[5] = 0;
  h[17] = 0;
  h[19] = 0; /* no recipient */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQELIM);
  h[19] = 65;
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQELIM);
  h[19] = NR;
  h[20] = 0x7f; /* a header of two gigabytes */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQELIM);
  h[20] = 0;
  h[21] = 0;
  h[22] = 0;
  h[23] = NQKMFIX; /* no room for the entries */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQELIM);
  memcpy(h, st, sizeof h);
  h[6] = 0xff; /* a chunk of four gigabytes */
  NQTEQI(nqkmpeek(h, sizeof h, &hl, NULL, NULL), NQELIM);
  /* a header whose entries do not add up to its length */
  memcpy(st2, st, n);
  st2[NQKMFIX] = (uint8_t)NQMLKEM1024; /* the first entry, a longer KEM */
  {
    nqkmctx c;
    uint32_t ch;
    NQTEQI(nqkmpeek(st2, n, &hl, NULL, NULL), NQOK);
    NQTEQI(nqkmdini(&c, NQMLKEM512, ksk[0], kz[0].sk, NULL, 0, st2, hl, &ch,
                    NULL),
           NQEDEC);
    st2[NQKMFIX] = 99; /* not a KEM */
    NQTEQI(nqkmdini(&c, NQMLKEM512, ksk[0], kz[0].sk, NULL, 0, st2, hl, &ch,
                    NULL),
           NQEDEC);
    NQTEQI(nqkmdini(&c, NQMLKEM512, ksk[0], kz[0].sk, NULL, 0, st, hl - 1,
                    &ch, NULL),
           NQEDEC);
  }
}

/* refusals and misuse */
static void targs(void) {
  nqkmctx c;
  nqkrcp r[NQKMRCP + 1];
  uint8_t ctxb[256];
  size_t hl = 0, k = 0, i;
  uint32_t ch = 0;
  rcps(r);
  NQTEQI(nqkmhlen(r, 0, &hl), NQEARG);
  NQTEQI(nqkmhlen(NULL, 1, &hl), NQEARG);
  NQTEQI(nqkmhlen(r, 1, NULL), NQEARG);
  for (i = NR; i <= NQKMRCP; i++) r[i] = r[0];
  NQTEQI(nqkmhlen(r, NQKMRCP, &hl), NQOK);
  NQTCHK(hl == NQKMFIX + 57 * 64 + 768 * 62 + 1088 + 1568);
  NQTEQI(nqkmhlen(r, NQKMRCP + 1, &hl), NQEARG);
  r[1].alg = NQHQC128;
  NQTEQI(nqkmhlen(r, NR, &hl), NQENOSUP);
  r[1].alg = (nqkalg)77;
  NQTEQI(nqkmhlen(r, NR, &hl), NQEARG);
  rcps(r);
  r[1].pklen--;
  NQTEQI(nqkmhlen(r, NR, &hl), NQEDEC);
  rcps(r);
  r[2].pk = NULL;
  NQTEQI(nqkmhlen(r, NR, &hl), NQEARG);
  rcps(r);
  NQTEQI(nqkmeini(NULL, r, NR, (nqsalg)0, NULL, 0, CH, st, MAXS, &hl),
         NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 0, CH, NULL, MAXS, &hl),
         NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 3, CH, st, MAXS, &hl), NQEARG);
  memset(ctxb, 'c', sizeof ctxb);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, ctxb, 256, CH, st, MAXS, &hl),
         NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 0, 1023, st, MAXS, &hl),
         NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)200, NULL, 0, CH, st, MAXS, &hl),
         NQENOSUP);
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 0, CH, st, 10, &hl), NQEBUF);
  NQTCHK(hl == NQKMFIX + 3 * 57 + 768 + 1088 + 1568);
  /* a context of the longest size, and the default chunk */
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, ctxb, 255, 0, st, MAXS, &hl), NQOK);
  NQTEQI(nqkmefin(&c, pt, 3, NULL, 0, st + hl, MAXS - hl, &k), NQOK);
  {
    nqkmctx d;
    NQTEQI(nqkmdini(&d, kalg[0], ksk[0], kz[0].sk, ctxb, 255, st, hl, &ch,
                    NULL),
           NQOK);
    NQTCHK(ch == NQKFCHUNK);
    NQTEQI(nqkmdfin(&d, st + hl, k, NULL, 0, back, sizeof back, &k), NQOK);
    NQTCHK(k == 3 && memcmp(back, pt, 3) == 0);
    /* a context that ended is used out of order */
    NQTEQI(nqkmdupd(&d, st + hl, CH + 16, back, sizeof back, &k), NQESTATE);
    NQTEQI(nqkmdfin(&d, st + hl, 19, NULL, 0, back, sizeof back, &k),
           NQESTATE);
  }
  NQTEQI(nqkmeupd(&c, pt, CH, st, MAXS, &k), NQESTATE);
  NQTEQI(nqkmefin(&c, pt, 1, NULL, 0, st, MAXS, &k), NQESTATE);
  NQTEQI(nqkmeupd(NULL, pt, CH, st, MAXS, &k), NQEARG);
  /* the chunks: a part where a whole is wanted, a buffer too small */
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 0, CH, st, MAXS, &hl), NQOK);
  NQTEQI(nqkmeupd(&c, pt, CH, st2, 5, &k), NQEBUF);
  NQTCHK(k == CH + 16);
  NQTEQI(nqkmefin(&c, pt, 9, NULL, 0, st2, 5, &k), NQEBUF);
  NQTCHK(k == 25);
  NQTEQI(nqkmeupd(&c, pt, CH - 1, st2, MAXS, &k), NQEARG);
  NQTEQI(nqkmeupd(&c, pt, CH, st2, MAXS, &k), NQESTATE);
  /* a key for a stream that is not signed, none for one that is, a
   * last chunk over the chunk size */
  NQTEQI(nqkmeini(&c, r, NR, (nqsalg)0, NULL, 0, CH, st, MAXS, &hl), NQOK);
  NQTEQI(nqkmefin(&c, pt, 1, ssk, sz.sk, st2, MAXS, &k), NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, NQMLDSA44, NULL, 0, CH, st, MAXS, &hl), NQOK);
  NQTEQI(nqkmefin(&c, pt, 1, NULL, 0, st2, MAXS, &k), NQEARG);
  NQTEQI(nqkmeini(&c, r, NR, NQMLDSA44, NULL, 0, CH, st, MAXS, &hl), NQOK);
  NQTEQI(nqkmefin(&c, pt, 9, ssk, sz.sk, st2, 30, &k), NQEBUF);
  NQTCHK(k == 25 + sz.sig + 16);
  NQTEQI(nqkmefin(&c, pt, CH + 1, ssk, sz.sk, st2, MAXS, &k), NQEARG);
  /* a signing key that is not one */
  NQTEQI(nqkmeini(&c, r, NR, NQMLDSA44, NULL, 0, CH, st, MAXS, &hl), NQOK);
  NQTCHK(nqkmefin(&c, pt, 9, ssk, 7, st2, MAXS, &k) != NQOK);
  /* the reader's refusals */
  NQTEQI(nqkmdini(NULL, kalg[0], ksk[0], kz[0].sk, NULL, 0, st, hl, &ch,
                  NULL),
         NQEARG);
  NQTEQI(nqkmdini(&c, NQHQC128, ksk[0], kz[0].sk, NULL, 0, st, hl, &ch, NULL),
         NQENOSUP);
  NQTEQI(nqkmdini(&c, (nqkalg)77, ksk[0], kz[0].sk, NULL, 0, st, hl, &ch,
                  NULL),
         NQEARG);
  NQTEQI(nqkmdini(&c, kalg[0], NULL, kz[0].sk, NULL, 0, st, hl, &ch, NULL),
         NQEARG);
  NQTEQI(nqkmdini(&c, kalg[0], ksk[0], kz[0].sk - 1, NULL, 0, st, hl, &ch,
                  NULL),
         NQEDEC);
  NQTEQI(nqkmdini(&c, kalg[0], ksk[0], kz[0].sk, NULL, 2, st, hl, &ch, NULL),
         NQEARG);
  i = seal(NQMLDSA44, NULL, 0, 20, st);
  NQTCHK(i > 0);
  NQTEQI(nqkmpeek(st, i, &hl, NULL, NULL), NQOK);
  NQTEQI(nqkmdini(&c, kalg[0], ksk[0], kz[0].sk, NULL, 0, st, hl, &ch, NULL),
         NQOK);
  NQTEQI(nqkmdfin(&c, st + hl, i - hl, spk, sz.pk, back, 3, &k), NQEBUF);
  NQTCHK(k == 20);
  NQTEQI(nqkmdfin(&c, NULL, i - hl, spk, sz.pk, back, sizeof back, &k),
         NQEARG);
  NQTEQI(nqkmdini(&c, kalg[0], ksk[0], kz[0].sk, NULL, 0, st, hl, &ch, NULL),
         NQOK);
  /* shorter than a tag and the record */
  NQTEQI(nqkmdfin(&c, st + hl, 30, spk, sz.pk, back, sizeof back, &k),
         NQEDEC);
  NQTEQI(nqkmdini(&c, kalg[0], ksk[0], kz[0].sk, NULL, 0, st, hl, &ch, NULL),
         NQOK);
  NQTEQI(nqkmdupd(&c, st + hl, 7, back, sizeof back, &k), NQEDEC);
}

int main(void) {
  keys();
  tround();
  tsig();
  ttamper();
  tpeek();
  targs();
  return nqtdone("tkm");
}
