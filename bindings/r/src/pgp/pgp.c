/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * OpenPGP (RFC 9580), version 6, with the algorithms noqtis has: Ed25519
 * (27) and X25519 (25) of the RFC, and the post-quantum ones of
 * RFC 9980: ML-DSA-65+Ed25519 (30), ML-KEM-768+X25519 (35)
 * and SLH-DSA-SHAKE-128s, -128f and -256s (32, 33, 34).
 *
 * Written: version 6 keys (a primary signing key, a user ID, an
 * encryption subkey, their self-signatures), version 6 signatures,
 * one-pass signed messages, detached and cleartext signatures, version
 * 6 session key packets (to keys and to a passphrase) and version 2
 * encrypted data under AES-256 with OCB. Read: the same, with GCM and
 * EAX and AES-128 and -192 as well, packets in the old header format
 * and with partial lengths.
 *
 * Not here: version 3 and 4 keys and signatures, RSA, DSA, Elgamal and
 * the NIST and Brainpool curves, CFB encryption, compressed data (this
 * library has no inflate), X448 and Ed448. What is not here is reported
 * as NQENOSUP, never guessed at.
 */
#include <string.h>

#include "aead/aead.h"
#include "cap/cap.h"
#include "core/int.h"
#include "der/der.h"
#include "hash/h.h"
#include "pgp/pgp.h"
#include "xdh/xdh.h"

#define PGPMAX ((size_t)1 << 30)
#define FP 32

/* packet types */
#define TPKESK 1
#define TSIG 2
#define TSKESK 3
#define TOPS 4
#define TSECKEY 5
#define TPUBKEY 6
#define TSECSUB 7
#define TCOMP 8
#define TMARKER 10
#define TLIT 11
#define TTRUST 12
#define TUID 13
#define TPUBSUB 14
#define TUATTR 17
#define TSEIPD 18
#define TPAD 21

/* public-key algorithms */
#define AX25519 25
#define AED25519 27
#define AMLDSA65 30
#define ASLH128S 32
#define ASLH128F 33
#define ASLH256S 34
#define AMLKEM768 35

/* ---- sizes ---- */

static size_t pubsz(int a) {
  switch (a) {
  case AX25519:
  case AED25519:
  case ASLH128S:
  case ASLH128F:
    return 32;
  case ASLH256S:
    return 64;
  case AMLDSA65:
    return 32 + 1952;
  case AMLKEM768:
    return 32 + 1184;
  default:
    return 0;
  }
}

static size_t secsz(int a) {
  switch (a) {
  case AX25519:
  case AED25519:
    return 32;
  case ASLH128S:
  case ASLH128F:
  case AMLDSA65:
    return 64;
  case ASLH256S:
    return 128;
  case AMLKEM768:
    return 32 + 64;
  default:
    return 0;
  }
}

static size_t sigsz(int a) {
  switch (a) {
  case AED25519:
    return 64;
  case AMLDSA65:
    return 64 + 3309;
  case ASLH128S:
    return 7856;
  case ASLH128F:
    return 17088;
  case ASLH256S:
    return 29792;
  default:
    return 0;
  }
}

static int issig(int a) { return sigsz(a) != 0; }
static int isenc(int a) { return a == AX25519 || a == AMLKEM768; }

static nqsalg slhalg(int a) {
  return a == ASLH128S ? NQSLHK128S : a == ASLH128F ? NQSLHK128F
                                                    : NQSLHK256S;
}

/* a hash by its OpenPGP number: the algorithm, and the size of the salt
 * a version 6 signature carries with it; 0 for one not taken */
static size_t hashof(int id, nqhalg *h) {
  switch (id) {
  case 8:
    *h = NQS256;
    return 16;
  case 9:
    *h = NQS384;
    return 24;
  case 10:
    *h = NQS512;
    return 32;
  case 12:
    *h = NQS3256;
    return 16;
  case 14:
    *h = NQS3512;
    return 32;
  default:
    return 0;
  }
}

static size_t keylen(int cipher) {
  return cipher == 7 ? 16 : cipher == 8 ? 24 : cipher == 9 ? 32 : 0;
}

static size_t noncelen(int aead) {
  return aead == 1 ? 16 : aead == 2 ? 15 : aead == 3 ? 12 : 0;
}

/* ---- bytes ---- */

static void put8(nqdw *w, unsigned v) {
  uint8_t b = (uint8_t)v;
  nqdwraw(w, &b, 1);
}

static void put32(nqdw *w, uint64_t v) {
  uint8_t b[4];
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
  nqdwraw(w, b, 4);
}

static uint32_t get32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

/* one packet, in the OpenPGP format of the header (section 4.2.1) */
static void pkt(nqdw *w, int type, const uint8_t *b, size_t n) {
  put8(w, 0xc0u | (unsigned)type);
  if (n < 192) {
    put8(w, (unsigned)n);
  } else if (n < 8384) {
    put8(w, (unsigned)(((n - 192) >> 8) + 192));
    put8(w, (unsigned)((n - 192) & 0xff));
  } else {
    put8(w, 0xff);
    put32(w, n);
  }
  nqdwraw(w, b, n);
}

/* a packet read: its body in the caller's bytes, or, when it came in
 * parts, in own (ownn bytes, to free) */
typedef struct {
  int type;
  const uint8_t *b;
  size_t n;
  uint8_t *own;
  size_t ownn;
} ppkt;

static void pktfree(ppkt *k) {
  if (k->own != NULL) nqfree(k->own, k->ownn);
  k->own = NULL;
}

/* a length of the OpenPGP format at p[*at]: 0 a whole length, 1 a
 * partial one (more follows the bytes it counts) */
static int newlen(const uint8_t *p, size_t n, size_t *at, size_t *len,
                  int *part) {
  uint8_t o;
  if (*at >= n) return NQEDEC;
  o = p[(*at)++];
  *part = 0;
  if (o < 192) {
    *len = o;
  } else if (o < 224) {
    if (*at >= n) return NQEDEC;
    *len = (((size_t)o - 192) << 8) + p[(*at)++] + 192;
  } else if (o == 255) {
    if (n - *at < 4) return NQEDEC;
    *len = get32(p + *at);
    *at += 4;
  } else {
    *len = (size_t)1 << (o & 0x1f);
    *part = 1;
  }
  return NQOK;
}

/* the next packet at p[*at] */
static int rdpkt(const uint8_t *p, size_t n, size_t *at, ppkt *k) {
  size_t i = *at, len = 0;
  int part = 0, rc;
  uint8_t h;
  memset(k, 0, sizeof *k);
  if (i >= n) return NQEDEC;
  h = p[i++];
  if ((h & 0x80) == 0) return NQEDEC;
  if ((h & 0x40) == 0) {
    /* the legacy format: the type in bits 5-2, the length's kind below */
    k->type = (h >> 2) & 0x0f;
    switch (h & 3) {
    case 0:
      if (n - i < 1) return NQEDEC;
      len = p[i++];
      break;
    case 1:
      if (n - i < 2) return NQEDEC;
      len = ((size_t)p[i] << 8) | p[i + 1];
      i += 2;
      break;
    case 2:
      if (n - i < 4) return NQEDEC;
      len = get32(p + i);
      i += 4;
      break;
    default:
      len = n - i; /* to the end */
      break;
    }
    if (len > n - i) return NQEDEC;
    k->b = p + i;
    k->n = len;
    *at = i + len;
    return NQOK;
  }
  k->type = h & 0x3f;
  rc = newlen(p, n, &i, &len, &part);
  if (rc != NQOK) return rc;
  if (len > n - i) return NQEDEC;
  if (!part) {
    k->b = p + i;
    k->n = len;
    *at = i + len;
    return NQOK;
  }
  /* partial lengths: the parts gathered into one body */
  k->ownn = n - i;
  k->own = (uint8_t *)nqmal(k->ownn > 0 ? k->ownn : 1);
  if (k->own == NULL) return NQEMEM;
  if (k->ownn == 0) k->ownn = 1;
  for (;;) {
    memcpy(k->own + k->n, p + i, len);
    k->n += len;
    i += len;
    if (!part) break;
    rc = newlen(p, n, &i, &len, &part);
    if (rc != NQOK || len > n - i) {
      pktfree(k);
      return NQEDEC;
    }
  }
  k->b = k->own;
  *at = i;
  return NQOK;
}

/* ---- AEAD ---- */

static int aeade(int aead, const uint8_t *key, size_t kl,
                 const uint8_t *nonce, const uint8_t *ad, size_t al,
                 const uint8_t *in, size_t n, uint8_t *out, uint8_t *tag) {
  nqgcm g;
  int rc;
  switch (aead) {
  case 1:
    return nqeaxe(key, kl, nonce, 16, ad, al, in, n, out, tag);
  case 2:
    return nqocbe(key, kl, nonce, 15, ad, al, in, n, out, tag);
  case 3:
    rc = nqgcmk(&g, key, kl);
    if (rc == NQOK) rc = nqgcme(&g, nonce, 12, ad, al, in, n, out, tag);
    nqwipe(&g, sizeof g);
    return rc;
  default:
    return NQENOSUP;
  }
}

static int aeadd(int aead, const uint8_t *key, size_t kl,
                 const uint8_t *nonce, const uint8_t *ad, size_t al,
                 const uint8_t *in, size_t n, const uint8_t *tag,
                 uint8_t *out) {
  nqgcm g;
  int rc;
  switch (aead) {
  case 1:
    return nqeaxd(key, kl, nonce, 16, ad, al, in, n, tag, out);
  case 2:
    return nqocbd(key, kl, nonce, 15, ad, al, in, n, tag, out);
  case 3:
    rc = nqgcmk(&g, key, kl);
    if (rc == NQOK)
      rc = nqgcmd(&g, nonce, 12, ad, al, in, n, tag, 16, out);
    nqwipe(&g, sizeof g);
    return rc;
  default:
    return NQENOSUP;
  }
}

/* HKDF with SHA-256, as every key of the format is derived */
static int hkdf(const uint8_t *salt, size_t sn, const uint8_t *ikm, size_t in,
                const uint8_t *info, size_t fn, uint8_t *out, size_t on) {
  uint8_t prk[32];
  int rc = nqhkx(NQS256, salt, sn, ikm, in, prk);
  if (rc == NQOK) rc = nqhke(NQS256, prk, sizeof prk, info, fn, out, on);
  nqwipe(prk, sizeof prk);
  return rc;
}

/* the key of a passphrase by one of the hashed S2K specifiers (section
 * 3.7.1.1 to 3.7.1.3): simple, salted, or iterated and salted, with
 * SHA2-256, -384 or -512. For a key longer than the digest, further
 * contexts are preloaded with zero octets. */
static int s2khash(const uint8_t *s, size_t sn, const uint8_t *pw,
                   size_t pwn, uint8_t *out, size_t on) {
  static const uint8_t zero[4] = {0, 0, 0, 0};
  nqhalg h;
  nqhctx c;
  const uint8_t *salt = NULL;
  uint8_t dig[64];
  uint64_t total, left;
  size_t need = s[0] == 0 ? 2 : s[0] == 1 ? 10 : 11, sl = 0, hl, o = 0, k;
  unsigned ctx = 0;
  if (sn != need) return NQEDEC;
  /* SHA-1, MD5 and RIPEMD-160 specifiers are older than version 6 */
  if (s[1] != 8 && s[1] != 9 && s[1] != 10) return NQENOSUP;
  (void)hashof(s[1], &h);
  hl = nqhlen(h);
  if (s[0] != 0) {
    salt = s + 2;
    sl = 8;
  }
  total = sl + pwn;
  if (s[0] == 3) {
    uint64_t cnt = ((uint64_t)16 + (s[10] & 15)) << ((s[10] >> 4) + 6);
    if (cnt > total) total = cnt;
  }
  while (o < on) {
    if (ctx > 3) return NQEDEC;
    nqhini(&c, h);
    if (ctx > 0) nqhupd(&c, zero, ctx);
    /* the salt and the passphrase, over and over, cut at the count */
    for (left = total; left > 0;) {
      k = left < sl ? (size_t)left : sl;
      if (k > 0) nqhupd(&c, salt, k);
      left -= k;
      k = left < pwn ? (size_t)left : pwn;
      if (k > 0) nqhupd(&c, pw, k);
      left -= k;
      if (sl + pwn == 0) break;
    }
    nqhfin(&c, dig, hl);
    k = on - o < hl ? on - o : hl;
    memcpy(out + o, dig, k);
    o += k;
    ctx++;
  }
  nqwipe(dig, sizeof dig);
  return NQOK;
}

/* Argon2id as this file writes it: 3 passes, 4 lanes, 2^16 KiB (64
 * MiB); and the most a key or message read may ask for: 16 passes and
 * 2^22 KiB (4 GiB), as nqa2id limits it. */
static uint8_t s2kt = 3, s2kp = 4, s2km = 16, s2ktmax = 16, s2kmmax = 22;

#ifdef NQTEST
void nqpgps2k(unsigned t, unsigned p, unsigned m) {
  s2kt = s2ktmax = (uint8_t)t;
  s2kp = (uint8_t)p;
  s2km = s2kmmax = (uint8_t)m;
}
#endif

/* the key of a passphrase, as the S2K specifier s says: Argon2id
 * (section 3.7.1.4), or one of the hashed ones */
static int s2k(const uint8_t *s, size_t sn, const uint8_t *pw, size_t pwn,
               uint8_t *out, size_t on) {
  uint32_t t, p, m;
  if (sn < 2) return NQEDEC;
  if (s[0] == 0 || s[0] == 1 || s[0] == 3)
    return s2khash(s, sn, pw, pwn, out, on);
  if (s[0] != 4) return NQENOSUP;
  if (sn != 20) return NQEDEC;
  t = s[17];
  p = s[18];
  if (t == 0 || p == 0 || s[19] > 31) return NQEDEC;
  /* as nqa2id limits it: a key file cannot ask for more */
  if (s[19] > s2kmmax || t > s2ktmax || p > 16) return NQELIM;
  m = (uint32_t)1 << s[19];
  if (m < 8 * p) return NQEDEC;
  return nqa2id(pw, pwn, s + 1, 16, NULL, 0, NULL, 0, t, m, p, out, on);
}

/* ---- keys ---- */

typedef struct {
  int alg;
  int sec;               /* a Secret Key or Secret Subkey packet */
  int sub;               /* a subkey packet */
  uint32_t created;
  const uint8_t *body;   /* the public key packet's fields */
  size_t bodylen;
  const uint8_t *pub;    /* the key material in them */
  const uint8_t *rest;   /* a secret packet: what follows those fields */
  size_t restlen;
  uint8_t fp[FP];
} pkey;

/* the fingerprint of a version 6 key (section 5.5.4.3) */
static void fprint(const uint8_t *body, size_t n, uint8_t fp[FP]) {
  nqhctx h;
  uint8_t pre[5];
  pre[0] = 0x9b;
  pre[1] = (uint8_t)(n >> 24);
  pre[2] = (uint8_t)(n >> 16);
  pre[3] = (uint8_t)(n >> 8);
  pre[4] = (uint8_t)n;
  nqhini(&h, NQS256);
  nqhupd(&h, pre, 5);
  nqhupd(&h, body, n);
  nqhfin(&h, fp, FP);
}

static int keyread(const ppkt *k, pkey *o) {
  size_t ml;
  memset(o, 0, sizeof *o);
  o->sec = k->type == TSECKEY || k->type == TSECSUB;
  o->sub = k->type == TPUBSUB || k->type == TSECSUB;
  if (k->n < 10) return NQEDEC;
  /* versions 3 and 4 are another format, and other fingerprints */
  if (k->b[0] != 6) return k->b[0] == 3 || k->b[0] == 4 ? NQENOSUP : NQEDEC;
  o->created = get32(k->b + 1);
  o->alg = k->b[5];
  ml = get32(k->b + 6);
  if (ml > k->n - 10) return NQEDEC;
  if (pubsz(o->alg) == 0) return NQENOSUP;
  if (ml != pubsz(o->alg)) return NQEDEC;
  o->body = k->b;
  o->bodylen = 10 + ml;
  o->pub = k->b + 10;
  o->rest = k->b + o->bodylen;
  o->restlen = k->n - o->bodylen;
  if (!o->sec && o->restlen != 0) return NQEDEC;
  if (o->sec && o->restlen == 0) return NQEDEC;
  fprint(o->body, o->bodylen, o->fp);
  return NQOK;
}

/* the secret key material of a secret packet into out (secsz bytes):
 * as it is, or opened with the passphrase (section 5.5.3) */
static int keysec(const pkey *k, const uint8_t *pw, size_t pwn,
                  uint8_t *out) {
  const uint8_t *r = k->rest, *sp, *iv, *ct;
  size_t n = k->restlen, want = secsz(k->alg), kl, nl, sl, cn;
  uint8_t key[32], kek[32], info[4], *ad;
  int cipher, aead, rc;
  if (!k->sec || n < 1) return NQEARG;
  if (r[0] == 0) {
    if (n != 1 + want) return NQEDEC;
    memcpy(out, r + 1, want);
    return NQOK;
  }
  /* 254 and 255 are CFB, with SHA-1 or a checksum */
  if (r[0] != 253) return NQENOSUP;
  if (n < 5 || (size_t)r[1] + 2 > n) return NQEDEC;
  cipher = r[2];
  aead = r[3];
  sl = r[4];
  kl = keylen(cipher);
  nl = noncelen(aead);
  if (kl == 0 || nl == 0) return NQENOSUP;
  /* the count covers the cipher, the mode, the specifier's length, the
   * specifier and the nonce */
  if ((size_t)r[1] != 3 + sl + nl || n < 2 + (size_t)r[1] + 16)
    return NQEDEC;
  sp = r + 5;
  iv = sp + sl;
  ct = iv + nl;
  cn = n - 2 - (size_t)r[1];
  if (cn != want + 16) return NQEDEC;
  if (pw == NULL) return NQEARG; /* a passphrase is needed */
  rc = s2k(sp, sl, pw, pwn, key, kl);
  if (rc != NQOK) return rc;
  info[0] = (uint8_t)(0xc0 | (k->sub ? TSECSUB : TSECKEY));
  info[1] = 6;
  info[2] = (uint8_t)cipher;
  info[3] = (uint8_t)aead;
  rc = hkdf(NULL, 0, key, kl, info, 4, kek, kl);
  nqwipe(key, sizeof key);
  if (rc != NQOK) return rc;
  ad = (uint8_t *)nqmal(1 + k->bodylen);
  if (ad == NULL) {
    nqwipe(kek, sizeof kek);
    return NQEMEM;
  }
  ad[0] = info[0];
  memcpy(ad + 1, k->body, k->bodylen);
  rc = aeadd(aead, kek, kl, iv, ad, 1 + k->bodylen, ct, want, ct + want, out);
  nqwipe(kek, sizeof kek);
  nqfree(ad, 1 + k->bodylen);
  return rc;
}

/* ---- signing and verifying a digest ---- */

/* an Ed25519 key pair from its 32 secret bytes */
static int edkeys(const uint8_t *s, uint8_t *pk, uint8_t *sk, size_t skn) {
  return nqskgd(NQED25519, s, 32, pk, 32, sk, skn);
}

static int rawsign(int alg, const uint8_t *sec, const uint8_t *dig, size_t dn,
                   uint8_t *sig) {
  nqssz z;
  uint8_t pk[32], *sk = NULL, *mp = NULL;
  size_t n = 0;
  int rc;
  if (alg == AED25519 || alg == AMLDSA65) {
    rc = nqssize(NQED25519, &z);
    if (rc != NQOK) return rc;
    sk = (uint8_t *)nqmal(z.sk);
    if (sk == NULL) return NQEMEM;
    rc = edkeys(sec, pk, sk, z.sk);
    if (rc == NQOK)
      rc = nqsign(NQED25519, sk, z.sk, dig, dn, NULL, 0, 0, sig, 64, &n);
    nqfree(sk, z.sk);
    if (rc != NQOK || alg == AED25519) return rc;
    /* then ML-DSA-65 over the same digest, its key from the seed */
    rc = nqssize(NQMLDSA65, &z);
    if (rc != NQOK) return rc;
    sk = (uint8_t *)nqmal(z.sk);
    mp = (uint8_t *)nqmal(z.pk);
    rc = sk == NULL || mp == NULL ? NQEMEM
                                  : nqskgd(NQMLDSA65, sec + 32, 32, mp, z.pk,
                                           sk, z.sk);
    if (rc == NQOK)
      rc = nqsign(NQMLDSA65, sk, z.sk, dig, dn, NULL, 0, 0, sig + 64, z.sig,
                  &n);
    if (sk != NULL) nqfree(sk, z.sk);
    if (mp != NULL) nqfree(mp, z.pk);
    return rc;
  }
  if (alg == ASLH128S || alg == ASLH128F || alg == ASLH256S) {
    return nqsign(slhalg(alg), sec, secsz(alg), dig, dn, NULL, 0, 0, sig,
                  sigsz(alg), &n);
  }
  return NQENOSUP;
}

static int rawvrfy(int alg, const uint8_t *pub, const uint8_t *dig,
                   size_t dn, const uint8_t *sig, size_t sn) {
  int rc;
  if (sn != sigsz(alg) || sn == 0) return NQEVRFY;
  switch (alg) {
  case AED25519:
    return nqvrfy(NQED25519, pub, 32, dig, dn, NULL, 0, 0, sig, 64);
  case AMLDSA65:
    /* both parts must verify */
    rc = nqvrfy(NQED25519, pub, 32, dig, dn, NULL, 0, 0, sig, 64);
    if (rc != NQOK) return rc;
    return nqvrfy(NQMLDSA65, pub + 32, 1952, dig, dn, NULL, 0, 0, sig + 64,
                  3309);
  case ASLH128S:
  case ASLH128F:
  case ASLH256S:
    return nqvrfy(slhalg(alg), pub, pubsz(alg), dig, dn, NULL, 0, 0, sig, sn);
  default:
    return NQENOSUP;
  }
}

/* ---- signatures ---- */

/* what is hashed before the trailer: up to four pieces */
typedef struct {
  const uint8_t *p[4];
  size_t n[4];
  size_t k;
} parts;

static void addpart(parts *x, const uint8_t *p, size_t n) {
  x->p[x->k] = p;
  x->n[x->k] = n;
  x->k++;
}

/* the digest of a version 6 signature (section 5.2.4): the salt, the
 * pieces, the signature's own fields, the trailer */
static int sigdig(nqhalg h, const uint8_t *salt, size_t sn, const parts *x,
                  const uint8_t *hdr, size_t hn, uint8_t *dig) {
  nqhctx c;
  uint8_t tr[6];
  size_t i;
  int rc = nqhini(&c, h);
  if (rc != NQOK) return rc;
  nqhupd(&c, salt, sn);
  for (i = 0; i < x->k; i++) {
    if (x->n[i] > 0) nqhupd(&c, x->p[i], x->n[i]);
  }
  nqhupd(&c, hdr, hn);
  tr[0] = 6;
  tr[1] = 0xff;
  tr[2] = (uint8_t)(hn >> 24);
  tr[3] = (uint8_t)(hn >> 16);
  tr[4] = (uint8_t)(hn >> 8);
  tr[5] = (uint8_t)hn;
  nqhupd(&c, tr, 6);
  return nqhfin(&c, dig, nqhlen(h));
}

/* the piece a key contributes to a signature over it */
static int keypart(nqdw *w, const pkey *k) {
  put8(w, 0x9b);
  put32(w, k->bodylen);
  nqdwraw(w, k->body, k->bodylen);
  return w->err;
}

/* one subpacket: its type and data */
static void subpkt(nqdw *w, int type, const uint8_t *d, size_t n) {
  put8(w, (unsigned)(n + 1));
  put8(w, (unsigned)type);
  nqdwraw(w, d, n);
}

/* a Signature packet of the type by the key k with the secret material
 * sec, at the time at, over the pieces x, with the salt (32 bytes,
 * SHA2-512) and the extra hashed subpackets ex; appended to out */
static int mksig(nqdw *out, int type, const pkey *k, const uint8_t *sec,
                 int64_t at, const uint8_t *salt, const parts *x,
                 const uint8_t *ex, size_t exn) {
  nqdw h, b;
  uint8_t dig[64], t4[4], fp[1 + FP], *sig = NULL;
  size_t sn = sigsz(k->alg);
  int rc;
  if (sn == 0) return NQENOSUP;
  if (at < 0 || at > 0xffffffffll) return NQEARG;
  nqdwini(&h);
  nqdwini(&b);
  /* the fields that are hashed: version, type, algorithms, the hashed
   * subpackets (creation time, issuer fingerprint, the caller's) */
  put8(&h, 6);
  put8(&h, (unsigned)type);
  put8(&h, (unsigned)k->alg);
  put8(&h, 10);
  put32(&h, 6 + 2 + FP + 1 + exn);
  t4[0] = (uint8_t)(at >> 24);
  t4[1] = (uint8_t)(at >> 16);
  t4[2] = (uint8_t)(at >> 8);
  t4[3] = (uint8_t)at;
  subpkt(&h, 2, t4, 4);
  fp[0] = 6;
  memcpy(fp + 1, k->fp, FP);
  subpkt(&h, 33, fp, sizeof fp);
  nqdwraw(&h, ex, exn);
  rc = h.err;
  if (rc != NQOK) goto done;
  rc = sigdig(NQS512, salt, 32, x, h.p, h.n, dig);
  if (rc != NQOK) goto done;
  sig = (uint8_t *)nqmal(sn);
  if (sig == NULL) {
    rc = NQEMEM;
    goto done;
  }
  rc = rawsign(k->alg, sec, dig, 64, sig);
  /* never given out unverified: a fault while signing would otherwise
   * show the key */
  if (rc == NQOK) rc = rawvrfy(k->alg, k->pub, dig, 64, sig, sn);
  if (rc == NQEVRFY) rc = NQEARG; /* the secret is not this key's */
  if (rc != NQOK) goto done;
  nqdwraw(&b, h.p, h.n);
  put32(&b, 0); /* no unhashed subpackets */
  nqdwraw(&b, dig, 2);
  put8(&b, 32);
  nqdwraw(&b, salt, 32);
  nqdwraw(&b, sig, sn);
  rc = b.err;
  if (rc == NQOK) {
    pkt(out, TSIG, b.p, b.n);
    rc = out->err;
  }
done:
  nqdwfree(&h);
  nqdwfree(&b);
  if (sig != NULL) nqfree(sig, sn);
  return rc;
}

/* a Signature packet read */
typedef struct {
  int type, pkalg, halg;
  const uint8_t *hdr;     /* version through the hashed subpackets */
  size_t hdrn;
  const uint8_t *left;    /* the first two bytes of the digest */
  const uint8_t *salt;
  size_t saltn;
  const uint8_t *sig;
  size_t sign;
  uint32_t created, keyexp;
  int hascreated, haskeyexp, hasissuer, hasflags, crit;
  uint8_t issuer[FP], flags;
} psig;

/* the subpackets of one area; hashed ones are taken, unhashed ones only
 * looked through for their form */
static int subread(const uint8_t *p, size_t n, int hashed, psig *s) {
  size_t i = 0, len;
  int part, t;
  while (i < n) {
    if (newlen(p, n, &i, &len, &part) != NQOK || part || len < 1 ||
        len > n - i)
      return NQEDEC;
    t = p[i] & 0x7f;
    if (hashed) {
      const uint8_t *d = p + i + 1;
      size_t dn = len - 1;
      switch (t) {
      case 2:
        if (dn != 4) return NQEDEC;
        s->created = get32(d);
        s->hascreated = 1;
        break;
      case 9:
        if (dn != 4) return NQEDEC;
        s->keyexp = get32(d);
        s->haskeyexp = 1;
        break;
      case 27:
        if (dn < 1) return NQEDEC;
        s->flags = d[0];
        s->hasflags = 1;
        break;
      case 33:
        if (dn == 1 + FP && d[0] == 6) {
          memcpy(s->issuer, d + 1, FP);
          s->hasissuer = 1;
        }
        break;
      case 3: case 4: case 5: case 6: case 7: case 10: case 11: case 12:
      case 16: case 20: case 21: case 22: case 23: case 24: case 25: case 26:
      case 28: case 29: case 30: case 31: case 32: case 34: case 35: case 39:
        break; /* known, and of no weight here */
      default:
        /* a critical subpacket this code does not know voids the
         * signature (section 5.2.3.7) */
        if (p[i] & 0x80) s->crit = 1;
        break;
      }
    }
    i += len;
  }
  return NQOK;
}

static int sigread(const ppkt *k, psig *s) {
  const uint8_t *b = k->b;
  size_t n = k->n, hn, un, i;
  nqhalg h;
  memset(s, 0, sizeof *s);
  if (n < 1) return NQEDEC;
  if (b[0] != 6) return b[0] == 3 || b[0] == 4 ? NQENOSUP : NQEDEC;
  if (n < 8) return NQEDEC;
  s->type = b[1];
  s->pkalg = b[2];
  s->halg = b[3];
  hn = get32(b + 4);
  if (hn > n - 8) return NQEDEC;
  s->hdr = b;
  s->hdrn = 8 + hn;
  i = 8 + hn;
  if (n - i < 4) return NQEDEC;
  un = get32(b + i);
  i += 4;
  if (un > n - i || n - i - un < 3) return NQEDEC;
  if (subread(b + 8, hn, 1, s) != NQOK ||
      subread(b + i, un, 0, s) != NQOK)
    return NQEDEC;
  i += un;
  s->left = b + i;
  s->saltn = b[i + 2];
  i += 3;
  if (s->saltn > n - i) return NQEDEC;
  s->salt = b + i;
  i += s->saltn;
  s->sig = b + i;
  s->sign = n - i;
  /* the salt has the size its hash calls for (table 23) */
  if (hashof(s->halg, &h) == 0) return NQENOSUP;
  if (s->saltn != hashof(s->halg, &h)) return NQEDEC;
  return NQOK;
}

/* NQOK when the signature s over the pieces x verifies under the key */
static int sigcheck(const psig *s, const pkey *k, const parts *x) {
  uint8_t dig[64];
  nqhalg h;
  int rc;
  if (hashof(s->halg, &h) == 0 || !issig(k->alg)) return NQENOSUP;
  if (s->pkalg != k->alg || s->crit || !s->hascreated) return NQEVRFY;
  if (s->hasissuer && memcmp(s->issuer, k->fp, FP) != 0) return NQEVRFY;
  rc = sigdig(h, s->salt, s->saltn, x, s->hdr, s->hdrn, dig);
  if (rc != NQOK) return rc;
  if (dig[0] != s->left[0] || dig[1] != s->left[1]) return NQEVRFY;
  rc = rawvrfy(k->alg, k->pub, dig, nqhlen(h), s->sig, s->sign);
  return rc == NQOK ? NQOK : rc == NQEMEM ? rc : NQEVRFY;
}

/* ---- certificates ---- */

typedef struct {
  pkey prim;
  pkey enc;              /* the encryption subkey, when hasenc */
  int hasenc;
  const uint8_t *uid;
  size_t uidlen;
  uint8_t flags;         /* the primary key's, 0x03 when it says none */
  uint32_t expires;      /* seconds after creation, 0 for never */
  ppkt hold[2];          /* bodies gathered from partial lengths */
} pcert;

static void certfree(pcert *c) {
  pktfree(&c->hold[0]);
  pktfree(&c->hold[1]);
}

#ifdef NQTEST
static const uint8_t *vouch[2];
void nqpgpvouch(const uint8_t *a, const uint8_t *b) {
  vouch[0] = a;
  vouch[1] = b;
}
#endif

/* whether the self-signature s of the key k, read from p, is good */
static int selfsig(const uint8_t *p, const psig *s, const pkey *k,
                   const parts *x) {
#ifdef NQTEST
  if (p == vouch[0] || p == vouch[1]) return 1; /* never NULL: p is read */
#else
  (void)p;
#endif
  return sigcheck(s, k, x) == NQOK;
}

/* reads the first certificate (or secret key) at p: the primary key,
 * its user ID, its encryption subkey, each taken only with a
 * self-signature that verifies; NQEVRFY for a key with none, a revoked
 * one, or one expired at the time at (0: not asked) */
static int certread(const uint8_t *p, size_t n, int64_t at, pcert *c) {
  ppkt k;
  pkey sub;
  psig s;
  nqdw kp, sp, up;
  parts x;
  const uint8_t *uid = NULL;
  size_t i = 0, uidn = 0;
  int rc, self = 0, revoked = 0, havesub = 0, first = 1, good;
  memset(c, 0, sizeof *c);
  memset(&sub, 0, sizeof sub);
  nqdwini(&kp);
  nqdwini(&sp);
  nqdwini(&up);
  rc = NQEDEC;
  while (i < n) {
    rc = rdpkt(p, n, &i, &k);
    if (rc != NQOK) goto done;
    if (first) {
      if (k.type != TPUBKEY && k.type != TSECKEY) {
        pktfree(&k);
        rc = NQEDEC;
        goto done;
      }
      rc = keyread(&k, &c->prim);
      c->hold[0] = k;
      if (rc != NQOK) goto done;
      if (!issig(c->prim.alg)) {
        rc = NQENOSUP;
        goto done;
      }
      rc = keypart(&kp, &c->prim);
      if (rc != NQOK) goto done;
      first = 0;
      continue;
    }
    switch (k.type) {
    case TPUBKEY:
    case TSECKEY:
      /* the next certificate: this one ends here */
      pktfree(&k);
      i = n;
      break;
    case TUID:
      /* a user ID in the caller's bytes; one that came in parts (never
       * written so) is passed over */
      if (k.own == NULL) {
        uid = k.b;
        uidn = k.n;
        up.n = 0;
        put8(&up, 0xb4);
        put32(&up, uidn);
        nqdwraw(&up, uid, uidn);
      }
      havesub = 0;
      pktfree(&k);
      break;
    case TPUBSUB:
    case TSECSUB:
      havesub = 0;
      if (c->hasenc || k.own != NULL || keyread(&k, &sub) != NQOK ||
          !isenc(sub.alg)) {
        pktfree(&k);
        break;
      }
      sp.n = 0;
      if (keypart(&sp, &sub) == NQOK) havesub = 1;
      c->hold[1] = k;
      break;
    case TSIG:
      if (sigread(&k, &s) != NQOK) {
        pktfree(&k);
        break; /* a signature this code does not read binds nothing */
      }
      memset(&x, 0, sizeof x);
      addpart(&x, kp.p, kp.n);
      good = 0;
      if (s.type == 0x1f || s.type == 0x20) {
        good = selfsig(p, &s, &c->prim, &x);
        if (good && s.type == 0x20) revoked = 1;
      } else if (s.type >= 0x10 && s.type <= 0x13 && uid != NULL) {
        addpart(&x, up.p, up.n);
        good = selfsig(p, &s, &c->prim, &x);
        if (good && c->uid == NULL) {
          c->uid = uid;
          c->uidlen = uidn;
        }
      } else if ((s.type == 0x18 || s.type == 0x28) && havesub) {
        addpart(&x, sp.p, sp.n);
        if (selfsig(p, &s, &c->prim, &x)) {
          if (s.type == 0x28) {
            havesub = 0; /* a revoked subkey */
          } else if (s.hasflags && (s.flags & 0x0c) != 0) {
            c->enc = sub;
            c->hasenc = 1;
          }
        }
      }
      /* what a self-signature of the primary key says about it */
      if (good && s.type != 0x20) {
        self = 1;
        if (s.hasflags) c->flags = s.flags;
        if (s.haskeyexp) c->expires = s.keyexp;
      }
      pktfree(&k);
      break;
    default:
      pktfree(&k);
      break;
    }
  }
  rc = NQOK;
  if (first) rc = NQEDEC;
  else if (!self || revoked) rc = NQEVRFY;
  else if (at > 0 && c->expires != 0 &&
           at > (int64_t)c->prim.created + (int64_t)c->expires)
    rc = NQEVRFY;
  if (c->flags == 0) c->flags = 0x03;
done:
  nqdwfree(&kp);
  nqdwfree(&sp);
  nqdwfree(&up);
  if (rc != NQOK) certfree(c);
  return rc;
}

/* ---- making keys ---- */

/* a key packet's public fields into w: version 6, the time, the
 * algorithm, the material */
static void keybody(nqdw *w, int alg, int64_t at, const uint8_t *pub) {
  put8(w, 6);
  put32(w, (uint64_t)at);
  put8(w, (unsigned)alg);
  put32(w, pubsz(alg));
  nqdwraw(w, pub, pubsz(alg));
}

/* new key material for alg: the secret part (secsz) and the public
 * part (pubsz) */
static int newkey(int alg, uint8_t *sec, uint8_t *pub) {
  nqssz z;
  nqksz kz;
  uint8_t seed[192], *sk = NULL;
  int rc;
  switch (alg) {
  case AX25519:
    rc = nqrand(sec, 32);
    if (rc == NQOK) rc = nqx25519b(pub, sec);
    return rc;
  case AED25519:
  case AMLDSA65:
    rc = nqrand(sec, alg == AED25519 ? 32 : 64);
    if (rc != NQOK) return rc;
    rc = nqssize(NQED25519, &z);
    if (rc != NQOK) return rc;
    sk = (uint8_t *)nqmal(z.sk);
    if (sk == NULL) return NQEMEM;
    rc = edkeys(sec, pub, sk, z.sk);
    nqfree(sk, z.sk);
    if (rc != NQOK || alg == AED25519) return rc;
    rc = nqssize(NQMLDSA65, &z);
    if (rc != NQOK) return rc;
    sk = (uint8_t *)nqmal(z.sk);
    if (sk == NULL) return NQEMEM;
    rc = nqskgd(NQMLDSA65, sec + 32, 32, pub + 32, z.pk, sk, z.sk);
    nqfree(sk, z.sk);
    return rc;
  case ASLH128S:
  case ASLH128F:
  case ASLH256S:
    /* SK.seed, SK.prf, PK.seed; the secret key is all four values */
    rc = nqrand(seed, 3 * pubsz(alg) / 2);
    if (rc == NQOK)
      rc = nqskgd(slhalg(alg), seed, 3 * pubsz(alg) / 2, pub, pubsz(alg),
                  sec, secsz(alg));
    nqwipe(seed, sizeof seed);
    return rc;
  case AMLKEM768:
    rc = nqrand(sec, 96);
    if (rc == NQOK) rc = nqx25519b(pub, sec);
    if (rc != NQOK) return rc;
    rc = nqksize(NQMLKEM768, &kz);
    if (rc != NQOK) return rc;
    sk = (uint8_t *)nqmal(kz.sk);
    if (sk == NULL) return NQEMEM;
    rc = nqkkgd(NQMLKEM768, sec + 32, 64, pub + 32, kz.pk, sk, kz.sk);
    nqfree(sk, kz.sk);
    return rc;
  default:
    return NQENOSUP;
  }
}

/* a Secret Key or Secret Subkey packet: the public fields, then the
 * secret material as it is, or under the passphrase (Argon2id of 64
 * MiB, 3 passes, 4 lanes; AES-256 with OCB) */
static int secpkt(nqdw *out, int type, const uint8_t *body, size_t bn,
                  const uint8_t *sec, size_t sn, const uint8_t *pw,
                  size_t pwn) {
  nqdw b;
  uint8_t sp[20], iv[15], key[32], kek[32], info[4], tag[16], *ct = NULL,
      *ad = NULL;
  int rc;
  nqdwini(&b);
  nqdwraw(&b, body, bn);
  if (pw == NULL) {
    put8(&b, 0);
    nqdwraw(&b, sec, sn);
    rc = b.err;
    goto fin;
  }
  sp[0] = 4;
  rc = nqrand(sp + 1, 16);
  if (rc == NQOK) rc = nqrand(iv, sizeof iv);
  if (rc != NQOK) goto fin;
  sp[17] = s2kt;
  sp[18] = s2kp;
  sp[19] = s2km;
  rc = s2k(sp, sizeof sp, pw, pwn, key, 32);
  if (rc != NQOK) goto fin;
  info[0] = (uint8_t)(0xc0 | type);
  info[1] = 6;
  info[2] = 9;
  info[3] = 2;
  rc = hkdf(NULL, 0, key, 32, info, 4, kek, 32);
  nqwipe(key, sizeof key);
  if (rc != NQOK) goto fin;
  ct = (uint8_t *)nqmal(sn);
  ad = (uint8_t *)nqmal(1 + bn);
  if (ct == NULL || ad == NULL) {
    rc = NQEMEM;
    goto fin;
  }
  ad[0] = info[0];
  memcpy(ad + 1, body, bn);
  rc = aeade(2, kek, 32, iv, ad, 1 + bn, sec, sn, ct, tag);
  nqwipe(kek, sizeof kek);
  if (rc != NQOK) goto fin;
  put8(&b, 253);
  put8(&b, 3 + sizeof sp + sizeof iv);
  put8(&b, 9);
  put8(&b, 2);
  put8(&b, sizeof sp);
  nqdwraw(&b, sp, sizeof sp);
  nqdwraw(&b, iv, sizeof iv);
  nqdwraw(&b, ct, sn);
  nqdwraw(&b, tag, 16);
  rc = b.err;
fin:
  if (rc == NQOK) {
    pkt(out, type, b.p, b.n);
    rc = out->err;
  }
  if (b.p != NULL) nqwipe(b.p, b.n);
  nqdwfree(&b);
  if (ct != NULL) nqfree(ct, sn);
  if (ad != NULL) nqfree(ad, 1 + bn);
  return rc;
}

/* gives a finished writer to the caller's buffer */
static int giveout(nqdw *w, uint8_t *out, size_t cap, size_t *outlen) {
  if (w->err != NQOK) return w->err;
  if (outlen != NULL) *outlen = w->n;
  if (out == NULL) return NQOK;
  if (cap < w->n) return NQEBUF;
  if (w->n > 0) memcpy(out, w->p, w->n);
  return NQOK;
}

int nqpgpgen(int sigalg, int encalg, const char *uid, int64_t created,
             const uint8_t *pw, size_t pwlen, uint8_t *sec, size_t scap,
             size_t *slen, uint8_t *pub, size_t pcap, size_t *plen) {
  /* what the primary key says of itself: it certifies and signs, takes
   * version 2 encrypted data, prefers AES-256 with OCB then GCM,
   * SHA2-512 then SHA3-512, SHA3-256, SHA2-256, and AES-256 then
   * AES-128 where only the old encrypted data packet is to be had */
  static const uint8_t prim[] = {2, 27, 0x03, 2, 30, 0x08, 5, 39, 9, 2,
                                 9, 3, 5, 21, 10, 14, 12, 8, 3, 11, 9, 7};
  /* an encryption subkey: for communications and for storage */
  static const uint8_t sub[] = {2, 27, 0x0c};
  nqdw ws, wp, pb, sb, kp, x1;
  pkey pk, ek;
  ppkt k;
  parts x;
  uint8_t psec[128], ppub[1984], esec[96], epub[1216], salt[32];
  size_t un;
  int rc;
  if (slen != NULL) *slen = 0;
  if (plen != NULL) *plen = 0;
  if (uid == NULL || slen == NULL || plen == NULL ||
      (sec == NULL && scap != 0) || (pub == NULL && pcap != 0) ||
      (pw == NULL && pwlen != 0) || created < 0 || created > 0xffffffffll)
    return NQEARG;
  un = strlen(uid);
  /* a user ID is UTF-8 text; by convention "Name <address>" */
  if (un == 0 || un > 255 || !nqcinok(uid, un)) return NQEARG;
  if (!issig(sigalg) || (encalg != 0 && !isenc(encalg))) return NQENOSUP;
  nqdwini(&ws);
  nqdwini(&wp);
  nqdwini(&pb);
  nqdwini(&sb);
  nqdwini(&kp);
  nqdwini(&x1);
  memset(&k, 0, sizeof k);
  rc = newkey(sigalg, psec, ppub);
  if (rc != NQOK) goto done;
  /* the primary key */
  keybody(&pb, sigalg, created, ppub);
  if (pb.err != NQOK) {
    rc = pb.err;
    goto done;
  }
  k.type = TPUBKEY;
  k.b = pb.p;
  k.n = pb.n;
  rc = keyread(&k, &pk);
  if (rc != NQOK) goto done;
  pkt(&wp, TPUBKEY, pb.p, pb.n);
  rc = secpkt(&ws, TSECKEY, pb.p, pb.n, psec, secsz(sigalg), pw, pwlen);
  if (rc == NQOK) rc = keypart(&kp, &pk);
  if (rc != NQOK) goto done;
  /* a direct key signature: the key's own properties */
  memset(&x, 0, sizeof x);
  addpart(&x, kp.p, kp.n);
  rc = nqrand(salt, sizeof salt);
  if (rc == NQOK)
    rc = mksig(&x1, 0x1f, &pk, psec, created, salt, &x, prim, sizeof prim);
  if (rc != NQOK) goto done;
  nqdwraw(&wp, x1.p, x1.n);
  nqdwraw(&ws, x1.p, x1.n);
  /* the user ID, and the certification that binds it */
  pkt(&wp, TUID, (const uint8_t *)uid, un);
  pkt(&ws, TUID, (const uint8_t *)uid, un);
  x1.n = 0;
  put8(&x1, 0xb4);
  put32(&x1, un);
  nqdwraw(&x1, (const uint8_t *)uid, un);
  addpart(&x, x1.p, x1.n);
  rc = nqrand(salt, sizeof salt);
  if (rc == NQOK) {
    nqdw sg;
    nqdwini(&sg);
    rc = mksig(&sg, 0x13, &pk, psec, created, salt, &x, NULL, 0);
    nqdwraw(&wp, sg.p, sg.n);
    nqdwraw(&ws, sg.p, sg.n);
    nqdwfree(&sg);
  }
  if (rc != NQOK) goto done;
  /* the encryption subkey, and its binding signature */
  if (encalg != 0) {
    nqdw sg;
    rc = newkey(encalg, esec, epub);
    if (rc != NQOK) goto done;
    keybody(&sb, encalg, created, epub);
    if (sb.err != NQOK) {
      rc = sb.err;
      goto done;
    }
    k.type = TPUBSUB;
    k.b = sb.p;
    k.n = sb.n;
    rc = keyread(&k, &ek);
    if (rc != NQOK) goto done;
    pkt(&wp, TPUBSUB, sb.p, sb.n);
    rc = secpkt(&ws, TSECSUB, sb.p, sb.n, esec, secsz(encalg), pw, pwlen);
    if (rc != NQOK) goto done;
    x1.n = 0;
    rc = keypart(&x1, &ek);
    if (rc != NQOK) goto done;
    memset(&x, 0, sizeof x);
    addpart(&x, kp.p, kp.n);
    addpart(&x, x1.p, x1.n);
    nqdwini(&sg);
    rc = nqrand(salt, sizeof salt);
    if (rc == NQOK)
      rc = mksig(&sg, 0x18, &pk, psec, created, salt, &x, sub, sizeof sub);
    nqdwraw(&wp, sg.p, sg.n);
    nqdwraw(&ws, sg.p, sg.n);
    nqdwfree(&sg);
    if (rc != NQOK) goto done;
  }
  rc = giveout(&ws, sec, scap, slen);
  if (rc == NQOK || rc == NQEBUF) {
    int r2 = giveout(&wp, pub, pcap, plen);
    if (rc == NQOK) rc = r2;
  }
done:
  nqwipe(psec, sizeof psec);
  nqwipe(esec, sizeof esec);
  if (ws.p != NULL) nqwipe(ws.p, ws.n);
  nqdwfree(&ws);
  nqdwfree(&wp);
  nqdwfree(&pb);
  nqdwfree(&sb);
  nqdwfree(&kp);
  nqdwfree(&x1);
  return rc;
}

int nqpgpinfo(const uint8_t *key, size_t n, nqpgpk *o) {
  pcert c;
  size_t l;
  int rc;
  if (o != NULL) memset(o, 0, sizeof *o);
  if (key == NULL || o == NULL) return NQEARG;
  if (n > PGPMAX) return NQELIM;
  rc = certread(key, n, 0, &c);
  if (rc != NQOK) return rc;
  o->alg = c.prim.alg;
  o->secret = c.prim.sec;
  /* a secret key under a passphrase says so in its first octet */
  o->locked = c.prim.sec && c.prim.rest[0] != 0;
  o->created = c.prim.created;
  o->expires = c.expires == 0 ? 0 : (int64_t)c.prim.created + c.expires;
  memcpy(o->fp, c.prim.fp, FP);
  if (c.hasenc) {
    o->encalg = c.enc.alg;
    memcpy(o->encfp, c.enc.fp, FP);
  }
  l = c.uidlen < sizeof o->uid - 1 ? c.uidlen : 0;
  if (l > 0 && nqcinok((const char *)c.uid, l)) memcpy(o->uid, c.uid, l);
  certfree(&c);
  return NQOK;
}

/* ---- armor (section 6.2) ---- */

static const char *const armlab[] = {"PGP MESSAGE", "PGP PUBLIC KEY BLOCK",
                                     "PGP PRIVATE KEY BLOCK",
                                     "PGP SIGNATURE"};

int nqpgparm(int kind, const uint8_t *in, size_t n, char *out, size_t cap,
             size_t *outlen) {
  static const char bg[] = "-----BEGIN ", en[] = "-----END ",
                    d5[] = "-----\n";
  const char *lab;
  char line[65];
  size_t ll, need, o = 0, i;
  if (outlen != NULL) *outlen = 0;
  if (kind < NQPGPMSG || kind > NQPGPSIG || outlen == NULL ||
      (in == NULL && n != 0) || (out == NULL && cap != 0))
    return NQEARG;
  if (n > PGPMAX) return NQELIM;
  lab = armlab[kind - NQPGPMSG];
  ll = strlen(lab);
  /* the header line, an empty line (no armor headers), the base64 in
   * lines of 64, the tail line; no checksum */
  need = 11 + ll + 6 + 1 + nqb64n(n) + (nqb64n(n) + 63) / 64 + 9 + ll + 6;
  *outlen = need;
  if (out == NULL) return NQOK;
  if (cap < need) return NQEBUF;
  memcpy(out + o, bg, 11);
  o += 11;
  memcpy(out + o, lab, ll);
  o += ll;
  memcpy(out + o, d5, 6);
  o += 6;
  out[o++] = '\n';
  for (i = 0; i < n; i += 48) {
    size_t k = n - i < 48 ? n - i : 48;
    nqb64e(in + i, k, line);
    memcpy(out + o, line, nqb64n(k));
    o += nqb64n(k);
    out[o++] = '\n';
  }
  memcpy(out + o, en, 9);
  o += 9;
  memcpy(out + o, lab, ll);
  o += ll;
  memcpy(out + o, d5, 6);
  return NQOK;
}

/* the end of the line that starts at i */
static size_t eol(const char *s, size_t n, size_t i) {
  while (i < n && s[i] != '\n') i++;
  return i;
}

/* the text of a line without its line end and trailing space */
static size_t trimmed(const char *s, size_t i, size_t e) {
  while (e > i && (s[e - 1] == '\r' || s[e - 1] == ' ' || s[e - 1] == '\t'))
    e--;
  return e;
}

/* one armor at in[*at]: its kind and its bytes; *at moves past its
 * tail line. Armor headers and a checksum line are passed over. */
static int dearm(const char *in, size_t n, size_t *at, int *kind,
                 uint8_t *out, size_t cap, size_t *outlen) {
  size_t i = *at, e, t, o = 0, k, q = 0, ll;
  char quad[4];
  uint8_t three[3];
  int kd = 0, pad = 0;
  /* the header line */
  for (;;) {
    if (i >= n) return NQEDEC;
    e = eol(in, n, i);
    t = trimmed(in, i, e);
    if (t > i) break;
    i = e + 1;
  }
  if (t - i < 16 || memcmp(in + i, "-----BEGIN ", 11) != 0 ||
      memcmp(in + t - 5, "-----", 5) != 0)
    return NQEDEC;
  for (kd = NQPGPMSG; kd <= NQPGPSIG; kd++) {
    ll = strlen(armlab[kd - NQPGPMSG]);
    if (t - i == 16 + ll && memcmp(in + i + 11, armlab[kd - NQPGPMSG], ll) == 0)
      break;
  }
  if (kd > NQPGPSIG) return NQEDEC;
  i = e + 1;
  /* armor headers, to the empty line that ends them */
  for (;;) {
    if (i >= n) return NQEDEC;
    e = eol(in, n, i);
    t = trimmed(in, i, e);
    if (t == i) {
      i = e + 1;
      break;
    }
    i = e + 1;
  }
  /* the base64, to the tail line or the checksum line */
  for (;;) {
    size_t b = i;
    if (i >= n) return NQEDEC;
    e = eol(in, n, i);
    t = trimmed(in, i, e);
    i = e + 1;
    if (t == b) continue;
    if (in[b] == '-') {
      ll = strlen(armlab[kd - NQPGPMSG]);
      if (t - b != 14 + ll || memcmp(in + b, "-----END ", 9) != 0 ||
          memcmp(in + b + 9, armlab[kd - NQPGPMSG], ll) != 0 ||
          memcmp(in + t - 5, "-----", 5) != 0)
        return NQEDEC;
      break;
    }
    if (in[b] == '=' && t - b == 5) continue; /* the optional CRC24 */
    for (; b < t; b++) {
      if (in[b] == ' ' || in[b] == '\t') continue;
      if (pad) return NQEDEC;
      quad[q++] = in[b];
      if (q < 4) continue;
      q = 0;
      pad = quad[3] == '=';
      if (nqb64d(quad, 4, three, 3, &k) != NQOK) return NQEDEC;
      if (k > cap - o) return NQEBUF;
      memcpy(out + o, three, k);
      o += k;
    }
  }
  if (q != 0) return NQEDEC;
  *at = i < n ? i : n;
  *kind = kd;
  *outlen = o;
  return NQOK;
}

int nqpgpdearm(const char *in, size_t n, int *kind, uint8_t *out, size_t cap,
               size_t *outlen) {
  size_t at = 0;
  int kd = 0, rc;
  if (outlen != NULL) *outlen = 0;
  if (in == NULL || outlen == NULL || (out == NULL && cap != 0))
    return NQEARG;
  if (n > PGPMAX) return NQELIM;
  rc = dearm(in, n, &at, &kd, out, cap, outlen);
  if (rc != NQOK) {
    *outlen = 0;
    return rc;
  }
  /* one armor: nothing but space after it */
  for (; at < n; at++) {
    if (in[at] != ' ' && in[at] != '\t' && in[at] != '\r' && in[at] != '\n') {
      *outlen = 0;
      return NQEDEC;
    }
  }
  if (kind != NULL) *kind = kd;
  return NQOK;
}

/* ---- messages: signed ---- */

/* Text with its line ends made the same: CRLF (the canonical text of
 * section 5.2.1.2, what a text signature signs) or LF. With strip (the
 * cleartext framework, section 7.1) space and tabs at the end of each
 * line are left out. */
static int canontext(const uint8_t *in, size_t n, int strip, int crlf,
                     nqdw *w) {
  size_t i = 0, e, t;
  while (i < n) {
    e = i;
    while (e < n && in[e] != '\n') e++;
    t = e;
    if (t > i && in[t - 1] == '\r') t--;
    if (strip) {
      while (t > i && (in[t - 1] == ' ' || in[t - 1] == '\t')) t--;
    }
    nqdwraw(w, in + i, t - i);
    if (e < n) nqdwraw(w, (const uint8_t *)"\r\n" + (crlf ? 0 : 1),
                       crlf ? 2 : 1);
    i = e + 1;
  }
  return w->err;
}

/* a Literal Data packet of binary data, with no file name */
static void literal(nqdw *w, const uint8_t *msg, size_t n, int64_t at) {
  nqdw b;
  nqdwini(&b);
  put8(&b, 'b');
  put8(&b, 0);
  put32(&b, (uint64_t)at);
  nqdwraw(&b, msg, n);
  if (b.err != NQOK && w->err == NQOK) w->err = b.err;
  pkt(w, TLIT, b.p, b.n);
  nqdwfree(&b);
}

/* a signed message into w: a one-pass signature packet, the literal
 * data, the signature (section 10.3) */
static int signedmsg(nqdw *w, const pkey *k, const uint8_t *sec,
                     const uint8_t *msg, size_t n, int64_t at) {
  nqdw o;
  parts x;
  uint8_t salt[32];
  int rc = nqrand(salt, sizeof salt);
  if (rc != NQOK) return rc;
  nqdwini(&o);
  put8(&o, 6);
  put8(&o, 0x00);
  put8(&o, 10);
  put8(&o, (unsigned)k->alg);
  put8(&o, 32);
  nqdwraw(&o, salt, 32);
  nqdwraw(&o, k->fp, FP);
  put8(&o, 1);
  rc = o.err;
  if (rc == NQOK) {
    pkt(w, TOPS, o.p, o.n);
    literal(w, msg, n, at);
    memset(&x, 0, sizeof x);
    addpart(&x, msg, n);
    rc = mksig(w, 0x00, k, sec, at, salt, &x, NULL, 0);
  }
  nqdwfree(&o);
  return rc;
}

int nqpgpsign(const uint8_t *key, size_t kn, const uint8_t *pw, size_t pwlen,
              const uint8_t *msg, size_t n, int mode, int64_t at,
              uint8_t *out, size_t cap, size_t *outlen) {
  pcert c;
  nqdw w, t;
  parts x;
  uint8_t sec[128], salt[32];
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (key == NULL || outlen == NULL || (msg == NULL && n != 0) ||
      (out == NULL && cap != 0) || (pw == NULL && pwlen != 0) ||
      mode < NQPGPINLINE || mode > NQPGPCLEAR)
    return NQEARG;
  if (kn > PGPMAX || n > PGPMAX) return NQELIM;
  rc = certread(key, kn, nqcreal(), &c);
  if (rc != NQOK) return rc;
  nqdwini(&w);
  nqdwini(&t);
  if (!c.prim.sec || (c.flags & 0x02) == 0) {
    rc = NQEARG; /* not a secret key, or not one that signs */
    goto done;
  }
  rc = keysec(&c.prim, pw, pwlen, sec);
  if (rc != NQOK) goto done;
  if (mode == NQPGPINLINE) {
    rc = signedmsg(&w, &c.prim, sec, msg, n, at);
  } else if (mode == NQPGPDETACHED) {
    memset(&x, 0, sizeof x);
    addpart(&x, msg, n);
    rc = nqrand(salt, sizeof salt);
    if (rc == NQOK)
      rc = mksig(&w, 0x00, &c.prim, sec, at, salt, &x, NULL, 0);
  } else {
    /* the cleartext framework (section 7): the text, dash-escaped,
     * then the armored signature over its canonical form */
    nqdw sg;
    char *arm = NULL;
    size_t i = 0, an = 0, tn;
    static const char hd[] = "-----BEGIN PGP SIGNED MESSAGE-----\n\n";
    if (!nqcutf8((const char *)msg, n)) {
      rc = NQEARG; /* a cleartext signature is of text */
      goto done;
    }
    nqdwini(&sg);
    /* the line end before the signature is not part of the text */
    tn = n;
    if (tn > 0 && msg[tn - 1] == '\n') tn--;
    if (tn > 0 && tn < n && msg[tn - 1] == '\r') tn--;
    rc = canontext(msg, tn, 1, 1, &t);
    memset(&x, 0, sizeof x);
    addpart(&x, t.p, t.n);
    if (rc == NQOK) rc = nqrand(salt, sizeof salt);
    if (rc == NQOK)
      rc = mksig(&sg, 0x01, &c.prim, sec, at, salt, &x, NULL, 0);
    if (rc == NQOK) rc = nqpgparm(NQPGPSIG, sg.p, sg.n, NULL, 0, &an);
    if (rc == NQOK) {
      arm = (char *)nqmal(an);
      rc = arm == NULL ? NQEMEM
                       : nqpgparm(NQPGPSIG, sg.p, sg.n, arm, an, &an);
    }
    if (rc == NQOK) {
      nqdwraw(&w, (const uint8_t *)hd, sizeof hd - 1);
      while (i < n) {
        size_t e = i;
        while (e < n && msg[e] != '\n') e++;
        /* a line that starts with a dash is escaped */
        if (msg[i] == '-') nqdwraw(&w, (const uint8_t *)"- ", 2);
        nqdwraw(&w, msg + i, e - i);
        nqdwraw(&w, (const uint8_t *)"\n", 1);
        i = e + 1;
      }
      nqdwraw(&w, (const uint8_t *)arm, an);
      rc = w.err;
    }
    if (arm != NULL) nqfree(arm, an);
    nqdwfree(&sg);
  }
  if (rc == NQOK) rc = giveout(&w, out, cap, outlen);
done:
  nqwipe(sec, sizeof sec);
  nqdwfree(&w);
  nqdwfree(&t);
  certfree(&c);
  return rc;
}

/* checks the signature packet k over the data (the text canonical for a
 * text signature) under the certificate; *at gets its time */
static int vrfy1(const ppkt *k, const pcert *c, const uint8_t *data,
                 size_t n, int64_t *at) {
  psig s;
  parts x;
  nqdw t;
  int rc = sigread(k, &s);
  if (rc != NQOK) return rc;
  if (s.type != 0x00 && s.type != 0x01) return NQENOSUP;
  if ((c->flags & 0x02) == 0) return NQEVRFY; /* a key that does not sign */
  nqdwini(&t);
  memset(&x, 0, sizeof x);
  if (s.type == 0x01) {
    rc = canontext(data, n, 0, 1, &t);
    addpart(&x, t.p, t.n);
  } else {
    addpart(&x, data, n);
  }
  if (rc == NQOK) rc = sigcheck(&s, &c->prim, &x);
  /* the key held when the signature was made */
  if (rc == NQOK &&
      (s.created < c->prim.created ||
       (c->expires != 0 &&
        (int64_t)s.created > (int64_t)c->prim.created + c->expires)))
    rc = NQEVRFY;
  if (rc == NQOK && at != NULL) *at = s.created;
  nqdwfree(&t);
  return rc;
}

/* the packets of a signed message or a detached signature at p: the
 * content (in the message, or the caller's) and the signature checked */
static int vrfypkts(const uint8_t *p, size_t n, const pcert *c,
                    const uint8_t *msg, size_t mlen, int hasmsg,
                    uint8_t *out, size_t cap, size_t *outlen, int64_t *at) {
  ppkt k, lit;
  const uint8_t *data = msg;
  size_t i = 0, dn = mlen, nl;
  int rc = NQEDEC, havelit = 0, done = 0, ops = 0;
  memset(&lit, 0, sizeof lit);
  while (i < n && !done) {
    rc = rdpkt(p, n, &i, &k);
    if (rc != NQOK) break;
    switch (k.type) {
    case TMARKER:
    case TPAD:
      break;
    case TOPS:
      ops = 1;
      break;
    case TCOMP:
      rc = NQENOSUP; /* compressed data: no inflate here */
      done = 1;
      break;
    case TLIT:
      /* format, file name, date, then the data */
      if (k.n < 2 || (size_t)k.b[1] + 6 > k.n || havelit) {
        rc = NQEDEC;
        done = 1;
        break;
      }
      nl = k.b[1];
      lit = k;
      memset(&k, 0, sizeof k);
      data = lit.b + 6 + nl;
      dn = lit.n - 6 - nl;
      havelit = 1;
      break;
    case TSIG:
      if (!havelit && !hasmsg) {
        rc = ops ? NQEDEC : NQEARG; /* detached, and nothing to check */
      } else {
        rc = vrfy1(&k, c, data, dn, at);
      }
      done = 1;
      break;
    default:
      rc = NQEDEC;
      done = 1;
      break;
    }
    pktfree(&k);
  }
  if (!done && rc == NQOK) rc = NQEDEC; /* no signature at all */
  if (rc == NQOK) {
    if (outlen != NULL) *outlen = dn;
    if (out != NULL) {
      if (cap < dn) rc = NQEBUF;
      else if (dn > 0) memcpy(out, data, dn);
    }
  }
  pktfree(&lit);
  return rc;
}

int nqpgpvrfy(const uint8_t *cert, size_t cn, const uint8_t *sig, size_t sn,
              const uint8_t *msg, size_t mlen, uint8_t *out, size_t cap,
              size_t *outlen, int64_t *at) {
  static const char hd[] = "-----BEGIN PGP SIGNED MESSAGE-----";
  pcert c;
  nqdw t;
  uint8_t *bin = NULL;
  size_t bn = 0, i, e;
  int rc, kind = 0;
  if (outlen != NULL) *outlen = 0;
  if (at != NULL) *at = 0;
  if (cert == NULL || sig == NULL || (msg == NULL && mlen != 0) ||
      (out == NULL && cap != 0))
    return NQEARG;
  if (cn > PGPMAX || sn > PGPMAX || mlen > PGPMAX) return NQELIM;
  rc = certread(cert, cn, 0, &c);
  if (rc != NQOK) return rc;
  nqdwini(&t);
  if (sn >= sizeof hd - 1 && memcmp(sig, hd, sizeof hd - 1) == 0) {
    /* the cleartext framework: armor headers, an empty line, the
     * dash-escaped text, the armored signature */
    const char *s = (const char *)sig;
    size_t a;
    i = eol(s, sn, 0) + 1;
    for (;;) {
      if (i >= sn) {
        rc = NQEDEC;
        goto done;
      }
      e = eol(s, sn, i);
      i = e + 1;
      {
        size_t b = e;
        while (b > 0 && s[b - 1] != '\n') b--;
        if (trimmed(s, b, e) == b) break;
      }
    }
    for (;;) {
      if (i >= sn) {
        rc = NQEDEC;
        goto done;
      }
      e = eol(s, sn, i);
      if (e - i >= 29 && memcmp(s + i, "-----BEGIN PGP SIGNATURE-----", 29)
                             == 0)
        break;
      /* "- " before a line is the escape, and is not part of it */
      a = i + (e - i >= 2 && s[i] == '-' && s[i + 1] == ' ' ? 2 : 0);
      nqdwraw(&t, (const uint8_t *)s + a, e - a);
      nqdwraw(&t, (const uint8_t *)"\n", 1);
      i = e + 1;
    }
    if (t.err != NQOK) {
      rc = t.err;
      goto done;
    }
    /* the line end before the signature is not part of the text */
    if (t.n > 0) t.n--;
    if (t.n > 0 && t.p[t.n - 1] == '\r') t.n--;
    bn = sn - i;
    bin = (uint8_t *)nqmal(bn > 0 ? bn : 1);
    if (bin == NULL) {
      rc = NQEMEM;
      goto done;
    }
    a = i;
    rc = dearm(s, sn, &a, &kind, bin, bn, &e);
    if (rc == NQOK && kind != NQPGPSIG) rc = NQEDEC;
    if (rc == NQOK) {
      /* a text signature over the text with its trailing space off */
      nqdw cn2;
      ppkt k;
      size_t pi = 0;
      memset(&k, 0, sizeof k);
      nqdwini(&cn2);
      rc = canontext(t.p, t.n, 1, 1, &cn2);
      if (rc == NQOK) rc = rdpkt(bin, e, &pi, &k);
      if (rc == NQOK) {
        psig sg;
        parts x;
        memset(&sg, 0, sizeof sg);
        rc = k.type == TSIG ? sigread(&k, &sg) : NQEDEC;
        if (rc == NQOK && sg.type != 0x01) rc = NQEDEC;
        memset(&x, 0, sizeof x);
        addpart(&x, cn2.p, cn2.n);
        if (rc == NQOK && (c.flags & 0x02) == 0) rc = NQEVRFY;
        if (rc == NQOK) rc = sigcheck(&sg, &c.prim, &x);
        if (rc == NQOK && at != NULL) *at = sg.created;
        pktfree(&k);
      }
      nqdwfree(&cn2);
    }
    if (rc == NQOK) {
      /* the text as it was signed: without the space at its line ends,
       * with LF between its lines */
      nqdw lf;
      nqdwini(&lf);
      rc = canontext(t.p, t.n, 1, 0, &lf);
      if (rc == NQOK) {
        if (outlen != NULL) *outlen = lf.n;
        if (out != NULL) {
          if (cap < lf.n) rc = NQEBUF;
          else if (lf.n > 0) memcpy(out, lf.p, lf.n);
        }
      }
      nqdwfree(&lf);
    }
    goto done;
  }
  /* armored, or the packets themselves */
  if (sn >= 5 && memcmp(sig, "-----", 5) == 0) {
    bn = sn;
    bin = (uint8_t *)nqmal(bn);
    if (bin == NULL) {
      rc = NQEMEM;
      goto done;
    }
    rc = nqpgpdearm((const char *)sig, sn, &kind, bin, bn, &e);
    if (rc == NQOK && kind != NQPGPMSG && kind != NQPGPSIG) rc = NQEDEC;
    if (rc == NQOK)
      rc = vrfypkts(bin, e, &c, msg, mlen, msg != NULL, out, cap, outlen, at);
  } else {
    rc = vrfypkts(sig, sn, &c, msg, mlen, msg != NULL, out, cap, outlen, at);
  }
done:
  if (rc != NQOK && rc != NQEBUF && outlen != NULL) *outlen = 0;
  if (bin != NULL) nqfree(bin, bn > 0 ? bn : 1);
  nqdwfree(&t);
  certfree(&c);
  return rc;
}

/* ---- messages: encrypted ---- */

/* the key that wraps a session key for an ML-KEM-768+X25519 recipient
 * (RFC 9980 section 4.2.1) */
static void kemkek(const uint8_t *mlss, const uint8_t *ecss,
                   const uint8_t *ecct, const uint8_t *ecpk, uint8_t *kek) {
  static const char dom[] = "OpenPGPCompositeKDFv1";
  nqhctx h;
  uint8_t b[2];
  nqhini(&h, NQS3256);
  nqhupd(&h, mlss, 32);
  nqhupd(&h, ecss, 32);
  nqhupd(&h, ecct, 32);
  nqhupd(&h, ecpk, 32);
  b[0] = AMLKEM768;
  nqhupd(&h, b, 1);
  nqhupd(&h, (const uint8_t *)dom, sizeof dom - 1);
  b[1] = (uint8_t)(sizeof dom - 1);
  nqhupd(&h, b + 1, 1);
  nqhfin(&h, kek, 32);
}

/* a version 6 PKESK packet: the session key sk (32 bytes) to the
 * encryption key k */
static int pkesk(nqdw *w, const pkey *k, const uint8_t *sk) {
  nqdw b;
  uint8_t eph[32], epk[32], ss[32], kek[32], ikm[96], wr[40],
      ct[1088], ms[32];
  int rc;
  nqdwini(&b);
  put8(&b, 6);
  put8(&b, 1 + FP);
  put8(&b, 6);
  nqdwraw(&b, k->fp, FP);
  put8(&b, (unsigned)k->alg);
  rc = nqrand(eph, sizeof eph);
  if (rc == NQOK) rc = nqx25519b(epk, eph);
  if (rc == NQOK) rc = nqx25519(ss, eph, k->pub);
  if (rc != NQOK) goto done;
  nqdwraw(&b, epk, 32);
  if (k->alg == AX25519) {
    /* HKDF of the ephemeral key, the recipient's key and the shared
     * secret; AES-128 key wrap (section 5.1.6) */
    memcpy(ikm, epk, 32);
    memcpy(ikm + 32, k->pub, 32);
    memcpy(ikm + 64, ss, 32);
    rc = hkdf(NULL, 0, ikm, 96, (const uint8_t *)"OpenPGP X25519", 14, kek,
              16);
    if (rc == NQOK) rc = nqkwrap(kek, 16, sk, 32, wr);
  } else {
    rc = nqenc(NQMLKEM768, k->pub + 32, 1184, ct, sizeof ct, ms, sizeof ms);
    if (rc == NQOK) {
      kemkek(ms, ss, epk, k->pub, kek);
      nqdwraw(&b, ct, sizeof ct);
      rc = nqkwrap(kek, 32, sk, 32, wr);
    }
  }
  if (rc == NQOK) {
    put8(&b, 40);
    nqdwraw(&b, wr, 40);
    rc = b.err;
  }
  if (rc == NQOK) {
    pkt(w, TPKESK, b.p, b.n);
    rc = w->err;
  }
done:
  nqwipe(eph, sizeof eph);
  nqwipe(ss, sizeof ss);
  nqwipe(ms, sizeof ms);
  nqwipe(kek, sizeof kek);
  nqwipe(ikm, sizeof ikm);
  nqdwfree(&b);
  return rc;
}

/* opens a PKESK body with the encryption key k and its secret material:
 * NQOK with the session key (sn bytes), NQEVRFY when it is not for
 * this key */
static int unpkesk(const uint8_t *b, size_t n, const pkey *k,
                   const uint8_t *sec, uint8_t *sk, size_t *sn) {
  nqksz kz;
  uint8_t ss[32], kek[32], ikm[96], ms[32], mpk[1184], *msk;
  const uint8_t *eph, *wr;
  size_t i, wl;
  int rc;
  if (n < 2 || b[0] != 6) return n >= 1 && b[0] == 3 ? NQENOSUP : NQEDEC;
  i = 2 + (size_t)b[1];
  if (i >= n) return NQEDEC;
  /* named for a key: this one, or not ours; unnamed: tried */
  if (b[1] != 0 &&
      (b[1] != 1 + FP || b[2] != 6 || memcmp(b + 3, k->fp, FP) != 0))
    return NQEVRFY;
  if (b[i] != k->alg) return NQEVRFY;
  i++;
  if (n - i < 32) return NQEDEC;
  eph = b + i;
  i += 32;
  rc = nqx25519(ss, sec, eph);
  if (rc != NQOK) return rc == NQEVRFY ? NQEVRFY : rc;
  if (k->alg == AX25519) {
    memcpy(ikm, eph, 32);
    memcpy(ikm + 32, k->pub, 32);
    memcpy(ikm + 64, ss, 32);
    rc = hkdf(NULL, 0, ikm, 96, (const uint8_t *)"OpenPGP X25519", 14, kek,
              16);
    wl = 16;
  } else {
    if (n - i < 1088) return NQEDEC;
    rc = nqksize(NQMLKEM768, &kz);
    if (rc != NQOK) return rc;
    msk = (uint8_t *)nqmal(kz.sk);
    if (msk == NULL) return NQEMEM;
    rc = nqkkgd(NQMLKEM768, sec + 32, 64, mpk, sizeof mpk, msk, kz.sk);
    if (rc == NQOK)
      rc = nqdec(NQMLKEM768, msk, kz.sk, b + i, 1088, ms, sizeof ms);
    nqfree(msk, kz.sk);
    i += 1088;
    if (rc == NQOK) kemkek(ms, ss, eph, k->pub, kek);
    wl = 32;
  }
  if (rc == NQOK) {
    if (n - i < 1 || (size_t)b[i] != n - i - 1) {
      rc = NQEDEC;
    } else {
      wr = b + i + 1;
      /* a session key of 16, 24 or 32 bytes, wrapped into 8 more */
      if (b[i] != 24 && b[i] != 32 && b[i] != 40) rc = NQEDEC;
      else rc = nqkunwrap(kek, wl, wr, b[i], sk);
      if (rc == NQOK) *sn = (size_t)b[i] - 8;
    }
  }
  nqwipe(ss, sizeof ss);
  nqwipe(ms, sizeof ms);
  nqwipe(kek, sizeof kek);
  nqwipe(ikm, sizeof ikm);
  return rc;
}

/* a version 6 SKESK packet: the session key under a passphrase */
static int skesk(nqdw *w, const uint8_t *pw, size_t pwn, const uint8_t *sk) {
  nqdw b;
  uint8_t sp[20], iv[15], key[32], kek[32], info[4] = {0xc3, 6, 9, 2},
      ct[32], tag[16];
  int rc;
  nqdwini(&b);
  sp[0] = 4;
  rc = nqrand(sp + 1, 16);
  if (rc == NQOK) rc = nqrand(iv, sizeof iv);
  if (rc != NQOK) return rc;
  sp[17] = s2kt;
  sp[18] = s2kp;
  sp[19] = s2km;
  rc = s2k(sp, sizeof sp, pw, pwn, key, 32);
  if (rc == NQOK) rc = hkdf(NULL, 0, key, 32, info, 4, kek, 32);
  if (rc == NQOK) rc = aeade(2, kek, 32, iv, info, 4, sk, 32, ct, tag);
  nqwipe(key, sizeof key);
  nqwipe(kek, sizeof kek);
  if (rc == NQOK) {
    put8(&b, 6);
    put8(&b, 3 + sizeof sp + sizeof iv);
    put8(&b, 9);
    put8(&b, 2);
    put8(&b, sizeof sp);
    nqdwraw(&b, sp, sizeof sp);
    nqdwraw(&b, iv, sizeof iv);
    nqdwraw(&b, ct, 32);
    nqdwraw(&b, tag, 16);
    rc = b.err;
  }
  if (rc == NQOK) {
    pkt(w, TSKESK, b.p, b.n);
    rc = w->err;
  }
  nqdwfree(&b);
  return rc;
}

static int unskesk(const uint8_t *b, size_t n, const uint8_t *pw, size_t pwn,
                   uint8_t *sk, size_t *sn) {
  uint8_t key[32], kek[32], info[4];
  size_t kl, nl, sl, cn;
  const uint8_t *iv, *ct;
  int rc;
  if (n < 2 || b[0] != 6) return n >= 1 && b[0] == 4 ? NQENOSUP : NQEDEC;
  if (n < 5) return NQEDEC;
  kl = keylen(b[2]);
  nl = noncelen(b[3]);
  sl = b[4];
  if (kl == 0 || nl == 0) return NQENOSUP;
  if ((size_t)b[1] != 3 + sl + nl || n < 2 + (size_t)b[1] + 16) return NQEDEC;
  iv = b + 5 + sl;
  ct = iv + nl;
  cn = n - 2 - (size_t)b[1] - 16;
  if (cn != 16 && cn != 24 && cn != 32) return NQEDEC;
  rc = s2k(b + 5, sl, pw, pwn, key, kl);
  if (rc != NQOK) return rc;
  info[0] = 0xc3;
  info[1] = 6;
  info[2] = b[2];
  info[3] = b[3];
  rc = hkdf(NULL, 0, key, kl, info, 4, kek, kl);
  if (rc == NQOK) rc = aeadd(b[3], kek, kl, iv, info, 4, ct, cn, ct + cn, sk);
  nqwipe(key, sizeof key);
  nqwipe(kek, sizeof kek);
  if (rc == NQOK) *sn = cn;
  return rc;
}

#define CHUNKC 8 /* chunks of 2^(8+6) = 16 KiB */

/* a version 2 SEIPD packet: the plaintext packets in pt under the
 * session key, AES-256 with OCB (section 5.13.2) */
static int seipd(nqdw *w, const uint8_t *sk, const uint8_t *pt, size_t n) {
  nqdw b;
  uint8_t info[13] = {0xd2, 2, 9, 2, CHUNKC}, salt[32], km[39], nonce[15],
          tag[16], *ct = NULL;
  size_t ch = (size_t)1 << (CHUNKC + 6), i;
  uint64_t idx = 0;
  int rc, j;
  nqdwini(&b);
  rc = nqrand(salt, sizeof salt);
  /* 32 bytes of key, then 7 of the nonce; the chunk index is the rest */
  if (rc == NQOK) rc = hkdf(salt, 32, sk, 32, info, 5, km, sizeof km);
  if (rc != NQOK) return rc;
  ct = (uint8_t *)nqmal(ch);
  if (ct == NULL) {
    nqwipe(km, sizeof km);
    return NQEMEM;
  }
  nqdwraw(&b, info + 1, 4);
  nqdwraw(&b, salt, 32);
  memcpy(nonce, km + 32, 7);
  for (i = 0; i < n && rc == NQOK; i += ch, idx++) {
    size_t k = n - i < ch ? n - i : ch;
    for (j = 0; j < 8; j++) nonce[7 + j] = (uint8_t)(idx >> (8 * (7 - j)));
    rc = aeade(2, km, 32, nonce, info, 5, pt + i, k, ct, tag);
    nqdwraw(&b, ct, k);
    nqdwraw(&b, tag, 16);
  }
  if (rc == NQOK) {
    /* the final tag: no text, the total length in the associated data */
    for (j = 0; j < 8; j++) {
      nonce[7 + j] = (uint8_t)(idx >> (8 * (7 - j)));
      info[5 + j] = (uint8_t)((uint64_t)n >> (8 * (7 - j)));
    }
    rc = aeade(2, km, 32, nonce, info, 13, NULL, 0, ct, tag);
    nqdwraw(&b, tag, 16);
  }
  if (rc == NQOK) rc = b.err;
  if (rc == NQOK) {
    pkt(w, TSEIPD, b.p, b.n);
    rc = w->err;
  }
  nqwipe(km, sizeof km);
  nqfree(ct, ch);
  nqdwfree(&b);
  return rc;
}

/* opens a SEIPD body with the session key: the plaintext packets into
 * a new buffer (*cap bytes, to free) */
static int unseipd(const uint8_t *b, size_t n, const uint8_t *sk, size_t skn,
                   uint8_t **out, size_t *cap, size_t *len) {
  uint8_t info[13], km[48], nonce[16], *pt;
  size_t kl, nl, ch, i, o = 0, body;
  uint64_t idx = 0;
  int rc = NQOK, j;
  if (n < 1) return NQEDEC;
  if (b[0] != 2) return b[0] == 1 ? NQENOSUP : NQEDEC;
  if (n < 5 + 32 + 16) return NQEDEC;
  kl = keylen(b[1]);
  nl = noncelen(b[2]);
  if (kl == 0 || nl == 0) return NQENOSUP;
  if (b[3] > 16) return NQEDEC;
  /* the session key is of the cipher the packet names */
  if (skn != kl) return NQEVRFY;
  ch = (size_t)1 << (b[3] + 6);
  info[0] = 0xd2;
  memcpy(info + 1, b, 4);
  rc = hkdf(b + 4, 32, sk, skn, info, 5, km, kl + nl - 8);
  if (rc != NQOK) return rc;
  memcpy(nonce, km + kl, nl - 8);
  body = n - 36 - 16; /* chunks with their tags, before the final tag */
  *cap = body > 0 ? body : 1;
  pt = (uint8_t *)nqmal(*cap);
  if (pt == NULL) {
    nqwipe(km, sizeof km);
    return NQEMEM;
  }
  for (i = 0; i < body && rc == NQOK; idx++) {
    size_t k = body - i < ch + 16 ? body - i : ch + 16;
    if (k < 16) {
      rc = NQEDEC;
      break;
    }
    for (j = 0; j < 8; j++)
      nonce[nl - 8 + (size_t)j] = (uint8_t)(idx >> (8 * (7 - j)));
    rc = aeadd(b[2], km, kl, nonce, info, 5, b + 36 + i, k - 16,
               b + 36 + i + k - 16, pt + o);
    o += k - 16;
    i += k;
  }
  if (rc == NQOK) {
    for (j = 0; j < 8; j++) {
      nonce[nl - 8 + (size_t)j] = (uint8_t)(idx >> (8 * (7 - j)));
      info[5 + j] = (uint8_t)((uint64_t)o >> (8 * (7 - j)));
    }
    rc = aeadd(b[2], km, kl, nonce, info, 13, NULL, 0, b + n - 16, pt);
  }
  nqwipe(km, sizeof km);
  if (rc != NQOK) {
    nqfree(pt, *cap);
    return rc == NQEMEM ? rc : rc == NQEDEC ? rc : NQEVRFY;
  }
  *out = pt;
  *len = o;
  return NQOK;
}

int nqpgpenc(const uint8_t *const *certs, const size_t *certlens, size_t nc,
             const uint8_t *pw, size_t pwlen, const uint8_t *signer,
             size_t signerlen, const uint8_t *spw, size_t spwlen,
             const uint8_t *msg, size_t n, int64_t at, uint8_t *out,
             size_t cap, size_t *outlen) {
  nqdw w, in;
  pcert c, sc;
  uint8_t sk[32], sec[128];
  size_t i;
  int rc;
  if (outlen != NULL) *outlen = 0;
  if (outlen == NULL || (msg == NULL && n != 0) ||
      (out == NULL && cap != 0) || (nc != 0 && (certs == NULL ||
                                               certlens == NULL)) ||
      (nc == 0 && pw == NULL) || nc > 64 || (pw == NULL && pwlen != 0) ||
      (signer == NULL && signerlen != 0) || at < 0 || at > 0xffffffffll)
    return NQEARG;
  if (n > PGPMAX) return NQELIM;
  nqdwini(&w);
  nqdwini(&in);
  rc = nqrand(sk, sizeof sk);
  for (i = 0; i < nc && rc == NQOK; i++) {
    if (certs[i] == NULL) {
      rc = NQEARG;
      break;
    }
    rc = certread(certs[i], certlens[i], nqcreal(), &c);
    if (rc != NQOK) break;
    /* a certificate with no encryption subkey cannot receive */
    rc = c.hasenc ? pkesk(&w, &c.enc, sk) : NQEARG;
    certfree(&c);
  }
  if (rc == NQOK && pw != NULL) rc = skesk(&w, pw, pwlen, sk);
  if (rc != NQOK) goto done;
  /* what is encrypted: a signed message, or the literal data alone */
  if (signer != NULL) {
    rc = certread(signer, signerlen, nqcreal(), &sc);
    if (rc == NQOK) {
      if (!sc.prim.sec || (sc.flags & 0x02) == 0) rc = NQEARG;
      if (rc == NQOK) rc = keysec(&sc.prim, spw, spwlen, sec);
      if (rc == NQOK) rc = signedmsg(&in, &sc.prim, sec, msg, n, at);
      nqwipe(sec, sizeof sec);
      certfree(&sc);
    }
  } else {
    literal(&in, msg, n, at);
    rc = in.err;
  }
  if (rc == NQOK) rc = seipd(&w, sk, in.p, in.n);
  if (rc == NQOK) rc = giveout(&w, out, cap, outlen);
done:
  nqwipe(sk, sizeof sk);
  if (in.p != NULL) nqwipe(in.p, in.n);
  nqdwfree(&w);
  nqdwfree(&in);
  return rc;
}

int nqpgpdec(const uint8_t *key, size_t kn, const uint8_t *pw, size_t pwlen,
             const uint8_t *signer, size_t signerlen, const uint8_t *msg,
             size_t n, uint8_t *out, size_t cap, size_t *outlen,
             int *signedby, int64_t *at) {
  pcert c, sc;
  ppkt k;
  uint8_t sk[32], sec[128], *bin = NULL, *pt = NULL;
  const uint8_t *p = msg;
  size_t pn = n, i = 0, skn = 0, bn = 0, ptc = 0, ptn = 0, e = 0;
  int rc, have = 0, kind = 0, tried = NQEVRFY, hask = 0;
  if (outlen != NULL) *outlen = 0;
  if (signedby != NULL) *signedby = 0;
  if (at != NULL) *at = 0;
  if (msg == NULL || outlen == NULL || (out == NULL && cap != 0) ||
      (key == NULL && pw == NULL) || (pw == NULL && pwlen != 0) ||
      (signer == NULL && signerlen != 0))
    return NQEARG;
  if (n > PGPMAX || kn > PGPMAX) return NQELIM;
  memset(&c, 0, sizeof c);
  if (key != NULL) {
    rc = certread(key, kn, 0, &c);
    if (rc != NQOK) return rc;
    hask = 1;
    if (!c.hasenc || !c.enc.sec) {
      certfree(&c);
      return NQEARG; /* no secret encryption subkey */
    }
    /* with a key, the passphrase is the key's */
    rc = keysec(&c.enc, pw, pwlen, sec);
    if (rc != NQOK) {
      certfree(&c);
      return rc;
    }
  }
  if (n >= 5 && memcmp(msg, "-----", 5) == 0) {
    bn = n;
    bin = (uint8_t *)nqmal(bn);
    if (bin == NULL) {
      rc = NQEMEM;
      goto done;
    }
    rc = nqpgpdearm((const char *)msg, n, &kind, bin, bn, &e);
    if (rc == NQOK && kind != NQPGPMSG) rc = NQEDEC;
    if (rc != NQOK) goto done;
    p = bin;
    pn = e;
  }
  /* the session key packets, then the encrypted data */
  rc = NQEDEC;
  while (i < pn) {
    rc = rdpkt(p, pn, &i, &k);
    if (rc != NQOK) goto done;
    if (k.type == TPKESK && hask && !have) {
      int r = unpkesk(k.b, k.n, &c.enc, sec, sk, &skn);
      if (r == NQOK) have = 1;
      else if (r != NQEVRFY) tried = r;
    } else if (k.type == TSKESK && !hask && !have) {
      int r = unskesk(k.b, k.n, pw, pwlen, sk, &skn);
      if (r == NQOK) have = 1;
      else if (r != NQEVRFY) tried = r;
    } else if (k.type == TSEIPD) {
      rc = have ? unseipd(k.b, k.n, sk, skn, &pt, &ptc, &ptn) : tried;
      pktfree(&k);
      break;
    } else if (k.type != TPKESK && k.type != TSKESK && k.type != TMARKER &&
               k.type != TPAD) {
      /* the old encrypted data packets, or not a message */
      rc = k.type == 9 || k.type == 20 ? NQENOSUP : NQEDEC;
      pktfree(&k);
      break;
    }
    pktfree(&k);
    rc = NQEDEC; /* no encrypted data yet */
  }
  if (rc != NQOK) goto done;
  /* inside: a signed message when a signer's certificate is given to
   * check it with, else the content whatever signs it */
  if (signer != NULL) {
    rc = certread(signer, signerlen, 0, &sc);
    if (rc == NQOK) {
      rc = vrfypkts(pt, ptn, &sc, NULL, 0, 0, out, cap, outlen, at);
      if (rc == NQOK && signedby != NULL) *signedby = 1;
      certfree(&sc);
    }
  } else {
    ppkt q;
    size_t j = 0;
    rc = NQEDEC;
    while (j < ptn) {
      rc = rdpkt(pt, ptn, &j, &q);
      if (rc != NQOK) break;
      if (q.type == TLIT) {
        if (q.n < 2 || (size_t)q.b[1] + 6 > q.n) {
          rc = NQEDEC;
        } else {
          size_t dn = q.n - 6 - q.b[1];
          *outlen = dn;
          if (out != NULL) {
            if (cap < dn) rc = NQEBUF;
            else if (dn > 0) memcpy(out, q.b + 6 + q.b[1], dn);
          }
        }
        pktfree(&q);
        break;
      }
      if (q.type == TCOMP) rc = NQENOSUP;
      else if (q.type != TOPS && q.type != TSIG && q.type != TMARKER &&
               q.type != TPAD)
        rc = NQEDEC;
      pktfree(&q);
      if (rc != NQOK) break;
      rc = NQEDEC;
    }
  }
done:
  nqwipe(sk, sizeof sk);
  nqwipe(sec, sizeof sec);
  if (pt != NULL) nqfree(pt, ptc);
  if (bin != NULL) nqfree(bin, bn);
  if (hask) certfree(&c);
  if (rc != NQOK && rc != NQEBUF) *outlen = 0;
  return rc;
}
