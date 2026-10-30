/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* A TLS 1.3 client (RFC 8446); internal. The public functions (nqtl*,
 * noqtis.h) wrap the context below.
 *
 * What it does: one full handshake with an (EC)DHE key share
 * (X25519MLKEM768, draft-ietf-tls-ecdhe-mlkem, first; X25519 as well;
 * P-256 and P-384 offered in supported_groups, with a share only when a
 * HelloRetryRequest asks for one), at most one HelloRetryRequest, the
 * server's certificate path checked against caller-supplied anchors
 * (src/der), a stapled OCSP response, and its CertificateVerify
 * (src/cls), the three AEAD cipher suites, application data both ways,
 * KeyUpdate, close_notify. What it never does: TLS 1.2 or earlier,
 * PSK, resumption, 0-RTT, client certificates (a CertificateRequest is
 * answered with an empty Certificate), renegotiation, compression.
 * Anything else a server sends ends the connection with an alert.
 *
 * The context holds no pointer into the caller's memory after nqtlnew;
 * the I/O callbacks move bytes, and the library opens no socket. */
#ifndef NQTLS_H
#define NQTLS_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"
#include "aead/aead.h"
#include "der/x509.h"
#include "hash/h.h"

/* record content types */
#define NQTLCCS 20
#define NQTLALERT 21
#define NQTLHS 22
#define NQTLAPP 23

/* handshake message types */
#define NQTLCH 1
#define NQTLSH 2
#define NQTLNST 4
#define NQTLEE 8
#define NQTLCERT 11
#define NQTLCR 13
#define NQTLCV 15
#define NQTLFIN 20
#define NQTLKU 24
#define NQTLMH 254 /* message_hash (section 4.4.1) */

/* named groups */
#define NQTLX25519 0x001d
#define NQTLP256 0x0017 /* secp256r1 */
#define NQTLP384 0x0018 /* secp384r1 */
#define NQTLHYB 0x11ec /* X25519MLKEM768 */

/* cipher suites */
#define NQTLA128 0x1301 /* TLS_AES_128_GCM_SHA256 */
#define NQTLA256 0x1302 /* TLS_AES_256_GCM_SHA384 */
#define NQTLC20 0x1303  /* TLS_CHACHA20_POLY1305_SHA256 */

/* the record limits of section 5 */
#define NQTLPT 16384           /* plaintext */
#define NQTLCT (16384 + 256)   /* ciphertext */
#define NQTLHMAX (1u << 18)    /* the largest handshake message accepted */
#define NQTLCMAX 10            /* certificates in the server's chain */
#define NQTLXMAX 40            /* extensions in one ClientHello */
#define NQTLWHY 200

/* states (nqtls.st) */
#define NQTLST0 0   /* the first ClientHello is out */
#define NQTLSHS 1   /* after the ServerHello: the encrypted flight */
#define NQTLSFIN 3  /* the server's Finished checked */
#define NQTLUP 4    /* connected */

/* the hybrid share sizes: ML-KEM-768 first, then X25519 */
#define NQTLHEK (1184 + 32)
#define NQTLHCT (1088 + 32)

/* one direction's traffic protection */
typedef struct {
  int on;
  uint16_t suite;
  nqgcm g;              /* AES-GCM suites */
  uint8_t ck[32];       /* ChaCha20-Poly1305 */
  uint8_t iv[12];
  uint64_t seq;
  uint8_t sec[NQHMAX];  /* the traffic secret, for KeyUpdate */
} nqtlkey;

/* test hooks (tests/ttls*.c), never set by the public API: a
 * ClientHello given byte for byte (and the second one after a
 * HelloRetryRequest), the client's X25519 private key, the (EC)DHE
 * secret itself (for a group noqtis does not implement), and switches
 * that skip the path check or the CertificateVerify signature (the RFC
 * 8448 server has a 1024-bit RSA key and a self-signed certificate).
 * They exist only where NQTEST is defined (the test library and the
 * fuzzers): elsewhere a context has no hooks, nqtlhook does not exist,
 * and NQTLHK reads a constant all-zero set, so every hook branch is
 * compiled out of the library that is installed. */
typedef struct {
  const uint8_t *ch1, *ch2;
  size_t ch1n, ch2n;
  const uint8_t *xsk;
  const uint8_t *ss;
  size_t ssn;
  int nopath, nocv;
  int64_t now;          /* 0: the clock */
  int one;              /* send one key share only (the first group) */
} nqtlhk;

/* what a ClientHello offered, read back from its own bytes */
typedef struct {
  uint8_t sid[32];
  size_t sidn;
  uint16_t suites[8];
  size_t nsuite;
  uint16_t ext[NQTLXMAX];
  size_t next;
  uint16_t grp[16];     /* supported_groups */
  size_t ngrp;
  uint16_t ks[4];       /* the groups it sent key shares for */
  size_t nks;
  uint16_t sig[16];     /* signature_algorithms */
  size_t nsig;
  const uint8_t *rnd;
} nqtloff;

/* one Certificate Transparency log of the caller's list (ct.c) */
typedef struct {
  uint8_t id[32];       /* log_id: the SHA-256 of the key */
  size_t key, keyn;     /* its SubjectPublicKeyInfo: lk + key, keyn bytes */
  size_t op;            /* its operator, by index in the list */
  int st;               /* NQTLCT* */
  int64_t stt;          /* since when */
  int ti;               /* a temporal interval [tis, tie) for notAfter */
  int64_t tis, tie;
} nqtlog;

/* log states (nqtlog.st); 0 for none or one not known */
#define NQTLCTP 1   /* pending */
#define NQTLCTQ 2   /* qualified */
#define NQTLCTU 3   /* usable */
#define NQTLCTR 4   /* readonly */
#define NQTLCTX 5   /* retired */
#define NQTLCTJ 6   /* rejected */

struct nqtls {
  nqtlio io;
  char host[256];
  int ip;               /* host is an address literal: 4 or 16 bytes */
  uint8_t ipb[16];
  /* trust anchors, parsed from the caller's bundle (their bytes in ab) */
  uint8_t *ab;
  size_t abn;
  nqcert *anc;
  size_t nanc, ancap;
#ifdef NQTEST
  nqtlhk hk;
#endif
  /* state */
  int st;
  int err;              /* the first error, sticky */
  char why[NQTLWHY];
  int sent;             /* close_notify sent */
  int eof;              /* close_notify received */
  /* the handshake */
  uint8_t ch[4096];     /* the ClientHello on the wire */
  size_t chn;
  uint8_t rnd[32], sid[32];
  uint8_t ck[1024];     /* the HelloRetryRequest cookie */
  size_t ckn;
  nqtloff off;
  int hrr;              /* a HelloRetryRequest was seen */
  uint16_t hrrg;        /* the group it asked for */
  uint16_t hrrs;        /* its cipher suite */
  uint16_t suite;
  nqhalg h;
  size_t hl;
  uint16_t grp;         /* the group the server chose */
  uint8_t xsk[32], xpk[32];
  uint8_t esk[48], epk[97]; /* a P-256 or P-384 share, after a retry */
  uint8_t *kdk;         /* the X25519MLKEM768 secret (nqmal'd) */
  uint8_t kek[NQTLHEK]; /* and its share */
  nqfctx th;            /* the transcript hash */
  int thon;
  int creq;             /* a CertificateRequest came */
  uint8_t crctx[256];   /* its certificate_request_context */
  size_t crctxn;
  uint16_t cvs;         /* the CertificateVerify scheme */
  uint8_t sec[NQHMAX];  /* handshake secret, then master secret */
  uint8_t chs[NQHMAX], shs[NQHMAX];
  uint8_t cfk[NQHMAX];
  size_t rsl;           /* record_size_limit, 0 when none */
  nqtlkey rk, wk;
  /* the server's certificates, parsed from a copy of its Certificate
   * message (cm) */
  uint8_t *cm;
  size_t cmn;
  nqcert crt[NQTLCMAX];
  size_t ncrt;
  nqspan ocsp;          /* the leaf's stapled OCSPResponse, in cm */
  nqspan sctl;          /* its signed_certificate_timestamp list, in cm */
  /* Certificate Transparency: the caller's logs (nqtlct), none when off */
  nqtlog *lg;
  size_t nlg;
  uint8_t *lk;          /* their keys */
  size_t lkn;
  /* receiving: one record at a time */
  uint8_t rb[5 + NQTLCT];
  size_t rbn;           /* bytes of rb filled */
  size_t pp, pn;        /* plaintext of the current record: rb + 5 + pp */
  int pt;               /* its content type, 0 when none is left */
  /* handshake reassembly */
  uint8_t *hm;
  size_t hmcap, hmn, hmoff;
  /* sending */
  uint8_t wb[5 + NQTLCT];
};

/* ---- the context (api.c) ---- */

/* nqtlnew without the NQTLS switch and without requiring anchors (the
 * tests' constructor) */
int nqtlmk(nqtls **t, const char *host, const uint8_t *ca, size_t calen,
           const nqtlio *io);
#ifdef NQTEST
/* sets the test hooks; before nqtlhand */
void nqtlhook(nqtls *t, const nqtlhk *hk);
#define NQTLHK(t) (&(t)->hk)
#else
extern const nqtlhk nqtlhk0;
#define NQTLHK(t) ((void)(t), &nqtlhk0)
#endif
/* nqtlwr, nqtlrd and nqtlend without the NQTLS switch */
int nqtlw(nqtls *t, const uint8_t *b, size_t n);
int nqtlr(nqtls *t, uint8_t *b, size_t cap, size_t *got);
int nqtle(nqtls *t);

/* ---- key schedule (ks.c) ---- */

/* HKDF-Expand-Label (section 7.1) */
int nqtlexp(nqhalg h, const uint8_t *sec, const char *label,
            const uint8_t *ctx, size_t cn, uint8_t *out, size_t n);
/* Derive-Secret with the transcript hash already taken */
int nqtlder(nqhalg h, const uint8_t *sec, const char *label,
            const uint8_t *th, uint8_t *out);
/* the next stage's secret: HKDF-Extract(Derive-Secret(sec, "derived",
 * ""), ikm); sec NULL for the early secret (salt 0, ikm 0) */
int nqtlnext(nqhalg h, const uint8_t *sec, const uint8_t *ikm, size_t in,
             uint8_t *out);
/* installs traffic secret sec as the key of k for suite */
int nqtlkeys(nqtlkey *k, uint16_t suite, nqhalg h, const uint8_t *sec);
/* the hash of a suite: NQS256, NQS384, or 0 for one not offered */
nqhalg nqtlsh(uint16_t suite);

/* ---- records (rec.c) ---- */

/* sends n bytes of type ty, fragmented, protected when wk is on */
int nqtlsend(nqtls *t, int ty, const uint8_t *b, size_t n);
/* reads the next record into rb and its plaintext into pp/pn/pt */
int nqtlrec(nqtls *t);
/* the next handshake message: *m points at its header (4 bytes) and
 * body, *n is header + body; valid until the next call */
int nqtlmsg(nqtls *t, const uint8_t **m, size_t *n);
/* the parts of nqtlmsg: nqtlpop takes a whole buffered message (*got 0
 * when there is none), nqtlpush appends the current record's handshake
 * bytes */
int nqtlpop(nqtls *t, const uint8_t **m, size_t *n, int *got);
int nqtlpush(nqtls *t);
/* NQOK when no handshake bytes and no record plaintext are buffered:
 * the check before a key change (section 5.1) */
int nqtlflat(nqtls *t);
/* the first error: records it with an alert number and a sentence,
 * sends the fatal alert (best effort) and returns rc */
int nqtlfail(nqtls *t, int rc, int alert, const char *why);

/* ---- the handshake (hs.c) ---- */

int nqtlhand(nqtls *t);
/* reads what a ClientHello offered */
int nqtlscan(const uint8_t *ch, size_t n, nqtloff *o);
/* post-handshake messages (NewSessionTicket, KeyUpdate) */
int nqtlpost(nqtls *t, const uint8_t *m, size_t n);

/* ---- certificates (crt.c) ---- */

/* parses a PEM bundle (or one DER certificate) into t->anc; NQEDEC
 * when nothing in it is a certificate this module can use */
int nqtlca(nqtls *t, const uint8_t *b, size_t n);
/* checks the server's chain in t->crt for t->host at time now */
int nqtlpath(nqtls *t, int64_t now);
/* 1 when the certificate c names host (RFC 6125: DNS names in the
 * subjectAltName, a wildcard only as the whole leftmost label) or, for
 * an address, lists it as an iPAddress */
int nqtlname(const nqcert *c, const char *host, int ip, const uint8_t *ipb);
/* parses an IPv4 or IPv6 literal; the byte count (4, 16) or 0 */
int nqtlip(const char *s, uint8_t *out);
/* checks the CertificateVerify signature sig of scheme over the
 * transcript hash th with the leaf key */
int nqtlcv(nqtls *t, uint16_t scheme, const uint8_t *th, const uint8_t *sig,
           size_t sn);

/* ---- Certificate Transparency (ct.c) ---- */

/* reads a log list (Chrome's log_list.json, v3) into t->lg */
int nqtlctl(nqtls *t, const uint8_t *js, size_t n);
/* checks the SCTs of leaf (embedded; issuer iss) and of the TLS
 * extension at time now against t->lg: SCTs from two operators */
int nqtlctv(nqtls *t, const nqcert *leaf, const nqcert *iss, int64_t now);

#endif /* NQTLS_H */
