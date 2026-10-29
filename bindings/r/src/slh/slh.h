/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* SLH-DSA (FIPS 205): the twelve parameter sets, key generation, signing
 * and verification, for the public dispatchers in noqtis.h and for the
 * ACVP tests. Internal: not part of the public API.
 *
 * Keys and signatures are the FIPS 205 byte strings: pk = PK.seed ||
 * PK.root (2n bytes), sk = SK.seed || SK.prf || PK.seed || PK.root (4n
 * bytes).
 *
 * Errors: NQEARG for a NULL pointer with a nonzero length, an unknown
 * parameter set or hash, a context over 255 bytes, a seed or randomness
 * of the wrong length, or a key buffer larger than the key; NQEBUF for an
 * output buffer that is too small; NQEDEC for a key or signature of the
 * wrong length; NQEVRFY for a signature that does not verify; NQERNG when
 * the operating system's random source fails. */
#ifndef NQSLH_H
#define NQSLH_H

#include <stddef.h>
#include <stdint.h>

#include "noqtis.h"

/* One parameter set (FIPS 205 table 2); w = 16 throughout. */
typedef struct {
  const char *name; /* "SLH-DSA-SHA2-128s", ... */
  nqsalg alg;
  unsigned sha2;    /* 1: the SHA-2 instantiation, 0: SHAKE */
  unsigned n;       /* security parameter, bytes */
  unsigned h;       /* hypertree height */
  unsigned d;       /* layers */
  unsigned hp;      /* h' = h / d, one XMSS tree */
  unsigned a;       /* FORS tree height */
  unsigned k;       /* FORS trees */
  unsigned m;       /* H_msg output, bytes */
  unsigned len;     /* WOTS+ chains: 2n + 3 */
  size_t pk, sk, sig;
} nqslp;

#define NQSLNSET 12
/* In the order of nqsalg: SHA-2 128s, 128f, 192s, 192f, 256s, 256f, then
 * SHAKE likewise. */
extern const nqslp nqsltab[NQSLNSET];

/* The parameter set for alg; NULL when alg is not an SLH-DSA set. */
const nqslp *nqslpar(nqsalg alg);
/* By name ("SLH-DSA-SHAKE-192f"); NULL when unknown. */
const nqslp *nqslfind(const char *name);

/* ---- key generation (FIPS 205 algorithms 18 and 21) ---- */

/* seed is SK.seed || SK.prf || PK.seed, 3n bytes. pklen and sklen must be
 * exactly 2n and 4n. */
int nqslkgd(nqsalg alg, const uint8_t *seed, size_t seedlen,
            uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
/* The seed from nqrand. */
int nqslkg(nqsalg alg, uint8_t *pk, size_t pklen, uint8_t *sk,
           size_t sklen);

/* ---- the external interface (FIPS 205 algorithms 22 to 25) ---- */

/* ctx is the context string (at most 255 bytes, NULL/0 for none). ph is
 * 0 for pure SLH-DSA, or an nqhalg for HashSLH-DSA (section 10.2.2): msg
 * is then the message, hashed here, and M' carries that hash's OID.
 * siglen is the buffer size (at least p->sig); *outlen (may be NULL)
 * gets p->sig. */

/* Hedged: opt_rand is n fresh bytes from nqrand. */
int nqslsign(nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *msg, size_t msglen, const uint8_t *ctx,
             size_t ctxlen, int ph, uint8_t *sig, size_t siglen,
             size_t *outlen);
/* rnd is opt_rand, n bytes. rnd NULL (rndlen 0) or n zero bytes selects
 * the deterministic variant, opt_rand = PK.seed (as noqtis.h's nqsignd
 * promises: "all zero gives the deterministic variant"); the zero test
 * runs in constant time. */
int nqslsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
              const uint8_t *msg, size_t msglen, const uint8_t *ctx,
              size_t ctxlen, int ph, const uint8_t *rnd, size_t rndlen,
              uint8_t *sig, size_t siglen, size_t *outlen);
int nqslvrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *msg, size_t msglen, const uint8_t *ctx,
             size_t ctxlen, int ph, const uint8_t *sig, size_t siglen);

/* ---- the internal interface (FIPS 205 algorithms 19 and 20) ---- */

/* msg is M itself, with no domain separator: the interface ACVP calls
 * "internal". addrnd is opt_rand exactly (n bytes); NULL (rndlen 0) is
 * the deterministic variant, opt_rand = PK.seed. */
int nqslsigi(nqsalg alg, const uint8_t *sk, size_t sklen,
             const uint8_t *msg, size_t msglen, const uint8_t *addrnd,
             size_t rndlen, uint8_t *sig, size_t siglen, size_t *outlen);
int nqslvrfi(nqsalg alg, const uint8_t *pk, size_t pklen,
             const uint8_t *msg, size_t msglen, const uint8_t *sig,
             size_t siglen);

#endif /* NQSLH_H */
