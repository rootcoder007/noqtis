/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: Notary Of Quantum-safe Traceable Inputs and Seals.
 *
 * Public interface. Every function returns NQOK (0) or a negative NQE*
 * code; a failed verification is NQEVRFY, never NQOK. Callers allocate
 * every output buffer and pass its length.
 */
#ifndef NOQTIS_H
#define NOQTIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NQAPI marks the public functions: the only symbols a shared noqtis
 * exports. A Windows DLL build defines NQBUILD and NQDLL; its users define
 * NQDLL (CMake and noqtis.pc do it for them). Static builds need nothing. */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(NQDLL) && defined(NQBUILD)
#    define NQAPI __declspec(dllexport)
#  elif defined(NQDLL)
#    define NQAPI __declspec(dllimport)
#  else
#    define NQAPI
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define NQAPI __attribute__((visibility("default")))
#else
#  define NQAPI
#endif

#define NQVMAJ 0
#define NQVMIN 1
#define NQVPAT 0

/* ---- error codes ---------------------------------------------------- */

#define NQOK       0
#define NQEARG    -1  /* an argument is out of range or NULL */
#define NQEBUF    -2  /* an output buffer is too small */
#define NQEVRFY   -3  /* a signature, MAC or digest does not verify */
#define NQEDEC    -4  /* input is not in the encoding the standard defines */
#define NQERNG    -5  /* the operating system's random source failed */
#define NQEMEM    -6  /* the allocation hook returned NULL */
#define NQEIO     -7  /* a file could not be read or written */
#define NQENOSUP  -8  /* an algorithm or option noqtis does not provide */
#define NQELIM    -9  /* input exceeds a size or depth limit */
#define NQESTATE -10  /* a context was used out of order */

NQAPI const char *nqerr(int err);
NQAPI const char *nqver(void);

/* ---- core ----------------------------------------------------------- */

/* Wipes len bytes at p; the compiler cannot remove the stores. */
NQAPI void nqwipe(void *p, size_t len);

/* 1 when the two buffers are equal, 0 otherwise, in time that depends only
 * on len. */
NQAPI int nqcteq(const void *a, const void *b, size_t len);

/* Fills buf with len bytes from the operating system's CSPRNG. */
NQAPI int nqrand(uint8_t *buf, size_t len);

/* Replaces the allocator the capsule and parser layers use; NULL for both
 * restores malloc/free. Not thread safe: call before anything else. */
typedef void *(*nqmalfn)(size_t size, void *user);
typedef void (*nqfreefn)(void *ptr, size_t size, void *user);
NQAPI int nqsetal(nqmalfn mal, nqfreefn fre, void *user);

/* ---- hashes --------------------------------------------------------- */

typedef enum {
  NQS224 = 1, NQS256, NQS384, NQS512, NQS512T224, NQS512T256,
  NQS3224, NQS3256, NQS3384, NQS3512,
  NQSHK128, NQSHK256
} nqhalg;

/* Opaque, but sized here so callers can keep it on the stack. */
typedef struct {
  uint64_t opq[52];
} nqhctx;

/* Digest size in bytes; for SHAKE, the output the pre-hash variants use
 * (32 for SHAKE128, 64 for SHAKE256). 0 if unknown. */
NQAPI size_t nqhlen(nqhalg alg);

NQAPI int nqhash(nqhalg alg, const uint8_t *in, size_t inlen,
                 uint8_t *out, size_t outlen);
NQAPI int nqhini(nqhctx *ctx, nqhalg alg);
NQAPI int nqhupd(nqhctx *ctx, const uint8_t *in, size_t inlen);
/* For SHAKE, may be called again to squeeze more output. */
NQAPI int nqhfin(nqhctx *ctx, uint8_t *out, size_t outlen);

NQAPI int nqhmac(nqhalg alg, const uint8_t *key, size_t keylen,
                 const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* ---- signatures ----------------------------------------------------- */

/* NQSLH*: SLH-DSA with SHA-2; NQSLHK*: SLH-DSA with SHAKE. */
typedef enum {
  NQMLDSA44 = 1, NQMLDSA65, NQMLDSA87,
  NQSLH128S, NQSLH128F, NQSLH192S, NQSLH192F, NQSLH256S, NQSLH256F,
  NQSLHK128S, NQSLHK128F, NQSLHK192S, NQSLHK192F, NQSLHK256S, NQSLHK256F
} nqsalg;

typedef struct {
  size_t pk;
  size_t sk;
  size_t sig;
} nqssz;

NQAPI int nqssize(nqsalg alg, nqssz *sz);
/* "ML-DSA-65", "SLH-DSA-SHA2-128s", ...; NULL if unknown. */
NQAPI const char *nqsname(nqsalg alg);
NQAPI int nqsfind(const char *name, nqsalg *alg);

NQAPI int nqskg(nqsalg alg, uint8_t *pk, size_t pklen,
                uint8_t *sk, size_t sklen);
/* Key generation from the standard's seed (xi for ML-DSA; SK.seed ||
 * SK.prf || PK.seed for SLH-DSA), for the test vectors. */
NQAPI int nqskgd(nqsalg alg, const uint8_t *seed, size_t seedlen,
                 uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);

/* Signing with a context string (at most 255 bytes; NULL/0 for none).
 * ph is 0 for the pure variant, or an nqhalg for HashML-DSA /
 * HashSLH-DSA, in which case msg is the message and is hashed here. */
NQAPI int nqsign(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *ctx, size_t ctxlen, int ph,
                 uint8_t *sig, size_t siglen, size_t *outlen);
/* rnd is the standard's per-signature randomness (32 bytes for ML-DSA,
 * n bytes for SLH-DSA); all zero gives the deterministic variant. */
NQAPI int nqsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *ctx, size_t ctxlen, int ph,
                  const uint8_t *rnd, size_t rndlen,
                  uint8_t *sig, size_t siglen, size_t *outlen);
NQAPI int nqvrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *ctx, size_t ctxlen, int ph,
                 const uint8_t *sig, size_t siglen);

/* ---- key encapsulation ---------------------------------------------- */

typedef enum {
  NQMLKEM512 = 1, NQMLKEM768, NQMLKEM1024,
  NQHQC128, NQHQC192, NQHQC256
} nqkalg;

typedef struct {
  size_t pk;
  size_t sk;
  size_t ct;
  size_t ss;
} nqksz;

NQAPI int nqksize(nqkalg alg, nqksz *sz);
NQAPI const char *nqkname(nqkalg alg);
NQAPI int nqkfind(const char *name, nqkalg *alg);

NQAPI int nqkkg(nqkalg alg, uint8_t *pk, size_t pklen,
                uint8_t *sk, size_t sklen);
NQAPI int nqkkgd(nqkalg alg, const uint8_t *seed, size_t seedlen,
                 uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);
NQAPI int nqenc(nqkalg alg, const uint8_t *pk, size_t pklen,
                uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
NQAPI int nqencd(nqkalg alg, const uint8_t *pk, size_t pklen,
                 const uint8_t *seed, size_t seedlen,
                 uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);
/* Implicit rejection: a bad ciphertext yields a pseudorandom secret and
 * NQOK, as the standards require; only malformed sizes fail. */
NQAPI int nqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
                const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

/* ---- capsules ------------------------------------------------------- */

typedef struct nqrep nqrep;

/* Writes noqtis.json and noqtis.sig into dir, covering every regular file
 * in it. tsa NULL: no timestamp. */
NQAPI int nqseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, const char *meta,
                 const char *tsa);
/* Checks dir against its seal; trust NULL accepts the key in the seal (and
 * the report says so). The report lists every check. */
NQAPI int nqchk(const char *dir, const uint8_t *trust, size_t trustlen,
                nqrep **rep);
NQAPI size_t nqrepn(const nqrep *r);
NQAPI int nqrepi(const nqrep *r, size_t i, const char **check, int *ok,
                 const char **detail);
NQAPI void nqrepfree(nqrep *r);

#ifdef __cplusplus
}
#endif

#endif /* NOQTIS_H */
