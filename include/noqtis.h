/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: Notary of Quantum-Safe Traceable Inputs and Seals.
 *
 * Public interface. Every function returns NQOK (0) or a negative NQE*
 * code; a failed verification is NQEVRFY, never NQOK. Callers allocate
 * every output buffer and pass its length; the exceptions are the
 * reports (nqrep, freed with nqrepfree) and the handles (nqp11, nqtls)
 * that a few functions make.
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
#define NQVMIN 3
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
#define NQEFLT   -11  /* a signature failed the checks made right after
                       * signing (a fault while signing or in the stored
                       * key); it was zeroed, not returned */
#define NQEKAT   -12  /* a known answer of nqselftest did not match */
#define NQESTOP  -13  /* the caller's hook (nqsetstop) asked to stop */

NQAPI const char *nqerr(int err);
NQAPI const char *nqver(void);
/* Known answers for every algorithm family (the hashes, HMAC, the key
 * derivations, HMAC_DRBG, ML-KEM, HQC, ML-DSA, SLH-DSA key generation
 * but not its signing, Ed25519 and a hybrid, X25519 and ECDH, RSA and
 * ECDSA verification, the ciphers; nqselftest(3) lists the tests), run
 * in about a tenth of a second: NQOK, or NQEKAT when one does not match. A
 * module can run it once before use, as FIPS 140-3 asks. The masked
 * decapsulations and signatures draw on the random source, so without
 * one (NQFREE with no nqsetrng) it returns NQEKAT. Safe to call from
 * several threads at once: one test runs at a time, the others wait. */
NQAPI int nqselftest(void);

/* ---- core ----------------------------------------------------------- */

/* Wipes len bytes at p; the compiler cannot remove the stores. */
NQAPI void nqwipe(void *p, size_t len);

/* 1 when the two buffers are equal, 0 otherwise, in time that depends only
 * on len. */
NQAPI int nqcteq(const void *a, const void *b, size_t len);

/* Fills buf with len bytes from the operating system's CSPRNG. */
NQAPI int nqrand(uint8_t *buf, size_t len);
/* A random source of the caller's (a hardware generator, an HSM, a
 * DRBG the caller seeds): fn fills len bytes at buf and returns 0, or
 * anything else on failure (then noqtis returns NQERNG). From then on
 * nqrand, and every masked or hedged operation, draws from it; fn NULL
 * restores the operating system's source. It may be set at any time,
 * also while other threads call into noqtis: a call sees the source of
 * before or of after, with its own user pointer. In a freestanding
 * build (NQFREE) there is no operating system source, and nqrand fails
 * until a source is set. */
typedef int (*nqrngfn)(uint8_t *buf, size_t len, void *user);
NQAPI int nqsetrng(nqrngfn fn, void *user);

/* Progress of the long calls, for a caller to show (noqtis(1) draws a
 * bar): fn(stage, done, total, user) is called as the work goes, from the
 * thread doing it, with done from 0 to total, and once more with done ==
 * total when the stage ends. Stages: NQPHASH, the bytes of a folder's
 * files that nqseal, nqseal2 and nqchkx hash (total: the folder's
 * listing); NQPSIGN, an SLH-DSA signature's d + 1 trees (FORS, then each
 * hypertree layer), the slow part of signing. Only counts the caller
 * could know are reported, nothing that depends on a secret. Global,
 * and safe to set while other threads work, as nqsetrng; each thread's
 * stage is its own. NULL stops it. */
#define NQPHASH 1
#define NQPSIGN 2
typedef void (*nqprogfn)(int stage, uint64_t done, uint64_t total,
                         void *user);
NQAPI int nqsetprog(nqprogfn fn, void *user);

/* Stopping a long call: fn(user) is asked as the work goes, from the
 * thread doing it, wherever NQPHASH progress is reported (the files
 * nqseal, nqseal2 and nqchkx hash, once per 16 KiB read). When it
 * returns anything but 0 the call ends with NQESTOP: a seal writes
 * nothing, and a check gives no report. fn must be quick and must not
 * call back into the library; a flag another thread or a signal handler
 * sets is what it is for. Global, and safe to set while other threads
 * work, as nqsetprog; NULL stops asking. */
typedef int (*nqstopfn)(void *user);
NQAPI int nqsetstop(nqstopfn fn, void *user);

/* The temporary files the capsule layer writes a file through before it
 * renames it into place (nqseal, nqseal2, nqtsput, nqersput: a new name
 * beside it, made with O_EXCL), for a caller that removes them when a
 * signal stops it: fn(ev, path, user) with NQTPRE right before each
 * attempt to make path, NQTNEW once it is made (the library's file),
 * NQTNOT when it is not (the name was taken, or another error: never the
 * library's file), and NQTEND once it is renamed into place or removed.
 * NQTPRE is always followed by NQTNEW or NQTNOT, with nothing between.
 * Called from the thread doing the work; fn must not call back into the
 * library. Global, and safe to set while other threads work, as
 * nqsetprog; NULL stops it. */
#define NQTPRE 0
#define NQTNEW 1
#define NQTNOT 2
#define NQTEND 3
typedef void (*nqtmpfn)(int ev, const char *path, void *user);
NQAPI int nqsettmp(nqtmpfn fn, void *user);

/* Replaces the allocator the capsule and parser layers (JSON, DER,
 * CMS, OpenPGP, TLS), the multi-recipient stream (noqtis-kstream-2),
 * PKCS #11 and Argon2id (nqa2id, nqpwenc, nqpwdec) use (the data layer
 * has its own, nqdsetal); NULL for both
 * restores malloc/free. Setting it is safe while other threads work,
 * but memory is freed by the allocator in place at that moment: set it
 * before anything is allocated, or make both free either's memory. */
typedef void *(*nqmalfn)(size_t size, void *user);
typedef void (*nqfreefn)(void *ptr, size_t size, void *user);
NQAPI int nqsetal(nqmalfn mal, nqfreefn fre, void *user);

/* ---- hashes --------------------------------------------------------- */

typedef enum {
  NQS224 = 1, NQS256, NQS384, NQS512, NQS512T224, NQS512T256,
  NQS3224, NQS3256, NQS3384, NQS3512,
  NQSHK128, NQSHK256
} nqhalg;

/* Opaque, but sized here so callers can keep it on the stack. nqhupd and
 * nqhfin check its fields and return NQESTATE for a context nqhini did
 * not make (one copied in from elsewhere and changed, say). */
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

/* PBKDF2 (RFC 8018) on that HMAC: outlen bytes (1 to NQPBOMAX) from the
 * password pw and the salt after iters iterations (1 to NQPBIMAX).
 * NQEARG outside those limits or for a NULL pointer with a length,
 * NQENOSUP for SHAKE. It costs an attacker no memory: where the choice
 * is free, nqa2id is the one to use. */
#define NQPBIMAX 100000000u
#define NQPBOMAX 1024u
NQAPI int nqpbkdf2(nqhalg alg, const uint8_t *pw, size_t pwlen,
                   const uint8_t *salt, size_t slen, uint32_t iters,
                   uint8_t *out, size_t outlen);

/* BLAKE2b (RFC 7693): an outlen-byte digest (1 to 64) of in, keyed with
 * keylen bytes of key (0 to 64; key may be NULL when keylen is 0, the
 * plain hash). The key makes it a MAC: compare tags with nqcteq.
 * NQEARG for a length out of range or a NULL pointer. */
NQAPI int nqb2b(const uint8_t *key, size_t keylen, const uint8_t *in,
                size_t inlen, uint8_t *out, size_t outlen);

/* ---- symmetric encryption: ChaCha20, AES-SIV, AES-GCM-SIV ----
 *
 * The two SIV modes are authenticated encryption that survives a nonce
 * used twice, or needs none: use them where a nonce cannot be counted or
 * remembered, and where the same message must give the same ciphertext.
 * Decryption returns NQEVRFY for a ciphertext, key, nonce or associated
 * data that does not verify, and the output is then all zero. out may
 * not overlap in. All three are constant time in the key and the data. */

/* The ChaCha20 stream cipher (RFC 8439 section 2.4): inlen bytes of in
 * XORed with the key stream of the 32-byte key and the 12-byte nonce,
 * from block counter ctr (a block is 64 bytes; RFC 8439 starts messages
 * at 1). Decryption is the same call. out may be in.
 *
 * NOT AUTHENTICATED: a changed ciphertext decrypts to a changed
 * plaintext with no error, and a (key, nonce, counter) used for two
 * messages gives away their XOR. It is here for protocols that add
 * their own authentication; to encrypt, use nqsivenc or nqgsivenc.
 * NQEARG for another key or nonce length or a NULL pointer; NQELIM for
 * more bytes than the 32-bit counter has blocks left. */
NQAPI int nqcha20(const uint8_t *key, size_t keylen, const uint8_t *nonce,
                  size_t nlen, uint32_t ctr, const uint8_t *in,
                  size_t inlen, uint8_t *out);

/* AES-SIV (RFC 5297), deterministic authenticated encryption. key is 32,
 * 48 or 64 bytes: two AES-128, AES-192 or AES-256 keys. ad is nad
 * associated strings of adlen[i] bytes each (0 to NQSIVADMAX of them;
 * NULL when nad is 0), authenticated and not encrypted, each a separate
 * input: a nonce, where there is one, is by convention the last. The
 * output is the 16-byte synthetic IV, then inlen bytes of ciphertext:
 * outlen must be inlen + 16 (nqsivenc) or inlen - 16 (nqsivdec).
 * The same key, strings and plaintext always give the same output: it
 * shows when two messages are equal, and nothing else. */
#define NQSIVADMAX 126u
NQAPI int nqsivenc(const uint8_t *key, size_t keylen,
                   const uint8_t *const *ad, const size_t *adlen,
                   size_t nad, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t outlen);
NQAPI int nqsivdec(const uint8_t *key, size_t keylen,
                   const uint8_t *const *ad, const size_t *adlen,
                   size_t nad, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t outlen);

/* AES-GCM-SIV (RFC 8452), authenticated encryption that resists nonce
 * misuse. key is 16 or 32 bytes (AES-128 or AES-256), nonce 12 bytes, ad
 * the associated data (NULL with length 0 for none). The output is inlen
 * bytes of ciphertext, then the 16-byte tag: outlen must be inlen + 16
 * (nqgsivenc) or inlen - 16 (nqgsivdec). A nonce should still be new for
 * each message; one used twice with the same key shows only whether the
 * two messages and their associated data were equal.
 * NQELIM for a plaintext or associated data over 2^36 bytes. */
NQAPI int nqgsivenc(const uint8_t *key, size_t keylen, const uint8_t *nonce,
                    size_t nlen, const uint8_t *ad, size_t adlen,
                    const uint8_t *in, size_t inlen, uint8_t *out,
                    size_t outlen);
NQAPI int nqgsivdec(const uint8_t *key, size_t keylen, const uint8_t *nonce,
                    size_t nlen, const uint8_t *ad, size_t adlen,
                    const uint8_t *in, size_t inlen, uint8_t *out,
                    size_t outlen);

/* KangarooTwelve (RFC 9861): outlen bytes (1 or more) of KT128 (bits
 * 128) or KT256 (bits 256) of in, with the customization string custom
 * (NULL with length 0 for none, the default). An extendable-output
 * function on TurboSHAKE, Keccak with 12 rounds: a shorter output is the
 * start of a longer one, and an input over 8192 bytes is hashed as a
 * tree. 32 bytes of KT128 or 64 of KT256 give their full strength
 * against collisions (128 and 256 bits). With a secret key as custom it
 * is a MAC (RFC 9861 section 4): compare tags with nqcteq.
 * NQEARG for other bits, an outlen of 0 or a NULL pointer. */
NQAPI int nqkt(unsigned bits, const uint8_t *in, size_t inlen,
               const uint8_t *custom, size_t clen, uint8_t *out,
               size_t outlen);

/* The same in pieces, for an input that is not in memory at once:
 * nqktini, nqktupd any number of times, then nqktfin once, with the
 * customization string and the output length. Opaque, but sized here so
 * callers can keep it on the stack; nqktfin wipes it, and nqktupd and
 * nqktfin return NQESTATE for a context nqktini did not make or nqktfin
 * has ended. */
typedef struct {
  uint64_t opq[62];
} nqktctx;
NQAPI int nqktini(nqktctx *ctx, unsigned bits);
NQAPI int nqktupd(nqktctx *ctx, const uint8_t *in, size_t inlen);
NQAPI int nqktfin(nqktctx *ctx, const uint8_t *custom, size_t clen,
                  uint8_t *out, size_t outlen);

/* Argon2id (RFC 9106, version 0x13) on that BLAKE2b: outlen bytes from
 * the password pw, the salt, the optional secret key and associated
 * data ad (NULL with length 0 for none), t passes over m KiB of memory
 * in p lanes. The limits, each NQEARG outside it: */
#define NQA2TMAX 1024u     /* passes t: 1 to this */
#define NQA2PMAX 255u      /* lanes p: 1 to this */
#define NQA2MMAX 4194304u  /* memory m in KiB: 8p to this (4 GiB) */
#define NQA2SMIN 8u        /* the shortest salt (16 or more is usual) */
#define NQA2OMIN 4u        /* output: 4 to 1024 bytes */
#define NQA2OMAX 1024u
/* pw, salt, key and ad are each under 2^32 bytes (the RFC's limit).
 * The memory is allocated once, through the nqsetal hook (NQEMEM when
 * it fails; NQELIM when m KiB does not fit in a size_t), and wiped and
 * freed before the call returns; the lanes run one after another in the
 * calling thread. Its second half reads memory at places that depend
 * on the password, as Argon2id is designed to. */
NQAPI int nqa2id(const uint8_t *pw, size_t pwlen, const uint8_t *salt,
                 size_t slen, const uint8_t *key, size_t klen,
                 const uint8_t *ad, size_t alen, uint32_t t, uint32_t m,
                 uint32_t p, uint8_t *out, size_t outlen);

/* ---- signatures ----------------------------------------------------- */

/* NQSLH*: SLH-DSA with SHA-2; NQSLHK*: SLH-DSA with SHAKE.
 * NQED25519: Ed25519 (RFC 8032), classical: for interoperability (DSSE
 * envelopes, say), never for a capsule seal.
 * NQMDED*: hybrid ML-DSA + Ed25519 ("ML-DSA-65+Ed25519"): pk = ML-DSA pk
 * || Ed25519 pk, sk = ML-DSA sk || Ed25519 sk, sig = ML-DSA sig ||
 * Ed25519 sig; both must verify. Each part signs with the context
 * "noqtis-hybrid:" || ctx (so ctx is at most 241 bytes), which keeps a
 * part from passing as a plain signature; the pre-hash variant is
 * HashML-DSA with SHA-512 and Ed25519ph. */
typedef enum {
  NQMLDSA44 = 1, NQMLDSA65, NQMLDSA87,
  NQSLH128S, NQSLH128F, NQSLH192S, NQSLH192F, NQSLH256S, NQSLH256F,
  NQSLHK128S, NQSLHK128F, NQSLHK192S, NQSLHK192F, NQSLHK256S, NQSLHK256F,
  NQED25519, NQMDED44, NQMDED65, NQMDED87
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
 * SK.prf || PK.seed for SLH-DSA; the 32-byte private key for Ed25519;
 * xi || the Ed25519 key, 64 bytes, for a hybrid), for the test vectors. The seed may
 * overlap pk or sk. On any error pk and sk are cleared. */
NQAPI int nqskgd(nqsalg alg, const uint8_t *seed, size_t seedlen,
                 uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen);

/* Signing with a context string (at most 255 bytes; NULL/0 for none).
 * ph is 0 for the pure variant, or an nqhalg for HashML-DSA /
 * HashSLH-DSA, in which case msg is the message and is hashed here.
 * sig may overlap msg (signing in place). */
NQAPI int nqsign(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *ctx, size_t ctxlen, int ph,
                 uint8_t *sig, size_t siglen, size_t *outlen);
/* The version 2 secret-key container (docs/spec/keyfile.md): the key S
 * with, for Ed25519 and the hybrids, the Ed25519 public key P, and
 * T = SHA3-256("noqtis-sk-2" || 0x00 || name || 0x00 || S || P). Every
 * signing function takes S (as before) or the container X; with X, T is
 * computed again after signing and, for Ed25519 and the hybrids, the
 * public key derived again from the seed and compared with P, and a
 * signature leaves only when both hold (NQEFLT otherwise), so that a
 * change to any stored byte of the key, the fields that only feed the
 * signer's randomness among them, is caught. nqsxsz gives X's length;
 * nqsxmk makes X from S (x may be sk; xlen at least nqsxsz's); nqsxchk
 * checks X: NQOK, NQEDEC when damaged, NQENOSUP for a key of S's length
 * (no integrity value), NQEARG for an unknown alg. */
NQAPI int nqsxsz(nqsalg alg, size_t *n);
NQAPI int nqsxmk(nqsalg alg, const uint8_t *sk, size_t sklen, uint8_t *x,
                 size_t xlen);
NQAPI int nqsxchk(nqsalg alg, const uint8_t *x, size_t xlen);
/* rnd is the standard's per-signature randomness (32 bytes for ML-DSA
 * and the hybrids, n bytes for SLH-DSA, none for Ed25519: rnd may then be
 * NULL with rndlen 0); all zero gives the deterministic variant. Ed25519
 * (alone or in a hybrid) signs deterministically here, as RFC 8032 does;
 * nqsign hedges it with fresh randomness instead, which verifies the same
 * way. */
NQAPI int nqsignd(nqsalg alg, const uint8_t *sk, size_t sklen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *ctx, size_t ctxlen, int ph,
                  const uint8_t *rnd, size_t rndlen,
                  uint8_t *sig, size_t siglen, size_t *outlen);
NQAPI int nqvrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *ctx, size_t ctxlen, int ph,
                 const uint8_t *sig, size_t siglen);

/* ML-DSA with an external mu (FIPS 204, Algorithm 7 line 6 and
 * Algorithm 8 line 7): the caller supplies the 64-byte message
 * representative mu instead of the message, so the message can be
 * hashed somewhere else than where the key is (a token, an HSM).
 * NQMLDSA44, NQMLDSA65 and NQMLDSA87 only (NQENOSUP for the others).
 * nqsmu computes mu from the public key as nqsign would (pure with ph 0,
 * or HashML-DSA with ph an nqhalg; ctx at most 255 bytes); mulen must be
 * NQMU. A signature from nqsignmu on nqsmu's mu is the one nqsignd
 * gives with the same rnd, and nqvrfymu accepts what nqvrfy accepts.
 * rnd is NULL (rndlen 0) for the hedged signature, or 32 bytes (all
 * zero: deterministic). The signature is checked before it is returned,
 * as nqsign's is (NQEFLT otherwise). */
#define NQMU 64
NQAPI int nqsmu(nqsalg alg, const uint8_t *pk, size_t pklen,
                const uint8_t *msg, size_t msglen, const uint8_t *ctx,
                size_t ctxlen, int ph, uint8_t *mu, size_t mulen);
NQAPI int nqsignmu(nqsalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *mu, size_t mulen, const uint8_t *rnd,
                   size_t rndlen, uint8_t *sig, size_t siglen,
                   size_t *outlen);
NQAPI int nqvrfymu(nqsalg alg, const uint8_t *pk, size_t pklen,
                   const uint8_t *mu, size_t mulen, const uint8_t *sig,
                   size_t siglen);

/* Streaming signatures: the message in pieces (nqsupd, any number of
 * times, empty pieces too), the signature or verdict of the one-call
 * functions at the end. nqsini starts signing with sk, nqvini checking
 * with pk; nqsfin and nqvfin take the same key again (NQEARG for
 * another) and end the context, which then gives NQESTATE, as does a
 * context nqsini or nqvini did not make, or one used in the other
 * direction. nqsctx holds no pointer and no copy of the key; it is
 * wiped at the end, also on error. What streams:
 *   - ML-DSA, pure (ph 0) and pre-hash: mu is one pass over the
 *     message, finished through the external-mu path; the bytes are
 *     nqsignd's for the same message, context and rnd, nqsign's
 *     hedging when rnd is NULL;
 *   - HashSLH-DSA, Ed25519ph (ph NQS512 only) and the hybrids with ph
 *     NQS512: the message's hash streams, and the end is the one-call
 *     signature on it.
 * Pure SLH-DSA, pure Ed25519 or Ed25519ctx, and the pure hybrids are
 * NQENOSUP: their signers read the message twice (the randomiser or
 * the nonce first, then the digest). rnd and rndlen are nqsignd's; NULL
 * (rndlen 0) is nqsign's hedged signature, and for Ed25519 alone any
 * non-NULL rnd with rndlen 0 is RFC 8032's deterministic one. */
typedef struct {
  uint64_t opq[160];
} nqsctx;
NQAPI int nqsini(nqsctx *c, nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *ctx, size_t ctxlen, int ph);
NQAPI int nqvini(nqsctx *c, nqsalg alg, const uint8_t *pk, size_t pklen,
                 const uint8_t *ctx, size_t ctxlen, int ph);
NQAPI int nqsupd(nqsctx *c, const uint8_t *msg, size_t n);
NQAPI int nqsfin(nqsctx *c, const uint8_t *sk, size_t sklen,
                 const uint8_t *rnd, size_t rndlen, uint8_t *sig,
                 size_t siglen, size_t *outlen);
NQAPI int nqvfin(nqsctx *c, const uint8_t *pk, size_t pklen,
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
 * NQOK, as the standards require. It fails on a NULL argument or an
 * unknown alg (NQEARG), on ss shorter than the shared secret (NQEBUF),
 * on a secret key or ciphertext of the wrong length (NQEDEC; an HQC
 * secret key of specification 5.0 is one: HQC follows specification 5.1,
 * whose secret key is the 32-byte seed), on an ML-KEM secret key whose
 * embedded hash does not match (NQEDEC), and, since ML-KEM and HQC
 * decapsulation are masked with fresh randomness, when the random source
 * (nqsetrng) fails (NQERNG). */
NQAPI int nqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
                const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

/* One message sealed to an ML-KEM public key (noqtis-kseal-1), for the
 * hidden list of a commitment: "NQKS", the version 1, the algorithm (1
 * byte, its nqkalg), the ML-KEM ciphertext, then the message under
 * ChaCha20-Poly1305 and its 16-byte tag. The AEAD's key and nonce are
 * HKDF-SHA-256 of the shared secret, with info "noqtis-kseal-1", the
 * SHA3-256 of the public key, the context's length (1 byte) and bytes,
 * the 6-byte header and the KEM ciphertext; its associated data is the
 * header, the KEM ciphertext, the context's length and bytes. ctx (at
 * most 255 bytes; NULL/0 for none) must be the same to open. alg is
 * NQMLKEM512, NQMLKEM768 or NQMLKEM1024 (NQENOSUP otherwise). The
 * output is NQKSOVH + the KEM ciphertext size + n bytes (n at most
 * NQKSMAX, NQELIM above); *outlen gets it, also with NQEBUF. msg and
 * out must not overlap. */
#define NQKSOVH 22u
#define NQKSMAX ((size_t)1 << 30)
NQAPI int nqkseal(nqkalg alg, const uint8_t *pk, size_t pklen,
                  const uint8_t *ctx, size_t ctxlen, const uint8_t *msg,
                  size_t n, uint8_t *out, size_t cap, size_t *outlen);
/* Opens what nqkseal wrote (n bytes at in) with the secret key: the
 * message to msg (cap bytes; *outlen gets its size, also with NQEBUF).
 * NQEDEC for a header, version or algorithm that is not this one's, or
 * a size too small to hold one; NQEVRFY when the tag does not verify (a
 * changed byte anywhere, another key or another ctx: the KEM's implicit
 * rejection gives another key, so the tag fails); msg is then zeroed. */
NQAPI int nqkopen(nqkalg alg, const uint8_t *sk, size_t sklen,
                  const uint8_t *ctx, size_t ctxlen, const uint8_t *in,
                  size_t n, uint8_t *msg, size_t cap, size_t *outlen);

/* A stream sealed to an ML-KEM public key (noqtis-kstream-1), for files
 * of any size in bounded memory: the STREAM construction on
 * ChaCha20-Poly1305. The header, NQKFHDR bytes then the KEM ciphertext:
 * "NQKF", the version 1, the algorithm (its nqkalg), the chunk size (32
 * bits, big-endian), a random 7-byte nonce prefix. The key is
 * HKDF-SHA-256 of the shared secret with info "noqtis-kstream-1", the
 * SHA3-256 of the public key, the context's length and bytes and the
 * whole header, so a changed header gives another key. Then the chunks,
 * each its plaintext under the AEAD and a 16-byte tag, with the nonce
 * prefix || the chunk's number (32 bits, big-endian) || 1 for the last
 * chunk, 0 before it; every chunk but the last holds exactly the chunk
 * size, the last 0 to the chunk size (an empty stream is one empty last
 * chunk). Moved, repeated or dropped chunks, a stream cut at a chunk's
 * end, bytes after the last chunk and a changed header all fail a tag.
 * The chunk size is NQKFCMIN to NQKFCMAX (0 for NQKFCHUNK); a reader
 * refuses another (NQELIM) before deriving anything; at most 2^32
 * chunks (NQELIM for more: a nonce would repeat).
 *
 * nqkfeini writes the header to hdr (cap bytes; *hlen its size, also
 * with NQEBUF); nqkfeupd seals one full chunk (n the chunk size),
 * nqkfefin the last (n at most the chunk size), each to out with its
 * tag (*outlen). nqkfdini reads the header (hlen exactly NQKFHDR + the
 * KEM ciphertext's size) and gives the chunk size; nqkfdupd opens one
 * chunk of the chunk size plus 16 bytes and nqkfdfin the last (16 bytes
 * to the chunk size plus 16), each plaintext to out only when its tag
 * verifies (NQEVRFY otherwise, out zeroed). The caller decides which
 * chunk is the last: the one the input ends with. The last call, and
 * any error but NQEBUF, ends the stream: the context is wiped and then
 * gives NQESTATE. alg is an ML-KEM set (NQENOSUP for HQC); ctx (at most
 * 255 bytes) must be the same to open. */
#define NQKFHDR 17u
#define NQKFCHUNK 65536u
#define NQKFCMIN 1024u
#define NQKFCMAX 16777216u
typedef struct {
  uint64_t opq[16];
} nqkfctx;
NQAPI int nqkfeini(nqkfctx *c, nqkalg alg, const uint8_t *pk, size_t pklen,
                   const uint8_t *ctx, size_t ctxlen, uint32_t chunk,
                   uint8_t *hdr, size_t cap, size_t *hlen);
NQAPI int nqkfeupd(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqkfefin(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqkfdini(nqkfctx *c, nqkalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr,
                   size_t hlen, uint32_t *chunk);
NQAPI int nqkfdupd(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqkfdfin(nqkfctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);

/* A stream sealed to several ML-KEM public keys at once, and signed by
 * its sender when asked (noqtis-kstream-2). The stream is the one above
 * under a random file key; the header carries that key once for each
 * recipient, so any one of their secret keys opens it, and no byte of
 * the header can change without every chunk failing. The header,
 * NQKMFIX bytes then one entry per recipient: "NQKM", the version 2,
 * the flags (bit 0: signed), the chunk size (32 bits, big-endian), a
 * random 7-byte nonce prefix, the signature algorithm (its nqsalg, 0
 * when not signed), the number of recipients (16 bits) and the header's
 * whole length (32 bits); each entry is the recipient's KEM (its
 * nqkalg), the first 8 bytes of the SHA3-256 of its public key, the KEM
 * ciphertext and the file key under ChaCha20-Poly1305 (48 bytes).
 *
 * A signed stream ends, after its last chunk, with one more record of
 * the signature's size plus 16 bytes: the sender's signature over the
 * header and the whole plaintext, inside the encryption. Only a
 * recipient learns who signed, and a recipient cannot pass the stream
 * on as if the sender had sealed it to someone else. A reader releases
 * plaintext chunk by chunk, before the signature at the end is checked:
 * what it wrote is the sender's only once nqkmdfin returned NQOK.
 *
 * nqkmhlen gives the header's size for n recipients (1 to NQKMRCP);
 * nqkmeini writes it to hdr (cap bytes; *hlen its size, also with
 * NQEBUF), sig the algorithm the sender signs with or 0; nqkmeupd seals
 * one full chunk; nqkmefin seals the last (n at most the chunk size)
 * and, for a signed stream, signs with sk (the secret key of sig; NULL
 * otherwise) and appends the record: out needs n + 16 bytes, plus the
 * signature's size + 16.
 *
 * nqkmpeek reads the first NQKMFIX bytes of a stream: the header's
 * whole length, the signature algorithm (0: not signed) and the number
 * of recipients. nqkmdini opens the header (hlen exactly that length)
 * with one recipient's secret key; nqkmdupd opens one chunk of the
 * chunk size plus 16 bytes; nqkmdfin opens the last, in which is, for a
 * signed stream, also the record that follows it, and checks the
 * signature under pk (the sender's public key). With pk NULL the
 * signature is not checked: the caller does not ask who sent it.
 *
 * Errors, beyond those of the stream above: NQEVRFY from nqkmdini when
 * no entry opens with the key (not a recipient, or another context),
 * and from nqkmdfin when the signature does not verify under pk, or pk
 * is given for a stream that is not signed; NQELIM for more than
 * NQKMRCP recipients or a header length outside what they can take;
 * NQENOSUP for a signature algorithm this noqtis does not know. */
#define NQKMFIX 24u
#define NQKMRCP 64u
typedef struct {
  nqkalg alg;
  const uint8_t *pk;
  size_t pklen;
} nqkrcp;
typedef struct {
  uint64_t opq[64];
} nqkmctx;
NQAPI int nqkmhlen(const nqkrcp *r, size_t n, size_t *hlen);
NQAPI int nqkmpeek(const uint8_t *in, size_t n, size_t *hlen, nqsalg *sig,
                   size_t *nrcp);
NQAPI int nqkmeini(nqkmctx *c, const nqkrcp *r, size_t n, nqsalg sig,
                   const uint8_t *ctx, size_t ctxlen, uint32_t chunk,
                   uint8_t *hdr, size_t cap, size_t *hlen);
NQAPI int nqkmeupd(nqkmctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqkmefin(nqkmctx *c, const uint8_t *in, size_t n,
                   const uint8_t *sk, size_t sklen, uint8_t *out, size_t cap,
                   size_t *outlen);
NQAPI int nqkmdini(nqkmctx *c, nqkalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *ctx, size_t ctxlen, const uint8_t *hdr,
                   size_t hlen, uint32_t *chunk, nqsalg *sig);
NQAPI int nqkmdupd(nqkmctx *c, const uint8_t *in, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqkmdfin(nqkmctx *c, const uint8_t *in, size_t n,
                   const uint8_t *pk, size_t pklen, uint8_t *out, size_t cap,
                   size_t *outlen);

/* ---- passphrase key files ------------------------------------------- */

/* A secret key under a passphrase (noqtis-pwkey-1): the header, 35
 * bytes ("NQPW", the version 1, the KDF 1 (Argon2id, version 0x13), the
 * AEAD 1 (ChaCha20-Poly1305), m KiB, t and p as 32-bit big-endian
 * numbers, a random 16-byte salt), then the key under the AEAD and its
 * 16-byte tag. Argon2id of the passphrase and the salt gives the AEAD's
 * key and nonce (44 bytes); its associated data is the header and the
 * caller's ad (at most 1024 bytes: the key file's first line, say), so
 * no header field or ad changes without the tag failing. Defaults and
 * the limits both functions enforce: */
#define NQPWM 65536u       /* memory: 64 MiB */
#define NQPWT 3u           /* passes */
#define NQPWP 4u           /* lanes */
#define NQPWMMIN 8192u     /* memory at least 8 MiB */
#define NQPWMMAX 1048576u  /* at most 1 GiB */
#define NQPWTMAX 16u       /* passes 1 to 16 */
#define NQPWPMAX 16u       /* lanes 1 to 16 */
#define NQPWWORK 4194304u  /* m * t at most: 4 GiB of passes */
#define NQPWOVH 51u        /* bytes beyond the key: header and tag */
#define NQPWMAX 65536u     /* the longest key */
#define NQPWLEN 4096u      /* the longest passphrase (at least 1 byte) */
/* The KDF byte of the header names the derivation: NQPWA2, Argon2id as
 * above, the default; or NQPWPB, PBKDF2 with HMAC-SHA-256 (RFC 8018),
 * for places whose rules ask for it. Under NQPWPB the header's t is the
 * iteration count and its m and p are 0. */
#define NQPWA2 1
#define NQPWPB 2
#define NQPWI 600000u      /* PBKDF2 iterations: the default */
#define NQPWIMIN 100000u   /* at least */
#define NQPWIMAX 10000000u /* at most */
/* nqpwenc writes sklen + NQPWOVH bytes to out (cap; *outlen gets the
 * size, also with NQEBUF); m, t and p are 0 for the defaults. NQEARG
 * for a parameter outside the limits, NQERNG when the salt cannot be
 * drawn. sk and out must not overlap. */
NQAPI int nqpwenc(const uint8_t *pw, size_t pwlen, const uint8_t *ad,
                  size_t alen, uint32_t m, uint32_t t, uint32_t p,
                  const uint8_t *sk, size_t sklen, uint8_t *out, size_t cap,
                  size_t *outlen);
/* nqpwenc under the derivation kdf: NQPWA2 with m, t and p as there, or
 * NQPWPB with t the iteration count (0 for NQPWI; NQPWIMIN to NQPWIMAX)
 * and m and p 0. NQEARG for any other kdf. nqpwdec reads both. */
NQAPI int nqpwenc2(int kdf, const uint8_t *pw, size_t pwlen,
                   const uint8_t *ad, size_t alen, uint32_t m, uint32_t t,
                   uint32_t p, const uint8_t *sk, size_t sklen,
                   uint8_t *out, size_t cap, size_t *outlen);
/* Reads n bytes from nqpwenc: the key to sk (cap bytes; *sklen gets its
 * size, also with NQEBUF). Everything that can be checked before the
 * passphrase is: NQEDEC for a magic, version, KDF or AEAD that is not
 * this one or a size too small; NQELIM for parameters outside the
 * limits above (a file cannot ask for more memory or time) or a key
 * over NQPWMAX. Then NQEVRFY for a wrong passphrase or any changed
 * byte; sk is zeroed on every error. */
NQAPI int nqpwdec(const uint8_t *pw, size_t pwlen, const uint8_t *ad,
                  size_t alen, const uint8_t *in, size_t n, uint8_t *sk,
                  size_t cap, size_t *sklen);

/* ---- capsules ------------------------------------------------------- */

typedef struct nqrep nqrep;

/* Writes noqtis.json and noqtis.sig into dir, covering every regular file
 * in it (a link, a special file or a refused name is NQEARG; more than
 * 2,000,000 files, a path over 4096 bytes, folders over 64 deep or a
 * manifest over 512 MiB is NQELIM). The creation
 * time is SOURCE_DATE_EPOCH when set, else the clock. tsa must be NULL:
 * the library makes no network requests (NQENOSUP otherwise); add a
 * timestamp afterwards with nqtsreq and nqtsput. */
NQAPI int nqseal(const char *dir, nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, const char *meta,
                 const char *tsa);
/* Why nqseal or nqseal2 returned NQEARG for dir: *why gets the first
 * thing in it that a capsule cannot hold, and path (cap bytes, always
 * NUL-terminated when cap > 0; cut when too long) its path relative to
 * dir. NQSWLINK: a symbolic link or reparse point; NQSWODD: not a regular
 * file or folder (a device, a FIFO, a socket); NQSWNAME: a name noqtis
 * refuses (see noqtis-capsule(5)); NQSWCASE: a path equal to another but
 * for ASCII case; NQSWKEY: a file that starts like a noqtis secret key,
 * which would ship with the capsule. *why is 0 when nothing in dir stops
 * a seal: then the secret and public keys given were not one pair. */
enum { NQSWLINK = 1, NQSWODD, NQSWNAME, NQSWCASE, NQSWKEY };
NQAPI int nqsealwhy(const char *dir, int *why, char *path, size_t cap);
/* An input of a capsule: the input capsule's id (nqcapid) and a short
 * name for it (1 to 255 bytes of UTF-8, no control character). */
typedef struct {
  uint8_t id[32];
  const char *name;
} nqcin;
/* nqseal in format 2 (noqtis-capsule-2, noqtis-seal-2): the manifest also
 * carries a Merkle tree over its entries, so that nqprove can show single
 * files without the rest's names, sizes or digests, and the nin capsules
 * it was made from (at most 1024; in may be NULL when nin is 0). The seal
 * signs the manifest's head (everything but the list of files). Its
 * leaves are unsalted: anyone who can guess a file not shown (path and
 * content) can confirm the guess from a proof. nqseal3 salts them. */
NQAPI int nqseal2(const char *dir, nqsalg alg, const uint8_t *sk,
                  size_t sklen, const uint8_t *pk, size_t pklen,
                  const char *meta, const nqcin *in, size_t nin);
/* nqseal2 in format 3 (noqtis-capsule-3, noqtis-seal-3): each entry also
 * carries a salt of 32 bytes, in its Merkle leaf too, so that a proof
 * lets no one confirm a guess of the files it does not show. skey NULL
 * (skeylen 0): fresh salts from nqrand; else the 32-byte salt key the
 * salts are derived from (noqtis-capsule(5)), for a reproducible capsule:
 * keep it secret, as whoever has it can compute every salt. */
NQAPI int nqseal3(const char *dir, nqsalg alg, const uint8_t *sk,
                  size_t sklen, const uint8_t *pk, size_t pklen,
                  const char *meta, const nqcin *in, size_t nin,
                  const uint8_t *skey, size_t skeylen);
/* The id of the capsule in dir: the SHA-256 of the bytes its seal signs
 * (manifest_sha256 of a format 1 seal, head_sha256 of a format 2 or 3
 * one),
 * read from noqtis.sig. Nothing else is checked: check the capsule first
 * (nqchk) before relying on it. */
NQAPI int nqcapid(const char *dir, uint8_t id[32]);
/* Checks dir against its seal; trust NULL accepts the key in the seal (and
 * the report says so). The report lists every check. NQOK only when every
 * check passed, NQEVRFY otherwise (*rep is still set); free it with
 * nqrepfree. nqchk is nqchkt with no TSA anchors, so a seal that carries a
 * timestamp fails its timestamp check there. */
NQAPI int nqchk(const char *dir, const uint8_t *trust, size_t trustlen,
                nqrep **rep);
/* nqchk with nanc TSA trust anchors (DER certificates anc[i] of anclen[i]
 * bytes, at most 32): the seal must then carry an RFC 3161 token over the
 * signature bytes that verifies under one of them. */
NQAPI int nqchkt(const char *dir, const uint8_t *trust, size_t trustlen,
                 const uint8_t *const *anc, const size_t *anclen,
                 size_t nanc, nqrep **rep);
/* What nqchkx checks beyond nqchkt. Any member may be zero/NULL. */
typedef struct {
  const uint8_t *trust; /* the trusted public key, or NULL */
  size_t trustlen;
  const uint8_t *const *anc; /* TSA trust anchors, as nqchkt */
  const size_t *anclen;
  size_t nanc;
  /* a partial check: only these listed paths (normalised, '/' separated)
   * are checked; files not named, and files present but not listed, are
   * not, and the report says so in "partial" rows */
  const char *const *only;
  size_t nonly;
  /* lineage: capsule folders to find a format 2 capsule's inputs in, by
   * their id (nqcapid); each input found is checked the same way, with no
   * key pinned, its own inputs too, to 64 levels; one "lineage" row per
   * input */
  const char *const *lin;
  size_t nlin;
  /* key statements (noqtis-keys-1, from nqkstmt): stmt[i] of
   * stmtlen[i] bytes, at most 32; they need a trusted key. The "key" row
   * then also accepts a key the trusted key was rotated to, and a
   * "key.time" row requires a verified timestamp from before the seal's
   * key was rotated away or revoked, or has expired (nqkexp) */
  const char *const *stmt;
  const size_t *stmtlen;
  size_t nstmt;
} nqcopt;
/* A key statement (noqtis-keys-1), canonical JSON, to out (cap bytes;
 * *outlen gets the size, also with NQEBUF): the holder of the key pair
 * (sk, pk) of alg says that from time at (seconds since 1970, UTC) it is
 * replaced by the key pair (nsk, npk) of nalg, a rotation, which both
 * keys sign; or, with nsk and npk NULL, that it is revoked. reason is
 * NULL or up to 255 bytes of text. Both algorithms must be post-quantum
 * (NQENOSUP for Ed25519 alone); each signature is checked before the
 * statement is written (NQEARG when a pair does not match). */
NQAPI int nqkstmt(nqsalg alg, const uint8_t *sk, size_t sklen,
                  const uint8_t *pk, size_t pklen, nqsalg nalg,
                  const uint8_t *nsk, size_t nsklen, const uint8_t *npk,
                  size_t npklen, int64_t at, const char *reason, char *out,
                  size_t cap, size_t *outlen);
/* A key statement of the kind "expire": the holder of the key pair (sk,
 * pk) of alg says that the key seals until at and not after. Until then
 * a check with the statement accepts its seals as it does without one;
 * from then on (by the system clock: SOURCE_DATE_EPOCH, which sets only
 * the times noqtis writes, does not change it) it accepts only a seal
 * with a verified timestamp from before at, as for a key revoked at at.
 * The limits and results are nqkstmt's. */
NQAPI int nqkexp(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, int64_t at,
                 const char *reason, char *out, size_t cap, size_t *outlen);
/* Identity cards (noqtis-idcard-1): a signing key's holder says who they
 * are, in canonical JSON signed by the key itself under the context
 * "noqtis-idcard-1", so that a card is never taken for a seal or a key
 * statement, nor they for a card. The limits of its fields, in bytes: */
#define NQCARDPK 2624   /* a public key (ML-DSA-87+Ed25519, the largest) */
#define NQCARDEMAIL 254 /* an e-mail address */
#define NQCARDURL 1024  /* a web page */
#define NQCARDMAX ((size_t)256 << 10) /* a whole card nqcardvrfy reads */
/* A card that verified: its key (the algorithm, the public key and the
 * SHA-256 of it, as nqinsp's info.key writes it in hex), when it was made
 * and the fields it holds, NUL-terminated ("" for a field it has not). */
typedef struct {
  nqsalg alg;
  uint8_t pk[NQCARDPK];
  size_t pklen;
  uint8_t fp[32];
  int64_t created; /* seconds since 1970, UTC */
  char utc[21];    /* the same, as the card writes it */
  char name[256];
  char orcid[20];
  char email[NQCARDEMAIL + 1];
  char url[NQCARDURL + 1];
  char affil[256];
} nqcardf;
/* An identity card for the key pair (sk, pk) of alg, made at created
 * (seconds since 1970, UTC), to out (cap bytes; *outlen gets the size,
 * also with NQEBUF). name is required: 1 to 255 bytes of UTF-8 text, no
 * control character, no space at either end; affil likewise, or NULL.
 * orcid is NULL or an ORCID iD (0000-0002-1825-0097, or its
 * https://orcid.org/ address), its ISO 7064 MOD 11-2 check digit right;
 * the card holds the bare iD. email is NULL or local@domain.tld, url NULL
 * or an https:// address, neither with a space. NQEARG for a field out of
 * these limits, or when sk and pk are not one pair (the signature is
 * checked before the card is written); NQENOSUP for Ed25519 alone. */
NQAPI int nqcard(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, const char *name,
                 const char *orcid, const char *email, const char *url,
                 const char *affil, int64_t created, char *out, size_t cap,
                 size_t *outlen);
/* Checks the card of n bytes: NQOK when it is a noqtis-idcard-1 card in
 * canonical form whose fields are within nqcard's limits and whose
 * signature verifies under the key it carries, and, when pk is not NULL,
 * that key is pk (pklen bytes). *f then gets the card's fields; it is
 * zeroed on any other result. NQEVRFY when the signature does not verify
 * or the key is not pk, NQEDEC when it is not such a card, NQELIM over
 * NQCARDMAX bytes. */
NQAPI int nqcardvrfy(const char *card, size_t n, const uint8_t *pk,
                     size_t pklen, nqcardf *f);
/* A DSSE envelope (the in-toto and SLSA signing wrapper) of n payload
 * bytes of type (1 to 255 printable ASCII bytes, no quote or backslash),
 * signed by the key pair (sk, pk) of alg over PAE(type, payload), to out
 * (cap bytes; *outlen gets the size, also with NQEBUF), as canonical
 * JSON {"payload","payloadType","signatures":[{"keyid","sig"}]}; keyid
 * is the hex SHA-256 of pk. The signature is checked before the envelope
 * is written (NQEARG when the pair does not match). */
NQAPI int nqdsse(nqsalg alg, const uint8_t *sk, size_t sklen,
                 const uint8_t *pk, size_t pklen, const char *type,
                 const uint8_t *payload, size_t n, char *out, size_t cap,
                 size_t *outlen);
/* Checks the DSSE envelope env (n bytes): NQOK when one of its signatures
 * verifies under pk over PAE(payloadType, payload); the payload then goes
 * to payload (cap bytes; *outlen its size, also with NQEBUF) and, when
 * type is not NULL, the payloadType to type. NQEVRFY when none verifies,
 * NQEDEC when it is not an envelope. */
NQAPI int nqdssevrfy(nqsalg alg, const uint8_t *pk, size_t pklen,
                     const char *env, size_t n, uint8_t *payload, size_t cap,
                     size_t *outlen, char type[256]);
/* nqchkt with the options of o (NULL: none). */
NQAPI int nqchkx(const char *dir, const nqcopt *o, nqrep **rep);
/* A proof that the files paths[0..np) are in the format 2 (noqtis-proof-1)
 * or format 3 (noqtis-proof-2) capsule in dir: the seal, the manifest's
 * head (its Merkle root and leaf count) and, per file, its entry and audit
 * path, so that nqchkp can check those files and learns none of the
 * others' names, sizes or digests. For format 2 the hashes on the paths
 * are of unsalted leaves, so a guess of another file can be confirmed;
 * for format 3 it cannot (noqtis-capsule(5)).
 * Written to out (cap bytes); *outlen gets the size, also with NQEBUF
 * when cap is too small. NQENOSUP for a format 1 capsule, NQEIO for a
 * path the manifest does not list. Check the capsule (nqchk) first. */
NQAPI int nqprove(const char *dir, const char *const *paths, size_t np,
                  char *out, size_t cap, size_t *outlen);
/* Checks a proof of n bytes: the seal and its signature over the head
 * (with o's trusted key and TSA anchors; its other members are not used),
 * and each entry's audit path to the head's root ("proof.entry" rows);
 * with dir (or NULL), each proven file there against its entry. */
NQAPI int nqchkp(const char *proof, size_t n, const nqcopt *o,
                 const char *dir, nqrep **rep);
/* What the capsule in dir says, read with nqchk's strict readers but with
 * nothing checked: no digest, signature, timestamp or file. NQOK when the
 * seal and the manifest parse: the report then ends with info.format,
 * info.alg, info.key (the SHA-256 of the seal's public key, hex),
 * info.created, info.files, info.bytes, info.timestamp ("present" or
 * "none") and, when the manifest has one, info.meta (canonical JSON).
 * NQEDEC when one does not parse (*rep holds the failing rows); NQEARG and
 * NQEMEM return no report. Free it with nqrepfree. */
NQAPI int nqinsp(const char *dir, nqrep **rep);
/* nqinsp, and before the info rows one "info.file" row per listed file,
 * in manifest order: its size in bytes, its SHA-256 (64 hex digits) and
 * its path (normal form, '/' separated), with a space between. The paths pass the checker's path rules; nothing
 * is checked against a folder or the signature, so a caller fetching
 * the files (noqtis check <url>) checks the capsule after. */
NQAPI int nqfiles(const char *dir, nqrep **rep);
NQAPI size_t nqrepn(const nqrep *r);
NQAPI int nqrepi(const nqrep *r, size_t i, const char **check, int *ok,
                 const char **detail);
NQAPI void nqrepfree(nqrep *r);

/* RFC 3161 timestamps for a sealed capsule. The library makes no network
 * request: the caller sends the request to a TSA and passes back its
 * reply. nqtsreq writes the TimeStampReq for the seal in dir (the SHA-256
 * imprint of the seal's decoded signature, the nonce when not NULL: at
 * most 32 bytes, big-endian, and certReq TRUE) to req of reqlen bytes; at
 * most 128 bytes, *outlen gets the size. */
NQAPI int nqtsreq(const char *dir, const uint8_t *nonce, size_t noncelen,
                  uint8_t *req, size_t reqlen, size_t *outlen);
/* Stores the token in rsp (a TimeStampResp, or a bare token) as the
 * timestamp of dir's noqtis.sig, replacing any it has, once it checks:
 * granted, its imprint the hash of the seal's signature, its nonce the
 * given one (when not NULL), and its signature valid under its TSA
 * certificate at genTime; with nanc anchors (DER, at most 32), that
 * certificate must also have a path to one of them. Without anchors the
 * TSA is not trusted, only its reply checked: trust is nqchkt's job.
 * *gt (when not NULL) gets genTime, in seconds since the epoch; *why
 * (when not NULL) a sentence on what failed, or NULL. NQEVRFY when the
 * reply does not check; nothing is written then. */
NQAPI int nqtsput(const char *dir, const uint8_t *rsp, size_t rsplen,
                  const uint8_t *nonce, size_t noncelen,
                  const uint8_t *const *anc, const size_t *anclen,
                  size_t nanc, int64_t *gt, const char **why);
/* RFC 4998 evidence records: noqtis.ers beside the seal, whose data
 * object is noqtis.sig byte for byte, kept provable for as long as its
 * archive timestamps are renewed: before the last TSA certificate
 * expires (timestamp renewal, h the record's hash) or its hash weakens
 * (hash-tree renewal, a new h). As with nqtsreq, the library makes no
 * network request. nqersreq writes the TimeStampReq for the next
 * archive timestamp with hash h (NQS256, NQS384 or NQS512; 0 for the
 * record's last one, or SHA-256 for a first) to req (128 bytes are
 * enough). nqersput checks the reply as nqtsput does, and with it the
 * record already there (each token under the nanc anchors, at most 32,
 * on paths valid at its genTime and the next one's, the last now; with
 * no anchors, each token alone), and writes the record with the new
 * archive timestamp: *how (when not NULL) is 0 for a new record, 1 for
 * a timestamp renewal and 2 for a hash-tree renewal, *gt its genTime.
 * NQEVRFY when the reply or the record there does not check; nothing
 * is written then. While a record is there, nqtsput and nqseal refuse
 * (NQESTATE): either would change the seal it proves. nqchkt and nqchkx
 * check the record under their TSA anchors ("ers" row). */
NQAPI int nqersreq(const char *dir, nqhalg h, const uint8_t *nonce,
                   size_t noncelen, uint8_t *req, size_t reqlen,
                   size_t *outlen, const char **why);
NQAPI int nqersput(const char *dir, nqhalg h, const uint8_t *rsp,
                   size_t rsplen, const uint8_t *nonce, size_t noncelen,
                   const uint8_t *const *anc, const size_t *anclen,
                   size_t nanc, int64_t *gt, int *how, const char **why);

/* ---- a key store ---------------------------------------------------- */

/* A key store is a folder of other people's public keys: for each, who
 * its holder is said to be (a name and an e-mail address, from its
 * identity card when it has one), the certifications other keys made of
 * that, and how far the owner of the store trusts the key's holder to
 * certify (NQKT...). From these a key's validity follows (NQKV...): a
 * key is fully valid when its trust is NQKTULT (the owner's own keys),
 * or when one fully valid key of trust NQKTFULL certified it, or three
 * of trust NQKTMARG; one or two marginal ones make it marginally valid.
 * Certifications are followed five levels from an NQKTULT key, and only
 * signature keys certify. A key is named by its fingerprint, the
 * SHA-256 of the public key.
 *
 * The folder must exist. It is the owner's own state: a card, a
 * certification and a key's fingerprint are checked when they are put
 * in, and whoever can write the folder decides what it trusts. A key's
 * file there (<64 hex digits>.pub) is a key file as noqtis keygen
 * writes one.
 *
 * nqksadd puts in the key pk of alg (an nqkalg when kem is 1, else an
 * nqsalg): with a card (of cardlen bytes, a signature key's, verified
 * and naming this key; name and email NULL) or with a name (1 to 255
 * bytes, as nqcard takes one) and an e-mail address or NULL. A key
 * that is there keeps its trust; its name becomes the new one, and a
 * certification of the old name no longer counts. fp, when not NULL,
 * gets the fingerprint.
 *
 * nqkslist gives the entries, in the order of their fingerprints, that
 * answer q: all with q NULL, else those whose fingerprint in hex starts
 * with q (8 digits or more) or whose name, address or algorithm name
 * ("ML-KEM-768") holds q, ASCII letters of either case alike. *n gets their number, also with NQEBUF
 * when e (cap entries) holds fewer. nqksget gives one key.
 *
 * nqkscert certifies the key fp of the store with the key pair (sk, pk)
 * of alg at time at (seconds since 1970, UTC): a noqtis-cert-1
 * statement, canonical JSON signed under the context "noqtis-cert-1",
 * that fp belongs to the name and address the store has for it. It is
 * kept in the store and, when out is not NULL, given out (*outlen its
 * size, also with NQEBUF). nqkscput puts in a certification made
 * elsewhere: the key it is about and the key that made it must be in
 * the store, the first under the name and address it says, and its
 * signature must verify. nqkstrust sets a key's trust, nqksdel removes
 * a key with its card and every certification of it and by it.
 *
 * Errors: NQEARG for a NULL pointer, a name or address out of nqcard's
 * limits, a key of the wrong length, a level that is not one, or a key
 * pair that does not match; NQENOSUP for an algorithm this noqtis does
 * not know, and for Ed25519 alone as the certifying key; NQEIO when the
 * folder or a key's files cannot be read or written (a key that is not
 * there among them); NQEDEC for a file of the store, a card or a
 * certification that is not one; NQEVRFY for a card or certification
 * whose signature does not verify, or that names another key, name or
 * address; NQEBUF, NQELIM, NQEMEM. */
#define NQKTUNK 0   /* trust: not said */
#define NQKTNEVER 1 /* never trusted to certify */
#define NQKTMARG 2  /* marginally */
#define NQKTFULL 3  /* fully */
#define NQKTULT 4   /* ultimately: the owner's own key */
#define NQKVNONE 0  /* validity: not known to belong to its name */
#define NQKVMARG 1  /* marginally valid */
#define NQKVFULL 2  /* fully valid */
typedef struct {
  int kem;         /* 1: a KEM key (alg an nqkalg), 0: a signature key */
  int alg;
  uint8_t fp[32];
  size_t pklen;
  char name[256];
  char email[255]; /* "" when it has none */
  int card;        /* 1 when the store holds its identity card */
  int trust;       /* NQKT... */
  int valid;       /* NQKV... */
  size_t ncert;    /* certifications of it under its present name */
} nqkse;
NQAPI int nqksadd(const char *dir, int kem, int alg, const uint8_t *pk,
                  size_t pklen, const char *name, const char *email,
                  const char *card, size_t cardlen, uint8_t fp[32]);
NQAPI int nqkslist(const char *dir, const char *q, nqkse *e, size_t cap,
                   size_t *n);
NQAPI int nqksget(const char *dir, const uint8_t fp[32], int *kem, int *alg,
                  uint8_t *pk, size_t cap, size_t *pklen);
NQAPI int nqkscert(const char *dir, nqsalg alg, const uint8_t *sk,
                   size_t sklen, const uint8_t *pk, size_t pklen,
                   const uint8_t fp[32], int64_t at, char *out, size_t cap,
                   size_t *outlen);
NQAPI int nqkscput(const char *dir, const char *cert, size_t n);
NQAPI int nqkstrust(const char *dir, const uint8_t fp[32], int level);
NQAPI int nqksdel(const char *dir, const uint8_t fp[32]);
/* Publishing a key, and finding one by its holder's address. A bundle
 * is text: the identity card of a signature key, then every other key
 * of the store that this key certified under its own name and address
 * (a KEM key to seal to its holder, a second signature key), each with
 * that certification; armored (nqarmenc) as NOQTIS IDENTITY CARD,
 * NOQTIS PUBLIC KEY (a key file) and NOQTIS CERTIFICATION.
 *
 * nqksexp writes the bundle of the key fp, which must have its card in
 * the store (NQEARG for one without, or a KEM key). nqksimp reads one,
 * of at most 1 MiB: the card must verify, every key after it must come
 * with a certification by the card's key that verifies and says the
 * card's name and address, and all of them go into the store; fp gets
 * the card key's fingerprint, *nkeys the number of keys put in (also
 * on an error, for those before it). With email not NULL the card must
 * be for that address (ASCII letters of either case alike), else
 * NQEVRFY: the bundle is not the answer to a lookup of that address.
 * Nothing a bundle brings is trusted or valid for that alone.
 *
 * nqksurl gives the address a bundle is published at for an e-mail
 * address, NUL-terminated: https://<domain>/.well-known/noqtis/<40 hex
 * digits>, the first 20 bytes of the SHA-256 of the part before the @
 * in lower case. NQEARG for what is not an address, or whose domain
 * has other characters than letters, digits, dots and hyphens. Fetching
 * it is the caller's: the library does not open connections here. */
NQAPI int nqksexp(const char *dir, const uint8_t fp[32], char *out,
                  size_t cap, size_t *outlen);
NQAPI int nqksimp(const char *dir, const char *bundle, size_t n,
                  const char *email, uint8_t fp[32], size_t *nkeys);
NQAPI int nqksurl(const char *email, char *url, size_t cap);

/* ---- ASCII armor ---------------------------------------------------- */

/* Bytes as text that mail and a terminal carry (RFC 7468): a line
 * -----BEGIN <label>-----, the bytes in base64 (RFC 4648 section 4) in
 * lines of 64 characters, a line -----END <label>-----. A label is 1 to
 * NQARMLAB - 1 capitals and digits with single spaces between them
 * ("NOQTIS SIGNATURE"). There are no headers and no checksum.
 *
 * nqarmlen gives the number of characters nqarmenc writes for n bytes;
 * nqarmenc writes them (no NUL after them). nqarmdec reads one armor:
 * space and line ends (LF or CRLF) may come before it, after it and
 * between the base64 characters, nothing else may; the END label must
 * be the BEGIN label. It writes the label, with a NUL, to label when
 * lcap is not 0, and the bytes to out, which never needs more than
 * three bytes for every four characters of in.
 *
 * The base64 here is not constant time: armor what is public (a
 * signature, a sealed stream, a public key), never a secret key.
 *
 * Errors: NQEARG for a NULL pointer or a label that is not one; NQEBUF
 * for an output, or a label buffer, that is too small; NQELIM for an n
 * whose text has no size_t length; NQEDEC for text that is not one
 * armor as described. */
#define NQARMLAB 64u
NQAPI int nqarmlen(const char *label, size_t n, size_t *len);
NQAPI int nqarmenc(const char *label, const uint8_t *in, size_t n,
                   char *out, size_t cap, size_t *outlen);
NQAPI int nqarmdec(const char *in, size_t n, char *label, size_t lcap,
                   uint8_t *out, size_t cap, size_t *outlen);

/* ---- certificates and CMS (S/MIME) ---------------------------------- */

/* X.509 certificates for noqtis keys (RFC 5280), in DER.
 *
 * nqx5self makes a self-signed certificate for the signature key pair
 * (sk, pk) of alg: ML-DSA (RFC 9881), SLH-DSA (RFC 9909) or Ed25519
 * (RFC 8410); NQENOSUP for the hybrids, which have no standard
 * encoding. Its subject is the common name cn (as nqcard takes a name)
 * with, when email is not NULL, that address as the rfc822Name of its
 * subjectAltName. It is valid from nb to na (seconds since 1970, UTC),
 * signs mail (digitalSignature, nonRepudiation, the e-mail protection
 * purpose) and is a CA of path length 0, so that it can issue the
 * second kind. Its holder gives it to those who are to trust the key:
 * a certificate nobody else signed proves nothing by itself.
 *
 * nqx5kem makes a certificate for the ML-KEM public key pk of alg (RFC
 * 9935; key usage keyEncipherment), issued by the holder of the
 * certificate icert with its secret key isk of ialg, under icert's
 * name and address: the certificate others encrypt to.
 *
 * nqx5info reads a certificate: who it names, its key, its validity.
 *
 * out holds cap bytes; *outlen gets the size, also with NQEBUF. NQEARG
 * for a NULL pointer, a name or address nqcard would refuse, a key of
 * the wrong length, na not after nb, a key pair or issuer that does
 * not match; NQEDEC for a certificate that is not one. */
typedef struct {
  int kem;          /* 1: an ML-KEM key (alg an nqkalg) */
  int alg;          /* nqsalg or nqkalg; 0 for a key of another kind */
  uint8_t fp[32];   /* SHA-256 of the certificate */
  int64_t nb, na;   /* valid from, to (seconds since 1970) */
  int ca;
  char name[256];   /* the subject's common name, "" when none */
  char email[255];  /* its first rfc822Name, "" when none */
  size_t pkoff;     /* the public key: its place in the certificate, */
  size_t pklen;     /* and its length */
} nqx5f;
NQAPI int nqx5self(nqsalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *pk, size_t pklen, const char *cn,
                   const char *email, int64_t nb, int64_t na, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqx5kem(nqsalg ialg, const uint8_t *isk, size_t isklen,
                  const uint8_t *icert, size_t icertlen, nqkalg alg,
                  const uint8_t *pk, size_t pklen, int64_t nb, int64_t na,
                  uint8_t *out, size_t cap, size_t *outlen);
NQAPI int nqx5info(const uint8_t *cert, size_t n, nqx5f *f);

/* The Cryptographic Message Syntax (RFC 5652), in DER.
 *
 * nqcmssign signs the n bytes at msg with the secret key sk of alg,
 * whose certificate is cert, at the time at: a SignedData of one
 * signer, with the signed attributes content type, signing time and
 * message digest, the signature over them (RFC 9882 for ML-DSA, RFC
 * 9814 for SLH-DSA, RFC 8419 for Ed25519) and the certificate inside;
 * the content inside too, or left out when detached is not 0.
 *
 * nqcmsvrfy checks a SignedData of one signer: the digest of the
 * content, the signed attributes, the signature under the signer's
 * certificate, and that certificate against the nanc trust anchors
 * (certificates in DER): it is one of them, or chains to one through
 * the certificates the message carries. The content is the one inside,
 * or msg for a detached signature (given both, they must be equal).
 * The certificates must hold at the time at, or with at 0 at the
 * signing time the message states, else now. On NQOK the content is
 * copied to out (when not NULL; *outlen its size) and *signer, when
 * not NULL, says who signed. Signatures by RSA and ECDSA certificates
 * verify as well. NQEVRFY when anything does not check out.
 *
 * nqcmsenc encrypts msg to the nr recipients whose ML-KEM certificates
 * are given: an AuthEnvelopedData (RFC 5083) under AES-256-GCM (RFC
 * 5084), the content key carried to each in a KEMRecipientInfo (RFC
 * 9629, RFC 9936: ML-KEM, HKDF with SHA-256, AES Key Wrap). nqcmsdec
 * opens one with the ML-KEM secret key sk of alg; cert, when not NULL,
 * is that key's certificate and picks its recipient entry, else every
 * entry of that algorithm is tried. NQEVRFY when no entry opens with
 * the key or the content does not authenticate.
 *
 * NQEARG, NQEBUF and NQEDEC as above; NQELIM over 1 GiB; NQENOSUP for
 * an algorithm these functions do not take, or more than one signer. */
NQAPI int nqcmssign(nqsalg alg, const uint8_t *sk, size_t sklen,
                    const uint8_t *cert, size_t certlen, const uint8_t *msg,
                    size_t n, int detached, int64_t at, uint8_t *out,
                    size_t cap, size_t *outlen);
NQAPI int nqcmsvrfy(const uint8_t *cms, size_t n, const uint8_t *msg,
                    size_t mlen, const uint8_t *const *anc,
                    const size_t *anclen, size_t nanc, int64_t at,
                    uint8_t *out, size_t cap, size_t *outlen, nqx5f *signer);
NQAPI int nqcmsenc(const uint8_t *const *rcert, const size_t *rcertlen,
                   size_t nr, const uint8_t *msg, size_t n, uint8_t *out,
                   size_t cap, size_t *outlen);
NQAPI int nqcmsdec(nqkalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *cert, size_t certlen, const uint8_t *cms,
                   size_t n, uint8_t *out, size_t cap, size_t *outlen);

/* S/MIME (RFC 8551): the same as mail. The content is a MIME entity,
 * its header lines and its body (a text part: "Content-Type:
 * text/plain", an empty line, the text); its line ends are made CRLF
 * before it is signed or encrypted, as S/MIME requires.
 *
 * nqsmsign signs the entity: an application/pkcs7-mime entity of the
 * smime-type signed-data with the content inside or, when detached is
 * not 0, a multipart/signed entity whose first part is the content in
 * the clear and whose second is the signature (a mail reader without
 * S/MIME still shows the text). nqsmvrfy checks either form as
 * nqcmsvrfy does and gives the signed entity. nqsmenc encrypts the
 * entity to ML-KEM certificates (application/pkcs7-mime,
 * authEnveloped-data); nqsmdec opens it. To sign and encrypt, sign
 * first and encrypt the result.
 *
 * The results are text: the header fields MIME-Version, Content-Type,
 * Content-Transfer-Encoding and Content-Disposition, an empty line and
 * base64, with CRLF line ends. The errors are those of the CMS
 * functions; NQEDEC also for an entity that is not of these types. */
NQAPI int nqsmsign(nqsalg alg, const uint8_t *sk, size_t sklen,
                   const uint8_t *cert, size_t certlen, const char *entity,
                   size_t n, int detached, int64_t at, char *out, size_t cap,
                   size_t *outlen);
NQAPI int nqsmvrfy(const char *mime, size_t n, const uint8_t *const *anc,
                   const size_t *anclen, size_t nanc, int64_t at, char *out,
                   size_t cap, size_t *outlen, nqx5f *signer);
NQAPI int nqsmenc(const uint8_t *const *rcert, const size_t *rcertlen,
                  size_t nr, const char *entity, size_t n, char *out,
                  size_t cap, size_t *outlen);
NQAPI int nqsmdec(nqkalg alg, const uint8_t *sk, size_t sklen,
                  const uint8_t *cert, size_t certlen, const char *mime,
                  size_t n, char *out, size_t cap, size_t *outlen);

/* ---- OpenPGP -------------------------------------------------------- */

/* OpenPGP (RFC 9580), version 6, with the algorithms noqtis has, named
 * by their OpenPGP numbers: Ed25519 (NQPGPED25519) and X25519
 * (NQPGPX25519) of the RFC, and those of RFC 9980:
 * ML-DSA-65+Ed25519, ML-KEM-768+X25519, and SLH-DSA-SHAKE-128s, -128f
 * and -256s. Keys, signatures and messages are packets in binary;
 * nqpgparm and nqpgpdearm turn them into ASCII armor and back, and
 * nqpgpvrfy and nqpgpdec take either.
 *
 * Not here: version 3 and 4 keys and signatures, RSA, DSA, Elgamal and
 * the NIST and Brainpool curves, CFB encryption and compressed data.
 * Those give NQENOSUP.
 *
 * nqpgpgen makes a key: a primary key of sigalg that certifies and
 * signs, the user ID uid (1 to 255 bytes of UTF-8, by convention
 * "Name <address>"), and, when encalg is not 0, an encryption subkey
 * of encalg, with their self-signatures, at the time created (seconds
 * since 1970). sec gets the transferable secret key, under the
 * passphrase pw when that is not NULL (Argon2id, AES-256 with OCB);
 * pub the certificate to give to others. A post-quantum OpenPGP key
 * holds its seeds, so it is made here: it cannot be made of a key file
 * that noqtis keygen wrote.
 *
 * nqpgpinfo reads a certificate or a secret key: its algorithms,
 * fingerprints (SHA-256 of the key packet), user ID and times. Only
 * what a self-signature of the primary key binds is taken; NQEVRFY for
 * a key with no such signature or a revoked one.
 *
 * nqpgpsign signs msg with the secret key (pw its passphrase, or
 * NULL): mode NQPGPINLINE a signed message that carries the data,
 * NQPGPDETACHED a signature alone, NQPGPCLEAR the text with the armored
 * signature under it (msg must be UTF-8 text). nqpgpvrfy checks one
 * of the three under the certificate cert: msg is what a detached
 * signature signs (NULL otherwise); the data comes back in out, and
 * *at gets the signature's time. The at of nqpgpsign and nqpgpenc is
 * the time written into the signature or message; whether a key given
 * to them has expired is judged by the system clock. nqpgpvrfy and
 * nqpgpdec judge the signer's key at the time its signature states.
 *
 * nqpgpenc encrypts msg to the encryption subkeys of nc certificates
 * (at most 64) and, with pw not NULL, to that passphrase as well
 * (certs may then be none): AES-256 with OCB, in chunks. With signer
 * (a secret key, spw its passphrase) the message is signed first.
 * nqpgpdec opens one with the secret key (pw its passphrase), or with
 * key NULL with the passphrase pw of the message. With signer (a
 * certificate) the message inside must be signed by it, and *signedby
 * is 1; without, the content is given whatever signs it.
 *
 * out NULL asks for the size alone where the function can tell it
 * (nqpgparm); elsewhere *outlen gets the size with NQEBUF. NQEVRFY
 * when a signature, a key or a message does not check out; NQEARG also
 * for a key that cannot do what is asked (no secret part, no
 * encryption subkey, a passphrase missing); NQEDEC for what is not
 * OpenPGP; NQELIM over 1 GiB, and for a key file that asks Argon2id for
 * more than 4 GiB or 16 passes. */
#define NQPGPX25519 25
#define NQPGPED25519 27
#define NQPGPMLDSA65 30   /* ML-DSA-65+Ed25519 */
#define NQPGPSLH128S 32   /* SLH-DSA-SHAKE-128s */
#define NQPGPSLH128F 33
#define NQPGPSLH256S 34
#define NQPGPMLKEM768 35  /* ML-KEM-768+X25519 */
#define NQPGPINLINE 0
#define NQPGPDETACHED 1
#define NQPGPCLEAR 2
#define NQPGPMSG 1  /* armor: PGP MESSAGE */
#define NQPGPPUB 2  /* PGP PUBLIC KEY BLOCK */
#define NQPGPSEC 3  /* PGP PRIVATE KEY BLOCK */
#define NQPGPSIG 4  /* PGP SIGNATURE */
typedef struct {
  int alg;          /* the primary key's algorithm */
  int encalg;       /* the encryption subkey's, 0 when it has none */
  int secret;       /* 1 for a secret key */
  int locked;       /* 1 when it is under a passphrase */
  uint8_t fp[32];   /* fingerprints: the primary key's, the subkey's */
  uint8_t encfp[32];
  int64_t created;  /* seconds since 1970 */
  int64_t expires;  /* 0: never */
  char uid[256];    /* the user ID, "" when it has none it could show */
} nqpgpk;
NQAPI int nqpgpgen(int sigalg, int encalg, const char *uid, int64_t created,
                   const uint8_t *pw, size_t pwlen, uint8_t *sec, size_t scap,
                   size_t *slen, uint8_t *pub, size_t pcap, size_t *plen);
NQAPI int nqpgpinfo(const uint8_t *key, size_t n, nqpgpk *o);
NQAPI int nqpgpsign(const uint8_t *key, size_t kn, const uint8_t *pw,
                    size_t pwlen, const uint8_t *msg, size_t n, int mode,
                    int64_t at, uint8_t *out, size_t cap, size_t *outlen);
NQAPI int nqpgpvrfy(const uint8_t *cert, size_t cn, const uint8_t *sig,
                    size_t sn, const uint8_t *msg, size_t mlen, uint8_t *out,
                    size_t cap, size_t *outlen, int64_t *at);
NQAPI int nqpgpenc(const uint8_t *const *certs, const size_t *certlens,
                   size_t nc, const uint8_t *pw, size_t pwlen,
                   const uint8_t *signer, size_t signerlen,
                   const uint8_t *spw, size_t spwlen, const uint8_t *msg,
                   size_t n, int64_t at, uint8_t *out, size_t cap,
                   size_t *outlen);
NQAPI int nqpgpdec(const uint8_t *key, size_t kn, const uint8_t *pw,
                   size_t pwlen, const uint8_t *signer, size_t signerlen,
                   const uint8_t *msg, size_t n, uint8_t *out, size_t cap,
                   size_t *outlen, int *signedby, int64_t *at);
NQAPI int nqpgparm(int kind, const uint8_t *in, size_t n, char *out,
                   size_t cap, size_t *outlen);
NQAPI int nqpgpdearm(const char *in, size_t n, int *kind, uint8_t *out,
                     size_t cap, size_t *outlen);

/* ---- keys on a token (PKCS #11) ------------------------------------- */

/* Signing and decapsulating with private keys that stay on a token: a
 * smart card, a hardware security module, or a software token. The
 * token's maker ships a PKCS #11 module, a shared library; nqp11open
 * loads the one at the path module (a path with a folder in it, never a
 * bare name the loader would search for) and starts it. The key types
 * are those of PKCS #11 version 3.2: ML-DSA, SLH-DSA and ML-KEM, and
 * Ed25519 of version 3.0.
 *
 * nqp11toks lists the tokens present. nqp11login opens a session with
 * the token in a slot and, with pin not NULL, logs the user in; one
 * session per handle. nqp11keys lists the private keys there that
 * noqtis can use; nqp11pub gives a key's public key, in the form the
 * rest of noqtis takes (for nqvrfy, nqenc and key files).
 *
 * nqp11sign signs msg with a signature key: the signature is what
 * nqsign makes with the same context, and nqvrfy checks it. (No
 * pre-hash variants, and no hybrid keys.) nqp11dec decapsulates an
 * ML-KEM ciphertext, as nqdec does; the token must be of version 3.2.
 * nqp11gen makes a key pair on the token under a label, never to leave
 * it.
 *
 * NQEIO when the module cannot be loaded or the token refuses (nqp11why
 * then gives the module's own return value, a CKR_ number of the
 * standard); NQEDEC for a library that is not a PKCS #11 module;
 * NQEVRFY for a wrong or locked PIN; NQENOSUP when the token has not
 * the mechanism, and on systems that load no shared libraries;
 * NQESTATE before nqp11login, or for a second one; NQEBUF with the
 * count or size in *n. A handle is for one thread at a time. */
typedef struct nqp11 nqp11;
typedef struct {
  unsigned long slot;
  char label[33];
  char maker[33];
  char model[17];
  char serial[17];
  int login;         /* 1 when its keys need the PIN */
} nqp11t;
typedef struct {
  int kem;           /* 1: alg is a nqkalg; 0: a nqsalg */
  int alg;
  unsigned long h;   /* the object, in this session */
  char label[65];
  uint8_t id[32];
  size_t idlen;
} nqp11k;
NQAPI int nqp11open(const char *module, nqp11 **p);
NQAPI void nqp11close(nqp11 *p);
NQAPI unsigned long nqp11why(const nqp11 *p);
NQAPI int nqp11toks(nqp11 *p, nqp11t *t, size_t cap, size_t *n);
NQAPI int nqp11login(nqp11 *p, unsigned long slot, const char *pin,
                     size_t pinlen);
NQAPI int nqp11keys(nqp11 *p, nqp11k *k, size_t cap, size_t *n);
NQAPI int nqp11pub(nqp11 *p, const nqp11k *k, uint8_t *pk, size_t cap,
                   size_t *pklen);
NQAPI int nqp11sign(nqp11 *p, const nqp11k *k, const uint8_t *msg, size_t n,
                    const uint8_t *ctx, size_t ctxlen, uint8_t *sig,
                    size_t cap, size_t *siglen);
NQAPI int nqp11dec(nqp11 *p, const nqp11k *k, const uint8_t *ct,
                   size_t ctlen, uint8_t *ss, size_t sslen);
NQAPI int nqp11gen(nqp11 *p, int kem, int alg, const char *label,
                   nqp11k *k);
/* Seals dir as nqseal (fmt 1), nqseal2 (fmt 2) or nqseal3 with fresh
 * salts (fmt 3) does (in and nin as there, and they must be NULL and 0
 * for fmt 1), with the signature key k
 * of the token: the key never leaves it, and the public key written to
 * the seal is the token's own (nqp11pub). The signature is checked
 * before anything is written. The returns of nqseal and of nqp11sign;
 * NQEARG also for a KEM key, NQENOSUP for an Ed25519 key (alone it is
 * never a seal). */
NQAPI int nqp11seal(nqp11 *p, const nqp11k *k, const char *dir, int fmt,
                    const char *meta, const nqcin *in, size_t nin);

/* ---- TLS 1.3 client ------------------------------------------------- */

/* A TLS 1.3 client (RFC 8446): X25519MLKEM768 and X25519 key shares
 * (P-256 and P-384 when the server asks for them), the AES-GCM and
 * ChaCha20-Poly1305 suites, and the server's certificate path (with name
 * constraints) and host name checked against the caller's trust
 * anchors, a stapled OCSP response checked (must-staple honoured), and,
 * with nqtlct, Certificate Transparency, so noqtis can fetch over HTTPS
 * with no other library. The
 * library opens no connection: the caller connects a socket and passes
 * two callbacks that move bytes. No TLS 1.2, PSK, 0-RTT or client
 * certificates. Built without the CMake option NQTLS, every nqtl
 * function returns NQENOSUP. See nqtlnew(3). */
typedef struct nqtls nqtls;

/* wr sends all n bytes (NQOK, or NQEIO); rd reads 1 to cap bytes into b
 * and sets *got, 0 at the end of the stream (NQOK, or NQEIO). */
typedef struct {
  int (*wr)(void *user, const uint8_t *b, size_t n);
  int (*rd)(void *user, uint8_t *b, size_t cap, size_t *got);
  void *user;
} nqtlio;

/* A client for host (a DNS name, sent as SNI and matched against the
 * certificate, or an IPv4 / IPv6 literal matched against its
 * addresses) that trusts the certificates in ca (a PEM bundle or one
 * DER certificate of calen bytes, copied). NQEDEC when ca holds no
 * certificate noqtis can read, NQEARG for a host name it will not
 * send. */
NQAPI int nqtlnew(nqtls **t, const char *host, const uint8_t *ca,
                  size_t calen, const nqtlio *io);
/* Turns on Certificate Transparency for t, before nqtlhs: json (len
 * bytes, copied) is a log list in the form of Chrome's log_list.json,
 * version 3. The handshake then needs SCTs, embedded in the server's
 * certificate or sent in TLS, that verify and come from logs of at
 * least two operators, usable when they signed. Off by default: a log
 * list goes stale, so keep it current. NQEDEC for a list that does not
 * parse, holds no log or a log whose log_id is not its key's hash;
 * NQESTATE once the handshake has begun. */
NQAPI int nqtlct(nqtls *t, const uint8_t *json, size_t len);
/* The handshake. NQEVRFY for a certificate, signature or MAC that does
 * not check out, NQEDEC for a message TLS 1.3 does not allow here,
 * NQENOSUP for a server that offers nothing noqtis speaks, NQEIO for
 * the transport. Every error is final: the alert is sent, nqtlwhy says
 * what failed, and every later call returns the same code. */
NQAPI int nqtlhs(nqtls *t);
/* Sends n bytes of application data. */
NQAPI int nqtlwr(nqtls *t, const uint8_t *b, size_t n);
/* Reads 1 to cap bytes of application data into b, or *got 0 after the
 * server's close_notify. A stream that ends without close_notify is
 * NQEIO (it may have been cut short). */
NQAPI int nqtlrd(nqtls *t, uint8_t *b, size_t cap, size_t *got);
/* Sends close_notify; nothing more can be written. */
NQAPI int nqtlend(nqtls *t);
/* A sentence on the first error, "" when there is none. */
NQAPI const char *nqtlwhy(const nqtls *t);
/* Wipes and frees t; NULL is fine. */
NQAPI void nqtlfree(nqtls *t);

#ifdef __cplusplus
}
#endif

#endif /* NOQTIS_H */
