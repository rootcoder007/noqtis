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
#define NQVPAT 1

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
/* rnd is the standard's per-signature randomness (32 bytes for ML-DSA
 * and the hybrids, n bytes for SLH-DSA, none for Ed25519, which is
 * deterministic: rnd may then be NULL with rndlen 0); all zero gives the
 * deterministic variant. */
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
 * NQOK, as the standards require. It fails on malformed sizes (NQEARG,
 * NQEBUF), on a secret key whose embedded hash does not match (NQEDEC),
 * and, since ML-KEM decapsulation is masked with fresh randomness, when
 * the operating system's random source fails (NQERNG). */
NQAPI int nqdec(nqkalg alg, const uint8_t *sk, size_t sklen,
                const uint8_t *ct, size_t ctlen, uint8_t *ss, size_t sslen);

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
/* An input of a capsule: the input capsule's id (nqcapid) and a short
 * name for it (1 to 255 bytes of UTF-8, no control character). */
typedef struct {
  uint8_t id[32];
  const char *name;
} nqcin;
/* nqseal in format 2 (noqtis-capsule-2, noqtis-seal-2): the manifest also
 * carries a Merkle tree over its entries, so that nqprove can show single
 * files without the rest, and the nin capsules it was made from (at most
 * 1024; in may be NULL when nin is 0). The seal signs the manifest's head
 * (everything but the list of files). */
NQAPI int nqseal2(const char *dir, nqsalg alg, const uint8_t *sk,
                  size_t sklen, const uint8_t *pk, size_t pklen,
                  const char *meta, const nqcin *in, size_t nin);
/* The id of the capsule in dir: the SHA-256 of the bytes its seal signs
 * (manifest_sha256 of a format 1 seal, head_sha256 of a format 2 one),
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
   * key was rotated away or revoked */
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
/* A proof (noqtis-proof-1) that the files paths[0..np) are in the format 2
 * capsule in dir: the seal, the manifest's head (its Merkle root and leaf
 * count) and, per file, its entry and audit path, so that nqchkp can
 * check those files and learns nothing of the others' names or digests.
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

/* ---- TLS 1.3 client ------------------------------------------------- */

/* A TLS 1.3 client (RFC 8446): X25519MLKEM768 and X25519 key shares,
 * the AES-GCM and ChaCha20-Poly1305 suites, and the server's
 * certificate path and host name checked against the caller's trust
 * anchors, so noqtis can fetch over HTTPS with no other library. The
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
