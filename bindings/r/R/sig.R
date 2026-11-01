#' Algorithms and their sizes
#'
#' Lists every signature and key encapsulation algorithm the bundled
#' library provides, with the sizes in bytes of its keys, signatures,
#' ciphertexts and shared secrets.
#'
#' The signature algorithms are ML-DSA-44, 65 and 87 (FIPS 204, security
#' categories 2, 3 and 5); the twelve SLH-DSA parameter sets (FIPS 205),
#' `SLH-DSA-SHA2-` and `SLH-DSA-SHAKE-` followed by `128`, `192` or `256`
#' (the security category: 1, 3 or 5) and `s` (small signatures, slow
#' signing) or `f` (fast signing, larger signatures); Ed25519 (RFC 8032,
#' not post-quantum); and the hybrids ML-DSA-44+Ed25519,
#' ML-DSA-65+Ed25519 and ML-DSA-87+Ed25519, whose signature verifies only
#' when both halves do. The key encapsulation mechanisms are ML-KEM-512,
#' 768 and 1024 (FIPS 203) and HQC-128, 192 and 256.
#'
#' @return A data frame with one row per algorithm and the columns `name`,
#'   `type` (`"sig"` or `"kem"`), `pk`, `sk`, `sig`, `ct` and `ss` (sizes
#'   in bytes; `NA` where they do not apply) and `id` (the library's
#'   number for the algorithm).
#'
#' @family library functions
#'
#' @examples
#' a <- nqalgs()
#' a[a$type == "sig", c("name", "pk", "sk", "sig")]
#' a[a$type == "kem", c("name", "pk", "sk", "ct", "ss")]
#' @export
nqalgs <- function() .tab()

#' Generate a key pair
#'
#' Generates a signature key pair (ML-DSA, SLH-DSA, Ed25519, the hybrids
#' ML-DSA-44/65/87+Ed25519) or a key encapsulation key pair (ML-KEM, HQC).
#'
#' Without `seed`, the key pair comes from fresh operating-system
#' randomness. With `seed`, it is the standard's deterministic key
#' generation from that seed (the same seed always gives the same pair),
#' which test vectors use; a seed is as secret as the secret key it makes.
#' A hybrid's keys are the ML-DSA key followed by the Ed25519 key.
#' SLH-DSA key generation builds one hash tree and takes noticeably
#' longer for the `s` parameter sets than for the `f` ones.
#'
#' @param alg Algorithm name, one of `nqalgs()$name` (case is ignored).
#' @param seed `NULL` (the default) for fresh randomness from the operating
#'   system, or a raw vector holding the standard's seed for deterministic
#'   key generation: xi (32 bytes) for ML-DSA; SK.seed, SK.prf and PK.seed
#'   (3n bytes) for SLH-DSA; the 32-byte private key for Ed25519; xi and
#'   the Ed25519 key (64 bytes) for a hybrid; d and z (64 bytes) for
#'   ML-KEM; the HQC seed.
#'
#' @return A list with the raw vectors `pk` (public key) and `sk` (secret
#'   key) in the standard's encoding, and `alg`, the algorithm name as the
#'   library spells it.
#'
#' @section Errors:
#' An unknown algorithm, or a `seed` of the wrong length.
#'
#' @references
#' FIPS 203 \doi{10.6028/NIST.FIPS.203}, FIPS 204
#' \doi{10.6028/NIST.FIPS.204}, FIPS 205 \doi{10.6028/NIST.FIPS.205} and
#' RFC 8032 \doi{10.17487/RFC8032} define the key generation and the
#' encodings.
#'
#' @family key functions
#' @seealso [nqsign()] and [nqencap()] use the keys; [nqwritekey()] saves
#'   them in the command-line tool's key files.
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' c(pk = length(k$pk), sk = length(k$sk))
#' # the same seed gives the same key pair
#' s <- as.raw(0:31)
#' identical(nqkeygen("ML-DSA-44", seed = s)$pk,
#'           nqkeygen("ML-DSA-44", seed = s)$pk)
#' nqkeygen("ML-KEM-512", seed = as.raw(0:63))$alg
#' h <- nqkeygen("ml-dsa-65+ed25519")
#' h$alg
#' @export
nqkeygen <- function(alg, seed = NULL) {
  kind <- .kind(alg)
  a <- .alg(alg, kind)
  if (!is.null(seed)) .rawarg(seed, "seed")
  r <- .Call(Ckg, as.integer(kind == "kem"), a$id, seed)
  list(pk = r[[1]], sk = r[[2]], alg = a$name)
}

#' Sign and verify
#'
#' `nqsign()` signs a message with ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
#' Ed25519 (RFC 8032) or a hybrid ML-DSA+Ed25519, whose signature verifies
#' only when both parts do; `nqverify()` checks such a signature.
#'
#' Signing is hedged by default: fresh randomness goes into every
#' signature, so signing twice gives two different, equally valid
#' signatures, and a power analysis of repeated signing learns less. For
#' Ed25519 the randomness goes into the nonce's hash; the signatures
#' verify as any RFC 8032 ones. `det = TRUE` gives the standard's
#' deterministic signature instead (all-zero randomness for ML-DSA and
#' SLH-DSA, RFC 8032's own nonce for Ed25519), the same bytes every time,
#' for reproducible output and test vectors.
#'
#' Every signature is verified under the public key held in the secret
#' key before it is returned. A signature that fails that check was made
#' while the computation was disturbed (a voltage or clock glitch, a
#' flipped memory bit) or with a damaged key; such a signature can give
#' the key away, so it is never returned and `nqsign()` signals an error.
#'
#' `ctx` is the standards' context string: a signature made with one
#' context verifies only with the same one, which keeps signatures made
#' for one purpose from being accepted for another. `ph` selects the
#' pre-hash variants (HashML-DSA, HashSLH-DSA), which sign the hash of
#' `msg`; they verify only as pre-hash signatures with the same hash.
#' Ed25519 takes neither a context nor a pre-hash in this interface.
#'
#' @param sk Secret key, a raw vector (as from [nqkeygen()]).
#' @param msg The message: a raw vector, or one string, which is signed as
#'   its UTF-8 bytes.
#' @param alg Signature algorithm name, one of the `"sig"` rows of
#'   [nqalgs()].
#' @param ctx `NULL` or a context string (raw vector or string, at most 255
#'   bytes), bound into the signature; verification needs the same one.
#' @param det `FALSE` (the default) for hedged signing with fresh
#'   randomness; `TRUE` for the deterministic variant.
#' @param ph `NULL` for the pure algorithm, or a hash name (see [nqhash()])
#'   for HashML-DSA / HashSLH-DSA, which hash `msg` with it first.
#' @param rnd `NULL`, or the standard's per-signature randomness as a raw
#'   vector (32 bytes for ML-DSA and the hybrids, n bytes for SLH-DSA,
#'   none for Ed25519), for test vectors;
#'   it overrides `det`.
#'
#' @return `nqsign()`: the signature, a raw vector of the algorithm's
#'   signature size (see [nqalgs()]). `nqverify()`: `TRUE` when the
#'   signature verifies, `FALSE` otherwise (including a signature, key or
#'   context of the wrong length or encoding).
#'
#' @section Errors:
#' `nqsign()`: an unknown algorithm, a secret key of the wrong length, a
#' context over 255 bytes, an unknown pre-hash, `rnd` of the wrong length,
#' or `"noqtis: ...: the signature failed the check after signing (a
#' fault)"`. `nqverify()` returns `FALSE` rather than an error for any
#' signature that does not verify.
#'
#' @references
#' National Institute of Standards and Technology (2024).
#' *Module-Lattice-Based Digital Signature Standard*, FIPS 204.
#' \doi{10.6028/NIST.FIPS.204}
#'
#' National Institute of Standards and Technology (2024).
#' *Stateless Hash-Based Digital Signature Standard*, FIPS 205.
#' \doi{10.6028/NIST.FIPS.205}
#'
#' Josefsson, S. and Liusvaara, I. (2017). *Edwards-Curve Digital
#' Signature Algorithm (EdDSA)*, RFC 8032. \doi{10.17487/RFC8032}
#'
#' @family signature functions
#' @seealso [nqkeygen()] makes the keys; [nqdsse()] signs a payload in a
#'   DSSE envelope; [nqseal()] signs a whole folder.
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' s <- nqsign(k$sk, "hello", "ML-DSA-44")
#' nqverify(k$pk, "hello", s, "ML-DSA-44")
#' nqverify(k$pk, "hellO", s, "ML-DSA-44")
#' # a context binds the signature to one purpose
#' s2 <- nqsign(k$sk, "hello", "ML-DSA-44", ctx = "invoices")
#' nqverify(k$pk, "hello", s2, "ML-DSA-44", ctx = "invoices")
#' nqverify(k$pk, "hello", s2, "ML-DSA-44")
#' # deterministic signatures repeat; hedged ones do not
#' identical(nqsign(k$sk, "hello", "ML-DSA-44", det = TRUE),
#'           nqsign(k$sk, "hello", "ML-DSA-44", det = TRUE))
#' # pre-hash: HashML-DSA with SHA-512
#' s3 <- nqsign(k$sk, "hello", "ML-DSA-44", ph = "sha512")
#' nqverify(k$pk, "hello", s3, "ML-DSA-44", ph = "sha512")
#' # a hybrid needs both halves to verify
#' h <- nqkeygen("ML-DSA-44+Ed25519")
#' nqverify(h$pk, "hello", nqsign(h$sk, "hello", h$alg), h$alg)
#' # SLH-DSA, hash-based
#' sl <- nqkeygen("SLH-DSA-SHAKE-128f")
#' length(nqsign(sl$sk, "hello", sl$alg))
#' @export
nqsign <- function(sk, msg, alg, ctx = NULL, det = FALSE, ph = NULL,
                   rnd = NULL) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  msg <- .bytes(msg, "msg")
  if (!is.null(ctx)) ctx <- .bytes(ctx, "ctx")
  if (!is.null(rnd)) {
    .rawarg(rnd, "rnd")
  } else if (isTRUE(det)) {
    # 32 for ML-DSA and the hybrids, none for Ed25519, n for SLH-DSA
    n <- if (a$name == "Ed25519") {
      0L
    } else if (startsWith(a$name, "ML-DSA")) {
      32L
    } else {
      a$pk %/% 2L
    }
    rnd <- raw(n)
  } else if (!identical(det, FALSE)) {
    stop("'det' must be TRUE or FALSE", call. = FALSE)
  }
  .Call(Csign, a$id, sk, msg, ctx, .ph(ph), rnd)
}

#' @rdname nqsign
#' @param pk Public key, a raw vector.
#' @param sig Signature, a raw vector.
#' @export
nqverify <- function(pk, msg, sig, alg, ctx = NULL, ph = NULL) {
  a <- .alg(alg, "sig")
  .rawarg(pk, "pk")
  .rawarg(sig, "sig")
  msg <- .bytes(msg, "msg")
  if (!is.null(ctx)) ctx <- .bytes(ctx, "ctx")
  rc <- .Call(Cvrfy, a$id, pk, msg, sig, ctx, .ph(ph))
  if (rc == 0L) {
    return(TRUE)
  }
  # NQEVRFY, NQEDEC: not a valid signature under this key
  if (rc %in% c(-3L, -4L)) {
    return(FALSE)
  }
  # NQEARG for an over-long context is a failed check as well
  if (rc == -1L && !is.null(ctx) && length(ctx) > 255L) {
    return(FALSE)
  }
  stop(sprintf("noqtis: nqvrfy: %s", .Call(Cerr, rc)), call. = FALSE)
}
