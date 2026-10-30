#' Algorithms and their sizes
#'
#' Lists every signature and key encapsulation algorithm the bundled
#' library provides, with the sizes in bytes of its keys, signatures,
#' ciphertexts and shared secrets.
#'
#' @return A data frame with one row per algorithm and the columns `name`,
#'   `type` (`"sig"` or `"kem"`), `pk`, `sk`, `sig`, `ct` and `ss` (sizes
#'   in bytes; `NA` where they do not apply) and `id` (the library's
#'   number for the algorithm).
#'
#' @examples
#' nqalgs()
#' @export
nqalgs <- function() .tab()

#' Generate a key pair
#'
#' Generates a signature key pair (ML-DSA, SLH-DSA, Ed25519, the hybrids
#' ML-DSA-44/65/87+Ed25519) or a key encapsulation key pair (ML-KEM, HQC).
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
#'   key) in the standard's encoding, and `alg`, the algorithm name.
#'
#' @seealso [nqsign()], [nqencap()].
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' length(k$pk)
#' k2 <- nqkeygen("ML-KEM-512", seed = as.raw(0:63))
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
#' @param sk Secret key, a raw vector (as from [nqkeygen()]).
#' @param msg The message: a raw vector, or one string, which is signed as
#'   its UTF-8 bytes.
#' @param alg Signature algorithm name, one of the `"sig"` rows of
#'   [nqalgs()].
#' @param ctx `NULL` or a context string (raw vector or string, at most 255
#'   bytes), bound into the signature; verification needs the same one.
#' @param det `FALSE` (the default) for hedged signing with fresh
#'   randomness; `TRUE` for the deterministic variant (all-zero
#'   per-signature randomness).
#' @param ph `NULL` for the pure algorithm, or a hash name (see [nqhash()])
#'   for HashML-DSA / HashSLH-DSA, which hash `msg` with it first.
#' @param rnd `NULL`, or the standard's per-signature randomness as a raw
#'   vector (32 bytes for ML-DSA and the hybrids, n bytes for SLH-DSA,
#'   none for Ed25519), for test vectors;
#'   it overrides `det`.
#'
#' @return `nqsign()`: the signature, a raw vector. `nqverify()`: `TRUE`
#'   when the signature verifies, `FALSE` otherwise (including a signature,
#'   key or context of the wrong length or encoding).
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' s <- nqsign(k$sk, "hello", "ML-DSA-44")
#' nqverify(k$pk, "hello", s, "ML-DSA-44")
#' nqverify(k$pk, "hellO", s, "ML-DSA-44")
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
