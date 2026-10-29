#' Key encapsulation
#'
#' `nqencap()` makes a fresh shared secret and its ciphertext for a public
#' key (ML-KEM, FIPS 203, or HQC); `nqdecap()` recovers the shared secret
#' from the ciphertext with the secret key.
#'
#' Decapsulation uses implicit rejection, as FIPS 203 and HQC require: a
#' changed ciphertext gives an unrelated pseudorandom secret, not an error.
#' Only a key or ciphertext of the wrong length is an error.
#'
#' @param pk Public key, a raw vector (as from [nqkeygen()]).
#' @param alg Key encapsulation algorithm name, one of the `"kem"` rows of
#'   [nqalgs()].
#' @param seed `NULL` (the default) for fresh randomness, or the standard's
#'   encapsulation seed as a raw vector (m, 32 bytes, for ML-KEM; m and
#'   salt for HQC), for test vectors.
#'
#' @return `nqencap()`: a list with the raw vectors `ct` (ciphertext) and
#'   `ss` (shared secret). `nqdecap()`: the shared secret, a raw vector.
#'
#' @examples
#' k <- nqkeygen("ML-KEM-768")
#' e <- nqencap(k$pk, "ML-KEM-768")
#' identical(nqdecap(k$sk, e$ct, "ML-KEM-768"), e$ss)
#' @export
nqencap <- function(pk, alg, seed = NULL) {
  a <- .alg(alg, "kem")
  .rawarg(pk, "pk")
  if (!is.null(seed)) .rawarg(seed, "seed")
  r <- .Call(Cenc, a$id, pk, seed)
  list(ct = r[[1]], ss = r[[2]])
}

#' @rdname nqencap
#' @param sk Secret key, a raw vector.
#' @param ct Ciphertext, a raw vector.
#' @export
nqdecap <- function(sk, ct, alg) {
  a <- .alg(alg, "kem")
  .rawarg(sk, "sk")
  .rawarg(ct, "ct")
  .Call(Cdec, a$id, sk, ct)
}

#' Random bytes from the operating system
#'
#' Bytes from the operating system's cryptographically secure generator,
#' the same source key generation uses (see the Randomness section of
#' [noqtis-package]). Independent of [set.seed()].
#'
#' @param n Number of bytes.
#'
#' @return A raw vector of length `n`.
#'
#' @examples
#' nqrand(16)
#' @export
nqrand <- function(n) {
  if (!is.numeric(n) || length(n) != 1L || is.na(n) || n < 0 ||
    n != floor(n) || n > .Machine$integer.max) {
    stop("'n' must be one non-negative whole number", call. = FALSE)
  }
  .Call(Crand, as.integer(n))
}
