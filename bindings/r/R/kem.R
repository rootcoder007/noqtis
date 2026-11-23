#' Key encapsulation
#'
#' `nqencap()` makes a fresh shared secret and its ciphertext for a public
#' key (ML-KEM, FIPS 203, or HQC); `nqdecap()` recovers the shared secret
#' from the ciphertext with the secret key.
#'
#' The holder of the public key sends nothing; whoever wants to share a
#' secret with them calls `nqencap()`, sends `ct`, and keeps `ss`. The
#' key holder's `nqdecap()` gives the same `ss`. The shared secret (32
#' bytes for ML-KEM and for HQC) is meant as key material for a key
#' derivation or a symmetric cipher, not as text.
#'
#' `nqencap()` calls the library's `nqenc()` (`nqencd()` with `seed`),
#' `nqdecap()` its `nqdec()`. The sizes in bytes (public key, secret key,
#' ciphertext): ML-KEM-512 800, 1632, 768; ML-KEM-768 1184, 2400, 1088;
#' ML-KEM-1024 1568, 3168, 1568; HQC-128 2241, 32, 4433; HQC-192 4514,
#' 32, 8978; HQC-256 7237, 32, 14421. HQC follows its specification
#' version 5.1 of 2026-11-09, whose secret key is its 32-byte seed; keys
#' and ciphertexts of version 5.0 (noqtis before 0.3.0) do not
#' interoperate with these, and a 5.0 secret key is refused.
#'
#' Decapsulation uses implicit rejection, as FIPS 203 and HQC require: a
#' changed ciphertext gives an unrelated pseudorandom secret, not an error,
#' so an attacker learns nothing from which ciphertexts are accepted.
#' Only a key or ciphertext of the wrong length is an error. ML-KEM and
#' HQC decapsulation are masked against power analysis.
#'
#' @param pk Public key, a raw vector (as from [nqkeygen()]).
#' @param alg Key encapsulation algorithm name, one of the `"kem"` rows of
#'   [nqalgs()].
#' @param seed `NULL` (the default) for fresh randomness, or the standard's
#'   encapsulation seed as a raw vector (m, 32 bytes, for ML-KEM; m and
#'   salt, 32, 40 or 48 bytes, for HQC-128, -192, -256), for test vectors.
#'
#' @return `nqencap()`: a list with the raw vectors `ct` (ciphertext) and
#'   `ss` (shared secret). `nqdecap()`: the shared secret, a raw vector.
#'
#' @section Errors:
#' An unknown algorithm, a key, ciphertext or seed of the wrong length;
#' for ML-KEM, a public key that fails the input check of FIPS 203
#' (section 7.2) or a secret key whose stored hash of its public key does
#' not match (section 7.3); for HQC, a public key whose unused top bits
#' are not zero or a secret key that is not 32 bytes; the random
#' source failing (both decapsulations draw fresh mask shares).
#'
#' @references
#' National Institute of Standards and Technology (2024).
#' *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203.
#' \doi{10.6028/NIST.FIPS.203}
#'
#' Gaborit, P., Aguilar-Melchor, C., Aragon, N. et al. (2025).
#' *Hamming Quasi-Cyclic (HQC)*, specification version 5.1 of
#' 2026-11-09. <https://pqc-hqc.org/>
#'
#' @family key encapsulation functions
#' @seealso [nqkeygen()] makes the key pairs; [nqhash()] can derive keys
#'   from the shared secret.
#'
#' @examples
#' k <- nqkeygen("ML-KEM-768")
#' e <- nqencap(k$pk, "ML-KEM-768")
#' identical(nqdecap(k$sk, e$ct, "ML-KEM-768"), e$ss)
#' # a changed ciphertext gives another secret, not an error
#' bad <- e$ct
#' bad[1] <- xor(bad[1], as.raw(1))
#' identical(nqdecap(k$sk, bad, "ML-KEM-768"), e$ss)
#' # HQC, a code-based KEM
#' h <- nqkeygen("HQC-128")
#' eh <- nqencap(h$pk, "HQC-128")
#' identical(nqdecap(h$sk, eh$ct, "HQC-128"), eh$ss)
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
#' the same source key generation, hedged signing and encapsulation use
#' (`getrandom()` on Linux, `arc4random_buf()` on macOS and the BSDs,
#' `BCryptGenRandom()` on Windows), read through the library's `nqrand()`.
#' Independent of [set.seed()] and of R's own generator; suitable for
#' keys, nonces and salts.
#'
#' @param n Number of bytes.
#'
#' @return A raw vector of length `n`.
#'
#' @section Errors:
#' `n` not one non-negative whole number, or
#' `"noqtis: ...: the operating` `system's random source` `failed"`.
#'
#' @family library functions
#'
#' @examples
#' nqrand(16)
#' set.seed(1)
#' a <- nqrand(8)
#' set.seed(1)
#' b <- nqrand(8)
#' identical(a, b)
#' @export
nqrand <- function(n) {
  if (!.count1(n)) {
    stop("'n' must be one non-negative whole number", call. = FALSE)
  }
  .Call(Crand, as.integer(n))
}
