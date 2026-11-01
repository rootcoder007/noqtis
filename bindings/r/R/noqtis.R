#' noqtis: post-quantum signatures, key encapsulation and file capsules
#'
#' R interface to the noqtis C library: ML-DSA (FIPS 204), SLH-DSA
#' (FIPS 205), ML-KEM (FIPS 203), HQC, the SHA-2 and SHA-3 families
#' (FIPS 180-4, FIPS 202) and HMAC, and capsules, signed records of the
#' exact files in a folder.
#'
#' Keys, signatures, ciphertexts and shared secrets are raw vectors in the
#' encodings the standards define. Algorithms are named as in
#' [nqalgs()], for example `"ML-DSA-65"`, `"SLH-DSA-SHAKE-128f"` or
#' `"ML-KEM-768"`.
#'
#' @section Randomness:
#' Key generation, hedged signing and encapsulation draw their randomness
#' from the operating system's cryptographically secure generator through
#' the library's own `nqrand()` (`getrandom()` on Linux, `arc4random_buf()`
#' on macOS and the BSDs, `BCryptGenRandom()` on Windows). R's random
#' number generator is never used, so [set.seed()] has no effect on them
#' and they do not change `.Random.seed`. Deterministic results need an
#' explicit `seed` (key generation, encapsulation) or `det = TRUE`
#' (signing), which exist for test vectors.
#'
#' @section Secrets in R:
#' The library wipes every secret buffer of its own before it returns.
#' Secret keys and shared secrets returned to R are ordinary raw vectors:
#' R may copy them and does not wipe memory it frees, so keep them out of
#' saved workspaces and logs.
#'
#' @keywords internal
#' @useDynLib noqtis, .registration = TRUE
"_PACKAGE"

#' Version of the bundled noqtis library
#'
#' @return A string, the version of the C library compiled into this
#'   package.
#'
#' @examples
#' nqver()
#' @export
nqver <- function() .Call(Cver)

#' Known-answer self-test of the bundled noqtis library
#'
#' Runs fixed inputs through every algorithm family (hashes, HMAC, ML-KEM,
#' ML-DSA, SLH-DSA, HQC, Ed25519 and a hybrid) and compares the outputs
#' with stored answers, the power-on self-test of a FIPS 140-3 module. It
#' takes about a tenth of a second.
#'
#' @return `TRUE`, invisibly; an error when an answer differs.
#'
#' @examples
#' nqselftest()
#' @export
nqselftest <- function() invisible(.Call(Cself))
