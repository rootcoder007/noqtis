#' noqtis: post-quantum signatures, key encapsulation and file capsules
#'
#' R interface to the noqtis C library, which the package bundles and
#' compiles (C11, no dependencies): the post-quantum signature schemes
#' ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), Ed25519 (RFC 8032) and the
#' hybrids ML-DSA+Ed25519; the key encapsulation mechanisms ML-KEM
#' (FIPS 203) and HQC; the SHA-2 (FIPS 180-4) and SHA-3 and SHAKE
#' (FIPS 202) hash functions and HMAC (RFC 2104); and capsules, signed
#' records of the exact files in a folder.
#'
#' Keys, signatures, ciphertexts and shared secrets are raw vectors in the
#' encodings the standards define, so they interoperate with other
#' implementations of the same standards. Algorithms are named as
#' [nqalgs()] lists them, for example `"ML-DSA-65"`,
#' `"SLH-DSA-SHAKE-128f"`, `"ML-DSA-65+Ed25519"` or `"ML-KEM-768"`; case
#' is ignored.
#'
#' @section Functions:
#' \describe{
#'   \item{Library}{[nqver()], [nqselftest()], [nqalgs()], [nqrand()].}
#'   \item{Keys}{[nqkeygen()]; the command-line tool's key files with
#'     [nqreadkey()] and [nqwritekey()].}
#'   \item{Signatures}{[nqsign()], [nqverify()]; DSSE envelopes with
#'     [nqdsse()] and [nqdsseverify()].}
#'   \item{Key encapsulation}{[nqencap()], [nqdecap()].}
#'   \item{Hashes}{[nqhash()], [nqhmac()].}
#'   \item{Capsules}{[nqseal()], [nqcheck()], [nqcapid()], [nqfiles()],
#'     [nqprove()]; key statements with [nqrotate()] and [nqrevoke()];
#'     identity cards with [nqidcard()] and [nqidcheck()].}
#' }
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
#' @section Protections inside the library:
#' No branch and no memory index depends on a secret. ML-DSA and Ed25519
#' signing, the secret-keyed hash of SLH-DSA, and ML-KEM and HQC
#' decapsulation are also masked: the secret is split into random shares
#' that change on every call, against power analysis. Every signature is
#' verified under the public key before it is returned, so a signature
#' made while the computation was disturbed (a fault, which can give the
#' key away) is never released; [nqsign()] signals an error instead.
#' [nqselftest()] runs the library's known-answer tests.
#'
#' @section Secrets in R:
#' The library wipes every secret buffer of its own before it returns.
#' Secret keys and shared secrets returned to R are ordinary raw vectors:
#' R may copy them and does not wipe memory it frees, so keep them out of
#' saved workspaces and logs, and write secret keys with [nqwritekey()],
#' which makes the file readable by its owner only.
#'
#' @section Errors:
#' Invalid arguments (a wrong type, an unknown algorithm, a key or seed of
#' the wrong length) are errors with a message that names the argument.
#' Failures of the library are errors of the form
#' `"noqtis: <call>: <reason>"`. A signature or check that does not
#' verify is not an error: [nqverify()] returns `FALSE`, [nqcheck()]
#' reports failed rows.
#'
#' @references
#' National Institute of Standards and Technology (2024).
#' *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203.
#' \doi{10.6028/NIST.FIPS.203}
#'
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
#' Aguilar Melchor, C. et al. (2025). *Hamming Quasi-Cyclic (HQC)*,
#' specification version 5.0.0 of 2025-08-22.
#'
#' @keywords internal
#' @useDynLib noqtis, .registration = TRUE
"_PACKAGE"

#' Version of the bundled noqtis library
#'
#' The version of the noqtis C library compiled into this package, which
#' is also the package's own version.
#'
#' @return A string, `"major.minor.patch"`.
#'
#' @family library functions
#'
#' @examples
#' nqver()
#' utils::packageVersion("noqtis") == nqver()
#' @export
nqver <- function() .Call(Cver)

#' Known-answer self-test of the bundled noqtis library
#'
#' Runs fixed inputs through every algorithm family and compares the
#' outputs with stored answers, the power-on self-test a FIPS 140-3
#' cryptographic module runs before it is used.
#'
#' Seven tests run through the library's public interface: SHA-2, SHA-3
#' and SHAKE on a fixed message; HMAC-SHA-256 and HMAC-SHA-512; key
#' generation, encapsulation and decapsulation for ML-KEM-512, 768 and
#' 1024; key generation and deterministic signing and verification for
#' ML-DSA-44, 65 and 87; SLH-DSA key generation; HQC-128 key generation,
#' encapsulation and decapsulation; and Ed25519 and ML-DSA-44+Ed25519
#' signing and verification. Every output and return code of a test is
#' hashed with SHA-256 and compared with the stored hash, which was made
#' where the library's test suite checks the same functions against the
#' NIST test vectors. The whole run takes about a tenth of a second.
#'
#' A mismatch means the compiled library does not compute what it should:
#' a miscompilation, an unsupported compiler option, or faulty hardware.
#' Do not use the package on that machine until the cause is found.
#'
#' @return `TRUE`, invisibly, when every answer matches.
#'
#' @section Errors:
#' `"noqtis: self-test: a self-test known answer did not match"` when one
#' does not.
#'
#' @references
#' National Institute of Standards and Technology (2019). *Security
#' Requirements for Cryptographic Modules*, FIPS 140-3.
#' \doi{10.6028/NIST.FIPS.140-3}
#'
#' @family library functions
#'
#' @examples
#' nqselftest()
#' system.time(nqselftest())
#' @export
nqselftest <- function() invisible(.Call(Cself))
