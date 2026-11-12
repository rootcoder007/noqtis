#' Hashes and HMAC
#'
#' `nqhash()` computes a SHA-2 (FIPS 180-4), SHA-3 or SHAKE (FIPS 202)
#' digest of a raw vector, a string or a file; `nqhmac()` computes an
#' HMAC (RFC 2104) with a SHA-2 or SHA-3 hash.
#'
#' Hash names: `"sha224"`, `"sha256"`, `"sha384"`, `"sha512"`,
#' `"sha512-224"`, `"sha512-256"`, `"sha3-224"`, `"sha3-256"`,
#' `"sha3-384"`, `"sha3-512"`, `"shake128"`, `"shake256"` (case is
#' ignored). The output is 28, 32, 48, 64, 28, 32, 28, 32, 48 and 64
#' bytes for the fixed-length hashes; SHAKE128 and SHAKE256 are
#' extendable-output functions that give `len` bytes (by default 32 and
#' 64).
#'
#' A file is read in chunks of 1 MiB, so files larger than memory hash
#' without being loaded whole. A string is hashed as its UTF-8 bytes,
#' with no terminating newline. The HMAC key may have any length.
#'
#' @param x A raw vector, or one string (hashed as its UTF-8 bytes), or,
#'   with `file = TRUE`, the path of a file.
#' @param alg Hash name.
#' @param file `TRUE` to hash the file at path `x`, read in chunks of 1 MiB.
#' @param hex `TRUE` to return lowercase hexadecimal text instead of raw
#'   bytes.
#' @param len For SHAKE only, the output length in bytes (default 32 for
#'   SHAKE128 and 64 for SHAKE256).
#'
#' @return The digest, a raw vector, or a string when `hex = TRUE`.
#'
#' @section Errors:
#' An unknown hash name, `len` with a fixed-length hash, `file = TRUE`
#' with a path that is not an existing file, or SHAKE for `nqhmac()`.
#'
#' @references
#' National Institute of Standards and Technology (2015). *Secure Hash
#' Standard (SHS)*, FIPS 180-4. \doi{10.6028/NIST.FIPS.180-4}
#'
#' National Institute of Standards and Technology (2015). *SHA-3
#' Standard: Permutation-Based Hash and Extendable-Output Functions*,
#' FIPS 202. \doi{10.6028/NIST.FIPS.202}
#'
#' Krawczyk, H., Bellare, M. and Canetti, R. (1997). *HMAC: Keyed-Hashing
#' for Message Authentication*, RFC 2104. \doi{10.17487/RFC2104}
#'
#' @family hash functions
#' @seealso [nqsign()] can sign a hash (`ph`); [nqfiles()] lists the
#'   SHA-256 of every file of a capsule.
#'
#' @examples
#' nqhash("abc", hex = TRUE)
#' nqhash(charToRaw("abc"), "sha3-256")
#' nqhash("abc", "shake128", len = 16)
#' nqhash("abc", "sha512-256", hex = TRUE)
#' f <- tempfile()
#' writeBin(charToRaw("abc"), f)
#' identical(nqhash(f, file = TRUE), nqhash("abc"))
#' unlink(f)
#' nqhmac("key", "The quick brown fox jumps over the lazy dog", hex = TRUE)
#' nqhmac(as.raw(1:64), "data", "sha3-256", hex = TRUE)
#' @export
nqhash <- function(x, alg = "sha256", file = FALSE, hex = FALSE,
                   len = NULL) {
  id <- .hid(alg)
  n <- .hlen(id, len)
  d <- if (isTRUE(file)) {
    .hfile(x, id, n)
  } else if (identical(file, FALSE)) {
    .Call(Chash, id, .bytes(x, "x"), n)
  } else {
    stop("'file' must be TRUE or FALSE", call. = FALSE)
  }
  if (isTRUE(hex)) .hex(d) else d
}

#' @rdname nqhash
#' @param key HMAC key, a raw vector or one string.
#' @export
nqhmac <- function(key, x, alg = "sha256", hex = FALSE) {
  id <- .hid(alg)
  if (id >= 11L) stop("HMAC needs a SHA-2 or SHA-3 hash", call. = FALSE)
  d <- .Call(Chmac, id, .bytes(key, "key"), .bytes(x, "x"))
  if (isTRUE(hex)) .hex(d) else d
}

# The output length of hash id: its own, or len for SHAKE.
.hlen <- function(id, len) {
  if (is.null(len)) {
    return(c(28L, 32L, 48L, 64L, 28L, 32L, 28L, 32L, 48L, 64L, 32L, 64L)[id])
  }
  if (id < 11L) stop("'len' applies to SHAKE only", call. = FALSE)
  if (!.count1(len)) {
    stop("'len' must be one non-negative whole number", call. = FALSE)
  }
  as.integer(len)
}

# The digest of the file at path x, read in chunks of 1 MiB.
.hfile <- function(x, id, n) {
  if (!.file1(x)) {
    stop("'x' must be the path of an existing file", call. = FALSE)
  }
  con <- file(x, "rb")
  on.exit(close(con), add = TRUE)
  ctx <- .Call(Chini, id)
  repeat {
    b <- readBin(con, "raw", 1048576L)
    if (length(b) == 0L) break
    ctx <- .Call(Chupd, ctx, b)
  }
  .Call(Chfin, ctx, n)
}
