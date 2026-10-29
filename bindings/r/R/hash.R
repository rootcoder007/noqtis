#' Hashes and HMAC
#'
#' `nqhash()` computes a SHA-2 (FIPS 180-4), SHA-3 or SHAKE (FIPS 202)
#' digest of a raw vector, a string or a file; `nqhmac()` computes an HMAC.
#'
#' Hash names: `"sha224"`, `"sha256"`, `"sha384"`, `"sha512"`,
#' `"sha512-224"`, `"sha512-256"`, `"sha3-224"`, `"sha3-256"`,
#' `"sha3-384"`, `"sha3-512"`, `"shake128"`, `"shake256"` (case is
#' ignored).
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
#' @examples
#' nqhash("abc", hex = TRUE)
#' nqhash(charToRaw("abc"), "sha3-256")
#' nqhash("abc", "shake128", len = 16)
#' f <- tempfile()
#' writeBin(charToRaw("abc"), f)
#' nqhash(f, file = TRUE, hex = TRUE)
#' unlink(f)
#' nqhmac("key", "The quick brown fox jumps over the lazy dog", hex = TRUE)
#' @export
nqhash <- function(x, alg = "sha256", file = FALSE, hex = FALSE,
                   len = NULL) {
  id <- .hid(alg)
  shk <- id >= 11L
  n <- if (is.null(len)) {
    c(28L, 32L, 48L, 64L, 28L, 32L, 28L, 32L, 48L, 64L, 32L, 64L)[id]
  } else {
    if (!shk) stop("'len' applies to SHAKE only", call. = FALSE)
    if (!is.numeric(len) || length(len) != 1L || is.na(len) || len < 0 ||
      len != floor(len) || len > .Machine$integer.max) {
      stop("'len' must be one non-negative whole number", call. = FALSE)
    }
    as.integer(len)
  }
  if (isTRUE(file)) {
    if (!is.character(x) || length(x) != 1L || is.na(x) || !file.exists(x) ||
      dir.exists(x)) {
      stop("'x' must be the path of an existing file", call. = FALSE)
    }
    con <- file(x, "rb")
    on.exit(close(con))
    ctx <- .Call(Chini, id)
    repeat {
      b <- readBin(con, "raw", 1048576L)
      if (length(b) == 0L) break
      ctx <- .Call(Chupd, ctx, b)
    }
    d <- .Call(Chfin, ctx, n)
  } else if (identical(file, FALSE)) {
    d <- .Call(Chash, id, .bytes(x, "x"), n)
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
