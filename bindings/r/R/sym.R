#' KangarooTwelve, AES-SIV, AES-GCM-SIV and the ChaCha20 stream
#'
#' `nqkt()` is KangarooTwelve (RFC 9861): `n` bytes of KT128 (`bits =
#' 128`) or KT256 (`bits = 256`), the tree hash and extendable-output
#' function on Keccak with 12 rounds, with an optional customization
#' string (a secret key there makes it a MAC). A shorter output is the
#' start of a longer one.
#'
#' `nqsivenc()` and `nqsivdec()` are AES-SIV (RFC 5297), deterministic
#' authenticated encryption: no nonce is needed, and the same key,
#' associated strings and message always give the same output, which
#' shows when two messages are equal and nothing else.
#'
#' `nqgsivenc()` and `nqgsivdec()` are AES-GCM-SIV (RFC 8452),
#' authenticated encryption that resists a nonce used twice: a nonce
#' should still be new for each message, but one used again shows only
#' whether the two messages were equal.
#'
#' `nqchacha20()` is the ChaCha20 stream cipher (RFC 8439) on its own.
#' **It is not authenticated**: a changed ciphertext decrypts to a
#' changed message with no error, and a key and nonce used for two
#' messages give away their XOR. It is for protocols that add their own
#' authentication; to encrypt, use `nqsivenc()` or `nqgsivenc()`.
#'
#' The ciphers run in time that does not depend on the key or the
#' message.
#'
#' @param x The message, or for the two decryptions the output of the
#'   encryption: a raw vector, or one string (its UTF-8 bytes).
#' @param n The output length in bytes, 1 or more; 32 bytes of KT128 and
#'   64 of KT256 give their full strength against collisions.
#' @param bits `128` (KT128) or `256` (KT256).
#' @param custom `NULL`, or the customization string: a raw vector or one
#'   string.
#' @param key The key, a raw vector: 32, 48 or 64 bytes for AES-SIV (two
#'   AES keys), 16 or 32 for AES-GCM-SIV, 32 for ChaCha20.
#' @param ad The associated data, authenticated and not encrypted. For
#'   AES-SIV a list of up to 126 raw vectors or strings, each a separate
#'   input (a nonce, where there is one, is by convention the last); for
#'   AES-GCM-SIV `NULL`, one raw vector or one string.
#' @param nonce The nonce, a raw vector of 12 bytes.
#' @param counter The block counter the key stream starts at, a whole
#'   number from 0 to 2^32 - 1; a block is 64 bytes.
#'
#' @return A raw vector. `nqkt()`: `n` bytes. `nqsivenc()`: the 16-byte
#'   synthetic IV, then the ciphertext. `nqgsivenc()`: the ciphertext,
#'   then the 16-byte tag. `nqsivdec()` and `nqgsivdec()`: the message;
#'   they stop with an error when the key, the nonce, the associated data
#'   or the input are not the ones encrypted. `nqchacha20()`: `x` XORed
#'   with the key stream (the same call decrypts).
#'
#' @references
#' Viguier, B., Wong, D., Van Assche, G., Dang, Q. and Daemen, J. (2025).
#' *KangarooTwelve and TurboSHAKE*. RFC 9861. \doi{10.17487/RFC9861}
#'
#' Harkins, D. (2008). *Synthetic Initialization Vector (SIV)
#' Authenticated Encryption Using the Advanced Encryption Standard
#' (AES)*. RFC 5297. \doi{10.17487/RFC5297}
#'
#' Gueron, S., Langley, A. and Lindell, Y. (2019). *AES-GCM-SIV: Nonce
#' Misuse-Resistant Authenticated Encryption*. RFC 8452.
#' \doi{10.17487/RFC8452}
#'
#' Nir, Y. and Langley, A. (2018). *ChaCha20 and Poly1305 for IETF
#' Protocols*. RFC 8439. \doi{10.17487/RFC8439}
#'
#' @family hash functions
#'
#' @examples
#' nqkt("abc")
#' nqkt("abc", n = 64, bits = 256, custom = "my application")
#'
#' key <- as.raw(1:64)
#' ct <- nqsivenc(key, "a message", ad = list("header"))
#' rawToChar(nqsivdec(key, ct, ad = list("header")))
#'
#' nonce <- as.raw(1:12)
#' ct <- nqgsivenc(key[1:32], nonce, "a message", ad = "header")
#' rawToChar(nqgsivdec(key[1:32], nonce, ct, ad = "header"))
#'
#' ks <- nqchacha20(key[1:32], nonce, "not authenticated")
#' rawToChar(nqchacha20(key[1:32], nonce, ks))
#' @export
nqkt <- function(x, n = 32L, bits = 128L, custom = NULL) {
  if (!.count1(n)) stop("'n' must be a whole number", call. = FALSE)
  if (!.count1(bits) || !bits %in% c(128, 256)) {
    stop("'bits' must be 128 or 256", call. = FALSE)
  }
  if (!is.null(custom)) custom <- .bytes(custom, "custom")
  .Call(Ckt, as.integer(bits), .bytes(x, "x"), custom, as.integer(n))
}

#' The associated strings of AES-SIV as a list of raw vectors.
#' @noRd
.sivad <- function(ad) {
  if (is.null(ad)) {
    return(list())
  }
  if (!is.list(ad)) {
    stop("'ad' must be a list of raw vectors or strings", call. = FALSE)
  }
  lapply(ad, .bytes, what = "ad")
}

#' @rdname nqkt
#' @export
nqsivenc <- function(key, x, ad = list()) {
  .Call(Csiv, 0L, .rawarg(key, "key"), .sivad(ad), .bytes(x, "x"))
}

#' @rdname nqkt
#' @export
nqsivdec <- function(key, x, ad = list()) {
  .Call(Csiv, 1L, .rawarg(key, "key"), .sivad(ad), .rawarg(x, "x"))
}

#' @rdname nqkt
#' @export
nqgsivenc <- function(key, nonce, x, ad = NULL) {
  if (!is.null(ad)) ad <- .bytes(ad, "ad")
  .Call(
    Cgsiv, 0L, .rawarg(key, "key"), .rawarg(nonce, "nonce"), ad,
    .bytes(x, "x")
  )
}

#' @rdname nqkt
#' @export
nqgsivdec <- function(key, nonce, x, ad = NULL) {
  if (!is.null(ad)) ad <- .bytes(ad, "ad")
  .Call(
    Cgsiv, 1L, .rawarg(key, "key"), .rawarg(nonce, "nonce"), ad,
    .rawarg(x, "x")
  )
}

#' @rdname nqkt
#' @export
nqchacha20 <- function(key, nonce, x, counter = 0) {
  if (!is.numeric(counter) || length(counter) != 1L || is.na(counter)) {
    stop("'counter' must be one number", call. = FALSE)
  }
  .Call(
    Ccha20, .rawarg(key, "key"), .rawarg(nonce, "nonce"),
    as.double(counter), .bytes(x, "x")
  )
}
