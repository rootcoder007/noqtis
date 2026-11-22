# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#' OpenPGP keys, signatures and encrypted messages
#'
#' OpenPGP (RFC 9580) in its version 6 forms, with Ed25519 and X25519 of
#' that RFC and the post-quantum algorithms of RFC 9980.
#' `nqpgpkeygen()` makes a key; `nqpgpinfo()` reads one; `nqpgpsign()`
#' and `nqpgpverify()` sign and check; `nqpgpencrypt()` and
#' `nqpgpdecrypt()` encrypt and open; `nqpgparmor()` and
#' `nqpgpdearmor()` turn packets into ASCII armor and back.
#'
#' Algorithms are named `"mldsa65-ed25519"` (the default), `"ed25519"`,
#' `"slh-shake-128s"`, `"slh-shake-128f"` and `"slh-shake-256s"` for the
#' primary key, which certifies and signs, and `"mlkem768-x25519"` and
#' `"x25519"` for the encryption subkey. Keys, signatures and messages
#' are binary packets (raw vectors); the functions that read them also
#' take the armored text.
#'
#' Versions 3 and 4, RSA, CFB encryption and compressed data are not
#' supported, and are reported as errors.
#'
#' They call the library's `nqpgpgen()`, `nqpgpinfo()`, `nqpgpsign()`,
#' `nqpgpvrfy()`, `nqpgpenc()`, `nqpgpdec()`, `nqpgparm()` and
#' `nqpgpdearm()` (nqpgpgen(3), which gives the key encapsulations in
#' full).
#'
#' @param userid The user ID, by convention `"Name <address>"`.
#' @param alg The primary key's algorithm.
#' @param encalg The encryption subkey's algorithm, or `NULL` for a key
#'   that only signs. The default follows `alg`.
#' @param passphrase A passphrase (one string or a raw vector), or
#'   `NULL`: for `nqpgpkeygen()` the one to keep the secret key under;
#'   for `nqpgpsign()` the secret key's; for `nqpgpencrypt()` one that
#'   opens the message as well; for `nqpgpdecrypt()` the secret key's,
#'   or with `key = NULL` the message's.
#' @param created,at When the key or the signature is made: a `POSIXct`
#'   time or seconds since 1970.
#' @param key A secret key, a raw vector.
#' @param cert A certificate (the public key), a raw vector.
#' @param msg The message: a raw vector or one string. For
#'   `nqpgpverify()`, what a detached signature signs, or `NULL`; for
#'   `nqpgpdecrypt()`, the encrypted message.
#' @param mode `"inline"` for a signed message that carries the data,
#'   `"detached"` for the signature alone, `"clear"` for the text with
#'   the armored signature under it.
#' @param sig A signed message, a cleartext signature or a detached
#'   signature: a raw vector or one string.
#' @param certs A list of the recipients' certificates (at most 64).
#' @param signer For `nqpgpencrypt()`, a secret key to sign the message
#'   with first; for `nqpgpdecrypt()`, a certificate the message inside
#'   must be signed by. `NULL` for neither.
#' @param signerpass The passphrase of the `signer` key, or `NULL`.
#' @param kind `"message"`, `"public key"`, `"private key"` or
#'   `"signature"`.
#' @param data Packets, a raw vector.
#' @param text Armored text: one string or a raw vector.
#'
#' @return `nqpgpkeygen()`: a list with `sec` (the secret key) and `pub`
#'   (the certificate), raw vectors. `nqpgpinfo()`: a list with `alg`,
#'   `encalg` (`NULL` for none), `secret`, `locked`, `fingerprint`,
#'   `encfingerprint`, `created`, `expires` (`NULL`: never) and
#'   `userid`. `nqpgpsign()`, `nqpgpencrypt()`: a raw vector.
#'   `nqpgpverify()`: a list with `data` and `at`, or `NULL` when the
#'   signature does not verify. `nqpgpdecrypt()`: a list with `data`,
#'   `signed` and `at`, or `NULL` when the message does not open or its
#'   signature does not verify. `nqpgparmor()`: one string.
#'   `nqpgpdearmor()`: a list with `kind` and `data`.
#'
#' @family mail and key functions
#' @examples
#' k <- nqpgpkeygen("Ada Example <ada@example.org>", "ed25519")
#' nqpgpinfo(k$pub)$userid
#' s <- nqpgpsign(k$sec, "hello")
#' rawToChar(nqpgpverify(k$pub, s)$data)
#' e <- nqpgpencrypt("a secret", list(k$pub))
#' rawToChar(nqpgpdecrypt(e, k$sec)$data)
#' cat(substr(nqpgparmor("public key", k$pub), 1, 37))
#' @export
nqpgpkeygen <- function(userid, alg = "mldsa65-ed25519",
                        encalg = if (identical(alg, "ed25519")) {
                          "x25519"
                        } else {
                          "mlkem768-x25519"
                        },
                        passphrase = NULL, created = Sys.time()) {
  r <- .Call(
    Cpgpgen, .pgpalg(alg, FALSE), .pgpalg(encalg, TRUE),
    .str1(userid, "userid", FALSE), .at(created),
    .pgppw(passphrase, "passphrase")
  )
  list(sec = r$sec, pub = r$pub)
}

#' @rdname nqpgpkeygen
#' @export
nqpgpinfo <- function(key) {
  f <- .Call(Cpgpinfo, .pgpin(key, "key"))
  f$alg <- .pgpname(f$alg)
  f$encalg <- if (f$encalg == 0L) NULL else .pgpname(f$encalg)
  f
}

#' @rdname nqpgpkeygen
#' @export
nqpgpsign <- function(key, msg, mode = c("inline", "detached", "clear"),
                      passphrase = NULL, at = Sys.time()) {
  mode <- match.arg(mode)
  .Call(
    Cpgpsign, .pgpin(key, "key"), .pgppw(passphrase, "passphrase"),
    .bytes(msg, "msg"), match(mode, c("inline", "detached", "clear")) - 1L,
    .at(at)
  )
}

#' @rdname nqpgpkeygen
#' @export
nqpgpverify <- function(cert, sig, msg = NULL) {
  r <- .Call(
    Cpgpvrfy, .pgpin(cert, "cert"), .bytes(sig, "sig"),
    if (is.null(msg)) NULL else .bytes(msg, "msg")
  )
  if (r[[1L]] != 0L) {
    return(NULL)
  }
  list(data = r[[2L]], at = r[[3L]])
}

#' @rdname nqpgpkeygen
#' @export
nqpgpencrypt <- function(msg, certs = list(), passphrase = NULL,
                         signer = NULL, signerpass = NULL,
                         at = Sys.time()) {
  certs <- lapply(.certs(certs, "certs"), .pgpin, what = "certs")
  .Call(
    Cpgpenc, certs, .pgppw(passphrase, "passphrase"),
    if (is.null(signer)) NULL else .pgpin(signer, "signer"),
    .pgppw(signerpass, "signerpass"), .bytes(msg, "msg"), .at(at)
  )
}

#' @rdname nqpgpkeygen
#' @export
nqpgpdecrypt <- function(msg, key = NULL, passphrase = NULL,
                         signer = NULL) {
  r <- .Call(
    Cpgpdec, if (is.null(key)) NULL else .pgpin(key, "key"),
    .pgppw(passphrase, "passphrase"),
    if (is.null(signer)) NULL else .pgpin(signer, "signer"),
    .bytes(msg, "msg")
  )
  if (r[[1L]] != 0L) {
    return(NULL)
  }
  list(data = r[[2L]], signed = r[[3L]], at = r[[4L]])
}

#' @rdname nqpgpkeygen
#' @export
nqpgparmor <- function(kind, data) {
  kind <- match.arg(kind, .pgpkinds)
  .rawarg(data, "data")
  .Call(Cpgparm, match(kind, .pgpkinds), data)
}

#' @rdname nqpgpkeygen
#' @export
nqpgpdearmor <- function(text) {
  r <- .Call(Cpgpdearm, .bytes(text, "text"))
  list(kind = .pgpkinds[r$kind], data = r$data)
}

.pgpkinds <- c("message", "public key", "private key", "signature")

# the OpenPGP numbers of the algorithms
.pgpalgs <- c(
  "x25519" = 25L, "ed25519" = 27L, "mldsa65-ed25519" = 30L,
  "slh-shake-128s" = 32L, "slh-shake-128f" = 33L, "slh-shake-256s" = 34L,
  "mlkem768-x25519" = 35L
)

#' The OpenPGP number of an algorithm name; 0 for NULL where allowed.
#' @noRd
.pgpalg <- function(alg, enc) {
  if (enc && is.null(alg)) {
    return(0L)
  }
  ok <- .is1(alg) && tolower(alg) %in% names(.pgpalgs)
  if (!ok) {
    stop(
      sprintf(
        "'%s' must be one of %s", if (enc) "encalg" else "alg",
        toString(names(.pgpalgs))
      ),
      call. = FALSE
    )
  }
  .pgpalgs[[tolower(alg)]]
}

#' The name of an OpenPGP algorithm number.
#' @noRd
.pgpname <- function(id) {
  i <- match(id, .pgpalgs)
  if (is.na(i)) as.character(id) else names(.pgpalgs)[i]
}

#' A passphrase as bytes, or NULL.
#' @noRd
.pgppw <- function(x, what) {
  if (is.null(x)) NULL else .bytes(x, what)
}

#' An OpenPGP key or certificate as packets: armored text is read.
#' @noRd
.pgpin <- function(x, what) {
  x <- .bytes(x, what)
  armored <- length(x) >= 5L && identical(x[1:5], charToRaw("-----"))
  if (armored) .Call(Cpgpdearm, x)$data else x
}
