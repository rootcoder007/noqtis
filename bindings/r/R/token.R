# SPDX-License-Identifier: LGPL-3.0-or-later

#' Keys on a token (PKCS #11)
#'
#' Signing and decapsulating with private keys that stay on a token: a
#' smart card, a hardware security module, or a software token.
#' `nqtoken()` loads the PKCS #11 module the token's maker ships;
#' `nqtokens()` lists the tokens present; `nqtokenlogin()` opens a
#' session and gives the PIN; `nqtokenkeys()` lists the private keys
#' noqtis can use; `nqtokenpub()` gives a key's public key;
#' `nqtokensign()` signs; `nqtokendecap()` decapsulates;
#' `nqtokenkeygen()` makes a key pair on the token; `nqtokenclose()`
#' ends the session and unloads the module.
#'
#' The key types are those of PKCS #11 version 3.2 (ML-DSA, SLH-DSA and
#' ML-KEM) and Ed25519. A signature made on a token is the one
#' [nqsign()] makes, and [nqverify()] checks it; decapsulation needs a
#' module of version 3.2.
#'
#' They call the library's `nqp11open()`, `nqp11close()`, `nqp11toks()`,
#' `nqp11login()`, `nqp11keys()`, `nqp11pub()`, `nqp11sign()`,
#' `nqp11dec()` and `nqp11gen()` (nqp11open(3)).
#'
#' @param module The path of the PKCS #11 module (a shared library). It
#'   must have a folder in it: a bare name, which the system would
#'   search for, is refused.
#' @param token A token from `nqtoken()`.
#' @param slot The slot of the token, from `nqtokens()`.
#' @param pin The PIN, one string, or `NULL` for a session without
#'   login.
#' @param key One row of `nqtokenkeys()`.
#' @param msg The message, a raw vector.
#' @param ctx The context: a raw vector or one string of at most 255
#'   bytes, or `NULL`.
#' @param ct An ML-KEM ciphertext, a raw vector.
#' @param alg The algorithm of the new key.
#' @param label The label of the new key, 1 to 64 bytes.
#'
#' @return `nqtoken()`: a token. `nqtokens()`: a data frame with
#'   `slot`, `label`, `maker`, `model`, `serial` and `login` (the keys
#'   need the PIN). `nqtokenkeys()` and `nqtokenkeygen()`: a data frame
#'   with `alg`, `kem`, `label`, `id` (hexadecimal) and `handle`.
#'   `nqtokenpub()`, `nqtokensign()`, `nqtokendecap()`: a raw vector.
#'   `nqtokenlogin()`, `nqtokenclose()`: `NULL`, invisibly.
#'
#' @family mail and key functions
#' @examples
#' \dontrun{
#' t <- nqtoken("/usr/lib/softhsm/libsofthsm2.so")
#' nqtokenlogin(t, nqtokens(t)$slot[1], "1234")
#' k <- nqtokenkeygen(t, "ML-DSA-65", "release")
#' sig <- nqtokensign(t, k, charToRaw("a release"))
#' nqverify(nqtokenpub(t, k), charToRaw("a release"), sig, "ML-DSA-65")
#' nqtokenclose(t)
#' }
#' @export
nqtoken <- function(module) {
  if (!.is1(module) || !nzchar(module)) {
    stop("'module' must be the path of a PKCS #11 module", call. = FALSE)
  }
  structure(
    list(ptr = .Call(Cp11open, path.expand(module))),
    class = "nqtoken"
  )
}

#' @rdname nqtoken
#' @export
nqtokenclose <- function(token) {
  invisible(.Call(Cp11close, .tokptr(token)))
}

#' @rdname nqtoken
#' @export
nqtokens <- function(token) {
  r <- .Call(Cp11toks, .tokptr(token))
  data.frame(
    slot = r[[1L]], label = r[[2L]], maker = r[[3L]], model = r[[4L]],
    serial = r[[5L]], login = r[[6L]], stringsAsFactors = FALSE
  )
}

#' @rdname nqtoken
#' @export
nqtokenlogin <- function(token, slot, pin = NULL) {
  if (!is.numeric(slot) || length(slot) != 1L || is.na(slot)) {
    stop("'slot' must be one slot number", call. = FALSE)
  }
  invisible(.Call(
    Cp11login, .tokptr(token), as.double(slot), .str1(pin, "pin")
  ))
}

#' @rdname nqtoken
#' @export
nqtokenkeys <- function(token) {
  .tokkeys(.Call(Cp11keys, .tokptr(token)))
}

#' @rdname nqtoken
#' @export
nqtokenpub <- function(token, key) {
  .tokuse(token, 0L, key, NULL, NULL)
}

#' @rdname nqtoken
#' @export
nqtokensign <- function(token, key, msg, ctx = NULL) {
  .rawarg(msg, "msg")
  if (!is.null(ctx)) ctx <- .bytes(ctx, "ctx")
  .tokuse(token, 1L, key, msg, ctx)
}

#' @rdname nqtoken
#' @export
nqtokendecap <- function(token, key, ct) {
  .tokuse(token, 2L, key, .rawarg(ct, "ct"), NULL)
}

#' @rdname nqtoken
#' @export
nqtokenkeygen <- function(token, alg, label) {
  type <- .kind(alg)
  a <- .alg(alg, type)
  .tokkeys(.Call(
    Cp11gen, .tokptr(token), type == "kem", a$id,
    .str1(label, "label", FALSE)
  ))
}

#' @export
print.nqtoken <- function(x, ...) {
  cat("<noqtis token: a PKCS #11 module>\n")
  invisible(x)
}

#' The pointer of a token object.
#' @noRd
.tokptr <- function(token) {
  if (!inherits(token, "nqtoken")) {
    stop("'token' must be a token from nqtoken()", call. = FALSE)
  }
  token$ptr
}

#' Keys from the C side as a data frame.
#' @noRd
.tokkeys <- function(r) {
  type <- ifelse(r[[1L]], "kem", "sig")
  alg <- mapply(
    function(id, t) .algid(id, t)$name, r[[2L]], type,
    USE.NAMES = FALSE
  )
  data.frame(
    alg = as.character(alg), kem = r[[1L]], label = r[[4L]],
    id = vapply(r[[5L]], .hex, character(1L)), handle = r[[3L]],
    stringsAsFactors = FALSE
  )
}

#' One operation with a key of the token.
#' @noRd
.tokuse <- function(token, op, key, data, ctx) {
  ok <- is.data.frame(key) && nrow(key) == 1L &&
    all(c("alg", "kem", "id", "handle") %in% names(key))
  if (!ok) {
    stop("'key' must be one row of nqtokenkeys()", call. = FALSE)
  }
  type <- if (key$kem) "kem" else "sig"
  i <- seq(1L, max(nchar(key$id) - 1L, 1L), by = 2L)
  id <- if (nzchar(key$id)) {
    as.raw(strtoi(substring(key$id, i, i + 1L), 16L))
  } else {
    raw(0)
  }
  .Call(
    Cp11use, .tokptr(token), op, key$kem, .alg(key$alg, type)$id,
    as.double(key$handle), id, data, ctx
  )
}
