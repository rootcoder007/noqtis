# SPDX-License-Identifier: LGPL-3.0-or-later

#' Text armor
#'
#' `nqarmor()` writes bytes as text (RFC 7468): a `-----BEGIN label-----`
#' line, base64 in lines of 64 characters, and the END line.
#' `nqdearmor()` reads one armor back.
#'
#' They call the library's `nqarmlen()`, `nqarmenc()` and `nqarmdec()`
#' (nqarmenc(3)).
#'
#' @param label The label: capitals and digits with single spaces
#'   between them, such as `"NOQTIS SIGNATURE"`.
#' @param data A raw vector.
#' @param text The armored text: one string, or a raw vector.
#'
#' @return `nqarmor()`: one string. `nqdearmor()`: a list with `label`
#'   and `data` (a raw vector). Text that is not exactly one well-formed
#'   armor is an error.
#'
#' @family mail and key functions
#' @examples
#' a <- nqarmor("NOQTIS TEST", as.raw(1:40))
#' cat(a)
#' nqdearmor(a)$label
#' @export
nqarmor <- function(label, data) {
  .rawarg(data, "data")
  .Call(Carmor, .str1(label, "label", FALSE), data)
}

#' @rdname nqarmor
#' @export
nqdearmor <- function(text) {
  .Call(Cdearmor, .bytes(text, "text"))
}

#' X.509 certificates for noqtis keys
#'
#' `nqcert()` makes a self-signed X.509 certificate for a signature key:
#' give it to those who are to trust the key. `nqkemcert()` makes one for
#' an ML-KEM public key, issued by a signature key under the name of its
#' own certificate: what others encrypt to. `nqcertinfo()` reads what a
#' certificate says.
#'
#' The self-signed certificate is a certification authority of path
#' length 0, so that it can issue the certificate of the holder's ML-KEM
#' key. Certificates are DER; [nqarmor()] with the label `"CERTIFICATE"`
#' makes the PEM form.
#'
#' They call the library's `nqx5self()`, `nqx5kem()` and `nqx5info()`
#' (nqx5self(3)).
#'
#' @param sk,pk The signature key pair (ML-DSA, SLH-DSA or Ed25519).
#' @param alg The algorithm of the key the certificate is for.
#' @param name The holder's name.
#' @param email The holder's address, or `NULL`.
#' @param notbefore,notafter The time the certificate is valid from and
#'   to: a `POSIXct` time or seconds since 1970.
#' @param issuersk,issueralg,issuercert The issuer's secret signature
#'   key, its algorithm, and its certificate from `nqcert()`.
#' @param cert A certificate (DER), a raw vector.
#'
#' @return `nqcert()` and `nqkemcert()`: the certificate, a raw vector.
#'   `nqcertinfo()`: a list with `alg` (`""` for a key noqtis does not
#'   have), `kem`, `fingerprint` (SHA-256 of the certificate),
#'   `notbefore`, `notafter`, `ca`, `name`, `email` and `pk`.
#'
#' @family mail and key functions
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' cert <- nqcert(k$sk, k$pk, "ML-DSA-44", "Ada Example",
#'   email = "ada@example.org"
#' )
#' nqcertinfo(cert)$name
#' e <- nqkeygen("ML-KEM-768")
#' kc <- nqkemcert(k$sk, "ML-DSA-44", cert, e$pk, "ML-KEM-768")
#' nqcertinfo(kc)$kem
#' @export
nqcert <- function(sk, pk, alg, name, email = NULL,
                   notbefore = Sys.time(),
                   notafter = Sys.time() + 730 * 86400) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  .Call(
    Cx5self, a$id, sk, pk, .str1(name, "name", FALSE),
    .str1(email, "email"), .at(notbefore), .at(notafter)
  )
}

#' @rdname nqcert
#' @export
nqkemcert <- function(issuersk, issueralg, issuercert, pk, alg,
                      notbefore = Sys.time(),
                      notafter = Sys.time() + 730 * 86400) {
  ia <- .alg(issueralg, "sig")
  a <- .alg(alg, "kem")
  .rawarg(issuersk, "issuersk")
  .rawarg(issuercert, "issuercert")
  .rawarg(pk, "pk")
  .Call(
    Cx5kem, ia$id, issuersk, issuercert, a$id, pk, .at(notbefore),
    .at(notafter)
  )
}

#' @rdname nqcert
#' @export
nqcertinfo <- function(cert) {
  .rawarg(cert, "cert")
  .Call(Cx5info, cert)
}

#' Signed and encrypted messages (CMS and S/MIME)
#'
#' The Cryptographic Message Syntax (RFC 5652) with post-quantum keys,
#' and the same as mail (S/MIME, RFC 8551). `nqcmssign()` signs with a
#' signature key and its certificate; `nqcmsverify()` checks against
#' certificates the caller trusts. `nqcmsencrypt()` encrypts to ML-KEM
#' certificates (AuthEnvelopedData, AES-256-GCM; RFC 9629 and RFC 9936);
#' `nqcmsdecrypt()` opens with the secret key of one of them. The
#' `nqsmime*()` functions do the same with a MIME entity (header lines,
#' an empty line, the body) and write an S/MIME message.
#'
#' Verification trusts a signer only when its certificate is one of
#' `anchors`, byte for byte.
#'
#' They call the library's `nqcmssign()`, `nqcmsvrfy()`, `nqcmsenc()` and
#' `nqcmsdec()`, and for S/MIME `nqsmsign()`, `nqsmvrfy()`, `nqsmenc()`
#' and `nqsmdec()` (nqcmssign(3), nqsmsign(3)).
#'
#' @param sk The secret key: a signature key to sign, an ML-KEM key to
#'   decrypt.
#' @param cert The certificate of `sk`; to decrypt, `NULL` or the
#'   certificate that names the recipient to use.
#' @param msg The content, a raw vector; for `nqcmsverify()`, the content
#'   of a detached signature, or `NULL`.
#' @param alg The algorithm of `sk`.
#' @param detached `TRUE` to leave the content out of the signature (for
#'   S/MIME: `multipart/signed`, which keeps the entity readable).
#' @param at The signing time, or when to judge the certificates' dates:
#'   a `POSIXct` time or seconds since 1970.
#' @param cms A SignedData or AuthEnvelopedData (DER), a raw vector.
#' @param anchors A list of trusted certificates (raw vectors).
#' @param certs A list of the recipients' ML-KEM certificates.
#' @param entity A MIME entity: one string, or a raw vector.
#' @param mime An S/MIME message: one string, or a raw vector.
#'
#' @return `nqcmssign()`, `nqcmsencrypt()`: a raw vector (DER).
#'   `nqsmimesign()`, `nqsmimeencrypt()`: one string. `nqcmsverify()`,
#'   `nqsmimeverify()`: a list with `content` (for S/MIME `entity`, a
#'   string) and `signer` (as [nqcertinfo()] gives), or `NULL` when the
#'   signature does not verify or the signer is not an anchor.
#'   `nqcmsdecrypt()`: the content, a raw vector (`nqsmimedecrypt()`:
#'   the entity, a string), or `NULL` when the message is not for this
#'   key or was changed.
#'
#' @family mail and key functions
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' cert <- nqcert(k$sk, k$pk, "ML-DSA-44", "Ada Example")
#' s <- nqcmssign(k$sk, cert, charToRaw("hello"), "ML-DSA-44")
#' v <- nqcmsverify(s, list(cert))
#' rawToChar(v$content)
#' v$signer$name
#'
#' e <- nqkeygen("ML-KEM-768")
#' kc <- nqkemcert(k$sk, "ML-DSA-44", cert, e$pk, "ML-KEM-768")
#' m <- nqsmimeencrypt(list(kc), "Content-Type: text/plain\r\n\r\nhi\r\n")
#' nqsmimedecrypt(e$sk, m, "ML-KEM-768")
#' @export
nqcmssign <- function(sk, cert, msg, alg, detached = FALSE,
                      at = Sys.time()) {
  .cmssign(sk, cert, .rawarg(msg, "msg"), alg, detached, at, FALSE)
}

#' @rdname nqcmssign
#' @export
nqcmsverify <- function(cms, anchors, msg = NULL, at = Sys.time()) {
  .rawarg(cms, "cms")
  if (!is.null(msg)) .rawarg(msg, "msg")
  r <- .Call(Ccmsvrfy, cms, msg, .certs(anchors, "anchors"), .at(at), FALSE)
  if (r[[1L]] != 0L) {
    return(NULL)
  }
  list(content = r[[2L]], signer = r[[3L]])
}

#' @rdname nqcmssign
#' @export
nqcmsencrypt <- function(certs, msg) {
  .rawarg(msg, "msg")
  .Call(Ccmsenc, .certs(certs, "certs"), msg, FALSE)
}

#' @rdname nqcmssign
#' @export
nqcmsdecrypt <- function(sk, cms, alg, cert = NULL) {
  .cmsdec(sk, .rawarg(cms, "cms"), alg, cert, FALSE)
}

#' @rdname nqcmssign
#' @export
nqsmimesign <- function(sk, cert, entity, alg, detached = FALSE,
                        at = Sys.time()) {
  rawToChar(.cmssign(
    sk, cert, .bytes(entity, "entity"), alg, detached, at, TRUE
  ))
}

#' @rdname nqcmssign
#' @export
nqsmimeverify <- function(mime, anchors, at = Sys.time()) {
  r <- .Call(
    Ccmsvrfy, .bytes(mime, "mime"), NULL, .certs(anchors, "anchors"),
    .at(at), TRUE
  )
  if (r[[1L]] != 0L) {
    return(NULL)
  }
  list(entity = .utf8(r[[2L]]), signer = r[[3L]])
}

#' @rdname nqcmssign
#' @export
nqsmimeencrypt <- function(certs, entity) {
  rawToChar(.Call(
    Ccmsenc, .certs(certs, "certs"), .bytes(entity, "entity"), TRUE
  ))
}

#' @rdname nqcmssign
#' @export
nqsmimedecrypt <- function(sk, mime, alg, cert = NULL) {
  r <- .cmsdec(sk, .bytes(mime, "mime"), alg, cert, TRUE)
  if (is.null(r)) NULL else .utf8(r)
}

#' nqcmssign and nqsmimesign: the checks and the call.
#' @noRd
.cmssign <- function(sk, cert, msg, alg, detached, at, mime) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(cert, "cert")
  if (!.flag1(detached)) {
    stop("'detached' must be TRUE or FALSE", call. = FALSE)
  }
  .Call(Ccmssign, a$id, sk, cert, msg, detached, .at(at), mime)
}

#' nqcmsdecrypt and nqsmimedecrypt: NULL when it does not open.
#' @noRd
.cmsdec <- function(sk, cms, alg, cert, mime) {
  a <- .alg(alg, "kem")
  .rawarg(sk, "sk")
  if (!is.null(cert)) .rawarg(cert, "cert")
  r <- .Call(Ccmsdec, a$id, sk, cert, cms, mime)
  if (r[[1L]] != 0L) NULL else r[[2L]]
}

#' A list of raw vectors (one raw vector is a list of one).
#' @noRd
.certs <- function(x, what) {
  if (is.raw(x)) x <- list(x)
  ok <- is.list(x) && all(vapply(x, is.raw, logical(1L)))
  if (!ok) {
    stop(sprintf("'%s' must be a list of raw vectors", what), call. = FALSE)
  }
  unname(x)
}

#' Raw bytes as one UTF-8 string.
#' @noRd
.utf8 <- function(x) {
  s <- rawToChar(x)
  Encoding(s) <- "UTF-8"
  s
}
