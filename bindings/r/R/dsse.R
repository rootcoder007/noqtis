#' DSSE envelopes
#'
#' `nqdsse()` wraps a payload in a DSSE envelope (the in-toto and SLSA
#' signing wrapper), signed with any signature algorithm of [nqalgs()]
#' over the envelope's pre-authentication encoding, as canonical JSON with
#' `payload`, `payloadType` and one signature whose `keyid` is the hex
#' SHA-256 of `pk`. `nqdsseverify()` checks one.
#'
#' @param sk,pk The key pair (`nqdsse()`), or the public key to check
#'   with (`nqdsseverify()`).
#' @param payload The payload: a raw vector, or one string, taken as its
#'   UTF-8 bytes.
#' @param type The payload type, 1 to 255 printable ASCII characters with
#'   no space, quote or backslash, such as
#'   `"application/vnd.in-toto+json"`.
#' @param alg Signature algorithm name.
#' @param env The envelope: a raw vector, or one string.
#'
#' @return `nqdsse()`: the envelope, a raw vector. `nqdsseverify()`: a
#'   list with `type` and `payload` (a raw vector) when one of the
#'   envelope's signatures verifies under `pk`, `NULL` when none does; an
#'   error when `env` is not an envelope.
#'
#' @examples
#' k <- nqkeygen("ML-DSA-65")
#' e <- nqdsse(k$sk, k$pk, '{"a":1}', "application/json", "ML-DSA-65")
#' v <- nqdsseverify(k$pk, e, "ML-DSA-65")
#' rawToChar(v$payload)
#' @export
nqdsse <- function(sk, pk, payload, type, alg) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  if (!is.character(type) || length(type) != 1L || is.na(type)) {
    stop("'type' must be one string", call. = FALSE)
  }
  .Call(Cdsse, a$id, sk, pk, enc2utf8(type), .bytes(payload, "payload"))
}

#' @rdname nqdsse
#' @export
nqdsseverify <- function(pk, env, alg) {
  a <- .alg(alg, "sig")
  .rawarg(pk, "pk")
  r <- .Call(Cdssevrfy, a$id, pk, .bytes(env, "env"))
  if (r[[1]] == -4L) {
    stop("noqtis: nqdssevrfy: not a DSSE envelope", call. = FALSE)
  }
  if (r[[1]] != 0L) {
    return(NULL)
  }
  list(type = r[[2]], payload = r[[3]])
}
