# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#' Identity cards for a signing key
#'
#' An identity card (`noqtis-idcard-1`, canonical JSON) ties a signing
#' key to who holds it: a name and, when given, an ORCID iD, an e-mail
#' address, a web page and an affiliation, signed by the key itself under
#' the card's own context, so that a card is never taken for a seal or a
#' key statement. `nqidcard()` makes one; `nqidcheck()` checks one.
#'
#' A card is self-signed: it shows that whoever holds the key wrote it and
#' that it is unchanged, not that the name is true. Give the key's SHA-256
#' (`key_sha256`) where people already know you, or let readers pin your
#' public key with `pk`. The key must be post-quantum: Ed25519 alone is
#' refused. `noqtis check --card` names the sealer of a capsule from its
#' card.
#'
#' @param sk,pk The key pair the card is for; for `nqidcheck()`, `pk` is
#'   `NULL` or the public key the card must be for.
#' @param alg Its signature algorithm.
#' @param name Your name: 1 to 255 bytes of text, no control character, no
#'   space at either end.
#' @param orcid `NULL`, or your ORCID iD (`"0000-0002-1825-0097"` or its
#'   `https://orcid.org/` address); its check digit must be right, and the
#'   card holds the bare iD.
#' @param email `NULL`, or an e-mail address (`local@domain.tld`, at most
#'   254 bytes).
#' @param url `NULL`, or an `https://` web page (at most 1024 bytes).
#' @param affil `NULL`, or your affiliation, as `name`.
#' @param at When the card is made: a `POSIXct` time or seconds since 1970
#'   (UTC); default now.
#' @param card A card: a raw vector, or the path of a card file.
#'
#' @return `nqidcard()`: the card, a raw vector (write it with
#'   [writeBin()]). `nqidcheck()`: a list with `name`, `orcid`, `email`,
#'   `url`, `affil` (`NULL` for a field the card has not), `created`,
#'   `alg`, `pk` and `key_sha256` when the card verifies (and is for
#'   `pk`); `NULL` when its signature does not verify or it is for another
#'   key. Input that is not a card is an error.
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' card <- nqidcard(k$sk, k$pk, "ML-DSA-44", "Ada Lovelace",
#'   orcid = "0000-0002-1825-0097")
#' nqidcheck(card, k$pk)$orcid
#' @export
nqidcard <- function(sk, pk, alg, name, orcid = NULL, email = NULL,
                     url = NULL, affil = NULL, at = Sys.time()) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  .Call(Ccard, a$id, sk, pk, .str1(name, "name", FALSE),
        .str1(orcid, "orcid"), .str1(email, "email"), .str1(url, "url"),
        .str1(affil, "affil"), .at(at))
}

#' @rdname nqidcard
#' @export
nqidcheck <- function(card, pk = NULL) {
  if (is.character(card)) {
    if (length(card) != 1L || is.na(card) || !file.exists(card)) {
      stop("'card' must be a raw vector or the path of a card file",
        call. = FALSE)
    }
    n <- file.size(card)
    if (is.na(n) || n > 256 * 1024) {
      stop("'card' is over 256 KiB, larger than any card", call. = FALSE)
    }
    card <- readBin(card, "raw", n = n)
  }
  .rawarg(card, "card")
  if (!is.null(pk)) .rawarg(pk, "pk")
  r <- .Call(Ccardvrfy, card, pk)
  if (r[[1L]] == -4L) {
    stop("'card' is not a noqtis-idcard-1 card", call. = FALSE)
  }
  if (r[[1L]] != 0L) {
    return(NULL)
  }
  f <- r[[2L]]
  opt <- function(s) if (nzchar(s)) s else NULL
  list(
    name = f$name, orcid = opt(f$orcid), email = opt(f$email),
    url = opt(f$url), affil = opt(f$affil), created = f$created,
    alg = f$alg, pk = f$pk, key_sha256 = f$key_sha256
  )
}

.str1 <- function(x, what, null = TRUE) {
  if (null && is.null(x)) {
    return(NULL)
  }
  if (!is.character(x) || length(x) != 1L || is.na(x)) {
    stop(sprintf("'%s' must be %sone string", what,
      if (null) "NULL or " else ""), call. = FALSE)
  }
  enc2utf8(x)
}
