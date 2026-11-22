# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#' A store of public keys
#'
#' A folder of other people's public keys under their names and
#' addresses, with certifications of them and how far each owner is
#' trusted. `nqksadd()` puts a key in; `nqkslist()` lists and finds;
#' `nqksget()` gives a key back; `nqkscertify()` signs that a key
#' belongs to its name; `nqksaddcert()` takes a certification someone
#' else made; `nqkstrust()` sets the trust in an owner; `nqksdel()`
#' removes a key; `nqksexport()` and `nqksimport()` carry a signature key
#' with its identity card, and the keys it certified as its own, from one
#' store to another; `nqksurl()` is where the
#' keys of an address are looked for.
#'
#' A key is valid when its owner is trusted `"ultimate"` (the store
#' owner's own keys), or when one valid key trusted `"full"` certified
#' it, or three trusted `"marginal"`. The store is a plain folder that
#' nothing signs: keep it where only you can write.
#'
#' They call the library's `nqksadd()`, `nqkslist()`, `nqksget()`,
#' `nqkscert()`, `nqkscput()`, `nqkstrust()`, `nqksdel()`, `nqksexp()`,
#' `nqksimp()` and `nqksurl()` (nqksadd(3), which gives the certification
#' and the rules of validity in full).
#'
#' @param dir The folder of the store; it must exist.
#' @param pk A public key, a raw vector; for `nqkscertify()`, the public
#'   key of `sk`.
#' @param alg The algorithm of the key.
#' @param name The name to keep the key under; `NULL` with `card`, which
#'   then says who the key is.
#' @param email Its address, or `NULL`. For `nqksimport()`, the address
#'   the keys of the bundle must be for, or `NULL`; for `nqksurl()`, the
#'   address to look up.
#' @param card Its identity card ([nqidcard()]), or `NULL`. A key added
#'   with its card takes its name and address from the card.
#' @param query `NULL` for every key, or a name, an address or the start
#'   of a fingerprint in hexadecimal.
#' @param fingerprint The key: a raw vector of 32 bytes (SHA-256 of the
#'   public key), as `nqksadd()` returns and `nqkslist()` lists.
#' @param sk The secret signature key that certifies.
#' @param at When the certification is made: a `POSIXct` time or seconds
#'   since 1970.
#' @param cert A certification: one string, as `nqkscertify()` returns.
#' @param level `"unknown"`, `"never"`, `"marginal"`, `"full"` or
#'   `"ultimate"`.
#' @param bundle A bundle: one string, as `nqksexport()` returns.
#'
#' @return `nqksadd()`: the key's fingerprint. `nqkslist()`: a data
#'   frame with `alg`, `kem`, `fingerprint` (hexadecimal), `name`,
#'   `email`, `card`, `trust`, `valid` (`"none"`, `"marginal"` or
#'   `"full"`) and `certs`, and the attribute `"fingerprints"`, a list
#'   of the raw fingerprints. `nqksget()`: a list with `alg` and `pk`.
#'   `nqkscertify()`, `nqksexport()`, `nqksurl()`: one string.
#'   `nqksimport()`: a list with `fingerprint` (of the first key) and
#'   `keys` (how many came in). The others: `NULL`, invisibly.
#'
#' @family mail and key functions
#' @examples
#' d <- file.path(tempdir(), "nqkeys")
#' dir.create(d)
#' me <- nqkeygen("ML-DSA-44")
#' bob <- nqkeygen("ML-KEM-768")
#' card <- nqidcard(me$sk, me$pk, "ML-DSA-44", "Me", email = "me@example.org")
#' mine <- nqksadd(d, me$pk, "ML-DSA-44", card = card)
#' his <- nqksadd(d, bob$pk, "ML-KEM-768", "Bob", "bob@example.org")
#' nqkstrust(d, mine, "ultimate")
#' cert <- nqkscertify(d, me$sk, me$pk, "ML-DSA-44", his)
#' nqkslist(d, "bob@example.org")$valid
#' nqksurl("bob@example.org")
#' unlink(d, recursive = TRUE)
#' @export
nqksadd <- function(dir, pk, alg, name = NULL, email = NULL, card = NULL) {
  type <- .kind(alg)
  a <- .alg(alg, type)
  .rawarg(pk, "pk")
  if (!is.null(card)) .rawarg(card, "card")
  .Call(
    Cksadd, .ksdir(dir), type == "kem", a$id, pk,
    .str1(name, "name", !is.null(card)), .str1(email, "email"), card
  )
}

#' @rdname nqksadd
#' @export
nqkslist <- function(dir, query = NULL) {
  r <- .Call(Ckslist, .ksdir(dir), .str1(query, "query"))
  type <- ifelse(r[[1L]], "kem", "sig")
  alg <- mapply(
    function(id, t) .algid(id, t)$name, r[[2L]], type,
    USE.NAMES = FALSE
  )
  out <- data.frame(
    alg = as.character(alg), kem = r[[1L]],
    fingerprint = vapply(r[[3L]], .hex, character(1L)),
    name = r[[4L]], email = r[[5L]], card = r[[6L]],
    trust = .kstrust[r[[7L]] + 1L],
    valid = c("none", "marginal", "full")[r[[8L]] + 1L],
    certs = r[[9L]], stringsAsFactors = FALSE
  )
  attr(out, "fingerprints") <- r[[3L]]
  out
}

#' @rdname nqksadd
#' @export
nqksget <- function(dir, fingerprint) {
  r <- .Call(Cksget, .ksdir(dir), .ksfp(fingerprint))
  type <- if (r$kem) "kem" else "sig"
  list(alg = .algid(r$alg, type)$name, pk = r$pk)
}

#' @rdname nqksadd
#' @export
nqkscertify <- function(dir, sk, pk, alg, fingerprint, at = Sys.time()) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  .Call(Ckscert, .ksdir(dir), a$id, sk, pk, .ksfp(fingerprint), .at(at))
}

#' @rdname nqksadd
#' @export
nqksaddcert <- function(dir, cert) {
  invisible(.Call(Cksop, 0L, .ksdir(dir), .bytes(cert, "cert"), 0L))
}

#' @rdname nqksadd
#' @export
nqkstrust <- function(dir, fingerprint,
                      level = c(
                        "unknown", "never", "marginal", "full", "ultimate"
                      )) {
  level <- match.arg(level)
  invisible(.Call(
    Cksop, 1L, .ksdir(dir), .ksfp(fingerprint),
    match(level, .kstrust) - 1L
  ))
}

#' @rdname nqksadd
#' @export
nqksdel <- function(dir, fingerprint) {
  invisible(.Call(Cksop, 2L, .ksdir(dir), .ksfp(fingerprint), 0L))
}

#' @rdname nqksadd
#' @export
nqksexport <- function(dir, fingerprint) {
  .Call(Cksexp, .ksdir(dir), .ksfp(fingerprint))
}

#' @rdname nqksadd
#' @export
nqksimport <- function(dir, bundle, email = NULL) {
  .Call(
    Cksimp, .ksdir(dir), .bytes(bundle, "bundle"), .str1(email, "email")
  )
}

#' @rdname nqksadd
#' @export
nqksurl <- function(email) {
  .Call(Cksurl, .str1(email, "email", FALSE))
}

.kstrust <- c("unknown", "never", "marginal", "full", "ultimate")

#' The folder of a store: one path, expanded.
#' @noRd
.ksdir <- function(dir) {
  if (!.is1(dir) || !nzchar(dir)) {
    stop("'dir' must be the path of one folder", call. = FALSE)
  }
  path.expand(dir)
}

#' A fingerprint: 32 raw bytes, or 64 hexadecimal digits.
#' @noRd
.ksfp <- function(fp) {
  if (.is1(fp) && grepl("^[0-9a-fA-F]{64}$", fp)) {
    i <- seq(1L, 63L, by = 2L)
    fp <- as.raw(strtoi(substring(fp, i, i + 1L), 16L))
  }
  if (!is.raw(fp) || length(fp) != 32L) {
    stop(
      "'fingerprint' must be 32 raw bytes or 64 hexadecimal digits",
      call. = FALSE
    )
  }
  fp
}
