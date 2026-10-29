#' Seal and check a capsule
#'
#' A capsule is a signed record of the exact files in a folder.
#' `nqseal()` writes `noqtis.json` (the manifest: every regular file with
#' its size, SHA-256 and SHA3-256) and `noqtis.sig` (the signature over the
#' manifest) into the folder. `nqcheck()` checks a folder against its seal
#' and reports every check.
#'
#' The creation time in the manifest is the `SOURCE_DATE_EPOCH`
#' environment variable when set, else the clock. Sealing refuses a folder
#' that holds a symbolic link or a special file. Capsules are the same
#' files the `noqtis` command-line tool writes and checks.
#'
#' The library makes no network requests: an RFC 3161 timestamp is added
#' to a seal by other tools, and `nqcheck()` verifies it when `anchors` is
#' given.
#'
#' @param dir Path of the folder.
#' @param sk Secret key, a raw vector (as from [nqkeygen()]).
#' @param pk Public key, a raw vector; for `nqseal()` it must pair with `sk`
#'   and is written into the seal; for `nqcheck()`, `NULL` accepts the key
#'   in the seal (the `key` row then says so), otherwise the seal must be
#'   made with this key.
#' @param alg Signature algorithm name, one of the `"sig"` rows of
#'   [nqalgs()].
#' @param meta `NULL`, or one string of JSON text (an object) stored in
#'   the manifest under `"meta"`.
#' @param anchors `NULL`, or a list of up to 32 raw vectors, DER encoded
#'   certificates of trusted timestamp authorities; the seal must then
#'   carry an RFC 3161 timestamp token that verifies under one of them.
#'
#' @return `nqseal()`: the paths of the two files written, invisibly.
#'   `nqcheck()`: a data frame with one row per check and the columns
#'   `check`, `ok` (logical) and `detail`; its attribute `"ok"` is `TRUE`
#'   only when every check passed.
#'
#' @examples
#' d <- file.path(tempdir(), "capsule")
#' dir.create(d)
#' writeLines("hello", file.path(d, "a.txt"))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = '{"project":"demo"}')
#' r <- nqcheck(d, k$pk)
#' r
#' attr(r, "ok")
#' writeLines("hellO", file.path(d, "a.txt"))
#' attr(nqcheck(d, k$pk), "ok")
#' unlink(d, recursive = TRUE)
#' @export
nqseal <- function(dir, sk, pk, alg, meta = NULL) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  if (!is.null(meta) &&
    (!is.character(meta) || length(meta) != 1L || is.na(meta))) {
    stop("'meta' must be NULL or one string of JSON text", call. = FALSE)
  }
  d <- .dir(dir)
  .Call(Cseal, d, a$id, sk, pk, meta)
  invisible(file.path(dir, c("noqtis.json", "noqtis.sig")))
}

#' @rdname nqseal
#' @export
nqcheck <- function(dir, pk = NULL, anchors = NULL) {
  if (!is.null(pk)) .rawarg(pk, "pk")
  if (!is.null(anchors)) {
    if (is.raw(anchors)) anchors <- list(anchors)
    if (!is.list(anchors) || !all(vapply(anchors, is.raw, NA))) {
      stop("'anchors' must be a list of raw vectors", call. = FALSE)
    }
    if (length(anchors) == 0L) anchors <- NULL
  }
  d <- .dir(dir)
  r <- .Call(Cchk, d, pk, anchors)
  out <- data.frame(check = r[[2]], ok = r[[3]], detail = r[[4]],
    stringsAsFactors = FALSE)
  attr(out, "ok") <- r[[1]] == 0L && nrow(out) > 0L && all(out$ok)
  out
}
