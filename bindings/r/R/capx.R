#' Inspect a capsule, and why a folder cannot be sealed
#'
#' `nqinspect()` reads what the capsule in `dir` says, with nothing
#' checked (no digest, signature, timestamp or file): its format,
#' algorithm, key fingerprint, creation time, number of files and bytes,
#' whether it has a timestamp, and its meta. `nqsealwhy()` says why
#' [nqseal()] refused a folder: the first thing in it a capsule cannot
#' hold.
#'
#' They call the library's `nqinsp()` and `nqsealwhy()` (nqinsp(3),
#' nqseal(3)).
#'
#' @inheritParams nqcapid
#'
#' @return `nqinspect()`: a data frame with columns `check` (`"info.*"`),
#'   `ok` and `detail`. `nqsealwhy()`: `NULL` when nothing in `dir` stops a
#'   seal (the keys given were then not one pair), else a list with `why`
#'   (`"link"`, `"odd"` for a device or pipe, `"name"`, `"case"` for a path
#'   equal to another but for case, or `"key"` for a noqtis secret key
#'   file) and `path`, its path in `dir`.
#'
#' @family capsule functions
#'
#' @examples
#' d <- file.path(tempdir(), "insp")
#' dir.create(d)
#' writeLines("hello", file.path(d, "a.txt"))
#' nqsealwhy(d)
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44")
#' nqinspect(d)
#' unlink(d, recursive = TRUE)
#' @export
nqinspect <- function(dir) .rep(.Call(Cinsp, .dir(dir)))

#' @rdname nqinspect
#' @export
nqsealwhy <- function(dir) {
  r <- .Call(Csealwhy, .dir(dir))
  if (r[[1]] == 0L) {
    return(NULL)
  }
  w <- c("link", "odd", "name", "case", "key")
  # a reason this version has no word for is given by its number
  list(why = c(w, as.character(r[[1]]))[min(r[[1]], length(w) + 1L)],
       path = r[[2]])
}

#' Timestamps and evidence records
#'
#' The library makes no network request: `nqtsreq()` writes the RFC 3161
#' TimeStampReq for a sealed capsule's signature, which the caller sends
#' to a time-stamping authority, and `nqtsput()` checks the authority's
#' reply and stores it as the seal's timestamp. `nqersreq()` and
#' `nqersput()` do the same for the archive timestamps of the capsule's
#' RFC 4998 evidence record (`noqtis.ers`), which keeps the seal provable
#' after its algorithm or the authority's certificate ages: a renewal with
#' the same `hash` renews the timestamp, another `hash` the hash tree.
#'
#' They call the library's `nqtsreq()` and `nqtsput()`, `nqersreq()` and
#' `nqersput()` (nqtsput(3), nqersput(3), which give the request and the
#' imprints in full).
#'
#' @inheritParams nqinspect
#' @param nonce `NULL`, or a nonce of at most 32 bytes (a raw vector),
#'   given again to the `put` function.
#' @param reply The authority's reply (a TimeStampResp or a bare token),
#'   a raw vector.
#' @param anchors `NULL`, or a list of DER certificates (raw vectors) the
#'   authority's certificate must chain to.
#' @param hash `NULL` (the record's hash, SHA-256 for a first one), or
#'   `"sha256"`, `"sha384"` or `"sha512"`.
#'
#' @return `nqtsreq()`, `nqersreq()`: the request, a raw vector.
#'   `nqtsput()`: the time the token gives, as a `POSIXct`. `nqersput()`:
#'   a list with `time` and `how` (`"new"`, `"timestamp"` or
#'   `"hash-tree"`).
#'
#' @section Errors:
#' A reply that does not check (with what failed), a folder that is not
#' sealed.
#'
#' @references
#' Adams, C. et al. (2001). *Internet X.509 Public Key Infrastructure
#' Time-Stamp Protocol (TSP)*, RFC 3161. \doi{10.17487/RFC3161}
#'
#' Gondrom, T., Brandner, R. and Pordesch, U. (2007). *Evidence Record
#' Syntax (ERS)*, RFC 4998. \doi{10.17487/RFC4998}
#'
#' @family capsule functions
#'
#' @examples
#' d <- file.path(tempdir(), "ts")
#' dir.create(d)
#' writeLines("hello", file.path(d, "a.txt"))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44")
#' q <- nqtsreq(d, nonce = as.raw(1:8))
#' length(q)
#' length(nqersreq(d))
#' unlink(d, recursive = TRUE)
#' @export
nqtsreq <- function(dir, nonce = NULL) {
  if (!is.null(nonce)) .rawarg(nonce, "nonce")
  .Call(Ctsreq, .dir(dir), nonce, FALSE, 0L)
}

#' @rdname nqtsreq
#' @export
nqtsput <- function(dir, reply, nonce = NULL, anchors = NULL) {
  if (!is.null(nonce)) .rawarg(nonce, "nonce")
  r <- .Call(
    Ctsput, .dir(dir), .rawarg(reply, "reply"), nonce,
    .anchors(anchors), FALSE, 0L
  )
  as.POSIXct(r[1], origin = "1970-01-01", tz = "UTC")
}

#' @rdname nqtsreq
#' @export
nqersreq <- function(dir, hash = NULL, nonce = NULL) {
  if (!is.null(nonce)) .rawarg(nonce, "nonce")
  .Call(Ctsreq, .dir(dir), nonce, TRUE, if (is.null(hash)) 0L else .hid(hash))
}

#' @rdname nqtsreq
#' @export
nqersput <- function(dir, reply, hash = NULL, nonce = NULL, anchors = NULL) {
  if (!is.null(nonce)) .rawarg(nonce, "nonce")
  r <- .Call(
    Ctsput, .dir(dir), .rawarg(reply, "reply"), nonce,
    .anchors(anchors), TRUE, if (is.null(hash)) 0L else .hid(hash)
  )
  list(time = as.POSIXct(r[1], origin = "1970-01-01", tz = "UTC"),
       how = c("new", "timestamp", "hash-tree")[r[2] + 1])
}

#' Bundles and chains of capsules
#'
#' `nqpack()` writes the capsule in `dir` as one file (noqtis-bundle-1,
#' the format of `noqtis pack`): its seal, manifest, evidence record and
#' every listed file, or with `files = FALSE` only its data record; the
#' same folder gives the same bytes. `nqunpack()` reads a bundle into a
#' new folder, refusing it whole when any path or size is not one a
#' capsule holds. `nqcheckpack()` checks the capsule in a bundle in
#' place: it is unpacked to a temporary folder, checked with [nqcheck()]
#' and removed. `nqchain()` checks an append-only chain of capsules,
#' oldest first: each sealed in format 2 with the one before as its only
#' input, all by the first one's key.
#'
#' They call libnqd's `nqdpack()`, `nqdunpack()` and `nqdchain()`
#' (nqdpack(3), nqdchain(3), which give the bundle's layout and the
#' chain's rules).
#'
#' @inheritParams nqinspect
#' @param file The bundle's path (for `nqpack()`, a file that does not
#'   exist).
#' @param files `TRUE` for every listed file, `FALSE` for the data record
#'   only.
#' @param pk `NULL`, or the public key the seal (or the chain's first
#'   capsule) must carry.
#' @param dirs The chain's capsule folders, oldest first.
#'
#' @return `nqpack()`: `file`, invisibly. `nqunpack()`: `dir`, invisibly.
#'   `nqcheckpack()`: as [nqcheck()]. `nqchain()`: a data frame of the
#'   `link`, `key` and `head` rows with the attributes `"ok"` and
#'   `"head"` (the last capsule's id, a raw vector, when every row
#'   passed, else `NULL`).
#'
#' @section Errors:
#' A bundle that is cut, out of order or names a path a capsule cannot
#' hold; an existing output.
#'
#' @family capsule functions
#'
#' @examples
#' d <- file.path(tempdir(), "pk")
#' dir.create(d)
#' writeLines("hello", file.path(d, "a.txt"))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44")
#' b <- tempfile(fileext = ".nqb")
#' nqpack(d, b)
#' attr(nqcheckpack(b, k$pk), "ok")
#' u <- file.path(tempdir(), "pku")
#' nqunpack(b, u)
#' list.files(u)
#' unlink(c(d, u), recursive = TRUE)
#' unlink(b)
#' @export
nqpack <- function(dir, file, files = TRUE) {
  if (!.flag1(files)) stop("'files' must be TRUE or FALSE", call. = FALSE)
  .path1(file, "file")
  .Call(Cdpack, .dir(dir), files, enc2native(file))
  invisible(file)
}

#' @rdname nqpack
#' @export
nqunpack <- function(file, dir) {
  .bundle1(file)
  .path1(dir, "dir")
  .Call(Cdunpack, file, dir, FALSE)
  invisible(dir)
}

#' @rdname nqpack
#' @export
nqcheckpack <- function(file, pk = NULL) {
  .bundle1(file)
  t <- tempfile("noqtis")
  .Call(Cdunpack, file, t, FALSE)
  on.exit(.Call(Cdunpack, file, t, TRUE), add = TRUE)
  nqcheck(t, pk)
}

#' @rdname nqpack
#' @export
nqchain <- function(dirs, pk = NULL) {
  if (!is.character(dirs) || length(dirs) == 0L || anyNA(dirs)) {
    stop("'dirs' must name capsule folders", call. = FALSE)
  }
  if (!is.null(pk)) .rawarg(pk, "pk")
  ds <- vapply(dirs, .dir, "")
  r <- .Call(Cdchain, unname(ds), pk)
  out <- .drep(r[[1]])
  attr(out, "head") <- if (isTRUE(attr(out, "ok"))) r[[2]] else NULL
  out
}

#' The path of one existing bundle file, or an error.
#' @param file What the caller gave.
#' @noRd
.bundle1 <- function(file) {
  if (!.file1(file)) stop("'file' must be one existing bundle", call. = FALSE)
  file
}
