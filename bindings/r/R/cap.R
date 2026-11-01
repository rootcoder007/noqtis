#' Seal and check a capsule
#'
#' A capsule is a signed record of the exact files in a folder.
#' `nqseal()` writes `noqtis.json` (the manifest: every regular file with
#' its size, SHA-256 and SHA3-256) and `noqtis.sig` (the signature over the
#' manifest) into the folder. `nqcheck()` checks a folder against its seal
#' and reports every check.
#'
#' The manifest is canonical JSON (RFC 8785): its bytes, and so its
#' signature, depend only on the files. The creation time in the manifest
#' is the `SOURCE_DATE_EPOCH` environment variable when set, else the
#' clock. Sealing refuses a folder that holds a symbolic link, a special
#' file, a refused name (a control character, a backslash or a colon, or
#' invalid UTF-8), two paths that differ only in case, or a file that
#' starts like a noqtis secret key. Capsules are the same files the
#' `noqtis` command-line tool writes and checks.
#'
#' `nqcheck()` fails closed: anything it cannot check is a failed row,
#' never a silent pass. A file changed, added, removed or renamed, a
#' manifest or seal that is not canonical, a signature that does not
#' verify, or a key other than `pk` each fail their row; the attribute
#' `"ok"` is `TRUE` only when every row passed. Without `pk`, the key in
#' the seal is accepted and the `key` row says so: that shows the folder
#' is as someone sealed it, not who.
#'
#' The library makes no network requests: an RFC 3161 timestamp, or an
#' RFC 4998 evidence record, is added to a seal by the command-line tool
#' (`noqtis timestamp`, `noqtis ers`), and `nqcheck()` verifies them when
#' `anchors` is given.
#'
#' @param dir Path of the folder.
#' @param sk Secret key, a raw vector (as from [nqkeygen()]).
#' @param pk Public key, a raw vector; for `nqseal()` it must pair with `sk`
#'   and is written into the seal; for `nqcheck()`, `NULL` accepts the key
#'   in the seal (the `key` row then says so), otherwise the seal must be
#'   made with this key.
#' @param alg Signature algorithm name, one of the `"sig"` rows of
#'   [nqalgs()]; Ed25519 alone is refused, as it is not post-quantum.
#' @param meta `NULL`, or one string of JSON text (an object) stored in
#'   the manifest under `"meta"`.
#' @param anchors `NULL`, or a list of up to 32 raw vectors, DER encoded
#'   certificates of trusted timestamp authorities; the seal must then
#'   carry an RFC 3161 timestamp token that verifies under one of them,
#'   and an evidence record, when the folder has one, must verify too.
#' @param format `1` (the default) or `2`. Format 2 adds a Merkle tree over
#'   the files to the manifest and signs its head, so that [nqprove()] can
#'   show some files without the others.
#' @param inputs `NULL`, or the folders of the capsules this one was made
#'   from (format 2, the default with it). Each is recorded by its id
#'   ([nqcapid()]) under its name: `names(inputs)` where given, else the
#'   folder's last component. Check the inputs first.
#' @param only `NULL`, or the paths (as the manifest lists them, `/`
#'   between folders) of the files to check; the others are not read, and
#'   `partial` rows say so.
#' @param lineage `NULL`, or capsule folders among which the inputs of a
#'   format 2 capsule are found by id and checked, with no key pinned, to
#'   64 levels; one `lineage` row per input.
#' @param keys `NULL`, or key statements from [nqrotate()] or
#'   [nqrevoke()] (a list of raw vectors, or a character vector of
#'   files), at most 32; they need `pk`. The seal may then be by a key
#'   `pk` was rotated to, and must carry a verified timestamp from before
#'   its key was rotated away or revoked.
#' @param proof `NULL`, or a proof from [nqprove()] (a raw vector or the
#'   path of a file), checked instead of the folder: its seal, its
#'   signature over the manifest's head and each proven entry. `dir` may
#'   then be `NULL`; given, the proven files in it are checked too.
#'   `only`, `lineage` and `keys` do not apply.
#'
#' @return `nqseal()`: the paths of the two files written, invisibly.
#'   `nqcheck()`: a data frame with one row per check and the columns
#'   `check`, `ok` (logical) and `detail`; its attribute `"ok"` is `TRUE`
#'   only when every check passed.
#'
#' @section Errors:
#' `nqseal()`: keys that are not a pair, a folder that holds something a
#' capsule cannot (the reasons above), `meta` that is not a JSON object,
#' `inputs` with format 1, a folder whose evidence record covers the
#' seal (sealing again would replace what it proves), or a folder over
#' the limits (2,000,000 files, paths over 4096 bytes, 64 levels).
#' `nqcheck()` reports problems with the capsule as failed rows; only
#' invalid arguments are errors.
#'
#' @references
#' Rundgren, A., Jordan, B. and Erdtman, S. (2020). *JSON Canonicalization
#' Scheme (JCS)*, RFC 8785. \doi{10.17487/RFC8785}
#'
#' Laurie, B., Messeri, E. and Stradling, R. (2021). *Certificate
#' Transparency Version 2.0*, RFC 9162 (the Merkle tree of format 2).
#' \doi{10.17487/RFC9162}
#'
#' @family capsule functions
#' @seealso [nqprove()] and [nqfiles()] for format 2 capsules;
#'   [nqrotate()] for key changes; [nqidcard()] to say who sealed it.
#'
#' @examples
#' d <- tempfile("capsule")
#' dir.create(d)
#' writeLines("hello", file.path(d, "a.txt"))
#' dir.create(file.path(d, "data"))
#' writeLines("1,2", file.path(d, "data", "b.csv"))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = '{"project":"demo"}')
#' r <- nqcheck(d, k$pk)
#' r
#' attr(r, "ok")
#' # a changed file fails its row, and the whole check
#' writeLines("hellO", file.path(d, "a.txt"))
#' r <- nqcheck(d, k$pk)
#' r[!r$ok, ]
#' attr(r, "ok")
#' # a partial check reads only the files named
#' attr(nqcheck(d, k$pk, only = "data/b.csv"), "ok")
#' # another key is refused
#' other <- nqkeygen("ML-DSA-44")
#' attr(nqcheck(d, other$pk), "ok")
#' unlink(d, recursive = TRUE)
#' @export
nqseal <- function(dir, sk, pk, alg, meta = NULL,
                   format = if (is.null(inputs)) 1L else 2L,
                   inputs = NULL) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  if (!is.null(meta) &&
    (!is.character(meta) || length(meta) != 1L || is.na(meta))) {
    stop("'meta' must be NULL or one string of JSON text", call. = FALSE)
  }
  if (!is.numeric(format) || length(format) != 1L || is.na(format) ||
    !format %in% c(1, 2)) {
    stop("'format' must be 1 or 2", call. = FALSE)
  }
  if (format == 1 && !is.null(inputs)) {
    stop("'inputs' need format 2", call. = FALSE)
  }
  d <- .dir(dir)
  if (format == 1) {
    .Call(Cseal, d, a$id, sk, pk, meta)
  } else {
    if (is.null(inputs)) inputs <- character()
    if (!is.character(inputs) || anyNA(inputs)) {
      stop("'inputs' must be the folders of capsules", call. = FALSE)
    }
    nm <- names(inputs)
    if (is.null(nm)) nm <- rep("", length(inputs))
    nm <- as.character(nm)
    miss <- is.na(nm) | nm == ""
    nm[miss] <- basename(inputs[miss])
    ids <- lapply(inputs, nqcapid)
    .Call(Cseal2, d, a$id, sk, pk, meta, unname(ids), enc2utf8(unname(nm)))
  }
  invisible(file.path(dir, c("noqtis.json", "noqtis.sig")))
}

#' @rdname nqseal
#' @export
nqcheck <- function(dir, pk = NULL, anchors = NULL, only = NULL,
                    lineage = NULL, keys = NULL, proof = NULL) {
  if (!is.null(pk)) .rawarg(pk, "pk")
  if (!is.null(anchors)) {
    if (is.raw(anchors)) anchors <- list(anchors)
    if (!is.list(anchors) || !all(vapply(anchors, is.raw, NA))) {
      stop("'anchors' must be a list of raw vectors", call. = FALSE)
    }
    if (length(anchors) == 0L) anchors <- NULL
  }
  if (!is.null(proof)) {
    proof <- .blob(proof, "proof")
    if (!is.null(only) || !is.null(lineage) || !is.null(keys)) {
      stop("'only', 'lineage' and 'keys' do not apply to a proof",
        call. = FALSE)
    }
  }
  if (!is.null(only) && (!is.character(only) || anyNA(only))) {
    stop("'only' must be a character vector of paths", call. = FALSE)
  }
  if (!is.null(lineage)) {
    lineage <- vapply(lineage, .dir, "", USE.NAMES = FALSE)
  }
  if (!is.null(keys)) {
    if (is.raw(keys)) keys <- list(keys)
    keys <- lapply(keys, .blob, what = "keys")
    if (is.null(pk)) {
      stop("'keys' need 'pk', the trusted key", call. = FALSE)
    }
  }
  d <- if (is.null(dir) && !is.null(proof)) NULL else .dir(dir)
  r <- .Call(Cchk, d, pk, anchors, if (is.null(only)) NULL else
    enc2utf8(only), lineage, keys, proof)
  .rep(r)
}

.rep <- function(r) {
  out <- data.frame(check = r[[2]], ok = r[[3]], detail = r[[4]],
    stringsAsFactors = FALSE)
  attr(out, "ok") <- r[[1]] == 0L && nrow(out) > 0L && all(out$ok)
  out
}

# A raw vector as given, or the bytes of the file one string names.
.blob <- function(x, what) {
  if (is.raw(x)) {
    return(x)
  }
  if (is.character(x) && length(x) == 1L && !is.na(x) && file.exists(x)) {
    return(readBin(x, "raw", file.size(x)))
  }
  stop(sprintf("'%s' must be raw vectors or file paths", what),
    call. = FALSE)
}

#' Capsule ids, files and proofs
#'
#' `nqcapid()` gives a capsule's id: the SHA-256 of the bytes its seal
#' signs, which [nqseal()] records for its `inputs`. `nqfiles()` lists the
#' files a capsule's manifest holds. Neither checks anything: use
#' [nqcheck()] for that.
#'
#' `nqprove()` writes a proof (`noqtis-proof-1`, JSON) that some files are
#' in a format 2 capsule: the seal, the manifest's head (the Merkle root
#' and the number of files) and, per file, its entry and Merkle audit path
#' (RFC 9162). The proof holds nothing of the capsule's other files, not
#' even their names or digests. `nqcheck(proof = )` checks it, alone or
#' against the files.
#'
#' The id is the same for any copy of the capsule, wherever it is kept,
#' and changes when the folder is sealed again.
#'
#' @param dir Path of the capsule folder.
#' @param paths The files to prove, as the manifest lists them (`/`
#'   between folders).
#'
#' @return `nqcapid()`: a raw vector of 32 bytes. `nqfiles()`: a data
#'   frame with the columns `path`, `size` and `sha256` (64 hex digits),
#'   in manifest order. `nqprove()`: the proof, a raw vector.
#'
#' @section Errors:
#' A folder with no seal or manifest that reads; for `nqprove()`, a
#' format 1 capsule or a path the manifest does not list.
#'
#' @references
#' Laurie, B., Messeri, E. and Stradling, R. (2021). *Certificate
#' Transparency Version 2.0*, RFC 9162. \doi{10.17487/RFC9162}
#'
#' @family capsule functions
#'
#' @examples
#' d <- tempfile("proved")
#' dir.create(d)
#' writeLines("one", file.path(d, "a.txt"))
#' writeLines("two", file.path(d, "b.txt"))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 2)
#' nqfiles(d)
#' p <- nqprove(d, "a.txt")
#' grepl("b.txt", rawToChar(p), fixed = TRUE)
#' attr(nqcheck(NULL, k$pk, proof = p), "ok")
#' nqcapid(d)
#' unlink(d, recursive = TRUE)
#' @export
nqcapid <- function(dir) .Call(Ccapid, .dir(dir))

#' @rdname nqcapid
#' @export
nqfiles <- function(dir) {
  r <- .Call(Cfiles, .dir(dir))
  bad <- !r[[3]]
  if (r[[1]] != 0L || any(bad)) {
    why <- if (any(bad)) r[[4]][bad][1] else "the manifest does not parse"
    stop(sprintf("noqtis: nqfiles: %s", why), call. = FALSE)
  }
  d <- r[[4]][r[[2]] == "info.file"]
  m <- regmatches(d, regexec("^([0-9]+) ([0-9a-f]{64}) (.*)$", d))
  data.frame(
    path = vapply(m, `[`, "", 4L),
    size = as.numeric(vapply(m, `[`, "", 2L)),
    sha256 = vapply(m, `[`, "", 3L),
    stringsAsFactors = FALSE
  )
}

#' @rdname nqcapid
#' @export
nqprove <- function(dir, paths) {
  if (!is.character(paths) || length(paths) == 0L || anyNA(paths)) {
    stop("'paths' must name at least one file", call. = FALSE)
  }
  .Call(Cprove, .dir(dir), enc2utf8(paths))
}

#' Rotate or revoke a seal key
#'
#' A key statement (`noqtis-keys-1`, canonical JSON) says that a signing
#' key is replaced by a new one from a given time (`nqrotate()`, signed by
#' both keys) or revoked from then (`nqrevoke()`, signed by the key).
#' [nqcheck()] follows statements from a trusted key with its `keys`
#' argument.
#'
#' A rotation moves trust from the old key to the new one: a checker who
#' trusts the old key then accepts seals by the new one. A seal made with
#' a key that was rotated away or revoked still passes when a verified
#' RFC 3161 timestamp shows it was made before that time; without one it
#' fails, since the seal's own creation time is only the sealer's word.
#' Both signatures of a rotation are checked before it is returned. Both
#' algorithms must be post-quantum: Ed25519 alone is refused.
#'
#' @param sk,pk The key pair the statement is about.
#' @param alg Its signature algorithm.
#' @param nsk,npk The new key pair.
#' @param nalg The new key pair's algorithm.
#' @param at When the statement takes effect: a `POSIXct` time or seconds
#'   since 1970 (UTC); default now.
#' @param reason `NULL`, or up to 255 bytes of text kept in the statement.
#'
#' @return The statement, a raw vector (write it with [writeBin()]).
#'
#' @section Errors:
#' An unknown algorithm, Ed25519 alone, keys that are not pairs, or a
#' `reason` over 255 bytes.
#'
#' @family capsule functions
#'
#' @examples
#' old <- nqkeygen("ML-DSA-44")
#' new <- nqkeygen("ML-DSA-65")
#' s <- nqrotate(old$sk, old$pk, "ML-DSA-44", new$sk, new$pk, "ML-DSA-65",
#'   reason = "yearly")
#' cat(rawToChar(s))
#' r <- nqrevoke(old$sk, old$pk, "ML-DSA-44",
#'   at = as.POSIXct("2026-01-01", tz = "UTC"), reason = "laptop lost")
#' substr(rawToChar(r), 1, 60)
#' @export
nqrotate <- function(sk, pk, alg, nsk, npk, nalg, at = Sys.time(),
                     reason = NULL) {
  a <- .alg(alg, "sig")
  b <- .alg(nalg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  .rawarg(nsk, "nsk")
  .rawarg(npk, "npk")
  .Call(Ckstmt, a$id, sk, pk, b$id, nsk, npk, .at(at), reason)
}

#' @rdname nqrotate
#' @export
nqrevoke <- function(sk, pk, alg, at = Sys.time(), reason = NULL) {
  a <- .alg(alg, "sig")
  .rawarg(sk, "sk")
  .rawarg(pk, "pk")
  .Call(Ckstmt, a$id, sk, pk, a$id, NULL, NULL, .at(at), reason)
}

.at <- function(at) {
  if (inherits(at, "POSIXt")) at <- as.numeric(as.POSIXct(at))
  if (!is.numeric(at) || length(at) != 1L || is.na(at)) {
    stop("'at' must be a time or seconds since 1970", call. = FALSE)
  }
  floor(as.double(at))
}
