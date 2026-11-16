#' More of the data record: parse, synthetic data, calibration, chunks
#'
#' `nqdparse()` reads JSON text as a data record, as `noqtis data check`
#' reads one, and returns it in canonical form (an error says what is
#' wrong and where). `nqdschk()` checks the CSV file of one `"schemas"`
#' element against it. `nqdsyn()` writes a synthetic stand-in for a CSV
#' file from the schema the record pins for it (the same bytes for the
#' same seed) and records it as a synthetic source; real data is never
#' replaced. `nqdcal()` calibrates the drift warnings of a file's summary
#' on files known not to have drifted from it, so [nqdrift()] then warns
#' only beyond what they showed. `nqdchunk()` records the SHA-256 of each
#' run of `chunk` bytes of a large file, and `nqdpiece()` checks a piece
#' of that file (the bytes from `off` on) against them, reading only the
#' piece.
#'
#' @inheritParams nqdata
#' @param json One string of JSON text.
#' @param schema One `"schemas"` element, JSON text.
#' @param file The file's path in `dir`, `/` between folders.
#' @param seed A whole number from 0 to 2^53.
#' @param rows The rows to write; 0 for the schema's minimum, else 100.
#' @param known Paths of CSV files known not to have drifted.
#' @param delim,header As for [nqschema()].
#' @param chunk The run size in bytes, 1024 to 2^30.
#' @param piece The path of a file holding the piece.
#' @param off Where the piece starts in the large file, a multiple of its
#'   chunk.
#'
#' @return `nqdparse()`: one string. `nqdschk()`, `nqdpiece()`: a data
#'   frame as [nqdcheck()] returns. `nqdcal()`, `nqdchunk()`: the element
#'   recorded, one JSON string. `nqdsyn()`: `dir`, invisibly.
#'
#' @section Errors:
#' JSON that is not a record, a file that is not CSV, a schema with no
#' columns, a stand-in over a real source, a chunk size out of range.
#'
#' @family data record functions
#'
#' @examples
#' d <- file.path(tempdir(), "dx")
#' dir.create(file.path(d, "data"), recursive = TRUE)
#' writeLines(c("id,x", "1,0.5", "2,1.5", "3,2.5"), file.path(d, "a.csv"))
#' nqdparse('{"format":"noqtis-data-1"}')
#' s <- nqschema(d, "a.csv")
#' attr(nqdschk(d, s), "ok")
#' nqdput(d, "schemas", sub('"a.csv"', '"data/s.csv"', s, fixed = TRUE))
#' nqdsyn(d, "data/s.csv", seed = 7)
#' readLines(file.path(d, "data", "s.csv"))
#' nqdpin(d, "a.csv")
#' invisible(nqdcal(d, "a.csv", file.path(d, "a.csv")))
#' writeBin(as.raw(rep(0:255, 8)), file.path(d, "big.bin"))
#' invisible(nqdchunk(d, "big.bin", chunk = 1024))
#' p <- tempfile()
#' writeBin(as.raw(rep(0:255, 4)), p)
#' attr(nqdpiece(d, "big.bin", p, off = 1024), "ok")
#' unlink(c(d, p), recursive = TRUE)
#' @export
nqdparse <- function(json) {
  if (!.is1(json)) stop("'json' must be one string", call. = FALSE)
  .Call(Cdparse, enc2utf8(json))
}

#' @rdname nqdparse
#' @export
nqdschk <- function(dir, schema) {
  if (!.is1(schema)) stop("'schema' must be one string", call. = FALSE)
  .drep(.Call(Cdschk, .dir(dir), enc2utf8(schema)))
}

#' A whole number from 0 to 2^53, as a double, or an error.
#' @noRd
.u53 <- function(x, what) {
  if (!is.numeric(x) || length(x) != 1L || is.na(x) || x < 0 ||
        x != floor(x) || x > 2^53) {
    stop(sprintf("'%s' must be a whole number from 0 to 2^53", what),
      call. = FALSE
    )
  }
  as.double(x)
}

#' @rdname nqdparse
#' @export
nqdsyn <- function(dir, file, seed, rows = 0) {
  .path1(file, "file")
  .Call(Cdsyn, .dir(dir), file, .u53(seed, "seed"), .u53(rows, "rows"))
  invisible(dir)
}

#' @rdname nqdparse
#' @export
nqdcal <- function(dir, file, known, delim = ",", header = TRUE) {
  .path1(file, "file")
  if (!is.character(known) || length(known) == 0L || anyNA(known) ||
        !all(file.exists(known))) {
    stop("'known' must name existing CSV files", call. = FALSE)
  }
  d <- .dir(dir)
  s <- .Call(Cdkey, d, "stats", file)
  if (is.null(s)) {
    stop(sprintf("no summary of %s to calibrate: pin one with nqdpin()",
                 file), call. = FALSE)
  }
  e <- .Call(Cdcal, s, normalizePath(known), delim, !isTRUE(header))
  nqdput(d, "stats", e)
  e
}

#' @rdname nqdparse
#' @export
nqdchunk <- function(dir, file, chunk = 1048576) {
  .path1(file, "file")
  d <- .dir(dir)
  e <- .Call(Cdchunk, d, file, .u53(chunk, "chunk"))
  nqdput(d, "chunks", e)
  e
}

#' @rdname nqdparse
#' @export
nqdpiece <- function(dir, file, piece, off = 0) {
  .path1(file, "file")
  .file1e(piece, "piece")
  e <- .Call(Cdkey, .dir(dir), "chunks", file)
  if (is.null(e)) {
    stop(sprintf("no chunk digests of %s: record them with nqdchunk()",
                 file), call. = FALSE)
  }
  .drep(.Call(Cdpiece, e, normalizePath(piece), .u53(off, "off")))
}

#' Commitments, citation and the report of a capsule
#'
#' `nqdcommit()` commits to some content (a randomisation list, an
#' analysis plan) in the data record, as `noqtis commit` does: the record
#' gets the SHA3-256 of the content under a fresh 32-byte secret salt,
#' which is returned; keep the salt and the content out of the capsule
#' until the reveal, and seal the capsule (with a timestamp) so the
#' commitment is dated. Without the salt the record says nothing of the
#' content. `nqdreveal()` finds the commitment that content and salt
#' match, comparing every recorded digest in constant time. `nqdcite()`
#' writes how to cite the data, from the record's `"cite"`. `nqdreport()`
#' checks the capsule and its record and writes a report of both, as
#' `noqtis report` does.
#'
#' @inheritParams nqdata
#' @param x The content: a raw vector or one string.
#' @param kind `"randomisation"`, `"preregistration"` or `"other"`.
#' @param label `NULL`, or a label.
#' @param after `NULL`, or a UTC time `"YYYY-MM-DDTHH:MM:SSZ"` before which
#'   it is not to be revealed.
#' @param salt The salt `nqdcommit()` returned.
#' @param format `nqdcite()`: `"cff"` (CITATION.cff) or `"bibtex"`;
#'   `nqdreport()`: `"md"` (Markdown) or `"txt"`.
#' @param pk `NULL`, or the public key the seal must carry.
#'
#' @return `nqdcommit()`: the salt, a raw vector of 32 bytes.
#'   `nqdreveal()`: the position (from 1) of the matching commitment in
#'   `"commits"`, or `NA`. `nqdcite()`, `nqdreport()`: one string.
#'
#' @section Errors:
#' A record without `"cite"` (`nqdcite()`), a folder with neither a seal
#' nor a record (`nqdreport()`).
#'
#' @family data record functions
#'
#' @examples
#' d <- file.path(tempdir(), "cm")
#' dir.create(d)
#' writeLines("x", file.path(d, "a.txt"))
#' s <- nqdcommit(d, "arm A: 1, 4\narm B: 2, 3\n", kind = "randomisation")
#' nqdreveal(d, "arm A: 1, 4\narm B: 2, 3\n", s)
#' nqdreveal(d, "something else", s)
#' nqdput(d, "cite", '{"title":"T","authors":["A. Author"],"year":2026}')
#' cat(nqdcite(d))
#' k <- nqkeygen("ML-DSA-44")
#' nqseal(d, k$sk, k$pk, "ML-DSA-44")
#' cat(nqdreport(d, k$pk, format = "txt"))
#' unlink(d, recursive = TRUE)
#' @export
nqdcommit <- function(dir, x, kind = c("other", "randomisation",
                                       "preregistration"),
                      label = NULL, after = NULL) {
  kind <- match.arg(kind)
  d <- .dir(dir)
  salt <- nqrand(32L)
  e <- c(
    sprintf('"kind":"%s"', kind), sprintf('"created":"%s"', .now()),
    '"alg":"sha3-256"',
    sprintf('"digest":"%s"', .Call(Cdcommit, salt, .bytes(x, "x")))
  )
  if (!is.null(label)) {
    if (!.is1(label)) stop("'label' must be one string", call. = FALSE)
    e <- c(e, paste0('"label":', .jstr(label)))
  }
  if (!is.null(after)) {
    if (!.is1(after) || nchar(after) != 20L) {
      stop("'after' must be a UTC time YYYY-MM-DDTHH:MM:SSZ", call. = FALSE)
    }
    e <- c(e, paste0('"after":', .jstr(after)))
  }
  nqdput(d, "commits", paste0("{", paste(e, collapse = ","), "}"))
  salt
}

#' @rdname nqdcommit
#' @export
nqdreveal <- function(dir, x, salt) {
  i <- .Call(Cdreveal, .dir(dir), .rawarg(salt, "salt"), .bytes(x, "x"))
  if (is.na(i)) NA_integer_ else i + 1L
}

#' @rdname nqdcommit
#' @export
nqdcite <- function(dir, format = c("cff", "bibtex")) {
  format <- match.arg(format)
  .Call(Cdcite, .dir(dir), if (format == "cff") 1L else 2L)
}

#' @rdname nqdcommit
#' @export
nqdreport <- function(dir, pk = NULL, format = c("md", "txt")) {
  format <- match.arg(format)
  d <- .dir(dir)
  if (!is.null(pk)) .rawarg(pk, "pk")
  sealed <- file.exists(file.path(d, "noqtis.sig"))
  hasrec <- file.exists(file.path(d, "noqtis.data.json"))
  if (!sealed && !hasrec) {
    stop(sprintf("%s holds neither a seal nor a data record", dir),
      call. = FALSE
    )
  }
  .Call(Cdrpt, d, pk, if (format == "md") 1L else 2L, sealed, hasrec)
}

#' Record the environment of a run
#'
#' `nqdenv()` records in the data record's `"env"` the environment of a
#' run, as `noqtis env` does (the platform, the noqtis version, the locale
#' and time zone, the SHA-256 of the lock files at the top of `dir`, the
#' random number generator and its seed), and fills the runtime: R, its
#' version, and the packages. `nqdpkgs()` lists the packages: by default
#' those loaded in this session, each with its version and where it came
#' from (`"CRAN"` or the repository its description names, `"github"` and
#' the like for a remote install, `"base"` for R's own, else `"local"`).
#' Nothing is fetched.
#'
#' @inheritParams nqdata
#' @param rng `NULL`, or the random number generator's kind; the default
#'   is R's, `RNGkind()[1]`, when `seed` is given.
#' @param seed `NULL`, or the seed (a number or one string).
#' @param locks `NULL` for the known lock files present in `dir`
#'   (`renv.lock`, `uv.lock`, `Cargo.lock`, ...), or the lock files to
#'   record, paths in `dir`. Each is read inside `dir`; one reached
#'   through a symbolic link is refused (an error).
#' @param pkgs `NULL` for `nqdpkgs()`, or a data frame with the columns
#'   `name`, `version` and `source`.
#' @param which The packages to list: names, or `NULL` for those loaded.
#'
#' @return `nqdenv()`: the element recorded, one JSON string.
#'   `nqdpkgs()`: a data frame with the columns `name`, `version` and
#'   `source`, sorted by name.
#'
#' @family data record functions
#'
#' @examples
#' d <- file.path(tempdir(), "env")
#' dir.create(d)
#' writeLines("{}", file.path(d, "renv.lock"))
#' head(nqdpkgs())
#' e <- nqdenv(d, seed = 42)
#' substr(e, 1, 60)
#' unlink(d, recursive = TRUE)
#' @export
nqdenv <- function(dir, rng = NULL, seed = NULL, locks = NULL,
                   pkgs = NULL) {
  d <- .dir(dir)
  if (!is.null(seed) && is.null(rng)) rng <- RNGkind()[1L]
  e <- c(.envplat(), .envrt(if (is.null(pkgs)) nqdpkgs() else pkgs),
         .locks(d, locks), .envrng(rng, seed))
  j <- paste0("{", paste(e, collapse = ","), "}")
  nqdput(d, "env", j)
  j
}

#' The platform members of env: os, arch, noqtis, locale, tz.
#' @noRd
.envplat <- function() {
  e <- c(
    paste0('"os":', .jstr(.osname())), paste0('"arch":', .jstr(.archname())),
    paste0('"noqtis":', .jstr(nqver()))
  )
  loc <- Sys.getenv("LC_ALL")
  if (!nzchar(loc)) loc <- Sys.getenv("LANG")
  if (nzchar(loc)) e <- c(e, paste0('"locale":', .jstr(loc)))
  tz <- Sys.getenv("TZ")
  if (nzchar(tz)) e <- c(e, paste0('"tz":', .jstr(tz)))
  e
}

#' The runtime member of env: R, its version and the packages p (a data
#' frame with name, version and source; any atomic column class).
#' @param p The packages.
#' @noRd
.envrt <- function(p) {
  if (!is.data.frame(p) || !all(c("name", "version", "source") %in% names(p))) {
    stop("'pkgs' must be a data frame with name, version and source",
      call. = FALSE
    )
  }
  cols <- p[c("name", "version", "source")]
  if (any(vapply(cols, is.list, NA))) {
    stop("'pkgs' must not have list columns", call. = FALSE)
  }
  p <- lapply(cols, as.character)
  if (anyNA(unlist(p))) stop("'pkgs' must not hold NA", call. = FALSE)
  o <- order(p$name)
  pj <- sprintf(
    '{"name":%s,"version":%s,"source":%s}',
    vapply(p$name[o], .jstr, ""), vapply(p$version[o], .jstr, ""),
    vapply(p$source[o], .jstr, "")
  )
  rv <- paste(R.version$major, R.version$minor, sep = ".")
  sprintf(
    '"runtime":{"language":"r","version":%s,"packages":[%s]}',
    .jstr(rv), paste(pj, collapse = ",")
  )
}

#' The rng member of env, or nothing without rng.
#' @param rng,seed As for nqdenv().
#' @noRd
.envrng <- function(rng, seed) {
  if (is.null(rng)) {
    return(character(0))
  }
  if (!.is1(rng)) stop("'rng' must be one string", call. = FALSE)
  g <- paste0('"kind":', .jstr(rng))
  if (!is.null(seed)) {
    sv <- format(seed, scientific = FALSE)
    if (is.character(seed)) sv <- .jstr(seed)
    g <- paste0(g, ',"seed":', sv)
  }
  paste0('"rng":{', g, "}")
}

#' the lock files in d (those named, else the known ones present)
#' @noRd
.locks <- function(d, locks) {
  known <- c(
    "renv.lock", "uv.lock", "poetry.lock", "Pipfile.lock",
    "requirements.txt", "Cargo.lock", "go.sum", "package-lock.json",
    "pnpm-lock.yaml", "yarn.lock", "environment.yml", "Manifest.toml"
  )
  f <- if (is.null(locks)) known[file.exists(file.path(d, known))] else locks
  if (!is.null(locks) && !all(file.exists(file.path(d, f)))) {
    stop("'locks' must name files in 'dir'", call. = FALSE)
  }
  if (length(f) == 0L) {
    return(character(0))
  }
  f <- sort(f)
  # each opened from d, never through a link
  h <- vapply(f, function(x) .Call(Cdsha, d, enc2utf8(x)), "")
  el <- sprintf('{"path":%s,"sha256":"%s"}', vapply(f, .jstr, ""), h)
  paste0('"locks":[', paste(el, collapse = ","), "]")
}

#' The operating system's name as the data record writes it.
#' @noRd
.osname <- function(s = Sys.info()[["sysname"]]) {
  s <- tolower(s)
  os <- c(
    windows = "windows", darwin = "macos", linux = "linux",
    freebsd = "freebsd", openbsd = "openbsd", netbsd = "netbsd"
  )
  if (s %in% names(os)) os[[s]] else "other"
}

#' The processor's name as the data record writes it.
#' @noRd
.archname <- function(m = Sys.info()[["machine"]]) {
  m <- tolower(m)
  ar <- c(
    x86_64 = "x86_64", amd64 = "x86_64", "x86-64" = "x86_64",
    arm64 = "aarch64", aarch64 = "aarch64", i386 = "i686", i686 = "i686",
    x86 = "i686"
  )
  if (m %in% names(ar)) ar[[m]] else m
}

#' Where a package came from, by the fields of its DESCRIPTION (a list).
#' @noRd
.pkgsrc <- function(d) {
  if (!is.null(d$Priority) && d$Priority == "base") return("base")
  if (!is.null(d$RemoteType)) return(d$RemoteType)
  if (!is.null(d$Repository)) return(d$Repository)
  "local"
}

#' @rdname nqdenv
#' @export
nqdpkgs <- function(which = NULL) {
  n <- sort(if (is.null(which)) loadedNamespaces() else which)
  data.frame(
    name = n,
    version = vapply(n, function(p) as.character(utils::packageVersion(p)), ""),
    source = vapply(n, function(p) .pkgsrc(utils::packageDescription(p)), ""),
    row.names = NULL
  )
}
