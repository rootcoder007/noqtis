#' The data record of a capsule
#'
#' A capsule's data record, `noqtis.data.json` in its folder, says where
#' each data file came from, the schema of its CSV files, summaries that
#' show drift later, and the steps and checks made with it (the format
#' `noqtis-data-1`). It is a file of the capsule like any other: seal the
#' folder ([nqseal()]) after changing the record, and the seal covers it.
#' The record is canonical JSON, the same bytes the `noqtis` tool and
#' every other binding write.
#'
#' `nqdata()` returns the record as one string of JSON. `nqdadd()`
#' records each file's SHA-256 and size as a source, keeping what the
#' record already says of it, with where it came from. `nqdput()` adds
#' an element (JSON text) to a member: `"sources"`, `"schemas"`,
#' `"stats"` (replacing the one with the same path), `"checks"` (the same
#' name), `"steps"`, `"commits"` (appended), or sets `"env"` or
#' `"cite"`; `nqdput()` with `json = NULL` removes the element with path
#' or name `key`, or the whole member. `nqdcheck()` checks the record
#' and every file it lists: SHA-256 and size of each source, each
#' schema, and the checks recorded as failed.
#'
#' @param dir Path of the capsule folder.
#' @param files Paths of files in `dir`, `/` between folders.
#' @param url,title,publisher,licence Where the files came from;
#'   `NULL` leaves what the record says.
#' @param retrieved `NULL`, `"now"` (the clock, or `SOURCE_DATE_EPOCH`)
#'   or a UTC time `"YYYY-MM-DDTHH:MM:SSZ"`.
#' @param synthetic `TRUE` when the files are generated stand-ins for the
#'   real data; every report row about them says so.
#' @param member One of the record's members, as above.
#' @param json One string of JSON text, or `NULL` to remove.
#' @param key `NULL`, or the path (or name, for `"checks"`) of the
#'   element to remove.
#' @return `nqdata()`: one string. `nqdcheck()`: a data frame with
#'   columns `check`, `ok` and `detail`, and the attribute `"ok"`, `TRUE`
#'   only when every row passed. The others: `dir`, invisibly.
#' @seealso [nqschema()], [nqdpin()], [nqdiff()], [nqseal()].
#' @examples
#' d <- file.path(tempdir(), "cap")
#' dir.create(file.path(d, "data"), recursive = TRUE)
#' writeLines(c("x,y", "1,a", "2,b"), file.path(d, "data", "a.csv"))
#' nqdadd(d, "data/a.csv", url = "https://example.org/a.csv")
#' nqdata(d)
#' nqdcheck(d)
#' unlink(d, recursive = TRUE)
#' @export
nqdata <- function(dir) {
  .Call(Cdload, .dir(dir))
}

#' @rdname nqdata
#' @export
nqdadd <- function(dir, files, url = NULL, title = NULL, publisher = NULL,
                   licence = NULL, retrieved = NULL, synthetic = FALSE) {
  d <- .dir(dir)
  if (!is.character(files) || !length(files) || anyNA(files)) {
    stop("'files' must be paths of files in 'dir'", call. = FALSE)
  }
  f <- list(
    url = url, title = title, publisher = publisher, licence = licence
  )
  if (!is.null(retrieved)) {
    f$retrieved <- if (identical(retrieved, "now")) .now() else retrieved
  }
  f <- f[!vapply(f, is.null, TRUE)]
  for (n in names(f)) {
    if (!.is1(f[[n]])) {
      stop(sprintf("'%s' must be one string", n), call. = FALSE)
    }
  }
  if (length(f) && length(files) > 1L && !is.null(url)) {
    stop("'url' describes one file: add the files one at a time",
      call. = FALSE
    )
  }
  vals <- vapply(f, .jstr, "")
  if (isTRUE(synthetic)) {
    f$synthetic <- TRUE
    vals <- c(vals, synthetic = "true")
  }
  .Call(Cdadd, d, enc2utf8(files), names(vals), unname(vals))
  invisible(dir)
}

#' @rdname nqdata
#' @export
nqdput <- function(dir, member, json, key = NULL) {
  d <- .dir(dir)
  if (!.is1(member)) stop("'member' must be one string", call. = FALSE)
  if (is.null(json)) {
    if (!is.null(key) && !.is1(key)) {
      stop("'key' must be one string", call. = FALSE)
    }
    .Call(Cddel, d, member, key)
  } else {
    if (!.is1(json)) {
      stop("'json' must be one string of JSON text", call. = FALSE)
    }
    .Call(Cdput, d, member, enc2utf8(json))
  }
  invisible(dir)
}

#' @rdname nqdata
#' @export
nqdcheck <- function(dir) {
  .drep(.Call(Cdchk, .dir(dir)))
}

#' Pin and check the schema of CSV files
#'
#' `nqschema()` reads each CSV file (RFC 4180) and returns its schema as
#' JSON: the columns, the narrowest type each fits (`bool`, `int`,
#' `real`, `date`, `text`; a leading zero keeps a code text), whether
#' each has missing values (`""` and `NA`), the number of rows, and with
#' `ranges` each number and date range. With `put`, it records them in
#' the data record instead. `nqschk()` checks the files against the
#' schemas the record pins: header, types, missing values, ranges, sets,
#' row counts and rules (add rules with [nqdput()]).
#'
#' @inheritParams nqdata
#' @param put `TRUE` to record the schemas in the data record.
#' @param delim The field delimiter, one character.
#' @param header `FALSE` when the first line is data (the columns are then
#'   named V1, V2, ...).
#' @param ranges `TRUE` to pin number and date ranges too.
#' @return `nqschema()`: one JSON string per file (invisibly with `put`).
#'   `nqschk()`: a data frame as [nqdcheck()] returns, of the schema and
#'   rule rows (of `files` only, when given).
#' @examples
#' d <- file.path(tempdir(), "sch")
#' dir.create(d)
#' writeLines(c("id,when", "1,2024-01-02", "2,2024-02-29"),
#'            file.path(d, "a.csv"))
#' nqschema(d, "a.csv")
#' nqschema(d, "a.csv", put = TRUE)
#' nqschk(d)
#' unlink(d, recursive = TRUE)
#' @export
nqschema <- function(dir, files, put = FALSE, delim = ",", header = TRUE,
                     ranges = FALSE) {
  d <- .dir(dir)
  out <- vapply(files, function(f) {
    .Call(Cdinfer, d, enc2utf8(f), delim, !isTRUE(header), isTRUE(ranges))
  }, "", USE.NAMES = FALSE)
  if (!isTRUE(put)) {
    return(out)
  }
  for (s in out) .Call(Cdput, d, "schemas", s)
  invisible(out)
}

#' @rdname nqschema
#' @export
nqschk <- function(dir, files = NULL) {
  r <- nqdcheck(dir)
  keep <- r$check %in% c("schema", "rule")
  if (!is.null(files)) {
    f <- vapply(strsplit(r$detail, ":", fixed = TRUE), `[`, "", 1L)
    keep <- keep & sub(" [synthetic]", "", f, fixed = TRUE) %in% files
  }
  out <- r[keep, , drop = FALSE]
  rownames(out) <- NULL
  attr(out, "ok") <- nrow(out) > 0L && all(out$ok)
  out
}

#' Summaries that show drift later, and the check against them
#'
#' `nqdpin()` records in the data record summaries of each CSV file, of a
#' fixed size whatever the file's: for a numeric column a quantile sketch
#' of 1,001 points (every distinct value when there are at most 1,001),
#' the population stability index's decile bins and first-digit counts;
#' for any other column the counts of its 1,000 most frequent values.
#' `nqdrift()` compares each summarised file (or `current`, a later copy)
#' with its summary: the two-sample Kolmogorov-Smirnov test, PSI and
#' Jensen-Shannon divergence, the chi-square test of homogeneity, and
#' Benford's first-digit test. The tests and their error are defined in
#' the manual page `noqtis-drift(1)`; on the test vectors they match R's
#' [stats::ks.test()] and [stats::chisq.test()] to 1e-9.
#'
#' @inheritParams nqschema
#' @param current `NULL`, or one path per file: the file to compare in
#'   its place (a new download of the same source, say).
#' @param psiwarn,psifail PSI from which a column warns, and fails (when
#'   both samples have `minn` values).
#' @param alpha A KS or chi-square p-value below it warns.
#' @param minn Values each sample needs before PSI alone fails a column.
#' @param benford `TRUE`: a Benford p-value below `alpha` warns too.
#' @return `nqdpin()`: `dir`, invisibly. `nqdrift()`: a data frame with
#'   columns `check` (`"drift"` or `"drift.warn"`), `ok`, `detail` and
#'   `stats` (the numbers of the row as JSON, or `NA`), and the
#'   attributes `"ok"` (no column failed) and `"level"` (`"ok"`,
#'   `"warn"` or `"fail"`).
#' @examples
#' d <- file.path(tempdir(), "dft")
#' dir.create(d)
#' write.csv(data.frame(x = round(stats::qnorm(ppoints(200)), 6)),
#'           file.path(d, "a.csv"), row.names = FALSE, quote = FALSE)
#' nqdpin(d, "a.csv")
#' nqdrift(d)
#' unlink(d, recursive = TRUE)
#' @export
nqdpin <- function(dir, files, delim = ",", header = TRUE) {
  d <- .dir(dir)
  for (f in files) {
    s <- .Call(Cdstats, d, enc2utf8(f), delim, !isTRUE(header))
    .Call(Cdput, d, "stats", s)
  }
  invisible(dir)
}

#' @rdname nqdpin
#' @export
nqdrift <- function(dir, files = NULL, current = NULL, psiwarn = 0.1,
                    psifail = 0.25, alpha = 0.001, minn = 1000,
                    benford = FALSE, delim = ",", header = TRUE) {
  d <- .dir(dir)
  if (is.null(files)) {
    files <- .statpaths(d)
  }
  if (!length(files)) {
    stop("the record has no summaries: pin some with nqdpin()",
      call. = FALSE
    )
  }
  if (!is.null(current) && length(current) != length(files)) {
    stop("'current' needs one path per file", call. = FALSE)
  }
  lv <- as.numeric(c(psiwarn, psifail, alpha, minn, isTRUE(benford)))
  rs <- lapply(seq_along(files), function(i) {
    s <- .Call(Cdkey, d, "stats", enc2utf8(files[i]))
    if (is.null(s)) {
      stop(sprintf("no summary of %s: pin one with nqdpin()", files[i]),
        call. = FALSE
      )
    }
    cur <- if (is.null(current)) file.path(d, files[i]) else current[i]
    .drep(.Call(Cddrift, s, cur, delim, !isTRUE(header), lv))
  })
  out <- do.call(rbind, rs)
  rownames(out) <- NULL
  attr(out, "ok") <- all(out$ok)
  attr(out, "level") <- if (!all(out$ok)) {
    "fail"
  } else if (any(out$check == "drift.warn")) {
    "warn"
  } else {
    "ok"
  }
  out
}

#' What changed between two capsules
#'
#' The files added, removed or changed between the two capsules'
#' manifests (when both are sealed), and what differs in their data
#' records: sources, schemas, summaries (counts, medians, PSI between
#' them), environment, steps, checks, commitments and citation. Nothing
#' is checked: run [nqcheck()] and [nqdcheck()] first.
#'
#' @param a,b Paths of the two capsule folders, before and after.
#' @return A data frame with columns `what`, `differs` and `detail`, and
#'   the attribute `"same"`.
#' @examples
#' a <- file.path(tempdir(), "da")
#' b <- file.path(tempdir(), "db")
#' dir.create(a)
#' dir.create(b)
#' writeLines("x", file.path(a, "f.txt"))
#' writeLines("y", file.path(b, "f.txt"))
#' nqdadd(a, "f.txt")
#' nqdadd(b, "f.txt")
#' nqdiff(a, b)
#' unlink(c(a, b), recursive = TRUE)
#' @export
nqdiff <- function(a, b) {
  r <- .Call(Cddiff, .dir(a), .dir(b))
  out <- data.frame(
    what = r[[2]], differs = !r[[3]], detail = r[[4]],
    stringsAsFactors = FALSE
  )
  attr(out, "same") <- r[[1]] == 0L
  out
}

# A report as a data frame; the "stats" column when a row has numbers.
.drep <- function(r) {
  out <- data.frame(
    check = r[[2]], ok = r[[3]], detail = r[[4]],
    stringsAsFactors = FALSE
  )
  if (any(!is.na(r[[5]]))) out$stats <- r[[5]]
  attr(out, "ok") <- r[[1]] == 0L && nrow(out) > 0L && all(out$ok)
  out
}

# One string as JSON text.
.jstr <- function(s) {
  s <- enc2utf8(s)
  s <- gsub("\\", "\\\\", s, fixed = TRUE)
  s <- gsub("\"", "\\\"", s, fixed = TRUE)
  for (i in c(1:31)) {
    ch <- intToUtf8(i)
    s <- gsub(ch, sprintf("\\u%04x", i), s, fixed = TRUE)
  }
  paste0("\"", s, "\"")
}

# The time now (or SOURCE_DATE_EPOCH), as the record writes it.
.now <- function() {
  e <- Sys.getenv("SOURCE_DATE_EPOCH")
  t <- if (nzchar(e)) as.POSIXct(as.numeric(e), origin = "1970-01-01",
                                 tz = "UTC") else Sys.time()
  format(t, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
}

# The paths the record's summaries are of, from its canonical JSON:
# in "stats", each element's "path" comes right before its "rows", a
# count (in "schemas" the "rows" that follows is an object).
.statpaths <- function(d) {
  j <- .Call(Cdload, d)
  s <- regmatches(j, regexpr("\"stats\":\\[.*", j))
  if (!length(s)) {
    return(character())
  }
  m <- gregexpr("\"path\":\"((?:[^\"\\\\]|\\\\.)*)\",\"rows\":[0-9]", s,
                perl = TRUE)
  p <- regmatches(s, m)[[1]]
  p <- sub("^\"path\":\"", "", sub("\",\"rows\":[0-9]$", "", p))
  gsub("\\\\(.)", "\\1", p)
}
