# The notice of a newer release, when the package is attached.

# The address that answers with the address of the latest release.
updurl <- "https://github.com/rootcoder007/noqtis/releases/latest"

# The version in the header lines of that answer, or NA.
updver <- function(h) {
  l <- grep("^location:", h, ignore.case = TRUE, value = TRUE)
  m <- regmatches(l, regexec("/releases/tag/v([0-9]+(\\.[0-9]+)*)\\s*$", l))
  v <- unlist(lapply(m, function(x) x[2L]))
  v <- v[!is.na(v)]
  if (length(v) == 0L) NA_character_ else v[[1L]]
}

# The version of the latest release, or NA when it cannot be had: two
# seconds at most, and no error or warning leaves this function.
updget <- function(url = updurl) {
  op <- options(timeout = 2)
  on.exit(options(op), add = TRUE)
  tryCatch(
    suppressWarnings(updver(curlGetHeaders(url, redirect = FALSE))),
    error = function(e) NA_character_
  )
}

# Is the notice off. It is, unless asked for by options(noqtis.update =
# TRUE) or the variable NOQTIS_UPDATE_CHECK; and always in a session that
# is not interactive, under the variable NOQTIS_NO_UPDATE_CHECK, or under
# options(noqtis.update = FALSE).
updoff <- function(live = interactive()) {
  on <- isTRUE(getOption("noqtis.update")) ||
    nzchar(Sys.getenv("NOQTIS_UPDATE_CHECK"))
  !live || !on || nzchar(Sys.getenv("NOQTIS_NO_UPDATE_CHECK")) ||
    isFALSE(getOption("noqtis.update"))
}

# The text of the notice, or NULL. The answer and its time are kept in
# `file`; the question is asked again after a day, by `get` (a test
# gives its own) or by updget().
updmsg <- function(cur, file, now = as.numeric(Sys.time()), get = NULL) {
  old <- tryCatch(
    scan(file, what = "", n = 2L, quiet = TRUE),
    error = function(e) character(),
    warning = function(w) character()
  )
  t <- suppressWarnings(as.numeric(old[1L]))
  v <- old[2L]
  if (is.na(t) || now < t || now - t >= 86400) {
    v <- if (is.null(get)) updget() else get()
    dir.create(dirname(file), recursive = TRUE, showWarnings = FALSE)
    tryCatch(
      writeLines(paste(format(now, scientific = FALSE), v), file),
      error = function(e) NULL,
      warning = function(w) NULL
    )
  }
  ok <- !is.na(v) && grepl("^[0-9]+(\\.[0-9]+)*$", v)
  if (!ok || utils::compareVersion(v, cur) <= 0L) {
    return(NULL)
  }
  paste0(
    "noqtis ", v, " is available (this is ", cur, "): ", updurl,
    "\noptions(noqtis.update = FALSE) stops this notice."
  )
}

# The notice for this installation, or NULL.
updrun <- function() {
  if (updoff()) {
    return(NULL)
  }
  updmsg(
    as.character(utils::packageVersion("noqtis")),
    file.path(tools::R_user_dir("noqtis", "cache"), "update")
  )
}

.onAttach <- function(libname, pkgname) {
  m <- updrun()
  if (!is.null(m)) {
    packageStartupMessage(m)
  }
}
