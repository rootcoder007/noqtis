# Copies the golden capsule shipped in inst/extdata into a fresh folder.
golden <- function() {
  src <- system.file("extdata", "capsule", package = "noqtis")
  d <- tempfile("nqcap")
  dir.create(d)
  file.copy(list.files(src, full.names = TRUE, all.files = TRUE,
    no.. = TRUE), d, recursive = TRUE)
  # the zero-length file, in case an archive tool dropped it
  if (!file.exists(file.path(d, "empty"))) file.create(file.path(d, "empty"))
  d
}

# The key the golden capsule was sealed with (seed bytes 0, 1, ..., 31).
gkey <- function() nqkeygen("ML-DSA-44", seed = as.raw(0:31))

flip <- function(x, i = 1L) {
  x[i] <- xor(x[i], as.raw(1L))
  x
}

# RFC 4648 base64, for the CLI's key files and the timestamp field.
b64e <- function(x) {
  a <- c(LETTERS, letters, 0:9, "+", "/")
  x <- as.integer(x)
  n <- length(x)
  pad <- (3L - n %% 3L) %% 3L
  x <- c(x, integer(pad))
  out <- character(0)
  for (i in seq(1L, length(x), by = 3L)) {
    v <- x[i] * 65536L + x[i + 1L] * 256L + x[i + 2L]
    out <- c(out, a[v %/% 262144L + 1L], a[(v %/% 4096L) %% 64L + 1L],
      a[(v %/% 64L) %% 64L + 1L], a[v %% 64L + 1L])
  }
  if (pad > 0L) out[(length(out) - pad + 1L):length(out)] <- "="
  paste(out, collapse = "")
}

b64d <- function(s) {
  a <- c(LETTERS, letters, 0:9, "+", "/")
  ch <- strsplit(gsub("[\r\n]", "", s), "")[[1]]
  pad <- sum(ch == "=")
  v <- match(ch[ch != "="], a) - 1L
  v <- c(v, integer(pad))
  out <- integer(0)
  for (i in seq(1L, length(v), by = 4L)) {
    w <- v[i] * 262144L + v[i + 1L] * 4096L + v[i + 2L] * 64L + v[i + 3L]
    out <- c(out, w %/% 65536L, (w %/% 256L) %% 256L, w %% 256L)
  }
  as.raw(out[seq_len(length(out) - pad)])
}

# A noqtis-key-1 public key file, and its reader.
wpub <- function(path, alg, pk) {
  b <- b64e(pk)
  l <- substring(b, seq(1L, nchar(b), 64L),
    pmin(seq(64L, nchar(b) + 63L, 64L), nchar(b)))
  writeLines(c(paste("noqtis-key-1", alg, "pub"), l), path, sep = "\n")
}

rpub <- function(path) {
  l <- readLines(path)
  list(alg = strsplit(l[1], " ")[[1]][2], pk = b64d(paste(l[-1],
    collapse = "")))
}

# The noqtis command-line tool: NOQTIS_CLI, else noqtis on the PATH.
cli <- function() {
  p <- Sys.getenv("NOQTIS_CLI", "")
  if (!nzchar(p)) p <- Sys.which("noqtis")
  if (!nzchar(p) || !file.exists(p)) "" else unname(p)
}

runcli <- function(...) {
  out <- suppressWarnings(system2(cli(), c(...), stdout = TRUE,
    stderr = TRUE))
  s <- attr(out, "status")
  list(out = out, rc = if (is.null(s)) 0L else s)
}

# The base64 public key in a seal file (JSON), without a JSON parser.
sealpk <- function(path) {
  s <- readChar(path, file.size(path), useBytes = TRUE)
  sub('.*"public_key":"([^"]*)".*', "\\1", s)
}
