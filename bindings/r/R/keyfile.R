# The CLI's key files (DESIGN.md, "Key files"): a header line
# "noqtis-key-1 <algorithm> <pub|sec>", then the key bytes as padded base64
# in lines of 64 characters.

.b64a <- c(LETTERS, letters, as.character(0:9), "+", "/")

# The base64 text of a raw vector, in lines of 64 characters.
.b64enc <- function(x) {
  if (length(x) == 0L) {
    return(character(0))
  }
  v <- as.integer(x)
  pad <- (3L - length(v) %% 3L) %% 3L
  v <- matrix(c(v, integer(pad)), nrow = 3L)
  w <- v[1L, ] * 65536L + v[2L, ] * 256L + v[3L, ]
  q <- rbind(w %/% 262144L, (w %/% 4096L) %% 64L, (w %/% 64L) %% 64L,
    w %% 64L)
  ch <- .b64a[as.vector(q) + 1L]
  if (pad > 0L) {
    ch[(length(ch) - pad + 1L):length(ch)] <- "="
  }
  s <- paste(ch, collapse = "")
  st <- seq(1L, nchar(s), by = 64L)
  substring(s, st, pmin(st + 63L, nchar(s)))
}

# The bytes of strict base64 (RFC 4648, padded, canonical), or NULL.
.b64dec <- function(s) {
  r <- charToRaw(s)
  n <- length(r)
  if (n == 0L || n %% 4L != 0L) {
    return(NULL)
  }
  pad <- sum(r[c(n - 1L, n)] == charToRaw("="))
  if (pad == 1L && r[n - 1L] == charToRaw("=")) {
    return(NULL) # "x=" then a data character
  }
  tab <- rep(NA_integer_, 256L)
  tab[as.integer(charToRaw(paste(.b64a, collapse = ""))) + 1L] <- 0:63
  body <- r[seq_len(n - pad)]
  v <- tab[as.integer(body) + 1L]
  if (anyNA(v)) {
    return(NULL) # outside the alphabet, or '=' before the end
  }
  v <- c(v, integer(pad))
  q <- matrix(v, nrow = 4L)
  w <- q[1L, ] * 262144L + q[2L, ] * 4096L + q[3L, ] * 64L + q[4L, ]
  b <- rbind(w %/% 65536L, (w %/% 256L) %% 256L, w %% 256L)
  out <- as.raw(as.vector(b))
  out <- out[seq_len(length(out) - pad)]
  # canonical: the bits the padding drops are zero
  if (!identical(paste(.b64enc(out), collapse = ""), s)) {
    return(NULL)
  }
  out
}

# Any algorithm by name (case ignored), as the CLI finds it.
.kalg <- function(name) {
  t <- .tab()
  i <- match(toupper(name), toupper(t$name))
  if (is.na(i)) {
    stop(sprintf("unknown algorithm '%s'; see nqalgs()", name),
      call. = FALSE)
  }
  t[i, , drop = FALSE]
}

.kfbad <- function(path) {
  stop(sprintf(paste0("%s is not a noqtis key file (want a first line ",
    "\"noqtis-key-1 <alg> <pub|sec>\")"), path), call. = FALSE)
}

#' Read and write the command-line tool's key files
#'
#' `nqreadkey()` reads a key file written by `noqtis keygen` (or by
#' `nqwritekey()`), as strictly as the command-line tool reads it: the
#' exact header line `noqtis-key-1 <algorithm> <pub|sec>`, then the key as
#' padded base64 with LF or CRLF line ends and no other character,
#' canonical padding, and exactly the algorithm's key size.
#' `nqwritekey()` writes one.
#'
#' @param path The key file.
#' @param key The key, a raw vector (`$pk` or `$sk` of [nqkeygen()]).
#' @param alg The algorithm name, one of `nqalgs()$name` (case is ignored).
#' @param kind `"pub"` for a public key, `"sec"` for a secret key.
#' @param force `TRUE` to replace an existing file; it is removed first,
#'   so the new file never inherits its permissions.
#'
#' @return `nqreadkey()`: a list with `alg` (the algorithm name as the
#'   library spells it), `kind` (`"pub"` or `"sec"`) and `key` (a raw
#'   vector). `nqwritekey()`: `path`, invisibly.
#'
#' @details A secret key file is created readable by its owner only (on
#'   Windows it takes the folder's permissions). An existing file is never
#'   replaced unless `force = TRUE`. R's base64 here is not constant time:
#'   read secret key files where timing cannot be observed.
#'
#' @seealso [nqkeygen()], [nqsign()].
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' f <- tempfile()
#' nqwritekey(f, k$sk, "ML-DSA-44", "sec")
#' identical(nqreadkey(f)$key, k$sk)
#' readLines(f, n = 1)
#' @export
nqreadkey <- function(path) {
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
    !file.exists(path) || dir.exists(path)) {
    stop("'path' must be one existing key file", call. = FALSE)
  }
  sz <- file.size(path)
  if (is.na(sz) || sz > 1048576) {
    .kfbad(path)
  }
  b <- readBin(path, "raw", n = sz)
  nl <- which(b == as.raw(10L))
  if (length(nl) == 0L || nl[1L] > 96L) {
    .kfbad(path)
  }
  h <- b[seq_len(nl[1L] - 1L)]
  if (length(h) > 0L && h[length(h)] == as.raw(13L)) {
    h <- h[-length(h)]
  }
  if (any(h < as.raw(32L) | h > as.raw(126L))) {
    .kfbad(path)
  }
  f <- strsplit(rawToChar(h), " ", fixed = TRUE)[[1L]]
  if (length(f) != 3L || !grepl(" [^ ]+$", rawToChar(h)) ||
    f[1L] != "noqtis-key-1" || !(f[3L] %in% c("pub", "sec"))) {
    .kfbad(path)
  }
  a <- .kalg(f[2L])
  want <- if (f[3L] == "pub") a$pk else a$sk
  rest <- b[-seq_len(nl[1L])]
  rest <- rest[rest != as.raw(10L) & rest != as.raw(13L)]
  k <- if (any(rest < as.raw(33L) | rest > as.raw(126L))) {
    NULL
  } else {
    .b64dec(rawToChar(rest))
  }
  if (is.null(k) || length(k) != want) {
    stop(sprintf(paste0("%s: the key is not %d bytes of base64 for %s (the ",
      "file is damaged or cut short)"), path, want, a$name), call. = FALSE)
  }
  list(alg = a$name, kind = f[3L], key = k)
}

#' @rdname nqreadkey
#' @export
nqwritekey <- function(path, key, alg, kind = c("sec", "pub"),
                       force = FALSE) {
  kind <- match.arg(kind)
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    stop("'path' must be one file path", call. = FALSE)
  }
  if (!is.logical(force) || length(force) != 1L || is.na(force)) {
    stop("'force' must be TRUE or FALSE", call. = FALSE)
  }
  .rawarg(key, "key")
  if (!is.character(alg) || length(alg) != 1L || is.na(alg)) {
    stop("'alg' must be one algorithm name; see nqalgs()", call. = FALSE)
  }
  a <- .kalg(alg)
  want <- if (kind == "pub") a$pk else a$sk
  if (length(key) != want) {
    stop(sprintf("a %s %s key is %d bytes, not %d", a$name, kind, want,
      length(key)), call. = FALSE)
  }
  # a dangling link counts as there (Sys.readlink() is NA for no file)
  lk <- Sys.readlink(path)
  if (file.exists(path) || (!is.na(lk) && nzchar(lk))) {
    if (!force) {
      stop(sprintf("%s exists (force = TRUE replaces it)", path),
        call. = FALSE)
    }
    if (!file.remove(path)) {
      stop(sprintf("cannot remove %s", path), call. = FALSE)
    }
  }
  txt <- c(sprintf("noqtis-key-1 %s %s", a$name, kind), .b64enc(key))
  old <- Sys.umask(if (kind == "sec") "077" else "022")
  on.exit(Sys.umask(old), add = TRUE)
  con <- file(path, open = "wb")
  on.exit(close(con), add = TRUE, after = FALSE)
  writeBin(charToRaw(paste0(paste(txt, collapse = "\n"), "\n")), con)
  if (kind == "sec") {
    Sys.chmod(path, "0600", use_umask = FALSE)
  }
  invisible(path)
}
