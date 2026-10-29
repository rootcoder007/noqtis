.hashes <- c(
  "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256",
  "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256"
)

# The algorithm table, built once from the C library.
.tab <- local({
  t <- NULL
  function() {
    if (is.null(t)) {
      t <<- .algsraw()
    }
    t
  }
})

.algsraw <- function() {
  x <- .Call(Calgs)
  data.frame(
    name = x[[3]], type = x[[1]], pk = x[[4]], sk = x[[5]], sig = x[[6]],
    ct = x[[7]], ss = x[[8]], id = x[[2]], stringsAsFactors = FALSE
  )
}

# One row of the table for alg (a name, case ignored) of the given type.
.alg <- function(alg, type = c("sig", "kem")) {
  type <- match.arg(type)
  if (!is.character(alg) || length(alg) != 1L || is.na(alg)) {
    stop("'alg' must be one algorithm name; see nqalgs()", call. = FALSE)
  }
  t <- .tab()
  t <- t[t$type == type, , drop = FALSE]
  i <- match(toupper(alg), toupper(t$name))
  if (is.na(i)) {
    what <- if (type == "sig") "signature" else "key encapsulation"
    stop(sprintf("unknown %s algorithm '%s'; see nqalgs()", what, alg),
      call. = FALSE)
  }
  t[i, , drop = FALSE]
}

.kind <- function(alg) {
  t <- .tab()
  i <- match(toupper(alg), toupper(t$name))
  if (!is.character(alg) || length(alg) != 1L || is.na(i)) {
    stop("'alg' must be one algorithm name; see nqalgs()", call. = FALSE)
  }
  t$type[i]
}

# Hash name to the library's nqhalg number.
.hid <- function(alg) {
  if (!is.character(alg) || length(alg) != 1L || is.na(alg)) {
    stop("'alg' must be one hash name", call. = FALSE)
  }
  i <- match(tolower(alg), .hashes)
  if (is.na(i)) {
    stop(sprintf("unknown hash '%s'; one of: %s", alg,
      paste(.hashes, collapse = ", ")), call. = FALSE)
  }
  i
}

# Pre-hash argument: NULL (pure) or a hash name.
.ph <- function(ph) if (is.null(ph)) 0L else .hid(ph)

# A raw vector, or a single string taken as its UTF-8 bytes.
.bytes <- function(x, what) {
  if (is.raw(x)) {
    return(x)
  }
  if (is.character(x) && length(x) == 1L && !is.na(x)) {
    return(charToRaw(enc2utf8(x)))
  }
  stop(sprintf("'%s' must be a raw vector or one string", what),
    call. = FALSE)
}

.rawarg <- function(x, what) {
  if (!is.raw(x)) {
    stop(sprintf("'%s' must be a raw vector", what), call. = FALSE)
  }
  x
}

.hex <- function(x) paste(sprintf("%02x", as.integer(x)), collapse = "")

.dir <- function(dir) {
  if (!is.character(dir) || length(dir) != 1L || is.na(dir) ||
    !dir.exists(dir)) {
    stop("'dir' must be the path of an existing folder", call. = FALSE)
  }
  enc2utf8(normalizePath(dir, mustWork = TRUE))
}
