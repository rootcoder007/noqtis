# The CLI's key files (docs/guides/keys.md, docs/spec/keyfile.md): a
# header line "noqtis-key-1 <algorithm> <pub|sec>", or "noqtis-key-2
# <algorithm> sec" for a signature secret key in the version 2 container,
# then the key bytes as padded base64 in lines of 64 characters.

#' Read and write the command-line tool's key files
#'
#' `nqreadkey()` reads a key file written by `noqtis keygen` (or by
#' `nqwritekey()`), as strictly as the command-line tool reads it: the
#' exact header line `noqtis-key-1 <algorithm> <pub|sec>`, then the key as
#' padded base64 (RFC 4648) with LF or CRLF line ends and no other
#' character, canonical padding, and exactly the algorithm's key size.
#' `nqwritekey()` writes one. A signature secret key is written as
#' `noqtis-key-2 <algorithm> sec` holding its version 2 container
#' ([nqsxmk()]: the key with an integrity value that every signature
#' checks), and `nqreadkey()` returns that container, which checks when
#' it is read and signs as the key does; a key file of version 1 (before
#' noqtis 0.3.0) still reads, as the key alone. With `pass`, a secret
#' key file is kept under a passphrase (noqtis-pwkey-1, as
#' `noqtis keygen --pass-fd` writes it: Argon2id of the passphrase, 64
#' MiB, 3 passes and 4 lanes, then ChaCha20-Poly1305); `nqreadkey()`
#' needs the same `pass` to read it. `nqpwenc()` and `nqpwdec()` are
#' that protection on its own, for a key of up to 65536 bytes kept
#' elsewhere; `nqpwenc2()` is `nqpwenc()`
#' with PBKDF2 (HMAC-SHA-256) in place of Argon2id when `kdf` is
#' `"pbkdf2"`, as `noqtis keygen --kdf pbkdf2` writes it, and `nqpwdec()`
#' and `nqreadkey()` read both. They call the library's `nqpwenc()`,
#' `nqpwenc2()` and `nqpwdec()`, whose manual page nqpwenc(3) gives the
#' construction in full.
#'
#' @param path The key file.
#' @param key The key, a raw vector (`$pk` or `$sk` of [nqkeygen()], or a
#'   container from [nqsxmk()]).
#' @param alg The algorithm name, one of `nqalgs()$name` (case is ignored).
#' @param kind `"pub"` for a public key, `"sec"` for a secret key.
#' @param force `TRUE` to replace an existing file; it is removed first,
#'   so the new file never inherits its permissions.
#' @param pass `NULL`, or the passphrase (1 to 4096 bytes): a raw vector
#'   or one string. Never written or shown anywhere; an error never
#'   repeats it.
#' @param sk The secret key, a raw vector.
#' @param x What `nqpwenc()` returned, a raw vector.
#' @param ad `NULL`, or associated data (a raw vector) bound to it.
#' @param m,t,p Argon2id's memory in KiB (8192 to 1048576), passes (1 to
#'   16) and lanes (1 to 16), with `m` times `t` at most 4194304; 0 for
#'   the defaults 65536, 3 and 4. With `kdf = "pbkdf2"`, `t` is the
#'   iteration count (100000 to 10000000; 0 for 600000) and `m` and `p`
#'   are 0.
#' @param kdf `"argon2id"` or `"pbkdf2"`: how the passphrase becomes the
#'   key's key.
#'
#' @return `nqreadkey()`: a list with `alg` (the algorithm name as the
#'   library spells it), `kind` (`"pub"` or `"sec"`) and `key` (a raw
#'   vector). `nqwritekey()`: `path`, invisibly. `nqpwenc()` and
#'   `nqpwenc2()`: the protected key, 51 bytes longer. `nqpwdec()`: the
#'   key.
#'
#' @details A secret key file is created readable by its owner only (on
#'   Windows it takes the folder's permissions). An existing file is never
#'   replaced unless `force = TRUE`, and a dangling symbolic link counts
#'   as an existing file. R's base64 here is not constant time: read
#'   secret key files where timing cannot be observed.
#'
#' @section Errors:
#' `nqreadkey()`: a file that is not a key file (a wrong header, a
#' non-canonical or cut-short body, a key of the wrong size); a version 2
#' key whose integrity value does not match; a key under
#' a passphrase without `pass`, a wrong passphrase or a changed file.
#' `nqwritekey()`: an unknown algorithm, a key of the wrong size for it,
#' or an existing file without `force = TRUE`.
#'
#' @references
#' Josefsson, S. (2006). *The Base16, Base32, and Base64 Data Encodings*,
#' RFC 4648. \doi{10.17487/RFC4648}
#'
#' Biryukov, A., Dinu, D., Khovratovich, D. and Josefsson, S. (2021).
#' *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
#' Applications*, RFC 9106. \doi{10.17487/RFC9106}
#'
#' Nir, Y. and Langley, A. (2018). *ChaCha20 and Poly1305 for IETF
#' Protocols*. RFC 8439. \doi{10.17487/RFC8439}
#'
#' @family key functions
#' @seealso [nqkeygen()], [nqsign()].
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' f <- tempfile()
#' nqwritekey(f, k$sk, "ML-DSA-44", "sec")
#' # a signature key reads back as its version 2 container
#' identical(nqreadkey(f)$key, nqsxmk(k$sk, "ML-DSA-44"))
#' readLines(f, n = 1)
#' g <- tempfile()
#' nqwritekey(g, k$pk, "ML-DSA-44", "pub")
#' nqreadkey(g)$kind
#' unlink(c(f, g))
#' # under a passphrase (light Argon2id parameters for the example)
#' x <- nqpwenc(k$sk, "a passphrase", m = 8192, t = 1, p = 1)
#' identical(nqpwdec(x, "a passphrase"), k$sk)
#' y <- nqpwenc2(k$sk, "a passphrase", "pbkdf2", t = 100000)
#' identical(nqpwdec(y, "a passphrase"), k$sk)
#' h <- tempfile()
#' nqwritekey(h, k$sk, "ML-DSA-44", "sec", pass = "a passphrase")
#' identical(
#'   nqreadkey(h, pass = "a passphrase")$key,
#'   nqsxmk(k$sk, "ML-DSA-44")
#' )
#' unlink(h)
#' @export
nqreadkey <- function(path, pass = NULL) {
  if (!.file1(path)) {
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
  f <- .kfhead(b[seq_len(nl[1L] - 1L)], path)
  a <- .kalg(f[2L])
  want <- .kfwant(a, f, path)
  k <- .kfopen(.kfbody(b[-seq_len(nl[1L])]), f[3L], a, want, pass, path,
               f[1L])
  .kfsound(k, want, a, f[1L] == "noqtis-key-2", path)
  list(alg = a$name, kind = f[3L], key = k)
}

#' The length of the key a file with header fields f holds: the version 2
#' container of a signature secret key, else the key itself.
#' @noRd
.kfwant <- function(a, f, path) {
  if (f[1L] != "noqtis-key-2") {
    return(if (f[3L] == "pub") a$pk else a$sk)
  }
  if (a$type != "sig") {
    stop(sprintf(paste0(
      "%s: a %s key has no version 2 container (only signature keys do)"
    ), path, a$name), call. = FALSE)
  }
  nqsxsz(a$name)
}

#' An error unless k is a key of want bytes and, for a version 2 file,
#' a container whose integrity value holds.
#' @noRd
.kfsound <- function(k, want, a, v2, path) {
  if (is.null(k) || length(k) != want) {
    stop(sprintf(paste0(
      "%s: the key is not %d bytes of base64 for %s (the ",
      "file is damaged or cut short)"
    ), path, want, a$name), call. = FALSE)
  }
  if (v2 && !nqsxchk(k, a$name)) {
    stop(sprintf(paste0(
      "%s: the secret key is damaged: its integrity value does not ",
      "match (restore the file from a copy)"
    ), path), call. = FALSE)
  }
  invisible(k)
}

#' @rdname nqreadkey
#' @export
nqwritekey <- function(path, key, alg, kind = c("sec", "pub"),
                       force = FALSE, pass = NULL) {
  kind <- match.arg(kind)
  if (!.is1(path)) {
    stop("'path' must be one file path", call. = FALSE)
  }
  if (!.flag1(force)) {
    stop("'force' must be TRUE or FALSE", call. = FALSE)
  }
  .rawarg(key, "key")
  if (!.is1(alg)) {
    stop("'alg' must be one algorithm name; see nqalgs()", call. = FALSE)
  }
  a <- .kalg(alg)
  key <- .kfkey(key, a, kind)
  magic <- if (kind == "sec" && a$type == "sig") {
    "noqtis-key-2"
  } else {
    "noqtis-key-1"
  }
  if (!is.null(pass)) {
    if (kind != "sec") {
      stop("a passphrase protects a secret key only", call. = FALSE)
    }
    key <- nqpwenc(key, pass, charToRaw(sprintf("%s %s sec", magic, a$name)))
  }
  .kfclear(path, force)
  txt <- c(sprintf("%s %s %s", magic, a$name, kind), .b64enc(key))
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

#' @rdname nqreadkey
#' @export
nqpwenc <- function(sk, pass, ad = NULL, m = 0, t = 0, p = 0) {
  .rawarg(sk, "sk")
  if (!is.null(ad)) .rawarg(ad, "ad")
  for (v in list(m, t, p)) {
    if (!.count1(v)) stop("'m', 't' and 'p' must be whole numbers",
                          call. = FALSE)
  }
  .Call(Cpwenc, .pass(pass), ad, as.double(c(m, t, p)), sk)
}

#' @rdname nqreadkey
#' @export
nqpwenc2 <- function(sk, pass, kdf = c("argon2id", "pbkdf2"), ad = NULL,
                     m = 0, t = 0, p = 0) {
  kdf <- match.arg(kdf)
  .rawarg(sk, "sk")
  if (!is.null(ad)) .rawarg(ad, "ad")
  for (v in list(m, t, p)) {
    if (!.count1(v)) stop("'m', 't' and 'p' must be whole numbers",
                          call. = FALSE)
  }
  .Call(Cpwenc2, if (kdf == "pbkdf2") 2L else 1L, .pass(pass), ad,
        as.double(c(m, t, p)), sk)
}

#' @rdname nqreadkey
#' @export
nqpwdec <- function(x, pass, ad = NULL) {
  .rawarg(x, "x")
  if (!is.null(ad)) .rawarg(ad, "ad")
  .Call(Cpwdec, .pass(pass), ad, x)
}

#' The bytes a key file holds for key: for a signature secret key its
#' version 2 container, made from the key or taken as it is once it
#' checks; else the key, of the algorithm's size.
#' @noRd
.kfkey <- function(key, a, kind) {
  if (kind == "sec" && a$type == "sig") {
    if (length(key) == a$sk) {
      return(nqsxmk(key, a$name))
    }
    if (length(key) != nqsxsz(a$name) || !nqsxchk(key, a$name)) {
      stop(sprintf(
        "a %s secret key is %d bytes (or a sound container of %d), not %d",
        a$name, a$sk, nqsxsz(a$name), length(key)
      ), call. = FALSE)
    }
    return(key)
  }
  want <- if (kind == "pub") a$pk else a$sk
  if (length(key) != want) {
    stop(sprintf(
      "a %s %s key is %d bytes, not %d", a$name, kind, want, length(key)
    ), call. = FALSE)
  }
  key
}

#' The passphrase's bytes, checked without showing it.
#' @noRd
.pass <- function(pass) {
  b <- if (is.raw(pass)) pass else if (.is1(pass)) {
    charToRaw(enc2utf8(pass))
  } else {
    stop("'pass' must be a raw vector or one string", call. = FALSE)
  }
  if (length(b) < 1L || length(b) > 4096L) {
    stop("'pass' must be 1 to 4096 bytes", call. = FALSE)
  }
  b
}

#' The key of a decoded body: opened with pass when it is under a
#' passphrase (noqtis-pwkey-1), else as it is.
#' @param k The decoded body, or NULL.
#' @param kind "pub" or "sec".
#' @param a The algorithm's row of the table.
#' @param want The key's size.
#' @param pass The passphrase, or NULL.
#' @param path The key file, for messages.
#' @param magic The file's first word, part of the passphrase's ad.
#' @noRd
.kfopen <- function(k, kind, a, want, pass, path, magic = "noqtis-key-1") {
  sec <- kind == "sec" && !is.null(k)
  prot <- sec && length(k) == want + 51L &&
    identical(k[1:4], charToRaw("NQPW"))
  if (prot && is.null(pass)) {
    stop(sprintf("%s is protected by a passphrase: give 'pass'", path),
      call. = FALSE
    )
  }
  if (prot) {
    ad <- charToRaw(sprintf("%s %s sec", magic, a$name))
    return(nqpwdec(k, pass, ad))
  }
  if (!is.null(pass) && sec && length(k) == want) {
    stop(sprintf("%s is not protected by a passphrase", path),
      call. = FALSE
    )
  }
  k
}

.b64a <- c(LETTERS, letters, as.character(0:9), "+", "/")

#' The base64 text of a raw vector, in lines of 64 characters.
#' @noRd
.b64enc <- function(x) {
  if (length(x) == 0L) {
    return(character(0))
  }
  v <- as.integer(x)
  pad <- (3L - length(v) %% 3L) %% 3L
  v <- matrix(c(v, integer(pad)), nrow = 3L)
  w <- v[1L, ] * 65536L + v[2L, ] * 256L + v[3L, ]
  q <- rbind(
    w %/% 262144L, (w %/% 4096L) %% 64L, (w %/% 64L) %% 64L,
    w %% 64L
  )
  ch <- .b64a[as.vector(q) + 1L]
  if (pad > 0L) {
    ch[(length(ch) - pad + 1L):length(ch)] <- "="
  }
  s <- paste(ch, collapse = "")
  st <- seq(1L, nchar(s), by = 64L)
  substring(s, st, pmin(st + 63L, nchar(s)))
}

#' The bytes of strict base64 (RFC 4648, padded, canonical), or NULL.
#' @noRd
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

#' Any algorithm by name (case ignored), as the CLI finds it.
#' @noRd
.kalg <- function(name) {
  t <- .tab()
  i <- match(toupper(name), toupper(t$name))
  if (is.na(i)) {
    stop(sprintf("unknown algorithm '%s'; see nqalgs()", name),
      call. = FALSE
    )
  }
  t[i, , drop = FALSE]
}

#' The error for a file that is not a key file.
#' @noRd
.kfbad <- function(path) {
  stop(sprintf(paste0(
    "%s is not a noqtis key file (want a first line ",
    "\"noqtis-key-1 <alg> <pub|sec>\" or \"noqtis-key-2 <alg> sec\")"
  ), path), call. = FALSE)
}

#' The header fields of a key file, or an error: the exact line
#' "noqtis-key-1 <alg> <pub|sec>" or "noqtis-key-2 <alg> sec" (a CR
#' before the LF dropped).
#' @noRd
.kfhead <- function(h, path) {
  if (length(h) > 0L && h[length(h)] == as.raw(13L)) {
    h <- h[-length(h)]
  }
  if (any(h < as.raw(32L) | h > as.raw(126L))) {
    .kfbad(path)
  }
  f <- strsplit(rawToChar(h), " ", fixed = TRUE)[[1L]]
  if (length(f) != 3L || !grepl(" [^ ]+$", rawToChar(h)) ||
        !(f[1L] %in% c("noqtis-key-1", "noqtis-key-2")) ||
        !(f[3L] %in% c("pub", "sec")) ||
        (f[1L] == "noqtis-key-2" && f[3L] != "sec")) {
    .kfbad(path)
  }
  f
}

#' The key bytes of the base64 body (line ends dropped), or NULL.
#' @noRd
.kfbody <- function(rest) {
  rest <- rest[rest != as.raw(10L) & rest != as.raw(13L)]
  if (any(rest < as.raw(33L) | rest > as.raw(126L))) {
    return(NULL)
  }
  .b64dec(rawToChar(rest))
}

#' Clears path for a new key file: an existing file, or a dangling link
#' (Sys.readlink() is NA for no file), is removed with force, refused
#' without it.
#' @noRd
.kfclear <- function(path, force) {
  lk <- Sys.readlink(path)
  if (!file.exists(path) && (is.na(lk) || !nzchar(lk))) {
    return(invisible())
  }
  if (!force) {
    stop(sprintf("%s exists (force = TRUE replaces it)", path),
      call. = FALSE
    )
  }
  if (!file.remove(path)) {
    stop(sprintf("cannot remove %s", path), call. = FALSE)
  }
  invisible()
}
