#' BLAKE2b, Argon2id and constant-time comparison
#'
#' `nqblake2b()` is BLAKE2b (RFC 7693): an `n`-byte digest of `x`, keyed
#' (a MAC) with up to 64 bytes of `key`. `nqargon2id()` is Argon2id (RFC
#' 9106, version 0x13), the memory-hard password hash: `n` bytes from the
#' password and the salt, `t` passes over `m` KiB of memory in `p`
#' lanes, with an optional secret key and associated data. `nqcteq()`
#' compares two raw vectors in time that depends only on their length;
#' compare MACs and tags with it.
#'
#' @param x The message: a raw vector, or one string (its UTF-8 bytes).
#' @param key `NULL`, or a raw vector: the BLAKE2b key (0 to 64 bytes), or
#'   Argon2id's secret key.
#' @param n The output length in bytes: 1 to 64 for BLAKE2b, 4 to 1024
#'   for Argon2id.
#' @param pw The password, a raw vector or one string.
#' @param salt The salt, a raw vector of 8 bytes or more (16 is usual).
#' @param t Passes, 1 to 1024.
#' @param m Memory in KiB, 8 `p` to 4194304.
#' @param p Lanes, 1 to 255; they run one after another.
#' @param ad `NULL`, or associated data, a raw vector.
#' @param a,b Raw vectors to compare.
#'
#' @return `nqblake2b()` and `nqargon2id()`: a raw vector of `n` bytes.
#'   `nqcteq()`: `TRUE` or `FALSE`.
#'
#' @section Errors:
#' A length or cost out of the ranges above, or an argument of the wrong
#' type.
#'
#' @references
#' Saarinen, M.-J. and Aumasson, J.-P. (2015). *The BLAKE2 Cryptographic
#' Hash and Message Authentication Code (MAC)*, RFC 7693.
#' \doi{10.17487/RFC7693}
#'
#' Biryukov, A., Dinu, D., Khovratovich, D. and Josefsson, S. (2021).
#' *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
#' Applications*, RFC 9106. \doi{10.17487/RFC9106}
#'
#' @family hash functions
#'
#' @examples
#' nqblake2b("abc")
#' nqblake2b("abc", key = as.raw(1:32), n = 32)
#' nqargon2id("password", as.raw(1:16), t = 1, m = 8, p = 1)
#' nqcteq(nqblake2b("a"), nqblake2b("a"))
#' @export
nqblake2b <- function(x, key = NULL, n = 64L) {
  if (!.count1(n)) stop("'n' must be a whole number", call. = FALSE)
  if (!is.null(key)) .rawarg(key, "key")
  .Call(Cb2b, key, .bytes(x, "x"), as.integer(n))
}

#' @rdname nqblake2b
#' @export
nqargon2id <- function(pw, salt, t = 3, m = 65536, p = 4, n = 32L,
                       key = NULL, ad = NULL) {
  for (v in list(t, m, p, n)) {
    if (!is.numeric(v) || length(v) != 1L || is.na(v) || v < 0 ||
          v != floor(v) || v > 4294967295) {
      stop("'t', 'm', 'p' and 'n' must be whole numbers", call. = FALSE)
    }
  }
  .rawarg(salt, "salt")
  if (!is.null(key)) .rawarg(key, "key")
  if (!is.null(ad)) .rawarg(ad, "ad")
  .Call(
    Ca2id, .bytes(pw, "pw"), salt, key, ad, as.double(c(t, m, p)),
    as.integer(n)
  )
}

#' @rdname nqblake2b
#' @export
nqcteq <- function(a, b) .Call(Ccteq, .rawarg(a, "a"), .rawarg(b, "b"))

#' ML-DSA with an external mu
#'
#' `nqmu()` computes the 64-byte message representative mu of FIPS 204
#' for a message under a public key, as [nqsign()] computes it, so that a
#' large message can be hashed apart from where the secret key is (a
#' token, a hardware module). `nqsignmu()` signs that mu: the signature
#' is the one [nqsign()] gives for the message with the same randomness.
#' `nqverifymu()` checks a signature against a mu.
#'
#' @param pk Public key, a raw vector.
#' @param sk Secret key, a raw vector.
#' @param msg The message: a raw vector or one string.
#' @param mu The 64-byte mu, a raw vector (from `nqmu()`).
#' @param sig The signature, a raw vector.
#' @param alg `"ML-DSA-44"`, `"ML-DSA-65"` or `"ML-DSA-87"`.
#' @param ctx `NULL`, or the context string (at most 255 bytes), a raw
#'   vector or one string.
#' @param ph `NULL` for the pure variant, or a hash name (see [nqhash()])
#'   for HashML-DSA.
#' @param det `TRUE` for the deterministic signature.
#' @param rnd `NULL`, or the 32 bytes of per-signature randomness.
#'
#' @return `nqmu()`: a raw vector of 64 bytes. `nqsignmu()`: the signature.
#'   `nqverifymu()`: `TRUE` or `FALSE`.
#'
#' @section Errors:
#' An algorithm other than ML-DSA, a mu that is not 64 bytes, a key of the
#' wrong size.
#'
#' @references
#' National Institute of Standards and Technology (2024).
#' *Module-Lattice-Based Digital Signature Standard*, FIPS 204, Algorithm
#' 7 line 6 and Algorithm 8 line 7. \doi{10.6028/NIST.FIPS.204}
#'
#' @family signature functions
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' mu <- nqmu(k$pk, "a long message", "ML-DSA-44")
#' s <- nqsignmu(k$sk, mu, "ML-DSA-44", det = TRUE)
#' identical(s, nqsign(k$sk, "a long message", "ML-DSA-44", det = TRUE))
#' nqverifymu(k$pk, mu, s, "ML-DSA-44")
#' @export
nqmu <- function(pk, msg, alg, ctx = NULL, ph = NULL) {
  a <- .alg(alg, "sig")
  .Call(
    Csmu, a$id, .rawarg(pk, "pk"), .bytes(msg, "msg"), .ctxb(ctx),
    .ph(ph)
  )
}

#' @rdname nqmu
#' @export
nqsignmu <- function(sk, mu, alg, det = FALSE, rnd = NULL) {
  a <- .alg(alg, "sig")
  .Call(
    Csignmu, a$id, .rawarg(sk, "sk"), .rawarg(mu, "mu"),
    .rnd(det, rnd, 32L)
  )
}

#' @rdname nqmu
#' @export
nqverifymu <- function(pk, mu, sig, alg) {
  a <- .alg(alg, "sig")
  .Call(
    Cvrfymu, a$id, .rawarg(pk, "pk"), .rawarg(mu, "mu"),
    .rawarg(sig, "sig")
  )
}

# A context string: NULL, a raw vector or one string.
.ctxb <- function(ctx) if (is.null(ctx)) NULL else .bytes(ctx, "ctx")

# The per-signature randomness of det and rnd: NULL (hedged), n zeros.
.rnd <- function(det, rnd, n) {
  if (!.flag1(det)) stop("'det' must be TRUE or FALSE", call. = FALSE)
  if (det && !is.null(rnd)) {
    stop("'det' and 'rnd' exclude each other", call. = FALSE)
  }
  if (det) {
    return(raw(n))
  }
  if (!is.null(rnd)) .rawarg(rnd, "rnd")
  rnd
}

#' Sign and verify a message given in pieces
#'
#' `nqsigner()` and `nqverifier()` start a signature or its check over a
#' message that arrives in pieces; `nqupdate()` adds each piece, and
#' `nqfinish()` gives the signature (the bytes [nqsign()] gives for the
#' whole message with the same randomness) or whether it verifies. Only
#' the piece at hand is held in memory. `nqsignfile()` and
#' `nqverifyfile()` do it for a file, 64 KiB at a time.
#'
#' What streams: ML-DSA (pure and with a pre-hash); HashSLH-DSA,
#' Ed25519ph and the ML-DSA+Ed25519 hybrids with `ph = "sha512"`. Pure
#' SLH-DSA, pure Ed25519 and the pure hybrids read the message twice and
#' cannot stream (an error). A stream is used once: after `nqfinish()` it
#' is an error to use it again. The secret key is not copied into the
#' stream; it is given again to `nqfinish()` through the stream, which
#' keeps a reference to it.
#'
#' @inheritParams nqmu
#' @param s A stream from `nqsigner()` or `nqverifier()`.
#' @param x The next piece: a raw vector or one string.
#' @param file The path of the file to sign or check.
#'
#' @return `nqsigner()`, `nqverifier()`: a stream (class `"nqstream"`).
#'   `nqupdate()`: `s`, invisibly. `nqfinish()` and `nqsignfile()`: the
#'   signature (a signer), or `TRUE` or `FALSE` (a verifier, with `sig`).
#'   `nqverifyfile()`: `TRUE` or `FALSE`.
#'
#' @section Errors:
#' An algorithm and variant that cannot stream, a stream used after its
#' end, a key of the wrong size.
#'
#' @family signature functions
#'
#' @examples
#' k <- nqkeygen("ML-DSA-44")
#' s <- nqsigner(k$sk, "ML-DSA-44")
#' nqupdate(s, "part one, ")
#' nqupdate(s, "part two")
#' sig <- nqfinish(s, det = TRUE)
#' identical(sig, nqsign(k$sk, "part one, part two", "ML-DSA-44", det = TRUE))
#' v <- nqverifier(k$pk, "ML-DSA-44")
#' nqupdate(v, "part one, part two")
#' nqfinish(v, sig = sig)
#' f <- tempfile()
#' writeBin(as.raw(0:255), f)
#' nqverifyfile(f, k$pk, nqsignfile(f, k$sk, "ML-DSA-44"), "ML-DSA-44")
#' unlink(f)
#' @export
nqsigner <- function(sk, alg, ctx = NULL, ph = NULL) {
  a <- .alg(alg, "sig")
  p <- .Call(Csini, a$id, .rawarg(sk, "sk"), .ctxb(ctx), .ph(ph), FALSE)
  structure(list(p = p, alg = a, key = sk, verify = FALSE),
    class = "nqstream"
  )
}

#' @rdname nqsigner
#' @export
nqverifier <- function(pk, alg, ctx = NULL, ph = NULL) {
  a <- .alg(alg, "sig")
  p <- .Call(Csini, a$id, .rawarg(pk, "pk"), .ctxb(ctx), .ph(ph), TRUE)
  structure(list(p = p, alg = a, key = pk, verify = TRUE),
    class = "nqstream"
  )
}

.stream <- function(s) {
  if (!inherits(s, "nqstream")) {
    stop("'s' must be a stream from nqsigner() or nqverifier()",
      call. = FALSE
    )
  }
  s
}

#' @rdname nqsigner
#' @export
nqupdate <- function(s, x) {
  .Call(Csupd, .stream(s)$p, .bytes(x, "x"))
  invisible(s)
}

#' @rdname nqsigner
#' @export
nqfinish <- function(s, sig = NULL, det = FALSE, rnd = NULL) {
  s <- .stream(s)
  if (s$verify) {
    return(.Call(Cvfin, s$p, s$key, .rawarg(sig, "sig")))
  }
  n <- .rndlen(s$alg)
  .Call(Csfin, s$p, s$alg$id, s$key, .rnd(det, rnd, n))
}

# Bytes of per-signature randomness: 32 for ML-DSA and the hybrids, n for
# SLH-DSA, none for Ed25519.
.rndlen <- function(a) {
  if (a$name == "Ed25519") {
    return(0L)
  }
  if (startsWith(a$name, "ML-DSA")) 32L else a$pk %/% 2L
}

#' @export
print.nqstream <- function(x, ...) {
  cat(sprintf(
    "<noqtis %s stream, %s>\n", if (x$verify) "verify" else "sign",
    x$alg$name
  ))
  invisible(x)
}

# Feeds the file at path to the stream s, 64 KiB at a time.
.feed <- function(s, path) {
  if (!.file1(path)) stop("'file' must be one existing file", call. = FALSE)
  con <- file(path, open = "rb")
  on.exit(close(con))
  repeat {
    b <- readBin(con, "raw", n = 65536L)
    if (length(b) == 0L) break
    nqupdate(s, b)
  }
  s
}

#' @rdname nqsigner
#' @export
nqsignfile <- function(file, sk, alg, ctx = NULL, ph = NULL, det = FALSE) {
  nqfinish(.feed(nqsigner(sk, alg, ctx, ph), file), det = det)
}

#' @rdname nqsigner
#' @export
nqverifyfile <- function(file, pk, sig, alg, ctx = NULL, ph = NULL) {
  nqfinish(.feed(nqverifier(pk, alg, ctx, ph), file), sig = sig)
}

#' Seal a message or a file to an ML-KEM key
#'
#' `nqkseal()` encrypts a message to an ML-KEM public key
#' (noqtis-kseal-1: ML-KEM, then ChaCha20-Poly1305 under a key derived
#' with HKDF-SHA-256); only the holder of the secret key opens it with
#' `nqkopen()`, and only with the same context. `nqbox()` encrypts a file
#' of any size the same way, in chunks, in the format of `noqtis box`
#' (noqtis-kstream-1), holding one chunk in memory; `nqunbox()` opens it,
#' writing each chunk only once its tag verifies, and removes what it
#' wrote when one does not.
#'
#' @param msg The message: a raw vector or one string.
#' @param x What `nqkseal()` returned.
#' @param pk,sk The ML-KEM key pair (from [nqkeygen()]).
#' @param alg `"ML-KEM-512"`, `"ML-KEM-768"` or `"ML-KEM-1024"`.
#' @param ctx `NULL`, or a context (at most 255 bytes): a raw vector or
#'   one string, needed again to open.
#' @param input,output Paths of the file to read and of the file to write
#'   (which must not exist).
#' @param chunk The chunk size in bytes, 1024 to 16777216.
#'
#' @return `nqkseal()`: a raw vector. `nqkopen()`: the message, a raw
#'   vector. `nqbox()`, `nqunbox()`: `output`, invisibly.
#'
#' @section Errors:
#' A changed byte, another key or another context (the tag does not
#' verify), a cut, extended or reordered stream, bytes that are not a
#' sealed message or stream of this algorithm, an HQC key.
#'
#' @references
#' National Institute of Standards and Technology (2024).
#' *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203.
#' \doi{10.6028/NIST.FIPS.203}
#'
#' Hoang, V. T., Reyhanitabar, R., Rogaway, P. and Vizar, D. (2015).
#' Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance.
#' *CRYPTO 2015*. \doi{10.1007/978-3-662-47989-6_24}
#'
#' @family key encapsulation functions
#'
#' @examples
#' k <- nqkeygen("ML-KEM-768")
#' x <- nqkseal("a hidden list", k$pk, "ML-KEM-768", ctx = "trial 1")
#' rawToChar(nqkopen(x, k$sk, "ML-KEM-768", ctx = "trial 1"))
#' f <- tempfile()
#' writeBin(as.raw(rep(0:255, 20)), f)
#' g <- tempfile()
#' h <- tempfile()
#' nqbox(f, g, k$pk, "ML-KEM-768", chunk = 1024)
#' nqunbox(g, h, k$sk, "ML-KEM-768")
#' identical(readBin(h, "raw", 5120), readBin(f, "raw", 5120))
#' unlink(c(f, g, h))
#' @export
nqkseal <- function(msg, pk, alg, ctx = NULL) {
  a <- .alg(alg, "kem")
  .Call(Ckseal, a$id, .rawarg(pk, "pk"), .ctxb(ctx), .bytes(msg, "msg"))
}

#' @rdname nqkseal
#' @export
nqkopen <- function(x, sk, alg, ctx = NULL) {
  a <- .alg(alg, "kem")
  .Call(Ckopen, a$id, .rawarg(sk, "sk"), .ctxb(ctx), .rawarg(x, "x"))
}

# Moves the connection i to o in pieces of n bytes through f(b, last),
# the last piece the one no byte follows, one piece in memory.
.pump <- function(i, o, n, f) {
  b <- readBin(i, "raw", n = n)
  repeat {
    nx <- if (length(b) == n) readBin(i, "raw", n = 1L) else raw(0)
    last <- length(nx) == 0L
    writeBin(f(b, last), o)
    if (last) break
    b <- c(nx, readBin(i, "raw", n = n - 1L))
  }
}

.io <- function(input, output) {
  if (!.file1(input)) stop("'input' must be one existing file", call. = FALSE)
  if (!.is1(output) || file.exists(output)) {
    stop("'output' must be the path of a file that does not exist",
      call. = FALSE
    )
  }
}

#' @rdname nqkseal
#' @export
nqbox <- function(input, output, pk, alg, ctx = NULL, chunk = 65536L) {
  a <- .alg(alg, "kem")
  .io(input, output)
  if (!.count1(chunk)) stop("'chunk' must be a whole number", call. = FALSE)
  x <- .Call(Ckfeini, a$id, .rawarg(pk, "pk"), .ctxb(ctx), as.integer(chunk))
  i <- file(input, open = "rb")
  on.exit(close(i))
  o <- file(output, open = "wb")
  ok <- FALSE
  on.exit(
    {
      close(o)
      if (!ok) unlink(output)
    },
    add = TRUE
  )
  writeBin(x[[2]], o)
  .pump(i, o, as.integer(chunk), function(b, last) {
    .Call(Ckfupd, x[[1]], b, last, FALSE, as.integer(chunk))
  })
  ok <- TRUE
  invisible(output)
}

#' @rdname nqkseal
#' @export
nqunbox <- function(input, output, sk, alg, ctx = NULL) {
  a <- .alg(alg, "kem")
  .io(input, output)
  i <- file(input, open = "rb")
  on.exit(close(i))
  h <- readBin(i, "raw", n = 17L + a$ct)
  x <- .Call(Ckfdini, a$id, .rawarg(sk, "sk"), .ctxb(ctx), h)
  old <- Sys.umask("077")
  o <- file(output, open = "wb")
  Sys.umask(old)
  ok <- FALSE
  on.exit(
    {
      close(o)
      if (!ok) unlink(output)
    },
    add = TRUE
  )
  .pump(i, o, x[[2]] + 16L, function(b, last) {
    .Call(Ckfupd, x[[1]], b, last, TRUE, x[[2]])
  })
  ok <- TRUE
  invisible(output)
}
