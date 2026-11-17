# Passphrase key files, streaming signatures, sealed messages and
# streams, external mu, BLAKE2b and Argon2id, against the known answers
# in fixtures/kat.txt (copied from the repository's tests/vectors).

kat <- function(set) {
  l <- readLines(test_path("fixtures", "kat.txt"))
  l <- l[!startsWith(l, "#")]
  blocks <- split(l[nzchar(l)], cumsum(!nzchar(l))[nzchar(l)])
  recs <- lapply(blocks, function(b) {
    kv <- regmatches(b, regexpr("=", b, fixed = TRUE), invert = TRUE)
    stats::setNames(
      vapply(kv, function(x) if (length(x) > 1L) x[2L] else "", ""),
      vapply(kv, `[`, "", 1L)
    )
  })
  Filter(function(r) identical(r[["set"]], set), unname(recs))
}

hx <- function(s) {
  if (!nzchar(s)) {
    return(raw(0))
  }
  as.raw(strtoi(substring(s, seq(1L, nchar(s), 2L), seq(2L, nchar(s), 2L)),
                16L))
}

test_that("passphrase-protected keys open to the known answers", {
  r <- kat("pwk")[[1]]
  expect_identical(nqpwdec(hx(r[["out"]]), hx(r[["pw"]]), hx(r[["ad"]])),
                   hx(r[["sk"]]))
  out <- hx(r[["out"]])
  expect_error(nqpwdec(out, "wrong", hx(r[["ad"]])), "verification failed")
  expect_error(nqpwdec(out, hx(r[["pw"]]), as.raw(1)), "verification failed")
  expect_error(nqpwdec(out[1:40], hx(r[["pw"]]), hx(r[["ad"]])))
  expect_error(nqpwdec(flip(out, length(out)), hx(r[["pw"]]), hx(r[["ad"]])),
               "verification failed")
  e <- tryCatch(nqpwdec(out, "s3cret-pass"), error = conditionMessage)
  expect_false(grepl("s3cret", e, fixed = TRUE))
})

test_that("key files under a passphrase round-trip", {
  k <- nqkeygen("ML-DSA-44")
  x <- nqpwenc(k$sk, "pw", m = 8192, t = 1, p = 1)
  expect_length(x, length(k$sk) + 51L)
  expect_identical(nqpwdec(x, charToRaw("pw")), k$sk)
  expect_error(nqpwenc(k$sk, "pw", m = 1024, t = 1, p = 1))
  expect_error(nqpwenc(k$sk, ""), "1 to 4096")
  expect_error(nqpwenc(k$sk, 1), "raw vector or one string")
  f <- tempfile()
  on.exit(unlink(f))
  nqwritekey(f, k$sk, "ML-DSA-44", "sec", pass = "pw")
  expect_match(readLines(f, n = 1L), "^noqtis-key-1 ML-DSA-44 sec$")
  expect_identical(nqreadkey(f, pass = "pw")$key, k$sk)
  expect_error(nqreadkey(f), "protected by a passphrase")
  expect_error(nqreadkey(f, pass = "no"), "verification failed")
  expect_error(nqwritekey(tempfile(), k$pk, "ML-DSA-44", "pub", pass = "x"),
               "secret key only")
})

test_that("streamed signatures are the one-call ones", {
  msg <- as.raw(rep(0:250, 40))
  for (a in list(c("ML-DSA-44", ""), c("ML-DSA-65", "sha512"),
                 c("SLH-DSA-SHA2-128f", "sha256"), c("Ed25519", "sha512"),
                 c("ML-DSA-65+Ed25519", "sha512"))) {
    ph <- if (nzchar(a[2])) a[2] else NULL
    n <- c("ML-DSA-44" = 32, "ML-DSA-65" = 32, "SLH-DSA-SHA2-128f" = 48,
           "Ed25519" = 32, "ML-DSA-65+Ed25519" = 64)[[a[1]]]
    k <- nqkeygen(a[1], seed = as.raw(seq_len(n) - 1L))
    want <- nqsign(k$sk, msg, a[1], ctx = "c", ph = ph, det = TRUE)
    for (step in c(1L, 999L, length(msg))) {
      s <- nqsigner(k$sk, a[1], ctx = "c", ph = ph)
      for (i in seq(1L, length(msg), by = step)) {
        nqupdate(s, msg[i:min(i + step - 1L, length(msg))])
      }
      expect_identical(nqfinish(s, det = TRUE), want)
      expect_error(nqupdate(s, msg), "out of order")
    }
    v <- nqverifier(k$pk, a[1], ctx = "c", ph = ph)
    nqupdate(v, msg)
    expect_true(nqfinish(v, sig = want))
    v <- nqverifier(k$pk, a[1], ctx = "c", ph = ph)
    nqupdate(v, msg[-1])
    expect_false(nqfinish(v, sig = want))
  }
  k <- nqkeygen("SLH-DSA-SHA2-128f")
  expect_error(nqsigner(k$sk, "SLH-DSA-SHA2-128f"), "not supported")
  expect_error(nqupdate(list(), raw(1)), "stream from")
  f <- tempfile()
  on.exit(unlink(f))
  writeBin(msg, f)
  k <- nqkeygen("ML-DSA-44")
  s <- nqsignfile(f, k$sk, "ML-DSA-44", det = TRUE)
  expect_identical(s, nqsign(k$sk, msg, "ML-DSA-44", det = TRUE))
  expect_true(nqverifyfile(f, k$pk, s, "ML-DSA-44"))
  expect_output(print(nqsigner(k$sk, "ML-DSA-44")), "sign stream")
  expect_output(print(nqverifier(k$pk, "ML-DSA-44")), "verify stream")
})

test_that("sealed messages open to the known answers", {
  for (r in kat("kseal")) {
    k <- nqkeygen(r[["alg"]], seed = hx(r[["kseed"]]))
    expect_identical(nqkopen(hx(r[["out"]]), k$sk, r[["alg"]],
                             ctx = hx(r[["ctx"]])), hx(r[["msg"]]))
  }
  r <- kat("kseal")[[2]]
  k <- nqkeygen(r[["alg"]], seed = hx(r[["kseed"]]))
  out <- hx(r[["out"]])
  expect_error(nqkopen(flip(out, 30L), k$sk, r[["alg"]], ctx = hx(r[["ctx"]])),
               "verification failed")
  expect_error(nqkopen(out[1:10], k$sk, r[["alg"]]), "encoding")
  x <- nqkseal("round", k$pk, r[["alg"]], ctx = "x")
  expect_identical(rawToChar(nqkopen(x, k$sk, r[["alg"]], ctx = "x")), "round")
  expect_error(nqkopen(x, k$sk, r[["alg"]], ctx = "y"), "verification failed")
  h <- nqkeygen("HQC-128")
  expect_error(nqkseal("m", h$pk, "HQC-128"), "not supported")
})

unboxed <- function(r, b) {
  k <- nqkeygen(r[["alg"]], seed = hx(r[["kseed"]]))
  f <- tempfile()
  g <- tempfile()
  on.exit(unlink(c(f, g)))
  writeBin(b, f)
  nqunbox(f, g, k$sk, r[["alg"]], ctx = hx(r[["ctx"]]))
  readBin(g, "raw", length(b) + 1L)
}

test_that("sealed streams open to the known answers, and refuse changes", {
  for (r in kat("kstream")) {
    expect_identical(unboxed(r, hx(r[["out"]])), hx(r[["msg"]]))
  }
  r <- kat("kstream")[[2]]
  out <- hx(r[["out"]])
  h <- 17L + 768L
  n <- as.integer(r[["chunk"]]) + 16L
  expect_error(unboxed(r, flip(out, h + 5L)), "verification failed|changed")
  expect_error(unboxed(r, out[seq_len(length(out) - 3L)]))
  last <- h + ((length(out) - h - 1L) %/% n) * n
  expect_error(unboxed(r, out[seq_len(last)]))
  sw <- out
  sw[(h + 1L):(h + n)] <- out[(h + n + 1L):(h + 2L * n)]
  sw[(h + n + 1L):(h + 2L * n)] <- out[(h + 1L):(h + n)]
  expect_error(unboxed(r, sw))
  expect_error(unboxed(r, c(out, as.raw(0))))
  k <- nqkeygen(r[["alg"]], seed = hx(r[["kseed"]]))
  f <- tempfile()
  writeBin(out, f)
  g <- tempfile()
  expect_error(nqunbox(f, g, k$sk, r[["alg"]], ctx = "other"))
  expect_false(file.exists(g))
  unlink(f)
})

test_that("sealed streams round-trip, one chunk at a time", {
  k <- nqkeygen("ML-KEM-768")
  for (m in c(0L, 1L, 1023L, 1024L, 1025L, 5000L)) {
    p <- as.raw(seq_len(m) %% 251L)
    f <- tempfile()
    g <- tempfile()
    h <- tempfile()
    writeBin(p, f)
    nqbox(f, g, k$pk, "ML-KEM-768", ctx = "c", chunk = 1024L)
    nqunbox(g, h, k$sk, "ML-KEM-768", ctx = "c")
    expect_identical(readBin(h, "raw", m + 1L), p)
    expect_error(nqbox(f, g, k$pk, "ML-KEM-768"), "does not exist")
    unlink(c(f, g, h))
  }
  f <- tempfile()
  writeBin(as.raw(1:10), f)
  expect_error(nqbox(f, tempfile(), k$pk, "ML-KEM-768", chunk = 100L))
  unlink(f)
})

test_that("external mu signs and verifies the ACVP answers", {
  for (r in kat("mu")) {
    if (r[["kind"]] == "gen") {
      expect_identical(nqsignmu(hx(r[["key"]]), hx(r[["mu"]]), r[["alg"]],
                                rnd = hx(r[["rnd"]])), hx(r[["sig"]]))
    } else {
      expect_identical(nqverifymu(hx(r[["key"]]), hx(r[["mu"]]),
                                  hx(r[["sig"]]), r[["alg"]]),
                       r[["ok"]] == "1")
    }
  }
  k <- nqkeygen("ML-DSA-65")
  mu <- nqmu(k$pk, "msg", "ML-DSA-65", ctx = "c")
  expect_length(mu, 64L)
  expect_identical(nqsignmu(k$sk, mu, "ML-DSA-65", det = TRUE),
                   nqsign(k$sk, "msg", "ML-DSA-65", ctx = "c", det = TRUE))
  expect_error(nqmu(as.raw(1:32), "m", "Ed25519"), "not supported")
  expect_error(nqsignmu(k$sk, mu, "ML-DSA-65", det = TRUE, rnd = raw(32)),
               "exclude")
})

test_that("BLAKE2b and Argon2id give the known answers", {
  for (r in kat("b2b")) {
    d <- hx(r[["hash"]])
    key <- hx(r[["key"]])
    expect_identical(nqblake2b(hx(r[["in"]]), if (length(key)) key,
                               length(d)), d)
  }
  expect_error(nqblake2b("x", n = 65L), "1 to 64")
  for (r in kat("argon2")) {
    t <- hx(r[["tag"]])
    expect_identical(nqargon2id(hx(r[["pw"]]), hx(r[["salt"]]),
                                t = as.numeric(r[["t"]]),
                                m = as.numeric(r[["m"]]),
                                p = as.numeric(r[["p"]]), n = length(t),
                                key = hx(r[["key"]]), ad = hx(r[["ad"]])), t)
  }
  expect_error(nqargon2id("pw", raw(8), t = -1), "whole numbers")
  expect_true(nqcteq(as.raw(1:3), as.raw(1:3)))
  expect_false(nqcteq(as.raw(1:3), as.raw(c(1, 2, 4))))
  expect_false(nqcteq(as.raw(1), as.raw(1:2)))
})
