sigs <- function() {
  a <- nqalgs()
  n <- a$name[a$type == "sig"]
  # the SLH-DSA "s" (small) sets take seconds per signature
  if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
    n <- n[!grepl("^SLH-DSA-.*s$", n)]
  }
  n
}

test_that("every signature algorithm round trips and rejects tampering", {
  for (a in sigs()) {
    k <- nqkeygen(a)
    sz <- nqalgs()[nqalgs()$name == a, ]
    expect_length(k$pk, sz$pk)
    expect_length(k$sk, sz$sk)
    m <- charToRaw(paste("message for", a))
    s <- nqsign(k$sk, m, a)
    expect_length(s, sz$sig)
    expect_true(nqverify(k$pk, m, s, a), label = a)
    expect_false(nqverify(k$pk, flip(m), s, a), label = a)
    expect_false(nqverify(k$pk, m, flip(s, length(s)), a), label = a)
    expect_false(nqverify(k$pk, m, s[-1], a), label = a)
    expect_false(nqverify(k$pk, m, c(s, as.raw(0)), a), label = a)
    expect_false(nqverify(k$pk, m, raw(0), a), label = a)
    expect_false(nqverify(flip(k$pk, 2L), m, s, a), label = a)
    expect_false(nqverify(k$pk[-1], m, s, a), label = a)
    # context strings
    sc <- nqsign(k$sk, m, a, ctx = "ctx")
    expect_true(nqverify(k$pk, m, sc, a, ctx = "ctx"), label = a)
    expect_false(nqverify(k$pk, m, sc, a), label = a)
    expect_false(nqverify(k$pk, m, sc, a, ctx = "ctX"), label = a)
    expect_false(nqverify(k$pk, m, s, a, ctx = "ctx"), label = a)
  }
})

test_that("keys from a seed and deterministic signatures repeat", {
  for (a in c("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHAKE-128f")) {
    n <- if (startsWith(a, "ML-DSA")) 32L else 48L
    k1 <- nqkeygen(a, seed = as.raw(seq_len(n)))
    k2 <- nqkeygen(a, seed = as.raw(seq_len(n)))
    expect_identical(k1$pk, k2$pk, label = a)
    expect_identical(k1$sk, k2$sk, label = a)
    expect_false(identical(nqkeygen(a)$pk, k1$pk), label = a)
    d1 <- nqsign(k1$sk, "m", a, det = TRUE)
    d2 <- nqsign(k1$sk, "m", a, det = TRUE)
    expect_identical(d1, d2, label = a)
    r <- nqsign(k1$sk, "m", a, rnd = raw(if (n == 32L) 32L else 16L))
    expect_identical(r, d1, label = a)
    h1 <- nqsign(k1$sk, "m", a)
    h2 <- nqsign(k1$sk, "m", a)
    expect_false(identical(h1, h2), label = a)
    expect_true(nqverify(k1$pk, "m", h1, a), label = a)
    expect_error(nqkeygen(a, seed = as.raw(seq_len(n - 1L))), label = a)
    expect_error(nqsign(k1$sk, "m", a, rnd = raw(3)), label = a)
  }
})

test_that("the golden key is the one the capsule records", {
  k <- gkey()
  s <- sealpk(file.path(golden(), "noqtis.sig"))
  expect_identical(b64e(k$pk), s)
})

test_that("pre-hash signatures (HashML-DSA, HashSLH-DSA)", {
  for (a in c("ML-DSA-65", "SLH-DSA-SHAKE-128f")) {
    k <- nqkeygen(a)
    for (h in c("sha256", "sha512", "sha3-256", "shake128")) {
      s <- nqsign(k$sk, "data", a, ph = h)
      expect_true(nqverify(k$pk, "data", s, a, ph = h), label = h)
      expect_false(nqverify(k$pk, "data", s, a), label = h)
      expect_false(nqverify(k$pk, "data", s, a,
        ph = if (h == "sha512") "sha256" else "sha512"), label = h)
      expect_false(nqverify(k$pk, "Data", s, a, ph = h), label = h)
    }
  }
})

test_that("arguments are checked", {
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqsign(k$sk, "m", "ML-DSA-44", ctx = strrep("c", 256)))
  expect_false(nqverify(k$pk, "m", raw(2420), "ML-DSA-44",
    ctx = strrep("c", 256)))
  expect_error(nqsign(k$sk[-1], "m", "ML-DSA-44"))
  expect_error(nqsign("sk", "m", "ML-DSA-44"), "raw vector")
  expect_error(nqsign(k$sk, 1, "ML-DSA-44"), "raw vector or one string")
  expect_error(nqsign(k$sk, "m", "ML-DSA-44", det = NA), "det")
  expect_error(nqsign(k$sk, "m", "ML-DSA-44", ph = "md5"), "unknown hash")
  expect_error(nqverify("pk", "m", raw(1), "ML-DSA-44"), "raw vector")
  expect_error(nqkeygen("ML-DSA-44", seed = "abc"), "raw vector")
  # a string message is its UTF-8 bytes
  s <- nqsign(k$sk, "café", "ML-DSA-44")
  expect_true(nqverify(k$pk, charToRaw(enc2utf8("café")), s,
    "ML-DSA-44"))
  # empty messages are allowed
  s <- nqsign(k$sk, raw(0), "ML-DSA-44")
  expect_true(nqverify(k$pk, "", s, "ML-DSA-44"))
})
