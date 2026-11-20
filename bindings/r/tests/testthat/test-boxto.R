test_that("a file sealed to several keys opens for each, signed or not", {
  ks <- list(
    list(alg = "ML-KEM-512", k = nqkeygen("ML-KEM-512")),
    list(alg = "ML-KEM-768", k = nqkeygen("ML-KEM-768")),
    list(alg = "ML-KEM-1024", k = nqkeygen("ML-KEM-1024"))
  )
  x <- nqkeygen("ML-KEM-768")
  me <- nqkeygen("ML-DSA-44")
  other <- nqkeygen("ML-DSA-44")
  pks <- lapply(ks, function(e) e$k$pk)
  algs <- vapply(ks, function(e) e$alg, "")
  d <- tempfile()
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "in")
  out <- function() tempfile("o", tmpdir = d)
  for (n in c(0L, 1L, 1024L, 1025L, 5000L)) {
    m <- as.raw(seq_len(n) %% 249L)
    writeBin(m, f)
    for (signed in c(FALSE, TRUE)) {
      g <- out()
      nqboxto(f, g, pks, algs,
        ctx = "ctx", chunk = 1024L,
        sender = if (signed) me$sk, sender_alg = if (signed) "ML-DSA-44"
      )
      expect_identical(rawToChar(readBin(g, "raw", 4L)), "NQKM")
      for (e in ks) {
        h <- out()
        s <- nqunboxfrom(g, h, e$k$sk, e$alg,
          ctx = "ctx", sender = if (signed) me$pk
        )
        expect_identical(readBin(h, "raw", n + 1L), m)
        expect_identical(s, if (signed) "ML-DSA-44" else NA_character_)
      }
      # not a recipient; another context; another sender or none
      h <- out()
      expect_error(
        nqunboxfrom(g, h, x$sk, "ML-KEM-768", ctx = "ctx"), "not sealed to"
      )
      expect_false(file.exists(h))
      expect_error(nqunboxfrom(g, h, ks[[1]]$k$sk, "ML-KEM-512"), "context")
      expect_error(
        nqunboxfrom(g, h, ks[[2]]$k$sk, "ML-KEM-768",
          ctx = "ctx", sender = other$pk
        ),
        "sender"
      )
      expect_false(file.exists(h))
      # not asked who sent it: it opens, signed or not
      nqunboxfrom(g, h, ks[[3]]$k$sk, "ML-KEM-1024", ctx = "ctx")
      expect_identical(readBin(h, "raw", n + 1L), m)
      b <- readBin(g, "raw", file.size(g))
      b[length(b) - 2L] <- xor(b[length(b) - 2L], as.raw(1L))
      g2 <- out()
      writeBin(b, g2)
      h <- out()
      expect_error(
        nqunboxfrom(g2, h, ks[[1]]$k$sk, "ML-KEM-512", ctx = "ctx"),
        "changed or cut"
      )
      expect_false(file.exists(h))
    }
  }
})

test_that("nqboxto() and nqunboxfrom() refuse what they cannot take", {
  k <- nqkeygen("ML-KEM-768")
  me <- nqkeygen("ML-DSA-44")
  f <- tempfile()
  writeBin(as.raw(1:9), f)
  on.exit(unlink(f), add = TRUE)
  expect_error(nqboxto(f, tempfile(), list(), "ML-KEM-768"), "1 to 64")
  expect_error(nqboxto(f, tempfile(), k$pk, "ML-KEM-768"), "list")
  expect_error(
    nqboxto(f, tempfile(), list(k$pk), c("ML-KEM-768", "ML-KEM-512")),
    "one for each key"
  )
  expect_error(nqboxto(f, tempfile(), list(k$pk), "ML-DSA-44"), "unknown")
  expect_error(
    nqboxto(f, tempfile(), list(k$pk), "ML-KEM-768", sender = me$sk),
    "sender_alg"
  )
  expect_error(
    nqboxto(f, tempfile(), list(k$pk), "ML-KEM-768", chunk = 100L), "noqtis"
  )
  expect_error(nqboxto(f, f, list(k$pk), "ML-KEM-768"), "does not exist")
  expect_error(
    nqboxto(f, tempfile(), list(k$pk), "ML-KEM-768", chunk = 1.5),
    "whole number"
  )
  # a sender's key that is not one: the signing fails, nothing is left
  o <- tempfile()
  expect_error(
    nqboxto(f, o, list(k$pk), "ML-KEM-768",
      sender = raw(7), sender_alg = "ML-DSA-44"
    ),
    "noqtis"
  )
  expect_false(file.exists(o))
  # the routine itself: a key for every algorithm
  rr <- getDLLRegisteredRoutines("noqtis")$.Call
  expect_error(
    .Call(rr$Ckmeini, c(1L, 2L), list(k$pk), 0L, NULL, 1024L),
    "one for each algorithm"
  )
  # one algorithm for every key
  g <- tempfile()
  h <- tempfile()
  on.exit(unlink(c(g, h)), add = TRUE)
  nqboxto(f, g, list(k$pk, k$pk), "ML-KEM-768")
  nqunboxfrom(g, h, k$sk, "ML-KEM-768")
  expect_identical(readBin(h, "raw", 10L), as.raw(1:9))
  # a signature asked of a file that is not signed
  expect_error(
    nqunboxfrom(g, tempfile(), k$sk, "ML-KEM-768", sender = me$pk), "sender"
  )
  writeBin(charToRaw("NQKM"), h)
  expect_error(nqunboxfrom(h, tempfile(), k$sk, "ML-KEM-768"), "header")
})
