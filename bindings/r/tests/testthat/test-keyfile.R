# Key files: fixtures made once with the CLI,
#   noqtis keygen -a ML-DSA-44 --seed 000102...1f -o k44
fx <- function(f) test_path("fixtures", "keys", f)
td <- function() {
  d <- tempfile("nqkey")
  dir.create(d)
  d
}

test_that("a key file the CLI made reads back as the seed's key pair", {
  k <- nqkeygen("ML-DSA-44", seed = as.raw(0:31))
  s <- nqreadkey(fx("k44"))
  p <- nqreadkey(fx("k44.pub"))
  expect_identical(s, list(alg = "ML-DSA-44", kind = "sec", key = k$sk))
  expect_identical(p, list(alg = "ML-DSA-44", kind = "pub", key = k$pk))
})

test_that("nqwritekey writes the CLI's bytes, and reads them back", {
  k <- nqkeygen("ML-DSA-44", seed = as.raw(0:31))
  d <- td()
  nqwritekey(file.path(d, "k"), k$sk, "ml-dsa-44", "sec")
  nqwritekey(file.path(d, "k.pub"), k$pk, "ML-DSA-44", "pub")
  rd <- function(f) readBin(f, "raw", file.size(f))
  expect_identical(rd(file.path(d, "k")), rd(fx("k44")))
  expect_identical(rd(file.path(d, "k.pub")), rd(fx("k44.pub")))
  for (a in c("SLH-DSA-SHAKE-128f", "ML-KEM-768", "HQC-128")) {
    kk <- nqkeygen(a)
    f <- file.path(d, a)
    nqwritekey(f, kk$sk, a, "sec")
    expect_identical(nqreadkey(f)$key, kk$sk)
  }
})

test_that("a secret key file is owner-only and never overwritten", {
  skip_on_os("windows")
  k <- nqkeygen("ML-DSA-44")
  f <- file.path(td(), "k")
  nqwritekey(f, k$sk, "ML-DSA-44", "sec")
  expect_identical(format(file.mode(f)), "600")
  expect_error(nqwritekey(f, k$sk, "ML-DSA-44", "sec"), "exists")
  k2 <- nqkeygen("ML-DSA-44")
  nqwritekey(f, k2$sk, "ML-DSA-44", "sec", force = TRUE)
  expect_identical(nqreadkey(f)$key, k2$sk)
  expect_identical(format(file.mode(f)), "600")
})

test_that("CRLF line ends are read; anything else is refused", {
  t <- readBin(fx("k44.pub"), "raw", file.size(fx("k44.pub")))
  txt <- rawToChar(t)
  d <- td()
  w <- function(x) {
    f <- tempfile(tmpdir = d)
    writeBin(charToRaw(x), f)
    f
  }
  expect_identical(nqreadkey(w(gsub("\n", "\r\n", txt)))$key,
    nqreadkey(fx("k44.pub"))$key)
  head <- sub("\n.*", "", txt)
  body <- sub("^[^\n]*\n", "", txt)
  bad <- c(
    "", head, sub("noqtis-key-1", "noqtis-key-2", txt),
    sub(" pub", " pub extra", txt), sub(" pub", "  pub", txt),
    sub(" pub", " key", txt), sub("ML-DSA-44 pub", "ML-DSA-44", txt),
    paste0(head, "\n", sub("A", "-", body)),
    paste0(head, "\n", sub("\n", " \n", body)),
    paste0(head, "\n=", body),
    paste0(head, "\n", substr(body, 5, nchar(body)))
  )
  for (b in bad) {
    expect_error(nqreadkey(w(b)), "noqtis key file|bytes of base64",
      info = b)
  }
  expect_error(nqreadkey(w(sub("ML-DSA-44", "RSA-2048", txt))),
    "unknown algorithm")
  expect_error(nqreadkey(d), "existing key file")
})

test_that("non-canonical padding is refused", {
  k <- nqreadkey(fx("k44.pub"))$key
  s <- paste(noqtis:::.b64enc(k), collapse = "")
  p <- nchar(s) - nchar(sub("=+$", "", s))
  a <- c(LETTERS, letters, 0:9, "+", "/")
  last <- substr(s, nchar(s) - p, nchar(s) - p)
  nc <- a[bitwOr(match(last, a) - 1L, 1L) + 1L]
  expect_false(identical(nc, last))
  s2 <- paste0(substr(s, 1, nchar(s) - p - 1L), nc, strrep("=", p))
  expect_null(noqtis:::.b64dec(s2))
  expect_identical(noqtis:::.b64dec(s), k)
})

test_that("nqwritekey refuses a key that is not the algorithm's size", {
  k <- nqkeygen("ML-DSA-44")
  f <- tempfile()
  expect_error(nqwritekey(f, k$pk, "ML-DSA-44", "sec"), "key is")
  expect_error(nqwritekey(f, k$pk, "ML-DSA-99", "pub"), "unknown")
  expect_error(nqwritekey(f, "x", "ML-DSA-44", "pub"), "raw vector")
  expect_false(file.exists(f))
})
