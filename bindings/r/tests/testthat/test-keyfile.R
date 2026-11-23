# Key files: fixtures made once with the CLI,
#   noqtis keygen -a ML-DSA-44 --seed 000102...1f -o k44
# by noqtis 0.2 (k44, version 1) and by 0.3.0 (k44x, version 2)
fx <- function(f) file.path("fixtures", "keys", f)
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
  # version 2: the container of the same key
  expect_identical(
    nqreadkey(fx("k44x")),
    list(alg = "ML-DSA-44", kind = "sec", key = nqsxmk(k$sk, "ML-DSA-44"))
  )
})

test_that("nqwritekey writes the CLI's bytes, and reads them back", {
  k <- nqkeygen("ML-DSA-44", seed = as.raw(0:31))
  d <- td()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqwritekey(file.path(d, "k"), k$sk, "ml-dsa-44", "sec")
  nqwritekey(file.path(d, "k.pub"), k$pk, "ML-DSA-44", "pub")
  rd <- function(f) readBin(f, "raw", file.size(f))
  expect_identical(rd(file.path(d, "k")), rd(fx("k44x")))
  expect_identical(rd(file.path(d, "k.pub")), rd(fx("k44.pub")))
  for (a in c("SLH-DSA-SHAKE-128f", "ML-KEM-768", "HQC-128")) {
    kk <- nqkeygen(a)
    f <- file.path(d, a)
    nqwritekey(f, kk$sk, a, "sec")
    want <- if (a == "SLH-DSA-SHAKE-128f") nqsxmk(kk$sk, a) else kk$sk
    expect_identical(nqreadkey(f)$key, want)
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
  expect_identical(nqreadkey(f)$key, nqsxmk(k2$sk, "ML-DSA-44"))
  expect_identical(format(file.mode(f)), "600")
})

test_that("CRLF line ends are read; anything else is refused", {
  t <- readBin(fx("k44.pub"), "raw", file.size(fx("k44.pub")))
  txt <- rawToChar(t)
  d <- td()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  w <- function(x) {
    f <- tempfile(tmpdir = d)
    writeBin(charToRaw(x), f)
    f
  }
  expect_identical(
    nqreadkey(w(gsub("\n", "\r\n", txt, fixed = TRUE)))$key,
    nqreadkey(fx("k44.pub"))$key
  )
  head <- sub("\n.*", "", txt)
  body <- sub("^[^\n]*\n", "", txt)
  bad <- c(
    "", head, sub("noqtis-key-1", "noqtis-key-2", txt, fixed = TRUE),
    sub(" pub", " pub extra", txt, fixed = TRUE),
    sub(" pub", "  pub", txt, fixed = TRUE),
    sub(" pub", " key", txt, fixed = TRUE),
    sub("ML-DSA-44 pub", "ML-DSA-44", txt, fixed = TRUE),
    paste0(head, "\n", sub("A", "-", body, fixed = TRUE)),
    paste0(head, "\n", sub("\n", " \n", body, fixed = TRUE)),
    paste0(head, "\n=", body),
    paste0(head, "\n", substr(body, 5, nchar(body)))
  )
  for (b in bad) {
    expect_error(nqreadkey(w(b)), "noqtis key file|bytes of base64",
      info = b
    )
  }
  expect_error(
    nqreadkey(w(sub("ML-DSA-44", "RSA-2048", txt, fixed = TRUE))),
    "unknown algorithm"
  )
  expect_error(nqreadkey(d), "existing key file")
})

test_that("non-canonical padding is refused", {
  t <- readLines(fx("k44.pub"))
  k <- nqreadkey(fx("k44.pub"))$key
  s <- paste(t[-1L], collapse = "")
  p <- nchar(s) - nchar(sub("=+$", "", s))
  expect_identical(p, 2L)
  a <- c(LETTERS, letters, 0:9, "+", "/")
  last <- substr(s, nchar(s) - p, nchar(s) - p)
  nc <- a[bitwOr(match(last, a) - 1L, 1L) + 1L]
  expect_false(identical(nc, last))
  s2 <- paste0(substr(s, 1, nchar(s) - p - 1L), nc, strrep("=", p))
  lines <- function(x) {
    st <- seq(1L, nchar(x), by = 64L)
    substring(x, st, pmin(st + 63L, nchar(x)))
  }
  f <- tempfile()
  on.exit(unlink(f), add = TRUE)
  writeLines(c(t[1L], lines(s2)), f)
  expect_error(nqreadkey(f), "bytes of base64")
  writeLines(c(t[1L], lines(s)), f)
  expect_identical(nqreadkey(f)$key, k)
})

test_that("nqwritekey refuses a key that is not the algorithm's size", {
  k <- nqkeygen("ML-DSA-44")
  f <- tempfile()
  on.exit(unlink(f, recursive = TRUE), add = TRUE)
  expect_error(nqwritekey(f, k$pk, "ML-DSA-44", "sec"), "key is")
  expect_error(nqwritekey(f, k$pk, "ML-DSA-99", "pub"), "unknown")
  expect_error(nqwritekey(f, "x", "ML-DSA-44", "pub"), "raw vector")
  expect_false(file.exists(f))
})

test_that("key file arguments and odd files are refused", {
  k <- nqkeygen("ML-DSA-44", seed = as.raw(0:31))
  d <- td()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "k")
  expect_error(nqwritekey(1, k$sk, "ML-DSA-44"), "one file path")
  expect_error(nqwritekey(f, k$sk, "ML-DSA-44", force = NA), "TRUE or FALSE")
  expect_error(nqwritekey(f, k$sk, 44), "one algorithm name")
  big <- file.path(d, "big")
  writeBin(raw(1048577), big)
  expect_error(nqreadkey(big), "not a noqtis key file")
  txt <- readLines(fx("k44.pub"))
  w <- function(x) {
    g <- tempfile(tmpdir = d)
    writeLines(x, g)
    g
  }
  tab <- sub(" ", "\t", txt[1L], fixed = TRUE)
  expect_error(nqreadkey(w(c(tab, txt[-1L]))), "not a noqtis key file")
  last <- txt[length(txt)]
  odd <- paste0(substr(last, 1L, nchar(last) - 2L), "=A")
  expect_error(
    nqreadkey(w(c(txt[-length(txt)], odd))),
    "bytes of base64"
  )
})

test_that("an existing folder in the way is not removed", {
  k <- nqkeygen("ML-DSA-44")
  d <- td()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- file.path(d, "k")
  dir.create(f)
  writeLines("x", file.path(f, "inside"))
  expect_error(
    suppressWarnings(nqwritekey(f, k$sk, "ML-DSA-44", force = TRUE)),
    "cannot remove"
  )
  expect_true(file.exists(file.path(f, "inside")))
})

test_that("the version 2 container: made, checked, signs, refused damaged", {
  for (a in c("ML-DSA-44", "Ed25519", "ML-DSA-65+Ed25519",
              "SLH-DSA-SHA2-128f")) {
    k <- nqkeygen(a)
    x <- nqsxmk(k$sk, a)
    expect_length(x, nqsxsz(a))
    expect_identical(x[seq_along(k$sk)], k$sk)
    expect_true(nqsxchk(x, a))
    expect_error(nqsxchk(k$sk, a), "no integrity value")
    expect_error(nqsxmk(x, a), "bytes")
    for (i in unique(round(seq(1, length(x), length.out = 40)))) {
      y <- x
      y[i] <- xor(y[i], as.raw(0x20))
      expect_false(nqsxchk(y, a))
    }
    expect_true(nqverify(k$pk, "m", nqsign(x, "m", a), a))
    y <- x
    y[length(y)] <- xor(y[length(y)], as.raw(1))
    expect_error(nqsign(y, "m", a), "fault")
    # a damaged version 2 file is refused when read
    d <- td()
    f <- file.path(d, "k")
    writeLines(c(sprintf("noqtis-key-2 %s sec", a), .b64enc(y)), f)
    expect_error(nqreadkey(f), "integrity value")
    expect_error(nqwritekey(file.path(d, "k2"), y, a), "sound container")
    # a version 1 file still reads, as the key
    writeLines(c(sprintf("noqtis-key-1 %s sec", a), .b64enc(k$sk)), f)
    expect_identical(nqreadkey(f)$key, k$sk)
    unlink(d, recursive = TRUE)
  }
  # KEM keys have no container
  d <- td()
  f <- file.path(d, "e")
  e <- nqkeygen("ML-KEM-768")
  writeLines(c("noqtis-key-2 ML-KEM-768 sec", .b64enc(e$sk)), f)
  expect_error(nqreadkey(f), "no version 2 container")
  unlink(d, recursive = TRUE)
})
