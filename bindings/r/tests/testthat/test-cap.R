test_that("the golden capsule checks", {
  d <- golden()
  r <- nqcheck(d)
  expect_s3_class(r, "data.frame")
  expect_named(r, c("check", "ok", "detail"))
  expect_true(attr(r, "ok"))
  expect_true(all(r$ok))
  expect_true(any(r$check == "file" & grepl("data/deep/c.bin", r$detail)))
  r <- nqcheck(d, gkey()$pk)
  expect_true(attr(r, "ok"))
  # a different trusted key
  r <- nqcheck(d, nqkeygen("ML-DSA-44")$pk)
  expect_false(attr(r, "ok"))
  expect_true(any(!r$ok & r$check == "key"))
})

test_that("a tampered copy fails", {
  d <- golden()
  writeLines("hellO", file.path(d, "a.txt"))
  r <- nqcheck(d)
  expect_false(attr(r, "ok"))
  expect_true(any(!r$ok & grepl("a.txt", r$detail)))
  # an added file
  d <- golden()
  writeLines("new", file.path(d, "data", "new.txt"))
  expect_false(attr(nqcheck(d), "ok"))
  # a removed file
  d <- golden()
  unlink(file.path(d, "data", "b.csv"))
  expect_false(attr(nqcheck(d), "ok"))
  # a changed manifest
  d <- golden()
  f <- file.path(d, "noqtis.json")
  s <- readChar(f, file.size(f), useBytes = TRUE)
  writeChar(sub("golden", "Golden", s, fixed = TRUE), f, eos = NULL,
    useBytes = TRUE)
  expect_false(attr(nqcheck(d), "ok"))
  # a changed signature
  d <- golden()
  f <- file.path(d, "noqtis.sig")
  s <- readChar(f, file.size(f), useBytes = TRUE)
  i <- regexpr('"signature":"', s, fixed = TRUE) + 13L + 100L
  substr(s, i, i) <- if (substr(s, i, i) == "Q") "R" else "Q"
  writeChar(s, f, eos = NULL, useBytes = TRUE)
  expect_false(attr(nqcheck(d), "ok"))
  # no seal at all
  d <- tempfile()
  dir.create(d)
  expect_false(isTRUE(tryCatch(attr(nqcheck(d), "ok"),
    error = function(e) FALSE)))
})

test_that("sealing the golden files again gives the golden manifest", {
  g <- golden()
  d <- tempfile("nqseal")
  dir.create(d)
  for (f in c("a.txt", "empty", "data")) {
    file.copy(file.path(g, f), d, recursive = TRUE)
  }
  if (!file.exists(file.path(d, "empty"))) file.create(file.path(d, "empty"))
  k <- gkey()
  old <- Sys.getenv("SOURCE_DATE_EPOCH", NA)
  Sys.setenv(SOURCE_DATE_EPOCH = "1793210645")
  on.exit(if (is.na(old)) Sys.unsetenv("SOURCE_DATE_EPOCH") else
    Sys.setenv(SOURCE_DATE_EPOCH = old))
  p <- nqseal(d, k$sk, k$pk, "ML-DSA-44",
    meta = '{"project":"golden","n":1.50,"tags":["a","b"]}')
  expect_true(all(file.exists(p)))
  rd <- function(f) readBin(f, "raw", file.size(f))
  expect_identical(rd(file.path(d, "noqtis.json")),
    rd(file.path(g, "noqtis.json")))
  expect_true(attr(nqcheck(d, k$pk), "ok"))
})

test_that("seal and check round trip, and bad arguments", {
  d <- tempfile("nqrt")
  dir.create(file.path(d, "sub"), recursive = TRUE)
  writeBin(as.raw(0:255), file.path(d, "sub", "x.bin"))
  writeLines("y", file.path(d, "y.txt"))
  for (a in c("ML-DSA-65", "SLH-DSA-SHAKE-128f")) {
    k <- nqkeygen(a)
    nqseal(d, k$sk, k$pk, a)
    expect_true(attr(nqcheck(d, k$pk), "ok"), label = a)
  }
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqseal(d, k$sk, nqkeygen("ML-DSA-44")$pk, "ML-DSA-44"))
  expect_error(nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = "{not json"))
  expect_error(nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = 1))
  expect_error(nqseal(tempfile(), k$sk, k$pk, "ML-DSA-44"), "folder")
  expect_error(nqcheck(tempfile()), "folder")
  expect_error(nqcheck(d, anchors = list("x")), "raw")
})

test_that("RFC 3161 timestamps verify under their anchor only", {
  fx <- test_path("fixtures", "tsa")
  rd <- function(f) readBin(f, "raw", file.size(f))
  tok <- rd(file.path(fx, "sample.tok"))
  root <- rd(file.path(fx, "root.der"))
  oth <- rd(file.path(fx, "other.der"))
  d <- golden()
  k <- gkey()
  # anchors given, but no timestamp in the seal
  r <- nqcheck(d, k$pk, anchors = list(root))
  expect_false(attr(r, "ok"))
  expect_true(any(!r$ok & r$check == "timestamp"))
  # the token over the golden signature, added to the seal
  f <- file.path(d, "noqtis.sig")
  s <- readChar(f, file.size(f), useBytes = TRUE)
  s <- paste0(substr(s, 1L, nchar(s) - 1L), ',"timestamp":"', b64e(tok),
    '"}')
  writeChar(s, f, eos = NULL, useBytes = TRUE)
  r <- nqcheck(d, k$pk, anchors = list(root))
  expect_true(attr(r, "ok"))
  expect_true(any(r$ok & r$check == "timestamp"))
  expect_false(attr(nqcheck(d, k$pk, anchors = list(oth)), "ok"))
  expect_true(attr(nqcheck(d, k$pk, anchors = list(oth, root)), "ok"))
  # without anchors a seal that carries a timestamp fails its check
  expect_false(attr(nqcheck(d, k$pk), "ok"))
})
