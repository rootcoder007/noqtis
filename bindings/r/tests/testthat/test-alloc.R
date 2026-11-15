# Each allocation the bundled library makes, failed in turn, until a
# call makes none that fails: every failing call is an error of the
# package, never a crash or a result missing a part, and the call that
# nothing fails returns as without the hook. Calfail (src/rnqd.c) is
# the switch: n >= 0 fails the n-th allocation from now, -1 disarms and
# says whether one was failed; no R function of the package calls it.

.alfail <- function(n) {
  .Call(get("Calfail", envir = asNamespace("noqtis")), as.integer(n))
}

sweep <- function(f) {
  on.exit(.alfail(-1L), add = TRUE)
  n <- 0L
  msg <- character()
  repeat {
    .alfail(n)
    e <- tryCatch({
      f()
      NA_character_
    }, error = conditionMessage)
    if (!.alfail(-1L)) {
      expect_identical(e, NA_character_)
      break
    }
    msg[n + 1L] <- e
    n <- n + 1L
  }
  # every failed allocation: an error, and one of the package's
  expect_false(anyNA(msg))
  expect_true(all(startsWith(msg, "noqtis: ")))
  invisible(n)
}

test_that("the data record's functions fail cleanly when memory runs out", {
  d <- tempfile("nqal")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  writeLines(c("x,c", "1,a", "2,b", "3,a"), file.path(d, "a.csv"))
  nqdadd(d, "a.csv", url = "https://example.org/a.csv")
  nqschema(d, "a.csv", put = TRUE)
  nqdpin(d, "a.csv")
  nqdchunk(d, "a.csv", 1024)
  nqdput(d, "cite", '{"title":"T","authors":["A. Author"],"year":2026}')
  expect_gt(sweep(function() nqdata(d)), 0L)
  expect_gt(sweep(function() nqdcheck(d)), 0L)
  expect_gt(sweep(function() nqschema(d, "a.csv")), 0L)
  expect_gt(sweep(function() nqdpin(d, "a.csv")), 0L)
  expect_gt(sweep(function() nqdaddr(d, "a.csv")), 0L)
  expect_gt(sweep(function() nqdfield(d, "sources", 0, "url")), 0L)
  expect_gt(sweep(function() nqdchunk(d, "a.csv", 1024)), 0L)
  expect_gt(sweep(function() nqdpiece(d, "a.csv", file.path(d, "a.csv"))), 0L)
  expect_gt(sweep(function() nqdcite(d)), 0L)
  expect_gt(sweep(function() nqdreport(d)), 0L)
  k <- nqkeygen("ML-DSA-44")
  nqseal(d, k$sk, k$pk, "ML-DSA-44")
  expect_gt(sweep(function() nqdreport(d, k$pk)), 0L)
})

test_that("the failing allocator is off unless armed", {
  expect_false(.alfail(-1L))
  # armed, with no allocation before the disarm: nothing failed
  .alfail(0L)
  expect_false(.alfail(-1L))
  expect_type(nqdparse('{"format":"noqtis-data-1"}'), "character")
})

test_that("a stream the library refuses is an error, and is freed", {
  # Cctxbad (src/rnq.c) zeroes the context, for this test only
  bad <- get("Cctxbad", envir = asNamespace("noqtis"))
  k <- nqkeygen("ML-DSA-44")
  s <- nqsigner(k$sk, "ML-DSA-44")
  nqupdate(s, "part one")
  .Call(bad, s$p)
  expect_error(nqupdate(s, "part two"),
               "noqtis: nqsupd: context used out of order", fixed = TRUE)
  # the context was freed: the stream is over
  expect_error(nqupdate(s, "x"), "noqtis: context used out of order",
               fixed = TRUE)
  expect_error(nqfinish(s), "context used out of order", fixed = TRUE)
})

