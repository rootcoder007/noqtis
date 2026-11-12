# The library itself, and the argument checks of the C glue (src/rnq.c)
# that the R functions never reach because they check first: called
# through the registered routines.

rt <- function() getDLLRegisteredRoutines("noqtis")$.Call

test_that("the library reports its version and passes its self-test", {
  expect_match(nqver(), "^[0-9]+[.][0-9]+[.][0-9]+")
  expect_invisible(nqselftest())
})

test_that("the glue refuses arguments of the wrong type", {
  r <- rt()
  k <- nqkeygen("ML-DSA-44")
  id <- nqalgs()$id[nqalgs()$name == "ML-DSA-44"]
  d <- golden()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  expect_identical(.Call(r$Cerr, -1L), "invalid argument")
  expect_error(.Call(r$Cerr, "x"), "'rc' must be one integer")
  expect_error(.Call(r$Ccapid, 1), "'dir' must be one path")
  expect_error(.Call(r$Cseal, d, id, k$sk, k$pk, 1), "JSON text")
  expect_error(
    .Call(r$Cseal2, d, id, k$sk, k$pk, 1, list(), character()),
    "JSON text"
  )
  expect_error(
    .Call(r$Cseal2, d, id, k$sk, k$pk, NA_character_, list(), character()),
    "JSON text"
  )
  expect_error(
    .Call(r$Cseal2, d, id, k$sk, k$pk, NULL, list(), "x"),
    "one id per name"
  )
  expect_error(
    .Call(r$Ckstmt, id, k$sk, k$pk, id, NULL, NULL, "now", NULL),
    "'at' must be one time"
  )
  expect_error(
    .Call(r$Cdsse, id, k$sk, k$pk, 1, raw(0)),
    "'type' must be one string"
  )
  expect_error(
    .Call(r$Ccard, id, k$sk, k$pk, 1, NULL, NULL, NULL, NULL, 0),
    "fields must be NULL or one string"
  )
  expect_error(
    .Call(r$Ccard, id, k$sk, k$pk, "A", NULL, NULL, NULL, NULL, "now"),
    "'at' must be one time"
  )
})

test_that("a proof larger than the first buffer is returned whole", {
  k <- nqkeygen("ML-DSA-44")
  d <- tempfile("nqbig")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  f <- sprintf("f%04d.txt", 1:600)
  for (x in f) writeLines(x, file.path(d, x))
  nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 2)
  p <- nqprove(d, f)
  expect_gt(length(p), 65536L)
  expect_true(attr(nqcheck(NULL, k$pk, proof = p), "ok"))
})
