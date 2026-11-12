# The argument checks every function shares (R/util.R) and those of the
# capsule helpers, through the exported functions.

test_that("algorithm and hash names must be one string", {
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqsign(k$sk, "m", 44), "one algorithm name")
  expect_error(nqsign(k$sk, "m", c("ML-DSA-44", "ML-DSA-65")), "one algorithm")
  expect_error(nqhash("abc", alg = 256), "one hash name")
  expect_error(nqhash("abc", alg = NA_character_), "one hash name")
  expect_error(nqhash("abc", alg = "md5"), "unknown hash 'md5'; one of: sha224")
  expect_error(nqkeygen(NA_character_), "one algorithm name")
})

test_that("the algorithm table is built once and kept", {
  expect_identical(nqalgs(), nqalgs())
})

test_that("capsule arguments are checked before any work", {
  k <- nqkeygen("ML-DSA-44")
  d <- golden()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  expect_error(nqcheck(d, k$pk, proof = 1), "raw vectors or file paths")
  expect_error(nqcheck(d, only = 1), "character vector of paths")
  expect_error(nqcheck(d, only = NA_character_), "character vector of paths")
  expect_error(
    nqseal(d, k$sk, k$pk, "ML-DSA-44", inputs = NA_character_),
    "folders of capsules"
  )
  expect_error(nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 3), "1 or 2")
  expect_error(nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = 1), "JSON text")
  expect_error(
    nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 1, inputs = d),
    "need format 2"
  )
  expect_error(nqcapid(file.path(d, "nowhere")), "existing folder")
})

test_that("one trust anchor may be given bare; none is no anchor", {
  d <- golden()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  g <- gkey()
  bare <- nqcheck(d, g$pk, anchors = as.raw(1:4))
  expect_s3_class(bare, "data.frame")
  expect_identical(bare, nqcheck(d, g$pk, anchors = list(as.raw(1:4))))
  expect_identical(nqcheck(d, g$pk, anchors = list()), nqcheck(d, g$pk))
  expect_error(nqcheck(d, g$pk, anchors = list("x")), "list of raw vectors")
})
