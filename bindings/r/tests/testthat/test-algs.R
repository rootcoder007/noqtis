test_that("nqalgs lists every algorithm with the standards' sizes", {
  a <- nqalgs()
  expect_s3_class(a, "data.frame")
  expect_equal(sum(a$type == "sig"), 19L)
  expect_equal(sum(a$type == "kem"), 6L)
  r <- a[a$name == "ML-DSA-44", ]
  expect_equal(c(r$pk, r$sk, r$sig), c(1312L, 2560L, 2420L))
  r <- a[a$name == "ML-DSA-87", ]
  expect_equal(c(r$pk, r$sk, r$sig), c(2592L, 4896L, 4627L))
  r <- a[a$name == "SLH-DSA-SHA2-128s", ]
  expect_equal(c(r$pk, r$sk, r$sig), c(32L, 64L, 7856L))
  r <- a[a$name == "ML-KEM-768", ]
  expect_equal(c(r$pk, r$sk, r$ct, r$ss), c(1184L, 2400L, 1088L, 32L))
  expect_true(all(is.na(a$ct[a$type == "sig"])))
})

test_that("nqver gives the library version", {
  expect_match(nqver(), "^[0-9]+\\.[0-9]+\\.[0-9]+")
})

test_that("nqrand uses the OS generator, not R's", {
  set.seed(1)
  s <- .Random.seed
  a <- nqrand(32)
  expect_identical(.Random.seed, s)
  set.seed(1)
  b <- nqrand(32)
  expect_type(a, "raw")
  expect_length(a, 32L)
  expect_false(identical(a, b))
  expect_length(nqrand(0), 0L)
  expect_error(nqrand(-1))
  expect_error(nqrand(1.5))
  expect_error(nqrand("a"))
})

test_that("unknown algorithm names are errors", {
  expect_error(nqkeygen("RSA-2048"), "nqalgs")
  expect_error(nqkeygen(c("ML-DSA-44", "ML-DSA-65")))
  expect_error(nqsign(raw(2560), "x", "ML-KEM-512"), "signature")
  expect_error(nqencap(raw(1312), "ML-DSA-44"), "encapsulation")
  # case is ignored
  expect_equal(nqkeygen("ml-dsa-44", seed = as.raw(0:31))$alg, "ML-DSA-44")
})
