# DSSE envelopes: the arguments (the round trips are in test-cap2.R).

test_that("nqdsse checks its arguments", {
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqdsse(k$sk, k$pk, "x", 1, "ML-DSA-44"), "'type' must be one")
  expect_error(nqdsse(k$sk, k$pk, "x", NA_character_, "ML-DSA-44"), "'type'")
  expect_error(nqdsse(k$sk, k$pk, 1, "t", "ML-DSA-44"), "'payload' must be")
  expect_error(nqdsse("x", k$pk, "p", "t", "ML-DSA-44"), "'sk' must be a raw")
  expect_error(nqdsseverify(k$pk, 1, "ML-DSA-44"), "'env' must be")
  expect_error(nqdsseverify(k$pk, "{}", "ML-KEM-512"), "signature")
})

test_that("a string payload is its UTF-8 bytes", {
  k <- nqkeygen("ML-DSA-44")
  e <- nqdsse(k$sk, k$pk, "café", "text/plain", "ML-DSA-44")
  v <- nqdsseverify(k$pk, e, "ML-DSA-44")
  expect_identical(v$payload, charToRaw(enc2utf8("café")))
})
