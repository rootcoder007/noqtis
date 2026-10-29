kems <- function() nqalgs()$name[nqalgs()$type == "kem"]

test_that("every KEM round trips, with implicit rejection", {
  for (a in kems()) {
    sz <- nqalgs()[nqalgs()$name == a, ]
    k <- nqkeygen(a)
    expect_length(k$pk, sz$pk)
    expect_length(k$sk, sz$sk)
    e <- nqencap(k$pk, a)
    expect_length(e$ct, sz$ct)
    expect_length(e$ss, sz$ss)
    expect_identical(nqdecap(k$sk, e$ct, a), e$ss, label = a)
    # a changed ciphertext: an unrelated secret, not an error
    for (i in c(1L, length(e$ct))) {
      bad <- nqdecap(k$sk, flip(e$ct, i), a)
      expect_length(bad, sz$ss)
      expect_false(identical(bad, e$ss), label = a)
      # and the same unrelated secret each time
      expect_identical(nqdecap(k$sk, flip(e$ct, i), a), bad, label = a)
    }
    # another key pair's secret key
    expect_false(identical(nqdecap(nqkeygen(a)$sk, e$ct, a), e$ss))
    # fresh randomness per encapsulation
    expect_false(identical(nqencap(k$pk, a)$ss, e$ss), label = a)
    # malformed sizes are errors
    expect_error(nqdecap(k$sk, e$ct[-1], a), label = a)
    expect_error(nqdecap(k$sk[-1], e$ct, a), label = a)
    expect_error(nqencap(k$pk[-1], a), label = a)
  }
})

test_that("seeded key generation and encapsulation repeat", {
  for (a in c("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")) {
    k1 <- nqkeygen(a, seed = as.raw(0:63))
    k2 <- nqkeygen(a, seed = as.raw(0:63))
    expect_identical(k1, k2)
    e1 <- nqencap(k1$pk, a, seed = as.raw(1:32))
    e2 <- nqencap(k1$pk, a, seed = as.raw(1:32))
    expect_identical(e1, e2)
    expect_identical(nqdecap(k1$sk, e1$ct, a), e1$ss)
    expect_error(nqkeygen(a, seed = as.raw(0:62)))
    expect_error(nqencap(k1$pk, a, seed = as.raw(1:31)))
  }
})

test_that("ML-KEM rejects an encapsulation key that fails the FIPS 203 check", {
  k <- nqkeygen("ML-KEM-512", seed = as.raw(0:63))
  pk <- k$pk
  # the first coefficient set to 4095 > q - 1 = 3328
  pk[1] <- as.raw(0xff)
  pk[2] <- as.raw(bitwOr(as.integer(pk[2]), 0x0f))
  expect_error(nqencap(pk, "ML-KEM-512"))
})
