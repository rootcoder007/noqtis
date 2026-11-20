h <- function(x) {
  i <- seq(1, nchar(x), 2)
  as.raw(strtoi(substring(x, i, i + 1), 16L))
}
ptn <- function(n) as.raw(seq_len(n) - 1L) # n below 251

test_that("KangarooTwelve gives the answers of RFC 9861", {
  expect_identical(nqkt(raw(0)), h(paste0(
    "1ac2d450fc3b4205d19da7bfca1b3751",
    "3c0803577ac7167f06fe2ce1f0ef39e5"
  )))
  expect_identical(nqkt(ptn(17)), h(paste0(
    "6bf75fa2239198db4772e36478f8e19b",
    "0f371205f6a9a93a273f51df37122888"
  )))
  expect_identical(nqkt(as.raw(255), custom = ptn(41)), h(paste0(
    "d848c5068ced736f4462159b9867fd4c",
    "20b808acc3d5bc48e0b06ba0a3762ec4"
  )))
  expect_identical(nqkt(raw(0), n = 32, bits = 256), h(paste0(
    "b23d2e9cea9f4904e02bec06817fc10c",
    "e38ce8e93ef4c89e6537076af8646404"
  )))
  # a shorter output starts a longer one; a string is its bytes; a tree
  big <- rep(ptn(250), 80)
  expect_identical(nqkt(big, n = 100)[1:32], nqkt(big))
  expect_identical(nqkt("abc"), nqkt(charToRaw("abc")))
  expect_false(identical(nqkt(big, custom = "a"), nqkt(big)))
  expect_length(nqkt(big, n = 64, bits = 256), 64L)
  expect_error(nqkt("x", n = 0), "1 or more")
  expect_error(nqkt("x", n = 1.5), "whole number")
  expect_error(nqkt("x", bits = 192), "128 or 256")
  expect_error(nqkt(complex(1)), "raw vector or one string")
})

test_that("AES-SIV gives the answer of RFC 5297 and refuses a change", {
  key <- h(paste0(
    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  ))
  ad <- h("101112131415161718191a1b1c1d1e1f2021222324252627")
  pt <- h("112233445566778899aabbccddee")
  out <- h("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
  expect_identical(nqsivenc(key, pt, list(ad)), out)
  expect_identical(nqsivdec(key, out, list(ad)), pt)
  expect_identical(nqsivenc(key, pt, list(ad)), out)
  expect_false(identical(nqsivenc(key, pt), out))
  expect_identical(nqsivenc(key, pt, NULL), nqsivenc(key, pt))
  expect_false(identical(nqsivenc(key, pt, list(ad, raw(0))), out))
  for (k in list(ptn(48), ptn(64))) {
    ct <- nqsivenc(k, "a message", list("a", "bc"))
    expect_identical(
      rawToChar(nqsivdec(k, ct, list("a", "bc"))), "a message"
    )
  }
  expect_identical(nqsivdec(key, nqsivenc(key, raw(0))), raw(0))
  bad <- out
  bad[21] <- xor(bad[21], as.raw(1))
  expect_error(nqsivdec(key, bad, list(ad)), "nqsivdec")
  expect_error(nqsivdec(key, out, list(c(ad, as.raw(0)))), "nqsivdec")
  expect_error(nqsivdec(key, out), "nqsivdec")
  expect_error(nqsivdec(ptn(32), out, list(ad)), "nqsivdec")
  expect_error(nqsivenc(ptn(40), pt), "nqsivenc")
  expect_error(nqsivdec(key, raw(5)), "shorter than the 16 bytes")
  expect_error(nqsivenc(key, pt, ad), "list of raw vectors or strings")
  expect_error(nqsivenc(key, pt, rep(list("a"), 127)), "more than 126")
  expect_error(nqsivenc("k", pt), "'key' must be a raw vector")
  expect_error(nqsivdec(key, "text"), "'x' must be a raw vector")
})

test_that("AES-GCM-SIV gives the answer of RFC 8452 and refuses a change", {
  key <- h("01000000000000000000000000000000")
  nonce <- h("030000000000000000000000")
  pt <- h("0100000000000000")
  out <- h("b5d839330ac7b786578782fff6013b815b287c22493a364c")
  expect_identical(nqgsivenc(key, nonce, pt), out)
  expect_identical(nqgsivdec(key, nonce, out), pt)
  k2 <- ptn(32)
  ct <- nqgsivenc(k2, nonce, "a message", ad = "header")
  expect_identical(
    rawToChar(nqgsivdec(k2, nonce, ct, ad = "header")), "a message"
  )
  expect_identical(nqgsivdec(k2, nonce, nqgsivenc(k2, nonce, raw(0))), raw(0))
  bad <- ct
  bad[length(bad)] <- xor(bad[length(bad)], as.raw(128))
  expect_error(nqgsivdec(k2, nonce, bad, ad = "header"), "nqgsivdec")
  expect_error(nqgsivdec(k2, nonce, ct, ad = "other"), "nqgsivdec")
  expect_error(nqgsivdec(k2, nonce, ct), "nqgsivdec")
  expect_error(nqgsivdec(k2, ptn(12), ct, ad = "header"), "nqgsivdec")
  expect_error(nqgsivenc(ptn(24), nonce, pt), "nqgsivenc")
  expect_error(nqgsivenc(key, ptn(8), pt), "nqgsivenc")
  expect_error(nqgsivdec(key, nonce, raw(3)), "shorter than the 16 bytes")
  expect_error(nqgsivenc(key, "n", pt), "'nonce' must be a raw vector")
})

test_that("ChaCha20 gives the answer of RFC 8439 and is its own inverse", {
  expect_identical(nqchacha20(raw(32), raw(12), raw(64)), h(paste0(
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
  )))
  k <- ptn(32)
  n <- ptn(12)
  m <- rep(ptn(100), 3)
  ct <- nqchacha20(k, n, m, counter = 7)
  expect_false(identical(ct, m))
  expect_identical(nqchacha20(k, n, ct, counter = 7), m)
  expect_identical(nqchacha20(k, n, m[65:300], counter = 8), ct[65:300])
  expect_identical(nqchacha20(k, n, raw(0)), raw(0))
  expect_error(nqchacha20(k[1:16], n, m), "nqcha20")
  expect_error(nqchacha20(k, n[1:8], m), "nqcha20")
  expect_error(nqchacha20(k, n, m, counter = -1), "whole number from 0")
  expect_error(nqchacha20(k, n, m, counter = 2^32), "whole number from 0")
  expect_error(nqchacha20(k, n, m, counter = 1.5), "whole number from 0")
  expect_error(nqchacha20(k, n, m, counter = "1"), "one number")
  expect_error(nqchacha20(k, n, m, counter = 2^32 - 1), "nqcha20")
})
