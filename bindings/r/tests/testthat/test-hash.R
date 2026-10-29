abc <- c(
  sha224 = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
  sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  sha384 = paste0("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b",
    "605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
  sha512 = paste0("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9e",
    "eee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac9",
    "4fa54ca49f"),
  "sha512-224" = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
  "sha512-256" = paste0("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0",
    "e2f13107e7af23"),
  "sha3-224" = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
  "sha3-256" = paste0("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46",
    "bfe24511431532"),
  "sha3-384" = paste0("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596",
    "da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
  "sha3-512" = paste0("b751850b1a57168a5693cd924b6b096e08f621827444f70d88",
    "4f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592",
    "f8274eec53f0"),
  shake128 = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
  shake256 = paste0("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94",
    "ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd",
    "8801e751e4")
)

test_that("every hash matches the known digest of 'abc'", {
  for (a in names(abc)) {
    expect_identical(nqhash("abc", a, hex = TRUE), abc[[a]], label = a)
    expect_identical(nqhash(charToRaw("abc"), toupper(a), hex = TRUE),
      abc[[a]], label = a)
  }
})

test_that("empty input, raw output and SHAKE lengths", {
  expect_identical(nqhash(raw(0), hex = TRUE),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  expect_identical(nqhash("", "sha3-512", hex = TRUE), paste0(
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"))
  d <- nqhash("abc")
  expect_type(d, "raw")
  expect_length(d, 32L)
  expect_identical(nqhash("abc", "shake128", len = 16, hex = TRUE),
    "5881092dd818bf5cf8a3ddb793fbcba7")
  expect_length(nqhash("abc", "shake256", len = 200), 200L)
  expect_error(nqhash("abc", "sha256", len = 16), "SHAKE")
  expect_error(nqhash("abc", "md5"), "unknown hash")
  expect_error(nqhash(1:3), "raw vector or one string")
})

test_that("a file hashes as its bytes, across chunk boundaries", {
  f <- tempfile()
  on.exit(unlink(f))
  b <- as.raw(rep_len(0:255, 1048576L * 2L + 77L))
  writeBin(b, f)
  for (a in c("sha256", "sha3-256", "shake256")) {
    expect_identical(nqhash(f, a, file = TRUE), nqhash(b, a), label = a)
  }
  writeBin(charToRaw("abc"), f)
  expect_identical(nqhash(f, "sha512", file = TRUE, hex = TRUE),
    abc[["sha512"]])
  writeBin(raw(0), f)
  expect_identical(nqhash(f, file = TRUE), nqhash(raw(0)))
  expect_error(nqhash(tempfile(), file = TRUE), "existing file")
  expect_error(nqhash(tempdir(), file = TRUE), "existing file")
})

test_that("HMAC matches RFC 4231 and OpenSSL", {
  m <- "what do ya want for nothing?"
  expect_identical(nqhmac("Jefe", m, hex = TRUE),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  expect_identical(nqhmac(charToRaw("Jefe"), m, "sha3-256", hex = TRUE),
    "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5")
  expect_error(nqhmac("k", "x", "shake128"), "HMAC")
})
