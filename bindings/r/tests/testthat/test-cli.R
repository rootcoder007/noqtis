# Cross-checks with the noqtis command-line tool, when it is installed
# (NOQTIS_CLI or noqtis on the PATH); skipped otherwise, as on CRAN.

test_that("signatures cross between the CLI and R", {
  skip_if(cli() == "", "the noqtis CLI is not available")
  d <- tempfile("nqcli")
  dir.create(d)
  key <- file.path(d, "k")
  msg <- file.path(d, "m.txt")
  writeLines("cross-check", msg)
  m <- readBin(msg, "raw", file.size(msg))
  for (a in c("ML-DSA-65", "SLH-DSA-SHA2-128f")) {
    unlink(c(key, paste0(key, ".pub")))
    expect_equal(runcli("keygen", "-a", a, "-o", key)$rc, 0L)
    p <- rpub(paste0(key, ".pub"))
    expect_identical(toupper(p$alg), toupper(a))
    sig <- file.path(d, "m.sig")
    unlink(sig)
    expect_equal(runcli("sign", "-k", key, "-o", sig, "-c", "R", msg)$rc, 0L)
    s <- readBin(sig, "raw", file.size(sig))
    expect_true(nqverify(p$pk, m, s, a, ctx = "R"), label = a)
    expect_false(nqverify(p$pk, m, s, a), label = a)
    # R signs, the CLI verifies
    k <- nqkeygen(a)
    pub <- file.path(d, "r.pub")
    wpub(pub, a, k$pk)
    writeBin(nqsign(k$sk, m, a, ctx = "R"), sig)
    expect_equal(runcli("verify", "-p", pub, "-s", sig, "-c", "R", msg)$rc,
      0L, label = a)
    expect_equal(runcli("verify", "-p", pub, "-s", sig, msg)$rc, 1L,
      label = a)
  }
  # the same deterministic key from the same seed
  unlink(c(key, paste0(key, ".pub")))
  runcli("keygen", "-a", "ML-DSA-44", "-o", key, "--seed",
    paste(sprintf("%02x", 0:31), collapse = ""))
  expect_identical(rpub(paste0(key, ".pub"))$pk, gkey()$pk)
})

test_that("capsules cross between the CLI and R", {
  skip_if(cli() == "", "the noqtis CLI is not available")
  d <- golden()
  expect_equal(runcli("check", d)$rc, 0L)
  writeLines("hellO", file.path(d, "a.txt"))
  expect_equal(runcli("check", d)$rc, 1L)
  # R seals, the CLI checks with R's public key
  k <- nqkeygen("ML-DSA-44")
  pub <- tempfile(fileext = ".pub")
  wpub(pub, "ML-DSA-44", k$pk)
  nqseal(d, k$sk, k$pk, "ML-DSA-44")
  expect_equal(runcli("check", "-p", pub, d)$rc, 0L)
  # hashes agree
  f <- file.path(d, "data", "deep", "c.bin")
  h <- runcli("hash", "-a", "sha3-256", f)$out
  expect_identical(sub(" .*", "", h[1]), nqhash(f, "sha3-256", file = TRUE,
    hex = TRUE))
})
