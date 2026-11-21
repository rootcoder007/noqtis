# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

pt0 <- 1767225600 # 2026-01-01T00:00:00Z

test_that("an OpenPGP key says what it was made with", {
  k <- nqpgpkeygen("Ada Example <ada@example.org>",
    passphrase = "a passphrase", created = pt0
  )
  f <- nqpgpinfo(k$pub)
  expect_identical(f$alg, "mldsa65-ed25519")
  expect_identical(f$encalg, "mlkem768-x25519")
  expect_false(f$secret)
  expect_null(f$expires)
  expect_identical(f$created, pt0)
  expect_identical(f$userid, "Ada Example <ada@example.org>")
  expect_length(f$fingerprint, 32L)
  expect_length(f$encfingerprint, 32L)
  s <- nqpgpinfo(k$sec)
  expect_true(s$secret)
  expect_true(s$locked)
  a <- nqpgparmor("public key", k$pub)
  expect_match(a, "^-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
  d <- nqpgpdearmor(a)
  expect_identical(d$kind, "public key")
  expect_identical(d$data, k$pub)
  # armored keys are read as well
  expect_identical(nqpgpinfo(a)$userid, f$userid)
  expect_error(nqpgpkeygen("X", "rsa"), "must be one of")
  expect_error(nqpgpkeygen("X", "ed25519", "nothing"), "must be one of")
  expect_error(nqpgpinfo(charToRaw("hello")))
})

test_that("OpenPGP signs three ways", {
  k <- nqpgpkeygen("Sig <sig@example.org>", "ed25519", NULL,
    passphrase = "pw", created = pt0
  )
  expect_null(nqpgpinfo(k$pub)$encalg)
  msg <- "signed text\nof two lines\n"
  for (mode in c("inline", "detached", "clear")) {
    s <- nqpgpsign(k$sec, msg, mode, passphrase = "pw", at = pt0 + 60)
    v <- nqpgpverify(k$pub, s, if (mode == "detached") msg else NULL)
    expect_identical(v$at, pt0 + 60)
    if (mode != "clear") expect_identical(rawToChar(v$data), msg)
  }
  s <- nqpgpsign(k$sec, msg, "detached", passphrase = "pw")
  expect_null(nqpgpverify(k$pub, s, "another text"))
  other <- nqpgpkeygen("Other <o@example.org>", "ed25519", NULL)
  expect_null(nqpgpverify(other$pub, s, msg))
  expect_error(nqpgpsign(k$sec, msg, passphrase = "wrong"))
  expect_error(nqpgpsign(k$sec, msg))
  expect_error(nqpgpsign(k$pub, msg))
  expect_error(nqpgpsign(k$sec, msg, "sideways"))
})

test_that("OpenPGP encrypts to keys and to a passphrase", {
  k <- nqpgpkeygen("Ada <ada@example.org>", created = pt0)
  msg <- as.raw(rep(1:250, 100))
  e <- nqpgpencrypt(msg, list(k$pub),
    passphrase = "open sesame", signer = k$sec, at = pt0 + 60
  )
  o <- nqpgpdecrypt(e, k$sec, signer = k$pub)
  expect_identical(o$data, msg)
  expect_true(o$signed)
  expect_identical(o$at, pt0 + 60)
  o <- nqpgpdecrypt(nqpgparmor("message", e), passphrase = "open sesame")
  expect_identical(o$data, msg)
  expect_false(o$signed)
  expect_null(nqpgpdecrypt(e, passphrase = "open sesam"))
  other <- nqpgpkeygen("Other <o@example.org>")
  expect_null(nqpgpdecrypt(e, other$sec))
  expect_null(nqpgpdecrypt(e, k$sec, signer = other$pub))
  sigonly <- nqpgpkeygen("Sig <sig@example.org>", "ed25519", NULL)
  expect_error(nqpgpencrypt(msg, list(sigonly$pub)))
  expect_error(nqpgpencrypt(msg))
})

test_that("defaults and unknown numbers", {
  # an Ed25519 key takes an X25519 subkey when none is named
  k <- nqpgpkeygen("Ed <ed@example.org>", alg = "ed25519")
  expect_identical(nqpgpinfo(k$pub)$encalg, "x25519")
  expect_identical(get(".pgpname", envir = asNamespace("noqtis"))(99L), "99")
  cc <- function(f, ...) .Call(get(f, envir = asNamespace("noqtis")), ...)
  expect_error(cc("Cpgpgen", 99L, 0L, "u", 0, NULL), "nqpgpgen")
})
