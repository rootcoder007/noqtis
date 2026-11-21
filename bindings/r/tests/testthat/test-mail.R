# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

mt0 <- 1767225600 # 2026-01-01T00:00:00Z
myear <- 365 * 86400

mailkeys <- function() {
  k <- nqkeygen("ML-DSA-44")
  cert <- nqcert(k$sk, k$pk, "ML-DSA-44", "Ada Example",
    email = "ada@example.org", notbefore = mt0, notafter = mt0 + myear
  )
  e <- nqkeygen("ML-KEM-768")
  kc <- nqkemcert(k$sk, "ML-DSA-44", cert, e$pk, "ML-KEM-768",
    notbefore = mt0, notafter = mt0 + myear
  )
  list(k = k, cert = cert, e = e, kc = kc)
}

test_that("armor goes there and back", {
  data <- as.raw(c(0, 1, 255, 10:60))
  a <- nqarmor("NOQTIS TEST", data)
  expect_match(a, "^-----BEGIN NOQTIS TEST-----\n")
  r <- nqdearmor(a)
  expect_identical(r$label, "NOQTIS TEST")
  expect_identical(r$data, data)
  expect_identical(nqdearmor(charToRaw(a))$data, data)
  expect_error(nqdearmor("not armor"))
  expect_error(nqarmor("lower case", data))
  expect_error(nqarmor("X", "text"), "raw vector")
  expect_error(nqarmor(1, data), "one string")
})

test_that("certificates say what they were made with", {
  m <- mailkeys()
  f <- nqcertinfo(m$cert)
  expect_identical(f$alg, "ML-DSA-44")
  expect_false(f$kem)
  expect_true(f$ca)
  expect_identical(f$name, "Ada Example")
  expect_identical(f$email, "ada@example.org")
  expect_identical(f$pk, m$k$pk)
  expect_identical(f$notbefore, mt0)
  expect_length(f$fingerprint, 32L)
  g <- nqcertinfo(m$kc)
  expect_true(g$kem)
  expect_identical(g$alg, "ML-KEM-768")
  expect_identical(g$name, "Ada Example")
  expect_identical(g$pk, m$e$pk)
  expect_error(nqcertinfo(charToRaw("not a certificate")))
  expect_error(nqcertinfo("x"), "raw vector")
  expect_error(nqcert(m$e$sk, m$e$pk, "ML-KEM-768", "X"))
  expect_error(nqkemcert(m$k$sk, "ML-DSA-44", m$cert, m$k$pk, "ML-DSA-44"))
})

test_that("CMS signs and verifies against anchors", {
  m <- mailkeys()
  msg <- charToRaw("a message to sign")
  for (det in c(FALSE, TRUE)) {
    s <- nqcmssign(m$k$sk, m$cert, msg, "ML-DSA-44",
      detached = det, at = mt0 + 3600
    )
    v <- nqcmsverify(s, list(m$cert),
      msg = if (det) msg else NULL, at = mt0 + 3600
    )
    expect_identical(v$content, msg)
    expect_identical(v$signer$name, "Ada Example")
    expect_null(nqcmsverify(s, list(m$kc),
      msg = if (det) msg else NULL, at = mt0 + 3600
    ))
    # with no anchor nothing is trusted: an error, not a verdict
    expect_error(nqcmsverify(s, list(),
      msg = if (det) msg else NULL, at = mt0 + 3600
    ))
  }
  expect_error(nqcmssign(m$k$sk, m$cert, msg, "ML-DSA-44", detached = NA))
  expect_error(nqcmsverify(msg, list("x")), "list of raw vectors")
  # one certificate alone is taken as a list of one
  s <- nqcmssign(m$k$sk, m$cert, msg, "ML-DSA-44", at = mt0 + 3600)
  expect_identical(nqcmsverify(s, m$cert, at = mt0 + 3600)$content, msg)
})

test_that("CMS encrypts to ML-KEM certificates", {
  m <- mailkeys()
  msg <- as.raw(rep(1:200, 20))
  e <- nqcmsencrypt(list(m$kc), msg)
  expect_identical(nqcmsdecrypt(m$e$sk, e, "ML-KEM-768", cert = m$kc), msg)
  expect_identical(nqcmsdecrypt(m$e$sk, e, "ML-KEM-768"), msg)
  other <- nqkeygen("ML-KEM-768")
  expect_null(nqcmsdecrypt(other$sk, e, "ML-KEM-768"))
  expect_error(nqcmsencrypt(list(m$cert), msg))
})

test_that("S/MIME messages round trip", {
  m <- mailkeys()
  ent <- "Content-Type: text/plain\r\n\r\nhello, mail\r\n"
  sm <- nqsmimesign(m$k$sk, m$cert, ent, "ML-DSA-44",
    detached = TRUE, at = mt0 + 3600
  )
  expect_match(sm, "multipart/signed", fixed = TRUE)
  expect_match(sm, "hello, mail", fixed = TRUE)
  v <- nqsmimeverify(sm, list(m$cert), at = mt0 + 3600)
  expect_identical(v$entity, ent)
  expect_identical(v$signer$email, "ada@example.org")
  bad <- sub("hello", "jello", sm, fixed = TRUE)
  expect_null(nqsmimeverify(bad, list(m$cert), at = mt0 + 3600))
  op <- nqsmimesign(m$k$sk, m$cert, ent, "ML-DSA-44", at = mt0 + 3600)
  expect_match(op, "signed-data", fixed = TRUE)
  expect_identical(
    nqsmimeverify(op, list(m$cert), at = mt0 + 3600)$entity, ent
  )
  se <- nqsmimeencrypt(list(m$kc), ent)
  expect_identical(nqsmimedecrypt(m$e$sk, se, "ML-KEM-768"), ent)
  other <- nqkeygen("ML-KEM-768")
  expect_null(nqsmimedecrypt(other$sk, se, "ML-KEM-768"))
})

test_that("a certificate of another algorithm is read without one", {
  # a P-256 root (tests/vectors/der/local/ec_root.der)
  pem <- paste(c(
    "-----BEGIN CERTIFICATE-----",
    "MIIB0TCCAVegAwIBAgIUH8dxz0EG6k0HK611EB0XuIbumo4wCgYIKoZIzj0EAwIw",
    "KDEUMBIGA1UECgwLbm9xdGlzIHRlc3QxEDAOBgNVBAMMB0VDIFJvb3QwHhcNMjYx",
    "MDI4MjAxMDM3WhcNMzYxMDI1MjAxMDM3WjAoMRQwEgYDVQQKDAtub3F0aXMgdGVz",
    "dDEQMA4GA1UEAwwHRUMgUm9vdDB2MBAGByqGSM49AgEGBSuBBAAiA2IABIAGn9p+",
    "opjiX0dEKelyGf1VzCw+8bLrEnPWtX2FxtFJJ5ZRvot1WIkipoFA2egOn9DGQVg1",
    "sd/Fe2nHfz83bOgV4F/TmPWHWACg1t5Zfa5TX8KbwhM7FMxcXImN/YFnJqNCMEAw",
    "DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCKiI54O",
    "0HqktwiPcYYdWlckiaNOMAoGCCqGSM49BAMCA2gAMGUCMD6HlojS2j0TUnRt8rUA",
    "+6p0vYzik11mKmsdjML/qn3NcaxAzvSqlPlKTV85jtpTKwIxAJKpwshOIpW69CBk",
    "ee1k9CXvzrFK5tBHvyLvwq4mIT+55sSquQM6xDqX198SDAaN3A==",
    "-----END CERTIFICATE-----"
  ), collapse = "\n")
  i <- nqcertinfo(nqdearmor(pem)$data)
  expect_identical(i$alg, "")
  expect_false(i$kem)
  expect_identical(i$name, "EC Root")
})

test_that("the compiled code checks its own arguments", {
  cc <- function(f, ...) .Call(get(f, envir = asNamespace("noqtis")), ...)
  id <- get(".alg", envir = asNamespace("noqtis"))("ML-DSA-44", "sig")$id
  k <- nqkeygen("ML-DSA-44")
  cert <- nqcert(k$sk, k$pk, "ML-DSA-44", "N", notbefore = 0, notafter = 10)
  expect_error(cc("Carmor", 1, raw(1)), "'label' must be one string")
  expect_error(
    cc("Cx5self", id, k$sk, k$pk, "n", NULL, "x", 1),
    "a time must be one number"
  )
  expect_error(
    cc("Ccmssign", id, k$sk, cert, raw(1), "no", 0, FALSE),
    "'detached' must be TRUE or FALSE"
  )
  expect_error(
    cc("Ccmsvrfy", raw(1), NULL, list(1), 0, FALSE),
    "'anchors' must be a list of raw vectors"
  )
})
