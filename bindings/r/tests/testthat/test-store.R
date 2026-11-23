# SPDX-License-Identifier: LGPL-3.0-or-later

st0 <- 1767225600 # 2026-01-01T00:00:00Z

test_that("a key store keeps, certifies and carries keys", {
  d <- file.path(tempfile("nqks"), "keys")
  d2 <- file.path(tempfile("nqks"), "keys")
  on.exit(unlink(c(dirname(d), dirname(d2)), recursive = TRUE))
  dir.create(d, recursive = TRUE)
  dir.create(d2, recursive = TRUE)
  me <- nqkeygen("ML-DSA-44")
  mykem <- nqkeygen("ML-KEM-768")
  bob <- nqkeygen("ML-KEM-768")
  card <- nqidcard(me$sk, me$pk, "ML-DSA-44", "Me Myself",
    email = "me@example.org", at = st0
  )
  # my signature key by its card, my KEM key under the same name
  mine <- nqksadd(d, me$pk, "ML-DSA-44", card = card)
  own <- nqksadd(d, mykem$pk, "ML-KEM-768", "Me Myself", "me@example.org")
  his <- nqksadd(d, bob$pk, "ML-KEM-768", "Bob Other", "bob@example.org")
  expect_length(mine, 32L)
  l <- nqkslist(d)
  expect_identical(nrow(l), 3L)
  expect_length(attr(l, "fingerprints"), 3L)
  b <- nqkslist(d, "bob@example.org")
  expect_identical(nrow(b), 1L)
  expect_identical(b$alg, "ML-KEM-768")
  expect_true(b$kem)
  expect_identical(b$valid, "none")
  expect_identical(b$trust, "unknown")
  expect_identical(b$fingerprint, paste(sprintf("%02x", as.integer(his)),
    collapse = ""
  ))
  g <- nqksget(d, his)
  expect_identical(g$alg, "ML-KEM-768")
  expect_identical(g$pk, bob$pk)
  # a signature key comes back as one
  expect_identical(nqksget(d, mine)$alg, "ML-DSA-44")
  # the fingerprint in hexadecimal names the key as well
  expect_identical(nqksget(d, b$fingerprint)$pk, bob$pk)
  expect_null(nqkstrust(d, mine, "ultimate"))
  cert <- nqkscertify(d, me$sk, me$pk, "ML-DSA-44", his, at = st0)
  expect_true(nzchar(cert))
  b <- nqkslist(d, "bob@example.org")
  expect_identical(b$valid, "full")
  expect_identical(b$certs, 1L)
  expect_true(nzchar(nqkscertify(d, me$sk, me$pk, "ML-DSA-44", own, at = st0)))
  # a bundle carries my card and my KEM key to another store
  bundle <- nqksexport(d, mine)
  expect_error(nqksexport(d, his))
  r <- nqksimport(d2, bundle, "me@example.org")
  expect_identical(r$fingerprint, mine)
  expect_identical(r$keys, 2L)
  expect_error(nqksimport(d2, bundle, "eve@example.org"))
  expect_null(nqksdel(d, his))
  expect_identical(nrow(nqkslist(d)), 2L)
  expect_identical(nrow(nqkslist(d, "nobody")), 0L)
  expect_error(nqkstrust(d, as.raw(1:5), "full"), "32 raw bytes")
  expect_error(nqkstrust(d, mine, "somewhat"))
  expect_error(nqksadd(d, me$pk, "ML-DSA-44"), "one string")
  expect_error(nqkslist(""), "one folder")
  expect_error(nqksaddcert(d, "not a certification"))
})

test_that("an address has one place to look its keys up", {
  u <- nqksurl("Ada@Example.org")
  expect_match(u, "^https://example.org/\\.well-known/noqtis/[0-9a-f]{40}$")
  expect_identical(u, nqksurl("ada@example.org"))
  expect_error(nqksurl("no address"))
  expect_error(nqksurl(NULL), "one string")
})

test_that("the compiled code checks its own arguments", {
  cc <- function(f, ...) .Call(get(f, envir = asNamespace("noqtis")), ...)
  d <- tempfile("nqks")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  k <- nqkeygen("ML-DSA-44")
  id <- get(".alg", envir = asNamespace("noqtis"))("ML-DSA-44", "sig")$id
  expect_error(cc("Cksget", d, raw(5)), "raw vector of 32 bytes")
  expect_error(
    cc("Cksadd", d, FALSE, id, k$pk, NULL, NULL, NULL),
    "'name' must be one string"
  )
})
