# Capsule format 2, proofs, partial checks, lineage, key statements and
# DSSE envelopes.

t0 <- 1700000000

mkcap <- function() {
  d <- tempfile("nqc2")
  dir.create(file.path(d, "sub"), recursive = TRUE)
  for (i in 0:2) {
    writeLines(
      sprintf("a,b\n%d,2", i),
      file.path(d, sprintf("f%d.csv", i))
    )
  }
  writeBin(as.raw(0:255), file.path(d, "sub", "y.bin"))
  d
}

rows <- function(r, n) r[r$check == n, , drop = FALSE]

test_that("format 2 seals, checks, ids and lists", {
  k <- nqkeygen("ML-DSA-44")
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 2)
  sig <- readLines(file.path(d, "noqtis.sig"), warn = FALSE)
  expect_match(paste(sig, collapse = ""), "noqtis-seal-2", fixed = TRUE)
  expect_true(attr(nqcheck(d, k$pk), "ok"))
  id <- nqcapid(d)
  expect_type(id, "raw")
  expect_length(id, 32L)
  f <- nqfiles(d)
  expect_setequal(f$path, c("f0.csv", "f1.csv", "f2.csv", "sub/y.bin"))
  y <- f[f$path == "sub/y.bin", ]
  expect_identical(y$size, 256)
  expect_identical(y$sha256, nqhash(as.raw(0:255), "sha256", hex = TRUE))
  writeLines("x", file.path(d, "f1.csv"))
  expect_false(attr(nqcheck(d, k$pk), "ok"))
  expect_error(nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 3), "format")
  expect_error(
    nqseal(d, k$sk, k$pk, "ML-DSA-44", format = 1, inputs = d),
    "format 2"
  )
  e <- mkcap()
  on.exit(unlink(e, recursive = TRUE), add = TRUE)
  expect_error(nqcapid(e), "noqtis")
  expect_error(nqfiles(e), "noqtis")
})

test_that("proofs", {
  k <- nqkeygen("ML-DSA-65")
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqseal(d, k$sk, k$pk, "ML-DSA-65", format = 2)
  p <- nqprove(d, c("f1.csv", "sub/y.bin"))
  t <- rawToChar(p)
  expect_match(t, "noqtis-proof-1", fixed = TRUE)
  expect_false(grepl("f0.csv", t, fixed = TRUE))
  r <- nqcheck(NULL, k$pk, proof = p)
  expect_true(attr(r, "ok"))
  expect_identical(nrow(rows(r, "proof.entry")), 2L)
  expect_true(attr(nqcheck(d, k$pk, proof = p), "ok"))
  pf <- tempfile(fileext = ".json")
  on.exit(unlink(pf, recursive = TRUE), add = TRUE)
  writeBin(p, pf)
  expect_true(attr(nqcheck(NULL, proof = pf), "ok"))
  writeLines("x", file.path(d, "f1.csv"))
  expect_false(attr(nqcheck(d, k$pk, proof = p), "ok"))
  expect_true(attr(nqcheck(NULL, k$pk, proof = p), "ok"))
  expect_false(attr(
    nqcheck(NULL, nqkeygen("ML-DSA-65")$pk, proof = p),
    "ok"
  ))
  bad <- charToRaw(sub("f1.csv", "f9.csv", t, fixed = TRUE))
  expect_false(attr(nqcheck(NULL, k$pk, proof = bad), "ok"))
  expect_error(nqprove(d, "nope"), "noqtis")
  expect_error(nqprove(d, character()), "paths")
  expect_error(nqcheck(d, k$pk, proof = p, only = "f1.csv"), "proof")
  e <- mkcap()
  on.exit(unlink(e, recursive = TRUE), add = TRUE)
  nqseal(e, k$sk, k$pk, "ML-DSA-65")
  expect_error(nqprove(e, "f0.csv"), "noqtis")
})

test_that("partial checks", {
  k <- nqkeygen("ML-DSA-44")
  for (fmt in 1:2) {
    d <- mkcap()
    on.exit(unlink(d, recursive = TRUE), add = TRUE)
    nqseal(d, k$sk, k$pk, "ML-DSA-44", format = fmt)
    writeLines("changed", file.path(d, "f0.csv"))
    unlink(file.path(d, "sub", "y.bin"))
    expect_false(attr(nqcheck(d, k$pk), "ok"))
    r <- nqcheck(d, k$pk, only = c("f1.csv", "f2.csv"))
    expect_true(attr(r, "ok"))
    expect_gt(nrow(rows(r, "partial")), 0L)
    expect_false(attr(nqcheck(d, k$pk, only = "f0.csv"), "ok"))
    expect_false(attr(nqcheck(d, k$pk, only = "missing"), "ok"))
  }
})

test_that("lineage", {
  k <- nqkeygen("ML-DSA-44")
  a <- mkcap()
  on.exit(unlink(a, recursive = TRUE), add = TRUE)
  nqseal(a, k$sk, k$pk, "ML-DSA-44")
  b <- mkcap()
  on.exit(unlink(b, recursive = TRUE), add = TRUE)
  nqseal(b, k$sk, k$pk, "ML-DSA-44", inputs = c(raw = a))
  man <- readLines(file.path(b, "noqtis.json"), warn = FALSE)
  expect_match(paste(man, collapse = ""), "\"name\":\"raw\"", fixed = TRUE)
  c2 <- mkcap()
  on.exit(unlink(c2, recursive = TRUE), add = TRUE)
  nqseal(c2, k$sk, k$pk, "ML-DSA-44", inputs = b)
  r <- nqcheck(c2, k$pk, lineage = c(a, b))
  expect_true(attr(r, "ok"))
  expect_identical(nrow(rows(r, "lineage")), 1L)
  expect_false(attr(nqcheck(c2, k$pk, lineage = c2), "ok"))
  writeLines("changed", file.path(a, "f0.csv"))
  r <- nqcheck(c2, k$pk, lineage = c(a, b))
  expect_false(attr(r, "ok"))
  expect_false(all(rows(r, "lineage")$ok))
})

test_that("key statements", {
  k1 <- nqkeygen("ML-DSA-44")
  k2 <- nqkeygen("ML-DSA-65")
  st <- nqrotate(k1$sk, k1$pk, "ML-DSA-44", k2$sk, k2$pk, "ML-DSA-65",
    at = t0, reason = "yearly"
  )
  expect_match(rawToChar(st), "noqtis-keys-1", fixed = TRUE)
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqseal(d, k2$sk, k2$pk, "ML-DSA-65")
  expect_false(attr(nqcheck(d, k1$pk), "ok"))
  r <- nqcheck(d, k1$pk, keys = list(st))
  expect_true(attr(r, "ok"))
  expect_gt(nrow(rows(r, "keys")), 0L)
  f <- tempfile(fileext = ".json")
  on.exit(unlink(f, recursive = TRUE), add = TRUE)
  writeBin(st, f)
  expect_true(attr(nqcheck(d, k1$pk, keys = f), "ok"))
  rv <- nqrevoke(k1$sk, k1$pk, "ML-DSA-44",
    at = as.POSIXct(t0, origin = "1970-01-01", tz = "UTC")
  )
  e <- mkcap()
  on.exit(unlink(e, recursive = TRUE), add = TRUE)
  nqseal(e, k1$sk, k1$pk, "ML-DSA-44")
  expect_true(attr(nqcheck(e, k1$pk), "ok"))
  r <- nqcheck(e, k1$pk, keys = rv)
  expect_false(attr(r, "ok"))
  expect_false(all(rows(r, "key.time")$ok))
  expect_error(nqcheck(e, keys = list(rv)), "pk")
  expect_error(
    nqrotate(k1$sk, k1$pk, "ML-DSA-44", k1$sk, k1$pk, "ML-DSA-44", at = t0),
    "noqtis"
  )
  expect_error(nqrevoke(k1$sk, k1$pk, "ML-DSA-44", at = "now"), "at")
  ed <- nqkeygen("Ed25519")
  expect_error(nqrevoke(ed$sk, ed$pk, "Ed25519", at = t0), "noqtis")
})

test_that("DSSE envelopes", {
  ty <- "application/vnd.in-toto+json"
  for (alg in c(
    "ML-DSA-65", "Ed25519", "ML-DSA-44+Ed25519",
    "SLH-DSA-SHAKE-128f"
  )) {
    k <- nqkeygen(alg)
    e <- nqdsse(k$sk, k$pk, '{"a":1}', ty, alg)
    t <- rawToChar(e)
    expect_match(t, nqhash(k$pk, "sha256", hex = TRUE), fixed = TRUE)
    v <- nqdsseverify(k$pk, e, alg)
    expect_identical(v$type, ty)
    expect_identical(rawToChar(v$payload), '{"a":1}')
    expect_identical(nqdsseverify(k$pk, t, alg)$type, ty)
    expect_null(nqdsseverify(nqkeygen(alg)$pk, e, alg))
    t2 <- sub('"payload":"[^"]*"', '"payload":"e30="', t)
    expect_null(nqdsseverify(k$pk, t2, alg))
  }
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqdsseverify(k$pk, "not json", "ML-DSA-44"), "envelope")
  expect_error(nqdsse(k$sk, k$pk, "x", "has space", "ML-DSA-44"), "noqtis")
  expect_error(nqdsse(
    k$sk, nqkeygen("ML-DSA-44")$pk, "x", "t",
    "ML-DSA-44"
  ), "noqtis")
  expect_gt(length(nqdsse(
    k$sk, k$pk, raw(0), "text/plain",
    "ML-DSA-44"
  )), 0L)
})

test_that("Ed25519 and the hybrids sign; a hybrid seals, Ed25519 does not", {
  for (alg in c(
    "Ed25519", "ML-DSA-44+Ed25519", "ML-DSA-65+Ed25519",
    "ML-DSA-87+Ed25519"
  )) {
    k <- nqkeygen(alg)
    s <- nqsign(k$sk, "m", alg)
    expect_true(nqverify(k$pk, "m", s, alg))
    expect_false(nqverify(k$pk, "M", s, alg))
    expect_true(nqverify(k$pk, "m", nqsign(k$sk, "m", alg, det = TRUE), alg))
  }
  k <- nqkeygen("ML-DSA-65+Ed25519", seed = as.raw(0:63))
  expect_identical(
    nqkeygen("ML-DSA-65+Ed25519", seed = as.raw(0:63))$pk,
    k$pk
  )
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqseal(d, k$sk, k$pk, "ML-DSA-65+Ed25519", format = 2)
  expect_true(attr(nqcheck(d, k$pk), "ok"))
  e <- nqkeygen("Ed25519")
  expect_error(nqseal(mkcap(), e$sk, e$pk, "Ed25519"), "noqtis")
})

test_that("a key statement's reason must be one string", {
  k1 <- nqkeygen("ML-DSA-44")
  expect_error(
    nqrevoke(k1$sk, k1$pk, "ML-DSA-44", at = t0, reason = 1),
    "'reason' must be NULL or one string"
  )
})

test_that("a format 2 seal keeps its meta", {
  k <- nqkeygen("ML-DSA-44")
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  nqseal(d, k$sk, k$pk, "ML-DSA-44", meta = '{"run":7}', format = 2)
  man <- readLines(file.path(d, "noqtis.json"), warn = FALSE)
  expect_match(paste(man, collapse = ""), '"run":7', fixed = TRUE)
  expect_true(attr(nqcheck(d, k$pk), "ok"))
})
