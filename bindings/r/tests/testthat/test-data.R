mkcap <- function() {
  d <- tempfile("nqd")
  dir.create(file.path(d, "data"), recursive = TRUE)
  con <- file(file.path(d, "data", "a.csv"), "wb")
  writeLines(c("id,name,score", "1,ann,3.5", "2,bob,4", "3,,NA"), con)
  close(con)
  d
}

test_that("a data record is written, read and checked", {
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE))
  withr_epoch <- Sys.getenv("SOURCE_DATE_EPOCH")
  Sys.setenv(SOURCE_DATE_EPOCH = "1767225600")
  on.exit(Sys.setenv(SOURCE_DATE_EPOCH = withr_epoch), add = TRUE)
  nqdadd(d, "data/a.csv", url = "https://example.org/a.csv",
         retrieved = "now", licence = "CC-BY-4.0 \"quoted\"")
  j <- nqdata(d)
  expect_match(j, "\"retrieved\":\"2026-01-01T00:00:00Z\"", fixed = TRUE)
  expect_match(j, "\"licence\":\"CC-BY-4.0 \\\"quoted\\\"\"", fixed = TRUE)
  expect_match(j, "^\\{\"format\":\"noqtis-data-1\",\"sources\"")
  r <- nqdcheck(d)
  expect_true(attr(r, "ok"))
  expect_identical(r$check, c("record", "source"))
  # adding again keeps the url
  nqdadd(d, "data/a.csv")
  expect_match(nqdata(d), "https://example.org/a.csv", fixed = TRUE)
  cat("4,dan,1,\n", file = file.path(d, "data", "a.csv"), append = TRUE)
  r <- nqdcheck(d)
  expect_false(attr(r, "ok"))
  expect_match(r$detail[2], "SHA-256 is")
  expect_error(nqdadd(d, "../x"), "not a path a capsule holds")
  expect_error(nqdput(d, "checks", "{\"name\":\"x\",\"status\":\"maybe\"}"),
               "must be one of pass, warn, fail")
  nqdput(d, "checks", "{\"name\":\"x\",\"status\":\"fail\"}")
  expect_identical(tail(nqdcheck(d)$check, 1), "recorded")
  nqdput(d, "checks", NULL, key = "x")
  expect_false(grepl("\"checks\"", nqdata(d), fixed = TRUE))
  expect_error(nqdata(tempdir()), "noqtis.data.json is missing")
})

test_that("schemas are inferred, pinned and checked", {
  d <- mkcap()
  on.exit(unlink(d, recursive = TRUE))
  s <- nqschema(d, "data/a.csv")
  expect_match(s, "\"name\":\"score\",\"nulls\":true,\"type\":\"real\"",
               fixed = TRUE)
  nqschema(d, "data/a.csv", put = TRUE, ranges = TRUE)
  r <- nqschk(d)
  expect_true(attr(r, "ok"))
  cat("9,dan,9\n", file = file.path(d, "data", "a.csv"), append = TRUE)
  r <- nqschk(d, "data/a.csv")
  expect_false(attr(r, "ok"))
  expect_true(any(grepl("outside its range", r$detail, fixed = TRUE)))
  expect_error(nqschema(d, "data/none.csv"), "cannot be read")
})

test_that("drift is found from the summaries alone", {
  d <- tempfile("nqd")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE))
  x <- sprintf("%.6f", stats::qnorm(stats::ppoints(60)))
  writeLines(c("x", x), file.path(d, "a.csv"))
  nqdpin(d, "a.csv")
  r <- nqdrift(d)
  expect_identical(attr(r, "level"), "ok")
  y <- sprintf("%.6f", stats::qnorm(stats::ppoints(60)) + 1)
  writeLines(c("x", y), file.path(d, "b.csv"))
  r <- nqdrift(d, "a.csv", current = file.path(d, "b.csv"), minn = 1)
  expect_identical(attr(r, "level"), "fail")
  st <- r$stats[!is.na(r$stats)]
  expect_match(st, "\"ksexact\":true", fixed = TRUE)
  ks <- suppressWarnings(stats::ks.test(as.numeric(x), as.numeric(y)))
  d1 <- as.numeric(sub(".*\"ksd\":([^,]+),.*", "\\1", st))
  expect_equal(d1, unname(ks$statistic), tolerance = 1e-12)
  expect_error(nqdrift(d, "b.csv"), "no summary of b.csv")
})

test_that("two capsules are compared", {
  a <- mkcap()
  b <- mkcap()
  on.exit(unlink(c(a, b), recursive = TRUE))
  nqdadd(a, "data/a.csv")
  nqdadd(b, "data/a.csv", url = "https://example.org/a.csv")
  expect_true(attr(nqdiff(a, a), "same"))
  r <- nqdiff(a, b)
  expect_false(attr(r, "same"))
  expect_true(any(r$what == "source" & grepl("url", r$detail, fixed = TRUE)))
})

# ---- against the values the C tests check (tests/nqd/tdrec.c, tdcsv.c,
# tddft.c); fixtures/nqd is a copy of the repository's tests/vectors/nqd

fx <- function(...) test_path("fixtures", "nqd", ...)

nqdcopy <- function(rec = TRUE) {
  d <- tempfile("nqdc")
  dir.create(file.path(d, "data"), recursive = TRUE)
  file.copy(fx("cap", "data", c("a.csv", "b.csv")), file.path(d, "data"))
  if (rec) file.copy(fx("cap", "noqtis.data.json"), d)
  d
}

# the value of k in drift/expect.txt (written by tests/nqd/drift.R)
dexp <- function(k) {
  l <- readLines(fx("drift", "expect.txt"))
  as.numeric(sub("^[^ ]+ ", "", l[startsWith(l, paste0(k, " "))]))
}

# the number after "k": in the JSON text j
jnum <- function(j, k) {
  as.numeric(sub(sprintf(".*\"%s\":([^,}]+).*", k), "\\1", j))
}

test_that("the C tests' record reads, checks and is made again here", {
  d <- nqdcopy()
  n <- nqdcopy(FALSE)
  on.exit(unlink(c(d, n), recursive = TRUE))
  f <- file.path(d, "noqtis.data.json")
  j <- readChar(f, file.size(f), useBytes = TRUE)
  expect_identical(nqdata(d), j)
  r <- nqdcheck(d)
  expect_true(attr(r, "ok"))
  expect_gte(nrow(r), 3L)
  # its source element of data/a.csv, made from the file and what it says
  nqdadd(n, "data/a.csv", url = "https://example.org/a.csv",
         publisher = "City of Example", licence = "OGL-Canada-2.0",
         retrieved = "2026-01-01T00:00:00Z")
  expect_identical(nqdata(n),
                   sub(",\\{\"path\":\"data/b.csv\".*\\]\\}$", "]}", j))
  expect_match(nqdata(n), paste0("\"sha256\":\"7a1668480cde19db0b76c7a36e6",
                                 "fee9a82afd9937f5d03cec3dae1705ce173e2\",",
                                 "\"size\":89"), fixed = TRUE)
})

test_that("the C tests' schema comes out the same", {
  d <- nqdcopy()
  on.exit(unlink(d, recursive = TRUE))
  want <- paste0(
    "{\"columns\":[{\"name\":\"id\",\"nulls\":false,\"type\":\"int\"},",
    "{\"name\":\"name\",\"nulls\":true,\"type\":\"text\"},",
    "{\"name\":\"score\",\"nulls\":true,\"type\":\"real\"},",
    "{\"name\":\"when\",\"nulls\":false,\"type\":\"date\"}],",
    "\"kind\":\"csv\",\"path\":\"data/a.csv\",\"rows\":{\"max\":3,",
    "\"min\":3}}"
  )
  expect_identical(nqschema(d, "data/a.csv"), want)
  s <- nqschema(d, "data/a.csv", ranges = TRUE)
  expect_match(s, "\"max\":4,\"min\":3.5", fixed = TRUE)
  expect_match(s, "\"max\":\"2024-03-01\",\"min\":\"2024-01-02\"",
               fixed = TRUE)
})

test_that("the C tests' drift statistics come out the same", {
  d <- tempfile("nqdd")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE))
  file.copy(fx("drift", "ref.csv"), d)
  nqdpin(d, "ref.csv")
  r <- nqdrift(d, "ref.csv", current = fx("drift", "cur.csv"))
  # fewer than 1,000 values: PSI warns, never fails
  expect_identical(attr(r, "level"), "warn")
  col <- function(n) {
    r$stats[!is.na(r$stats) & grepl(sprintf("\"name\":\"%s\"", n), r$stats,
                                    fixed = TRUE)][1]
  }
  x <- col("x")
  near <- function(a, b, tol) {
    expect_lte(abs(a - b) / if (abs(b) > 1e-300) abs(b) else 1, tol)
  }
  near(jnum(x, "ksd"), dexp("ks.d"), 1e-14)
  near(jnum(x, "ksp"), dexp("ks.p"), 1e-9)
  near(jnum(x, "psi"), dexp("psi"), 1e-12)
  near(jnum(x, "js"), dexp("js"), 1e-12)
  c <- col("c")
  near(jnum(c, "chisq"), dexp("chi.x2"), 1e-12)
  near(jnum(c, "df"), dexp("chi.df"), 0)
  near(jnum(c, "chisqp"), dexp("chi.p"), 1e-10)
  near(jnum(c, "psi"), dexp("cat.psi"), 1e-12)
})

test_that("a changed source shows in the diff of the C tests' capsule", {
  a <- nqdcopy()
  b <- nqdcopy()
  on.exit(unlink(c(a, b), recursive = TRUE))
  expect_true(attr(nqdiff(a, b), "same"))
  nqdadd(b, "data/a.csv", url = "https://example.org/a2.csv")
  r <- nqdiff(a, b)
  expect_false(attr(r, "same"))
  expect_true(any(r$what == "source" & r$differs &
                    grepl("url", r$detail, fixed = TRUE)))
})

test_that("sources: addresses in order, bytes checked, resolvers", {
  d <- file.path(tempdir(), "nqsrc")
  unlink(d, recursive = TRUE)
  dir.create(file.path(d, "data"), recursive = TRUE)
  b <- charToRaw("x,y\n1,a\n")
  writeBin(b, file.path(d, "data", "a.csv"))
  nqdadd(d, "data/a.csv", url = "https://example.org/a.csv")
  e <- regmatches(nqdata(d), regexpr('\\{"path":[^}]*\\}', nqdata(d)))
  e <- sub("}$", paste0(',"mirrors":["https://m.example.net/a.csv"],',
                        '"resolver":{"base":"https://data.example.org",',
                        '"id":"abcd-1234","kind":"socrata"}}'), e)
  nqdput(d, "sources", e)
  a <- nqdaddr(d, "data/a.csv")
  expect_identical(a$kind, c("url", "portal", "mirror"))
  expect_identical(a$url[2],
                   "https://data.example.org/api/views/abcd-1234.json")
  expect_true(nqdverify(d, "data/a.csv", b))
  expect_false(nqdverify(d, "data/a.csv", c(b, as.raw(10))))
  expect_identical(nqdfield(d, "sources", 0, "url"),
                   "https://example.org/a.csv")
  expect_null(nqdfield(d, "sources", 0, "title"))
  expect_error(nqdaddr(d, "none.csv"))
  rs <- '{"base":"https://example.org/a.csv","kind":"wayback"}'
  v <- file.path(test_path("..", "..", "..", ".."), "tests", "vectors",
                 "nqd", "src")
  skip_if_not(dir.exists(v))
  r <- nqdreply(rs, readBin(file.path(v, "wb.json"), "raw", 1e5))
  expect_identical(r, c(paste0("https://web.archive.org/web/20240102030405id_/",
                               "https://example.org/a.csv"),
                        "2024-01-02T03:04:05Z"))
  expect_error(nqdreply(rs, readBin(file.path(v, "wb-none.json"), "raw",
                                    1e5)), "no copy")
  expect_error(nqdrslv('{"base":"https://x.org/a","kind":"direct"}'))
  unlink(d, recursive = TRUE)
})

test_that("nqdrift() refuses a level that is not one number", {
  d <- tempfile("nqlv")
  dir.create(d)
  utils::write.csv(data.frame(x = 1:20), file.path(d, "a.csv"),
    row.names = FALSE
  )
  nqdpin(d, "a.csv")
  for (k in c("psiwarn", "psifail", "alpha", "minn")) {
    for (v in list(NA, NA_real_, "x", c(1, 2), -1, Inf, NULL)) {
      a <- c(list(d), stats::setNames(list(v), k))
      expect_error(do.call(nqdrift, a), "must be one number")
    }
  }
  expect_true(attr(nqdrift(d), "ok"))
})

test_that("nqdrift() reads a file of the capsule, never through a link", {
  skip_on_os("windows")
  w <- tempfile("nqln")
  d <- file.path(w, "d")
  dir.create(file.path(d, "sub"), recursive = TRUE)
  dir.create(file.path(w, "out"))
  on.exit(unlink(w, recursive = TRUE))
  x <- c("x", sprintf("%d", 1:20))
  for (f in c("a.csv", "sub/a.csv", "../out/a.csv")) {
    writeLines(x, file.path(d, f))
  }
  nqdpin(d, c("a.csv", "sub/a.csv"))
  expect_true(attr(nqdrift(d), "ok"))
  unlink(file.path(d, "a.csv"))
  unlink(file.path(d, "sub"), recursive = TRUE)
  file.symlink(file.path(w, "out", "a.csv"), file.path(d, "a.csv"))
  file.symlink(file.path(w, "out"), file.path(d, "sub"))
  for (f in c("a.csv", "sub/a.csv")) {
    r <- nqdrift(d, f)
    expect_false(attr(r, "ok"))
    expect_match(r$detail[1], "a link or not a plain file, refused")
  }
  # a file the caller names is read by its path, a link or not
  r <- nqdrift(d, "a.csv", current = file.path(d, "a.csv"))
  expect_true(attr(r, "ok"))
})

test_that("nqdenv() reads a lock file inside dir, never through a link", {
  skip_on_os("windows")
  w <- tempfile("nqlk")
  d <- file.path(w, "d")
  dir.create(d, recursive = TRUE)
  on.exit(unlink(w, recursive = TRUE))
  writeLines("{}", file.path(w, "renv.lock"))
  file.symlink(file.path(w, "renv.lock"), file.path(d, "renv.lock"))
  p <- data.frame(name = "a", version = "1", source = "x")
  expect_error(nqdenv(d, pkgs = p), "refused")
  expect_error(nqdenv(d, locks = "renv.lock", pkgs = p), "refused")
  unlink(file.path(d, "renv.lock"))
  file.copy(file.path(w, "renv.lock"), file.path(d, "renv.lock"))
  expect_match(nqdenv(d, pkgs = p), '"path":"renv.lock"', fixed = TRUE)
})
