# The arguments each function refuses and the branches the other tests do
# not reach, so every line of the R code and of its C interface is run.

C <- function(f, ...) .Call(get(f, envir = asNamespace("noqtis")), ...)

test_that("argument checks of the newer functions", {
  d <- tempfile("nqe")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE))
  writeLines("x", file.path(d, "a.txt"))
  k <- nqkeygen("ML-DSA-44")
  expect_error(nqblake2b("x", n = -1), "whole number")
  expect_error(nqsignmu(k$sk, raw(64), "ML-DSA-44", det = NA), "TRUE or FALSE")
  expect_error(nqbox(file.path(d, "a.txt"), tempfile(), raw(1), "ML-KEM-768",
                     chunk = -1), "whole number")
  expect_error(nqpwenc(k$sk, "pw", m = -1), "whole numbers")
  expect_error(nqpack(d, file.path(d, "b"), files = NA), "TRUE or FALSE")
  expect_error(nqpack(d, 1), "'file' must be one path")
  expect_error(nqchain(character()), "name capsule folders")
  expect_error(nqcheckpack(file.path(d, "none")), "one existing bundle")
  expect_error(nqunpack(file.path(d, "none"), tempfile()), "existing bundle")
  expect_error(nqdparse(1), "'json' must be one string")
  expect_error(nqdschk(d, 1), "'schema' must be one string")
  expect_error(nqdcal(d, "a.csv", "none.csv"), "existing CSV files")
  writeLines(c("x", "1"), file.path(d, "a.csv"))
  nqdadd(d, "a.csv")
  expect_error(nqdcal(d, "a.csv", file.path(d, "a.csv")), "to calibrate")
  expect_error(nqdpiece(d, "a.csv", file.path(d, "a.csv")), "chunk digests")
  expect_error(nqdpiece(d, "a.csv", file.path(d, "none")), "existing file")
  expect_error(nqdcommit(d, "x", label = 1), "'label' must be one string")
  s <- nqdcommit(d, "x", after = "2030-01-01T00:00:00Z")
  expect_match(nqdata(d), '"after":"2030-01-01T00:00:00Z"', fixed = TRUE)
  e <- tempfile("nqempty")
  dir.create(e)
  expect_error(nqdreport(e), "neither a seal nor a data record")
  expect_error(nqdenv(d, rng = 1), "'rng' must be one string")
  expect_match(nqdenv(d, rng = "x", seed = "s"), '"seed":"s"', fixed = TRUE)
  expect_match(nqdenv(d, seed = 3), '"rng":{"kind":', fixed = TRUE)
  old <- Sys.getenv("TZ", NA)
  Sys.setenv(TZ = "UTC")
  expect_match(nqdenv(d), '"tz":"UTC"', fixed = TRUE)
  if (is.na(old)) Sys.unsetenv("TZ") else Sys.setenv(TZ = old)
  expect_type(.osname(), "character")
  expect_type(.archname(), "character")
  expect_identical(.osname("Darwin"), "macos")
  expect_identical(.osname("Plan9"), "other")
  expect_identical(.archname("AMD64"), "x86_64")
  expect_identical(.archname("riscv64"), "riscv64")
  expect_identical(.pkgsrc(list(Priority = "base")), "base")
  expect_identical(.pkgsrc(list(RemoteType = "github")), "github")
  expect_identical(.pkgsrc(list(Repository = "CRAN")), "CRAN")
  expect_identical(.pkgsrc(list()), "local")
  expect_identical(.b64enc(raw(0)), character(0))
  expect_error(nqwritekey(tempfile(), k$sk, "ML-DSA-44", "sec"), NA)
  f <- tempfile()
  nqwritekey(f, k$sk, "ML-DSA-44", "sec")
  expect_error(nqreadkey(f, pass = "pw"), "not protected by a passphrase")
  unlink(c(e, f), recursive = TRUE)
})

test_that("the earlier data functions refuse what they document", {
  d <- tempfile("nqe2")
  dir.create(file.path(d, "data"), recursive = TRUE)
  on.exit(unlink(d, recursive = TRUE))
  writeLines(c("x", "1"), file.path(d, "data", "a.csv"))
  writeLines(c("x", "2"), file.path(d, "data", "b.csv"))
  expect_error(nqdadd(d, character()), "paths of files")
  expect_error(nqdadd(d, c("data/a.csv", "data/b.csv"), url = "https://e.org"),
               "one at a time")
  expect_error(nqdadd(d, "data/a.csv", title = 1), "'title' must be one string")
  nqdadd(d, "data/b.csv", synthetic = TRUE)
  expect_match(nqdata(d), '"synthetic":true', fixed = TRUE)
  expect_error(nqdput(d, 1, "{}"), "'member' must be one string")
  expect_error(nqdput(d, "checks", NULL, key = 1), "'key' must be one string")
  expect_error(nqdput(d, "checks", 1), "one string of JSON text")
  expect_error(nqdrift(d), "no summaries")
  nqdpin(d, "data/a.csv")
  expect_error(nqdrift(d, "data/a.csv", current = c("a", "b")),
               "one path per file")
  expect_identical(nqdrslv(paste0('{"base":"https://d.example.org",',
                                  '"id":"abcd-1234","kind":"socrata"}')),
                   "https://d.example.org/api/views/abcd-1234.json")
  rs <- '{"base":"https://d.example.org","id":"abcd-1234","kind":"socrata"}'
  expect_length(nqdreply(rs, charToRaw('{"id":"abcd-1234","name":"C"}')), 2L)
  expect_identical(nqdwayback("https://example.org/a.csv"),
                   "https://example.org/a.csv")
  expect_identical(.locks(d, NULL), character(0))
})

test_that("timestamps: a reply that checks is stored", {
  fx <- test_path("fixtures", "tsa")
  rd <- function(f) readBin(f, "raw", file.size(f))
  d <- golden()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  t <- nqtsput(d, rd(file.path(fx, "sample.tok")), nonce = NULL,
               anchors = list(rd(file.path(fx, "root.der"))))
  expect_s3_class(t, "POSIXct")
  expect_true(attr(nqcheck(d, gkey()$pk,
                           anchors = list(rd(file.path(fx, "root.der")))),
                   "ok"))
  expect_error(nqtsput(d, raw(2), nonce = "x"), "raw vector")
  expect_error(nqersreq(d, nonce = "x"), "raw vector")
  expect_error(nqersput(d, raw(2), nonce = "x"), "raw vector")
  e <- tempfile("nqns")
  dir.create(e)
  expect_error(nqtsreq(e), "noqtis: nqtsreq")
  unlink(e, recursive = TRUE)
})

test_that("evidence records: a first archive timestamp is stored", {
  # fixtures/ers/README says how the token was made
  fx <- test_path("fixtures", "ers")
  rd <- function(f) readBin(f, "raw", file.size(f))
  an <- list(rd(file.path(fx, "root.der")))
  d <- golden()
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  r <- nqersput(d, rd(file.path(fx, "seal.tok")), anchors = an)
  expect_s3_class(r$time, "POSIXct")
  expect_identical(r$how, "new")
  expect_true(file.exists(file.path(d, "noqtis.ers")))
  expect_true(attr(nqcheck(d, gkey()$pk, anchors = an), "ok"))
})

test_that("an empty file is boxed and opened; a short mu is refused", {
  k <- nqkeygen("ML-KEM-768")
  f <- tempfile()
  g <- tempfile()
  h <- tempfile()
  on.exit(unlink(c(f, g, h)), add = TRUE)
  file.create(f)
  nqbox(f, g, k$pk, "ML-KEM-768")
  expect_gt(file.size(g), 0)
  nqunbox(g, h, k$sk, "ML-KEM-768")
  expect_identical(file.size(h), 0)
  s <- nqkeygen("ML-DSA-44")
  expect_error(nqsignmu(s$sk, raw(63), "ML-DSA-44"), "invalid argument")
})

test_that("non-finite numbers are refused, and make a CSV column text", {
  expect_error(nqblake2b("x", n = NaN), "whole number")
  expect_error(nqblake2b("x", n = Inf), "whole number")
  expect_error(nqargon2id("pw", raw(16), t = Inf), "whole numbers")
  expect_error(nqdchunk(tempdir(), "a.csv", -Inf), "whole number")
  d <- tempfile("nqinf")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  writeLines(c("x,y", "1,1", "Inf,2", "NaN,3"), file.path(d, "a.csv"))
  s <- nqschema(d, "a.csv")
  expect_match(s, '{"name":"x","nulls":false,"type":"text"}', fixed = TRUE)
  expect_match(s, '{"name":"y","nulls":false,"type":"int"}', fixed = TRUE)
})

test_that("nqbox() removes its output when writing fails", {
  k <- nqkeygen("ML-KEM-768")
  f <- tempfile()
  o <- tempfile()
  on.exit(unlink(c(f, o)), add = TRUE)
  writeBin(as.raw(1:9), f)
  local_mocked_bindings(.pump = function(...) stop("the disk is full"))
  expect_error(nqbox(f, o, k$pk, "ML-KEM-768"), "the disk is full")
  expect_false(file.exists(o))
})

test_that("the C interface refuses what R would never pass", {
  r1 <- as.raw(1)
  expect_error(C("Ca2id", r1, raw(8), NULL, NULL, 1, 32L), "three numbers")
  expect_error(nqargon2id("pw", raw(8), t = 1, m = 1, p = 4), "nqa2id")
  expect_error(C("Cpwenc", r1, NULL, 1, raw(32)), "three numbers")
  expect_error(C("Cdsyn", ".", "a", "1", "2"), "must be numbers")
  expect_error(C("Cdcal", "{}", character(), ",", FALSE), "must name files")
  expect_error(C("Cdcal", "{}", NA_character_, ",", FALSE), "must not hold NA")
  expect_error(C("Cdchunk", ".", "a", "x"), "one number")
  expect_error(C("Cdpiece", "{}", ".", "x"), "one number")
  expect_error(C("Cdcommit", "x", r1), "raw vectors")
  expect_error(C("Cdreveal", ".", "x", r1), "raw vectors")
  expect_error(C("Cdchain", character(), NULL), "name capsule folders")
  expect_error(C("Cdchain", NA_character_, NULL), "must not hold NA")
  expect_error(C("Cdparse", 1), "must be one string")
  expect_error(C("Cdpack", 1, TRUE, "x"), "must be one path")
  expect_error(C("Cdinfer", ".", "a", "ab", FALSE, FALSE), "one byte")
  expect_error(C("Cddrift", "{}", NULL, "a", ",", FALSE, 1), "five numbers")
  expect_error(C("Cdsha", tempdir(), "none"), "none: cannot be read")
  expect_error(C("Cdadd", ".", "a", "f", character()), "each field")
  expect_error(C("Cdadd", tempdir(), NA_character_, character(), character()),
               "must not hold NA")
  expect_error(C("Cdrsp", "{}", "x"), "raw vector")
  expect_error(nqdrslv("{bad"), "the resolver: byte 1")
  k <- nqkeygen("ML-KEM-768")
  f <- tempfile()
  writeBin(as.raw(seq_len(1200) %% 256), f)
  expect_error(nqunbox(f, tempfile(), k$sk, "ML-KEM-768"), "header")
  unlink(f)
})

test_that("library failures come back as errors", {
  d <- tempfile("nqro")
  dir.create(d)
  on.exit({
    Sys.chmod(d, "0755")
    unlink(d, recursive = TRUE)
  })
  writeLines(c("x", "1"), file.path(d, "a.csv"))
  nqdadd(d, "a.csv")
  expect_error(nqdcite(d), "citation")
  expect_error(nqdput(d, "checks", NULL, key = "none"), "has no checks none")
  expect_error(nqdput(d, "sources", NULL, key = "none"), "no sources")
  expect_error(nqdadd(d, "none.csv"), "none.csv")
  expect_error(nqschema(d, "none.csv"), "none.csv")
  expect_error(nqdchunk(d, "a.csv", 10), "1024")
  expect_error(nqdaddr(d, "none.csv"))
  expect_error(C("Cdadd", d, "a.csv", "title", "{bad"), "title: byte 1")
  expect_error(C("Cddel", d, "zzz", "x"), "zzz: invalid argument")
  expect_error(C("Cdkey", d, "zzz", "x"), "zzz: invalid argument")
  nqdput(d, "checks", '{"name":"y","status":"pass"}')
  skip_on_os("windows")
  skip_if(Sys.info()[["user"]] == "root")
  Sys.chmod(d, "0555")
  expect_error(nqdput(d, "checks", '{"name":"x","status":"pass"}'),
               "cannot write")
  expect_error(nqdadd(d, "a.csv", url = "https://e.org"), "cannot write")
  expect_error(nqdput(d, "checks", NULL, key = "y"), "cannot write")
})

test_that("a record that cannot be written is an error, root or not", {
  # the record is written through a temporary file beside it, one of
  # sixteen names made from the process id (.noqtis.<pid><k>.tmp, both in
  # eight hex digits): with a folder at each of them no user can write it
  d <- tempfile("nqwr")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  tn <- file.path(d, sprintf(".noqtis.%08x%08x.tmp", Sys.getpid(), 0:15))
  blk <- function() {
    for (f in tn) {
      dir.create(f)
      writeLines("x", file.path(f, "keep"))
    }
  }
  blk()
  writeLines(c("x", "1"), file.path(d, "a.csv"))
  expect_error(nqdadd(d, "a.csv"), "cannot write")
  expect_error(nqdput(d, "checks", '{"name":"y","status":"pass"}'),
               "cannot write")
  unlink(tn, recursive = TRUE)
  nqdput(d, "checks", '{"name":"y","status":"pass"}')
  blk()
  expect_error(nqdput(d, "checks", NULL, key = "y"), "cannot write")
})

test_that("the locale comes from LANG when LC_ALL is empty", {
  d <- tempfile("nqlc")
  dir.create(d)
  old <- Sys.getenv(c("LC_ALL", "LANG"), unset = NA)
  on.exit({
    for (v in names(old)) {
      if (is.na(old[[v]])) {
        Sys.unsetenv(v)
      } else {
        do.call(Sys.setenv, as.list(old[v]))
      }
    }
    unlink(d, recursive = TRUE)
  }, add = TRUE)
  Sys.setenv(LC_ALL = "", LANG = "C.UTF-8")
  expect_match(nqdenv(d), '"locale":"C.UTF-8"', fixed = TRUE)
})

test_that("the C side of seal3, pbkdf2 and pwenc2 checks its arguments", {
  k <- nqkeygen("ML-DSA-44")
  d <- tempfile("nqc3")
  dir.create(d)
  on.exit(unlink(d, recursive = TRUE), add = TRUE)
  expect_error(C("Cseal3", d, 1L, k$sk, k$pk, 1, list(), character(), NULL),
               "one string of JSON")
  expect_error(C("Cseal3", d, 1L, k$sk, k$pk, NULL, list(raw(32)),
                 character(), NULL), "one id per name")
  expect_error(C("Cpbkdf2", 1L, charToRaw("pw"), raw(8), "x", 32L),
               "one number")
  expect_error(C("Cpwenc2", 1L, charToRaw("pw"), NULL, c(1, 2), k$sk),
               "three numbers")
})
