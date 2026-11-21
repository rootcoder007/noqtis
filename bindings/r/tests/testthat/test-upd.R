test_that("the version in the answer of the release page", {
  h <- c("HTTP/2 302 \r\n", "server: x\r\n",
         "Location: https://github.com/a/noqtis/releases/tag/v1.20.3\r\n")
  expect_identical(updver(h), "1.20.3")
  expect_identical(updver(sub("Location", "location", h, fixed = TRUE)),
                   "1.20.3")
  expect_identical(updver(c("HTTP/2 200 \r\n", "server: x\r\n")),
                   NA_character_)
  expect_identical(updver("location: https://x/releases/tag/v1.2;rm\r\n"),
                   NA_character_)
  expect_identical(updver(character()), NA_character_)
  # an address that cannot be reached is NA, without an error or a warning
  expect_no_warning(v <- updget("http://127.0.0.1:9/none"))
  expect_identical(v, NA_character_)
})

test_that("when the notice is off", {
  old <- Sys.getenv("NOQTIS_NO_UPDATE_CHECK", NA)
  ask <- Sys.getenv("NOQTIS_UPDATE_CHECK", NA)
  op <- options(noqtis.update = NULL)
  Sys.unsetenv("NOQTIS_NO_UPDATE_CHECK")
  Sys.unsetenv("NOQTIS_UPDATE_CHECK")
  # nothing is asked unless it is asked for
  expect_true(updoff(FALSE))
  expect_true(updoff(TRUE))
  options(noqtis.update = TRUE)
  expect_false(updoff(TRUE))
  expect_true(updoff(FALSE))
  options(noqtis.update = FALSE)
  expect_true(updoff(TRUE))
  options(noqtis.update = NULL)
  Sys.setenv(NOQTIS_UPDATE_CHECK = "1")
  expect_false(updoff(TRUE))
  Sys.setenv(NOQTIS_NO_UPDATE_CHECK = "1")
  expect_true(updoff(TRUE))
  if (is.na(ask)) {
    Sys.unsetenv("NOQTIS_UPDATE_CHECK")
  } else {
    Sys.setenv(NOQTIS_UPDATE_CHECK = ask)
  }
  # tests are not interactive: nothing is asked, nothing is said
  expect_null(updrun())
  expect_no_message(.onAttach("", "noqtis"))
  options(op)
  if (is.na(old)) {
    Sys.unsetenv("NOQTIS_NO_UPDATE_CHECK")
  } else {
    Sys.setenv(NOQTIS_NO_UPDATE_CHECK = old)
  }
})

test_that("the notice, asked once a day and kept between", {
  d <- tempfile("upd")
  f <- file.path(d, "sub", "update")
  cnt <- new.env()
  cnt$n <- 0L
  get <- function() {
    cnt$n <- cnt$n + 1L
    "0.2.0"
  }
  m <- updmsg("0.1.9", f, now = 1000, get = get)
  expect_match(m, "^noqtis 0\\.2\\.0 is available \\(this is 0\\.1\\.9\\)")
  expect_match(m, "options(noqtis.update = FALSE) stops this notice",
               fixed = TRUE)
  expect_identical(readLines(f), "1000 0.2.0")
  # within the day the kept answer is used
  expect_identical(updmsg("0.1.9", f, now = 1000 + 86399, get = get), m)
  expect_identical(cnt$n, 1L)
  # the same or a later installed version: nothing
  expect_null(updmsg("0.2.0", f, now = 2000, get = get))
  expect_null(updmsg("0.10.0", f, now = 2000, get = get))
  # after a day, and with a clock set back, it is asked again
  expect_identical(updmsg("0.1.9", f, now = 1000 + 86400, get = get), m)
  expect_identical(updmsg("0.1.9", f, now = 5, get = get), m)
  expect_identical(cnt$n, 3L)
  # no answer is kept as none, and is not a notice
  expect_null(updmsg("0.1.9", f, now = 1e6, get = function() NA_character_))
  expect_identical(readLines(f), "1000000 NA")
  expect_null(updmsg("0.1.9", f, now = 1e6 + 1, get = get))
  # a kept file with anything else in it is asked again, never shown
  writeLines("x y", f)
  expect_identical(updmsg("0.1.9", f, now = 3e6, get = get), m)
  writeLines(paste(3e6, "9;system('x')"), f)
  expect_null(updmsg("0.1.9", f, now = 3e6 + 1, get = get))
  # a place that cannot be written: the answer is still used
  expect_identical(
    updmsg("0.1.9", file.path(f, "under-a-file", "update"), now = 1,
           get = get), m
  )
  unlink(d, recursive = TRUE)
})

test_that("the notice at attach", {
  local_mocked_bindings(updrun = function() "noqtis 9 is available",
                        .package = "noqtis")
  expect_message(.onAttach("", "noqtis"), "noqtis 9 is available",
                 fixed = TRUE, class = "packageStartupMessage")
})

test_that("the question goes to updget() unless a test gives its own", {
  local_mocked_bindings(updget = function(...) "0.3.0", .package = "noqtis")
  f <- tempfile("upd")
  expect_match(updmsg("0.1.0", f, now = 1e6),
               "noqtis 0.3.0 is available (this is 0.1.0)", fixed = TRUE)
  unlink(f)
})

test_that("the notice for this installation", {
  local_mocked_bindings(
    updoff = function(...) FALSE,
    updmsg = function(cur, file, ...) paste(cur, basename(file)),
    .package = "noqtis"
  )
  expect_identical(updrun(),
                   paste(utils::packageVersion("noqtis"), "update"))
})
