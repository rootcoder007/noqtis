# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The rmoriebricklayer side of the differential test (run.sh): reads the
# lines `dv gen` wrote (dv.c describes them), recomputes each with
# rmoriebricklayer's native entry points (the .Call routines its R
# functions use, so with their input checks; ML-KEM decapsulation and
# ML-DSA signing both masked and plain) and compares the outputs byte for
# byte. Each difference goes to stderr; to stdout go, for each, the line
# with rmoriebricklayer's outputs and the cross-checks (its signature to
# verify, its ciphertext to decapsulate) for `dv chk`. Then a summary on
# stderr; exit 1 on any difference.
#
#   Rscript dv.R <file>
args <- commandArgs(trailingOnly = TRUE)
suppressPackageStartupMessages(library(rmoriebricklayer))
ns <- asNamespace("rmoriebricklayer")
C <- function(nm) get(nm, envir = ns)

h2r <- function(h) {
  if (identical(h, "-")) {
    return(raw(0))
  }
  n <- nchar(h)
  as.raw(strtoi(substring(h, seq.int(1L, n, 2L), seq.int(2L, n, 2L)), 16L))
}
r2h <- function(r) {
  if (is.null(r) || !length(r)) "-" else paste(as.character(r), collapse = "")
}
# NULL when rmoriebricklayer refuses (an error)
tc <- function(x) tryCatch(x, error = function(e) NULL)
lvl <- function(a) {
  if (startsWith(a, "ML-KEM-")) {
    as.integer(sub("ML-KEM-", "", a))
  } else {
    c(`HQC-128` = 1L, `HQC-192` = 3L, `HQC-256` = 5L)[[a]]
  }
}
mode <- function(a) {
  if (startsWith(a, "ML-DSA-")) as.integer(sub("ML-DSA-", "", a)) else NA
}
pre <- function(p) if (identical(p, "-")) "none" else p

# the outputs of one line: a list of variants, each a character vector
kk <- function(a, seed) {
  r <- if (startsWith(a, "ML-KEM-")) {
    tc(.Call(C("C_rmbl_mlkem_keygen"), lvl(a), seed))
  } else {
    tc(.Call(C("C_rmbl_hqc_keygen"), lvl(a), seed))
  }
  list(c(r2h(r$public), r2h(r$secret)))
}
ke <- function(a, pk, m) {
  r <- if (startsWith(a, "ML-KEM-")) {
    tc(.Call(C("C_rmbl_mlkem_encaps"), lvl(a), pk, m))
  } else {
    k <- c(`1` = 16L, `3` = 24L, `5` = 32L)[[as.character(lvl(a))]]
    tc(.Call(C("C_rmbl_hqc_encaps"), lvl(a), pk, head(m, k), m[-seq_len(k)]))
  }
  list(c(r2h(r$ciphertext), r2h(r$shared)))
}
kd <- function(a, sk, ct) {
  if (startsWith(a, "ML-KEM-")) {
    list(
      masked = r2h(tc(.Call(C("C_rmbl_mlkem_decaps_masked"), lvl(a), sk, ct))),
      plain = r2h(tc(.Call(C("C_rmbl_mlkem_decaps"), lvl(a), sk, ct)))
    )
  } else {
    list(r2h(tc(.Call(C("C_rmbl_hqc_decaps"), lvl(a), sk, ct))))
  }
}
skg <- function(a, seed) {
  r <- if (is.na(mode(a))) {
    tc(.Call(C("C_rmbl_slhdsa_keypair"), a, seed))
  } else {
    tc(.Call(C("C_rmbl_mldsa_keypair"), mode(a), seed))
  }
  list(c(r2h(r$public), r2h(r$secret)))
}
sgn <- function(a, sk, msg, ctx, ph, rnd) {
  if (is.na(mode(a))) {
    return(list(r2h(tc(.Call(
      C("C_rmbl_slhdsa_sign"), a, sk, msg, ctx, rnd, pre(ph)
    )))))
  }
  f <- C("C_rmbl_mldsa_sign")
  list(
    masked = r2h(tc(.Call(f, mode(a), sk, msg, ctx, rnd, pre(ph), TRUE))),
    plain = r2h(tc(.Call(f, mode(a), sk, msg, ctx, rnd, pre(ph), FALSE)))
  )
}
vrf <- function(a, pk, msg, ctx, ph, sig) {
  ok <- if (is.na(mode(a))) {
    tc(.Call(C("C_rmbl_slhdsa_verify"), a, pk, msg, ctx, sig, pre(ph)))
  } else {
    tc(.Call(C("C_rmbl_mldsa_verify"), mode(a), pk, msg, ctx, sig, pre(ph)))
  }
  list(if (isTRUE(ok)) "01" else "00")
}
hsh <- function(a, msg, n) {
  r <- if (a %in% c("shake128", "shake256")) {
    tc(.Call(C("C_rmbl_shake"), as.integer(sub("shake", "", a)), msg, n))
  } else {
    tc(.Call(C("C_rmbl_prehash_digest"), a, msg))
  }
  list(r2h(r))
}
hmc <- function(a, key, msg) {
  list(r2h(tc(.Call(
    C("C_rmbl_hmac_shax"), as.integer(sub("sha", "", a)), key, msg
  ))))
}

nin <- c(kk = 1L, ke = 3L, kd = 2L, sk = 1L, ss = 6L, sv = 5L, h = 1L, hm = 2L)
nout <- c(kk = 2L, ke = 2L, kd = 1L, sk = 2L, ss = 1L, sv = 1L, h = 1L, hm = 1L)
tot <- list()
count <- function(key, what) {
  if (is.null(tot[[key]])) tot[[key]] <<- c(n = 0L, agree = 0L, differ = 0L)
  tot[[key]][[what]] <<- tot[[key]][[what]] + 1L
}
short <- function(h) {
  if (identical(h, "-")) "refused" else
    sprintf("%s%s (%d bytes)", substr(h, 1L, 64L),
            if (nchar(h) > 64L) "..." else "", nchar(h) %/% 2L)
}
ndiff <- 0L
nl <- 0L

one <- function(l) {
  f <- strsplit(l, " ", fixed = TRUE)[[1]]
  op <- f[[1]]
  a <- f[[2]]
  ni <- nin[[op]]
  ins <- f[2L + seq_len(ni)]
  ex <- f[2L + ni + seq_len(nout[[op]])]
  x <- function(i) h2r(ins[[i]])
  got <- switch(op,
    kk = kk(a, x(1)),
    ke = ke(a, x(1), x(3)),
    kd = kd(a, x(1), x(2)),
    sk = skg(a, x(1)),
    ss = sgn(a, x(2), x(3), x(4), ins[[5]], x(6)),
    sv = vrf(a, x(1), x(2), x(3), ins[[4]], x(5)),
    h = hsh(a, x(1), nchar(ex[[1]]) %/% 2L),
    hm = hmc(a, x(1), x(2))
  )
  key <- paste(a, op)
  count(key, "n")
  bad <- FALSE
  for (v in seq_along(got)) {
    g <- got[[v]]
    if (identical(g, ex)) next
    bad <- TRUE
    w <- which(g != ex)[[1]]
    rf <- (g[[w]] == "-") != (ex[[w]] == "-")
    message(sprintf(
      "DIFF line %d: %s %s, output %d%s%s\n  noqtis: %s\n  rmoriebricklayer: %s",
      nl, op, a, w,
      if (!is.null(names(got))) paste0(" (", names(got)[[v]], ")") else "",
      if (rf) ", one side refused" else "",
      short(ex[[w]]), short(g[[w]])
    ))
    # the line with rmoriebricklayer's outputs, then the cross-checks
    writeLines(paste(c(op, a, ins, g), collapse = " "))
    if (op == "ss" && g[[1]] != "-") {
      cx <- vrf(a, x(1), x(3), x(4), ins[[5]], h2r(g[[1]]))[[1]]
      writeLines(paste(c("sv", a, ins[c(1, 3, 4, 5)], g[[1]], cx), collapse = " "))
    }
    if (op == "ke" && g[[1]] != "-" && ins[[2]] != "-") {
      writeLines(paste(c("kd", a, ins[[2]], g[[1]], g[[2]]), collapse = " "))
    }
  }
  if (bad) {
    count(key, "differ")
    ndiff <<- ndiff + 1L
  } else {
    count(key, "agree")
  }
}

message(sprintf(
  "dv.R: rmoriebricklayer %s from %s",
  format(packageVersion("rmoriebricklayer")),
  find.package("rmoriebricklayer")
))
con <- file(args[[1]], "r")
repeat {
  ls <- readLines(con, n = 200L)
  if (!length(ls)) break
  for (l in ls) {
    nl <- nl + 1L
    one(l)
  }
}
close(con)
for (k in names(tot)) {
  t <- tot[[k]]
  message(sprintf("dv.R: %s: %d cases, %d agree, %d differ", k, t[["n"]],
                  t[["agree"]], t[["differ"]]))
}
message(sprintf("dv.R: %d lines, %d differ", nl, ndiff))
quit(status = if (ndiff > 0L) 1L else 0L)
