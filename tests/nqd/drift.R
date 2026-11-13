# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Makes the drift test vectors (tests/vectors/nqd/drift/) and the values
# tests/nqd/tddft.c checks nqd against: R's stats::ks.test and
# chisq.test on the same data, and the PSI, Jensen-Shannon and Benford
# statistics written out from their definitions (noqtis-drift(1)).
#   Rscript --vanilla tests/nqd/drift.R tests/vectors/nqd/drift
# Run once; the outputs are committed. R 4.6.2 made them.
args <- commandArgs(TRUE)
out <- if (length(args)) args[1] else "."
set.seed(20261112)
f6 <- function(v) sprintf("%.6f", v)
f2 <- function(v) sprintf("%.2f", v)
wr <- function(df, name) {
  con <- file(file.path(out, name), "wb")
  writeLines(paste(names(df), collapse = ","), con, sep = "\n")
  for (i in seq_len(nrow(df)))
    writeLines(paste(df[i, ], collapse = ","), con, sep = "\n")
  close(con)
}
num <- function(s) as.numeric(s)

# small: exact KS (60 x 70 < 10000, no ties)
xr <- f6(rnorm(60)); xc <- f6(rnorm(70, 0.5))
cr <- sample(c("a", "b", "c", "d"), 60, TRUE, c(.4, .3, .2, .1))
cc <- sample(c("a", "b", "c", "d", "e"), 70, TRUE, c(.25, .25, .25, .15, .1))
br <- f2(rexp(60) * 1000); bc <- f2(runif(70) * 1000)
wr(data.frame(x = xr, c = cr, b = br), "ref.csv")
wr(data.frame(x = xc, c = cc, b = bc), "cur.csv")

# big: the sketch (3000 > 1001 values) and the asymptotic p
yr <- f6(rnorm(3000)); yc <- f6(rnorm(2500, 0.1, 1.1))
wr(data.frame(y = yr), "bigref.csv")
wr(data.frame(y = yc), "bigcur.csv")

v <- list()
k <- suppressWarnings(ks.test(num(xr), num(xc), exact = TRUE))
v$ks.d <- unname(k$statistic); v$ks.p <- k$p.value
lv <- c("a", "b", "c", "d", "e")
tab <- rbind(table(factor(cr, lv)), table(factor(cc, lv)))
tab <- tab[, colSums(tab) > 0]
ch <- chisq.test(tab, correct = FALSE)
v$chi.x2 <- unname(ch$statistic); v$chi.df <- unname(ch$parameter)
v$chi.p <- ch$p.value
k2 <- ks.test(num(yr), num(yc), exact = FALSE)
v$big.d <- unname(k2$statistic); v$big.p <- k2$p.value

# PSI and JS over the reference's type-1 deciles, bins closed on the
# right, an empty bin counted as 1e-6 in the PSI only
psi <- function(r, c) {
  r <- sort(r); n <- length(r)
  e <- if (length(unique(r)) <= 10) unique(r) else
    unique(r[ceiling(n * (1:9) / 10)])
  bin <- function(x) vapply(x, function(t) sum(t > e) + 1, 1)
  k <- length(e) + 1
  p <- tabulate(bin(r), k) / n; q <- tabulate(bin(c), k) / length(c)
  pf <- ifelse(p > 0, p, 1e-6); qf <- ifelse(q > 0, q, 1e-6)
  m <- (p + q) / 2
  js <- 0.5 * sum(ifelse(p > 0, p * log(p / m), 0)) +
    0.5 * sum(ifelse(q > 0, q * log(q / m), 0))
  c(sum((pf - qf) * log(pf / qf)), js)
}
s <- psi(num(xr), num(xc)); v$psi <- s[1]; v$js <- s[2]
s <- psi(num(yr), num(yc)); v$big.psi <- s[1]; v$big.js <- s[2]
pc <- tab[1, ] / sum(tab[1, ]); qc <- tab[2, ] / sum(tab[2, ])
pf <- ifelse(pc > 0, pc, 1e-6); qf <- ifelse(qc > 0, qc, 1e-6)
v$cat.psi <- sum((pf - qf) * log(pf / qf))

# Benford: the first significant digit of each value's text
fd <- function(s) as.integer(substr(gsub("[^1-9]", "", sub("e.*", "", s)), 1, 1))
d <- tabulate(fd(bc), 9)
bt <- chisq.test(d, p = log10(1 + 1 / (1:9)))
v$ben.x2 <- unname(bt$statistic); v$ben.p <- bt$p.value

con <- file(file.path(out, "expect.txt"), "wb")
for (n in names(v)) writeLines(sprintf("%s %.17g", n, v[[n]]), con)
close(con)
