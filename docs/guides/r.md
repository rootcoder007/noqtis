---
title: Use from R
description: The noqtis R package - seal the folder behind an analysis, check it, sign and verify, with the C library bundled.
---

The `noqtis` R package bundles the C library: nothing else to install,
and randomness comes from the operating system, never from R's random
number generator (`set.seed()` does not make keys repeat).

From r-universe, with binaries for Windows, macOS and Linux:

```r
install.packages("noqtis", repos = c("https://rootcoder007.r-universe.dev",
                                     "https://cloud.r-project.org"))
```

`install.packages("noqtis")` from CRAN works once CRAN has reviewed the
package.

## Seal the folder behind an analysis

```r
library(noqtis)
d <- file.path(tempdir(), "results")
dir.create(file.path(d, "data"), recursive = TRUE)
writeLines(c("a,b", "1,2"), file.path(d, "data", "in.csv"))
writeLines("r", file.path(d, "report.txt"))

k <- nqkeygen("ML-DSA-65")
nqseal(d, k$sk, k$pk, "ML-DSA-65", meta = '{"project":"tutorial"}')
r <- nqcheck(d, k$pk)
attr(r, "ok")

cat("edited\n", file = file.path(d, "report.txt"), append = TRUE)
r <- nqcheck(d, k$pk)
attr(r, "ok")
r[!r$ok, ]

sig <- nqsign(k$sk, "the results in table 2", "ML-DSA-65", ctx = "app-v1")
nqverify(k$pk, "the results in table 2", sig, "ML-DSA-65", ctx = "app-v1")
nqverify(k$pk, "the results in table 2", sig, "ML-DSA-65")

kk <- nqkeygen("ML-KEM-768")
e <- nqencap(kk$pk, "ML-KEM-768")
identical(nqdecap(kk$sk, e$ct, "ML-KEM-768"), e$ss)
nqhash("abc", "sha3-256", hex = TRUE)
```

A key made with `noqtis keygen` loads with `nqreadkey("me")$key`, and
`nqwritekey()` writes one the command line reads.

Run with `Rscript prov.R` (or `source("prov.R", echo = TRUE)`), the
interesting lines print:

```text
> attr(r, "ok")
[1] TRUE
> attr(r, "ok")
[1] FALSE
> r[!r$ok, ]
   check    ok                   detail
16  file FALSE report.txt: size differs
> nqverify(k$pk, "the results in table 2", sig, "ML-DSA-65", ctx = "app-v1")
[1] TRUE
> nqverify(k$pk, "the results in table 2", sig, "ML-DSA-65")
[1] FALSE
> identical(nqdecap(kk$sk, e$ct, "ML-KEM-768"), e$ss)
[1] TRUE
> nqhash("abc", "sha3-256", hex = TRUE)
[1] "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```

- `nqseal(dir, sk, pk, alg, meta)` writes `noqtis.json` and `noqtis.sig`
  into the folder; `meta` is one string of JSON text, signed with the
  manifest.
- `nqcheck(dir, pk)` returns a data frame with one row per check
  (`check`, `ok`, `detail`); `attr(r, "ok")` is `TRUE` only when every
  check passed. Without `pk` it accepts the key in the seal, and a row
  says so.
- Keys, signatures and ciphertexts are raw vectors in the standards'
  encodings, so they can be saved with `writeBin()` and checked by any
  conforming implementation.

## An identity card for your key

An identity card ties your signing key to your name and ORCID iD, signed
by the key itself; publish it with the key, and `noqtis check --card`
names you as the sealer of your capsules.

```r
library(noqtis)
k <- nqkeygen("ML-DSA-65")
card <- nqidcard(k$sk, k$pk, "ML-DSA-65", "Ada Lovelace",
                 orcid = "https://orcid.org/0000-0002-1825-0097")
writeBin(card, file.path(tempdir(), "ada.card"))

v <- nqidcheck(file.path(tempdir(), "ada.card"), k$pk)
v$name
v$orcid
identical(v$key_sha256, nqhash(k$pk, "sha256", hex = TRUE))

bad <- charToRaw(sub("Ada", "Eve", rawToChar(card)))
is.null(nqidcheck(bad))
inherits(try(nqidcard(k$sk, k$pk, "ML-DSA-65", "Ada Lovelace",
                      orcid = "0000-0002-1825-0098"), silent = TRUE),
         "try-error")
```

```text
> v$name
[1] "Ada Lovelace"
> v$orcid
[1] "0000-0002-1825-0097"
> identical(v$key_sha256, nqhash(k$pk, "sha256", hex = TRUE))
[1] TRUE
> is.null(nqidcheck(bad))
[1] TRUE
[1] TRUE
```

The card holds the bare ORCID iD, whose check digit must be right. A
changed card does not verify (`NULL`), and an iD with a wrong check
digit is refused. The card is self-signed, so give `v$key_sha256` where
people already know you, or let them pin your public key.

## In a reproducible workflow

Seal the output folder as the last step of the analysis script, and
publish the public key with the paper or the data release. A reader
checks the folder they downloaded with `nqcheck(dir, pk)`, or with the
`noqtis check -p key.pub dir` command, which reads the same capsule.

The package's vignette (`vignette("noqtis")`) and help pages
(`?nqseal`, `?nqsign`) cover every function.
