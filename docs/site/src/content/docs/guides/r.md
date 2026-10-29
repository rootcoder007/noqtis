---
title: Use from R
description: The noqtis R package - seal the folder behind an analysis, check it, sign and verify, with the C library bundled.
---

The `noqtis` R package bundles the C library: nothing else to install,
and randomness comes from the operating system, never from R's random
number generator (`set.seed()` does not make keys repeat).

:::note[Before the first release]
`install.packages("noqtis")` works once CRAN has reviewed the package.
Until then, install it from the repository (this compiles the bundled C
library, so it needs the R build tools):

```sh
git clone https://github.com/rootcoder007/noqtis.git
R CMD INSTALL noqtis/bindings/r
```
:::

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

## In a reproducible workflow

Seal the output folder as the last step of the analysis script, and
publish the public key with the paper or the data release. A reader
checks the folder they downloaded with `nqcheck(dir, pk)`, or with the
`noqtis check -p key.pub dir` command, which reads the same capsule.

The package's vignette (`vignette("noqtis")`) and help pages
(`?nqseal`, `?nqsign`) cover every function.
