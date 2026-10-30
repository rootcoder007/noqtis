# noqtis <img src="man/figures/logo.png" align="right" height="139" alt="NOQTIS hex logo" />

Seal the exact files behind a result with a post-quantum signature, so
anyone can check later, offline, that nothing changed. The `noqtis` R
package bundles the NOQTIS C library: ML-DSA (FIPS 204) and SLH-DSA
(FIPS 205) signatures, ML-KEM (FIPS 203), SHA-2 and SHA-3, and sealed
folders (capsules). Nothing else to install.

> **Status: unaudited.** The code has not had an external security
> audit; do not rely on it for anything that matters yet.

## Install

```r
install.packages("noqtis", repos = c("https://rootcoder007.r-universe.dev",
                                     "https://cloud.r-project.org"))
```

## Seal a folder, check it

```r
library(noqtis)
d <- file.path(tempdir(), "results")
dir.create(file.path(d, "data"), recursive = TRUE)
writeLines(c("a,b", "1,2"), file.path(d, "data", "in.csv"))

k <- nqkeygen("ML-DSA-65")
nqseal(d, k$sk, k$pk, "ML-DSA-65")
attr(nqcheck(d, k$pk), "ok")
```

The guide, with signatures, KEMs and partial checks:
https://rootcoder007.github.io/noqtis/guides/r/
